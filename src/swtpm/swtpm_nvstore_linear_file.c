#include "config.h"

#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <fcntl.h>

#include <libtpms/tpm_types.h>
#include <libtpms/tpm_library.h>
#include <libtpms/tpm_error.h>

#include "compiler_dependencies.h"
#include "swtpm.h"
#include "swtpm_debug.h"
#include "swtpm_nvstore_linear.h"
#include "logging.h"
#include "tpmstate.h"

/*
    Provides a linear backend based on memory-mapping a filesystem path.
    Can be used to access regular files (with automatic resizing) or block
    devices (with pre-allocated constant size, must be big enough for all state,
    otherwise writing will fail).
*/

static struct {
    TPM_BOOL mapped;
    int fd;
    unsigned char *ptr;
    TPM_BOOL can_truncate;
    uint32_t size;
} mmap_state;

/*
    Update ptr and stat in mmap_state. Closes mmap_state.fd on error.
*/
static TPM_RESULT
SWTPM_NVRAM_LinearFile_Mmap(void)
{
    TPM_RESULT rc = 0;
    struct stat st;

    TPM_DEBUG("SWTPM_NVRAM_LinearFile_Mmap: renewing mmap\n");

    if (fstat(mmap_state.fd, &st)) {
        logprintf(STDERR_FILENO,
                  "SWTPM_NVRAM_LinearFile_Mmap: Could not stat file: %s\n",
                  strerror(errno));
        rc = TPM_FAIL;
        goto fail;
    }

    if (st.st_size >= (uint32_t)sizeof(struct nvram_linear_hdr)) {
        /* valid regular file-ish */
        mmap_state.size = st.st_size;
        mmap_state.can_truncate = true;
    } else if (S_ISREG(st.st_mode)) {
        /* too small, and regular file - make room for at least the header */
        if (ftruncate(mmap_state.fd, sizeof(struct nvram_linear_hdr))) {
            logprintf(STDERR_FILENO,
                      "SWTPM_NVRAM_LinearFile_Mmap: Could not ftruncate file "
                      "(too small): %s\n",
                      strerror(errno));
            rc = TPM_FAIL;
            goto fail;
        }

        if (fstat(mmap_state.fd, &st)) {
            logprintf(STDERR_FILENO,
                      "SWTPM_NVRAM_LinearFile_Mmap: Could not stat file (after "
                      "truncate): %s\n",
                      strerror(errno));
            rc = TPM_FAIL;
            goto fail;
        }

        mmap_state.size = st.st_size;
        mmap_state.can_truncate = true;
    } else if (S_ISBLK(st.st_mode)) {
#if defined(BLKGETSIZE64)
        uint64_t bd_size;

        /* valid block device, can't resize, but can use as is */
        if (ioctl(mmap_state.fd, BLKGETSIZE64, &bd_size)) {
            logprintf(STDERR_FILENO,
                      "SWTPM_NVRAM_LinearFile_Mmap: Could not get block device "
                      "size): %s\n",
                      strerror(errno));
            rc = TPM_FAIL;
            goto fail;
        }

        mmap_state.size = bd_size;
        mmap_state.can_truncate = false;

        if (mmap_state.size < (uint32_t)sizeof(struct nvram_linear_hdr)) {
            logprintf(STDERR_FILENO, "SWTPM_NVRAM_LinearFile_Mmap: block device"
                                     " too small, cannot resize\n");
            rc = TPM_FAIL;
            goto fail;
        }
#else
        logprintf(STDERR_FILENO, "SWTPM_NVRAM_LinearFile_Mmap: block devices are"
                                 " not supported\n");
        rc = TPM_FAIL;
        goto fail;
#endif
    } else {
        logprintf(STDERR_FILENO, "SWTPM_NVRAM_LinearFile_Mmap: invalid stat\n");
        rc = TPM_FAIL;
        goto fail;
    }

    mmap_state.ptr = mmap(NULL, mmap_state.size, PROT_READ | PROT_WRITE,
                          MAP_SHARED, mmap_state.fd, 0);
    if (mmap_state.ptr == MAP_FAILED) {
        logprintf(STDERR_FILENO,
                  "SWTPM_NVRAM_LinearFile_Mmap: Could not mmap file: %s\n",
                  strerror(errno));
        rc = TPM_FAIL;
        goto fail;
    }

    mmap_state.mapped = true;
    return rc;

fail:
    mmap_state.mapped = false;
    close(mmap_state.fd);
    return rc;
}

/*
    Strip leading "file://" from uri if given.
*/
static const char*
SWTPM_NVRAM_LinearFile_UriToPath(const char* uri)
{
    const char *path = uri;

    if (strncmp(uri, "file://", 7) == 0) {
        path += 7;
    }

    return path;
}

static TPM_RESULT
SWTPM_NVRAM_LinearFile_Open(const char* uri,
                            unsigned char **data,
                            uint32_t *length)
{
    TPM_RESULT rc = 0;
    const char *path = SWTPM_NVRAM_LinearFile_UriToPath(uri);

    if (mmap_state.mapped) {
        logprintf(STDERR_FILENO,
                  "SWTPM_NVRAM_LinearFile_Open: Already open\n");
        return TPM_FAIL;
    }

    mmap_state.fd = open(path, O_RDWR|O_CREAT, tpmstate_get_mode());
    if (mmap_state.fd < 0) {
        logprintf(STDERR_FILENO,
                  "SWTPM_NVRAM_LinearFile_Open: Could not open file: %s\n",
                  strerror(errno));
        return TPM_FAIL;
    }

    rc = SWTPM_NVRAM_LinearFile_Mmap();
    if (rc == 0) {
        TPM_DEBUG("SWTPM_NVRAM_LinearFile_Open: Success opening '%s'\n", path);
        *length = mmap_state.size;
        *data = mmap_state.ptr;
    }

    return rc;
}

static TPM_RESULT
SWTPM_NVRAM_LinearFile_Flush(const char* uri SWTPM_ATTR_UNUSED,
                             uint32_t offset,
                             uint32_t count)
{
    TPM_RESULT rc = 0;
    uint8_t *msync_offset;
    uint32_t msync_count;

    if (!mmap_state.mapped) {
        logprintf(STDERR_FILENO,
                  "SWTPM_NVRAM_LinearFile_Flush: Nothing mapped\n");
        rc = TPM_FAIL;
    }

    /* msync parameters must be page-aligned */
    uint32_t pagesize = sysconf(_SC_PAGESIZE);
    msync_offset = mmap_state.ptr + (offset & ~(pagesize - 1));
#if defined(__CYGWIN__)
    /* Cygwin uses Win API FlushViewOfFile, which we call with len = 0 */
    msync_count = 0;
#else
    msync_count = (count + (pagesize - 1)) & ~(pagesize - 1);
#endif

    TPM_DEBUG("SWTPM_NVRAM_LinearFile_Flush: msync %d@0x%x\n",
              msync_count, msync_offset);

    if (rc == 0 && msync(msync_offset, msync_count, MS_SYNC)) {
        logprintf(STDERR_FILENO,
                  "SWTPM_NVRAM_LinearFile_Flush: Error in msync: %s\n",
                  strerror(errno));
        rc = TPM_FAIL;
    }

    return rc;
}

static void SWTPM_NVRAM_LinearFile_Cleanup(void)
{
    if (!mmap_state.mapped)
        return;

    SWTPM_NVRAM_LinearFile_Flush(NULL, 0, mmap_state.size);
    munmap(mmap_state.ptr, mmap_state.size);
    close(mmap_state.fd);
    mmap_state.fd = 0;
    mmap_state.mapped = false;
}

static TPM_RESULT
SWTPM_NVRAM_LinearFile_Resize(const char* uri SWTPM_ATTR_UNUSED,
                              unsigned char **data,
                              uint32_t *new_length,
                              uint32_t requested_length)
{
    TPM_RESULT rc = 0;

    if (!mmap_state.mapped) {
        logprintf(STDERR_FILENO,
                  "SWTPM_NVRAM_LinearFile_Resize: Nothing mapped\n");
        return TPM_FAIL;
    }

    /* assume we can resize files, but not anything else (like blockdevs) */
    if (mmap_state.can_truncate) {
        TPM_DEBUG("SWTPM_NVRAM_LinearFile_Resize: resizing file to %d\n",
                  requested_length);

        rc = SWTPM_NVRAM_LinearFile_Flush(NULL, 0, mmap_state.size);
        if (rc == 0 && munmap(mmap_state.ptr, mmap_state.size)) {
            logprintf(STDERR_FILENO,
                      "SWTPM_NVRAM_LinearFile_Resize: Error in munmap: %s\n",
                      strerror(errno));
            rc = TPM_FAIL;
        }
        /* only complain when ftruncate fails if growing was requested */
        if (rc == 0 &&
            ftruncate(mmap_state.fd, requested_length) &&
            mmap_state.size < requested_length) {

            logprintf(STDERR_FILENO,
                      "SWTPM_NVRAM_LinearFile_Resize: Error in ftruncate: %s\n",
                      strerror(errno));
            rc = TPM_FAIL;
        }
        if (rc == 0) {
            rc = SWTPM_NVRAM_LinearFile_Mmap();
        }
        if (rc == 0) {
            *data = mmap_state.ptr;
            *new_length = mmap_state.size;
        }
    } else {
        TPM_DEBUG("SWTPM_NVRAM_LinearFile_Resize: ignoring resize non-file\n");

        *new_length = mmap_state.size;
        if (mmap_state.size < requested_length) {
            rc = TPM_SIZE;
        }
    }

    return rc;
}

struct nvram_linear_store_ops nvram_linear_file_ops = {
    .open = SWTPM_NVRAM_LinearFile_Open,
    .flush = SWTPM_NVRAM_LinearFile_Flush,
    .resize = SWTPM_NVRAM_LinearFile_Resize,
    .cleanup = SWTPM_NVRAM_LinearFile_Cleanup,
};
