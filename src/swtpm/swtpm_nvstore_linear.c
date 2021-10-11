#include "config.h"

#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>

#include <libtpms/tpm_error.h>
#include <libtpms/tpm_nvfilename.h>

#include "compiler_dependencies.h"
#include "sys_dependencies.h"
#include "swtpm.h"
#include "swtpm_debug.h"
#include "swtpm_nvstore.h"
#include "swtpm_nvstore_linear.h"
#include "logging.h"
#include "utils.h"

static struct {
    TPM_BOOL      initialized;
    char          *loaded_uri;
    struct nvram_linear_store_ops *ops;

    unsigned char *data;
    uint32_t      length;
    struct nvram_linear_hdr *hdr; /* points into *data */
} state;

/*
    Attempts to flush the header of the linear state, if required by the store.
*/
static TPM_RESULT
SWTPM_NVRAM_Linear_FlushHeader(const char* uri)
{
    if (state.ops->flush) {
        return state.ops->flush(uri, 0, le16toh(state.hdr->hdrsize));
    }
    return 0;
}

/*
    Attempts a resize and ensures that state is updated correctly and the given
    new_size could actually be reached.
*/
static TPM_RESULT
SWTPM_NVRAM_Linear_SafeResize(const char* uri, uint32_t new_size)
{
    TPM_RESULT rc = 0;
    uint32_t result;

    if (!state.ops->resize) {
        return new_size < state.length ? 0 : TPM_SIZE;
    }

    rc = state.ops->resize(uri, &state.data, &result, new_size);
    if (rc) {
        return rc;
    }

    /* base address might have changed, update pointers */
    state.hdr = (struct nvram_linear_hdr*)state.data;
    state.length = result;

    if (result < new_size) {
        return TPM_SIZE;
    }

    return rc;
}

#define FILE_NR_INVALID 0xffffffff

/*
    Returns the offset into the state.hdr.files array given a TPM state name and
    number. Will be FILE_NR_INVALID if out of bounds or unknown name.
*/
static uint32_t
SWTPM_NVRAM_Linear_GetFileNr(const char *name)
{
    uint32_t rc = 0;
    if (strcmp(name, TPM_PERMANENT_ALL_NAME) == 0) {
        rc += 0;
    } else if (strcmp(name, TPM_VOLATILESTATE_NAME) == 0) {
        rc += 1;
    } else if (strcmp(name, TPM_SAVESTATE_NAME) == 0) {
        rc += 2;
    } else {
        logprintf(STDERR_FILENO,
                  "SWTPM_NVRAM_Linear_GetFileOffset: Unknown name '%s'\n",
                  name);
        return FILE_NR_INVALID;
    }
    if (rc >= SWTPM_NVSTORE_LINEAR_MAX_STATES) {
        logprintf(STDERR_FILENO,
                  "SWTPM_NVRAM_Linear_GetFileOffset: File limit exceeded: %d\n",
                  rc);
        return FILE_NR_INVALID;
    }
    return rc;
}

/*
    Allocate a new file entry in the linear address space of state.data.
    The new file will be placed at the end.

    Importantly, this may perform a resize, so pointers into state.data or
    state.hdr must not be kept over this function call.
*/
static TPM_RESULT
SWTPM_NVRAM_Linear_AllocFile(const char *uri, uint32_t file_nr, uint32_t size)
{
    TPM_RESULT rc = 0;
    struct nvram_linear_hdr_file *file;
    uint32_t new_offset = le16toh(state.hdr->hdrsize);
    uint32_t new_size;
    uint32_t cur_end;
    uint32_t i;
    uint32_t section_size = size;
    ROUND_TO_NEXT_POWER_OF_2_32(section_size);

    /* find end of current last file */
    for (i = 0; i < SWTPM_NVSTORE_LINEAR_MAX_STATES; i++) {
        file = &state.hdr->files[i];
        if (!file->offset) {
            continue;
        }

        cur_end = le32toh(file->offset) + le32toh(file->section_length);
        if (cur_end > new_offset) {
            new_offset = cur_end;
        }
    }

    new_size = new_offset + section_size;
    rc = SWTPM_NVRAM_Linear_SafeResize(uri, new_size);
    if (rc) {
        return rc;
    }

    file = &state.hdr->files[file_nr];
    file->section_length = htole32(section_size);
    file->data_length = htole32(size);
    file->offset = htole32(new_offset);

    TPM_DEBUG("SWTPM_NVRAM_Linear_AllocFile: allocated file %d @ %d "
              "(len=%d section=%d)\n",
              file_nr, new_offset, size, section_size);

    return rc;
}

/*
    Deallocate a file from state.data. It's entry in state.hdr will be zeroed,
    and the file length adjusted accordingly (if 'resize' is TRUE).
    If the file was not at the end, any following files will be moved forward,
    as to not leave any holes. This simplifies the allocator strategy, since it
    allows new files to always be placed at the end.

    If resize is true, this may perform a resize, so pointers into state.data or
    state.hdr must not be kept over this function call.
*/
static TPM_RESULT
SWTPM_NVRAM_Linear_RemoveFile(const char *uri,
                              uint32_t file_nr,
                              TPM_BOOL resize)
{
    TPM_RESULT rc = 0;
    uint32_t next_offset = 0xffffffff;
    uint32_t state_end = 0;
    uint32_t new_len;
    uint32_t i, cur_offset, cur_end;
    struct nvram_linear_hdr_file *file;
    struct nvram_linear_hdr_file old_file = state.hdr->files[file_nr];

    if (old_file.offset == 0) {
        return 0;
    }

    TPM_DEBUG("SWTPM_NVRAM_Linear_RemoveFile: removing filenr %d (resize=%d)\n",
              file_nr, resize);

    state.hdr->files[file_nr].offset = 0;
    state.hdr->files[file_nr].data_length = 0;
    state.hdr->files[file_nr].section_length = 0;

    /* find offset of file right after the one we remove, and adjust offsets */
    for (i = 0; i < SWTPM_NVSTORE_LINEAR_MAX_STATES; i++) {
        file = &state.hdr->files[i];
        if (!file->offset) {
            continue;
        }

        cur_offset = le32toh(file->offset);
        if (cur_offset > le32toh(old_file.offset)) {
            if (cur_offset < next_offset) {
                next_offset = cur_offset;
            }
            cur_end = cur_offset + le32toh(file->section_length);
            if (cur_end > state_end) {
                state_end = cur_end;
            }
            file->offset = htole32(cur_offset -
                                   le32toh(old_file.section_length));
        }
    }

    if (next_offset != 0xffffffff) {
        TPM_DEBUG("SWTPM_NVRAM_Linear_RemoveFile: compacting\n");
        /* if we weren't the end, compact by moving following files forward */
        memmove(state.data + le32toh(old_file.offset),
                state.data + next_offset,
                state_end - next_offset);
    }

    if (resize) {
        new_len = state.length - le32toh(old_file.section_length);
        rc = SWTPM_NVRAM_Linear_SafeResize(uri, new_len);
        if (rc == 0) {
            state.length = new_len;
        }
    }

    return rc;
}

static TPM_RESULT
SWTPM_NVRAM_Prepare_Linear(const char *uri)
{
    TPM_RESULT rc = 0;

    TPM_DEBUG("SWTPM_NVRAM_Prepare_Linear: uri='%s'\n", uri);

    if (state.initialized) {
        if (strcmp(state.loaded_uri, uri) == 0) {
            /* same URI loaded, this is okay, nothing to be done */
            return 0;
        }

        logprintf(STDERR_FILENO,
                  "SWTPM_NVRAM_PrepareLinear: Cannot prepare twice\n");
        return TPM_FAIL;
    }

    state.loaded_uri = malloc(strlen(uri) + 1);
    strcpy(state.loaded_uri, uri);

    /* TODO: Parse URI prefixes ("iscsi://", "rbd://", etc...) */
    state.ops = &nvram_linear_file_ops;

    if ((rc = state.ops->open(uri, &state.data, &state.length))) {
        return rc;
    }

    state.hdr = (struct nvram_linear_hdr*)state.data;

    if (le64toh(state.hdr->magic) != SWTPM_NVSTORE_LINEAR_MAGIC) {
        logprintf(STDOUT_FILENO,
                  "Formatting '%s' as new linear NVRAM store\n",
                  uri);

        state.hdr->magic = htole64(SWTPM_NVSTORE_LINEAR_MAGIC);
        state.hdr->version = SWTPM_NVSTORE_LINEAR_VERSION;
        state.hdr->hdrsize = htole16(sizeof(struct nvram_linear_hdr));
        memset(&state.hdr->files, 0, sizeof(state.hdr->files));

        SWTPM_NVRAM_Linear_FlushHeader(uri);

    } else {
        /* assume valid state found */
        if (state.hdr->version > SWTPM_NVSTORE_LINEAR_VERSION) {
            logprintf(STDERR_FILENO,
                      "SWTPM_NVRAM_PrepareLinear: Unknown format version: %d\n",
                      state.hdr->version);
            return TPM_FAIL;
        }
    }

    state.initialized = TRUE;
    return rc;
}

static TPM_RESULT
SWTPM_NVRAM_LoadData_Linear(unsigned char **data,
                            uint32_t *length,
                            uint32_t tpm_number SWTPM_ATTR_UNUSED,
                            const char *name,
                            const char *uri SWTPM_ATTR_UNUSED)
{
    uint32_t file_nr;
    uint32_t file_offset;
    uint32_t file_data_len;
    struct nvram_linear_hdr_file *file;

    TPM_DEBUG("SWTPM_NVRAM_LoadData_Linear: request for %s:%d\n",
              name, tpm_number);

    file_nr = SWTPM_NVRAM_Linear_GetFileNr(name);
    if (file_nr == FILE_NR_INVALID) {
        return TPM_FAIL;
    }

    file = &state.hdr->files[file_nr];
    file_offset = le32toh(file->offset);
    file_data_len = le32toh(file->data_length);

    if (!file_offset) {
        return TPM_RETRY;
    }

    if (file_offset + file_data_len > state.length) {
        /* shouldn't happen, but just to be safe */
        return TPM_FAIL;
    }

    if (data == NULL) {
        return TPM_FAIL;
    }

    /*
        TODO: at the moment, callers require a pointer that can be 'free'd, but
        for efficiency, it would be better to return the mapped area directly
    */
    *length = file_data_len;
    *data = malloc(file_data_len);
    if (*data == NULL) {
        return TPM_FAIL;
    }
    memcpy(*data, state.data + file_offset, file_data_len);

    TPM_DEBUG("SWTPM_NVRAM_LoadData_Linear: loaded %dB from %s:%d\n",
              file_data_len, name, tpm_number);

    return 0;
}

static TPM_RESULT
SWTPM_NVRAM_StoreData_Linear(unsigned char *filedata,
                             uint32_t filedata_length,
                             uint32_t tpm_number SWTPM_ATTR_UNUSED,
                             const char *name,
                             const char *uri)
{
    TPM_RESULT rc = 0;
    TPM_BOOL needs_hdr_flush = FALSE;
    TPM_BOOL needs_full_flush = FALSE;
    uint32_t file_nr;
    uint32_t file_offset;
    struct nvram_linear_hdr_file *file;

    TPM_DEBUG("SWTPM_NVRAM_StoreData_Linear: request for %dB to %s:%d\n",
              filedata_length, name, tpm_number);

    file_nr = SWTPM_NVRAM_Linear_GetFileNr(name);
    if (file_nr == FILE_NR_INVALID) {
        return TPM_FAIL;
    }

    file = &state.hdr->files[file_nr];

    if (!file->offset) {
        /* alloc */
        rc = SWTPM_NVRAM_Linear_AllocFile(uri, file_nr, filedata_length);
        if (rc) {
            return rc;
        }
        needs_hdr_flush = TRUE;
    } else if (filedata_length > le32toh(file->section_length)) {
        /* realloc, resize will be done by AllocFile */
        rc = SWTPM_NVRAM_Linear_RemoveFile(uri, file_nr, FALSE);
        if (rc) {
            return rc;
        }
        rc = SWTPM_NVRAM_Linear_AllocFile(uri, file_nr, filedata_length);
        if (rc) {
            return rc;
        }
        needs_full_flush = TRUE;
    }

    /* resize might have changed pointer */
    file = &state.hdr->files[file_nr];
    file_offset = le32toh(file->offset);

    if (filedata_length != le32toh(file->data_length)) {
        file->data_length = htole32(filedata_length);
        needs_hdr_flush = TRUE;
    }

    memcpy(state.data + file_offset, filedata, filedata_length);

    TPM_DEBUG("SWTPM_NVRAM_StoreData_Linear: stored %dB to %s:%d\n",
              filedata_length, name, tpm_number);

    if (needs_full_flush) {
        if (state.ops->flush) {
            rc = state.ops->flush(uri, 0, state.length);
        }
        return rc;
    }

    if (needs_hdr_flush) {
        rc = SWTPM_NVRAM_Linear_FlushHeader(uri);
    }

    if (rc == 0 && state.ops->flush) {
        rc = state.ops->flush(uri, file_offset, filedata_length);
    }

    return rc;
}

static TPM_RESULT
SWTPM_NVRAM_DeleteName_Linear(uint32_t tpm_number SWTPM_ATTR_UNUSED,
                              const char *name,
                              TPM_BOOL mustExist SWTPM_ATTR_UNUSED,
                              const char *uri)
{
    TPM_RESULT rc = 0;
    uint32_t file_nr;

    file_nr = SWTPM_NVRAM_Linear_GetFileNr(name);
    if (file_nr == FILE_NR_INVALID) {
        rc = TPM_FAIL;
    }

    if (rc == 0) {
        rc = SWTPM_NVRAM_Linear_RemoveFile(uri, file_nr, TRUE);
    }

    if (rc == 0 && state.ops->flush) {
        /* full flush, RemoveFile can move around data */
        rc = state.ops->flush(uri, 0, state.length);
    }

    return rc;
}

static void SWTPM_NVRAM_Cleanup_Linear(void) {
    if (state.ops && state.ops->cleanup) {
        state.ops->cleanup();
    }
    if (state.loaded_uri) {
        free(state.loaded_uri);
    }
}

static TPM_RESULT
SWTPM_NVRAM_CheckState_Linear(const char *uri SWTPM_ATTR_UNUSED,
                              const char *name,
                              size_t *blobsize)
{
    TPM_RESULT rc = 0;
    uint32_t file_nr;
    struct nvram_linear_hdr_file *file;

    file_nr = SWTPM_NVRAM_Linear_GetFileNr(name);
    if (file_nr == FILE_NR_INVALID) {
        rc = TPM_FAIL;
    }

    if (rc == 0) {
         file = &state.hdr->files[file_nr];
         if (file->offset == 0) {
             rc = TPM_RETRY;
         } else {
             *blobsize = le32toh(file->data_length);
         }
    }

    return rc;
}

struct nvram_backend_ops nvram_linear_ops = {
    .prepare = SWTPM_NVRAM_Prepare_Linear,
    .load    = SWTPM_NVRAM_LoadData_Linear,
    .store   = SWTPM_NVRAM_StoreData_Linear,
    .delete  = SWTPM_NVRAM_DeleteName_Linear,
    .cleanup = SWTPM_NVRAM_Cleanup_Linear,
    .check_state = SWTPM_NVRAM_CheckState_Linear,
};
