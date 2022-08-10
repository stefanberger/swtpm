/********************************************************************************/
/*                                                                              */
/*                      NVRAM File Abstraction Layer                            */
/*                           Written by Ken Goldman                             */
/*                       Adapted to SWTPM by Stefan Berger                      */
/*                     IBM Thomas J. Watson Research Center                     */
/*                                                                              */
/* (c) Copyright IBM Corporation 2006, 2010, 2014, 2015.			*/
/*										*/
/* All rights reserved.								*/
/* 										*/
/* Redistribution and use in source and binary forms, with or without		*/
/* modification, are permitted provided that the following conditions are	*/
/* met:										*/
/* 										*/
/* Redistributions of source code must retain the above copyright notice,	*/
/* this list of conditions and the following disclaimer.			*/
/* 										*/
/* Redistributions in binary form must reproduce the above copyright		*/
/* notice, this list of conditions and the following disclaimer in the		*/
/* documentation and/or other materials provided with the distribution.		*/
/* 										*/
/* Neither the names of the IBM Corporation nor the names of its		*/
/* contributors may be used to endorse or promote products derived from		*/
/* this software without specific prior written permission.			*/
/* 										*/
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		*/
/* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		*/
/* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR	*/
/* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		*/
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	*/
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		*/
/* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,	*/
/* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY	*/
/* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		*/
/* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE	*/
/* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		*/
/********************************************************************************/

#include "config.h"

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <libtpms/tpm_error.h>

#include "swtpm.h"
#include "swtpm_debug.h"
#include "swtpm_nvstore.h"
#include "key.h"
#include "logging.h"
#include "tpmstate.h"
#include "utils.h"

#define TPM_FILENAME_MAX 20

static int lock_fd = -1;

static const char *
SWTPM_NVRAM_Uri_to_Dir(const char *uri)
{
    return uri + strlen("dir://");
}

static TPM_RESULT
SWTPM_NVRAM_Validate_Dir(const char *tpm_state_path)
{
    TPM_RESULT  rc = 0;
    size_t      length;

    /* TPM_NV_DISK TPM emulation stores in local directory determined by environment variable. */
    if (rc == 0) {
        if (tpm_state_path == NULL) {
            logprintf(STDERR_FILENO,
                      "SWTPM_NVRAM_Validate_Dir: Error (fatal), TPM_PATH environment "
                      "variable not set\n");
            rc = TPM_FAIL;
        }
    }

    /* check that the directory name plus a file name will not overflow FILENAME_MAX */
    if (rc == 0) {
        length = strlen(tpm_state_path);
        if ((length + TPM_FILENAME_MAX) > FILENAME_MAX) {
            logprintf(STDERR_FILENO,
                      "SWTPM_NVRAM_Validate_Dir: Error (fatal), TPM state path name "
                      "%s too large\n", tpm_state_path);
            rc = TPM_FAIL;
        }
    }
    if (rc == 0) {
        TPM_DEBUG("SWTPM_NVRAM_Validate_Dir: Rooted state path %s\n", tpm_state_path);
    }

    return rc;
}

static void
SWTPM_NVRAM_Unlock_Dir(void)
{
    if (lock_fd >= 0) {
        close(lock_fd);
        lock_fd = -1;
    }
}

static TPM_RESULT
SWTPM_NVRAM_Lock_Dir(const char *backend_uri)
{
    const char *tpm_state_path;
    TPM_RESULT rc = 0;
    char *lockfile = NULL;
    struct flock flock = {
        .l_type = F_WRLCK,
        .l_whence = SEEK_SET,
        .l_start = 0,
        .l_len = 0,
    };

    if (lock_fd >= 0)
        return 0;

    tpm_state_path = SWTPM_NVRAM_Uri_to_Dir(backend_uri);

    if (asprintf(&lockfile, "%s/.lock", tpm_state_path) < 0) {
        logprintf(STDERR_FILENO,
                  "SWTPM_NVRAM_Lock_Dir: Could not asprintf lock filename\n");
        return TPM_FAIL;
    }

    lock_fd = open(lockfile, O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW, 0660);
    if (lock_fd < 0) {
        logprintf(STDERR_FILENO,
                  "SWTPM_NVRAM_Lock_Dir: Could not open lockfile: %s\n",
                  strerror(errno));
        rc = TPM_FAIL;
        goto exit;
    }

    if (fcntl(lock_fd, F_SETLK, &flock) < 0) {
        logprintf(STDERR_FILENO,
                  "SWTPM_NVRAM_Lock_Dir: Could not lock access to lockfile: %s\n",
                  strerror(errno));
        rc = TPM_FAIL;
        SWTPM_NVRAM_Unlock_Dir();
    }
exit:
    free(lockfile);

    return rc;
}

static TPM_RESULT
SWTPM_NVRAM_GetFilepathForName(char *filepath,       /* output: rooted file path */
                               size_t bufsize,
                               uint32_t tpm_number,
                               const char *name,     /* input: abstract name */
                               TPM_BOOL is_tempfile, /* input: is temporary file? */
                               const char *tpm_state_path)
{
    TPM_RESULT rc = 0;
    int n;
    char filename[FILENAME_MAX];

    if (rc == 0)
        rc = SWTPM_NVRAM_GetFilenameForName(filename, sizeof(filename),
                                            tpm_number, name, is_tempfile);
    if (rc == 0) {
        n = snprintf(filepath, bufsize, "%s/%s", tpm_state_path, filename);
        if ((size_t) n > bufsize)
            rc = TPM_FAIL;
    }

    return rc;
}

static TPM_RESULT
SWTPM_NVRAM_CheckState_Dir(const char *uri,
                           const char *name,
                           size_t *blobsize)
{
    TPM_RESULT    rc = 0;
    char          filepath[FILENAME_MAX]; /* rooted file path from name */
    struct stat   statbuf;
    const char   *tpm_state_path = NULL;
    uint32_t      tpm_number = 0;
    int           rc2;

    tpm_state_path = SWTPM_NVRAM_Uri_to_Dir(uri);
    if (rc == 0) {
        /* map name to the rooted file path */
        rc = SWTPM_NVRAM_GetFilepathForName(filepath, sizeof(filepath),
                                            tpm_number, name, false,
                                            tpm_state_path);
    }

    if (rc == 0) {
        rc2 = stat(filepath, &statbuf);
        if (rc2 != 0 && errno == ENOENT)
            rc = TPM_RETRY;
        else if (rc2 != 0)
            rc = TPM_FAIL;
        else if (!S_ISREG(statbuf.st_mode))
            rc = TPM_FAIL;

        if (rc == 0)
            *blobsize = statbuf.st_size;
    }

    return rc;
}

static TPM_RESULT
SWTPM_NVRAM_Prepare_Dir(const char *uri)
{
    TPM_RESULT    rc = 0;
    const char *tpm_state_path = NULL;

    tpm_state_path = SWTPM_NVRAM_Uri_to_Dir(uri);
    if (rc == 0)
        rc = SWTPM_NVRAM_Validate_Dir(tpm_state_path);

    return rc;
}

static void
SWTPM_NVRAM_Cleanup_Dir(void)
{
    SWTPM_NVRAM_Unlock_Dir();
}

static TPM_RESULT
SWTPM_NVRAM_LoadData_Dir(unsigned char **data,
                         uint32_t *length,
                         uint32_t tpm_number,
                         const char *name,
                         const char *uri)
{
    TPM_RESULT    rc = 0;
    int           irc;
    size_t        src;
    int           fd = -1;
    char          filepath[FILENAME_MAX]; /* rooted file path from name */
    struct stat   statbuf;
    const char    *tpm_state_path = NULL;

    tpm_state_path = SWTPM_NVRAM_Uri_to_Dir(uri);

    if (rc == 0) {
        /* map name to the rooted file path */
        rc = SWTPM_NVRAM_GetFilepathForName(filepath, sizeof(filepath),
                                            tpm_number, name, false,
                                            tpm_state_path);
    }

    /* open the file */
    if (rc == 0) {
        TPM_DEBUG("  SWTPM_NVRAM_LoadData: Opening file %s\n", filepath);
        fd = open(filepath, O_RDONLY);                          /* closed @1 */
        if (fd < 0) {     /* if failure, determine cause */
            if (errno == ENOENT) {
                TPM_DEBUG("SWTPM_NVRAM_LoadData: No such file %s\n",
                         filepath);
                rc = TPM_RETRY;         /* first time start up */
            }
            else {
                logprintf(STDERR_FILENO,
                          "SWTPM_NVRAM_LoadData: Error (fatal) opening "
                          "%s for read, %s\n", filepath, strerror(errno));
                rc = TPM_FAIL;
            }
        }
    }

    if (rc == 0) {
        if (fchmod(fd, tpmstate_get_mode()) < 0) {
            logprintf(STDERR_FILENO,
                      "SWTPM_NVRAM_LoadData: Could not fchmod %s : %s\n",
                      filepath, strerror(errno));
            rc = TPM_FAIL;
        }
    }

    /* determine the file length */
    if (rc == 0) {
        irc = fstat(fd, &statbuf);
        if (irc == -1L) {
            logprintf(STDERR_FILENO,
                      "SWTPM_NVRAM_LoadData: Error (fatal) fstat'ing %s, %s\n",
                      filepath, strerror(errno));
            rc = TPM_FAIL;
        }
    }
    if (rc == 0) {
        *length = statbuf.st_size;              /* save the length */
    }
    /* allocate a buffer for the actual data */
    if ((rc == 0) && *length != 0) {
        TPM_DEBUG(" SWTPM_NVRAM_LoadData: Reading %u bytes of data\n", *length);
        *data = malloc(*length);
        if (!*data) {
            logprintf(STDERR_FILENO,
                      "SWTPM_NVRAM_LoadData: Error (fatal) allocating %u "
                      "bytes\n", *length);
            rc = TPM_FAIL;
        }
    }
    /* read the contents of the file into the data buffer */
    if ((rc == 0) && *length != 0) {
        src = read(fd, *data, *length);
        if (src != *length) {
            logprintf(STDERR_FILENO,
                      "SWTPM_NVRAM_LoadData: Error (fatal), data read of %u "
                      "only read %lu\n", *length, (unsigned long)src);
            rc = TPM_FAIL;
        }
    }
    /* close the file */
    if (fd >= 0) {
        TPM_DEBUG(" SWTPM_NVRAM_LoadData: Closing file %s\n", filepath);
        irc = close(fd);               /* @1 */
        if (irc != 0) {
            logprintf(STDERR_FILENO,
                      "SWTPM_NVRAM_LoadData: Error (fatal) closing file %s\n",
                      filepath);
            rc = TPM_FAIL;
        }
        else {
            TPM_DEBUG(" SWTPM_NVRAM_LoadData: Closed file %s\n", filepath);
        }
    }

    return rc;
}

static TPM_RESULT
SWTPM_NVRAM_StoreData_Dir(unsigned char *filedata,
                          uint32_t filedata_length,
                          uint32_t tpm_number,
                          const char *name,
                          const char *uri)
{
    TPM_RESULT    rc = 0;
    int           fd = -1;
    int           dir_fd = -1;
    uint32_t      lrc;
    int           irc;
    char          tmpfile[FILENAME_MAX];  /* rooted temporary file path */
    char          filepath[FILENAME_MAX]; /* rooted file path from name */
    const char    *tpm_state_path = NULL;

#if 0
    static bool   do_dir_fsync = true; /* turn off fsync on dir if it fails,
                                          most likely due to AppArmor */
#endif
    /* don't do fsync on dir since this may cause TPM command timeouts */
    static bool   do_dir_fsync = false;

    tpm_state_path = SWTPM_NVRAM_Uri_to_Dir(uri);

    if (rc == 0) {
        /* map name to the rooted file path */
        rc = SWTPM_NVRAM_GetFilepathForName(filepath, sizeof(filepath),
                                            tpm_number, name, false,
                                            tpm_state_path);
    }

    if (rc == 0) {
        /* map name to the rooted temporary file path */
        rc = SWTPM_NVRAM_GetFilepathForName(tmpfile, sizeof(tmpfile),
                                            tpm_number, name, true,
                                            tpm_state_path);
    }

    if (rc == 0) {
        /* open the file */
        TPM_DEBUG(" SWTPM_NVRAM_StoreData: Opening file %s\n", tmpfile);
        fd = open(tmpfile, O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW,
                  tpmstate_get_mode());                        /* closed @1 */
        if (fd < 0) {
            logprintf(STDERR_FILENO,
                      "SWTPM_NVRAM_StoreData: Error (fatal) opening %s for "
                      "write failed, %s\n", tmpfile, strerror(errno));
            rc = TPM_FAIL;
        }
    }

    /* write the data to the file */
    if (rc == 0) {
        TPM_DEBUG("  SWTPM_NVRAM_StoreData: Writing %u bytes of data\n",
                  filedata_length);
        lrc = write_full(fd, filedata, filedata_length);
        if (lrc != filedata_length) {
            logprintf(STDERR_FILENO,
                      "SWTPM_NVRAM_StoreData: Error (fatal), data write "
                      "of %u only wrote %u\n", filedata_length, lrc);
            rc = TPM_FAIL;
        }
    }
#if 0 // disabled due to triggering TPM timeouts
    if (rc == 0 && fd >= 0) {
        TPM_DEBUG("  SWTPM_NVRAM_StoreData: Syncing file %s\n", tmpfile);
        irc = fsync(fd);
        if (irc != 0) {
            logprintf(STDERR_FILENO,
                      "SWTPM_NVRAM_StoreData: Error (fatal) syncing file, %s\n",
                      strerror(errno));
            rc = TPM_FAIL;
        } else {
            TPM_DEBUG("  SWTPM_NVRAM_StoreData: Synced file %s\n", tmpfile);
        }
    }
#endif
    if (fd >= 0) {
        TPM_DEBUG("  SWTPM_NVRAM_StoreData: Closing file %s\n", tmpfile);
        irc = close(fd);             /* @1 */
        if (irc != 0) {
            logprintf(STDERR_FILENO,
                      "SWTPM_NVRAM_StoreData: Error (fatal) closing file\n");
            rc = TPM_FAIL;
        }
        else {
            TPM_DEBUG("  SWTPM_NVRAM_StoreData: Closed file %s\n", tmpfile);
        }
    }

    if (rc == 0 && fd >= 0) {
        irc = rename(tmpfile, filepath);
        if (irc != 0) {
            logprintf(STDERR_FILENO,
                      "SWTPM_NVRAM_StoreData: Error (fatal) renaming file: %s\n",
                      strerror(errno));
            rc = TPM_FAIL;
        } else {
            TPM_DEBUG("  SWTPM_NVRAM_StoreData: Renamed file to %s\n", filepath);
        }
    }

    /*
     * Quote from linux man 2 fsync:
     *  Calling fsync() does not necessarily ensure that the entry in the
     *  directory containing the file has also reached disk. For that an
     *  explicit fsync() on a file descriptor for the directory is also needed.
     */
    if (rc == 0 && fd >= 0 && do_dir_fsync) {
        TPM_DEBUG(" SWTPM_NVRAM_StoreData: Opening dir %s\n", tpm_state_path);
        dir_fd = open(tpm_state_path, O_RDONLY);
        if (dir_fd < 0) {
            do_dir_fsync = false;
            logprintf(STDERR_FILENO,
                      "SWTPM_NVRAM_StoreData: Error opening %s for "
                      "fsync failed, %s. Continuing but check AppArmor profile.\n",
                      tpm_state_path, strerror(errno));
        }
    }
    if (rc == 0 && dir_fd >= 0) {
        TPM_DEBUG("  SWTPM_NVRAM_StoreData: Syncing dir %s\n", tpm_state_path);
        irc = fsync(dir_fd);
        if (irc != 0) {
            logprintf(STDERR_FILENO,
                      "SWTPM_NVRAM_StoreData: Error (fatal) syncing dir, %s\n",
                      strerror(errno));
            rc = TPM_FAIL;
        } else {
            TPM_DEBUG("  SWTPM_NVRAM_StoreData: Synced dir %s\n", tpm_state_path);
        }
    }
    if (dir_fd >= 0) {
        TPM_DEBUG("  SWTPM_NVRAM_StoreData: Closing dir %s\n", tpm_state_path);
        irc = close(dir_fd);
        if (irc != 0) {
            logprintf(STDERR_FILENO,
                      "SWTPM_NVRAM_StoreData: Error (fatal) closing dir\n");
            rc = TPM_FAIL;
        } else {
            TPM_DEBUG("  SWTPM_NVRAM_StoreData: Closed dir %s\n", tpm_state_path);
        }
    }

    if (rc != 0 && fd >= 0) {
        unlink(tmpfile);
    }

    return rc;
}

static TPM_RESULT
SWTPM_NVRAM_DeleteName_Dir(uint32_t tpm_number,
                           const char *name,
                           TPM_BOOL mustExist,
                           const char *uri)
{
    TPM_RESULT  rc = 0;
    int         irc;
    char        filepath[FILENAME_MAX]; /* rooted file path from name */
    const char  *tpm_state_path = NULL;

    tpm_state_path = SWTPM_NVRAM_Uri_to_Dir(uri);

    TPM_DEBUG(" SWTPM_NVRAM_DeleteName: Name %s\n", name);
    /* map name to the rooted file path */
    rc = SWTPM_NVRAM_GetFilepathForName(filepath, sizeof(filepath),
                                        tpm_number, name, false,
                                        tpm_state_path);
    if (rc == 0) {
        irc = remove(filepath);
        if ((irc != 0) &&               /* if the remove failed */
            (mustExist ||               /* if any error is a failure, or */
             (errno != ENOENT))) {      /* if error other than no such file */
            logprintf(STDERR_FILENO,
                      "SWTPM_NVRAM_DeleteName: Error, (fatal) file "
                      "remove failed, errno %d\n", errno);
            rc = TPM_FAIL;
        }
    }
    return rc;
}

struct nvram_backend_ops nvram_dir_ops = {
    .prepare = SWTPM_NVRAM_Prepare_Dir,
    .lock    = SWTPM_NVRAM_Lock_Dir,
    .load    = SWTPM_NVRAM_LoadData_Dir,
    .store   = SWTPM_NVRAM_StoreData_Dir,
    .delete  = SWTPM_NVRAM_DeleteName_Dir,
    .cleanup = SWTPM_NVRAM_Cleanup_Dir,
    .check_state = SWTPM_NVRAM_CheckState_Dir,
};
