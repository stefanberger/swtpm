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
#include <libtpms/tpm_nvfilename.h>

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
SWTPM_NVRAM_Lock_Dir(const char *backend_uri, unsigned int retries)
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

    while (1) {
        if (fcntl(lock_fd, F_SETLK, &flock) == 0)
            break;
        if (retries == 0) {
            rc = TPM_FAIL;
            SWTPM_NVRAM_Unlock_Dir();
            break;
        }
        retries--;
        usleep(10000);
    }
    if (rc == TPM_FAIL)
        logprintf(STDERR_FILENO,
                  "SWTPM_NVRAM_Lock_Dir: Could not lock access to lockfile: %s\n",
                  strerror(errno));

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
    bool          mode_is_default = false;
    bool          do_chmod;
    mode_t        mode;

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

    if (rc == 0) {
        mode = tpmstate_get_mode(&mode_is_default);
        /*
         * Make sure the file can be written to when state needs to be written.
         * Do not touch user-provided flags.
         */
        do_chmod = !mode_is_default;
        if (mode_is_default && (statbuf.st_mode & 0200) == 0) {
           mode |= 0200;
           do_chmod = true;
        }
        if (do_chmod && fchmod(fd, mode) < 0) {
            logprintf(STDERR_FILENO,
                      "SWTPM_NVRAM_LoadData: Could not fchmod %s : %s\n",
                      filepath, strerror(errno));
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
SWTPM_NVRAM_CreateBackupFilename(const char *filepath,
                                 char *bakfile,
                                 size_t bakfile_len,
                                 const char *suffix)
{
    TPM_RESULT rc = 0;
    int        irc;

    irc = snprintf(bakfile, bakfile_len, "%s.%s", filepath, suffix);
    if ((size_t)irc > bakfile_len) {
        logprintf(STDERR_FILENO,
                  "SWTPM_NVRAM_StoreData: Name of backup file is too long\n");
        rc = TPM_FAIL;
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
    uint32_t      lrc;
    int           irc;
    char          tmpfile[FILENAME_MAX];  /* rooted temporary file path */
    char          filepath[FILENAME_MAX]; /* rooted file path from name */
    char          bakfile[FILENAME_MAX];  /* rooted backup file name */
    const char    *tpm_state_path = NULL;
    bool          mode_is_default = true;
    bool          revertable_backup = false;
    mode_t        mode;
    mode_t        orig_umask = 0;

    tpm_state_path = SWTPM_NVRAM_Uri_to_Dir(uri);

    if (rc == 0) {
        /* map name to the rooted file path */
        rc = SWTPM_NVRAM_GetFilepathForName(filepath, sizeof(filepath),
                                            tpm_number, name, false,
                                            tpm_state_path);
    }

    if (rc == 0 &&
        tpmstate_get_make_backup() &&
        strcmp(name, TPM_PERMANENT_ALL_NAME) == 0 &&
        access(filepath, F_OK) == 0) {
        /* rename current permanent state file to backup file */
        rc = SWTPM_NVRAM_CreateBackupFilename(filepath,
                                              bakfile, sizeof(bakfile),
                                              "bak");
        if (rc == 0) {
            irc = rename(filepath, bakfile);
            if (irc != 0) {
                logprintf(STDERR_FILENO,
                          "SWTPM_NVRAM_StoreData: Error (fatal) renaming to backup file: %s\n",
                          strerror(errno));
                rc = TPM_FAIL;
            } else {
                revertable_backup = true;
            }
        }
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

        /*
         * If a new file is created at this point with user-requested mode bits
         * then use a temporary umask of 0 to have these mode bits set.
         * In the more frequent file truncation case the mode bits will also be
         * changed to what the user requested.
         */
        mode = tpmstate_get_mode(&mode_is_default);
        if (!mode_is_default)
            orig_umask = umask(0);

        fd = open(tmpfile, O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW,
                  mode);                                       /* closed @1 */

        if (!mode_is_default)
            umask(orig_umask);

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

    if (fd >= 0) {
        TPM_DEBUG("  SWTPM_NVRAM_StoreData: Closing file %s\n", tmpfile);
        irc = close(fd);             /* @1 */
        if (irc != 0) {
            logprintf(STDERR_FILENO,
                      "SWTPM_NVRAM_StoreData: Error (fatal) closing file\n");
            rc = TPM_FAIL;
        } else {
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
            revertable_backup = false;
        }
    }

    if (rc != 0 && fd >= 0) {
        unlink(tmpfile);
    }

    if (revertable_backup) {
        rename(bakfile, filepath);
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

/*
 * Try to restore the backup file if the 'normal' permanent state file does not
 * exist. This function will return an error if the backup file exists and the
 * 'normal' permanent state file does not exist but the renaming of the backup
 * file to the 'normal' permanent state file fails.
 * This function must be called before the state is first accessed so that no
 * new state is created due to a missing 'normal' permanent state file.
 */
static TPM_RESULT
SWTPM_NVRAM_RestoreBackupPreStart_Dir(const char *uri)
{
    TPM_RESULT    rc = 0;
    int           irc;
    char          filepath[FILENAME_MAX]; /* rooted file path from name */
    char          bakfile[FILENAME_MAX];  /* rooted backup file name */
    const char    *tpm_state_path;

    tpm_state_path = SWTPM_NVRAM_Uri_to_Dir(uri);

    rc = SWTPM_NVRAM_GetFilepathForName(filepath, sizeof(filepath),
                                        0, TPM_PERMANENT_ALL_NAME, false,
                                        tpm_state_path);

    if (rc == 0) {
        irc = access(filepath, F_OK);
        if (irc < 0 && errno == ENOENT) {
            /* permanent state file does not exist */
            rc = SWTPM_NVRAM_CreateBackupFilename(filepath,
                                                  bakfile, sizeof(bakfile),
                                                  "bak");
            if (rc == 0 &&
                access(bakfile, F_OK) == 0) {
                irc = rename(bakfile, filepath);
                if (irc < 0) {
                    logprintf(STDERR_FILENO,
                              "SWTPM_NVRAM_RestoreBackupPreStart_Dir: Restoring backup file failed: %s\n",
                              strerror(errno));
                    rc = TPM_FAIL;
                }
            }
        }
    }
    return rc;
}

/*
 * Restore the permanent state backup file in such a way that the 'original'
 * file is preserved and a 2nd call to this function will revert everything to
 * the original state if the first call to this function succeeded. An exception
 * is if the 'original' file did not exist. In this case the backup file will
 * become the permanent state file.
 *
 * If no permanent state backup file exists or it cannot be restored for any
 * other reason, then this function will return an error.
 */
static TPM_RESULT
SWTPM_NVRAM_RestoreBackup_Dir(const char *uri)
{
    TPM_RESULT    rc = 0;
    int           irc;
    int           access_res;
    char          filepath[FILENAME_MAX]; /* rooted file path from name */
    char          bakfile[FILENAME_MAX];  /* rooted backup file name */
    char          bakfile2[FILENAME_MAX];  /* rooted backup file name */
    const char    *tpm_state_path;

    tpm_state_path = SWTPM_NVRAM_Uri_to_Dir(uri);

    rc = SWTPM_NVRAM_GetFilepathForName(filepath, sizeof(filepath),
                                        0, TPM_PERMANENT_ALL_NAME, false,
                                        tpm_state_path);
    if (rc == 0) {
        rc = SWTPM_NVRAM_CreateBackupFilename(filepath,
                                              bakfile, sizeof(bakfile),
                                              "bak");
    }

    if (rc == 0) {
        rc = SWTPM_NVRAM_CreateBackupFilename(filepath,
                                              bakfile2, sizeof(bakfile2),
                                              "tmp");
    }

    if (rc == 0 && access(bakfile, F_OK) != 0) {
        logprintf(STDERR_FILENO,
                  "SWTPM_NVRAM_RestoreBackup_Dir: Backup file cannot be restored: %s\n",
                  strerror(errno));
        rc = TPM_FAIL;
    }

    if (rc == 0) {
        access_res = access(filepath, F_OK);
        if (access_res == 0) {
            /* rename 'original' file to bakfile2 */
            irc = rename(filepath, bakfile2); /* @1 */
            if (irc < 0) {
                logprintf(STDERR_FILENO,
                          "SWTPM_NVRAM_RestoreBackup_Dir: 'Original' file cannot be renamed.\n");
                rc = TPM_FAIL;
            }
        }
    }

    if (rc == 0 && rename(bakfile, filepath) != 0) {  /* @2 */
        /* backup file could not be renamed */
        logprintf(STDERR_FILENO,
                  "SWTPM_NVRAM_RestoreBackup_Dir: Error (fatal) renaming from backup file: %s\n",
                  strerror(errno));
        if (access_res == 0)
            rename(bakfile2, filepath); /* revert rename @1 */
        rc = TPM_FAIL;
    }

    if (rc == 0) {
        irc = rename(bakfile2, bakfile);
        if (irc < 0) {
            rename(filepath, bakfile); /* revert @2 */
            rename(bakfile2, filepath);/* revert @1 */
        }
    }

    return rc;
}

struct nvram_backend_ops nvram_dir_ops = {
    .prepare = SWTPM_NVRAM_Prepare_Dir,
    .lock    = SWTPM_NVRAM_Lock_Dir,
    .unlock  = SWTPM_NVRAM_Unlock_Dir,
    .load    = SWTPM_NVRAM_LoadData_Dir,
    .store   = SWTPM_NVRAM_StoreData_Dir,
    .delete  = SWTPM_NVRAM_DeleteName_Dir,
    .cleanup = SWTPM_NVRAM_Cleanup_Dir,
    .check_state    = SWTPM_NVRAM_CheckState_Dir,
    .restore_backup = SWTPM_NVRAM_RestoreBackup_Dir,
    .restore_backup_pre_start = SWTPM_NVRAM_RestoreBackupPreStart_Dir,
};
