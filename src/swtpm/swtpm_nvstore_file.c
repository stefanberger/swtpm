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
#include "swtpm_nvstore_file.h"
#include "key.h"
#include "logging.h"
#include "tpmstate.h"
#include "utils.h"

struct nvram_backend_ops nvram_file_ops = {
    .prepare = SWTPM_NVRAM_Prepare_File,
    .load    = SWTPM_NVRAM_LoadData_File,
    .store   = SWTPM_NVRAM_StoreData_File,
    .delete  = SWTPM_NVRAM_DeleteName_File,
};

/* SWTPM_NVRAM_GetFilenameForName() constructs a rooted file name from the name.

   The filename is of the form:

   state_directory/tpm_number.name

   A temporary filename used to write to may be created. It shold be rename()'d to
   the non-temporary filename.
*/

static TPM_RESULT
SWTPM_NVRAM_GetFilenameForName(char *filename,      /* output: rooted filename */
                               size_t bufsize,
                               uint32_t tpm_number,
                               const char *name,    /* input: abstract name */
                               bool is_tempfile,    /* input: is temporary file? */
                               const char *uri)     /* input: backend uri = dir path */
{
    TPM_RESULT res = TPM_SUCCESS;
    int n;
    const char *suffix = "";
    const char *state_dir = uri;

    TPM_DEBUG(" SWTPM_NVRAM_GetFilenameForName: For name %s\n", name);

    switch (tpmstate_get_version()) {
    case TPMLIB_TPM_VERSION_1_2:
        break;
    case TPMLIB_TPM_VERSION_2:
        suffix = "2";
        break;
    }

    if (is_tempfile) {
        n = snprintf(filename, bufsize, "%s/TMP%s-%02lx.%s",
                     state_dir, suffix, (unsigned long)tpm_number, name);
    } else {
        n = snprintf(filename, bufsize, "%s/tpm%s-%02lx.%s",
                     state_dir, suffix, (unsigned long)tpm_number, name);
    }
    if ((size_t)n > bufsize) {
        res = TPM_FAIL;
    }

    TPM_DEBUG("  SWTPM_NVRAM_GetFilenameForName: File name %s\n", filename);

    return res;
}

static TPM_RESULT
SWTPM_NVRAM_Validate_File(const char *uri)
{
    TPM_RESULT  rc = 0;
    const char  *tpm_state_path;
    size_t      length;

    /* TPM_NV_DISK TPM emulation stores in local directory determined by environment variable. */
    if (rc == 0) {
        tpm_state_path = uri;
        if (tpm_state_path == NULL) {
            logprintf(STDERR_FILENO,
                      "SWTPM_NVRAM_Validate_File: Error (fatal), TPM_PATH environment "
                      "variable not set\n");
            rc = TPM_FAIL;
        }
    }

    /* check that the directory name plus a file name will not overflow FILENAME_MAX */
    if (rc == 0) {
        length = strlen(tpm_state_path);
        if ((length + TPM_FILENAME_MAX) > FILENAME_MAX) {
            logprintf(STDERR_FILENO,
                      "SWTPM_NVRAM_Validate_File: Error (fatal), TPM state path name "
                      "%s too large\n", tpm_state_path);
            rc = TPM_FAIL;
        }
    }
    if (rc == 0)
        TPM_DEBUG("SWTPM_NVRAM_Validate_File: Rooted state path %s\n", tpm_state_path);

    return rc;
}

static TPM_RESULT
SWTPM_NVRAM_Lock_File(const char *uri)
{
    TPM_RESULT rc = 0;
    int fd;
    char *lockfile = NULL;
    struct flock flock = {
        .l_type = F_WRLCK,
        .l_whence = SEEK_SET,
        .l_start = 0,
        .l_len = 0,
    };

    if (asprintf(&lockfile, "%s/.lock", uri) < 0) {
        logprintf(STDERR_FILENO,
                  "SWTPM_NVRAM_Lock_Lockfile: Could not asprintf lock filename\n");
        return TPM_FAIL;
    }

    fd = open(lockfile, O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW, 0660);
    if (fd < 0) {
        logprintf(STDERR_FILENO,
                  "SWTPM_NVRAM_Lock_Lockfile: Could not open lockfile: %s\n",
                  strerror(errno));
        rc = TPM_FAIL;
        goto exit;
    }

    if (fcntl(fd, F_SETLK, &flock) < 0) {
        logprintf(STDERR_FILENO,
                  "SWTPM_NVRAM_Lock_Lockfile: Could not lock access to lockfile: %s\n",
                  strerror(errno));
        rc = TPM_FAIL;
        close(fd);
    }
exit:
    free(lockfile);

    return rc;
}

TPM_RESULT
SWTPM_NVRAM_Prepare_File(const char *uri)
{
    TPM_RESULT    rc = 0;

    if (rc == 0)
        rc = SWTPM_NVRAM_Validate_File(uri);
    if (rc == 0)
        rc = SWTPM_NVRAM_Lock_File(uri);

    return rc;
}

TPM_RESULT
SWTPM_NVRAM_LoadData_File(unsigned char **data,
                          uint32_t *length,
                          uint32_t tpm_number,
                          const char *name,
                          const char *uri)
{
    TPM_RESULT    rc = 0;
    int           irc;
    size_t        src;
    int           fd = -1;
    char          filename[FILENAME_MAX]; /* rooted file name from name */
    struct stat   statbuf;

    /* open the file */
    if (rc == 0) {
        /* map name to the rooted filename */
        rc = SWTPM_NVRAM_GetFilenameForName(filename, sizeof(filename),
                                            tpm_number, name, false, uri);
    }

    if (rc == 0) {
        TPM_DEBUG("  SWTPM_NVRAM_LoadData: Opening file %s\n", filename);
        fd = open(filename, O_RDONLY);                          /* closed @1 */
        if (fd < 0) {     /* if failure, determine cause */
            if (errno == ENOENT) {
                TPM_DEBUG("SWTPM_NVRAM_LoadData: No such file %s\n",
                         filename);
                rc = TPM_RETRY;         /* first time start up */
            }
            else {
                logprintf(STDERR_FILENO,
                          "SWTPM_NVRAM_LoadData: Error (fatal) opening "
                          "%s for read, %s\n", filename, strerror(errno));
                rc = TPM_FAIL;
            }
        }
    }

    if (rc == 0) {
        if (fchmod(fd, tpmstate_get_mode()) < 0) {
            logprintf(STDERR_FILENO,
                      "SWTPM_NVRAM_LoadData: Could not fchmod %s : %s\n",
                      filename, strerror(errno));
            rc = TPM_FAIL;
        }
    }

    /* determine the file length */
    if (rc == 0) {
        irc = fstat(fd, &statbuf);
        if (irc == -1L) {
            logprintf(STDERR_FILENO,
                      "SWTPM_NVRAM_LoadData: Error (fatal) fstat'ing %s, %s\n",
                      filename, strerror(errno));
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
        TPM_DEBUG(" SWTPM_NVRAM_LoadData: Closing file %s\n", filename);
        irc = close(fd);               /* @1 */
        if (irc != 0) {
            logprintf(STDERR_FILENO,
                      "SWTPM_NVRAM_LoadData: Error (fatal) closing file %s\n",
                      filename);
            rc = TPM_FAIL;
        }
        else {
            TPM_DEBUG(" SWTPM_NVRAM_LoadData: Closed file %s\n", filename);
        }
    }

    return rc;
}

TPM_RESULT
SWTPM_NVRAM_StoreData_File(unsigned char *filedata,
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
    char          tmpfile[FILENAME_MAX];  /* rooted temporary file */
    char          filename[FILENAME_MAX]; /* rooted file name from name */
    const char    *direname;

    if (rc == 0) {
        /* map name to the rooted filename */
        rc = SWTPM_NVRAM_GetFilenameForName(filename, sizeof(filename),
                                            tpm_number, name, false, uri);
    }

    if (rc == 0) {
        /* map name to the rooted temporary file */
        rc = SWTPM_NVRAM_GetFilenameForName(tmpfile, sizeof(tmpfile),
                                            tpm_number, name, true, uri);
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
        irc = rename(tmpfile, filename);
        if (irc != 0) {
            logprintf(STDERR_FILENO,
                      "SWTPM_NVRAM_StoreData: Error (fatal) renaming file: %s\n",
                      strerror(errno));
            rc = TPM_FAIL;
        } else {
            TPM_DEBUG("  SWTPM_NVRAM_StoreData: Renamed file to %s\n", filename);
        }
    }

    direname = uri;
    /*
     * Quote from linux man 2 fsync:
     *  Calling fsync() does not necessarily ensure that the entry in the
     *  directory containing the file has also reached disk. For that an
     *  explicit fsync() on a file descriptor for the directory is also needed.
     */
    if (rc == 0 && fd >= 0) {
        TPM_DEBUG(" SWTPM_NVRAM_StoreData: Opening dir %s\n", direname);
        dir_fd = open(direname, O_RDONLY);
        if (dir_fd < 0) {
            logprintf(STDERR_FILENO,
                      "SWTPM_NVRAM_StoreData: Error (fatal) opening %s for "
                      "fsync failed, %s\n", direname, strerror(errno));
            rc = TPM_FAIL;
        }
    }
    if (rc == 0 && dir_fd >= 0) {
        TPM_DEBUG("  SWTPM_NVRAM_StoreData: Syncing dir %s\n", direname);
        irc = fsync(dir_fd);
        if (irc != 0) {
            logprintf(STDERR_FILENO,
                      "SWTPM_NVRAM_StoreData: Error (fatal) syncing dir, %s\n",
                      strerror(errno));
            rc = TPM_FAIL;
        } else {
            TPM_DEBUG("  SWTPM_NVRAM_StoreData: Synced dir %s\n", direname);
        }
    }
    if (dir_fd >= 0) {
        TPM_DEBUG("  SWTPM_NVRAM_StoreData: Closing dir %s\n", direname);
        irc = close(dir_fd);
        if (irc != 0) {
            logprintf(STDERR_FILENO,
                      "SWTPM_NVRAM_StoreData: Error (fatal) closing dir\n");
            rc = TPM_FAIL;
        } else {
            TPM_DEBUG("  SWTPM_NVRAM_StoreData: Closed dir %s\n", direname);
        }
    }

    if (rc != 0 && fd >= 0) {
        unlink(tmpfile);
    }

    return rc;
}

TPM_RESULT SWTPM_NVRAM_DeleteName_File(uint32_t tpm_number,
                                  const char *name,
                                  TPM_BOOL mustExist,
                                  const char *uri)
{
    TPM_RESULT  rc = 0;
    int         irc;
    char        filename[FILENAME_MAX]; /* rooted file name from name */

    TPM_DEBUG(" SWTPM_NVRAM_DeleteName: Name %s\n", name);
    /* map name to the rooted filename */
    rc = SWTPM_NVRAM_GetFilenameForName(filename, sizeof(filename),
                                        tpm_number, name, false, uri);
    if (rc == 0) {
        irc = remove(filename);
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
