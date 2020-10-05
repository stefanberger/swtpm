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

/* This module abstracts out all NVRAM read and write operations.

   This implementation uses standard, portable C files.

   The basic high level abstractions are:

        SWTPM_NVRAM_LoadData();
        SWTPM_NVRAM_StoreData();
        SWTPM_NVRAM_DeleteName();

   They take a 'name' that is mapped to a rooted file name.
*/

#include "config.h"

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <fcntl.h>

#include <libtpms/tpm_error.h>
#include <libtpms/tpm_memory.h>
#include <libtpms/tpm_nvfilename.h>
#include <libtpms/tpm_library.h>

#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#if defined(__OpenBSD__)
 # define OPENSSL_OLD_API
#else
 #if OPENSSL_VERSION_NUMBER < 0x10100000
  #define OPENSSL_OLD_API
 #endif
#endif

#include "swtpm.h"
#include "swtpm_aes.h"
#include "swtpm_debug.h"
#include "swtpm_nvfile.h"
#include "key.h"
#include "logging.h"
#include "tpmstate.h"
#include "tpmlib.h"
#include "tlv.h"

/* local structures */
typedef struct {
    uint8_t  version;
    uint8_t  min_version; /* min. required version */
    uint16_t hdrsize;
    uint16_t flags;
    uint32_t totlen; /* length of the header and following data */
} __attribute__((packed)) blobheader;

#define BLOB_HEADER_VERSION 2

/* flags for blobheader */
#define BLOB_FLAG_ENCRYPTED              0x01
#define BLOB_FLAG_MIGRATION_ENCRYPTED    0x02  /* encrypted with migration key */
#define BLOB_FLAG_MIGRATION_DATA         0x04  /* migration data are available */
#define BLOB_FLAG_ENCRYPTED_256BIT_KEY   0x08  /* 256 bit file key was used */
#define BLOB_FLAG_MIGRATION_256BIT_KEY   0x10  /* 256 bit migration key was used */

typedef struct {
    enum encryption_mode data_encmode;
    TPM_SYMMETRIC_KEY_DATA symkey;
} encryptionkey ;

static encryptionkey filekey = {
    .symkey = {
        .userKeyLength = 0,
    },
};

static encryptionkey migrationkey = {
    .symkey = {
        .userKeyLength = 0,
    },
};

static uint32_t g_ivec_length;
static unsigned char *g_ivec;

/* local prototypes */

static TPM_RESULT SWTPM_NVRAM_GetFilenameForName(char *filename,
                                                 size_t bufsize,
                                                  uint32_t tpm_number,
                                                 const char *name,
                                                 bool is_tempfile);

static TPM_RESULT SWTPM_NVRAM_EncryptData(const encryptionkey *key,
                                          tlv_data *td,
                                          size_t *td_len,
                                          uint16_t tag_encrypted_data,
                                          const unsigned char *decrypt_data,
                                          uint32_t decrypt_length,
                                          uint16_t tag_ivec);

static TPM_RESULT SWTPM_NVRAM_GetDecryptedData(const encryptionkey *key,
                                               unsigned char **decrypt_data,
                                               uint32_t *decrypt_length,
                                               const unsigned char *encrypt_data,
                                               uint32_t encrypt_length,
                                               uint16_t tag_decryped_data,
                                               uint16_t tag_data,
                                               uint8_t hdrversion,
                                               uint16_t tag_ivec,
                                               uint16_t hdrflags,
                                               uint16_t flag_256bitkey);

static TPM_RESULT SWTPM_NVRAM_PrependHeader(unsigned char **data,
                                            uint32_t *length,
                                            uint16_t flags);

static TPM_RESULT SWTPM_NVRAM_CheckHeader(unsigned char *data, uint32_t length,
                                          uint32_t *dataoffset,
                                          uint16_t *hdrflags,
                                          uint8_t *hdrversion,
                                          bool quiet);

/* A file name in NVRAM is composed of 3 parts:

  1 - 'state_directory' is the rooted path to the TPM state home directory
  2 = 'tpm_number' is the TPM instance, 00 for a single TPM
  2 - the file name

  For the IBM cryptographic coprocessor version, the root path is hard coded.
  
  For the Linux and Windows versions, the path comes from an environment variable.  This variable is
  used once in TPM_NVRAM_Init().

  One root path is used for all virtual TPM's, so it can be a static variable.
*/

static int lockfile_fd = -1;

char state_directory[FILENAME_MAX];
static TPMLIB_TPMVersion tpmversion = TPMLIB_TPM_VERSION_1_2;

/*
 * SWTPM_NVRAM_Set_TPMVersion()  - set the version of the TPM being used
 */
void SWTPM_NVRAM_Set_TPMVersion(TPMLIB_TPMVersion version)
{
    tpmversion = version;
}

static TPM_RESULT SWTPM_NVRAM_Lock_Lockfile(const char *directory,
                                            int *fd)
{
    TPM_RESULT rc = 0;
    char *lockfile = NULL;
    struct flock flock = {
        .l_type = F_WRLCK,
        .l_whence = SEEK_SET,
        .l_start = 0,
        .l_len = 0,
    };

    if (asprintf(&lockfile, "%s/.lock", directory) < 0) {
        logprintf(STDERR_FILENO,
                  "SWTPM_NVRAM_Lock_Lockfile: Could not asprintf lock filename\n");
        return TPM_FAIL;
    }

    *fd = open(lockfile, O_WRONLY|O_CREAT|O_TRUNC, 0660);
    if (*fd < 0) {
        logprintf(STDERR_FILENO,
                  "SWTPM_NVRAM_Lock_Lockfile: Could not open lockfile: %s\n",
                  strerror(errno));
        rc = TPM_FAIL;
        goto exit;
    }

    if (fcntl(*fd, F_SETLK, &flock) < 0) {
        logprintf(STDERR_FILENO,
                  "SWTPM_NVRAM_Lock_Lockfile: Could not lock access to lockfile: %s\n",
                  strerror(errno));
        rc = TPM_FAIL;
        close(*fd);
        *fd = -1;
    }
exit:
    free(lockfile);

    return rc;
}

/* TPM_NVRAM_Init() is called once at startup.  It does any NVRAM required initialization.

   This function sets some static variables that are used by all TPM's.
*/

TPM_RESULT SWTPM_NVRAM_Init(void)
{
    TPM_RESULT  rc = 0;
    const char  *tpm_state_path;
    size_t      length;

    TPM_DEBUG(" SWTPM_NVRAM_Init:\n");

    /* TPM_NV_DISK TPM emulation stores in local directory determined by environment variable. */
    if (rc == 0) {
        tpm_state_path = tpmstate_get_dir();
        if (tpm_state_path == NULL) {
            logprintf(STDERR_FILENO,
                      "SWTPM_NVRAM_Init: Error (fatal), TPM_PATH environment "
                      "variable not set\n");
            rc = TPM_FAIL;
        }
    }

    /* check that the directory name plus a file name will not overflow FILENAME_MAX */
    if (rc == 0) {
        length = strlen(tpm_state_path);
        if ((length + TPM_FILENAME_MAX) > FILENAME_MAX) {
            logprintf(STDERR_FILENO,
                      "SWTPM_NVRAM_Init: Error (fatal), TPM state path name "
                      "%s too large\n", tpm_state_path);
            rc = TPM_FAIL;
        }
    }
    if (rc == 0) {
        strcpy(state_directory, tpm_state_path);
        TPM_DEBUG("TPM_NVRAM_Init: Rooted state path %s\n", state_directory);
    }

    if (rc == 0 && lockfile_fd < 0)
        rc = SWTPM_NVRAM_Lock_Lockfile(state_directory, &lockfile_fd);

    return rc;
}

/* Load 'data' of 'length' from the 'name'.

   'data' must be freed after use.
   
   Returns
        0 on success.
        TPM_RETRY and NULL,0 on non-existent file (non-fatal, first time start up)
        TPM_FAIL on failure to load (fatal), since it should never occur
*/

TPM_RESULT
SWTPM_NVRAM_LoadData(unsigned char **data,     /* freed by caller */
                     uint32_t *length,
                     uint32_t tpm_number,
                     const char *name)
{
    TPM_RESULT    rc = 0;
    long          lrc;
    size_t        src;
    int           irc;
    FILE          *file = NULL;
    char          filename[FILENAME_MAX]; /* rooted file name from name */
    unsigned char *decrypt_data = NULL;
    uint32_t      decrypt_length;
    uint32_t      dataoffset = 0;
    uint8_t       hdrversion = 0;
    uint16_t      hdrflags;

    TPM_DEBUG(" SWTPM_NVRAM_LoadData: From file %s\n", name);
    *data = NULL;
    *length = 0;
    /* open the file */
    if (rc == 0) {
        /* map name to the rooted filename */
        rc = SWTPM_NVRAM_GetFilenameForName(filename, sizeof(filename),
                                            tpm_number, name, false);
    }

    if (rc == 0) {
        TPM_DEBUG("  SWTPM_NVRAM_LoadData: Opening file %s\n", filename);
        file = fopen(filename, "rb");                           /* closed @1 */
        if (file == NULL) {     /* if failure, determine cause */
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
        if (fchmod(fileno(file), tpmstate_get_mode()) < 0) {
            logprintf(STDERR_FILENO,
                      "SWTPM_NVRAM_LoadData: Could not fchmod %s : %s\n",
                      filename, strerror(errno));
            rc = TPM_FAIL;
        }
    }

    /* determine the file length */
    if (rc == 0) {
        irc = fseek(file, 0L, SEEK_END);        /* seek to end of file */
        if (irc == -1L) {
            logprintf(STDERR_FILENO,
                      "SWTPM_NVRAM_LoadData: Error (fatal) fseek'ing %s, %s\n",
                      filename, strerror(errno));
            rc = TPM_FAIL;
        }
    }
    if (rc == 0) {
        lrc = ftell(file);                      /* get position in the stream */
        if (lrc == -1L) {
            logprintf(STDERR_FILENO,
                      "SWTPM_NVRAM_LoadData: Error (fatal) ftell'ing %s, %s\n",
                      filename, strerror(errno));
            rc = TPM_FAIL;
        }
        else {
            *length = (uint32_t)lrc;              /* save the length */
        }
    }
    if (rc == 0) {
        irc = fseek(file, 0L, SEEK_SET);        /* seek back to the beginning of the file */
        if (irc == -1L) {
            logprintf(STDERR_FILENO,
                      "SWTPM_NVRAM_LoadData: Error (fatal) fseek'ing %s, %s\n",
                      filename, strerror(errno));
            rc = TPM_FAIL;
        }
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
        src = fread(*data, 1, *length, file);
        if (src != *length) {
            logprintf(STDERR_FILENO,
                      "SWTPM_NVRAM_LoadData: Error (fatal), data read of %u "
                      "only read %lu\n", *length, (unsigned long)src);
            rc = TPM_FAIL;
        }
    }
    /* close the file */
    if (file != NULL) {
        TPM_DEBUG(" SWTPM_NVRAM_LoadData: Closing file %s\n", filename);
        irc = fclose(file);             /* @1 */
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

    if (rc == 0) {
        /* this function needs to return the plain data -- no tlv headers */

        /* try to get a header from it -- old files may not have one */
        irc = SWTPM_NVRAM_CheckHeader(*data, *length, &dataoffset,
                                      &hdrflags, &hdrversion, true);
        /* valid header -- this one can only be version 2 or later */
        if (irc) {
            hdrversion = 1; /* no header -- payload was written like vers. 1 */
            hdrflags = 0;
        }

        rc = SWTPM_NVRAM_GetDecryptedData(&filekey,
                                          &decrypt_data, &decrypt_length,
                                          *data + dataoffset,
                                          *length - dataoffset,
                                          TAG_ENCRYPTED_DATA, TAG_DATA,
                                          hdrversion,
                                          TAG_IVEC_ENCRYPTED_DATA,
                                          hdrflags,
                                          BLOB_FLAG_ENCRYPTED_256BIT_KEY);
        TPM_DEBUG(" SWTPM_NVRAM_LoadData: SWTPM_NVRAM_GetDecryptedData rc = %d\n",
                  rc);
        if (rc != 0)
            logprintf(STDERR_FILENO,
                      "SWTPM_NVRAM_LoadData: Error from SWTPM_NVRAM_GetDecryptedData "
                      "rc = %d\n", rc);

        if (rc == 0) {
            TPM_DEBUG(" SWTPM_NVRAM_LoadData: Decrypted %u bytes of "
                      "data to %u bytes.\n",
                      *length, decrypt_length);
            free(*data);
            *data = decrypt_data;
            *length = decrypt_length;
        }
    }

    if (rc != 0) {
        free(*data);
        *data = NULL;
    }

    return rc;
}

/* SWTPM_NVRAM_StoreData stores 'data' of 'length' to the rooted 'filename'

   Returns
        0 on success
        TPM_FAIL for other fatal errors
*/

static TPM_RESULT
SWTPM_NVRAM_StoreData_Intern(const unsigned char *data,
                             uint32_t length,
                             uint32_t tpm_number,
                             const char *name,
                             TPM_BOOL encrypt         /* encrypt if key is set */)
{
    TPM_RESULT    rc = 0;
    uint32_t      lrc;
    int           irc;
    FILE          *file = NULL;
    char          tmpfile[FILENAME_MAX];  /* rooted temporary file */
    char          filename[FILENAME_MAX]; /* rooted file name from name */
    unsigned char *filedata = NULL;
    uint32_t      filedata_length = 0;
    tlv_data      td[3];
    size_t        td_len = 0;
    uint16_t      flags = 0;

    TPM_DEBUG(" SWTPM_NVRAM_StoreData: To name %s\n", name);
    if (rc == 0) {
        /* map name to the rooted filename */
        rc = SWTPM_NVRAM_GetFilenameForName(filename, sizeof(filename),
                                            tpm_number, name, false);
    }

    if (rc == 0) {
        /* map name to the rooted temporary file */
        rc = SWTPM_NVRAM_GetFilenameForName(tmpfile, sizeof(tmpfile),
                                            tpm_number, name, true);
    }


    if (rc == 0) {
        /* open the file */
        TPM_DEBUG(" SWTPM_NVRAM_StoreData: Opening file %s\n", tmpfile);
        file = fopen(tmpfile, "wb");                           /* closed @1 */
        if (file == NULL) {
            logprintf(STDERR_FILENO,
                      "SWTPM_NVRAM_StoreData: Error (fatal) opening %s for "
                      "write failed, %s\n", tmpfile, strerror(errno));
            rc = TPM_FAIL;
        }
    }

    if (rc == 0) {
        if (fchmod(fileno(file), tpmstate_get_mode()) < 0) {
            logprintf(STDERR_FILENO,
                      "SWTPM_NVRAM_StoreData: Could not fchmod %s : %s\n",
                      tmpfile, strerror(errno));
            rc = TPM_FAIL;
        }
    }

    if (rc == 0) {
        if (encrypt && SWTPM_NVRAM_Has_FileKey()) {
            td_len = 3;
            rc = SWTPM_NVRAM_EncryptData(&filekey, &td[0], &td_len,
                                         TAG_ENCRYPTED_DATA, data, length,
                                         TAG_IVEC_ENCRYPTED_DATA);
            if (rc) {
                logprintf(STDERR_FILENO,
                          "SWTPM_NVRAM_EncryptData failed: 0x%02x\n", rc);
            } else {
                TPM_DEBUG("  SWTPM_NVRAM_StoreData: Encrypted %u bytes before "
                          "write, will write %u bytes\n", length,
                          td[0].tlv.length);
            }
            flags |= BLOB_FLAG_ENCRYPTED;
            if (SWTPM_NVRAM_FileKey_Size() == SWTPM_AES256_BLOCK_SIZE)
                flags |= BLOB_FLAG_ENCRYPTED_256BIT_KEY;
        } else {
            td_len = 1;
            td[0] = TLV_DATA_CONST(TAG_DATA, length, data);
        }
    }

    if (rc == 0)
        rc = tlv_data_append(&filedata, &filedata_length, td, td_len);

    if (rc == 0)
        rc = SWTPM_NVRAM_PrependHeader(&filedata, &filedata_length, flags);

    /* write the data to the file */
    if (rc == 0) {
        TPM_DEBUG("  SWTPM_NVRAM_StoreData: Writing %u bytes of data\n", length);
        lrc = fwrite(filedata, 1, filedata_length, file);
        if (lrc != filedata_length) {
            logprintf(STDERR_FILENO,
                      "TPM_NVRAM_StoreData: Error (fatal), data write "
                      "of %u only wrote %u\n", filedata_length, lrc);
            rc = TPM_FAIL;
        }
    }
    if (file != NULL) {
        TPM_DEBUG("  SWTPM_NVRAM_StoreData: Closing file %s\n", tmpfile);
        irc = fclose(file);             /* @1 */
        if (irc != 0) {
            logprintf(STDERR_FILENO,
                      "SWTPM_NVRAM_StoreData: Error (fatal) closing file\n");
            rc = TPM_FAIL;
        }
        else {
            TPM_DEBUG("  SWTPM_NVRAM_StoreData: Closed file %s\n", tmpfile);
        }
    }

    if (rc == 0 && file != NULL) {
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

    if (rc != 0 && file != NULL) {
        unlink(tmpfile);
    }

    tlv_data_free(td, td_len);
    free(filedata);

    TPM_DEBUG(" SWTPM_NVRAM_StoreData: rc=%d\n", rc);

    return rc;
}

TPM_RESULT SWTPM_NVRAM_StoreData(const unsigned char *data,
                                 uint32_t length,
                                 uint32_t tpm_number,
                                 const char *name)
{
    return SWTPM_NVRAM_StoreData_Intern(data, length, tpm_number, name, TRUE);
}

/* SWTPM_NVRAM_GetFilenameForName() constructs a rooted file name from the name.

   The filename is of the form:

   state_directory/tpm_number.name

   A temporary filename used to write to may be created. It shold be rename()'d to
   the non-temporary filename.
*/

static TPM_RESULT SWTPM_NVRAM_GetFilenameForName(char *filename,        /* output: rooted filename */
                                                 size_t bufsize,
                                                 uint32_t tpm_number,
                                                 const char *name,      /* input: abstract name */
                                                 bool is_tempfile)      /* input: is temporary file? */
{
    TPM_RESULT res = TPM_SUCCESS;
    int n;
    const char *suffix = "";

    TPM_DEBUG(" SWTPM_NVRAM_GetFilenameForName: For name %s\n", name);

    switch (tpmversion) {
    case TPMLIB_TPM_VERSION_1_2:
        break;
    case TPMLIB_TPM_VERSION_2:
        suffix = "2";
        break;
    }

    if (is_tempfile) {
        n = snprintf(filename, bufsize, "%s/TMP%s-%02lx.%s",
                     state_directory, suffix, (unsigned long)tpm_number, name);
    } else {
        n = snprintf(filename, bufsize, "%s/tpm%s-%02lx.%s",
                     state_directory, suffix, (unsigned long)tpm_number, name);
    }
    if ((size_t)n > bufsize) {
        res = TPM_FAIL;
    }

    TPM_DEBUG("  SWTPM_NVRAM_GetFilenameForName: File name %s\n", filename);

    return res;
}

/* TPM_NVRAM_DeleteName() deletes the 'name' from NVRAM

   Returns:
        0 on success, or if the file does not exist and mustExist is FALSE
        TPM_FAIL if the file could not be removed, since this should never occur and there is
                no recovery

   NOTE: Not portable code, but supported by Linux and Windows
*/

TPM_RESULT SWTPM_NVRAM_DeleteName(uint32_t tpm_number,
                                  const char *name,
                                  TPM_BOOL mustExist)
{
    TPM_RESULT  rc = 0;
    int         irc;
    char        filename[FILENAME_MAX]; /* rooted file name from name */

    TPM_DEBUG(" SWTPM_NVRAM_DeleteName: Name %s\n", name);
    /* map name to the rooted filename */
    rc = SWTPM_NVRAM_GetFilenameForName(filename, sizeof(filename),
                                        tpm_number, name, false);
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


TPM_RESULT SWTPM_NVRAM_Store_Volatile(void)
{
    TPM_RESULT     rc = 0;
    char           *name = TPM_VOLATILESTATE_NAME;
    uint32_t       tpm_number = 0;
    unsigned char  *buffer = NULL;
    uint32_t       buflen;

    TPM_DEBUG(" SWTPM_Store_Volatile: Name %s\n", name);
    if (rc == 0) {
        rc = TPMLIB_VolatileAll_Store(&buffer, &buflen);
    }
    if (rc == 0) {
        /* map name to the rooted filename */
        rc = SWTPM_NVRAM_StoreData(buffer, buflen, tpm_number, name);
    }

    free(buffer);

    return rc;
}

static TPM_RESULT
SWTPM_NVRAM_KeyParamCheck(uint32_t keylen,
                          enum encryption_mode encmode)
{
    TPM_RESULT rc = 0;

    if (keylen != SWTPM_AES128_BLOCK_SIZE &&
        keylen != SWTPM_AES256_BLOCK_SIZE) {
        rc = TPM_BAD_KEY_PROPERTY;
    }
    switch (encmode) {
    case ENCRYPTION_MODE_AES_CBC:
        break;
    case ENCRYPTION_MODE_UNKNOWN:
        rc = TPM_BAD_MODE;
    }

    return rc;
}

size_t SWTPM_NVRAM_FileKey_Size(void)
{
    return filekey.symkey.userKeyLength;
}

TPM_RESULT SWTPM_NVRAM_Set_FileKey(const unsigned char *key, uint32_t keylen,
                                   enum encryption_mode encmode)
{
    TPM_RESULT rc;

    rc = SWTPM_NVRAM_KeyParamCheck(keylen, encmode);

    if (rc == 0) {
        memcpy(filekey.symkey.userKey, key, keylen);
        filekey.symkey.userKeyLength = keylen;
        filekey.data_encmode = encmode;
    }

    return rc;
}

size_t SWTPM_NVRAM_MigrationKey_Size(void)
{
    return migrationkey.symkey.userKeyLength;
}

TPM_RESULT SWTPM_NVRAM_Set_MigrationKey(const unsigned char *key,
                                        uint32_t keylen,
                                        enum encryption_mode encmode)
{
    TPM_RESULT rc;

    rc = SWTPM_NVRAM_KeyParamCheck(keylen, encmode);

    if (rc == 0) {
        memcpy(migrationkey.symkey.userKey, key, keylen);
        migrationkey.symkey.userKeyLength = keylen;
        migrationkey.data_encmode = encmode;
    }

    return rc;
}

static int SWTPM_HMAC(unsigned char *md, unsigned int *md_len,
                      const void *key, int key_len,
                      const unsigned char *in, uint32_t in_length,
                      const unsigned char *ivec, uint32_t ivec_length)
{
    int ret = 0;

#if defined OPENSSL_OLD_API
    HMAC_CTX sctx, *ctx = &sctx;

    HMAC_CTX_init(ctx);
#else
    HMAC_CTX *ctx = HMAC_CTX_new();

    if (!ctx)
        return 0;
#endif


    if (!HMAC_Init_ex(ctx, key, key_len, EVP_sha256(), NULL) ||
        !HMAC_Update(ctx, in, in_length))
        goto err;

    if (ivec &&
        !HMAC_Update(ctx, ivec, ivec_length))
        goto err;

    if (!HMAC_Final(ctx, md, md_len))
        goto err;

    ret = 1;

err:
#if defined OPENSSL_OLD_API
    HMAC_CTX_cleanup(ctx);
#else
    HMAC_CTX_free(ctx);
#endif

    return ret;
}

/*
 * SWTPM_RollAndSetGlobalIvec: Create an IV for the AES CBC algorithm to use
 *                             Create it with a random number every time.
 *                             and leave the pointer to the data in @td.
 *
 * @td: pointer to tlv_data to get pointer to the random data
 * @tag_ivec: tag for the IV tlv header
 * @ivec_length: number of bytes needed for the ivec
 */
static TPM_RESULT SWTPM_RollAndSetGlobalIvec(tlv_data *td,
                                             uint16_t tag_ivec,
                                             uint32_t ivec_length)
{
    unsigned char data[16]; /* do not initialize */
    unsigned char hashbuf[SHA256_DIGEST_LENGTH];
    void *p;

    if (g_ivec_length < ivec_length) {
        p = realloc(g_ivec, ivec_length);
        if (!p) {
            *td = TLV_DATA_CONST(tag_ivec, 0, NULL);

            logprintf(STDOUT_FILENO,
                      "Could not allocate %u bytes.\n", ivec_length);
            return TPM_FAIL;
        }
        g_ivec = p;
        g_ivec_length = ivec_length;
    }

    if (RAND_bytes(g_ivec, g_ivec_length) != 1) {
        /* random data from stack to the rescue */
        SHA256(g_ivec, g_ivec_length, hashbuf);
        SHA256(data, sizeof(data), hashbuf);
        memcpy(g_ivec, hashbuf,
               g_ivec_length < sizeof(hashbuf)
                   ? g_ivec_length
                   : sizeof(hashbuf));
    }

    *td = TLV_DATA_CONST(tag_ivec, g_ivec_length, g_ivec);

    return 0;
}

/*
 * SWTPM_GetIvec: Get the encryption IV from the data stream. If none is
 *                found a NULL pointer is set in *ivec, otherwise a pointer
 *                to the beginning of the IV and its length are returned.
 */
static void SWTPM_GetIvec(const unsigned char *data, uint32_t length,
                          const unsigned char **ivec, uint32_t *ivec_length,
                          uint16_t tag)
{
    tlv_data td;

    if (!tlv_data_find_tag(data, length, tag, &td)) {
        *ivec = NULL;
    } else {
        *ivec = td.u.const_ptr;
        *ivec_length = td.tlv.length;
    }
}

/*
 * SWTPM_CalcHMAC
 *
 * @in: input buffer to calculate HMAC on
 * @in_length: length of input buffer
 * @td: pointer to a tlv_data structure to receive the result with the
 *      tag, length, and pointer to an allocated buffer holding the HMAC
 * @tpm_symmetric_key_token: symmetric key
 * @ivec: the IV for AES CBC
 * @ivec_length: the length of the IV
 *
 * Calculate an HMAC on the input buffer with payload and create an output
 * buffer with the HMAC
 */
static TPM_RESULT
SWTPM_CalcHMAC(const unsigned char *in, uint32_t in_length,
               tlv_data *td,
               const TPM_SYMMETRIC_KEY_DATA *tpm_symmetric_key_token,
               const unsigned char *ivec, uint32_t ivec_length)
{
    TPM_RESULT rc = 0;
    unsigned int md_len;
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned char *buffer = NULL;

    if (!SWTPM_HMAC(md, &md_len,
                    tpm_symmetric_key_token->userKey,
                    tpm_symmetric_key_token->userKeyLength,
                    in, in_length, ivec, ivec_length)) {
        logprintf(STDOUT_FILENO, "HMAC calculation failed.\n");
        return TPM_FAIL;
    }

    buffer = malloc(md_len);

    if (buffer) {
        *td = TLV_DATA(TAG_HMAC, md_len, buffer);
        memcpy(buffer, md, md_len);
    } else {
       logprintf(STDOUT_FILENO,
                 "Could not allocate %u bytes.\n", md_len);
       rc = TPM_FAIL;
    }

    return rc;
}

/*
 * SWTPM_CheckHMAC:
 *
 * @hmac: tlv_data with pointer to hmac bytes
 * @encrypted_data: tlv_data with pointer to encrypted data bytes
 * @tpm_symmetric_key_token: symmetric key
 * @ivec: the IV for AES CBC
 * @ivec_length: the length of the IV
 *
 * Verify the HMAC given the expected @hmac and the @tpm_symmetric_key_token
 * to calculate the HMAC over the @encrypted_data.
 */
static TPM_RESULT
SWTPM_CheckHMAC(tlv_data *hmac, tlv_data *encrypted_data,
                const TPM_SYMMETRIC_KEY_DATA *tpm_symmetric_key_token,
                const unsigned char *ivec, uint32_t ivec_length)
{
    const unsigned char *data;
    uint32_t data_length;
    unsigned int md_len;
    unsigned char md[EVP_MAX_MD_SIZE];

    md_len = EVP_MD_size(EVP_sha256());
    if (md_len > hmac->tlv.length) {
        logprintf(STDOUT_FILENO, "Insufficient bytes for CheckHMAC()\n");
        return TPM_FAIL;
    }

    data = encrypted_data->u.ptr;
    data_length = encrypted_data->tlv.length;

    if (!SWTPM_HMAC(md, &md_len,
                    tpm_symmetric_key_token->userKey,
                    tpm_symmetric_key_token->userKeyLength,
                    data, data_length, ivec, ivec_length)) {
        logprintf(STDOUT_FILENO, "HMAC() call failed.\n");
        return TPM_FAIL;
    }

    if (memcmp(hmac->u.ptr, md, md_len)) {
        logprintf(STDOUT_FILENO, "Verification of HMAC failed. "
                  "Data integrity is compromised\n");
        /* TPM_DECRYPT_ERROR indicates (to libtpms) that something
           exists but we have the wrong key. */
        return TPM_DECRYPT_ERROR;
    }

    return TPM_SUCCESS;
}

/*
 * SWTPM_CheckHash:
 *
 * @in: input buffer
 * @in_length: input buffer length
 * @out: output buffer
 * @out_length: output buffer length
 */
static TPM_RESULT
SWTPM_CheckHash(const unsigned char *in, uint32_t in_length,
                unsigned char **out, uint32_t *out_length)
{
    TPM_RESULT rc = 0;
    unsigned char *dest = NULL;
    unsigned char hashbuf[SHA256_DIGEST_LENGTH];
    const unsigned char *data = &in[sizeof(hashbuf)];
    uint32_t data_length = in_length - sizeof(hashbuf);

    /* hash the data */
    SHA256(data, data_length, hashbuf);

    if (memcmp(in, hashbuf, sizeof(hashbuf))) {
        logprintf(STDOUT_FILENO, "Verification of hash failed. "
                  "Data integrity is compromised\n");
        rc = TPM_FAIL;
    }

    if (rc == 0) {
        dest = malloc(data_length);
        if (dest) {
            *out = dest;
            *out_length = data_length;
            memcpy(dest, data, data_length);
        } else {
            logprintf(STDOUT_FILENO,
                      "Could not allocated %u bytes.\n", data_length);
            rc = TPM_FAIL;
        }
    }

    return rc;
}

static TPM_RESULT
SWTPM_NVRAM_EncryptData(const encryptionkey *key,
                        struct tlv_data *td, /* must provide 2 array members */
                        size_t *td_len,
                        uint16_t tag_encrypted_data,
                        const unsigned char *data, uint32_t length,
                        uint16_t tag_ivec)
{
    TPM_RESULT rc = 0;
    TPM_RESULT irc;
    unsigned char *tmp_data = NULL;
    uint32_t tmp_length = 0;

    *td_len = 0;

    if (key->symkey.userKeyLength > 0) {
        switch (key->data_encmode) {
        case ENCRYPTION_MODE_UNKNOWN:
            rc = TPM_BAD_MODE;
            break;
        case ENCRYPTION_MODE_AES_CBC:
            irc = SWTPM_RollAndSetGlobalIvec(&td[2], tag_ivec,
                                             key->symkey.userKeyLength);
            rc = SWTPM_SymmetricKeyData_Encrypt(&tmp_data, &tmp_length,
                                                data, length, &key->symkey,
                                                td[2].u.const_ptr,
                                                td[2].tlv.length);
            if (rc)
                 break;

            rc = SWTPM_CalcHMAC(tmp_data, tmp_length, &td[1], &key->symkey,
                                td[2].u.const_ptr, td[2].tlv.length);
            if (rc == 0) {
                td[0] = TLV_DATA(tag_encrypted_data, tmp_length, tmp_data);
                /* in case we couldn't get an IV */
                *td_len = (irc == 0) ? 3 : 2;
                tmp_data = NULL;
            }
            break;
        }
    }

    if (rc)
        tlv_data_free(td, *td_len);

    free(tmp_data);

    return rc;
}

static TPM_RESULT
SWTPM_NVRAM_DecryptData(const encryptionkey *key,
                        unsigned char **decrypt_data, uint32_t *decrypt_length,
                        const unsigned char *data, uint32_t length,
                        uint16_t tag_encrypted_data,
                        uint8_t hdrversion,
                        uint16_t tag_ivec, uint16_t hdrflags,
                        uint16_t flag_256bitkey)
{
    TPM_RESULT rc = 0;
    unsigned char *tmp_data = NULL;
    uint32_t tmp_length = 0;
    tlv_data td[2];
    const unsigned char *ivec = NULL;
    uint32_t ivec_length = 0;
    size_t keylen;

    if (key->symkey.userKeyLength > 0) {
        switch (key->data_encmode) {
        case ENCRYPTION_MODE_UNKNOWN:
            rc = TPM_BAD_MODE;
            break;
        case ENCRYPTION_MODE_AES_CBC:
            switch (hdrversion) {
            case 1:
                rc = SWTPM_SymmetricKeyData_Decrypt(&tmp_data,
                                                    &tmp_length,
                                                    data, length,
                                                    &key->symkey,
                                                    NULL, 0);
                if (rc == 0) {
                    rc = SWTPM_CheckHash(tmp_data, tmp_length,
                                         decrypt_data, decrypt_length);
                }
            break;
            case 2:
                keylen = (hdrflags & flag_256bitkey)
                          ? SWTPM_AES256_BLOCK_SIZE : SWTPM_AES128_BLOCK_SIZE;
                if (keylen != key->symkey.userKeyLength) {
                    logprintf(STDERR_FILENO,
                              "Wrong decryption key. Need %zu bit key.\n",
                              keylen * 8);
                    rc = TPM_BAD_KEY_PROPERTY;
                    break;
                }

                if (!tlv_data_find_tag(data, length, TAG_HMAC, &td[0]) ||
                    !tlv_data_find_tag(data, length, tag_encrypted_data,
                                       &td[1])) {
                    logprintf(STDERR_FILENO,
                              "Could not find HMAC or encrypted data (tag %u) "
                              "in byte stream.\n", tag_encrypted_data);
                    rc = TPM_FAIL;
                    break;
                }
                /* get the IV, if there is one */
                SWTPM_GetIvec(data, length, &ivec, &ivec_length, tag_ivec);

                rc = SWTPM_CheckHMAC(&td[0], &td[1], &key->symkey,
                                     ivec, ivec_length);
                if (rc == 0) {
                    rc = SWTPM_SymmetricKeyData_Decrypt(decrypt_data,
                                                        decrypt_length,
                                                        td[1].u.const_ptr,
                                                        td[1].tlv.length,
                                                        &key->symkey,
                                                        ivec, ivec_length);
                }
            break;
            default:
                rc = TPM_FAIL;
            }
            free(tmp_data);
        }
    }

    return rc;
}

static TPM_RESULT
SWTPM_NVRAM_GetPlainData(unsigned char **plain, uint32_t *plain_length,
                         const unsigned char *data, uint32_t length,
                         uint16_t tag_data,
                         uint8_t hdrversion)
{
    TPM_RESULT rc = 0;
    tlv_data td[1];

    switch (hdrversion) {
    case 1:
        *plain = malloc(length);
        if (*plain) {
            memcpy(*plain, data, length);
            *plain_length = length;
        } else {
            logprintf(STDERR_FILENO,
                      "Could not allocate %u bytes.\n", length);
            rc = TPM_FAIL;
        }
    break;

    case 2:
        if (!tlv_data_find_tag(data, length, tag_data, &td[0])) {
            logprintf(STDERR_FILENO,
                      "Could not find plain data in byte stream.\n");
            rc = TPM_FAIL;
            break;
        }
        *plain = malloc(td->tlv.length);
        if (*plain) {
            memcpy(*plain, td->u.const_ptr, td->tlv.length);
            *plain_length = td->tlv.length;
        } else {
            logprintf(STDERR_FILENO,
                      "Could not allocate %u bytes.\n", td->tlv.length);
            rc = TPM_FAIL;
        }
    break;
    }

    return rc;
}

/*
 * SWTPM_NVRAM_GetDecryptedData: Get the decrytped data either by just returning
 *                               the data if they were not encrypted or by
 *                               actually decrypting them if there is a key.
 *                               The plain data is returned, meaning any TLV
 *                               header has been removed.
 * @key: the encryption key, may be NULL
 * @decrypt_data: pointer to a pointer for the result
 * @decrypt_length: the length of the returned data
 * @data: input data
 * @length: length of the input data
 * @tag_encrypted_data: the tag the encrypted data is stored with
 * @tag_data: the tag the plain data is stored with
 * @hdrversion: the version found in the header that determines in what
 *              format the data is stored; tag-length-value is the format
 *              in v2
 * @tag_ivec: the tag for finding the IV
 * @hdrflags: the flags from the header
 * @flag_256bitkey: the flag in the header to check whether we expect a
 *                  256 bit key; different flag for migration and state key
 */
static TPM_RESULT
SWTPM_NVRAM_GetDecryptedData(const encryptionkey *key,
                             unsigned char **decrypt_data,
                             uint32_t *decrypt_length,
                             const unsigned char *data,
                             uint32_t length,
                             uint16_t tag_encrypted_data,
                             uint16_t tag_data,
                             uint8_t hdrversion,
                             uint16_t tag_ivec,
                             uint16_t hdrflags,
                             uint16_t flag_256bitkey)
{
    if (key && key->symkey.userKeyLength > 0) {
        /* we assume the data are encrypted when there's a key given */
        return SWTPM_NVRAM_DecryptData(key, decrypt_data, decrypt_length,
                                       data, length, tag_encrypted_data,
                                       hdrversion, tag_ivec, hdrflags,
                                       flag_256bitkey);
    }
    return SWTPM_NVRAM_GetPlainData(decrypt_data, decrypt_length,
                                    data, length, tag_data, hdrversion);
}

/*
 * Prepend a header in front of the state blob
 */
static TPM_RESULT
SWTPM_NVRAM_PrependHeader(unsigned char **data, uint32_t *length,
                          uint16_t flags)
{
    unsigned char *out = NULL;
    uint32_t out_len = sizeof(blobheader) + *length;
    blobheader bh = {
        .version = BLOB_HEADER_VERSION,
        .min_version = 1,
        .hdrsize = htons(sizeof(bh)),
        .flags = htons(flags),
        .totlen = htonl(out_len),
    };
    TPM_RESULT res;

    out = malloc(out_len);
    if (!out) {
        logprintf(STDERR_FILENO,
                  "Could not allocate %u bytes.\n", out_len);
        res = TPM_FAIL;
        goto error;
    }

    memcpy(out, &bh, sizeof(bh));
    memcpy(&out[sizeof(bh)], *data, *length);

    free(*data);

    *data = out;
    *length = out_len;

    return TPM_SUCCESS;

 error:
    free(*data);
    *data = NULL;
    *length = 0;

    return res;
}


static TPM_RESULT
SWTPM_NVRAM_CheckHeader(unsigned char *data, uint32_t length,
                        uint32_t *dataoffset, uint16_t *hdrflags,
                        uint8_t *hdrversion, bool quiet)
{
    blobheader *bh = (blobheader *)data;

    if (length < sizeof(bh)) {
        if (!quiet)
            logprintf(STDERR_FILENO,
                      "not enough bytes for header: %u\n", length);
        return TPM_BAD_PARAMETER;
    }

    if (ntohl(bh->totlen) != length) {
        if (!quiet)
            logprintf(STDERR_FILENO,
                      "broken header: bh->totlen %u != %u\n",
                      htonl(bh->totlen), length);
        return TPM_BAD_PARAMETER;
    }

    if (bh->min_version > BLOB_HEADER_VERSION) {
        if (!quiet)
            logprintf(STDERR_FILENO,
                      "Minimum required version for the blob is %d, we "
                      "only support version %d\n", bh->min_version,
                      BLOB_HEADER_VERSION);
        return TPM_BAD_VERSION;
    }

    *hdrversion = bh->version;
    *dataoffset = ntohs(bh->hdrsize);
    *hdrflags = ntohs(bh->flags);

    return TPM_SUCCESS;
}

/*
 * Get the state blob with the current name; read it from the filesystem.
 * Decrypt it if the caller asks for it and if a key is set. Return
 * whether it's still encrypyted.
 */
TPM_RESULT SWTPM_NVRAM_GetStateBlob(unsigned char **data,
                                    uint32_t *length,
                                    uint32_t tpm_number,
                                    const char *name,
                                    TPM_BOOL decrypt,
                                    TPM_BOOL *is_encrypted)
{
    TPM_RESULT res;
    uint16_t flags = 0;
    tlv_data td[3];
    size_t td_len;
    unsigned char *plain = NULL, *buffer = NULL;
    uint32_t plain_len, buffer_len = 0;

    *data = NULL;
    *length = 0;

    res = SWTPM_NVRAM_LoadData(&plain, &plain_len, tpm_number, name);
    if (res)
        return res;

    /* @plain contains unencrypted data without tlv headers */

    /* if the user doesn't want decryption and there's a file key, we need to
       encrypt the data */
    if (!decrypt && SWTPM_NVRAM_Has_FileKey()) {
        td_len = 3;
        res = SWTPM_NVRAM_EncryptData(&filekey, &td[0], &td_len,
                                      TAG_ENCRYPTED_DATA, plain, plain_len,
                                      TAG_IVEC_ENCRYPTED_DATA);
        if (res)
            goto err_exit;

        *is_encrypted = TRUE;
        if (SWTPM_NVRAM_FileKey_Size() == SWTPM_AES256_BLOCK_SIZE)
            flags |= BLOB_FLAG_ENCRYPTED_256BIT_KEY;
    } else {
        *is_encrypted = FALSE;
        td[0] = TLV_DATA(TAG_DATA, plain_len, plain);
        plain = NULL;
        td_len = 1;
    }

    res = tlv_data_append(&buffer, &buffer_len, td, td_len);
    if (res)
        goto err_exit;

    tlv_data_free(td, td_len);

    /* @buffer contains tlv data */

    if (SWTPM_NVRAM_Has_MigrationKey()) {
        /* we have to encrypt it now with the migration key */
        flags |= BLOB_FLAG_MIGRATION_ENCRYPTED;
        if (SWTPM_NVRAM_MigrationKey_Size() == SWTPM_AES256_BLOCK_SIZE)
             flags |= BLOB_FLAG_MIGRATION_256BIT_KEY;

        td_len = 3;
        res = SWTPM_NVRAM_EncryptData(&migrationkey, &td[0], &td_len,
                                      TAG_ENCRYPTED_MIGRATION_DATA,
                                      buffer, buffer_len,
                                      TAG_IVEC_ENCRYPTED_MIGRATION_DATA);
        if (res)
            goto err_exit;
    } else {
        td[0] = TLV_DATA(TAG_MIGRATION_DATA, buffer_len, buffer);
        buffer = NULL;
        td_len = 1;
    }
    flags |= BLOB_FLAG_MIGRATION_DATA;

    res = tlv_data_append(data, length, td, td_len);
    if (res)
        goto err_exit;

    /* put the header in clear text */
    if (*is_encrypted)
        flags |= BLOB_FLAG_ENCRYPTED;

    res = SWTPM_NVRAM_PrependHeader(data, length, flags);

err_exit:
    tlv_data_free(td, td_len);
    free(buffer);
    free(plain);

    return res;
}

/*
 * Set the state blob with the given name; the caller tells us if
 * the blob is encrypted; if it is encrypted, it will be written
 * into the file as-is, otherwise it will be encrypted if a key is set.
 */
TPM_RESULT SWTPM_NVRAM_SetStateBlob(unsigned char *data,
                                    uint32_t length,
                                    TPM_BOOL is_encrypted,
                                    uint32_t tpm_number,
                                    uint32_t blobtype)
{
    TPM_RESULT res;
    uint32_t dataoffset;
    unsigned char *plain = NULL, *mig_decrypt = NULL;
    uint32_t plain_len = 0, mig_decrypt_len = 0;
    uint16_t hdrflags;
    enum TPMLIB_StateType st = tpmlib_blobtype_to_statetype(blobtype);
    const char *blobname = tpmlib_get_blobname(blobtype);
    uint8_t hdrversion;

    if (st == 0) {
        logprintf(STDERR_FILENO,
                  "Unknown blob type %u\n", blobtype);
        return TPM_BAD_PARAMETER;
    }

    if (length == 0)
        return TPMLIB_SetState(st, NULL, 0);

    res = SWTPM_NVRAM_CheckHeader(data, length, &dataoffset, &hdrflags,
                                  &hdrversion, false);
    if (res != TPM_SUCCESS)
        return res;

    if (length - dataoffset == 0)
        return TPMLIB_SetState(st, NULL, 0);

    /*
     * We allow setting of blobs that were not encrypted before;
     * we just will not decrypt them even if the migration key is
     * set. This allows to 'upgrade' to encryption. 'Downgrading'
     * will not be possible once a migration key was used.
     */
    if ((hdrflags & BLOB_FLAG_MIGRATION_ENCRYPTED)) {
        /*
         * we first need to decrypt the data with the migration key
         */
        if (!SWTPM_NVRAM_Has_MigrationKey()) {
            logprintf(STDERR_FILENO,
                      "Missing migration key to decrypt %s\n", blobname);
            return TPM_KEYNOTFOUND;
        }

        res = SWTPM_NVRAM_DecryptData(&migrationkey,
                                      &mig_decrypt, &mig_decrypt_len,
                                      &data[dataoffset], length - dataoffset,
                                      TAG_ENCRYPTED_MIGRATION_DATA,
                                      hdrversion,
                                      TAG_IVEC_ENCRYPTED_MIGRATION_DATA,
                                      hdrflags, BLOB_FLAG_MIGRATION_256BIT_KEY);
        if (res) {
            logprintf(STDERR_FILENO,
                      "Decrypting the %s blob with the migration key failed; "
                      "res = %d\n", blobname, res);
            return res;
        }
    } else {
        res = SWTPM_NVRAM_GetPlainData(&mig_decrypt, &mig_decrypt_len,
                                       &data[dataoffset], length - dataoffset,
                                       TAG_MIGRATION_DATA,
                                       hdrversion);
        if (res)
            return res;
    }

    /*
     * Migration key has decrytped the data; if they are still encrypted
     * with the state encryption key, we need to decrypt them using that
     * key now.
     */
    if (is_encrypted || (hdrflags & BLOB_FLAG_ENCRYPTED)) {
        if (!SWTPM_NVRAM_Has_FileKey()) {
            logprintf(STDERR_FILENO,
                      "Missing state key to decrypt %s\n", blobname);
            res = TPM_KEYNOTFOUND;
            goto cleanup;
        }

        res = SWTPM_NVRAM_DecryptData(&filekey, &plain, &plain_len,
                                      mig_decrypt, mig_decrypt_len,
                                      TAG_ENCRYPTED_DATA,
                                      hdrversion, TAG_IVEC_ENCRYPTED_DATA,
                                      hdrflags, BLOB_FLAG_ENCRYPTED_256BIT_KEY);
        if (res) {
            logprintf(STDERR_FILENO,
                      "Decrypting the %s blob with the state key "
                      "failed; res = %d\n", blobname, res);
            goto cleanup;
        }
    } else {
        res = SWTPM_NVRAM_GetPlainData(&plain, &plain_len,
                                       mig_decrypt, mig_decrypt_len,
                                       TAG_DATA,
                                       hdrversion);
        if (res)
            goto cleanup;
    }

    /* SetState will make a copy of the buffer */
    res = TPMLIB_SetState(st, plain, plain_len);

    free(plain);

cleanup:
    free(mig_decrypt);

    return res;
}
