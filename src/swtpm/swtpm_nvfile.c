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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <libtpms/tpm_error.h>
#include <libtpms/tpm_memory.h>
#include <libtpms/tpm_nvfilename.h>
#include <libtpms/tpm_library.h>

#ifdef USE_FREEBL_CRYPTO_LIBRARY
# include <blapi.h>
#else
# ifdef USE_OPENSSL_CRYPTO_LIBRARY
#  include <openssl/sha.h>
# else
#  error "Unsupported crypto library."
# endif
#endif

#include "swtpm_aes.h"
#include "swtpm_debug.h"
#include "swtpm_nvfile.h"
#include "key.h"
#include "logging.h"
#include "tpmstate.h"

/* local structures */
typedef struct {
    uint8_t  version;
    uint8_t  min_version; /* min. required version */
    uint16_t hdrsize;
    uint16_t flags;
    uint32_t totlen; /* length of the header and following data */
} __attribute__((packed)) blobheader;

#define BLOB_HEADER_VERSION 1

/* flags for blobheader */
#define BLOB_FLAG_ENCRYPTED              0x1
#define BLOB_FLAG_MIGRATION_ENCRYPTED    0x2 /* encrypted with migration key */

typedef struct {
    enum encryption_mode data_encmode;
    TPM_SYMMETRIC_KEY_DATA symkey;
} encryptionkey ;

static encryptionkey filekey = {
    .symkey = {
        .valid = FALSE,
    },
};

static encryptionkey migrationkey = {
    .symkey = {
        .valid = FALSE,
    },
};


/* local prototypes */

static TPM_RESULT SWTPM_NVRAM_GetFilenameForName(char *filename,
                                                 size_t bufsize,
                                                  uint32_t tpm_number,
                                                 const char *name);

static TPM_RESULT SWTPM_NVRAM_EncryptData(const encryptionkey *key,
                                          unsigned char **encrypt_data,
                                          uint32_t *encrypt_length,
                                          const unsigned char *decrypt_data,
                                          uint32_t decrypt_length);

static TPM_RESULT SWTPM_NVRAM_DecryptData(const encryptionkey *key,
                                          unsigned char **decrypt_data,
                                          uint32_t *decrypt_length,
                                          const unsigned char *encrypt_data,
                                          uint32_t encrypt_length);

/* A file name in NVRAM is composed of 3 parts:

  1 - 'state_directory' is the rooted path to the TPM state home directory
  2 = 'tpm_number' is the TPM instance, 00 for a single TPM
  2 - the file name

  For the IBM cryptographic coprocessor version, the root path is hard coded.
  
  For the Linux and Windows versions, the path comes from an environment variable.  This variable is
  used once in TPM_NVRAM_Init().

  One root path is used for all virtual TPM's, so it can be a static variable.
*/

char state_directory[FILENAME_MAX];

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
            fprintf(stderr,
                    "SWTPM_NVRAM_Init: Error (fatal), TPM_PATH environment "
                    "variable not set\n");
            rc = TPM_FAIL;
        }
    }

    /* check that the directory name plus a file name will not overflow FILENAME_MAX */
    if (rc == 0) {
        length = strlen(tpm_state_path);
        if ((length + TPM_FILENAME_MAX) > FILENAME_MAX) {
            fprintf(stderr,
                    "SWTPM_NVRAM_Init: Error (fatal), TPM state path name "
                    "%s too large\n", tpm_state_path);
            rc = TPM_FAIL;
        }
    }
    if (rc == 0) {
        strcpy(state_directory, tpm_state_path);
        TPM_DEBUG("TPM_NVRAM_Init: Rooted state path %s\n", state_directory);
    }
    return rc;
}

/* Load 'data' of 'length' from the 'name'.

   'data' must be freed after use.
   
   Returns
        0 on success.
        TPM_RETRY and NULL,0 on non-existent file (non-fatal, first time start up)
        TPM_FAIL on failure to load (fatal), since it should never occur
*/

static TPM_RESULT
SWTPM_NVRAM_LoadData_Intern(unsigned char **data,     /* freed by caller */
                            uint32_t *length,
                            uint32_t tpm_number,
                            const char *name,
                            TPM_BOOL decrypt)         /* decrypt if key is set */
{
    TPM_RESULT    rc = 0;
    long          lrc;
    size_t        src;
    int           irc;
    FILE          *file = NULL;
    char          filename[FILENAME_MAX]; /* rooted file name from name */
    unsigned char *decrypt_data = NULL;
    uint32_t      decrypt_length;

    TPM_DEBUG(" SWTPM_NVRAM_LoadData: From file %s\n", name);
    *data = NULL;
    *length = 0;
    /* open the file */
    if (rc == 0) {
        /* map name to the rooted filename */
        rc = SWTPM_NVRAM_GetFilenameForName(filename, sizeof(filename),
                                            tpm_number, name);
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
                fprintf(stderr, "SWTPM_NVRAM_LoadData: Error (fatal) opening "
                        "%s for read, %s\n", filename, strerror(errno));
                rc = TPM_FAIL;
            }
        }
    }
    /* determine the file length */
    if (rc == 0) {
        irc = fseek(file, 0L, SEEK_END);        /* seek to end of file */
        if (irc == -1L) {
            fprintf(stderr,
                    "SWTPM_NVRAM_LoadData: Error (fatal) fseek'ing %s, %s\n",
                   filename, strerror(errno));
            rc = TPM_FAIL;
        }
    }
    if (rc == 0) {
        lrc = ftell(file);                      /* get position in the stream */
        if (lrc == -1L) {
            fprintf(stderr,
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
            fprintf(stderr,
                    "SWTPM_NVRAM_LoadData: Error (fatal) fseek'ing %s, %s\n",
                    filename, strerror(errno));
            rc = TPM_FAIL;
        }
    }
    /* allocate a buffer for the actual data */
    if ((rc == 0) && *length != 0) {
        TPM_DEBUG(" SWTPM_NVRAM_LoadData: Reading %u bytes of data\n", *length);
        rc = TPM_Malloc(data, *length);
        if (rc != 0) {
            fprintf(stderr,
                    "SWTPM_NVRAM_LoadData: Error (fatal) allocating %u "
                    "bytes\n", *length);
            rc = TPM_FAIL;
        }
    }
    /* read the contents of the file into the data buffer */
    if ((rc == 0) && *length != 0) {
        src = fread(*data, 1, *length, file);
        if (src != *length) {
            fprintf(stderr,
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
            fprintf(stderr,
                    "SWTPM_NVRAM_LoadData: Error (fatal) closing file %s\n",
                    filename);
            rc = TPM_FAIL;
        }
        else {
            TPM_DEBUG(" SWTPM_NVRAM_LoadData: Closed file %s\n", filename);
        }
    }

    if (rc == 0 && decrypt) {
        rc = SWTPM_NVRAM_DecryptData(&filekey, &decrypt_data, &decrypt_length,
                                     *data, *length);
        TPM_DEBUG(" SWTPM_NVRAM_LoadData: SWTPM_NVRAM_DecryptData rc = %d\n",
                  rc);
        if (rc == 0) {
            if (decrypt_data) {
                TPM_DEBUG(" SWTPM_NVRAM_LoadData: Decrypted %u bytes of "
                          "data to %u bytes.\n",
                          *length, decrypt_length);
                TPM_Free(*data);
                *data = decrypt_data;
                *length = decrypt_length;
            }
        }
    }

    return rc;
}

TPM_RESULT SWTPM_NVRAM_LoadData(unsigned char **data,     /* freed by caller */
                                uint32_t *length,
                                uint32_t tpm_number,
                                const char *name)
{
     return SWTPM_NVRAM_LoadData_Intern(data, length, tpm_number, name, TRUE);
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
    char          filename[FILENAME_MAX]; /* rooted file name from name */
    unsigned char *encrypt_data = NULL;
    uint32_t      encrypt_length = 0;

    TPM_DEBUG(" SWTPM_NVRAM_StoreData: To name %s\n", name);
    if (rc == 0) {
        /* map name to the rooted filename */
        rc = SWTPM_NVRAM_GetFilenameForName(filename, sizeof(filename),
                                            tpm_number, name);
    }
    if (rc == 0) {
        /* open the file */
        TPM_DEBUG(" SWTPM_NVRAM_StoreData: Opening file %s\n", filename);
        file = fopen(filename, "wb");                           /* closed @1 */
        if (file == NULL) {
            fprintf(stderr,
                    "SWTPM_NVRAM_StoreData: Error (fatal) opening %s for "
                    "write failed, %s\n", filename, strerror(errno));
            rc = TPM_FAIL;
        }
    }

    if (rc == 0 && encrypt) {
        rc = SWTPM_NVRAM_EncryptData(&filekey, &encrypt_data, &encrypt_length,
                                     data, length);
        if (encrypt_data) {
            TPM_DEBUG("  SWTPM_NVRAM_StoreData: Encrypted %u bytes before "
                      "write, will write %u bytes\n", length, encrypt_length);
            length = encrypt_length;
        }
    }

    /* write the data to the file */
    if (rc == 0) {
        TPM_DEBUG("  SWTPM_NVRAM_StoreData: Writing %u bytes of data\n", length);
        lrc = fwrite(encrypt_data ? encrypt_data : data, 1,
                     length, file);
        if (lrc != length) {
            fprintf(stderr, "TPM_NVRAM_StoreData: Error (fatal), data write "
                    "of %u only wrote %u\n", length, lrc);
            rc = TPM_FAIL;
        }
    }
    if (file != NULL) {
        TPM_DEBUG("  SWTPM_NVRAM_StoreData: Closing file %s\n", filename);
        irc = fclose(file);             /* @1 */
        if (irc != 0) {
            fprintf(stderr, "SWTPM_NVRAM_StoreData: Error (fatal) closing "
                    "file\n");
            rc = TPM_FAIL;
        }
        else {
            TPM_DEBUG("  SWTPM_NVRAM_StoreData: Closed file %s\n", filename);
        }
    }

    TPM_Free(encrypt_data);

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
*/

static TPM_RESULT SWTPM_NVRAM_GetFilenameForName(char *filename,        /* output: rooted filename */
                                                 size_t bufsize,
                                                 uint32_t tpm_number,
                                                 const char *name)      /* input: abstract name */
{
    TPM_RESULT res = TPM_SUCCESS;
    int n;

    TPM_DEBUG(" SWTPM_NVRAM_GetFilenameForName: For name %s\n", name);

    n = snprintf(filename, bufsize, "%s/tpm-%02lx.%s",
                 state_directory, (unsigned long)tpm_number, name);
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
                                        tpm_number, name);
    if (rc == 0) {
        irc = remove(filename);
        if ((irc != 0) &&               /* if the remove failed */
            (mustExist ||               /* if any error is a failure, or */
             (errno != ENOENT))) {      /* if error other than no such file */
            fprintf(stderr, "SWTPM_NVRAM_DeleteName: Error, (fatal) file "
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

    TPM_Free(buffer);

    return rc;
}

static TPM_RESULT
SWTPM_NVRAM_KeyParamCheck(uint32_t keylen,
                          enum encryption_mode encmode)
{
    TPM_RESULT rc = 0;

    if (keylen != TPM_AES_BLOCK_SIZE) {
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

TPM_BOOL SWTPM_NVRAM_Has_FileKey(void)
{
    return filekey.symkey.valid;
}

TPM_RESULT SWTPM_NVRAM_Set_FileKey(const unsigned char *key, uint32_t keylen,
                                   enum encryption_mode encmode)
{
    TPM_RESULT rc;

    rc = SWTPM_NVRAM_KeyParamCheck(keylen, encmode);

    if (rc == 0) {
        filekey.symkey.valid = TRUE;
        memcpy(filekey.symkey.userKey, key, keylen);
        filekey.data_encmode = encmode;
    }

    return rc;
}

TPM_BOOL SWTPM_NVRAM_Has_MigrationKey(void)
{
    return migrationkey.symkey.valid;
}

TPM_RESULT SWTPM_NVRAM_Set_MigrationKey(const unsigned char *key,
                                        uint32_t keylen,
                                        enum encryption_mode encmode)
{
    TPM_RESULT rc;

    rc = SWTPM_NVRAM_KeyParamCheck(keylen, encmode);

    if (rc == 0) {
        migrationkey.symkey.valid = TRUE;
        memcpy(migrationkey.symkey.userKey, key, keylen);
        migrationkey.data_encmode = encmode;
    }

    return rc;
}

static TPM_RESULT
SWTPM_PrependHash(const unsigned char *in, uint32_t in_length,
                  unsigned char **out, uint32_t *out_length)
{
    TPM_RESULT rc = 0;
    unsigned char *dest;
#ifdef USE_FREEBL_CRYPTO_LIBRARY
    unsigned char hashbuf[SHA256_LENGTH];
#else
    unsigned char hashbuf[SHA256_DIGEST_LENGTH];
#endif

    /* hash the data */
#ifdef USE_FREEBL_CRYPTO_LIBRARY
    if (SHA256_HashBuf(hashbuf, in, in_length) != SECSuccess) {
        logprintf(STDOUT_FILENO, "SHA256_HashBuff failed.\n");
        rc = TPM_FAIL;
    }
#else
    SHA256(in, in_length, hashbuf);
#endif

    *out_length = sizeof(hashbuf) + in_length;
    rc = TPM_Malloc(out, *out_length);

    if (rc == TPM_SUCCESS) {
        dest = *out;
        memcpy(dest, hashbuf, sizeof(hashbuf));
        memcpy(&dest[sizeof(hashbuf)], in, in_length);
    }

    return rc;
}

static TPM_RESULT
SWTPM_CheckHash(const unsigned char *in, uint32_t in_length,
                unsigned char **out, uint32_t *out_length)
{
    TPM_RESULT rc = 0;
    unsigned char *dest = NULL;
#ifdef USE_FREEBL_CRYPTO_LIBRARY
    unsigned char hashbuf[SHA256_LENGTH];
#else
    unsigned char hashbuf[SHA256_DIGEST_LENGTH];
#endif
    const unsigned char *data = &in[sizeof(hashbuf)];
    uint32_t data_length = in_length - sizeof(hashbuf);

    /* hash the data */
#ifdef USE_FREEBL_CRYPTO_LIBRARY
    if (SHA256_HashBuf(hashbuf, data, data_length) != SECSuccess) {
        logprintf(STDOUT_FILENO, "SHA256_HashBuff failed.\n");
        rc = TPM_FAIL;
    }
#else
    SHA256(data, data_length, hashbuf);
#endif

    if (memcmp(in, hashbuf, sizeof(hashbuf))) {
        logprintf(STDOUT_FILENO, "Verification of hash failed. "
                  "Data integrity is compromised\n");
        rc = TPM_FAIL;
    }

    if (rc == TPM_SUCCESS) {
        rc = TPM_Malloc(&dest, data_length);
        if (rc == TPM_SUCCESS) {
            *out = dest;
            *out_length = data_length;
            memcpy(dest, data, data_length);
        }
    }

    return rc;
}

static TPM_RESULT 
SWTPM_NVRAM_EncryptData(const encryptionkey *key,
                        unsigned char **encrypt_data,
                        uint32_t *encrypt_length,
                        const unsigned char *decrypt_data,
                        uint32_t decrypt_length)
{
    TPM_RESULT rc = 0;
    unsigned char *hashed_data = NULL;
    uint32_t hashed_length = 0;

    if (rc == 0) {
        if (key->symkey.valid) {
            switch (key->data_encmode) {
            case ENCRYPTION_MODE_UNKNOWN:
                rc = TPM_BAD_MODE;
                break;
            case ENCRYPTION_MODE_AES_CBC:
                rc = SWTPM_PrependHash(decrypt_data, decrypt_length,
                                       &hashed_data, &hashed_length);
                if (rc)
                     break;
                rc = TPM_SymmetricKeyData_Encrypt(encrypt_data,
                                                  encrypt_length,
                                                  hashed_data,
                                                  hashed_length,
                                                  &key->symkey);
                TPM_Free(hashed_data);
                break;
            }
        }
    }

    return rc;
}

static TPM_RESULT 
SWTPM_NVRAM_DecryptData(const encryptionkey *key,
                        unsigned char **decrypt_data,
                        uint32_t *decrypt_length,
                        const unsigned char *encrypt_data,
                        uint32_t encrypt_length)
{
    TPM_RESULT rc = 0;
    unsigned char *hashed_data = NULL;
    uint32_t hashed_length = 0;

    if (rc == 0) {
        if (key->symkey.valid) {
            switch (key->data_encmode) {
            case ENCRYPTION_MODE_UNKNOWN:
                rc = TPM_BAD_MODE;
                break;
            case ENCRYPTION_MODE_AES_CBC:
                rc = TPM_SymmetricKeyData_Decrypt(&hashed_data,
                                                  &hashed_length,
                                                  encrypt_data,
                                                  encrypt_length,
                                                  &key->symkey);
                if (rc == TPM_SUCCESS) {
                    rc = SWTPM_CheckHash(hashed_data, hashed_length,
                                         decrypt_data, decrypt_length);
                    TPM_Free(hashed_data);
                }
                break;
            }
        }
    }

    return rc;
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
        .min_version = BLOB_HEADER_VERSION,
        .hdrsize = htons(sizeof(bh)),
        .flags = htons(flags),
        .totlen = htonl(out_len),
    };
    TPM_RESULT res;

    res = TPM_Malloc(&out, out_len);
    if (res != TPM_SUCCESS)
        goto error;

    memcpy(out, &bh, sizeof(bh));
    memcpy(&out[sizeof(bh)], *data, *length);

    *data = out;
    *length = out_len;

    return res;

 error:
    TPM_Free(*data);
    *data = NULL;
    *length = 0;

    return res;
}


static TPM_RESULT
SWTPM_NVRAM_CheckHeader(unsigned char *data, uint32_t length,
                        uint32_t *dataoffset, uint16_t *hdrflags)
{
    blobheader *bh = (blobheader *)data;

    if (length < sizeof(bh))
        return TPM_BAD_PARAMETER;

    if (ntohl(bh->totlen) != length)
        return TPM_BAD_PARAMETER;

    if (bh->min_version > BLOB_HEADER_VERSION) {
        logprintf(STDERR_FILENO, "Minimum required version for the blob is %d, we "
                  "only support version %d\n", bh->min_version,
                  BLOB_HEADER_VERSION);
        return TPM_BAD_VERSION;
    }

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

    res = SWTPM_NVRAM_LoadData_Intern(data, length, tpm_number, name,
                                      decrypt);
    if (decrypt) {
        /* we asked for a decrypted blob, so it cannot be encrypted */
        *is_encrypted = FALSE;
    } else {
        /*
         * We did not ask for a decrypted blob; in this case it's
         * encrypted if there is a key set
         */
        *is_encrypted = filekey.symkey.valid;
    }

    if (res == TPM_SUCCESS && migrationkey.symkey.valid) {
        /*
         * we have to encrypt it now with the migration key
         */
        unsigned char *out = NULL;
        uint32_t out_len = 0;

        flags |= BLOB_FLAG_MIGRATION_ENCRYPTED;

        res = SWTPM_NVRAM_EncryptData(&migrationkey, &out, &out_len,
                                      *data, *length);
        TPM_Free(*data);
        if (res == TPM_SUCCESS) {
            *data = out;
            *length = out_len;
        } else {
            *data = NULL;
            *length = 0;
        }
    }

    if (res == TPM_SUCCESS) {
        /* put the header in clear text */
        if (*is_encrypted)
            flags |= BLOB_FLAG_ENCRYPTED;

        res = SWTPM_NVRAM_PrependHeader(data, length, flags);
    }

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
                                    const char *name)
{
    TPM_BOOL encrypt = !is_encrypted;
    TPM_RESULT res;
    uint32_t dataoffset;
    unsigned char *plain = NULL;
    uint32_t plain_len = 0;
    uint16_t hdrflags;

    if (length == 0) {
        /* with 0 bytes length we delete any existing file */
        SWTPM_NVRAM_DeleteName(tpm_number, name, FALSE);
        return TPM_SUCCESS;
    }

    res = SWTPM_NVRAM_CheckHeader(data, length, &dataoffset, &hdrflags);
    if (res != TPM_SUCCESS)
        return res;

    /*
     * We allow setting of blobs that were not encrypted before;
     * we just will not decrypt them even if the migration key is
     * set. This allows to 'upgrade' to encryption. 'Downgrading'
     * will not be possible once a migration key was used.
     */
    if ((hdrflags & BLOB_FLAG_MIGRATION_ENCRYPTED) && migrationkey.symkey.valid) {
         /*
          * we first need to decrypt the data with the migration key
          */
         res = SWTPM_NVRAM_DecryptData(&migrationkey,
                                       &plain, &plain_len,
                                       &data[dataoffset], length - dataoffset);
         if (res == TPM_SUCCESS) {
             res = SWTPM_NVRAM_StoreData_Intern(plain, plain_len,
                                                tpm_number,
                                                name,
                                                encrypt);
             TPM_Free(plain);
         }
         return res;
    }

    return SWTPM_NVRAM_StoreData_Intern(&data[dataoffset], length - dataoffset,
                                        tpm_number, name, encrypt);
}
