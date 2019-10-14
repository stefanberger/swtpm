/********************************************************************************/
/*                                                                              */
/*                      Platform Dependent Crypto                               */
/*                           Written by Ken Goldman                             */
/*                     IBM Thomas J. Watson Research Center                     */
/*            $Id: tpm_crypto_freebl.c 4655 2011-12-21 21:03:15Z kgoldman $     */
/*                                                                              */
/* (c) Copyright IBM Corporation 2006, 2010.					*/
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

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/aes.h>

#include <libtpms/tpm_types.h>
#include <libtpms/tpm_error.h>
#include <libtpms/tpm_memory.h>

#include "swtpm_aes.h"
#include "logging.h"

#define printf(X ...)

/* TPM_SymmetricKeyData_Encrypt() is AES non-portable code to encrypt 'decrypt_data' to
   'encrypt_data'

   The stream is padded as per PKCS#7 / RFC2630

   'encrypt_data' must be free by the caller
*/

TPM_RESULT SWTPM_SymmetricKeyData_Encrypt(unsigned char **encrypt_data,   /* output, caller frees */
                                          uint32_t *encrypt_length,		/* output */
                                          const unsigned char *decrypt_data,	/* input */
                                          uint32_t decrypt_length,		/* input */
                                          const TPM_SYMMETRIC_KEY_DATA
					    *tpm_symmetric_key_token,		/* input */
                                          const unsigned char *u_ivec,		/* input */
                                          uint32_t u_ivec_length)		/* input */
{
    TPM_RESULT          rc = 0;
    uint32_t              pad_length;
    unsigned char       *decrypt_data_pad;
    unsigned char       ivec[SWTPM_AES256_BLOCK_SIZE];       /* initial chaining vector */
    TPM_SYMMETRIC_KEY_DATA *tpm_symmetric_key_data =
	(TPM_SYMMETRIC_KEY_DATA *)tpm_symmetric_key_token;
    AES_KEY key;
    size_t userKeyLength = tpm_symmetric_key_token->userKeyLength;

    printf(" TPM_SymmetricKeyData_Encrypt: Length %u\n", decrypt_length);
    decrypt_data_pad = NULL;    /* freed @1 */

    if (rc == 0) {
        if (u_ivec != NULL && u_ivec_length != userKeyLength) {
            printf("TPM_SymmetricKeyData_Encrypt: IV is %u bytes, "
                   "but expected %u bytes\n", u_ivec_length,
                   tpm_symmetric_key_token->userKeyLength);
            rc = TPM_ENCRYPT_ERROR;
        } else {
            if (u_ivec) {
                /* copy user-provided IV */
                memcpy(ivec, u_ivec, u_ivec_length);
            } else {
                memset(ivec, 0, sizeof(ivec));
            }
        }
    }

    if (rc == 0) {
        /* calculate the pad length and padded data length */
        pad_length = userKeyLength - (decrypt_length % userKeyLength);
        *encrypt_length = decrypt_length + pad_length;
        printf("  TPM_SymmetricKeyData_Encrypt: Padded length %u pad length %u\n",
               *encrypt_length, pad_length);
        /* allocate memory for the encrypted response */
        *encrypt_data = malloc(*encrypt_length);
        if (!*encrypt_data) {
            logprintf(STDERR_FILENO,
                      "Could not allocated %u bytes.\n", *encrypt_length);
            rc = TPM_SIZE;
        }
    }
    /* allocate memory for the padded decrypted data */
    if (rc == 0) {
        decrypt_data_pad = malloc(*encrypt_length);
        if (!decrypt_data_pad) {
            logprintf(STDERR_FILENO,
                      "Could not allocated %u bytes.\n", *encrypt_length);
            rc = TPM_SIZE;
        }
    }

    if (rc == 0) {
        if (AES_set_encrypt_key(tpm_symmetric_key_data->userKey,
                                userKeyLength * 8,
                                &key) < 0) {
            rc = TPM_FAIL;
        }
    }

    /* pad the decrypted clear text data */
    if (rc == 0) {
        /* unpadded original data */
        memcpy(decrypt_data_pad, decrypt_data, decrypt_length);
        /* last gets pad = pad length */
        memset(decrypt_data_pad + decrypt_length, pad_length, pad_length);
        /* encrypt the padded input to the output */
        //TPM_PrintFour("  TPM_SymmetricKeyData_Encrypt: Input", decrypt_data_pad);
        AES_cbc_encrypt(decrypt_data_pad,
                        *encrypt_data,
                        *encrypt_length,
                        &key,
                        ivec,
                        AES_ENCRYPT);
        //TPM_PrintFour("  TPM_SymmetricKeyData_Encrypt: Output", *encrypt_data);
    }
    free(decrypt_data_pad);     /* @1 */
    return rc;
}

/* TPM_SymmetricKeyData_Decrypt() is AES non-portable code to decrypt 'encrypt_data' to
   'decrypt_data'

   The stream must be padded as per PKCS#7 / RFC2630

   decrypt_data must be free by the caller
*/

TPM_RESULT SWTPM_SymmetricKeyData_Decrypt(unsigned char **decrypt_data,   /* output, caller frees */
                                          uint32_t *decrypt_length,		/* output */
                                          const unsigned char *encrypt_data,	/* input */
                                          uint32_t encrypt_length,		/* input */
                                          const TPM_SYMMETRIC_KEY_DATA
					     *tpm_symmetric_key_token,		/* input */
					  const unsigned char *u_ivec,		/* input */
                                          uint32_t u_ivec_length)		/* input */
{
    TPM_RESULT          rc = 0;
    uint32_t		pad_length;
    uint32_t		i;
    unsigned char       *pad_data;
    unsigned char       ivec[SWTPM_AES256_BLOCK_SIZE];       /* initial chaining vector */
    TPM_SYMMETRIC_KEY_DATA *tpm_symmetric_key_data =
	(TPM_SYMMETRIC_KEY_DATA *)tpm_symmetric_key_token;
    AES_KEY             key;
    size_t userKeyLength = tpm_symmetric_key_token->userKeyLength;

    printf(" TPM_SymmetricKeyData_Decrypt: Length %u\n", encrypt_length);
    /* sanity check encrypted length */
    if (rc == 0) {
        if (encrypt_length < userKeyLength) {
            printf("TPM_SymmetricKeyData_Decrypt: Error, bad length\n");
            rc = TPM_DECRYPT_ERROR;
        }
    }
    if (rc == 0) {
        if (u_ivec != NULL && u_ivec_length != userKeyLength) {
            printf("TPM_SymmetricKeyData_Decrypt: IV is %u bytes, "
                   "but expected %u bytes\n", u_ivec_length, userKeyLength);
            rc = TPM_DECRYPT_ERROR;
        } else {
            if (u_ivec) {
                /* copy user-provided IV */
                memcpy(ivec, u_ivec, u_ivec_length);
            } else {
                memset(ivec, 0, sizeof(ivec));
            }
        }
    }
    /* allocate memory for the padded decrypted data */
    if (rc == 0) {
        *decrypt_data = malloc(encrypt_length);
        if (!*decrypt_data) {
            logprintf(STDERR_FILENO,
                      "Could not allocated %u bytes.\n", encrypt_length);
            rc = TPM_SIZE;
        }
    }

    if (rc == 0) {
        if (AES_set_decrypt_key(tpm_symmetric_key_data->userKey,
                                userKeyLength * 8,
                                &key) < 0) {
            rc = TPM_FAIL;
        }
    }

    /* decrypt the input to the padded output */
    if (rc == 0) {
        /* decrypt the padded input to the output */
        //TPM_PrintFour("  TPM_SymmetricKeyData_Decrypt: Input", encrypt_data);
        AES_cbc_encrypt(encrypt_data,
                        *decrypt_data,
                        encrypt_length,
                        &key,
                        ivec,
                        AES_DECRYPT);
        //TPM_PrintFour("  TPM_SymmetricKeyData_Decrypt: Output", *decrypt_data);
    }
    /* get the pad length */
    if (rc == 0) {
        /* get the pad length from the last byte */
        pad_length = (uint32_t)*(*decrypt_data + encrypt_length - 1);
        /* sanity check the pad length */
        printf(" TPM_SymmetricKeyData_Decrypt: Pad length %u\n", pad_length);
        if ((pad_length == 0) ||
            (pad_length > userKeyLength)) {
            printf("TPM_SymmetricKeyData_Decrypt: Error, illegal pad length\n");
            rc = TPM_DECRYPT_ERROR;
        }
    }
    if (rc == 0) {
        /* get the unpadded length */
        *decrypt_length = encrypt_length - pad_length;
        /* pad starting point */
        pad_data = *decrypt_data + *decrypt_length;
        /* sanity check the pad */
        for (i = 0 ; i < pad_length ; i++, pad_data++) {
            if (*pad_data != pad_length) {
                printf("TPM_SymmetricKeyData_Decrypt: Error, bad pad %02x at index %u\n",
                       *pad_data, i);
                rc = TPM_DECRYPT_ERROR;
            }
        }
    }
    return rc;
}
