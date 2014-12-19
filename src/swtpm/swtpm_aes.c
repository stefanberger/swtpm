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

#ifdef USE_FREEBL_CRYPTO_LIBRARY
# include <blapi.h>
#else
# ifdef USE_OPENSSL_CRYPTO_LIBRARY
#  include <openssl/aes.h>
# else
#  error "Unsupported crypto library."
# endif
#endif

#include <libtpms/tpm_types.h>
#include <libtpms/tpm_error.h>
#include <libtpms/tpm_memory.h>

#include "swtpm_aes.h"


#ifdef USE_FREEBL_CRYPTO_LIBRARY
/* TPM_SymmetricKeyData_Encrypt() is AES non-portable code to CBC encrypt 'decrypt_data' to
   'encrypt_data'

   The stream is padded as per PKCS#7 / RFC2630

   'encrypt_data' must be free by the caller
*/

TPM_RESULT TPM_SymmetricKeyData_Encrypt(unsigned char **encrypt_data,   /* output, caller frees */
                                        uint32_t *encrypt_length,		/* output */
                                        const unsigned char *decrypt_data,	/* input */
                                        uint32_t decrypt_length,		/* input */
                                        const TPM_SYMMETRIC_KEY_DATA
					*tpm_symmetric_key_token) 		/* input */
{
    TPM_RESULT          rc = 0;
    SECStatus 		rv;
    AESContext 		*cx;
    uint32_t		pad_length;
    uint32_t		output_length;			/* dummy */
    unsigned char       *decrypt_data_pad;
    unsigned char       ivec[TPM_AES_BLOCK_SIZE];       /* initial chaining vector */
    TPM_SYMMETRIC_KEY_DATA *tpm_symmetric_key_data =
	(TPM_SYMMETRIC_KEY_DATA *)tpm_symmetric_key_token;

    printf(" TPM_SymmetricKeyData_Encrypt: Length %u\n", decrypt_length);
    decrypt_data_pad = NULL;    /* freed @1 */
    cx = NULL;    		/* freed @2 */
    
    /* sanity check that the AES key has previously been generated */
    if (rc == 0) {
	if (!tpm_symmetric_key_data->valid) {
	    printf("TPM_SymmetricKeyData_Encrypt: Error (fatal), AES key not valid\n");
	    rc = TPM_FAIL;
	}
    }
    if (rc == 0) {
        /* calculate the PKCS#7 / RFC2630 pad length and padded data length */
        pad_length = TPM_AES_BLOCK_SIZE - (decrypt_length % TPM_AES_BLOCK_SIZE);
        *encrypt_length = decrypt_length + pad_length;
        printf("  TPM_SymmetricKeyData_Encrypt: Padded length %u pad length %u\n",
               *encrypt_length, pad_length);
        /* allocate memory for the encrypted response */
        rc = TPM_Malloc(encrypt_data, *encrypt_length);
    }
    /* allocate memory for the padded decrypted data */
    if (rc == 0) {
        rc = TPM_Malloc(&decrypt_data_pad, *encrypt_length);
    }
    if (rc == 0) {
        /* set the IV */
        memset(ivec, 0, sizeof(ivec));
	/* create a new AES context */
	cx = AES_CreateContext(tpm_symmetric_key_data->userKey,
			       ivec, 			/* CBC initialization vector */
			       NSS_AES_CBC,		/* CBC mode */
			       TRUE,			/* encrypt */
			       TPM_AES_BLOCK_SIZE,	/* key length */
			       TPM_AES_BLOCK_SIZE);	/* AES  block length */
	if (cx == NULL) {
	    printf("TPM_SymmetricKeyData_Encrypt: Error creating AES context\n");
	    rc = TPM_SIZE;
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
	/* perform the AES encryption */
	rv = AES_Encrypt(cx,
			 *encrypt_data, &output_length, *encrypt_length,	/* output */
			 decrypt_data_pad, *encrypt_length);			/* input */

	if (rv != SECSuccess) {
	    printf("TPM_SymmetricKeyData_Encrypt: Error, rv %d\n", rv);
	    rc = TPM_ENCRYPT_ERROR;
	}
    }
    if (rc == 0) {
       //TPM_PrintFour("  TPM_SymmetricKeyData_Encrypt: Output", *encrypt_data);
    }	
    free(decrypt_data_pad);     	/* @1 */
    if (cx != NULL) {
	/* due to a FreeBL bug, must zero the context before destroying it */
	unsigned char dummy_key[TPM_AES_BLOCK_SIZE];
	unsigned char dummy_ivec[TPM_AES_BLOCK_SIZE];
	memset(dummy_key, 0x00, TPM_AES_BLOCK_SIZE);
	memset(dummy_ivec, 0x00, TPM_AES_BLOCK_SIZE);
	rv = AES_InitContext(cx,			/* AES context */
			     dummy_key,			/* AES key */
			     TPM_AES_BLOCK_SIZE,	/* key length */
			     dummy_ivec, 		/* ivec */
			     NSS_AES_CBC,		/* CBC mode */
			     TRUE,			/* encrypt */
			     TPM_AES_BLOCK_SIZE);	/* AES  block length */
	AES_DestroyContext(cx, PR_TRUE);	/* @2 */
    }
    return rc;
}

/* TPM_SymmetricKeyData_Decrypt() is AES non-portable code to CBC decrypt 'encrypt_data' to
   'decrypt_data'

   The stream must be padded as per PKCS#7 / RFC2630

   decrypt_data must be free by the caller
*/

TPM_RESULT TPM_SymmetricKeyData_Decrypt(unsigned char **decrypt_data,   /* output, caller frees */
                                        uint32_t *decrypt_length,		/* output */
                                        const unsigned char *encrypt_data,	/* input */
                                        uint32_t encrypt_length,		/* input */
                                        const TPM_SYMMETRIC_KEY_DATA
					*tpm_symmetric_key_token) 		/* input */
{
    TPM_RESULT          rc = 0;
    SECStatus 		rv;
    AESContext 		*cx;
    uint32_t		pad_length;
    uint32_t		output_length;			/* dummy */
    uint32_t		i;
    unsigned char       *pad_data;
    unsigned char       ivec[TPM_AES_BLOCK_SIZE];       /* initial chaining vector */
    TPM_SYMMETRIC_KEY_DATA *tpm_symmetric_key_data =
	(TPM_SYMMETRIC_KEY_DATA *)tpm_symmetric_key_token;
    
    printf(" TPM_SymmetricKeyData_Decrypt: Length %u\n", encrypt_length);
    cx = NULL;    /* freed @1 */

    /* sanity check encrypted length */
    if (rc == 0) {
        if (encrypt_length < TPM_AES_BLOCK_SIZE) {
            printf("TPM_SymmetricKeyData_Decrypt: Error, bad length\n");
            rc = TPM_DECRYPT_ERROR;
        }
    }
    /* sanity check that the AES key has previously been generated */
    if (rc == 0) {
	if (!tpm_symmetric_key_data->valid) {
	    printf("TPM_SymmetricKeyData_Decrypt: Error (fatal), AES key not valid\n");
	    rc = TPM_FAIL;
	}
    }
    /* allocate memory for the PKCS#7 / RFC2630 padded decrypted data */
    if (rc == 0) {
        rc = TPM_Malloc(decrypt_data, encrypt_length);
    }
    if (rc == 0) {
        /* set the IV */
        memset(ivec, 0, sizeof(ivec));
	/* create a new AES context */
	cx = AES_CreateContext(tpm_symmetric_key_data->userKey,
			       ivec, 			/* CBC initialization vector */ 
			       NSS_AES_CBC,		/* CBC mode */
			       FALSE,			/* decrypt */
			       TPM_AES_BLOCK_SIZE,	/* key length */
			       TPM_AES_BLOCK_SIZE);	/* AES  block length */
	if (cx == NULL) {
	    printf("TPM_SymmetricKeyData_Decrypt: Error creating AES context\n");
	    rc = TPM_SIZE;
	}
    }
    /* decrypt the input to the PKCS#7 / RFC2630 padded output */
    if (rc == 0) {
        //TPM_PrintFour("  TPM_SymmetricKeyData_Decrypt: Input", encrypt_data);
	/* perform the AES decryption */
	rv = AES_Decrypt(cx,
			 *decrypt_data, &output_length, encrypt_length,	/* output */
			 encrypt_data, encrypt_length);			/* input */
	if (rv != SECSuccess) {
	    printf("TPM_SymmetricKeyData_Decrypt: Error, rv %d\n", rv);
	    rc = TPM_DECRYPT_ERROR;
	}
    }
    if (rc == 0) {
        //TPM_PrintFour("  TPM_SymmetricKeyData_Decrypt: Output", *decrypt_data);
    }
    /* get the pad length */
    if (rc == 0) {
        /* get the pad length from the last byte */
        pad_length = (uint32_t)*(*decrypt_data + encrypt_length - 1);
        /* sanity check the pad length */
        printf(" TPM_SymmetricKeyData_Decrypt: Pad length %u\n", pad_length);
        if ((pad_length == 0) ||
            (pad_length > TPM_AES_BLOCK_SIZE)) {
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
    if (cx != NULL) {
	/* due to a FreeBL bug, must zero the context before destroying it */
	unsigned char dummy_key[TPM_AES_BLOCK_SIZE];
	unsigned char dummy_ivec[TPM_AES_BLOCK_SIZE];
	memset(dummy_key, 0x00, TPM_AES_BLOCK_SIZE);
	memset(dummy_ivec, 0x00, TPM_AES_BLOCK_SIZE);
	rv = AES_InitContext(cx,			/* AES context */
			     dummy_key,			/* AES key */
			     TPM_AES_BLOCK_SIZE,	/* key length */
			     dummy_ivec, 		/* ivec */
			     NSS_AES_CBC,		/* CBC mode */
			     TRUE,			/* encrypt */
			     TPM_AES_BLOCK_SIZE);	/* AES  block length */
	AES_DestroyContext(cx, PR_TRUE);	/* @1 */
    }
    return rc;
}

#endif /* USE_FREEBL_CRYPTO_LIBRARY */

#ifdef USE_OPENSSL_CRYPTO_LIBRARY
/* TPM_SymmetricKeyData_Encrypt() is AES non-portable code to encrypt 'decrypt_data' to
   'encrypt_data'

   The stream is padded as per PKCS#7 / RFC2630

   'encrypt_data' must be free by the caller
*/

TPM_RESULT TPM_SymmetricKeyData_Encrypt(unsigned char **encrypt_data,   /* output, caller frees */
                                        uint32_t *encrypt_length,		/* output */
                                        const unsigned char *decrypt_data,	/* input */
                                        uint32_t decrypt_length,		/* input */
                                        const TPM_SYMMETRIC_KEY_DATA
					*tpm_symmetric_key_token) 		/* input */
{
    TPM_RESULT          rc = 0;
    uint32_t              pad_length;
    unsigned char       *decrypt_data_pad;
    unsigned char       ivec[TPM_AES_BLOCK_SIZE];       /* initial chaining vector */
    TPM_SYMMETRIC_KEY_DATA *tpm_symmetric_key_data =
	(TPM_SYMMETRIC_KEY_DATA *)tpm_symmetric_key_token;
    AES_KEY key;

    printf(" TPM_SymmetricKeyData_Encrypt: Length %u\n", decrypt_length);
    decrypt_data_pad = NULL;    /* freed @1 */
    if (rc == 0) {
        /* calculate the pad length and padded data length */
        pad_length = TPM_AES_BLOCK_SIZE - (decrypt_length % TPM_AES_BLOCK_SIZE);
        *encrypt_length = decrypt_length + pad_length;
        printf("  TPM_SymmetricKeyData_Encrypt: Padded length %u pad length %u\n",
               *encrypt_length, pad_length);
        /* allocate memory for the encrypted response */
        rc = TPM_Malloc(encrypt_data, *encrypt_length);
    }
    /* allocate memory for the padded decrypted data */
    if (rc == 0) {
        rc = TPM_Malloc(&decrypt_data_pad, *encrypt_length);
    }

    if (rc == 0) {
        if (AES_set_encrypt_key(tpm_symmetric_key_data->userKey,
                                sizeof(tpm_symmetric_key_data->userKey) * 8,
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
        /* set the IV */
        memset(ivec, 0, sizeof(ivec));
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

TPM_RESULT TPM_SymmetricKeyData_Decrypt(unsigned char **decrypt_data,   /* output, caller frees */
                                        uint32_t *decrypt_length,		/* output */
                                        const unsigned char *encrypt_data,	/* input */
                                        uint32_t encrypt_length,		/* input */
                                        const TPM_SYMMETRIC_KEY_DATA
					*tpm_symmetric_key_token) 		/* input */
{
    TPM_RESULT          rc = 0;
    uint32_t		pad_length;
    uint32_t		i;
    unsigned char       *pad_data;
    unsigned char       ivec[TPM_AES_BLOCK_SIZE];       /* initial chaining vector */
    TPM_SYMMETRIC_KEY_DATA *tpm_symmetric_key_data =
	(TPM_SYMMETRIC_KEY_DATA *)tpm_symmetric_key_token;
    AES_KEY             key;

    printf(" TPM_SymmetricKeyData_Decrypt: Length %u\n", encrypt_length);
    /* sanity check encrypted length */
    if (rc == 0) {
        if (encrypt_length < TPM_AES_BLOCK_SIZE) {
            printf("TPM_SymmetricKeyData_Decrypt: Error, bad length\n");
            rc = TPM_DECRYPT_ERROR;
        }
    }
    /* allocate memory for the padded decrypted data */
    if (rc == 0) {
        rc = TPM_Malloc(decrypt_data, encrypt_length);
    }

    if (rc == 0) {
        if (AES_set_decrypt_key(tpm_symmetric_key_data->userKey,
                                sizeof(tpm_symmetric_key_data->userKey) * 8,
                                &key) < 0) {
            rc = TPM_FAIL;
        }
    }

    /* decrypt the input to the padded output */
    if (rc == 0) {
        /* set the IV */
        memset(ivec, 0, sizeof(ivec));
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
            (pad_length > TPM_AES_BLOCK_SIZE)) {
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
#endif /* USE_OPENSSL_CRYPTO_LIBRARY */
