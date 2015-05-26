/********************************************************************************/
/*                                                                              */
/*                              NVRAM Utilities                                 */
/*                           Written by Ken Goldman                             */
/*                     IBM Thomas J. Watson Research Center                     */
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

#ifndef _SWTPM_NVFILE_H
#define _SWTPM_NVFILE_H

#include <libtpms/tpm_types.h>

#include "key.h"

/* characters in the TPM base file name, 14 for file name, slash, NUL terminator, etc.

   This macro is used once during initialization to ensure that the TPM_PATH environment variable
   length will not cause the rooted file name to overflow file name buffers.
*/

#define TPM_FILENAME_MAX 20

TPM_RESULT SWTPM_NVRAM_Init(void);

/*
  Basic abstraction for read and write
*/

TPM_RESULT SWTPM_NVRAM_LoadData(unsigned char **data,
                                uint32_t *length,
			        uint32_t tpm_number,
                                const char *name);
TPM_RESULT SWTPM_NVRAM_StoreData(const unsigned char *data,
                                 uint32_t length,
			         uint32_t tpm_number,
                                 const char *name);
TPM_RESULT SWTPM_NVRAM_DeleteName(uint32_t tpm_number,
				  const char *name,
                                  TPM_BOOL mustExist);
TPM_RESULT SWTPM_NVRAM_Store_Volatile(void);

TPM_RESULT SWTPM_NVRAM_Set_FileKey(const unsigned char *data,
                                   uint32_t length,
                                   enum encryption_mode mode);

TPM_RESULT SWTPM_NVRAM_Set_MigrationKey(const unsigned char *data,
                                        uint32_t length,
                                        enum encryption_mode mode);

TPM_RESULT SWTPM_NVRAM_GetStateBlob(unsigned char **data,
                                    uint32_t *length,
                                    uint32_t tpm_number,
                                    const char *name,
                                    TPM_BOOL decrypt,
                                    TPM_BOOL *is_encrypted);

TPM_RESULT SWTPM_NVRAM_SetStateBlob(unsigned char *data,
                                    uint32_t length,
                                    TPM_BOOL is_encrypted,
                                    uint32_t tpm_number,
                                    const char *name);

TPM_BOOL SWTPM_NVRAM_Has_FileKey(void);
TPM_BOOL SWTPM_NVRAM_Has_MigrationKey(void);

#endif /* _SWTPM_NVFILE_H */

