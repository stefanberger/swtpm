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

#ifndef _SWTPM_NVSTORE_DIR_H
#define _SWTPM_NVSTORE_DIR_H

#include <libtpms/tpm_types.h>
#include <libtpms/tpm_library.h>

/* characters in the TPM base file name, 14 for file name, slash, NUL terminator, etc.

   This macro is used once during initialization to ensure that the TPM_PATH environment variable
   length will not cause the rooted file name to overflow file name buffers.
*/

#define TPM_FILENAME_MAX 20

TPM_RESULT
SWTPM_NVRAM_Prepare_Dir(const char *uri);

TPM_RESULT
SWTPM_NVRAM_LoadData_Dir(unsigned char **data,
                         uint32_t *length,
                         uint32_t tpm_number,
                         const char *name,
                         const char *uri);

TPM_RESULT
SWTPM_NVRAM_StoreData_Dir(unsigned char *filedata,
                          uint32_t filedata_length,
                          uint32_t tpm_number,
                          const char *name,
                          const char *uri);

TPM_RESULT
SWTPM_NVRAM_DeleteName_Dir(uint32_t tpm_number,
                           const char *name,
                           TPM_BOOL mustExist,
                           const char *uri);

extern struct nvram_backend_ops nvram_dir_ops;

#endif /* _SWTPM_NVSTORE_DIR_H */
