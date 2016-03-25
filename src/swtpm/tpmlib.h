/*
 * tpmlib.h -- interface with libtpms
 *
 * (c) Copyright IBM Corporation 2015.
 *
 * Author: Stefan Berger <stefanb@us.ibm.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * Neither the names of the IBM Corporation nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _SWTPM_TPMLIB_H_
#define _SWTPM_TPMLIB_H_

#include <stdint.h>
#include <stdbool.h>

#include <libtpms/tpm_library.h>

const char *tpmlib_get_blobname(uint32_t blobtype);
TPM_RESULT tpmlib_start(struct libtpms_callbacks *cbs, uint32_t flags);
int tpmlib_get_tpm_property(enum TPMLIB_TPMProperty prop);
bool tpmlib_is_request_cancelable(const unsigned char *request, size_t req_len);
TPM_RESULT tpmlib_TpmEstablished_Reset(TPM_MODIFIER_INDICATOR *g_locty,
                                       TPM_MODIFIER_INDICATOR locty);

struct tpm_req_header {
    uint16_t tag;
    uint32_t size;
    uint32_t ordinal;
};

/* TPM 1.2 ordinals */
#define TPMLIB_TPM_ORD_TakeOwnership   0x0000000d
#define TPMLIB_TPM_ORD_CreateWrapKey   0x0000001f

#endif /* _SWTPM_TPMLIB_H_ */
