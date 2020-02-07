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
enum TPMLIB_StateType tpmlib_blobtype_to_statetype(uint32_t blobtype);
TPM_RESULT tpmlib_register_callbacks(struct libtpms_callbacks *cbs);
TPM_RESULT tpmlib_start(uint32_t flags, TPMLIB_TPMVersion tpmversion);
int tpmlib_get_tpm_property(enum TPMLIB_TPMProperty prop);
bool tpmlib_is_request_cancelable(TPMLIB_TPMVersion tpmversion,
                                  const unsigned char *request, size_t req_len);
void tpmlib_write_fatal_error_response(unsigned char **rbuffer,
                                       uint32_t *rlength,
                                       uint32_t *rTotal,
                                       TPMLIB_TPMVersion tpmversion);
void tpmlib_write_locality_error_response(unsigned char **rbuffer,
                                          uint32_t *rlength,
                                          uint32_t *rTotal,
                                          TPMLIB_TPMVersion tpmversion);
void tpmlib_write_success_response(unsigned char **rbuffer,
                                   uint32_t *rlength,
                                   uint32_t *rTotal,
                                   TPMLIB_TPMVersion tpmversion);
TPM_RESULT tpmlib_process(unsigned char **rbuffer, uint32_t *rlength,
                          uint32_t *rTotal,
                          unsigned char *command,
                          uint32_t command_length,
                          uint32_t locality_flags,
                          TPM_MODIFIER_INDICATOR *locality,
                          TPMLIB_TPMVersion tpmversion);

off_t tpmlib_handle_tcg_tpm2_cmd_header(const unsigned char *command,
                                        uint32_t command_length,
                                        TPM_MODIFIER_INDICATOR *locality);
uint32_t tpmlib_create_startup_cmd(uint16_t startupType,
                                   TPMLIB_TPMVersion tpmversion,
                                   unsigned char *buffer,
                                   uint32_t buffersize);

struct tpm_req_header {
    uint16_t tag;
    uint32_t size;
    uint32_t ordinal;
} __attribute__((packed));

struct tpm_resp_header {
    uint16_t tag;
    uint32_t size;
    uint32_t errcode;
} __attribute__((packed));

struct tpm2_send_command_prefix {
    uint32_t cmd;
    uint8_t  locality;
    uint32_t size; /* size of the following TPM request */
} __attribute__((packed));

struct tpm2_resp_prefix {
    uint32_t size; /* size of the following TPM response */
} __attribute__((packed));

/* TPM 1.2 and TPM 2 used the same structured for startup */
struct tpm_startup {
    struct tpm_req_header hdr;
    uint16_t startupType;
} __attribute__((packed));

/* Commands in tcg_tpm2_cmd_header 'cmd' */
#define TPM2_SEND_COMMAND   8

/* Tags supported by TPM2 */
#define TPM2_ST_NO_SESSION             0x8001
#define TPM2_ST_SESSIONS               0x8002

/* Tags supported by TPM 1.2 */
#define TPM_TAG_RQU_COMMAND            0x00C1

/* TPM 1.2 ordinals */
#define TPMLIB_TPM_ORD_TakeOwnership   0x0000000d
#define TPMLIB_TPM_ORD_CreateWrapKey   0x0000001f
#define TPMLIB_TPM_ORD_Startup         0x00000099

/* TPM 1.2 startup types */
#define TPM_ST_CLEAR                   0x0001
#define TPM_ST_STATE                   0x0002
#define TPM_ST_DEACTIVATED             0x0003
#define _TPM_ST_NONE                   0x0000 /* do not send Startup */

/* TPM 2 error codes */
#define TPM_RC_INSUFFICIENT 0x09a
#define TPM_RC_FAILURE      0x101
#define TPM_RC_LOCALITY     0x107

/* TPM 2 commands */
#define TPMLIB_TPM2_CC_CreatePrimary   0x00000131
#define TPMLIB_TPM2_CC_Startup         0x00000144
#define TPMLIB_TPM2_CC_Create          0x00000153

/* TPM 2 startup types */
#define TPM2_SU_CLEAR                  0x0000
#define TPM2_SU_STATE                  0x0001

#endif /* _SWTPM_TPMLIB_H_ */
