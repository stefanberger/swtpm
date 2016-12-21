/*
 * tpm_funcs.c -- interface with libtpms
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

#include "config.h"

#include <assert.h>
#include <endian.h>
#include <string.h>

#include <libtpms/tpm_library.h>
#include <libtpms/tpm_error.h>
#include <libtpms/tpm_nvfilename.h>
#include <libtpms/tpm_memory.h>

#include "tpmlib.h"
#include "logging.h"
#include "tpm_ioctl.h"
#include "swtpm_nvfile.h"
#include "locality.h"
#ifdef WITH_VTPM_PROXY
#include "vtpm_proxy.h"
#endif

/*
 * convert the blobtype integer into a string that libtpms
 * understands
 */
const char *tpmlib_get_blobname(uint32_t blobtype)
{
    switch (blobtype) {
    case PTM_BLOB_TYPE_PERMANENT:
        return TPM_PERMANENT_ALL_NAME;
    case PTM_BLOB_TYPE_VOLATILE:
        return TPM_VOLATILESTATE_NAME;
    case PTM_BLOB_TYPE_SAVESTATE:
        return TPM_SAVESTATE_NAME;
    default:
        return NULL;
    }
}

TPM_RESULT tpmlib_start(struct libtpms_callbacks *cbs, uint32_t flags,
                        TPMLIB_TPMVersion tpmversion)
{
    TPM_RESULT res;

    if ((res = TPMLIB_RegisterCallbacks(cbs)) != TPM_SUCCESS) {
        logprintf(STDERR_FILENO,
                  "Error: Could not register the callbacks.\n");
        return res;
    }

    if ((res = TPMLIB_ChooseTPMVersion(tpmversion)) != TPM_SUCCESS) {
        logprintf(STDERR_FILENO,
                  "Error: Could not choose TPM 2 implementation.\n");
        return res;
    }

    if ((res = TPMLIB_MainInit()) != TPM_SUCCESS) {
        logprintf(STDERR_FILENO,
                  "Error: Could not initialize libtpms.\n");
        return res;
    }

    if (flags & PTM_INIT_FLAG_DELETE_VOLATILE) {
        uint32_t tpm_number = 0;
        char *name = TPM_VOLATILESTATE_NAME;
        res = SWTPM_NVRAM_DeleteName(tpm_number,
                                     name,
                                     FALSE);
        if (res != TPM_SUCCESS) {
            logprintf(STDERR_FILENO,
                      "Error: Could not delete the volatile "
                      "state of the TPM.\n");
            goto error_terminate;
        }
    }
    return TPM_SUCCESS;

error_terminate:
    TPMLIB_Terminate();

    return res;
}

int tpmlib_get_tpm_property(enum TPMLIB_TPMProperty prop)
{
    int result;
    TPM_RESULT res;

    res = TPMLIB_GetTPMProperty(prop, &result);

    assert(res == TPM_SUCCESS);

    return result;
}

bool tpmlib_is_request_cancelable(TPMLIB_TPMVersion tpmversion,
                                  const unsigned char *request, size_t req_len)
{
    struct tpm_req_header *hdr;
    uint32_t ordinal;

    if (req_len < sizeof(struct tpm_req_header))
        return false;

    hdr = (struct tpm_req_header *)request;
    ordinal = be32toh(hdr->ordinal);

    if (tpmversion == TPMLIB_TPM_VERSION_2)
        return (ordinal == TPMLIB_TPM2_CC_CreatePrimary ||
                ordinal == TPMLIB_TPM2_CC_Create);

    return (ordinal == TPMLIB_TPM_ORD_TakeOwnership ||
            ordinal == TPMLIB_TPM_ORD_CreateWrapKey);
}

static void tpmlib_write_error_response(unsigned char **rbuffer,
                                        uint32_t *rlength,
                                        uint32_t *rTotal,
                                        TPM_RESULT errcode,
                                        TPMLIB_TPMVersion tpmversion)
{
    struct tpm_resp_header errresp = {
        .tag = (tpmversion == TPMLIB_TPM_VERSION_2)
               ? htobe16(0x8001)
               : htobe16(0xc4),
        .size = htobe32(sizeof(errresp)),
        .errcode = htobe32(errcode),
    };

    if (*rbuffer == NULL ||
        *rTotal < sizeof(errresp)) {
        TPM_Realloc(rbuffer, sizeof(errresp));
        if (*rbuffer)
            *rTotal = sizeof(errresp);
        else
            *rTotal = 0;
    }
    if (*rbuffer) {
        *rlength = sizeof(errresp);
        memcpy(*rbuffer, &errresp, sizeof(errresp));
    }
}

void tpmlib_write_fatal_error_response(unsigned char **rbuffer,
                                       uint32_t *rlength,
                                       uint32_t *rTotal,
                                       TPMLIB_TPMVersion tpmversion)
{
    TPM_RESULT errcode = (tpmversion == TPMLIB_TPM_VERSION_2)
                         ? TPM_RC_FAILURE
                         : TPM_FAIL;

    tpmlib_write_error_response(rbuffer, rlength, rTotal, errcode,
                                tpmversion);
}

void tpmlib_write_locality_error_response(unsigned char **rbuffer,
                                          uint32_t *rlength,
                                          uint32_t *rTotal,
                                          TPMLIB_TPMVersion tpmversion)
{
    TPM_RESULT errcode = (tpmversion == TPMLIB_TPM_VERSION_2)
                         ? TPM_RC_LOCALITY
                         : TPM_BAD_LOCALITY;

    tpmlib_write_error_response(rbuffer, rlength, rTotal, errcode,
                                tpmversion);
}

void tpmlib_write_success_response(unsigned char **rbuffer,
                                   uint32_t *rlength,
                                   uint32_t *rTotal,
                                   TPMLIB_TPMVersion tpmversion)
{
    tpmlib_write_error_response(rbuffer, rlength, rTotal, 0,
                                tpmversion);
}

#ifdef WITH_VTPM_PROXY
static void tpmlib_write_shortmsg_error_response(unsigned char **rbuffer,
                                                 uint32_t *rlength,
                                                 uint32_t *rTotal,
                                                 TPMLIB_TPMVersion tpmversion)
{
    TPM_RESULT errcode = (tpmversion == TPMLIB_TPM_VERSION_2)
                         ? TPM_RC_INSUFFICIENT
                         : TPM_BAD_PARAM_SIZE;

    tpmlib_write_error_response(rbuffer, rlength, rTotal, errcode,
                                tpmversion);
}

static TPM_RESULT tpmlib_process_setlocality(unsigned char **rbuffer,
                                             uint32_t *rlength,
                                             uint32_t *rTotal,
                                             unsigned char *command,
                                             uint32_t command_length,
                                             TPMLIB_TPMVersion tpmversion,
                                             uint32_t locality_flags,
                                             TPM_MODIFIER_INDICATOR *locality)
{
    TPM_MODIFIER_INDICATOR new_locality;

    if (command_length >= sizeof(struct tpm_req_header) + sizeof(char)) {
        if (!(locality_flags & LOCALITY_FLAG_ALLOW_SETLOCALITY)) {
            /* SETLOCALITY command is not allowed */
            tpmlib_write_fatal_error_response(rbuffer,
                                              rlength, rTotal,
                                              tpmversion);
        } else {
            new_locality = command[sizeof(struct tpm_req_header)];
            if (new_locality >=5 ||
                (new_locality == 4 &&
                 locality_flags & LOCALITY_FLAG_REJECT_LOCALITY_4)) {
                tpmlib_write_locality_error_response(rbuffer,
                                                     rlength, rTotal,
                                                    tpmversion);
            } else {
                tpmlib_write_success_response(rbuffer,
                                              rlength, rTotal,
                                              tpmversion);
                *locality = new_locality;
            }
        }
    } else {
        tpmlib_write_shortmsg_error_response(rbuffer,
                                             rlength, rTotal,
                                             tpmversion);
    }
    return TPM_SUCCESS;
}

TPM_RESULT tpmlib_process(unsigned char **rbuffer,
                          uint32_t *rlength,
                          uint32_t *rTotal,
                          unsigned char *command,
                          uint32_t command_length,
                          uint32_t locality_flags,
                          TPM_MODIFIER_INDICATOR *locality,
                          TPMLIB_TPMVersion tpmversion)
{
    /* process those commands we need to handle, e.g. SetLocality */
    struct tpm_req_header *req = (struct tpm_req_header *)command;
    uint32_t ordinal;

    if (command_length < sizeof(*req)) {
        tpmlib_write_shortmsg_error_response(rbuffer,
                                             rlength, rTotal,
                                             tpmversion);
        return TPM_SUCCESS;
    }

    ordinal = be32toh(req->ordinal);

    switch (tpmversion) {
    case TPMLIB_TPM_VERSION_1_2:
        switch (ordinal) {
        case TPM_CC_SET_LOCALITY:
            return tpmlib_process_setlocality(rbuffer, rlength, rTotal,
                                              command, command_length,
                                              tpmversion, locality_flags,
                                              locality);
        }
        break;

    case TPMLIB_TPM_VERSION_2:
        switch (ordinal) {
        case TPM2_CC_SET_LOCALITY:
            return tpmlib_process_setlocality(rbuffer, rlength, rTotal,
                                              command, command_length,
                                              tpmversion, locality_flags,
                                              locality);
        }
        break;
    }
    return TPM_SUCCESS;
}

#else

TPM_RESULT tpmlib_process(unsigned char **rbuffer,
                          uint32_t *rlength,
                          uint32_t *rTotal,
                          unsigned char *command,
                          uint32_t command_length,
                          uint32_t locality_flags,
                          TPM_MODIFIER_INDICATOR *locality,
                          TPMLIB_TPMVersion tpmversion)
{
    return TPM_SUCCESS;
}

#endif /* WITH_VTPM_PROXY */
