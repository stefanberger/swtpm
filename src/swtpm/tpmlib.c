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

TPM_RESULT tpmlib_start(struct libtpms_callbacks *cbs, uint32_t flags)
{
    TPM_RESULT res;

    if ((res = TPMLIB_RegisterCallbacks(cbs)) != TPM_SUCCESS) {
        logprintf(STDERR_FILENO,
                  "Error: Could not register the callbacks.\n");
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

bool tpmlib_is_request_cancelable(const unsigned char *request, size_t req_len)
{
    struct tpm_req_header *hdr;
    uint32_t ordinal;

    if (req_len < sizeof(struct tpm_req_header))
        return false;

    hdr = (struct tpm_req_header *)request;
    ordinal = be32toh(hdr->ordinal);

    return (ordinal == TPMLIB_TPM_ORD_TakeOwnership ||
            ordinal == TPMLIB_TPM_ORD_CreateWrapKey);
}

const static unsigned char TPM_ResetEstablishmentBit[] = {
    0x00, 0xC1,                     /* TPM Request */
    0x00, 0x00, 0x00, 0x0A,         /* length (10) */
    0x40, 0x00, 0x00, 0x0B          /* TPM_ORD_ResetEstablishmentBit */
};

TPM_RESULT tpmlib_TpmEstablished_Reset(TPM_MODIFIER_INDICATOR *g_locality,
                                       TPM_MODIFIER_INDICATOR locality)
{
    TPM_RESULT res;
    unsigned char *rbuffer = NULL;
    uint32_t rlength = 0;
    uint32_t rTotal = 0;
    TPM_MODIFIER_INDICATOR orig_locality = *g_locality;
    unsigned char command[sizeof(TPM_ResetEstablishmentBit)];

    memcpy(command, TPM_ResetEstablishmentBit, sizeof(command));
    *g_locality = locality;

    res = TPMLIB_Process(&rbuffer, &rlength, &rTotal,
                         command, sizeof(command));

    *g_locality = orig_locality;
    TPM_Free(rbuffer);

    return res;
}
