/*
 * ctrlchannel.c -- control channel implementation
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

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <stdint.h>
#include <endian.h>
#include <stddef.h>

#include <libtpms/tpm_library.h>
#include <libtpms/tpm_error.h>
#include <libtpms/tpm_tis.h>

#include "ctrlchannel.h"
#include "logging.h"
#include "tpm_ioctl.h"
#include "tpmlib.h"
#include "swtpm_nvfile.h"

/* local variables */

struct ctrlchannel {
    int fd;
};

struct ctrlchannel *ctrlchannel_new(int fd)
{
    struct ctrlchannel *cc = malloc(sizeof(struct ctrlchannel));

    if (!cc) {
        logprintf(STDERR_FILENO, "Out of memory");
        return NULL;
    }

    cc->fd = fd;
    return cc;
}

int ctrlchannel_get_fd(struct ctrlchannel *cc)
{
    if (!cc)
        return -1;

    return cc->fd;
}

int ctrlchannel_process_fd(int fd,
                           struct libtpms_callbacks *cbs,
                           bool *terminate,
                           TPM_MODIFIER_INDICATOR *locality,
                           bool *tpm_running)
{
    struct input {
        uint32_t cmd;
        uint8_t body[4092];
    } input;
    struct output {
        uint8_t body[4096];
    } output;
    ssize_t n;
    /* Write-only */
    ptm_cap *ptm_caps = (ptm_cap *)&output.body;
    ptm_res *res_p = (ptm_res *)&output.body;
    ptm_est *te = (ptm_est *)&output.body;
    ptm_getconfig *pgc = (ptm_getconfig *)&output.body;
    /* Read-write */
    ptm_init *init_p;
    ptm_reset_est *re;
    ptm_hdata *data;

    size_t out_len = 0;
    TPM_RESULT res;
    uint32_t remain;

    if (fd < 0)
        return -1;

    n = read(fd, &input, sizeof(input));
    if (n < 0) {
        goto err_socket;
    }
    if (n == 0) {
        /* remote socket closed */
        goto err_socket;
    }
    if ((size_t)n < sizeof(input.cmd)) {
        goto err_bad_input;
    }

    n -= sizeof(input.cmd);

    switch (be32toh(input.cmd)) {
    case CMD_GET_CAPABILITY:
        *ptm_caps = htobe64(
            PTM_CAP_INIT |
            PTM_CAP_SHUTDOWN |
            PTM_CAP_STOP |
            PTM_CAP_GET_TPMESTABLISHED |
            PTM_CAP_RESET_TPMESTABLISHED |
            PTM_CAP_HASHING |
            PTM_CAP_CANCEL_TPM_CMD |
            PTM_CAP_STORE_VOLATILE);

        out_len = sizeof(*ptm_caps);
        break;

    case CMD_INIT:
        if (n != (ssize_t)sizeof(ptm_init)) /* r/w */
            goto err_bad_input;

        init_p = (ptm_init *)input.body;

        TPMLIB_Terminate();

        *tpm_running = false;
        res = tpmlib_start(cbs, be32toh(init_p->u.req.init_flags));
        if (res) {
            logprintf(STDERR_FILENO,
                      "Error: Could not initialize the TPM\n");
        } else {
            *tpm_running = true;
        }

        *res_p = htobe32(res);
        out_len = sizeof(ptm_res);
        break;

    case CMD_STOP:
        if (n != 0) /* wo */
            goto err_bad_input;

        TPMLIB_Terminate();

        *tpm_running = false;

        *res_p = htobe32(TPM_SUCCESS);
        out_len = sizeof(ptm_res);
        break;

    case CMD_SHUTDOWN:
        if (n != 0) /* wo */
            goto err_bad_input;

        TPMLIB_Terminate();

        *res_p = htobe32(TPM_SUCCESS);
        out_len = sizeof(ptm_res);

        *terminate = true;
        break;

    case CMD_GET_TPMESTABLISHED:
        if (!*tpm_running)
            goto err_not_running;

        if (n != 0) /* wo */
            goto err_bad_input;

        out_len = sizeof(te->u.resp);
        memset(output.body, 0, out_len);

        res = htobe32(TPM_IO_TpmEstablished_Get(&te->u.resp.bit));
        te->u.resp.tpm_result = res;

        break;

    case CMD_RESET_TPMESTABLISHED:
        if (!*tpm_running)
            goto err_not_running;

        if (n < (ssize_t)sizeof(re->u.req.loc)) /* rw */
            goto err_bad_input;

        re = (ptm_reset_est *)input.body;

        if (re->u.req.loc > 4) {
            res = htobe32(TPM_BAD_LOCALITY);
        } else {
            res = htobe32(tpmlib_TpmEstablished_Reset(locality,
                                                      re->u.req.loc));
        }

        *res_p = res;
        out_len = sizeof(re->u.resp);
        break;

    case CMD_HASH_START:
        if (!*tpm_running)
            goto err_not_running;

        if (n != 0) /* wo */
            goto err_bad_input;

        *res_p = htobe32(TPM_IO_Hash_Start());
        out_len = sizeof(ptm_res);

        break;

    case CMD_HASH_DATA:
        if (!*tpm_running)
             goto err_not_running;

        if (n < (ssize_t)offsetof(ptm_hdata, u.req.data)) /* rw */
             goto err_bad_input;

        data = (ptm_hdata *)&input.body;
        remain = htobe32(data->u.req.length);
        n -= sizeof(data->u.req.length);
        /* n has the available number of bytes to hash */

        while (true) {
            res = TPM_IO_Hash_Data(data->u.req.data, n);
            if (res)
                break;
            remain -= n;
            if (!remain)
                break;

            n = read(fd, &data->u.req.data, sizeof(data->u.req.data));
            if (n <= 0) {
                res = TPM_IOERROR;
                break;
            }
        }

        data = (ptm_hdata *)&output.body;

        data->u.resp.tpm_result = htobe32(res);
        out_len = sizeof(data->u.resp.tpm_result);

        break;

    case CMD_HASH_END:
        if (!*tpm_running)
            goto err_not_running;

        if (n != 0) /* wo */
            goto err_bad_input;

        *res_p = htobe32(TPM_IO_Hash_End());
        out_len = sizeof(ptm_res);

        break;

    case CMD_CANCEL_TPM_CMD:
        if (!*tpm_running)
            goto err_not_running;

        if (n != 0) /* wo */
            goto err_bad_input;

        /* for cancellation to work, the TPM would have to
         * execute in another thread that polls on a cancel
         * flag
         */
        *res_p = htobe32(TPM_FAIL);
        out_len = sizeof(ptm_res);
        break;

    case CMD_STORE_VOLATILE:
        if (!*tpm_running)
            goto err_not_running;

        if (n != 0) /* wo */
            goto err_bad_input;

        *res_p = htobe32(SWTPM_NVRAM_Store_Volatile());
        out_len = sizeof(ptm_res);
        break;

    case CMD_GET_CONFIG:
        if (n != 0) /* wo */
            goto err_bad_input;

        pgc->u.resp.tpm_result = htobe32(0);
        pgc->u.resp.flags = 0;
        if (SWTPM_NVRAM_Has_FileKey())
            pgc->u.resp.flags |= PTM_CONFIG_FLAG_FILE_KEY;
        if (SWTPM_NVRAM_Has_MigrationKey())
            pgc->u.resp.flags |= PTM_CONFIG_FLAG_MIGRATION_KEY;

        out_len = sizeof(pgc->u.resp);
        break;

    default:
        logprintf(STDERR_FILENO,
                  "Error: Unknown command: 0x%08x\n", be32toh(input.cmd));

        *res_p = htobe32(TPM_BAD_ORDINAL);
        out_len = sizeof(ptm_res);
    }

send_resp:
    n = write(fd, output.body, out_len);
    if (n < 0) {
        logprintf(STDERR_FILENO,
                  "Error: Could not send response: %s\n", strerror(errno));
    } else if ((size_t)n != out_len) {
        logprintf(STDERR_FILENO,
                  "Error: Could not send complete response\n");
    }

    return fd;

err_bad_input:
    *res_p = htobe32(TPM_BAD_PARAMETER);
    out_len = sizeof(ptm_res);

    goto send_resp;

err_not_running:
    *res_p = htobe32(TPM_BAD_ORDINAL);
    out_len = sizeof(ptm_res);

    goto send_resp;

err_socket:
    close(fd);

    return -1;
}
