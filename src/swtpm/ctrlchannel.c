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

#include <libtpms/tpm_library.h>
#include <libtpms/tpm_error.h>

#include "ctrlchannel.h"
#include "logging.h"
#include "tpm_ioctl.h"
#include "tpmlib.h"

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
                           bool *terminate)
{
    struct input {
        uint32_t cmd;
        uint8_t body[4092];
    } input;
    struct output {
        uint8_t body[4096];
    } output;
    ssize_t n;
    ptm_init *init_p;
    ptm_cap *ptm_caps = (ptm_cap *)&output.body;
    ptm_res *res_p = (ptm_res *)&output.body;
    size_t out_len = 0;
    TPM_RESULT res;

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
            PTM_CAP_SHUTDOWN);

        out_len = sizeof(*ptm_caps);
        break;

    case CMD_INIT:
        if (n != sizeof(ptm_init)) {
            goto err_bad_input;
        } else {
            init_p = (ptm_init *)input.body;
            out_len = sizeof(ptm_res);

            TPMLIB_Terminate();

            res = tpmlib_start(cbs, be32toh(init_p->u.req.init_flags));
            if (res) {
                logprintf(STDERR_FILENO,
                          "Error: Could not initialize the TPM\n");
            }
            *res_p = htobe32(res);
        }
        break;

    case CMD_SHUTDOWN:
        if (n != 0) {
            goto err_bad_input;
        } else {
            out_len = sizeof(ptm_res);

            TPMLIB_Terminate();

            *res_p = htobe32(TPM_SUCCESS);

            *terminate = true;
        }
        break;

    default:
        logprintf(STDERR_FILENO,
                  "Error: Unknown command\n");
        out_len = sizeof(ptm_res);
        *res_p = htobe32(TPM_BAD_ORDINAL);
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
    out_len = sizeof(ptm_res);
    *res_p = htobe32(TPM_BAD_PARAMETER);

    goto send_resp;

err_socket:
    close(fd);

    return -1;
}
