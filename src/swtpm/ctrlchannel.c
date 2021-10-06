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
#include <stddef.h>
#include <time.h>
#include <poll.h>

#include <libtpms/tpm_library.h>
#include <libtpms/tpm_error.h>
#include <libtpms/tpm_tis.h>
#include <libtpms/tpm_memory.h>

#include "sys_dependencies.h"
#include "ctrlchannel.h"
#include "logging.h"
#include "tpm_ioctl.h"
#include "tpmlib.h"
#include "swtpm_nvstore.h"
#include "locality.h"
#include "mainloop.h"
#include "utils.h"
#include "swtpm_debug.h"
#include "swtpm_utils.h"

/* local variables */

struct ctrlchannel {
    int fd;
    int clientfd;
    char *sockpath;
};

struct ctrlchannel *ctrlchannel_new(int fd, bool is_client,
                                    const char *sockpath)
{
    struct ctrlchannel *cc = calloc(1, sizeof(struct ctrlchannel));

    if (!cc) {
        logprintf(STDERR_FILENO, "Out of memory");
        return NULL;
    }

    if (sockpath) {
        cc->sockpath = strdup(sockpath);
        if (!cc->sockpath) {
            logprintf(STDERR_FILENO, "Out of memory");
            free(cc);
            return NULL;
        }
    }

    cc->fd = cc->clientfd = -1;
    if (is_client)
        cc->clientfd = fd;
    else
        cc->fd = fd;

    return cc;
}

int ctrlchannel_get_fd(struct ctrlchannel *cc)
{
    if (!cc)
        return -1;

    return cc->fd;
}

int ctrlchannel_get_client_fd(struct ctrlchannel *cc)
{
    if (!cc)
        return -1;

    return cc->clientfd;
}

int ctrlchannel_set_client_fd(struct ctrlchannel *cc, int fd)
{
    int clientfd;

    if (!cc)
        return -1;

    clientfd = cc->clientfd;
    cc->clientfd = fd;

    return clientfd;
}

static int ctrlchannel_return_state(ptm_getstate *pgs, int fd)
{
    uint32_t blobtype = be32toh(pgs->u.req.type);
    const char *blobname = tpmlib_get_blobname(blobtype);
    uint32_t tpm_number = 0;
    unsigned char *blob = NULL;
    uint32_t blob_length = 0, return_length;
    TPM_BOOL is_encrypted = 0;
    TPM_BOOL decrypt =
        (be32toh(pgs->u.req.state_flags) & PTM_STATE_FLAG_DECRYPTED) != 0;
    TPM_RESULT res = 0;
    uint32_t offset = be32toh(pgs->u.req.offset);
    ptm_getstate pgs_res;
    uint32_t state_flags;
    struct iovec iov[2];
    int iovcnt, n;

    if (blobtype == PTM_BLOB_TYPE_VOLATILE)
        res = SWTPM_NVRAM_Store_Volatile();

    if (res == 0)
        res = SWTPM_NVRAM_GetStateBlob(&blob, &blob_length,
                                       tpm_number, blobname, decrypt,
                                       &is_encrypted);

    /* make sure the volatile state file is gone */
    if (blobtype == PTM_BLOB_TYPE_VOLATILE)
        SWTPM_NVRAM_DeleteName(tpm_number, blobname, FALSE);

    if (offset < blob_length) {
        return_length = blob_length - offset;
    } else {
        return_length = 0;
    }

    state_flags = (is_encrypted) ? PTM_STATE_FLAG_ENCRYPTED : 0;
    pgs_res.u.resp.tpm_result = htobe32(res);
    pgs_res.u.resp.state_flags = htobe32(state_flags);
    pgs_res.u.resp.totlength = htobe32(return_length);
    pgs_res.u.resp.length = htobe32(return_length);

    iov[0].iov_base = &pgs_res;
    iov[0].iov_len = offsetof(ptm_getstate, u.resp.data);
    iovcnt = 1;

    SWTPM_PrintAll(" Ctrl Rsp:", " ", iov[0].iov_base, iov[0].iov_len);

    if (res == 0 && return_length) {
        iov[1].iov_base = &blob[offset];
        iov[1].iov_len = return_length;
        iovcnt = 2;

        SWTPM_PrintAll(" Ctrl Rsp Continued:", " ",
                       iov[1].iov_base, min(iov[1].iov_len, 1024));
    }

    n = writev_full(fd, iov, iovcnt);
    if (n < 0) {
        logprintf(STDERR_FILENO,
                  "Error: Could not send response: %s\n", strerror(errno));
        close(fd);
        fd = -1;
    }

    free(blob);

    return fd;
}

static int ctrlchannel_receive_state(ptm_setstate *pss, ssize_t n, int fd)
{
    uint32_t blobtype = be32toh(pss->u.req.type);
    uint32_t tpm_number = 0;
    unsigned char *blob = NULL;
    uint32_t blob_length = be32toh(pss->u.req.length);
    uint32_t remain = blob_length, offset = 0;
    TPM_RESULT res;
    uint32_t flags = be32toh(pss->u.req.state_flags);
    TPM_BOOL is_encrypted = (flags & PTM_STATE_FLAG_ENCRYPTED) != 0;

    blob = malloc(blob_length);
    if (!blob) {
        logprintf(STDERR_FILENO,
                  "Could not allocated %u bytes.\n", blob_length);
        res = TPM_FAIL;
        goto err_send_resp;
    }

    n -= offsetof(ptm_setstate, u.req.data);
    /* n holds the number of available data bytes */

    while (true) {
        if (n < 0 || (uint32_t)n > remain) {
            res = TPM_BAD_PARAMETER;
            goto err_send_resp;
        }
        memcpy(&blob[offset], pss->u.req.data, n);
        offset += n;
        remain -= n;
        if (remain) {
            n = read_eintr(fd, pss->u.req.data, sizeof(pss->u.req.data));
            if (n < 0) {
                res = TPM_IOERROR;
                close(fd);
                fd = -1;
                goto err_fd_broken;
            } else if (n == 0) {
                res = TPM_BAD_PARAMETER;
                goto err_send_resp;
            }
        } else {
            break;
        }
    }

    res = SWTPM_NVRAM_SetStateBlob(blob, blob_length, is_encrypted,
                                   tpm_number, blobtype);

err_send_resp:
    pss->u.resp.tpm_result = htobe32(res);
    n = write_full(fd, pss, sizeof(pss->u.resp.tpm_result));
    if (n < 0) {
        logprintf(STDERR_FILENO,
                  "Error: Could not send response: %s\n", strerror(errno));
        close(fd);
        fd = -1;
    }

err_fd_broken:

    free(blob);

    return fd;
}

/* timespec_diff: calculate difference between two timespecs
 *
 * @end: end time
 * @start: start time; must be earlier than @end
 * @diff: result
 *
 * This function will return a negative tv_sec in result, if
 * @end is earlier than @start, the time difference otherwise.
 */
static void timespec_diff(struct timespec *end,
                          struct timespec *start,
                          struct timespec *diff)
{
    diff->tv_nsec = end->tv_nsec - start->tv_nsec;
    diff->tv_sec = end->tv_sec - start->tv_sec;
    if (diff->tv_nsec < 0) {
        diff->tv_nsec += 1E9;
        diff->tv_sec -= 1;
    }
}

struct input {
    uint32_t cmd;
    /* ptm_hdata is the largest buffer to receive */
    uint8_t body[sizeof(ptm_hdata)];
};

/*
 * ctrlchannel_recv_cmd: Receive a command on the control channel
 *
 * @fd: file descriptor for control channel
 * @msg: prepared msghdr struct for receiveing data with single
 *       msg_iov.
 *
 * This function returns 0 or a negative number if an error receiving
 * the command occurred, including a timeout. In case of success,
 * the nunber of bytes received is returned.
 */
static ssize_t ctrlchannel_recv_cmd(int fd,
                                    struct msghdr *msg)
{
    ssize_t n;
    size_t recvd = 0;
    size_t needed = offsetof(struct input, body);
    struct input *input = (struct input *)msg->msg_iov[0].iov_base;
    struct pollfd pollfd =  {
        .fd = fd,
        .events = POLLIN,
    };
    struct timespec deadline, now, timeout;
    int to;
    size_t buffer_len = msg->msg_iov[0].iov_len;
    /* Read-write */
    ptm_init *init_p;
    ptm_reset_est *pre;
    ptm_hdata *phd;
    ptm_getstate *pgs;
    ptm_setstate *pss;
    ptm_loc *pl;
    const void *msg_iov = msg->msg_iov;

    clock_gettime(CLOCK_REALTIME, &deadline);

    /* maximum allowed time is 500ms to receive everything */
    deadline.tv_nsec += 500 * 1E6;
    if (deadline.tv_nsec >= 1E9) {
        deadline.tv_nsec -= 1E9;
        deadline.tv_sec += 1;
    }

    while (recvd < buffer_len) {
        if (!recvd) {
            n = recvmsg(fd, msg, 0);
            /* address a coverity issue by validating msg */
            if (msg_iov != msg->msg_iov ||
                msg->msg_iov[0].iov_base != input ||
                msg->msg_iov[0].iov_len > buffer_len)
                return -1;
        } else
            n = read_eintr(fd, msg->msg_iov[0].iov_base + recvd, buffer_len - recvd);
        if (n <= 0)
            return n;
        recvd += n;
        /* we need to at least see the cmd */
        if (recvd < offsetof(struct input, body))
            goto wait_chunk;

        switch (be32toh(input->cmd)) {
        case CMD_GET_CAPABILITY:
            break;
        case CMD_INIT:
            needed = offsetof(struct input, body) +
                     sizeof(init_p->u.req);
            break;
        case CMD_SHUTDOWN:
            break;
        case CMD_GET_TPMESTABLISHED:
            break;
        case CMD_SET_LOCALITY:
            needed = offsetof(struct input, body) +
                     sizeof(pl->u.req);
            break;
        case CMD_HASH_START:
            break;
        case CMD_HASH_DATA:
            needed = offsetof(struct input, body) +
                     offsetof(struct ptm_hdata, u.req.data);
            if (recvd >= needed) {
                phd = (struct ptm_hdata *)&input->body;
                needed += be32toh(phd->u.req.length);
            }
            break;
        case CMD_HASH_END:
            break;
        case CMD_CANCEL_TPM_CMD:
            break;
        case CMD_STORE_VOLATILE:
            break;
        case CMD_RESET_TPMESTABLISHED:
            needed = offsetof(struct input, body) +
                     sizeof(pre->u.req);
            break;
        case CMD_GET_STATEBLOB:
            needed = offsetof(struct input, body) +
                     sizeof(pgs->u.req);
            break;
        case CMD_SET_STATEBLOB:
            needed = offsetof(struct input, body) +
                     offsetof(struct ptm_setstate, u.req.data);
            if (recvd >= needed) {
                pss = (struct ptm_setstate *)&input->body;
                needed += be32toh(pss->u.req.length);
            }
            break;
        case CMD_STOP:
            break;
        case CMD_GET_CONFIG:
            break;
        case CMD_SET_BUFFERSIZE:
            break;
        }

        if (recvd >= needed)
            break;

wait_chunk:
        clock_gettime(CLOCK_REALTIME, &now);
        timespec_diff(&deadline, &now, &timeout);

        if (timeout.tv_sec < 0)
            break;
        to = timeout.tv_sec * 1000 + timeout.tv_nsec / 1E6;

        /* wait for the next chunk */
        while (true) {
            n = poll(&pollfd, 1, to);
            if (n < 0 && errno == EINTR)
                continue;
            if (n <= 0)
                return n;
            break;
        }
        /* we should have data now */
    }
    return recvd;
}

static uint64_t get_ptm_caps_supported(TPMLIB_TPMVersion tpmversion)
{
    uint64_t caps =
              PTM_CAP_INIT
            | PTM_CAP_SHUTDOWN
            | PTM_CAP_GET_TPMESTABLISHED
            | PTM_CAP_SET_LOCALITY
            | PTM_CAP_HASHING
            | PTM_CAP_CANCEL_TPM_CMD
            | PTM_CAP_STORE_VOLATILE
            | PTM_CAP_RESET_TPMESTABLISHED
            | PTM_CAP_GET_STATEBLOB
            | PTM_CAP_SET_STATEBLOB
            | PTM_CAP_STOP
            | PTM_CAP_GET_CONFIG
#ifndef __CYGWIN__
            | PTM_CAP_SET_DATAFD
#endif
            | PTM_CAP_SET_BUFFERSIZE
            | PTM_CAP_GET_INFO;
    if (tpmversion == TPMLIB_TPM_VERSION_2)
        caps |= PTM_CAP_SEND_COMMAND_HEADER;

    return caps;
}

/*
 * ctrlchannel_process_fd: Read command from control channel and execute it
 *
 * @fd: file descriptor for control channel
 * @terminate: pointer to a boolean that will be set to true by this
 *             function in case the process should shut down; CMD_SHUTDOWN
 *             will set this
 * @locality: pointer to locality identifier that must point to the global
 *            locality variable and that will receive the new locality
 *            number when set via CMD_SET_LOCALITY
 * @tpm_running: indicates whether the TPM is running; may be changed by
 *               this function in case TPM is stopped or started
 * @mlp: mainloop parameters used; may be altered by this function incase of
 *       CMD_SET_DATAFD
 * @tpmversion: the emulated TPM's version
 *
 * This function returns the passed file descriptor or -1 in case the
 * file descriptor was closed.
 */
int ctrlchannel_process_fd(int fd,
                           bool *terminate,
                           TPM_MODIFIER_INDICATOR *locality,
                           bool *tpm_running,
                           struct mainLoopParams *mlp)
{
    struct input input = {0, };
    struct output {
        uint8_t body[sizeof(struct ptm_hdata)]; /* ptm_hdata is largest */
    } output;
    ssize_t n;
    struct iovec iov = {
        .iov_base = &input,
        .iov_len = sizeof(input),
    };
    char control[CMSG_SPACE(sizeof(int))];
    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = control,
        .msg_controllen = sizeof(control),
    };
    struct cmsghdr *cmsg = NULL;
    int *data_fd = NULL;

    /* Write-only */
    ptm_cap *ptm_caps = (ptm_cap *)&output.body;
    ptm_res *res_p = (ptm_res *)&output.body;
    ptm_est *te = (ptm_est *)&output.body;
    ptm_getconfig *pgc = (ptm_getconfig *)&output.body;
    /* Read-write */
    ptm_init *init_p;
    ptm_reset_est *re;
    ptm_hdata *data;
    ptm_getstate *pgs;
    ptm_setstate *pss;
    ptm_loc *pl;
    ptm_setbuffersize *psbs;
    ptm_getinfo *pgi, _pgi;

    size_t out_len = 0;
    TPM_RESULT res;
    uint32_t remain;
    uint32_t buffersize, maxsize, minsize;
    uint64_t info_flags;
    uint32_t offset;
    char *info_data = NULL;
    size_t length;
    TPM_MODIFIER_INDICATOR orig_locality;

    if (fd < 0)
        return -1;

    n = ctrlchannel_recv_cmd(fd, &msg);
    if (n <= 0) {
        goto err_socket;
    }

    SWTPM_PrintAll(" Ctrl Cmd:", " ", msg.msg_iov->iov_base, min(n, 1024));

    if ((size_t)n < sizeof(input.cmd)) {
        goto err_bad_input;
    }

    n -= sizeof(input.cmd);

    switch (be32toh(input.cmd)) {
    case CMD_GET_CAPABILITY:
        *ptm_caps = htobe64(get_ptm_caps_supported(mlp->tpmversion));

        out_len = sizeof(*ptm_caps);
        break;

    case CMD_INIT:
        if (n != (ssize_t)sizeof(ptm_init)) /* r/w */
            goto err_bad_input;

        init_p = (ptm_init *)input.body;

        TPMLIB_Terminate();

        *tpm_running = false;
        res = tpmlib_start(be32toh(init_p->u.req.init_flags),
                           mlp->tpmversion);
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
            orig_locality = *locality;
            *locality = re->u.req.loc;

            res = htobe32(TPM_IO_TpmEstablished_Reset());

            *locality = orig_locality;
        }

        *res_p = res;
        out_len = sizeof(re->u.resp);
        break;

    case CMD_SET_LOCALITY:
        if (n < (ssize_t)sizeof(pl->u.req.loc)) /* rw */
            goto err_bad_input;

        pl = (ptm_loc *)input.body;
        if (pl->u.req.loc > 4 ||
            (pl->u.req.loc == 4 &&
             mlp->locality_flags & LOCALITY_FLAG_REJECT_LOCALITY_4)) {
            res = TPM_BAD_LOCALITY;
        } else {
            res = TPM_SUCCESS;
            *locality = pl->u.req.loc;
        }

        *res_p = htobe32(res);
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

            n = read_eintr(fd, &data->u.req.data, sizeof(data->u.req.data));
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
        *res_p = htobe32(TPMLIB_CancelCommand());
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

    case CMD_GET_STATEBLOB:
        if (!*tpm_running)
            goto err_not_running;

        pgs = (ptm_getstate *)input.body;
        if (n < (ssize_t)sizeof(pgs->u.req)) /* rw */
            goto err_bad_input;

        return ctrlchannel_return_state(pgs, fd);

    case CMD_SET_STATEBLOB:
        if (*tpm_running)
            goto err_running;

        /* tpm state dir must be set */
        SWTPM_NVRAM_Init();

        pss = (ptm_setstate *)input.body;
        if (n < (ssize_t)offsetof(ptm_setstate, u.req.data)) /* rw */
            goto err_bad_input;

        return ctrlchannel_receive_state(pss, n, fd);

    case CMD_GET_CONFIG:
        if (n != 0) /* wo */
            goto err_bad_input;

        pgc->u.resp.tpm_result = htobe32(0);
        pgc->u.resp.flags = htobe32(0);
        if (SWTPM_NVRAM_Has_FileKey())
            pgc->u.resp.flags |= htobe32(PTM_CONFIG_FLAG_FILE_KEY);
        if (SWTPM_NVRAM_Has_MigrationKey())
            pgc->u.resp.flags |= htobe32(PTM_CONFIG_FLAG_MIGRATION_KEY);

        out_len = sizeof(pgc->u.resp);
        break;

    case CMD_SET_DATAFD:
#ifdef __CYGWIN__
        if (1)
            goto err_running;
#endif
        if (mlp->fd != -1)
            goto err_io;

        cmsg = CMSG_FIRSTHDR(&msg);
        if (!cmsg || cmsg->cmsg_len < CMSG_LEN(sizeof(int)) ||
             cmsg->cmsg_level != SOL_SOCKET ||
             cmsg->cmsg_type != SCM_RIGHTS ||
             !(data_fd = (int *)CMSG_DATA(cmsg)) ||
             *data_fd < 0) {
            logprintf(STDERR_FILENO, "no valid data socket in message; cmsg = "
                                     "%p", cmsg);
            goto err_bad_input;
        }

        mlp->flags |= MAIN_LOOP_FLAG_USE_FD | MAIN_LOOP_FLAG_KEEP_CONNECTION;
        mlp->fd = *data_fd;

        *res_p = htobe32(TPM_SUCCESS);
        out_len = sizeof(ptm_res);
        break;

    case CMD_SET_BUFFERSIZE:
        psbs = (ptm_setbuffersize *)input.body;
        if (n < (ssize_t)sizeof(psbs->u.req)) /* rw */
            goto err_bad_input;

        buffersize = be32toh(psbs->u.req.buffersize);

        if (buffersize > 0 && *tpm_running)
            goto err_running;

        buffersize = TPMLIB_SetBufferSize(buffersize,
                                          &minsize,
                                          &maxsize);

        *res_p = htobe32(TPM_SUCCESS);

        psbs = (ptm_setbuffersize *)&output.body;
        out_len = sizeof(psbs->u.resp);

        psbs->u.resp.buffersize = htobe32(buffersize);
        psbs->u.resp.minsize = htobe32(minsize);
        psbs->u.resp.maxsize = htobe32(maxsize);

        break;

    case CMD_GET_INFO:
        if (n < (ssize_t)sizeof(pgi->u.req)) /* rw */
            goto err_bad_input;

        /* copy since flags needs to be 8-byte aligned  */
        memcpy(&_pgi, input.body, sizeof(_pgi));
        pgi = &_pgi;

        info_flags = be64toh(pgi->u.req.flags);

        info_data = TPMLIB_GetInfo(info_flags);
        if (!info_data)
            goto err_memory;

        offset = be32toh(pgi->u.req.offset);
        if (offset >= strlen(info_data)) {
            free(info_data);
            goto err_bad_input;
        }

        length = min(strlen(info_data) + 1 - offset,
                     sizeof(pgi->u.resp.buffer));

        pgi = (ptm_getinfo *)&output.body;
        pgi->u.resp.tpm_result = htobe32(0);
        pgi->u.resp.totlength = htobe32(strlen(info_data) + 1);
        pgi->u.resp.length = htobe32(length);
        /* client has to collect whole string in case buffer is too small */
        memcpy(pgi->u.resp.buffer, &info_data[offset], length);
        free(info_data);

        out_len = offsetof(ptm_getinfo, u.resp.buffer) + length;

        break;

    default:
        logprintf(STDERR_FILENO,
                  "Error: Unknown command: 0x%08x\n", be32toh(input.cmd));

        *res_p = htobe32(TPM_BAD_ORDINAL);
        out_len = sizeof(ptm_res);
    }

send_resp:
    SWTPM_PrintAll(" Ctrl Rsp:", " ", output.body, min(out_len, 1024));

    n = write_full(fd, output.body, out_len);
    if (n < 0) {
        logprintf(STDERR_FILENO,
                  "Error: Could not send response: %s\n", strerror(errno));
        close(fd);
        fd = -1;
    }

    return fd;

err_bad_input:
    *res_p = htobe32(TPM_BAD_PARAMETER);
    out_len = sizeof(ptm_res);

    goto send_resp;

err_running:
err_not_running:
    *res_p = htobe32(TPM_BAD_ORDINAL);
    out_len = sizeof(ptm_res);

    goto send_resp;

err_io:
    *res_p = htobe32(TPM_IOERROR);
    out_len = sizeof(ptm_res);

    goto send_resp;

err_memory:
    *res_p = htobe32(TPM_SIZE);
    out_len = sizeof(ptm_res);

    goto send_resp;

err_socket:
    close(fd);

    return -1;
}

void ctrlchannel_free(struct ctrlchannel *cc)
{
    if (!cc)
        return;

    if (cc->fd >= 0)
        close(cc->fd);
    if (cc->clientfd >= 0)
        close(cc->clientfd);
    if (cc->sockpath) {
        unlink(cc->sockpath);
        free(cc->sockpath);
    }
    free(cc);
}
