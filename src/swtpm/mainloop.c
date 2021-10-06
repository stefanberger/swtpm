/*
 * mainloop.c -- The TPM Emulator's main processing loop
 *
 * (c) Copyright IBM Corporation 2014, 2015, 2016
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

/* mainLoop() is the main server loop.

   It reads a TPM request, processes the ordinal, and writes the response
*/

#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>

#include <libtpms/tpm_error.h>
#include <libtpms/tpm_library.h>
#include <libtpms/tpm_memory.h>

#include "swtpm_debug.h"
#include "swtpm_io.h"
#include "tpmlib.h"
#include "locality.h"
#include "logging.h"
#include "ctrlchannel.h"
#include "mainloop.h"
#include "utils.h"
#include "sys_dependencies.h"
#include "compiler_dependencies.h"
#include "swtpm_utils.h"

/* local variables */
static TPM_MODIFIER_INDICATOR locality;
bool tpm_running = false;

bool mainloop_terminate;

TPM_RESULT
mainloop_cb_get_locality(TPM_MODIFIER_INDICATOR *loc,
                         uint32_t tpmnum SWTPM_ATTR_UNUSED)
{
    *loc = locality;

    return TPM_SUCCESS;
}

int mainLoop(struct mainLoopParams *mlp,
             int notify_fd)
{
    TPM_RESULT          rc = 0;
    TPM_CONNECTION_FD   connection_fd;             /* file descriptor for read/write */
    unsigned char       *command = NULL;           /* command buffer */
    uint32_t            command_length;            /* actual length of command bytes */
    uint32_t            max_command_length;        /* command buffer size */
    off_t               cmd_offset;
    /* The response buffer is reused for each command. Thus it can grow but never shrink */
    unsigned char       *rbuffer = NULL;           /* actual response bytes */
    uint32_t            rlength = 0;               /* bytes in response buffer */
    uint32_t            rTotal = 0;                /* total allocated bytes */
    int                 ctrlfd;
    int                 ctrlclntfd;
    int                 sockfd;
    int                 ready;
    struct iovec        iov[3];
    uint32_t            ack = htobe32(0);
    struct tpm2_resp_prefix respprefix;

    /* poolfd[] indexes */
    enum {
        DATA_CLIENT_FD = 0,
        NOTIFY_FD,
        CTRL_SERVER_FD,
        CTRL_CLIENT_FD,
        DATA_SERVER_FD
    };

    TPM_DEBUG("mainLoop:\n");

    max_command_length = tpmlib_get_tpm_property(TPMPROP_TPM_BUFFER_MAX) +
                         sizeof(struct tpm2_send_command_prefix);

    command = malloc(max_command_length);
    if (!command) {
        logprintf(STDERR_FILENO, "Could not allocate %u bytes for buffer.\n",
                  max_command_length);
        return TPM_FAIL;
    }

    /* header and trailer that we may send by setting iov_len */
    iov[0].iov_base = &respprefix;
    iov[0].iov_len = 0;
    iov[2].iov_base = &ack;
    iov[2].iov_len = 0;

    connection_fd.fd = -1;
    ctrlfd = ctrlchannel_get_fd(mlp->cc);
    ctrlclntfd = ctrlchannel_get_client_fd(mlp->cc);

    sockfd = SWTPM_IO_GetSocketFD();

    if (mlp->startupType != _TPM_ST_NONE) {
        command_length = tpmlib_create_startup_cmd(
                                  mlp->startupType,
                                  mlp->tpmversion,
                                  command, max_command_length);
        if (command_length > 0)
            rc = TPMLIB_Process(&rbuffer, &rlength, &rTotal,
                                command, command_length);

        if (rc || command_length == 0) {
            mainloop_terminate = true;
            if (rc)
                logprintf(STDERR_FILENO, "Could not send Startup: 0x%x\n", rc);
        }
    }

    while (!mainloop_terminate) {

        while (rc == 0) {
            if (mlp->flags & MAIN_LOOP_FLAG_USE_FD)
                connection_fd.fd = mlp->fd;

            struct pollfd pollfds[] = {
                [DATA_CLIENT_FD] = {
                    .fd = connection_fd.fd,
                    .events = POLLIN | POLLHUP,
                    .revents = 0,
                },
                [NOTIFY_FD] = {
                    .fd = notify_fd,
                    .events = POLLIN,
                    .revents = 0,
                },
                [CTRL_SERVER_FD] = {
                    .fd = -1,
                    .events = POLLIN,
                    .revents = 0,
                },
                [CTRL_CLIENT_FD] = {
                    .fd = ctrlclntfd,
                    .events = POLLIN | POLLHUP,
                    .revents = 0,
                },
                [DATA_SERVER_FD] = {
                    /* listen socket for accepting clients */
                    .fd = -1,
                    .events = POLLIN,
                    .revents = 0,
                }
            };

            /* only listend for clients if we don't have one */
            if (connection_fd.fd < 0)
                pollfds[DATA_SERVER_FD].fd = sockfd;
            if (ctrlclntfd < 0)
                pollfds[CTRL_SERVER_FD].fd = ctrlfd;

            ready = poll(pollfds, 5, -1);
            if (ready < 0 && errno == EINTR)
                continue;

            if (ready < 0 ||
                (pollfds[NOTIFY_FD].revents & POLLIN) != 0) {
                SWTPM_IO_Disconnect(&connection_fd);
                break;
            }

            if (pollfds[DATA_CLIENT_FD].revents & (POLLHUP | POLLERR)) {
                logprintf(STDERR_FILENO, "Data client disconnected\n");
                mlp->fd = -1;
                /* chardev and unixio get this signal, not tcp */
                if (mlp->flags & MAIN_LOOP_FLAG_END_ON_HUP) {
                    /* only the chardev terminates here */
                    mainloop_terminate = true;
                    break;
                }
            }

            if (pollfds[DATA_SERVER_FD].revents & POLLIN)
                connection_fd.fd = accept(pollfds[DATA_SERVER_FD].fd, NULL, 0);

            if (pollfds[CTRL_SERVER_FD].revents & POLLIN)
                ctrlclntfd = accept(ctrlfd, NULL, 0);

            if (pollfds[CTRL_CLIENT_FD].revents & POLLIN) {
                ctrlclntfd = ctrlchannel_process_fd(ctrlclntfd,
                                                    &mainloop_terminate,
                                                    &locality, &tpm_running,
                                                    mlp);
                if (mainloop_terminate)
                    break;
            }

            if (pollfds[CTRL_CLIENT_FD].revents & POLLHUP) {
                if (ctrlclntfd >= 0)
                    close(ctrlclntfd);
                ctrlclntfd = -1;
            }

            if (!(pollfds[DATA_CLIENT_FD].revents & POLLIN))
                continue;

            /* Read the command.  The number of bytes is determined by 'paramSize' in the stream */
            if (rc == 0) {
                rc = SWTPM_IO_Read(&connection_fd, command, &command_length,
                                   max_command_length);
                if (rc != 0) {
                    /* connection broke */
                    SWTPM_IO_Disconnect(&connection_fd);
                }
            }

            cmd_offset = 0;
            /* Handle optional TCG Header in front of TPM 2 Command */
            if (rc == 0 && mlp->tpmversion == TPMLIB_TPM_VERSION_2) {
                cmd_offset = tpmlib_handle_tcg_tpm2_cmd_header(command,
                                                               command_length,
                                                               &locality);
                if (cmd_offset > 0) {
                    /* send header and trailer */
                    iov[0].iov_len = sizeof(respprefix);
                    iov[2].iov_len = sizeof(ack);
                } else {
                    iov[0].iov_len = 0;
                    iov[2].iov_len = 0;
                }
            }

            if (rc == 0) {
                if (!tpm_running) {
                    tpmlib_write_fatal_error_response(&rbuffer, &rlength,
                                                      &rTotal,
                                                      mlp->tpmversion);
                    goto skip_process;
                }
            }

            if (rc == 0) {
                rlength = 0;                                /* clear the response buffer */
                rc = tpmlib_process(&rbuffer,
                                    &rlength,
                                    &rTotal,
                                    &command[cmd_offset],
                                    command_length - cmd_offset,
                                    mlp->locality_flags,
                                    &locality,
                                    mlp->tpmversion);
                if (rlength)
                    goto skip_process;
            }

            if (rc == 0) {
                rlength = 0;                                /* clear the response buffer */
                rc = TPMLIB_Process(&rbuffer,
                                    &rlength,
                                    &rTotal,
                                    &command[cmd_offset],
                                    command_length - cmd_offset);
            }

skip_process:
            /* write the results */
            if (rc == 0) {
                respprefix.size = htobe32(rlength);
                iov[1].iov_base = rbuffer;
                iov[1].iov_len  = rlength;

                SWTPM_IO_Write(&connection_fd, iov, ARRAY_LEN(iov));
            }

            if (!(mlp->flags & MAIN_LOOP_FLAG_KEEP_CONNECTION)) {
                SWTPM_IO_Disconnect(&connection_fd);
                break;
            }
        }

        rc = 0; /* A fatal TPM_Process() error should cause the TPM to enter shutdown.  IO errors
                   are outside the TPM, so the TPM does not shut down.  The main loop should
                   continue to function.*/
        if (connection_fd.fd < 0 && mlp->flags & MAIN_LOOP_FLAG_TERMINATE)
            break;
    }

    free(rbuffer);
    free(command);

    if (ctrlclntfd >= 0)
        close(ctrlclntfd);
    ctrlchannel_set_client_fd(mlp->cc, -1);

    if (mlp->fd >= 0) {
        close(mlp->fd);
        mlp->fd = -1;
    }

    return rc;
}
