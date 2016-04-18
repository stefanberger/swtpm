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
#include "logging.h"
#include "ctrlchannel.h"
#include "mainloop.h"

/* local variables */
static TPM_MODIFIER_INDICATOR locality;
static bool tpm_running = true;

const static unsigned char TPM_Resp_FatalError[] = {
    0x00, 0xC4,                     /* TPM Response */
    0x00, 0x00, 0x00, 0x0A,         /* length (10) */
    0x00, 0x00, 0x00, 0x09          /* TPM_FAIL */
};


bool mainloop_terminate;


TPM_RESULT
mainloop_cb_get_locality(TPM_MODIFIER_INDICATOR *loc,
                         uint32_t tpmnum)
{
    *loc = locality;

    return TPM_SUCCESS;
}

static void
mainloop_write_fatal_error_response(unsigned char **rbuffer,
                                    uint32_t *rlength,
                                    uint32_t *rTotal)
{
    if (*rbuffer == NULL ||
        *rTotal < sizeof(TPM_Resp_FatalError)) {
        *rTotal = sizeof(TPM_Resp_FatalError);
        TPM_Realloc(rbuffer, *rTotal);
    }
    if (*rbuffer) {
        *rlength = sizeof(TPM_Resp_FatalError);
        memcpy(*rbuffer,
               TPM_Resp_FatalError,
               sizeof(TPM_Resp_FatalError));
    }
}

int mainLoop(struct mainLoopParams *mlp,
             int notify_fd,
             struct libtpms_callbacks *callbacks)
{
    TPM_RESULT          rc = 0;
    TPM_CONNECTION_FD   connection_fd;             /* file descriptor for read/write */
    unsigned char       *command = NULL;           /* command buffer */
    uint32_t            command_length;            /* actual length of command bytes */
    uint32_t            max_command_length;        /* command buffer size */
    /* The response buffer is reused for each command. Thus it can grow but never shrink */
    unsigned char       *rbuffer = NULL;           /* actual response bytes */
    uint32_t            rlength = 0;               /* bytes in response buffer */
    uint32_t            rTotal = 0;                /* total allocated bytes */
    int                 ctrlfd;
    int                 ctrlclntfd;
    bool                readall;
    int                 sockfd;

    TPM_DEBUG("mainLoop:\n");

    max_command_length = tpmlib_get_tpm_property(TPMPROP_TPM_BUFFER_MAX);

    rc = TPM_Malloc(&command, max_command_length);
    if (rc != TPM_SUCCESS) {
        fprintf(stderr, "Could not allocate %u bytes for buffer.\n",
                max_command_length);
        return rc;
    }

    connection_fd.fd = -1;
    ctrlfd = ctrlchannel_get_fd(mlp->cc);
    ctrlclntfd = -1;

    sockfd = SWTPM_IO_GetSocketFD();

    readall = (mlp->flags & MAIN_LOOP_FLAG_READALL);

    while (!mainloop_terminate) {

        while (rc == 0) {
            if (mlp->flags & MAIN_LOOP_FLAG_USE_FD)
                connection_fd.fd = mlp->fd;

            struct pollfd pollfds[] = {
                {
                    .fd = connection_fd.fd,
                    .events = POLLIN | POLLHUP,
                    .revents = 0,
                }, {
                    .fd = notify_fd,
                    .events = POLLIN,
                    .revents = 0,
                }, {
                    .fd = ctrlfd,
                    .events = POLLIN,
                    .revents = 0,
                } , {
                    .fd = ctrlclntfd,
                    .events = POLLIN | POLLHUP,
                    .revents = 0,
                } , {
                    /* listen socket for accepting clients */
                    .fd = -1,
                    .events = POLLIN,
                    .revents = 0,
                }
            };

            /* only listend for clients if we don't have one */
            if (connection_fd.fd < 0)
                pollfds[4].fd = sockfd;

            if (poll(pollfds, 5, -1) < 0 ||
                (pollfds[1].revents & POLLIN) != 0) {
                SWTPM_IO_Disconnect(&connection_fd);
                break;
            }

            if (pollfds[0].revents & POLLHUP) {
                /* chardev and unixio get this signal, not tcp */
                if (mlp->flags & MAIN_LOOP_FLAG_END_ON_HUP) {
                    /* only the chardev terminates here */
                    mainloop_terminate = true;
                    break;
                }
            }

            if (pollfds[4].revents & POLLIN)
                connection_fd.fd = accept(pollfds[4].fd, NULL, 0);

            if (pollfds[2].revents & POLLIN)
                ctrlclntfd = accept(ctrlfd, NULL, 0);

            if (pollfds[3].revents & POLLIN) {
                ctrlclntfd = ctrlchannel_process_fd(ctrlclntfd, callbacks,
                                                    &mainloop_terminate,
                                                    &locality, &tpm_running);
                if (mainloop_terminate)
                    break;
            }

            if (pollfds[3].revents & POLLHUP) {
                if (ctrlclntfd >= 0)
                    close(ctrlclntfd);
                ctrlclntfd = -1;
            }

            if (!(pollfds[0].revents & POLLIN))
                continue;

            /* Read the command.  The number of bytes is determined by 'paramSize' in the stream */
            if (rc == 0) {
                rc = SWTPM_IO_Read(&connection_fd, command, &command_length,
                                   max_command_length, mlp, readall);
                if (rc != 0) {
                    /* connection broke */
                    SWTPM_IO_Disconnect(&connection_fd);
                }
            }

            if (rc == 0) {
                if (!tpm_running) {
                    mainloop_write_fatal_error_response(&rbuffer, &rlength,
                                                        &rTotal);
                    goto skip_process;
                }
            }

            if (rc == 0) {
                rlength = 0;                                /* clear the response buffer */
                rc = TPMLIB_Process(&rbuffer,
                                    &rlength,
                                    &rTotal,
                                    command,                /* complete command array */
                                    command_length);        /* actual bytes in command */
            }

skip_process:
            /* write the results */
            if (rc == 0) {
                SWTPM_IO_Write(&connection_fd, rbuffer, rlength);
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

    TPM_Free(rbuffer);
    TPM_Free(command);

    if (ctrlclntfd >= 0)
        close(ctrlclntfd);

    return rc;
}
