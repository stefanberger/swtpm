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
#include <string.h>
#include <poll.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>

#include <libtpms/tpm_error.h>
#include <libtpms/tpm_library.h>
#include <libtpms/tpm_memory.h>

#include "swtpm_debug.h"
#include "tpmlib.h"
#include "logging.h"
#include "ctrlchannel.h"
#include "mainloop.h"

/* local variables */
bool mainloop_terminate;

int mainLoop(struct mainLoopParams *mlp,
             int notify_fd,
             struct libtpms_callbacks *callbacks)
{
    TPM_RESULT          rc = 0;
    unsigned char       *command = NULL;           /* command buffer */
    uint32_t            command_length;            /* actual length of command bytes */
    uint32_t            max_command_length;        /* command buffer size */
    /* The response buffer is reused for each command. Thus it can grow but never shrink */
    unsigned char       *rbuffer = NULL;           /* actual response bytes */
    uint32_t            rlength = 0;               /* bytes in response buffer */
    uint32_t            rTotal = 0;                /* total allocated bytes */
    int                 n;
    int                 ctrlfd;
    int                 ctrlclntfd;

    TPM_DEBUG("mainLoop:\n");

    max_command_length = tpmlib_get_tpm_property(TPMPROP_TPM_BUFFER_MAX);

    rc = TPM_Malloc(&command, max_command_length);
    if (rc != TPM_SUCCESS) {
        fprintf(stderr, "Could not allocate %u bytes for buffer.\n",
                max_command_length);
        return rc;
    }

    ctrlfd = ctrlchannel_get_fd(mlp->cc);
    ctrlclntfd = -1;

    while (!mainloop_terminate) {

        while (rc == 0) {
            struct pollfd pollfds[] = {
                {
                    .fd = mlp->fd,
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
                }
            };

            if (poll(pollfds, 4, -1) < 0 ||
                (pollfds[1].revents & POLLIN) != 0) {
                break;
            }

            if ((pollfds[0].revents & POLLHUP)) {
                mainloop_terminate = true;
                break;
            }

            if (pollfds[2].revents & POLLIN)
                ctrlclntfd = accept(ctrlfd, NULL, 0);

            if (pollfds[3].revents & POLLIN) {
                ctrlclntfd = ctrlchannel_process_fd(ctrlclntfd, callbacks,
                                                    &mainloop_terminate);
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
                n = read(mlp->fd, command, max_command_length);
                if (n > 0) {
                    command_length = n;
                } else {
                    rc = TPM_IOERROR;
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
            /* write the results */
            if (rc == 0) {
                n = write(mlp->fd, rbuffer, rlength);
                if (n < 0) {
                    logprintf(STDERR_FILENO, "Could not write to device: %s (%d)\n",
                              strerror(errno), errno);
                    rc = TPM_IOERROR;
                } else if ((uint32_t)n != rlength) {
                    logprintf(STDERR_FILENO, "Could not write complete response.\n");
                    rc = TPM_IOERROR;
                }
            }
        }

        rc = 0; /* A fatal TPM_Process() error should cause the TPM to enter shutdown.  IO errors
                   are outside the TPM, so the TPM does not shut down.  The main loop should
                   continue to function.*/
        if (mlp->flags & MAIN_LOOP_FLAG_TERMINATE)
            break;
    }

    TPM_Free(rbuffer);
    TPM_Free(command);

    if (ctrlclntfd >= 0)
        close(ctrlclntfd);

    return rc;
}
