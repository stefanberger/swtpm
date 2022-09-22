/*
 * mainloop.h -- The TPM Emulator's main processing loop
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

#ifndef _SWTPM_MAINLOOP_H_
#define _SWTPM_MAINLOOP_H_

#include <libtpms/tpm_library.h>

extern bool mainloop_terminate;
extern bool tpm_running;

struct mainLoopParams {
    uint32_t flags;
#define MAIN_LOOP_FLAG_TERMINATE        (1 << 0)
#define MAIN_LOOP_FLAG_USE_FD           (1 << 1)
#define MAIN_LOOP_FLAG_KEEP_CONNECTION  (1 << 2)
#define MAIN_LOOP_FLAG_END_ON_HUP       (1 << 3)
#define MAIN_LOOP_FLAG_CTRL_END_ON_HUP  (1 << 4) /* terminate on ctrl ch. client loss (QEMU) */

    int fd;
    struct ctrlchannel *cc;
    uint32_t locality_flags;
    TPMLIB_TPMVersion tpmversion;
    uint16_t startupType; /* use TPM 1.2 types */
    uint32_t lastCommand; /* last Command sent to TPM */
    bool disable_auto_shutdown;   /* TPM2_Shutdown() will NOT be sent by swtpm */
    /* whether to defer locking NVRAM storage due to incoming migration */
    bool incoming_migration;
    /* whether storage is is currently locked */
    bool storage_locked;
    /* whether to release the lock on outgoing migration */
    bool release_lock_outgoing;
    /* how many times to retry locking; use for fallback after releasing
       the lock on outgoing migration. */
    unsigned int locking_retries;
#define DEFAULT_LOCKING_RETRIES  300 /* 300 * 10ms */
};

int mainLoop(struct mainLoopParams *mlp,
             int notify_fd);
TPM_RESULT mainloop_cb_get_locality(TPM_MODIFIER_INDICATOR *loc,
                                    uint32_t tpmnum);
bool mainloop_ensure_locked_storage(struct mainLoopParams *mlp);
void mainloop_unlock_nvram(struct mainLoopParams *mlp,
                           unsigned int locking_retries);

#endif /* _SWTPM_MAINLOOP_H_ */
