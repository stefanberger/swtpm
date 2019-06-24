/*
 * ctrlchannel.h -- control channel implementation
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

#ifndef _SWTPM_CTRLCHANNEL_H_
#define _SWTPM_CTRLCHANNEL_H_

#include <stdbool.h>

#include <libtpms/tpm_types.h>

struct ctrlchannel;
struct libtpms_callbacks;
struct mainLoopParams;

struct ctrlchannel *ctrlchannel_new(int fd, bool isclient,
                                    const char *sockpath);
int ctrlchannel_get_fd(struct ctrlchannel *cc);
int ctrlchannel_get_client_fd(struct ctrlchannel *cc);
int ctrlchannel_set_client_fd(struct ctrlchannel *cc, int fd);
int ctrlchannel_process_fd(int fd,
                           bool *terminate,
                           TPM_MODIFIER_INDICATOR *locality,
                           bool *tpm_running,
                           struct mainLoopParams *mlp);
void ctrlchannel_free(struct ctrlchannel *cc);

#endif /* _SWTPM_CTRLCHANNEL_H_ */
