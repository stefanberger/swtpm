/*
 * common.h -- Header file for Common code for swtpm and swtpm_cuse
 *
 * (c) Copyright IBM Corporation 2014.
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
#ifndef _SWTPM_COMMON_H_
#define _SWTPM_COMMON_H_

#include "config.h"

#include <stdbool.h>

#include "compiler_dependencies.h"

int handle_log_options(char *options);
int handle_key_options(char *options);
int handle_migration_key_options(char *options);
int handle_pid_options(char *options);
int handle_tpmstate_options(char *options);
struct ctrlchannel;
int handle_ctrlchannel_options(char *options, struct ctrlchannel **cc);
struct server;
int handle_server_options(char *options, struct server **s);
int handle_locality_options(char *options, uint32_t *flags);
int handle_flags_options(char *options, bool *need_init_cmd,
                         uint16_t *startupType);
#ifdef WITH_SECCOMP
int handle_seccomp_options(char *options, unsigned int *seccomp_action);
#else
static inline int handle_seccomp_options(char *options SWTPM_ATTR_UNUSED,
                                         unsigned int *seccomp_action SWTPM_ATTR_UNUSED)
{
    return 0;
}
#endif

#endif /* _SWTPM_COMMON_H_ */

