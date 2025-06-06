/*
 * tpmstate.h -- tpmstate parameter handling
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

#ifndef _SWTPM_TPMSTATE_H_
#define _SWTPM_TPMSTATE_H_

#include <stdbool.h>
#include <sys/types.h>
#include <libtpms/tpm_library.h>

int tpmstate_set_backend_uri(char *backend_uri);
const char *tpmstate_get_backend_uri(void);

void tpmstate_set_mode(mode_t mode, bool mode_is_default);
mode_t tpmstate_get_mode(bool *mode_is_default);

void tpmstate_set_locking(bool do_locking);
bool tpmstate_get_locking(void);

void tpmstate_set_make_backup(bool make_backup);
bool tpmstate_get_make_backup(void);

void tpmstate_set_do_fsync(bool do_fsync);
bool tpmstate_get_do_fsync(void);

void tpmstate_global_free(void);

void tpmstate_set_version(TPMLIB_TPMVersion version);
TPMLIB_TPMVersion tpmstate_get_version(void);

#endif /* _SWTPM_TPMSTATE_H_ */
