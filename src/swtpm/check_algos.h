/*
 * check_algos.h -- Check available algorithms
 *
 * (c) Copyright IBM Corporation 2024.
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

#ifndef _SWTPM_CHECK_ALGOS_H_
#define _SWTPM_CHECK_ALGOS_H_

#include <stdbool.h>

#include <glib.h>

unsigned int check_ossl_algorithms_are_disabled(const gchar *const*algorithms,
                                                unsigned int disabled_filter,
                                                bool stop_on_first_disabled);

/* disabled_filters: */
#define DISABLED_BY_FIPS            (1 << 0)
#define DISABLED_SHA1_SIGNATURES    (1 << 1)
#define DISABLED_BY_CONFIG          (1 << 2)

/* return value: flags indicating how to configure OpenSSL */
#define FIX_DISABLE_FIPS            (1 << 0) /* fix by disabling FIPS mode */
#define FIX_ENABLE_SHA1_SIGNATURES  (1 << 1) /* fix by setting OPENSSL_ENABLE_SHA1_SIGNATURES=1 */
#define FIX_DISABLE_CONFIG          (1 << 2) /* fix by modifying openssl config (how?) */

int check_ossl_fips_disabled_remove_algorithms(gchar ***algorithms,
                                               gboolean check);
int check_ossl_fips_disabled_set_attributes(gchar ***attributes,
                                            gboolean check);

#endif /* _SWTPM_CHECK_ALGOS_H_ */
