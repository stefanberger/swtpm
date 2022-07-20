/*
 * fips.c -- FIPS mode related functions
 *
 * (c) Copyright IBM Corporation 2022.
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

#include "fips.h"
#include "logging.h"

#if defined(HAVE_OPENSSL_FIPS_H)
# include <openssl/fips.h>
#elif defined(HAVE_OPENSSL_FIPS_MODE_SET_API)
/* Cygwin has no fips.h but API exists */
extern int FIPS_mode(void);
extern int FIPS_mode_set(int);
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
# include <openssl/evp.h>
#endif

#include <openssl/err.h>

/*
 * disable_fips_mode: If possible, disable FIPS mode to avoid libtpms failures
 *
 * While libtpms does not provide a solution to disable deactivated algorithms
 * avoid libtpms failures due to FIPS mode enablement by disabling FIPS mode.
 *
 * Returns < 0 on error, 0 otherwise.
 */
#if defined(HAVE_OPENSSL_FIPS_H) || defined(HAVE_OPENSSL_FIPS_MODE_SET_API)
int fips_mode_disable(void)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    int mode = EVP_default_properties_is_fips_enabled(NULL);
#else
    int mode = FIPS_mode();
#endif
    int ret = 0;

    if (mode != 0) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        int rc = EVP_default_properties_enable_fips(NULL, 0);
#else
        int rc = FIPS_mode_set(0);
#endif
        if (rc == 1) {
            logprintf(STDOUT_FILENO,
                      "Warning: Disabled OpenSSL FIPS mode\n");
        } else {
            unsigned long err = ERR_get_error();
            logprintf(STDERR_FILENO,
                      "Failed to disable OpenSSL FIPS mode: %s\n",
                      ERR_error_string(err, NULL));
            ret = -1;
        }
    }
    return ret;
}
#else
/* OpenBSD & DragonFlyBSD case */
int fips_mode_disable(void)
{
    return 0;
}
#endif
