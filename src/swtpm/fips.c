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

#include <string.h>

#include "fips.h"
#include "logging.h"
#include "utils.h"
#include "swtpm_utils.h"

#include <openssl/opensslv.h>

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

#if defined(HAVE_OPENSSL_FIPS_H) || defined(HAVE_OPENSSL_FIPS_MODE_SET_API)
/*
 * fips_mode_enabled: Determine whether FIPS mode is enabled
 */
bool fips_mode_enabled(void)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    int mode = EVP_default_properties_is_fips_enabled(NULL);
#else
    int mode = FIPS_mode();
#endif
    return mode != 0;
}

/*
 * disable_fips_mode: If possible, disable FIPS mode to avoid libtpms failures
 *
 * While libtpms does not provide a solution to disable deactivated algorithms
 * avoid libtpms failures due to FIPS mode enablement by disabling FIPS mode.
 *
 * Returns < 0 on error, 0 otherwise.
 */
int fips_mode_disable(void)
{
    int ret = 0;

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
    return ret;
}
#else
/* OpenBSD & DragonFlyBSD case */
bool fips_mode_enabled(void)
{
    return false;
}

int fips_mode_disable(void)
{
    return 0;
}
#endif

/* list of FIPS-disabled algorithms that TPM 2 may enable */
static const char *fips_disabled[] = {
    "camellia",
    "rsaes",
    "tdes",
    NULL
};

/* list of minimum required key sizes for FIPS */
static const struct key_sizes {
    const char *keyword;
    unsigned int min_size;
} fips_key_sizes[] = {
    {
        .keyword = "ecc-min-size=",
        .min_size = 224,
    }, {
        // keep last
    }
};

/* Determine whether any of the algorithms in the array are FIPS-disable */
static bool _fips_algorithms_are_disabled(gchar *const*algorithms,
                                          const char **fips_disabled_algos,
                                          const struct key_sizes *key_sizes)
{
    bool all_good = true;
    unsigned long v;
    size_t i, l;
    int j;

    for (i = 0; fips_disabled_algos[i] != NULL; i++) {
        if (strv_strncmp(algorithms, fips_disabled_algos[i], -1) >= 0) {
            logprintf(STDERR_FILENO, "Warning(FIPS): Enable algorithms contain '%s'.\n",
                      fips_disabled_algos[i]);
            all_good = false;
            break;
        }
    }

    for (i = 0; key_sizes[i].keyword; i++) {
        l = strlen(key_sizes[i].keyword);
        j = strv_strncmp(algorithms, key_sizes[i].keyword, l);
        if (j >= 0) {
            /* trusting value from libtpms is well formatted avoiding checks */
            v = strtoul(&(algorithms[j][l]), NULL, 10);
            if (v < key_sizes[i].min_size) {
                logprintf(STDERR_FILENO,
                          "Warning(FIPS): Enabled key sizes %s%lu is smaller than required %u.\n",
                          key_sizes[i].keyword, v, key_sizes[i].min_size);
                all_good = false;
                break;
            }
        } else {
            logprintf(STDERR_FILENO,
                      "Warning(FIPS): Missing statement '%s%u' to restrict key size.\n",
                      key_sizes[i].keyword, key_sizes[i].min_size);
            all_good = false;
        }
    }
    return all_good;
}

/* Determine whether the algorithms in the given array contain any algorithms
 * that OpenSSL disables when the host is in FIPS mode. If any of these
 * algorithms are found to be disabled (unusable for libtpms), then 'false' is
 * returned, 'true' otherwise. If 'false' is returned then OpenSSL's FIPS mode
 * must be disabled for libtpms to not cause selftest failures.
 */
bool fips_algorithms_are_disabled(gchar *const*algorithms)
{
    return _fips_algorithms_are_disabled(algorithms, fips_disabled, fips_key_sizes);
}

static const struct {
    const char *attr;
    const char **fips_disabled_algos;
    const struct key_sizes *fips_key_sizes;
} fips_attributes[] = {
    {
        .attr = "fips-host",  // disables a few algos/keysizes but also needs the following ones to be disabled
        .fips_disabled_algos = fips_disabled,
        .fips_key_sizes = fips_key_sizes,
    }, {
        // keep last
    }
};

/* Determine whether any of the attributes disable those algorithms and key
 * sizes that would be a concern for FIPS mode (unusable for libtpms).
 * This function returns 'true' if all algorithms that are of a concern for
 * a host in FIPS mode are disabled, 'false' otherwise. If 'false' is returned
 * the OpenSSL's FIPS mode must be disable for libtpms to not cause selftest
 * failures.
 */
bool fips_attributes_disable_bad_algos(gchar *const*attributes,
                                       gchar *const*algorithms)
{
    bool ret = false;
    size_t i;

    for (i = 0; fips_attributes[i].attr != NULL; i++) {
        if (strv_strncmp(attributes, fips_attributes[i].attr, -1) >= 0) {
            ret = _fips_algorithms_are_disabled(algorithms,
                                                fips_attributes[i].fips_disabled_algos,
                                                fips_attributes[i].fips_key_sizes);
            if (!ret)
                break;
        }
    }
    return ret;
}
