/*
 * capabilities.c -- capabilities
 *
 * (c) Copyright IBM Corporation 2019.
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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libtpms/tpm_library.h>
#include <libtpms/tpm_error.h>

#include "capabilities.h"
#include "logging.h"
#include "swtpm_nvstore.h"

/* Convert the RSA key size indicators supported by libtpms into capability
 * strings.
 * libtpms may return us something like this here:
 * "TPMAttributes":{"manufacturer":"id:00001014",\
 * "version":"id:20191023","model":"swtpm","RSAKeySizes":[1024,2048,3072]}}
 *
 * or an older version may not report RSA keysizes:
 * "TPMAttributes":{"manufacturer":"id:00001014",\
 * "version":"id:20191023","model":"swtpm"}}
 */
static int get_rsa_keysize_caps(char **keysizecaps)
{
    int ret = 0;
    char *start, *endptr;
    const char *needle = "\"RSAKeySizes\":[";
    char *info_data = TPMLIB_GetInfo(4 /*TPMLIB_INFO_TPMFEATURES*/);
    char buffer[128];
    off_t offset = 0;
    int n;

    if (!info_data)
        goto cleanup;

    start = strstr(info_data, needle);
    if (start) {
        start += strlen(needle);
        while (1) {
            unsigned long int keysize = strtoul(start, &endptr, 10);

            if (*endptr != ',' && *endptr != ']') {
                logprintf(STDERR_FILENO, "Malformed TPMLIB_GetInfo() string\n");
                ret = -1;
                goto cleanup;
            }

            n = snprintf(buffer + offset, sizeof(buffer) - offset,
                         ", \"rsa-keysize-%lu\"",
                          keysize);
            if (n < 0 || (unsigned)n >= sizeof(buffer) - offset) {
                logprintf(STDERR_FILENO, "%s: buffer is too small\n", __func__);
                ret = -1;
                goto cleanup;
            }
            if (*endptr == ']')
                break;

            offset += n;
            start = endptr + 1;
        }

        *keysizecaps = strndup(buffer, sizeof(buffer) - 1);
        if (*keysizecaps == NULL)
            goto oom;
    }

cleanup:
    free(info_data);
    return ret;

oom:
    logprintf(STDERR_FILENO, "Out of memory\n");
    ret = -1;
    goto cleanup;
}

int capabilities_print_json(bool cusetpm)
{
    char *string = NULL;
    int ret = -1;
    int n;
#ifdef WITH_SECCOMP
    const char *cmdarg_seccomp = "\"cmdarg-seccomp\", ";
#else
    const char *cmdarg_seccomp = "";
#endif
    const char *with_tpm1 = "";
    const char *with_tpm2 = "";
    char *keysizecaps = NULL;
    const char *nvram_backend_dir = "\"nvram-backend-dir\", ";
    const char *nvram_backend_file = "\"nvram-backend-file\"";

    ret = get_rsa_keysize_caps(&keysizecaps);
    if (ret < 0)
        goto cleanup;

    if (TPMLIB_ChooseTPMVersion(TPMLIB_TPM_VERSION_1_2) == TPM_SUCCESS)
        with_tpm1 = "\"tpm-1.2\", ";
    if (TPMLIB_ChooseTPMVersion(TPMLIB_TPM_VERSION_2) == TPM_SUCCESS)
        with_tpm2 = "\"tpm-2.0\", ";

    n =  asprintf(&string,
         "{ "
         "\"type\": \"swtpm\", "
         "\"features\": [ "
             "%s%s%s%s%s%s%s%s%s%s%s"
          " ], "
         "\"version\": \"" VERSION "\" "
         "}",
         with_tpm1,
         with_tpm2,
         !cusetpm     ? "\"tpm-send-command-header\", ": "",
         !cusetpm     ? "\"flags-opt-startup\", "      : "",
         cmdarg_seccomp,
         true         ? "\"cmdarg-key-fd\", "          : "",
         true         ? "\"cmdarg-pwd-fd\", "          : "",
         true         ? "\"cmdarg-print-states\", "    : "",
         nvram_backend_dir,
         nvram_backend_file,
         keysizecaps  ? keysizecaps                    : ""
    );

    if (n < 0) {
        logprintf(STDERR_FILENO, "Out of memory\n");
        goto cleanup;
    }

    ret = 0;

    fprintf(stdout, "%s\n", string);

cleanup:
    free(keysizecaps);
    free(string);

    return ret;
}
