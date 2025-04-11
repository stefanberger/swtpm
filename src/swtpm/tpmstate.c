/*
 * tpmstate.c -- tpmstate parameter handling
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

#include "config.h"

#define _GNU_SOURCE
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

#include "tpmstate.h"
#include "logging.h"
#include "swtpm_nvstore.h"

static char *g_backend_uri;
static mode_t g_tpmstate_mode = 0640;
/* false if provided user via command line mode=..., true if using default */
static bool g_tpmstate_mode_is_default = true;
static TPMLIB_TPMVersion g_tpmstate_version = TPMLIB_TPM_VERSION_1_2;
static bool g_tpmstate_do_locking = true; /* true: due to dir backend being default */
static bool g_tpmstate_make_backup = false;

void tpmstate_global_free(void)
{
    free(g_backend_uri);
    g_backend_uri = NULL;
}

int tpmstate_set_backend_uri(char *backend_uri)
{
    g_backend_uri = strdup(backend_uri);
    if (!g_backend_uri) {
        logprintf(STDERR_FILENO, "Out of memory.\n");
        return -1;
    }

    return 0;
}

const char *tpmstate_get_backend_uri(void)
{
    if (g_backend_uri)
        return g_backend_uri;

    if (getenv("TPM_PATH")) {
        if (asprintf(&g_backend_uri, "dir://%s", getenv("TPM_PATH")) < 0) {
            logprintf(STDERR_FILENO,
                      "Could not asprintf TPM backend uri\n");
            return NULL;
        }
        return g_backend_uri;
    }

    return NULL;
}

void tpmstate_set_mode(mode_t mode, bool mode_is_default)
{
    g_tpmstate_mode = mode;
    g_tpmstate_mode_is_default = mode_is_default;
}

mode_t tpmstate_get_mode(bool *mode_is_default)
{
    *mode_is_default = g_tpmstate_mode_is_default;
    return g_tpmstate_mode;
}

void tpmstate_set_locking(bool do_locking)
{
    g_tpmstate_do_locking = do_locking;
}

bool tpmstate_get_locking(void)
{
    return g_tpmstate_do_locking;
}

void tpmstate_set_make_backup(bool make_backup)
{
    g_tpmstate_make_backup = make_backup;
}

bool tpmstate_get_make_backup(void)
{
    return g_tpmstate_make_backup;
}

void tpmstate_set_version(TPMLIB_TPMVersion version)
{
    g_tpmstate_version = version;
}

TPMLIB_TPMVersion tpmstate_get_version(void)
{
    return g_tpmstate_version;
}
