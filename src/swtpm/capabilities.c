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

#include "capabilities.h"
#include "logging.h"

int capabilities_print_json(bool cusetpm)
{
    char *string = NULL;
    int ret = -1;
    int n;
#ifdef WITH_SECCOMP
    bool with_seccomp = 1;
#else
    bool with_seccomp = 0;
#endif

    n =  asprintf(&string,
         "{ "
         "\"type\": \"swtpm\", "
         "\"features\": [ "
             "%s%s%s%s"
          " ] "
         "}",
         !cusetpm     ? "\"tpm-send-command-header\", ": "",
         with_seccomp ? "\"cmdarg-seccomp\", "         : "",
         true         ? "\"cmdarg-key-fd\", "          : "",
         true         ? "\"cmdarg-pwd-fd\""            : ""
    );

    if (n < 0) {
        logprintf(STDERR_FILENO, "Out of memory\n");
        goto cleanup;
    }

    ret = 0;

    fprintf(stdout, "%s\n", string);

cleanup:
    free(string);

    return ret;
}
