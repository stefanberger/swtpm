/*
 * common.c -- Common code for swtpm and swtpm_cuse
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

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>

#include <libtpms/tpm_error.h>

#include "common.h"
#include "options.h"
#include "key.h"
#include "logging.h"
#include "swtpm_nvfile.h"

/* --log %s */
static const OptionDesc logging_opt_desc[] = {
    {
        .name = "file",
        .type = OPT_TYPE_STRING,
    }, {
        .name = "fd",
        .type = OPT_TYPE_INT,
    },
    END_OPTION_DESC
};

/* --key %s */
static const OptionDesc key_opt_desc[] = {
    {
        .name = "file",
        .type = OPT_TYPE_STRING,
    }, {
        .name = "mode",
        .type = OPT_TYPE_STRING,
    }, {
        .name = "format",
        .type = OPT_TYPE_STRING,
    }, {
        .name = "remove",
        .type = OPT_TYPE_BOOLEAN,
    }, {
        .name = "pwdfile",
        .type = OPT_TYPE_STRING,
    },
    END_OPTION_DESC
};

/*
 * handle_log_options:
 * Parse and act upon the parsed log options. Initialize the logging.
 * @options: the log options
 *
 * Returns 0 on success, -1 on failure.
 */
int
handle_log_options(char *options)
{
    char *error = NULL;
    const char *logfile = NULL;
    int logfd;
    OptionValues *ovs = NULL;

    if (!options)
        return 0;

    ovs = options_parse(options, logging_opt_desc, &error);
    if (!ovs) {
        fprintf(stderr, "Error parsing logging options: %s\n",
                error);
        return -1;
    }
    logfile = option_get_string(ovs, "file", NULL);
    logfd = option_get_int(ovs, "fd", -1);
    if (logfile && (log_init(logfile) < 0)) {
        fprintf(stderr,
            "Could not open logfile for writing: %s\n",
            strerror(errno));
        goto error;
    } else if (logfd >= 0 && (log_init_fd(logfd) < 0)) {
        fprintf(stderr,
                "Could not access logfile using fd %d: %s\n",
                logfd, strerror(errno));
        goto error;
    }

    option_values_free(ovs);

    return 0;

error:
    option_values_free(ovs);

    return -1;
}

/*
 * handle_key_options:
 * Parse and act upon the parsed key options. Set global values related
 * to the options found.
 * @options: the key options to parse
 *
 * Returns 0 on success, -1 on failure.
 */
int
handle_key_options(char *options)
{
    OptionValues *ovs = NULL;
    char *error = NULL;
    const char *keyfile = NULL;
    const char *pwdfile = NULL;
    const char *tmp;
    enum key_format keyformat;
    enum encryption_mode encmode;
    unsigned char key[128/8];
    size_t maxkeylen = sizeof(key);
    size_t keylen;

    if (!options)
        return 0;

    ovs = options_parse(options, key_opt_desc, &error);

    if (!ovs) {
        fprintf(stderr, "Error parsing key options: %s\n",
                error);
        goto error;
    }

    keyfile = option_get_string(ovs, "file", NULL);
    pwdfile = option_get_string(ovs, "pwdfile", NULL);
    if (!keyfile && !pwdfile) {
        fprintf(stderr, "Either --key or --pwdfile is required\n");
        goto error;
    }

    tmp = option_get_string(ovs, "format", NULL);
    keyformat = key_format_from_string(tmp ? tmp : "hex");
    if (keyformat == KEY_FORMAT_UNKNOWN)
        goto error;

    tmp = option_get_string(ovs, "mode", NULL);
    encmode = encryption_mode_from_string(tmp ? tmp : "aes-cbc");
    if (encmode == ENCRYPTION_MODE_UNKNOWN)
        goto error;

    if (keyfile != NULL) {
        if (key_load_key(keyfile, keyformat,
                         key, &keylen, maxkeylen) < 0)
            goto error;
    } else {
        /* no key file, so must be pwdfile */
        if (key_from_pwdfile(pwdfile, key, &keylen,
                             maxkeylen) < 0)
            goto error;
    }

    if (SWTPM_NVRAM_Set_FileKey(key, keylen, encmode) != TPM_SUCCESS)
        goto error;

    if (option_get_bool(ovs, "remove", false)) {
        if (keyfile)
            unlink(keyfile);
        if (pwdfile)
            unlink(pwdfile);
    }

    option_values_free(ovs);

    return 0;

error:
    option_values_free(ovs);

    return -1;
}
