/*
 * swtpm_setup.c
 *
 * Authors: Stefan Berger <stefanb@us.ibm.com>
 *
 * (c) Copyright IBM Corporation 2011,2014,2015.
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <libgen.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>

#include "swtpm_setup.h"

/*
 * Those parameters interpreted by swtpm_setup.sh that have an additional
 * parameter.
 */
const char *one_arg_params[] = {
    "--tpm-state",
    "--tpmstate",
    "--tpm",
    "--ownerpass",
    "--srkpass",
    "--config",
    "--vmid",
    "--logfile",
    "--keyfile",
    "--pwdfile",
    NULL
};

int main(int argc, char *argv[])
{
    const char *program = "swtpm_setup.sh";
    char resolved_path[PATH_MAX];
    char *dir;
    char *path_program;
    size_t length;
    struct passwd *passwd = NULL;
    int i = 1, j;
    const char *userid = E_USER_ID;
    bool show_help = false;

    while (i < argc) {
        if (!strcmp("--runas", argv[i])) {
            i++;
            if (i == argc) {
                fprintf(stderr, "Missing user argument for --runas");
                exit(1);
            }
            userid = argv[i];
        } else if (!strcmp("--help", argv[i]) || !strcmp("-h", argv[i])) {
            show_help = true;
        } else if (!strcmp("--version", argv[i])) {
            show_help = true;
        }
        for (j = 0; one_arg_params[j] != NULL; j++) {
            if (!strcmp(one_arg_params[j], argv[i])) {
                i++;
                break;
            }
        }
        i++;
    }
    
    if (!realpath("/proc/self/exe", resolved_path)) {
        fprintf(stderr, "Could not resolve path to executable : %s\n",
                strerror(errno));
        return EXIT_FAILURE;
    }

    dir = dirname(resolved_path);
    if (!dir) {
        fprintf(stderr, "Could not get directory from path '%s'.",
                resolved_path);
        return EXIT_FAILURE;
    }

    length = strlen(dir) + 1 + strlen(program) + 2;

    path_program = malloc(length);
    if (!path_program) {
        fprintf(stderr, "Out of memory.\n");
        return EXIT_FAILURE;
    }

    if (snprintf(path_program, length, "%s/%s", dir, program) >=
        (int)length) {
        fprintf(stderr, "Internal error writing string.\n");
        return EXIT_FAILURE;
    }

    if (!show_help) {
        passwd = getpwnam(userid);
        if (!passwd) {
            fprintf(stderr, "Could not get account data of user %s.\n", userid);
            return EXIT_FAILURE;
        }

        if (setgid(passwd->pw_gid)) {
            fprintf(stderr,"Setting groupid to %s (%d) failed: %s\n",
                    userid, passwd->pw_gid, strerror(errno));
            return EXIT_FAILURE;
        }

        if (initgroups(passwd->pw_name, passwd->pw_gid)) {
            fprintf(stderr,"initgroups() failed: %s\n", strerror(errno));
            return EXIT_FAILURE;
        }

        if (setuid(passwd->pw_uid)) {
            fprintf(stderr,"Setting userid to %s (%d) failed.\n",
                    userid, passwd->pw_uid);
            return EXIT_FAILURE;
        }
    }
    /*
     * need to pass unmodified argv to swtpm_setup.sh
     */
    execv(path_program, argv);

    if (passwd) {
        /* should never get here */
        fprintf(stderr, "As user %s:", passwd->pw_name);
    }

    fprintf(stderr, "Could not execute '%s' : %s\n",
            path_program, strerror(errno));

    return EXIT_FAILURE;
}
