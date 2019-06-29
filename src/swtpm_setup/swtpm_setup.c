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

#if defined __APPLE__
#include <sys/mount.h>
#include <mach-o/dyld.h>
#endif

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
    "--swtpm_ioctl",
    "--pcr-banks",
    "--tcsd-system-ps-file",
    "--keyfile-fd",
    "--pwdfile-fd",
    NULL
};

static int change_process_owner(const char *user)
{
    struct passwd *passwd;
    long int uid, gid;
    char *endptr = NULL;

    uid = strtoul(user, &endptr, 10);
    if (*endptr != '\0') {
        /* a string */
        passwd = getpwnam(user);
        if (!passwd) {
            fprintf(stderr, "Error: User '%s' does not exist.\n", user);
            return -1;
        }

        if (initgroups(passwd->pw_name, passwd->pw_gid) < 0) {
            fprintf(stderr, "Error: initgroups(%s, %d) failed.\n",
                    passwd->pw_name, passwd->pw_gid);
           return -1;
        }
        gid = passwd->pw_gid;
        uid = passwd->pw_uid;
    } else {
        /* an integer */
        if ((unsigned long int)uid > UINT_MAX) {
            fprintf(stderr, "Error: uid %s outside valid range.\n", user);
            return -1;
        }
        gid = uid;
    }

    if (setgid(gid) < 0) {
        fprintf(stderr, "Error: setgid(%ld) failed.\n", gid);
        return -1;
    }
    if (setuid(uid) < 0) {
        fprintf(stderr, "Error: setuid(%ld) failed.\n", uid);
        return -1;
    }
    return 0;
}


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
    bool change_user = true;
    bool use_tpm2 = false;
    bool have_runas = false;
    const char *p;
#if defined __APPLE__
    char path[MAXPATHLEN];
    uint32_t pathlen = sizeof(path);
#endif

    while (i < argc) {
        if (!strcmp("--runas", argv[i])) {
            i++;
            if (i == argc) {
                fprintf(stderr, "Missing user argument for --runas");
                exit(1);
            }
            userid = argv[i];
            have_runas = true;
        } else if (!strcmp("--help", argv[i]) || !strcmp("-h", argv[i])) {
            change_user = false;
        } else if (!strcmp("--version", argv[i])) {
            change_user = false;
        } else if (!strcmp("--print-capabilities", argv[i])) {
            change_user = false;
        } else if (!strcmp("--tpm2", argv[i])) {
            use_tpm2 = true;
        }
        for (j = 0; one_arg_params[j] != NULL; j++) {
            if (!strcmp(one_arg_params[j], argv[i])) {
                i++;
                break;
            }
        }
        i++;
    }

#if defined __OpenBSD__ || defined __FreeBSD__ || defined __DragonFly__
    p = getenv("_");
#elif defined __APPLE__
    if (_NSGetExecutablePath(path, &pathlen) < 0) {
        fprintf(stderr, "Could not get path of 'self'.");
        return EXIT_FAILURE;
    }
    p = path;
#else
    p = "/proc/self/exe";
#endif
    if (!realpath(p, resolved_path)) {
        fprintf(stderr, "Could not resolve path (%s) to executable: %s\n",
                p, strerror(errno));
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
        goto exit_failure;
    }

    if (snprintf(path_program, length, "%s/%s", dir, program) >=
        (int)length) {
        fprintf(stderr, "Internal error writing string.\n");
        goto exit_failure;
    }

    /*
     * In case of TPM2 we don't require to run as root since none
     * of the tools we will run require root priviliges similar to
     * TrouSerS (tcsd). So unless we saw --runas, we will not attempt
     * to switch the user.
     */
    if (use_tpm2) {
        if (!have_runas) {
            change_user = false;
        }
    }

    /*
     * In case of TPM 1.2 we allow running this program as 'tss'
     * (E_USER_ID).
     */
    if (!use_tpm2 && change_user) {
        passwd = getpwnam(E_USER_ID);
        if (!passwd) {
            fprintf(stderr, "Could not get account data of user %s.\n", E_USER_ID);
            goto exit_failure;
        }
        if (passwd->pw_uid == geteuid())
            change_user = false;
    }

    if (change_user && change_process_owner(userid))
        goto exit_failure;
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

exit_failure:
    free(path_program);

    return EXIT_FAILURE;
}
