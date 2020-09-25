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

#define _GNU_SOURCE
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
#include <fcntl.h>

#if defined __APPLE__
#include <sys/mount.h>
#include <mach-o/dyld.h>
#endif

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
    "--rsa-keysize",
    NULL
};

/*
 * Those parameters interpreted by swtpm_setup.sh that have a file descriptor
 * parameter.
 */
const char *fd_arg_params[] = {
    "--keyfile-fd",
    "--pwdfile-fd",
    NULL
};

/*
 * Sanitize the file descriptor we pass to swtpm_setup.sh so that it can
 * freely use any fds in the range [100..109], e.g. 'exec 100 ... '.
 */
static int move_reserved_fd(const char *fdstring, char **newfdstring)
{
    char *endptr;
    long fd;
    int newfd;

    errno = 0;
    fd = strtol(fdstring, &endptr, 10);
    if (fdstring == endptr || *endptr != '\0' || fd < 0 || errno != 0) {
        fprintf(stderr, "Invalid file descriptor '%s'.\n", fdstring);
        return -1;
    }

    /* reserve file descriptors 100 - 109 for swtpm_setup.sh to use */
    if (fd >= 100 && fd <= 109) {
        newfd = fcntl(fd, F_DUPFD, 3);
        if (newfd < 0) {
            fprintf(stderr, "F_DUPFD failed: %s\n", strerror(errno));
            return -1;
        }
        if (newfd >= 100 && newfd <= 109) {
            fprintf(stderr, "newfd is also in reserved range: %u\n", newfd);
            return -1;
        }

        close(fd);

        if (asprintf(newfdstring, "%u", newfd) < 0) {
            fprintf(stderr, "Out of memory\n");
            return -1;
        }

        return 1;
    }
    return 0;
}

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
    int i = 1, j;
    const char *userid = NULL;
    bool change_user = true;
    const char *p;
#if defined __APPLE__
    char path[MAXPATHLEN];
    uint32_t pathlen = sizeof(path);
#endif
    char *newargv;
    int rc;

    while (i < argc) {
        if (!strcmp("--runas", argv[i])) {
            i++;
            if (i == argc) {
                fprintf(stderr, "Missing user argument for --runas\n");
                exit(1);
            }
            userid = argv[i];
        } else if (!strcmp("--help", argv[i]) || !strcmp("-h", argv[i])) {
            change_user = false;
        } else if (!strcmp("--version", argv[i])) {
            change_user = false;
        } else if (!strcmp("--print-capabilities", argv[i])) {
            change_user = false;
        }
        for (j = 0; one_arg_params[j] != NULL; j++) {
            if (!strcmp(one_arg_params[j], argv[i])) {
                i++;
                goto skip;
            }
        }
        /* Ensure that no file descriptor overlaps with those reserved
         * for free use by swtpm_setup.sh
         */
        for (j = 0; fd_arg_params[j] != NULL; j++) {
            if (!strcmp(fd_arg_params[j], argv[i]) &&
                i + 1 < argc) {
                i++;
                rc = move_reserved_fd(argv[i], &newargv);
                switch (rc) {
                case 0:
                    /* nothing to do */
                    break;
                case 1:
                    argv[i] = newargv;
                    break;
                default:
                    return EXIT_FAILURE;
                }
                break;
            }
        }
skip:
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
     * Unless we saw --runas, we will not attempt to switch the user.
     */
    if (!userid)
        change_user = false;

    if (change_user && change_process_owner(userid))
        goto exit_failure;
    /*
     * need to pass unmodified argv to swtpm_setup.sh
     */
    execv(path_program, argv);

    fprintf(stderr, "Could not execute '%s' : %s\n",
            path_program, strerror(errno));

exit_failure:
    free(path_program);

    return EXIT_FAILURE;
}
