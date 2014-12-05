/*
 * tcsd-launcher.c
 *
 * Authors: Stefan Berger <stefanb@us.ibm.com>
 *
 * (c) Copyright IBM Corporation 2011,2014.
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
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <libgen.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>

#define E_USER_GROUP "tss" /* preferably tss */

int main(int argc, char *argv[])
{
    const char *program = "/usr/sbin/tcsd";
    struct passwd *passwd;
    
    passwd = getpwnam(E_USER_GROUP);
    if (!passwd) {
        fprintf(stderr, "Could not get account data of user tss.\n");
        return EXIT_FAILURE;
    }

    if (getuid() != passwd->pw_uid ||
        getgid() != passwd->pw_gid) {
        fprintf(stderr, "Only %s is allowed to launch this program.\n",
                E_USER_GROUP);
        fprintf(stderr, "uid=%d, gid=%d\n", getuid(), getgid());
        return EXIT_FAILURE;
    }

    if (setegid(passwd->pw_gid)) {
        fprintf(stderr, "Setting effective groupid to tss (%d) failed.\n",
                passwd->pw_gid);
        return EXIT_FAILURE;
    }

    if (initgroups(passwd->pw_name, passwd->pw_gid)) {
        fprintf(stderr, "initgroups() failed: %s", strerror(errno));
        return EXIT_FAILURE;
    }

    if (seteuid(passwd->pw_uid)) {
        fprintf(stderr, "Setting effective userid to tss (%d) failed.\n",
                passwd->pw_uid);
        return EXIT_FAILURE;
    }

    execv(program, argv);

    /* should never get here */
    fprintf(stderr, "Could not execute '%s' : %s\n",
            program,
            strerror(errno));

    return EXIT_FAILURE;
}
