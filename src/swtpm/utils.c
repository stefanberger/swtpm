/*
 * utils.s -- utilities
 *
 * (c) Copyright IBM Corporation 2014, 2015.
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

#include <grp.h>
#include <pwd.h>
#include <fcntl.h>
#include <unistd.h>

#include "utils.h"
#include "logging.h"

int install_sighandlers(int pipefd[2], sighandler_t handler)
{
    if (pipe(pipefd) < 0) {
        logprintf(STDERR_FILENO, "Error: Could not open pipe.\n");
        goto err_exit;
    }

    if (signal(SIGTERM, handler) == SIG_ERR) {
        logprintf(STDERR_FILENO, "Could not install signal handler for SIGTERM.\n");
        goto err_close_pipe;
    }

    return 0;

err_close_pipe:
    close(pipefd[0]);
    pipefd[0] = -1;
    close(pipefd[1]);
    pipefd[1] = -1;

err_exit:
    return -1;
}

int
change_process_owner(const char *user)
{
    struct passwd *passwd = getpwnam(user);

    if (!passwd) {
        logprintf(STDERR_FILENO,
                  "Error: User '%s' does not exist.\n",
                  user);
        return 14;
    }
    if (initgroups(passwd->pw_name, passwd->pw_gid) < 0) {
        logprintf(STDERR_FILENO,
                  "Error: initgroups(%s, %d) failed.\n",
                  passwd->pw_name, passwd->pw_gid);
        return -10;
    }
    if (setgid(passwd->pw_gid) < 0) {
        logprintf(STDERR_FILENO,
                  "Error: setgid(%d) failed.\n",
                  passwd->pw_gid);
        return -11;
    }
    if (setuid(passwd->pw_uid) < 0) {
        logprintf(STDERR_FILENO,
                  "Error: setuid(%d) failed.\n",
                  passwd->pw_uid);
        return -12;
    }
    return 0;
}
