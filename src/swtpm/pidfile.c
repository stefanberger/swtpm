/*
 * pidfile.c -- pidfile handling
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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include "pidfile.h"
#include "logging.h"
#include "utils.h"

static char *g_pidfile;
static int pidfilefd = -1;

int pidfile_set(const char *pidfile)
{
   g_pidfile = strdup(pidfile);
   if (!g_pidfile) {
       logprintf(STDERR_FILENO, "Out of memory.\n");
       return -1;
   }

   return 0;
}

int pidfile_set_fd(int newpidfilefd)
{
    pidfilefd = newpidfilefd;

    return 0;
}

/*
 * pidfile_write: Write the given pid to the pidfile
 *
 * @pid: the PID to write
 *
 * Returns 0 on success, -1 on failure.
 */
int pidfile_write(pid_t pid)
{
    int fd;
    char buffer[32];
    ssize_t nwritten;

    if (g_pidfile) {
        fd = open(g_pidfile, O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW,
                  S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
    } else if (pidfilefd >= 0) {
        fd = pidfilefd;
        g_pidfile = fd_to_filename(pidfilefd);
        if (!g_pidfile)
            goto error;

        pidfile_set_fd(-1); /* will be closed */
    } else {
        return 0;
    }

    if (fd < 0) {
        logprintf(STDERR_FILENO, "Could not open pidfile %s : %s\n",
                  g_pidfile, strerror(errno));
        goto error;
    }

    if (snprintf(buffer, sizeof(buffer), "%d", pid) >= (int)sizeof(buffer)) {
        logprintf(STDERR_FILENO, "Could not write pid to buffer\n");
        goto error_close;
    }

    nwritten = write_full(fd, buffer, strlen(buffer));
    if (nwritten < 0 || nwritten != (ssize_t)strlen(buffer)) {
        logprintf(STDERR_FILENO, "Could not write to pidfile : %s\n",
                  strerror(errno));
        goto error_close;
    }

    close(fd);

    return 0;

error_close:
    close(fd);

error:
    return -1;
}

/*
 * pidfile_remove: Remove the pid file
 *
 */
void pidfile_remove(void)
{
    if (!g_pidfile)
        return;

    unlink(g_pidfile);

    free(g_pidfile);
    g_pidfile = NULL;
}