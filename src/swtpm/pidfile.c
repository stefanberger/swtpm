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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

#include "pidfile.h"
#include "logging.h"

static char *g_pidfile;

int pidfile_set(const char *pidfile)
{
   g_pidfile = strdup(pidfile);
   if (!g_pidfile) {
       logprintf(STDERR_FILENO, "Out of memory.\n");
       return -1;
   }

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
    FILE *f;

    if (!g_pidfile)
        return 0;

    f = fopen(g_pidfile, "w+");
    if (!f) {
        logprintf(STDERR_FILENO, "Could not open pidfile %s : %s\n",
                  g_pidfile, strerror(errno));
        goto error;
    }

    if (fprintf(f, "%d", pid) < 0) {
        logprintf(STDERR_FILENO, "Could not write to pidfile : %s\n",
                  strerror(errno));
        fclose(f);
        goto error;
    }

    fclose(f);

    return 0;

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
}