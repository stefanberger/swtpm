/*
 * server.c -- server parameters
 *
 * (c) Copyright IBM Corporation 2016.
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

#include <stdlib.h>
#include <string.h>

#include "logging.h"
#include "server.h"

struct server {
   int fd;
   unsigned int flags;
   char *sockpath; /* for UnixIO socket */
};

struct server *server_new(int fd, unsigned int flags,
                          const char *sockpath)
{
    struct server *c = calloc(1, sizeof(struct server));

    if (!c) {
        logprintf(STDERR_FILENO, "Out of memory");
        return NULL;
    }

    c->fd = fd;
    c->flags = flags;

    if (sockpath) {
        c->sockpath = strdup(sockpath);
        if (!c->sockpath) {
            logprintf(STDERR_FILENO, "Out of memory");
            free(c);
            c = NULL;
        }
    }

    return c;
}

int server_get_fd(struct server *c)
{
    return c->fd;
}

int server_set_fd(struct server *c, int fd)
{
    int oldfd = c->fd;

    c->fd = fd;

    return oldfd;
}

unsigned int server_get_flags(struct server *c)
{
    return c->flags;
}

void server_free(struct server *c)
{
    if (!c)
        return;

    if (c->fd >= 0)
        close(c->fd);

    if (c->sockpath) {
        unlink(c->sockpath);
        free(c->sockpath);
    }

    free(c);
}
