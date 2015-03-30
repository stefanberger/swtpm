/*
 * logging.c -- Logging functions
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

#define _GNU_SOURCE
#include <features.h>

#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>

#include "logging.h"

#define CONSOLE_LOGGING   2 /* stderr */
#define SUPPRESS_LOGGING -1

static int logfd = CONSOLE_LOGGING;

/*
 * log_init:
 * Initialize the logging to log into a file with the given name.
 * @filename: the log filename; use '-' to suppress logging
 *
 * Returns 0 on success, -1 on failure with errno set.
 */
int log_init(const char *filename)
{
    if (!strcmp(filename, "-")) {
        logfd = SUPPRESS_LOGGING;
        return 0;
    }

    logfd = open(filename, O_WRONLY|O_CREAT|O_APPEND, S_IRUSR|S_IWUSR);
    if (logfd < 0)
        return -1;

    return 0;
}

/*
 * log_init_fd:
 * Initialize the logging and have the logs written to the given file
 * descriptor.
 * @fd: file descriptor to log to
 *
 * Returns 0 on success, -1 on failure with errno set.
 */
int log_init_fd(int fd)
{
    int flags;

    close(logfd);
    logfd = fd;

    if (logfd >= 0) {
        flags = fcntl(logfd, F_GETFL);
        if (flags == -1)
            return -1;
        if ((flags & (O_RDWR|O_WRONLY)) == 0) {
            errno = EPERM;
            return -1;
        }
    }

    return 0;
}

/*
 * _logprintf:
 * Format a log line and output it to the given file descriptor.
 * @fd: file descriptor to log to
 * @format: printf type of format for the string
 * @ap: list of var args to format
 *
 * Returns the number of bytes written on success, a value < 0 on error.
 */
static int _logprintf(int fd, const char *format, va_list ap)
{
    char *buf = NULL;
    int ret = 0;

    if (logfd == SUPPRESS_LOGGING)
        return 0;

    if (logfd > 0)
        fd = logfd;

    ret = vasprintf(&buf, format, ap);
    if (ret < 0)
        goto cleanup;
    ret = write(fd, buf, strlen(buf));
    free(buf);

cleanup:
    return ret;
}

/*
 * logprintf:
 * log to stderr or logfile
 * @fd : the foile descriptor to log to
 * @format: the printf style format to format the var args into
 * @...  : var args list of parameters to format
 *
 * Returns the number of bytes written on success, a value < 0 on error.
 */
int logprintf(int fd, const char *format, ...)
{
    int ret;
    va_list ap;

    va_start(ap, format);
    ret = _logprintf(fd, format, ap);
    va_end(ap);

    return ret;
}

