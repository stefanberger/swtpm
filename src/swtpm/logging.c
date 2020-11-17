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

#include "sys_dependencies.h"

#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdbool.h>

#include "logging.h"
#include "utils.h"

#include <libtpms/tpm_library.h>

#define CONSOLE_LOGGING   2 /* stderr */
#define SUPPRESS_LOGGING -1

static int logfd = CONSOLE_LOGGING;
static unsigned int log_level = 1;
static char *log_prefix;

static void log_prefix_clear(void)
{
    free(log_prefix);
    log_prefix = NULL;
}

/*
 * log_init:
 * Initialize the logging to log into a file with the given name.
 * @filename: the log filename; use '-' to suppress logging
 *
 * Returns 0 on success, -1 on failure with errno set.
 */
int log_init(const char *filename, bool truncate)
{
    int flags;

    if (!strcmp(filename, "-")) {
        logfd = SUPPRESS_LOGGING;
        return 0;
    }

    if (!truncate) {
        flags = O_WRONLY|O_CREAT|O_APPEND|O_NOFOLLOW;
    } else {
        flags = O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW;
    }

    logfd = open(filename, flags, S_IRUSR|S_IWUSR);
    if (logfd < 0)
        return -1;

    log_prefix_clear();

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

    log_prefix_clear();

    return 0;
}

/*
 * log_set_level
 * Set the log level; the higher the level, the more is printed
 * @level: the log level
 */
int log_set_level(unsigned int level)
{
    log_level = level;
    char *prefixbuf = NULL;
    int ret = 0;

    if (level >= 5) {
        TPMLIB_SetDebugLevel(level - 4);

        if (asprintf(&prefixbuf, "%s%s",
                     log_prefix ? log_prefix : "",
                     "    ") < 0) {
            ret = -1;
            goto err_exit;
        }
        TPMLIB_SetDebugPrefix(prefixbuf);
        free(prefixbuf);
    }

    if (logfd != SUPPRESS_LOGGING)
        TPMLIB_SetDebugFD(logfd);

err_exit:
    return ret;
}

/*
 * log_set_prefix
 * Set the logging prefix; this function should be
 * call before log_set_level.
 *
 * @prefix: string to print before every line
 */
int log_set_prefix(const char *prefix)
{
    free(log_prefix);

    if (prefix) {
        log_prefix = strdup(prefix);
        if (!log_prefix)
            return -1;
    } else {
        log_prefix = NULL;
    }
    return 0;
}

/*
 * Check whether to write the string to the log following
 * the log level
 * @string: the string to print
 *
 * Returns -1 in case the string must not be printed following
 * the log level, the number of bytes used for indentation otherwise.
 */
int log_check_string(const char *string)
{
    unsigned int level, i;

    if (log_level == 0)
        return -1;

    level = log_level - 1;
    i = 0;
    while (1) {
        if (string[i] == 0)
            return -1;
        if (string[i] != ' ')
            return i;
        if (i == level)
            return -1;
        i++;
    }
}

/*
 * log_global_free: free memory allocated for global variables
 */
void log_global_free(void)
{
    free(log_prefix);
    log_prefix = NULL;
    TPMLIB_SetDebugPrefix(NULL);
}

/*
 * _logprintf:
 * Format a log line and output it to the given file descriptor.
 * @fd: file descriptor to log to
 * @format: printf type of format for the string
 * @ap: list of var args to format
 * @check_indent: whether to check the level or force printing
 *
 * Returns the number of bytes written on success, a value < 0 on error.
 */
static int _logprintf(int fd, const char *format, va_list ap, bool check_indent)
{
    char *buf = NULL;
    int ret = 0, len = 0;

    if (logfd == SUPPRESS_LOGGING)
        return 0;

    if (logfd > 0)
        fd = logfd;

    ret = vasprintf(&buf, format, ap);
    if (ret < 0)
        goto cleanup;

    if (!check_indent || log_check_string(buf) >= 0) {
        if (log_prefix) {
            ret = write_full(fd, log_prefix, strlen(log_prefix));
            if (ret < 0)
                goto err_exit;
            len = ret;
        }
        ret = write_full(fd, buf, strlen(buf));
        if (ret < 0)
            goto err_exit;
        ret += len;
    } else
        ret = 0;
err_exit:
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
    ret = _logprintf(fd, format, ap, true);
    va_end(ap);

    return ret;
}

/*
 * logprintfA:
 * log to stderr or logfile without checking the log level; indent each
 * line by a number of spaces
 *
 * @fd : the foile descriptor to log to
 * @indent: number of bytes to indent the string
 * @format: the printf style format to format the var args into
 * @...  : var args list of parameters to format
 *
 * Returns the number of bytes written on success, a value < 0 on error.
 */
int logprintfA(int fd, unsigned int indent, const char *format, ...)
{
    int ret;
    va_list ap;
    char spaces[20];

    if (indent) {
        if (indent > sizeof(spaces) - 1)
            indent = sizeof(spaces) - 1;
        memset(spaces, ' ', indent);
        spaces[indent] = 0;
        logprintfA(fd, 0, spaces, "");
    }

    va_start(ap, format);
    ret = _logprintf(fd, format, ap, false);
    va_end(ap);

    return ret;
}
