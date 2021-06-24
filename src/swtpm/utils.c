/*
 * utils.s -- utilities
 *
 * (c) Copyright IBM Corporation 2014, 2015, 2019.
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
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#if defined __APPLE__
#include <fcntl.h>
#include <sys/param.h>
#endif

#include "utils.h"
#include "logging.h"
#include "tpmlib.h"
#include "swtpm_debug.h"

void uninstall_sighandlers()
{
    if (signal(SIGTERM, SIG_DFL) == SIG_ERR)
        logprintf(STDERR_FILENO, "Could not uninstall signal handler for SIGTERM.\n");

    if (signal(SIGPIPE, SIG_DFL) == SIG_ERR)
        logprintf(STDERR_FILENO, "Could not uninstall signal handler for SIGPIPE.\n");
}

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

    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        logprintf(STDERR_FILENO, "Could not install signal handler for SIGPIPE.\n");
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
    struct passwd *passwd;
    long int uid, gid;
    char *endptr = NULL;

    uid = strtoul(user, &endptr, 10);
    if (*endptr != '\0') {
        /* a string */
        passwd = getpwnam(user);
        if (!passwd) {
            logprintf(STDERR_FILENO,
                      "Error: User '%s' does not exist.\n",
                      user);
            return -14;
        }

        if (initgroups(passwd->pw_name, passwd->pw_gid) < 0) {
            logprintf(STDERR_FILENO,
                      "Error: initgroups(%s, %d) failed.\n",
                      passwd->pw_name, passwd->pw_gid);
           return -10;
        }
        gid = passwd->pw_gid;
        uid = passwd->pw_uid;
    } else {
        /* an integer */
        if ((unsigned long int)uid > UINT_MAX) {
            logprintf(STDERR_FILENO,
                      "Error: uid %s outside valid range.\n",
                      user);
            return -13;
        }
        gid = uid;
    }

    if (setgid(gid) < 0) {
        logprintf(STDERR_FILENO,
                  "Error: setgid(%d) failed.\n",
                  gid);
        return -11;
    }
    if (setuid(uid) < 0) {
        logprintf(STDERR_FILENO,
                  "Error: setuid(%d) failed.\n",
                  uid);
        return -12;
    }
    return 0;
}

void tpmlib_debug_libtpms_parameters(TPMLIB_TPMVersion tpmversion)
{
    switch (tpmversion) {
    case TPMLIB_TPM_VERSION_1_2:
        TPM_DEBUG("TPM 1.2: Compiled for %u auth, %u transport, "
                  "and %u DAA session slots\n",
            tpmlib_get_tpm_property(TPMPROP_TPM_MIN_AUTH_SESSIONS),
            tpmlib_get_tpm_property(TPMPROP_TPM_MIN_TRANS_SESSIONS),
            tpmlib_get_tpm_property(TPMPROP_TPM_MIN_DAA_SESSIONS));
        TPM_DEBUG("TPM 1.2: Compiled for %u key slots, %u owner evict slots\n",
            tpmlib_get_tpm_property(TPMPROP_TPM_KEY_HANDLES),
            tpmlib_get_tpm_property(TPMPROP_TPM_OWNER_EVICT_KEY_HANDLES));
        TPM_DEBUG("TPM 1.2: Compiled for %u counters, %u saved sessions\n",
            tpmlib_get_tpm_property(TPMPROP_TPM_MIN_COUNTERS),
            tpmlib_get_tpm_property(TPMPROP_TPM_MIN_SESSION_LIST));
        TPM_DEBUG("TPM 1.2: Compiled for %u family, "
                  "%u delegate table entries\n",
            tpmlib_get_tpm_property(TPMPROP_TPM_NUM_FAMILY_TABLE_ENTRY_MIN),
            tpmlib_get_tpm_property(TPMPROP_TPM_NUM_DELEGATE_TABLE_ENTRY_MIN));
        TPM_DEBUG("TPM 1.2: Compiled for %u total NV, %u savestate, "
                  "%u volatile space\n",
            tpmlib_get_tpm_property(TPMPROP_TPM_MAX_NV_SPACE),
            tpmlib_get_tpm_property(TPMPROP_TPM_MAX_SAVESTATE_SPACE),
            tpmlib_get_tpm_property(TPMPROP_TPM_MAX_VOLATILESTATE_SPACE));
#if 0
        TPM_DEBUG("TPM1.2: Compiled for %u NV defined space\n",
            tpmlib_get_tpm_property(TPMPROP_TPM_MAX_NV_DEFINED_SIZE));
#endif
    break;
    case TPMLIB_TPM_VERSION_2:
    break;
    }
}

char *fd_to_filename(int fd)
{
#if defined __linux__

    char buffer[64];
    char *path;

    snprintf(buffer, sizeof(buffer), "/proc/self/fd/%d", fd);

    path = realpath(buffer, NULL);
    if (!path) {
        logprintf(STDERR_FILENO, "Could not read %s: %s\n",
                  buffer, strerror(errno));
        return NULL;
    }

    return path;

#elif defined __APPLE__

    char *path = malloc(MAXPATHLEN);
    if (!path) {
        logprintf(STDERR_FILENO, "Out of memory.\n");
        return NULL;
    }
    if (fcntl(fd, F_GETPATH, path) < 0) {
        logprintf(STDERR_FILENO, "fcntl for F_GETPATH failed: %\n",
                  strerror(errno));
        free(path);
        return NULL;
    }
    return path;

#else
    (void)fd;
    logprintf(STDERR_FILENO,
              "Cannot convert file descriptor to filename on this platform.\n");
    return NULL;

#endif
}

/*
 * write_full: Write all bytes of a buffer into the file descriptor
 *             and handle partial writes on the way.
 *
 * @fd: file descriptor to write to
 * @buffer: buffer
 * @buflen: length of buffer
 *
 * Returns -1 in case not all bytes could be transferred, number of
 * bytes written otherwise (must be equal to buflen).
 */
ssize_t write_full(int fd, const void *buffer, size_t buflen)
{
    size_t written = 0;
    ssize_t n;

    while (written < buflen) {
        n = write(fd, buffer, buflen - written);
        if (n == 0)
            return -1;
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        written += n;
        buffer += n;
    }
    return written;
}

/*
 * writev_full: Write all bytes of an iovec into the file descriptor
 *              and handle partial writes on the way.
 * @fd: file descriptor to write to
 * @iov: pointer to iov
 * @iovcnt: length of iov array
 *
 * Returns -1 in case not all bytes could be transferred, number of
 * bytes written otherwise (must be equal to buflen).
 */
ssize_t writev_full(int fd, const struct iovec *iov, int iovcnt)
{
    int i;
    size_t off;
    unsigned char *buf;
    ssize_t n;
    size_t bytecount = 0;
    size_t numbufs = 0;
    size_t lastidx = -1;

    for (i = 0; i < iovcnt; i++) {
        if (iov[i].iov_len) {
            bytecount += iov[i].iov_len;
            numbufs++;
            lastidx = i;
        }
    }

    if (numbufs == 1)
        return write_full(fd, iov[lastidx].iov_base, iov[lastidx].iov_len);

    buf = malloc(bytecount);
    if (!buf) {
        errno = ENOMEM;
        return -1;
    }

    off = 0;
    for (i = 0; i < iovcnt; i++) {
        if (!iov[i].iov_len)
            continue;
        memcpy(&buf[off], iov[i].iov_base, iov[i].iov_len);
        off += iov[i].iov_len;
    }

    n = write_full(fd, buf, off);

    free(buf);

    return n;
}

/*
 * read_einter: Read bytes from a file descriptor into a buffer
 *              and handle EINTR. Perform one read().
 *
 * @fd: file descriptor to read from
 * @buffer: buffer
 * @buflen: length of buffer
 *
 * Returns -1 in case an error occurred, number of bytes read otherwise.
 */
ssize_t read_eintr(int fd, void *buffer, size_t buflen)
{
    ssize_t n;

    while (true) {
        n = read(fd, buffer, buflen);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        return n;
    }
}
