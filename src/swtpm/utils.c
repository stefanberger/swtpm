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
}
