/* SPDX-License-Identifier: BSD-3-Clause */

/*
 * sd-notify.c -- Minimal sd_notify() implementation without libsystemd
 *
 * Sends notification messages to systemd via the $NOTIFY_SOCKET
 * Unix datagram socket. Supports filesystem and abstract AF_UNIX sockets.
 */

#include <config.h>

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "sd-notify.h"

int sd_notify(int unset_environment, const char *state)
{
    union {
        struct sockaddr_un un;
        struct sockaddr sa;
    } addr = {
        .un.sun_family = AF_UNIX,
    };
    const char *notify_socket;
    size_t path_len;
    socklen_t addr_len;
    int fd, r;

    notify_socket = getenv("NOTIFY_SOCKET");
    if (!notify_socket)
        return 0;

    if (notify_socket[0] != '/' && notify_socket[0] != '@')
        return -EAFNOSUPPORT;

    path_len = strlen(notify_socket);
    if (path_len >= sizeof(addr.un.sun_path))
        return -E2BIG;

    memcpy(addr.un.sun_path, notify_socket, path_len + 1);

    /* Abstract socket: replace '@' with NUL byte */
    if (addr.un.sun_path[0] == '@')
        addr.un.sun_path[0] = '\0';

    addr_len = offsetof(struct sockaddr_un, sun_path) + path_len;

    fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -errno;

    if (sendto(fd, state, strlen(state), MSG_NOSIGNAL,
               &addr.sa, addr_len) < 0)
        r = -errno;
    else
        r = 1; /* sent successfully */

    (void) close(fd);

    if (unset_environment)
        (void) unsetenv("NOTIFY_SOCKET");

    return r;
}
