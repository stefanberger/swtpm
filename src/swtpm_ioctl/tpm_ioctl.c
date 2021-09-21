/*
 * tpm_ioctl  --  ioctl utility for the TPM
 *
 * Authors: David Safford <safford@us.ibm.com>
 *          Stefan Berger <stefanb@us.ibm.com>
 *
 * (c) Copyright IBM Corporation 2014 - 2016.
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
/*
 * tool for using 'swtpm cuse' ioctls
 *
 * cuse_tpm_ioctl [ -c | -i | -s | -e | -l num | -C | -v ] devicepath
 *     -c get ptm capabilities
 *     -i do a hardware TPM_Init
 *     -s shutdown tpm_server_cuse
 *     -e get tpmEstablished bit
 *     -l set locality to num
 *     -h hash the given data
 *     -v store volatile data to file
 *     -C cancel an ongoing TPM command
 */

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <getopt.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netdb.h>
#include <sys/param.h>
#include <signal.h>
#include <poll.h>

#include <swtpm/tpm_ioctl.h>

#include <libtpms/tpm_error.h>

#include "sys_dependencies.h"
#include "swtpm.h"

#define DEFAULT_TCP_PORT 6546

#define devtoh32(is_chardev, x) (is_chardev ? x : be32toh(x))
#define htodev32(is_chardev, x) (is_chardev ? x : htobe32(x))

#define devtoh64(is_chardev, x) (is_chardev ? x : be64toh(x))
#define htodev64(is_chardev, x) (is_chardev ? x : htobe64(x))

/* for OpenBSD */
#ifndef _IOC_NRSHIFT
# define _IOC_NRSHIFT 0
#endif
#ifndef _IOC_NRMASK
# define _IOC_NRMASK 255
#endif

/* poll timeout that takes into account a busy swtpm creating a key */
#define DEFAULT_POLL_TIMEOUT 10000 /* ms */

static unsigned long ioctl_to_cmd(unsigned long ioctlnum)
{
    /* the ioctl number contains the command number - 1 */
    return ((ioctlnum >> _IOC_NRSHIFT) & _IOC_NRMASK) + 1;
}

/*
 * ctrlcmd - send a control command
 *
 * This function returns -1 on on error with errno indicating the error.
 * In case an ioctl is used, it returns 0 on success; otherwise
 * it returns the number of bytes received in the response.
 */
static int ctrlcmd(int fd, unsigned long cmd, void *msg, size_t msg_len_in,
                   size_t msg_len_out)
{
    struct stat statbuf;
    int n;

    n = fstat(fd, &statbuf);
    if (n < 0) {
        fprintf(stderr, "fstat failed: %s\n", strerror(errno));
        return -1;
    }

    if ((statbuf.st_mode & S_IFMT) == S_IFCHR) {
        n = ioctl(fd, cmd, msg);
    } else {
        uint32_t cmd_no = htobe32(ioctl_to_cmd(cmd));
        struct iovec iov[2] = {
            {
                .iov_base = &cmd_no,
                .iov_len = sizeof(cmd_no),
            }, {
                .iov_base = msg,
                .iov_len = msg_len_in,
            },
        };

        n = writev(fd, iov, 2);
        if (n > 0) {
            if (msg_len_out > 0) {
                struct pollfd fds = {
                    .fd = fd,
                    .events = POLLIN,
                };
                n = poll(&fds, 1, DEFAULT_POLL_TIMEOUT);
                if (n == 1) {
                    n = read(fd, msg, msg_len_out);
                } else if (n == 0) {
                    n = -1;
                    errno = ETIMEDOUT;
                }
            } else {
                /* we read 0 bytes */
                n = 0;
            }
        }
    }
    return n;
}

/*
 * Do PTM_HASH_START, PTM_HASH_DATA, PTM_HASH_END on the
 * data.
 */
static int do_hash_start_data_end(int fd, bool is_chardev, const char *input)
{
    ptm_res res;
    int n;
    size_t idx;
    ptm_hdata hdata;
    size_t inputlen;

    memset(&hdata, 0, sizeof(hdata));

    if (!input) {
        fprintf(stderr,
                "Input buffer for hashing must not be NULL.\n");
        return 1;
    }

    /* hash string given on command line */
    n = ctrlcmd(fd, PTM_HASH_START, &res, 0, sizeof(res));
    if (n < 0) {
        fprintf(stderr,
                "Could not execute ioctl PTM_HASH_START: "
                "%s\n", strerror(errno));
        return 1;
    }
    if (devtoh32(is_chardev, res) != 0) {
        fprintf(stderr,
                "TPM result from PTM_HASH_START: 0x%x\n",
                devtoh32(is_chardev, res));
        return 1;
    }
    inputlen = strlen(input);

    if (inputlen == 1 && input[0] == '-') {
        /* read data from stdin */
        while (1) {
            idx = 0;
            int c = 0;

            while (idx < sizeof(hdata.u.req.data)) {
                c = fgetc(stdin);
                if (c == EOF)
                    break;

                hdata.u.req.data[idx] = (char)c;
                idx++;
            }
            hdata.u.req.length = htodev32(is_chardev, idx);

            n = ctrlcmd(fd, PTM_HASH_DATA, &hdata,
                        offsetof(ptm_hdata, u.req.data) + idx,
                        sizeof(hdata.u.resp));

            res = devtoh32(is_chardev, hdata.u.resp.tpm_result);
            if (n < 0 || res != 0 || c == EOF)
                break;
        }
    } else {
        idx = 0;
        while (idx < inputlen) {
            size_t tocopy = inputlen - idx;

            if (tocopy > sizeof(hdata.u.req.data))
                tocopy = sizeof(hdata.u.req.data);

            hdata.u.req.length = htodev32(is_chardev, tocopy);
            memcpy(hdata.u.req.data, &input[idx], tocopy);
            idx += tocopy;

            n = ctrlcmd(fd, PTM_HASH_DATA, &hdata,
                        offsetof(ptm_hdata, u.req.data) + tocopy,
                        sizeof(hdata.u.resp));

            res = devtoh32(is_chardev, hdata.u.resp.tpm_result);
            if (n < 0 || res != 0)
                break;
        }
    }
    if (n < 0) {
        fprintf(stderr,
                "Could not execute ioctl PTM_HASH_DATA: "
                "%s\n", strerror(errno));
        return 1;
    }
    if (res != 0) {
        fprintf(stderr,
               "TPM result from PTM_HASH_DATA: 0x%x\n", res);
        return 1;
    }
    n = ctrlcmd(fd, PTM_HASH_END, &res, 0, sizeof(res));
    if (n < 0) {
        fprintf(stderr,
                "Could not execute ioctl PTM_HASH_END: "
                "%s\n", strerror(errno));
        return 1;
    }
    if (devtoh32(is_chardev, res) != 0) {
        fprintf(stderr,
                "TPM result from PTM_HASH_END: 0x%x\n",
                devtoh32(is_chardev, res));
        return 1;
    }

    return 0;
}

static uint32_t get_blobtype(const char *blobname)
{
    if (!blobname)
        return 0;
    if (!strcmp(blobname, "permanent"))
        return PTM_BLOB_TYPE_PERMANENT;
    if (!strcmp(blobname, "volatile"))
        return PTM_BLOB_TYPE_VOLATILE;
    if (!strcmp(blobname, "savestate"))
        return PTM_BLOB_TYPE_SAVESTATE;
    return 0;
}

/*
 * do_save_state_blob: Get a state blob from the TPM and store it into the
 *                     given file
 * @fd: file descriptor to talk to the TPM
 * @is_chardev: whether @fd is a character device using ioctl
 * @blobtype: the name of the blobtype
 * @filename: name of the file to store the blob into
 *
 */
static int do_save_state_blob(int fd, bool is_chardev, const char *blobtype,
                              const char *filename, size_t buffersize)
{
    int file_fd;
    ptm_res res;
    ptm_getstate pgs;
    uint16_t offset;
    ssize_t numbytes, remain = -1;
    bool had_error;
    int n;
    uint32_t bt;
    unsigned char *buffer =  NULL;
    uint32_t recvd_bytes;

    memset(&pgs, 0, sizeof(pgs));

    bt = get_blobtype(blobtype);
    if (!bt) {
        fprintf(stderr,
                "Unknown TPM state type '%s'", blobtype);
        return 1;
    }

    file_fd = open(filename, O_WRONLY|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR);
    if (file_fd < 0) {
        fprintf(stderr,
                "Could not open file '%s' for writing: %s\n",
                filename, strerror(errno));
        return 1;
    }

    if (!is_chardev)
        buffersize = 4096;

    had_error = false;
    offset = 0;

    while (true) {
        /* fill out request every time since response may change it */
        pgs.u.req.state_flags = htodev32(is_chardev, PTM_STATE_FLAG_DECRYPTED);
        pgs.u.req.type = htodev32(is_chardev, bt);
        pgs.u.req.offset = htodev32(is_chardev, offset);

        n = ctrlcmd(fd, PTM_GET_STATEBLOB, &pgs, sizeof(pgs.u.req),
                    sizeof(pgs.u.resp));
        if (n < 0) {
            fprintf(stderr,
                    "Could not execute ioctl PTM_GET_STATEBLOB: "
                    "%s\n", strerror(errno));
            had_error = true;
            break;
        }
        res = devtoh32(is_chardev, pgs.u.resp.tpm_result);
        if (res != 0 && (res & TPM_NON_FATAL) == 0) {
            fprintf(stderr,
                    "TPM result from PTM_GET_STATEBLOB: 0x%x\n",
                    res);
            had_error = true;
            break;
        }

        if (remain == -1)
            remain = devtoh32(is_chardev, pgs.u.resp.totlength);

        if (!is_chardev) {
            /* we receive a part of the chunk */
            recvd_bytes = n - offsetof(ptm_getstate, u.resp.data);
            if ((int32_t)recvd_bytes < 0) {
                fprintf(stderr,
                        "Too few bytes in response");
                had_error = true;
                break;
            }
        } else {
            recvd_bytes =
                MIN(devtoh32(is_chardev, pgs.u.resp.length),
                    sizeof(pgs.u.resp.data));
        }

        numbytes = write(file_fd, pgs.u.resp.data, recvd_bytes);
        if (numbytes < 0 || (uint32_t)numbytes != recvd_bytes) {
            fprintf(stderr,
                    "Could not write to file '%s': %s\n",
                    filename, strerror(errno));
            had_error = true;
            break;
        }
        remain -= recvd_bytes;

        /* done when the last byte was received */
        if (offset + recvd_bytes >= devtoh32(is_chardev, pgs.u.resp.totlength))
            break;

        if (buffersize) {
            /* continue with the read interface */
            buffer = malloc(buffersize);
            if (!buffer) {
                fprintf(stderr,
                        "Could not allocate buffer with %zu bytes.",
                        buffersize);
                had_error = true;
                break;
            }

            while (true) {
                /* read from TPM */
                n = read(fd, buffer, buffersize);
                if (n < 0) {
                    fprintf(stderr,
                            "Could not read from TPM: %s\n",
                            strerror(errno));
                    had_error = true;
                    break;
                }
                remain -= n;

                numbytes = write(file_fd, buffer, n);
                if (numbytes < 0) {
                    fprintf(stderr,
                            "Could not write to file '%s': %s\n",
                            filename, strerror(errno));
                    had_error = true;
                    break;
                }
                if (remain <= 0)
                    break;
            }

            break;
        } else {
            offset += devtoh32(is_chardev, pgs.u.resp.length);
        }
    }

    close(file_fd);

    free(buffer);

    if (had_error)
        return 1;

    if (remain != 0) {
        fprintf(stderr, "Unexpected number of remaining bytes: %zd\n", remain);
        return 1;
    }

    return 0;
}

/*
 * do_load_state_blob: Load a TPM state blob from a file and load it into the
 *                     TPM
 * @fd: file descriptor to talk to the TPM
 * @is_chardev: whether @fd is a character device
 * @blobtype: the name of the blobtype
 * @filename: name of the file to store the blob into
 * @buffersize: the size of the buffer to use via write() interface
 */
static int do_load_state_blob(int fd, bool is_chardev, const char *blobtype,
                              const char *filename,
                              size_t buffersize)
{
    int file_fd;
    ptm_res res;
    ptm_setstate pss;
    ssize_t numbytes;
    bool had_error;
    int n;
    uint32_t bt;
    unsigned char *buffer = NULL;
    struct stat statbuf;

    bt = get_blobtype(blobtype);
    if (!bt) {
        fprintf(stderr,
                "Unknown TPM state type '%s'", blobtype);
        return 1;
    }

    if (!filename) {
        fprintf(stderr,
                "Filename parameter must not be NULL\n");
        return 1;
    }

    file_fd = open(filename, O_RDONLY);
    if (file_fd < 0) {
        fprintf(stderr,
                "Could not open file '%s' for reading: %s\n",
                filename, strerror(errno));
        return 1;
    }

    if (!is_chardev) {
        n = fstat(file_fd, &statbuf);
        if (n < 0) {
            fprintf(stderr,
                    "Could not stat file '%s': %s\n",
                    filename, strerror(errno));
            close(file_fd);
            return 1;
        }
        buffersize = statbuf.st_size;
    }

    had_error = false;

    if (!buffersize) {
        /* use only the ioctl interface for the transfer */
        while (true) {
            size_t returnsize;

            /* fill out request every time since response may change it */
            pss.u.req.state_flags = htodev32(is_chardev, 0);
            pss.u.req.type = htodev32(is_chardev, bt);

            numbytes = read(file_fd, pss.u.req.data, sizeof(pss.u.req.data));
            if (numbytes < 0) {
                fprintf(stderr,
                        "Could not read from file '%s': %s\n",
                        filename, strerror(errno));
               had_error = true;
               break;
            }
            pss.u.req.length = htodev32(is_chardev, (uint32_t)numbytes);

            /* the returnsize is zero on all intermediate packets */
            returnsize = ((size_t)numbytes < sizeof(pss.u.req.data))
                         ? sizeof(pss) : 0;

            n = ctrlcmd(fd, PTM_SET_STATEBLOB, &pss,
                        offsetof(ptm_setstate, u.req.data) + numbytes,
                        returnsize);
            if (n < 0) {
                fprintf(stderr,
                        "Could not execute ioctl PTM_SET_STATEBLOB: "
                        "%s\n", strerror(errno));
                had_error = true;
                break;
            }
            res = devtoh32(is_chardev, pss.u.resp.tpm_result);
            if (res != 0) {
                fprintf(stderr,
                        "TPM result from PTM_SET_STATEBLOB: 0x%x\n",
                        res);
                had_error = true;
                break;
            }
            if ((size_t)numbytes < sizeof(pss.u.req.data))
                break;
        }
    } else {
        buffer = malloc(buffersize);
        if (!buffer) {
            fprintf(stderr,
                    "Could not allocate buffer with %zu bytes.",
                    buffersize);
            had_error = true;
            goto cleanup;
        }

        memset(&pss, 0, sizeof(pss));
        pss.u.req.state_flags = htodev32(is_chardev, 0);
        pss.u.req.type = htodev32(is_chardev, bt);
        /* will use write interface */
        if (is_chardev) {
            pss.u.req.length = htodev32(is_chardev, 0);
        } else {
            pss.u.req.length = htodev32(is_chardev, buffersize);
        }

        n = ctrlcmd(fd, PTM_SET_STATEBLOB, &pss,
                    offsetof(ptm_setstate, u.req.data) + 0,
                    0);
        if (n < 0) {
            fprintf(stderr,
                    "Could not execute ioctl PTM_SET_STATEBLOB: "
                    "%s\n", strerror(errno));
            had_error = 1;
            goto cleanup;
        }
        res = devtoh32(is_chardev, pss.u.resp.tpm_result);
        if (res != 0) {
            fprintf(stderr,
                    "TPM result from PTM_SET_STATEBLOB: 0x%x\n",
                    res);
            had_error = 1;
            goto cleanup;
        }

        while (true) {
            n = read(file_fd, buffer, buffersize);
            if (n < 0) {
                fprintf(stderr, "Could not read from file: %s\n",
                        strerror(errno));
                had_error = 1;
                goto cleanup;
            }
            if (n != write(fd, buffer, n)) {
                fprintf(stderr, "Could not write to file: %s\n",
                        strerror(errno));
                had_error = 1;
                goto cleanup;
            }

            if (!is_chardev) {
                n = read(fd, &pss.u.resp, sizeof(pss.u.resp));
                if (n < 0) {
                    fprintf(stderr,
                            "Error reading response: %s\n",
                            strerror(errno));
                    had_error = 1;
                    goto cleanup;
                }
                if (n != sizeof(pss.u.resp)) {
                    fprintf(stderr,
                            "Did not get enough response bytes "
                            "from PTM_SET_STATE_BLOB: %d\n", n);
                    had_error = 1;
                    goto cleanup;
                }
                res = devtoh32(is_chardev, pss.u.resp.tpm_result);
                if (res != 0) {
                    fprintf(stderr,
                            "TPM result from PTM_SET_STATEBLOB: 0x%x\n",
                            res);
                    had_error = 1;
                    goto cleanup;
                }
                break;
            }

            if ((size_t)n < buffersize) {
                /* close transfer with the ioctl() */
                pss.u.req.state_flags = htodev32(is_chardev, 0);
                pss.u.req.type = htodev32(is_chardev, bt);
                /* end the transfer */
                pss.u.req.length = htodev32(is_chardev, 0);

                n = ctrlcmd(fd, PTM_SET_STATEBLOB, &pss,
                            offsetof(ptm_setstate, u.req.data) + 0,
                            sizeof(pss.u.resp));
                if (n < 0) {
                    fprintf(stderr,
                            "Could not execute ioctl PTM_SET_STATEBLOB: "
                            "%s\n", strerror(errno));
                    had_error = 1;
                    goto cleanup;
                }
                res = devtoh32(is_chardev, pss.u.resp.tpm_result);
                if (res != 0) {
                    fprintf(stderr,
                            "TPM result from PTM_SET_STATEBLOB: 0x%x\n",
                            res);
                    had_error = 1;
                    goto cleanup;
                }
                break;
            }
        }
    }

 cleanup:
    close(file_fd);

    free(buffer);

    if (had_error)
        return 1;

    return 0;
}

static int change_fd_flags(int fd, int flags_to_clear, int flags_to_set) {
    int n;
    int orig_flags = fcntl(fd, F_GETFL, 0);

    if (orig_flags == -1) {
        fprintf(stderr, "fcntl(F_GETFL) failed: %s\n", strerror(errno));
        return -1;
    } else {
        int flags = (orig_flags & ~flags_to_clear) | flags_to_set;
        n = fcntl(fd, F_SETFL, flags);
        if (n == -1) {
            fprintf(stderr, "fcntl(F_SETFL) failed: %s\n", strerror(errno));
            return -1;
        }
    }
    return orig_flags;
}

/* Create a connection by setting the given file descriptor to non-blocking.
 * If the function returns successfully, the file descriptor will be blocking
 * again.
 */
static int connect_nonblock(int fd, const struct sockaddr *addr,
                            socklen_t addrlen, int allowed_errno,
                            const char *socktype)
{
    int n, sockerr;
    socklen_t optlen = sizeof(sockerr);
#if !defined(__CYGWIN__)
    int orig_flags = change_fd_flags(fd, 0, O_NONBLOCK);
#else
    int orig_flags = change_fd_flags(fd, 0, 0);
#endif

    n = connect(fd, addr, addrlen);
    /* n < 0: it must fail with EAGAIN (Unix socket) and then we have to poll
     *        and get SO_ERROR
     * n = 0: connection is established
     */
    if (n < 0 && errno != allowed_errno) {
        fprintf(stderr, "Connect failed: %s\n", strerror(errno));
        return -1;
    } else if (n < 0) {
        struct pollfd pollfd = {
            .fd = fd,
            .events = POLLOUT,
        };

        n = poll(&pollfd, 1, DEFAULT_POLL_TIMEOUT);
        /* Unix socket may return POLLHUP on error */
        if (n != 1 || (pollfd.revents & ~POLLOUT) != 0) {
            fprintf(stderr, "Could not connect using %s socket.\n", socktype);
            return -1;
        }

        n = getsockopt(fd, SOL_SOCKET, SO_ERROR, &sockerr, &optlen);
        if (n < 0) {
            fprintf(stderr, "getsockopt(SO_ERROR) failed: %s\n",
                    strerror(errno));
            return -1;
        }
        if (sockerr != 0) {
            fprintf(stderr, "Could not connect using %s socket.\n", socktype);
            return -1;
        }
    }
    return change_fd_flags(fd, ~0, orig_flags);
}

static int open_connection(const char *devname, char *tcp_hostname,
                           unsigned short tcp_port, const char *unix_path)
{
    int fd = -1;

    if (devname) {
        fd = open(devname, O_RDWR);
        if (fd < 0) {
            fprintf(stderr, "Unable to open device '%s'.\n", devname);
        }
    } else if (tcp_hostname) {
        struct addrinfo hints = {
            .ai_family = AF_UNSPEC,
            .ai_socktype = SOCK_STREAM,
        };
        struct addrinfo *ais = NULL, *ai;
        char portstr[10];

        snprintf(portstr, sizeof(portstr), "%u", tcp_port);

        int err = getaddrinfo(tcp_hostname, portstr, &hints, &ais);
        if (err != 0) {
            fprintf(stderr, "getaddrinfo failed on host '%s': %s\n",
                    tcp_hostname, gai_strerror(err));
            return -1;
        }

        for (ai = ais; ai != NULL; ai = ai->ai_next) {
            fd = socket(ai->ai_family, ai->ai_socktype, 0);
            if (fd < 0)
                continue;

            if (connect(fd,
                        (struct sockaddr *)ai->ai_addr, ai->ai_addrlen) == 0)
                break;
            close(fd);
            fd = -1;
        }
        freeaddrinfo(ais);

        if (fd < 0) {
            fprintf(stderr, "Could not connect to host '%s' on port '%u' "
                    "using TCP socket: %s\n", tcp_hostname, tcp_port,
                    strerror(errno));
        }
    } else if (unix_path) {
        struct sockaddr_un addr;
        size_t unix_path_len = strlen(unix_path) + 1;

        if (unix_path_len > sizeof(addr.sun_path)) {
            fprintf(stderr, "Socket path is too long.\n");
            return -1;
        }

        fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd > 0) {
            addr.sun_family = AF_UNIX;
            strncpy(addr.sun_path, unix_path, unix_path_len);
            if (connect_nonblock(fd, (struct sockaddr*)&addr,
                                 sizeof(addr), EAGAIN, "UnixIO") < 0) {
                close(fd);
                fd = -1;
            }
        }
    }

    return fd;
}

static int parse_tcp_optarg(char *optarg, char **tcp_hostname, int *tcp_port)
{
    char *pos = strrchr(optarg, ':');
    int n;

    *tcp_port = DEFAULT_TCP_PORT;

    if (!pos) {
        /* <server> */
        *tcp_hostname = strdup(optarg);
        if (*tcp_hostname == NULL) {
            fprintf(stderr, "Out of memory.\n");
            return -1;
        }
        return 0;
    } else if (pos == optarg) {
        if (strlen(&pos[1]) != 0) {
            /* :<port>  (not just ':') */
            n = sscanf(&pos[1], "%u", tcp_port);
            if (n != 1) {
                fprintf(stderr, "Invalid port '%s'\n", &pos[1]);
                return -1;
            }
            if (*tcp_port >= 65536) {
                fprintf(stderr, "Port '%s' outside valid range.\n",
                    &optarg[1]);
                return -1;
            }
        }

        *tcp_hostname = strdup("127.0.0.1");
        if (*tcp_hostname == NULL) {
            fprintf(stderr, "Out of memory.\n");
            return -1;
        }
    } else {
        /* <server>:<port> */
        n = sscanf(&pos[1], "%u", tcp_port);
        if (n != 1) {
            fprintf(stderr, "Invalid port '%s'\n", &pos[1]);
            return -1;
        }
        if (*tcp_port >= 65536) {
            fprintf(stderr, "Port '%s' outside valid range.\n",
                &optarg[1]);
            return -1;
        }

        *tcp_hostname = strndup(optarg, pos - optarg);
        if (*tcp_hostname == NULL) {
            fprintf(stderr, "Out of memory.\n");
            return -1;
        }
    }
    return 0;
}

static void versioninfo(void)
{
    fprintf(stdout,
"TPM emulator control tool version %d.%d.%d, Copyright (c) 2015 IBM Corp.\n"
,SWTPM_VER_MAJOR, SWTPM_VER_MINOR, SWTPM_VER_MICRO);
}

static void usage(const char *prgname)
{
    versioninfo();
    fprintf(stdout,
"\n"
"Usage: %s command <device path>\n"
"\n"
"The following commands are supported:\n"
"--tpm-device <device> : use the given device; default is /dev/tpm0\n"
"--tcp [<host>]:[<prt>]: connect to TPM on given host and port;\n"
"                        default host is 127.0.0.1, default port is %u\n"
"--unix <path>         : connect to TPM using UnixIO socket\n"
"-c                    : get ptm capabilities\n"
"-i                    : do a hardware TPM_Init; if volatile state is found,\n"
"                        it will resume the TPM with it and delete it\n"
"                        afterwards\n"
"--stop                : stop the TPM without exiting\n"
"-s                    : shutdown the TPM; stops and exists\n"
"-e                    : get the tpmEstablished bit\n"
"-r <loc>              : reset the tpmEstablished bit; use the given locality\n"
"-v                    : store the TPM's volatile data\n"
"-C                    : cancel an ongoing TPM command\n"
"-l <loc>              : set the locality to the given number; valid\n"
"                        localities are 0-4\n"
"-h <data>             : hash the given data; if data is '-' then data are\n"
"                        read from stdin\n"
"--save <type> <file>  : store the TPM state blob of given type in a file;\n"
"                        type may be one of volatile, permanent, or savestate\n"
"--load <type> <file>  : load the TPM state blob of given type from a file;\n"
"                        type may be one of volatile, permanent, or savestate\n"
"-g                    : get configuration flags indicating which keys are in\n"
"                        use\n"
"-b <buffersize>       : set the buffer size of the TPM and get its current\n"
"                        size; get minimum and maximum supported sizes\n"
"--info <flags>        : get TPM implementation specific information;\n"
"                        flags must be an integer value\n"
"--version             : display version and exit\n"
"--help                : display help screen and exit\n"
"\n"
, prgname, DEFAULT_TCP_PORT);
}

int main(int argc, char *argv[])
{
    int fd, n;
    ptm_est est;
    ptm_reset_est reset_est;
    ptm_loc loc;
    ptm_cap cap;
    ptm_res res;
    ptm_init init;
    ptm_getconfig cfg;
    ptm_setbuffersize psbs;
    ptm_getinfo pgi;
    char *tmp;
    size_t buffersize = 0;
    static struct option long_options[] = {
        {"tpm-device", required_argument, NULL, 'D'},
        {"tcp", required_argument, NULL, 'T'},
        {"unix", required_argument, NULL, 'U'},
        {"c", no_argument, NULL, 'c'},
        {"i", no_argument, NULL, 'i'},
        {"stop", no_argument, NULL, 't'},
        {"s", no_argument, NULL, 's'},
        {"e", no_argument, NULL, 'e'},
        {"r", required_argument, NULL, 'r'},
        {"v", no_argument, NULL, 'v'},
        {"C", no_argument, NULL, 'C'},
        {"l", required_argument, NULL, 'l'},
        {"h", required_argument, NULL, 'h'},
        {"g", no_argument, NULL, 'g'},
        {"b", required_argument, NULL, 'b'},
        {"save", required_argument, NULL, 'S'},
        {"load", required_argument, NULL, 'L'},
        {"version", no_argument, NULL, 'V'},
        {"info", required_argument, NULL, 'I'},
        {"help", no_argument, NULL, 'H'},
        {NULL, 0, NULL, 0},
    };
    int opt, option_index = 0;
    const char *command = NULL, *pcommand = NULL;
    const char *blobtype = NULL, *blobfile = NULL, *hashdata = NULL;
    const char *tpm_device = NULL, *unix_path = NULL;
    char *tcp_hostname = NULL;
    unsigned int locality = 0;
    unsigned int tpmbuffersize = 0;
    int tcp_port = -1;
    bool is_chardev;
    unsigned long int info_flags = 0;
    char *endptr = NULL;
    int ret = EXIT_FAILURE;

#if defined __NetBSD__
    while ((opt = getopt_long(argc, argv, "D:T:U:citser:vCl:h:gb:S:L:VI:H",
                              long_options, &option_index)) != -1) {
#else
    while ((opt = getopt_long_only(argc, argv, "", long_options,
                                   &option_index)) != -1) {
#endif
        switch (opt) {
        case 'D':
            tpm_device = optarg;
            break;
        case 'T':
            if (parse_tcp_optarg(optarg, &tcp_hostname, &tcp_port) < 0)
                return EXIT_FAILURE;
            break;
        case 'U':
            unix_path = optarg;
            break;
        case 'c':
        case 'i':
        case 't':
        case 's':
        case 'e':
        case 'v':
        case 'C':
        case 'g':
            command = argv[optind - 1];
            break;
        case 'h':
            command = argv[optind - 2];
            hashdata = argv[optind - 1];
            break;
        case 'r':
        case 'l':
            command = argv[optind - 2];
            if (sscanf(argv[optind - 1], "%u", &locality) != 1) {
                fprintf(stderr, "Could not get locality number from %s.\n",
                        argv[optind - 1]);
                goto exit;
            }
            if (locality > 4) {
                fprintf(stderr, "Locality outside valid range of [0..4].\n");
                goto exit;
            }
            break;
        case 'S':
            if (optind == argc ||
                !strncmp(argv[optind], "-", 1) ||
                !strncmp(argv[optind], "--", 2)) {
                fprintf(stderr, "Missing filename argument for --save option\n");
                goto exit;
            }
            command = argv[optind - 2];
            blobtype = argv[optind - 1];
            blobfile = argv[optind];
            optind++;
            break;
        case 'L':
            if (optind == argc ||
                !strncmp(argv[optind], "-", 1) ||
                !strncmp(argv[optind], "--", 2)) {
                fprintf(stderr, "Missing filename argument for --load option\n");
                goto exit;
            }
            command = argv[optind - 2];
            blobtype = argv[optind - 1];
            blobfile = argv[optind];
            optind++;
            break;
        case 'b':
            command = argv[optind - 2];
            if (sscanf(argv[optind - 1], "%u", &tpmbuffersize) != 1) {
                fprintf(stderr, "Could not get buffersize from %s.\n",
                        argv[optind - 1]);
                goto exit;
            }
            break;
        case 'I':
            command = argv[optind - 2];
            errno = 0;
            info_flags = strtoul(argv[optind - 1], &endptr, 0);
            if (errno || endptr[0] != '\0') {
                fprintf(stderr, "Cannot parse info flags.\n");
                goto exit;
            }
            break;
        case 'V':
            versioninfo();
            ret = EXIT_SUCCESS;
            goto exit;
        case 'H':
            usage(argv[0]);
            ret = EXIT_SUCCESS;
            goto exit;
        }
        if (!pcommand) {
            pcommand = command;
        } else {
            if (command != pcommand) {
                fprintf(stderr, "Only one command may be given.\n");
                goto exit;
            }
        }
    }

    if (!command) {
        fprintf(stderr, "No valid command.\n");
        goto exit;
    }

    if (!tpm_device && !tcp_hostname && !unix_path) {
        if (optind == argc) {
            fprintf(stderr, "Error: Missing device name.\n");
            goto exit;
        }

        tpm_device = argv[optind];
    }

    is_chardev = (tpm_device != NULL);
    if (is_chardev) {
        tmp = getenv("SWTPM_IOCTL_BUFFERSIZE");
        if (tmp) {
            if (sscanf(tmp, "%zu", &buffersize) != 1 || buffersize < 1)
                buffersize = 1;
        }
    } else {
        if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
            fprintf(stderr, "Could not install signal handler for SIGPIPE.");
            goto exit;
        }
    }

    fd = open_connection(tpm_device, tcp_hostname, tcp_port, unix_path);
    if (fd < 0) {
        goto exit;
    }

    if (!strcmp(command, "-c")) {
        n = ctrlcmd(fd, PTM_GET_CAPABILITY, &cap, 0, sizeof(cap));
        if (n < 0) {
            fprintf(stderr,
                    "Could not execute PTM_GET_CAPABILITY: "
                    "%s\n", strerror(errno));
            goto exit;
        }
        /* no tpm_result here */
        printf("ptm capability is 0x%" PRIx64 "\n",
               (uint64_t)devtoh64(is_chardev, cap));

    } else if (!strcmp(command, "-i")) {
        init.u.req.init_flags = htodev32(is_chardev,
                                         PTM_INIT_FLAG_DELETE_VOLATILE);
        n = ctrlcmd(fd, PTM_INIT, &init, sizeof(init.u.req),
                    sizeof(init.u.resp));
        if (n < 0) {
            fprintf(stderr,
                    "Could not execute PTM_INIT: "
                    "%s\n", strerror(errno));
            goto exit;
        }
        res = devtoh32(is_chardev, init.u.resp.tpm_result);
        if (res != 0) {
            fprintf(stderr,
                    "TPM result from PTM_INIT: 0x%x\n", res);
            goto exit;
        }

    } else if (!strcmp(command, "-e")) {
        n = ctrlcmd(fd, PTM_GET_TPMESTABLISHED, &est, 0, sizeof(est.u.resp));
        if (n < 0) {
            fprintf(stderr,
                    "Could not execute PTM_GET_ESTABLISHED: "
                    "%s\n", strerror(errno));
            goto exit;
        }
        res = devtoh32(is_chardev, est.u.resp.tpm_result);
        if (res != 0) {
            fprintf(stderr,
                    "TPM result from PTM_GET_TPMESTABLISHED: 0x%x\n", res);
            goto exit;
        }
        printf("tpmEstablished is %d\n", est.u.resp.bit);

    } else if (!strcmp(command, "-r")) {
        memset(&reset_est, 0, sizeof(reset_est));
        reset_est.u.req.loc = locality;
        n = ctrlcmd(fd, PTM_RESET_TPMESTABLISHED,
                    &reset_est, sizeof(reset_est.u.req),
                    sizeof(reset_est.u.resp));
        if (n < 0) {
            fprintf(stderr,
                    "Could not execute PTM_RESET_ESTABLISHED: "
                    "%s\n", strerror(errno));
            goto exit;
        }
        res = devtoh32(is_chardev, reset_est.u.resp.tpm_result);
        if (res != 0) {
            fprintf(stderr,
                    "TPM result from PTM_RESET_TPMESTABLISHED: 0x%x\n", res);
            goto exit;
        }

    } else if (!strcmp(command, "-s")) {
        n = ctrlcmd(fd, PTM_SHUTDOWN, &res, 0, sizeof(res));
        if (n < 0) {
            fprintf(stderr,
                    "Could not execute PTM_SHUTDOWN: "
                    "%s\n", strerror(errno));
            goto exit;
        }
        if (devtoh32(is_chardev, res) != 0) {
            fprintf(stderr,
                    "TPM result from PTM_SHUTDOWN: 0x%x\n",
                    devtoh32(is_chardev, res));
            goto exit;
        }

    } else if (!strcmp(command, "--stop")) {
        n = ctrlcmd(fd, PTM_STOP, &res, 0, sizeof(res));
        if (n < 0) {
            fprintf(stderr,
                    "Could not execute PTM_STOP: "
                    "%s\n", strerror(errno));
            goto exit;
        }
        if (devtoh32(is_chardev, res) != 0) {
            fprintf(stderr,
                    "TPM result from PTM_STOP: 0x%x\n",
                    devtoh32(is_chardev, res));
            goto exit;
        }

    } else if (!strcmp(command, "-l")) {
        loc.u.req.loc = locality;
        n = ctrlcmd(fd, PTM_SET_LOCALITY, &loc, sizeof(loc.u.req),
                    sizeof(loc.u.resp));
        if (n < 0) {
            fprintf(stderr,
                    "Could not execute PTM_SET_LOCALITY: "
                    "%s\n", strerror(errno));
            goto exit;
        }
        res = devtoh32(is_chardev, loc.u.resp.tpm_result);
        if (res != 0) {
            fprintf(stderr,
                    "TPM result from PTM_SET_LOCALITY: 0x%x\n", res);
            goto exit;
        }

    } else if (!strcmp(command, "-h")) {
        if (do_hash_start_data_end(fd, is_chardev, hashdata)) {
            goto exit;
        }

    } else if (!strcmp(command, "-C")) {
        n = ctrlcmd(fd, PTM_CANCEL_TPM_CMD, &res, 0, sizeof(res));
        if (n < 0) {
            fprintf(stderr,
                    "Could not execute PTM_CANCEL_TPM_CMD: "
                    "%s\n", strerror(errno));
            goto exit;
        }
        if (devtoh32(is_chardev, res) != 0) {
            fprintf(stderr,
                    "TPM result from PTM_CANCEL_TPM_CMD: 0x%x\n",
                    devtoh32(is_chardev, res));
            goto exit;
        }

    } else if (!strcmp(command, "-v")) {
        n = ctrlcmd(fd, PTM_STORE_VOLATILE, &res, 0, sizeof(res));
        if (n < 0) {
            fprintf(stderr,
                    "Could not execute PTM_STORE_VOLATILE: "
                    "%s\n", strerror(errno));
            goto exit;
        }
        if (devtoh32(is_chardev, res) != 0) {
            fprintf(stderr,
                    "TPM result from PTM_STORE_VOLATILE: 0x%x\n",
                    devtoh32(is_chardev, res));
            goto exit;
        }

    } else if (!strcmp(command, "--save")) {
        if (do_save_state_blob(fd, is_chardev, blobtype, blobfile, buffersize))
            goto exit;

    } else if (!strcmp(command, "--load")) {
        if (do_load_state_blob(fd, is_chardev, blobtype, blobfile, buffersize))
            goto exit;

    } else if (!strcmp(command, "-g")) {
        n = ctrlcmd(fd, PTM_GET_CONFIG, &cfg, 0, sizeof(cfg));
        if (n < 0) {
            fprintf(stderr,
                    "Could not execute PTM_GET_CONFIG: "
                    "%s\n", strerror(errno));
            goto exit;
        }
        res = devtoh32(is_chardev, cfg.u.resp.tpm_result);
        if (res != 0) {
            fprintf(stderr,
                    "TPM result from PTM_GET_CONFIG: 0x%x\n", res);
            goto exit;
        }
        printf("ptm configuration flags: 0x%x\n",
               devtoh32(is_chardev, cfg.u.resp.flags));
    } else if (!strcmp(command, "-b")) {
        memset(&psbs, 0, sizeof(psbs));
        psbs.u.req.buffersize = htodev32(is_chardev, tpmbuffersize);
        n = ctrlcmd(fd, PTM_SET_BUFFERSIZE, &psbs, sizeof(psbs.u.req),
                    sizeof(psbs.u.resp));
        if (n < 0) {
            fprintf(stderr,
                    "Could not execute PTM_SET_BUFFERSIZE: "
                    "%s\n", strerror(errno));
            goto exit;
        }
        res = devtoh32(is_chardev, psbs.u.resp.tpm_result);
        if (res != 0) {
            fprintf(stderr,
                    "TPM result from PTM_SET_BUFFERSIZE: 0x%x\n", res);
            goto exit;
        }
        printf("TPM buffersize: %u\n"
               "minimum size  : %u\n"
               "maximum size  : %u\n",
               devtoh32(is_chardev, psbs.u.resp.buffersize),
               devtoh32(is_chardev, psbs.u.resp.minsize),
               devtoh32(is_chardev, psbs.u.resp.maxsize));
    } else if (!strcmp(command, "--info")) {
        memset(&pgi, 0, sizeof(pgi));
        pgi.u.req.flags = htodev64(is_chardev, info_flags);
        pgi.u.req.offset = htodev64(is_chardev, 0);
        n = ctrlcmd(fd, PTM_GET_INFO, &pgi,
                    sizeof(pgi.u.req), sizeof(pgi.u.resp));
        if (n < 0) {
            fprintf(stderr,
                    "Could not execute PTM_GET_INFO: %s\n",
                    strerror(errno));
            goto exit;
        }
        res = devtoh32(is_chardev, pgi.u.resp.tpm_result);
        if (res != 0) {
            fprintf(stderr,
                    "TPM result from PTM_GET_INFO: 0x%x\n", res);
            goto exit;
        }
        printf("%s\n", pgi.u.resp.buffer);
    } else {
        usage(argv[0]);
        goto exit;
    }

    ret = EXIT_SUCCESS;

exit:
    free(tcp_hostname);
    return ret;
}
