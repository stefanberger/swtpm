/********************************************************************************/
/*                                                                              */
/*                              TPM Host IO                                     */
/*                           Written by Ken Goldman                             */
/*                     IBM Thomas J. Watson Research Center                     */
/*            $Id: tpm_io.c 4564 2011-04-13 19:33:38Z stefanb $                */
/*                                                                              */
/* (c) Copyright IBM Corporation 2006, 2010.					*/
/*										*/
/* All rights reserved.								*/
/* 										*/
/* Redistribution and use in source and binary forms, with or without		*/
/* modification, are permitted provided that the following conditions are	*/
/* met:										*/
/* 										*/
/* Redistributions of source code must retain the above copyright notice,	*/
/* this list of conditions and the following disclaimer.			*/
/* 										*/
/* Redistributions in binary form must reproduce the above copyright		*/
/* notice, this list of conditions and the following disclaimer in the		*/
/* documentation and/or other materials provided with the distribution.		*/
/* 										*/
/* Neither the names of the IBM Corporation nor the names of its		*/
/* contributors may be used to endorse or promote products derived from		*/
/* this software without specific prior written permission.			*/
/* 										*/
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		*/
/* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		*/
/* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR	*/
/* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		*/
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	*/
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		*/
/* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,	*/
/* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY	*/
/* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		*/
/* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE	*/
/* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		*/
/********************************************************************************/

/* These are platform specific.  This version uses a TCP/IP socket interface.

   Environment variables are:

           TPM_PORT - the client and server socket port number
*/

#include <config.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <limits.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <sys/time.h>

#include <libtpms/tpm_error.h>
#include <libtpms/tpm_error.h>
#include <libtpms/tpm_types.h>

#include "swtpm_debug.h"
#include "swtpm_io.h"


/*
  local prototypes
*/

static TPM_RESULT SWTPM_IO_ReadBytes(TPM_CONNECTION_FD *connection_fd,
                                     unsigned char *buffer,
                                     size_t nbytes);

#ifndef TPM_UNIX_DOMAIN_SOCKET
static TPM_RESULT SWTPM_IO_ServerSocket_Open(int *sock_fd,
                                           short port,
                                           uint32_t in_addr);
#else        /* TPM_UNIX_DOMAIN_SOCKET */
static TPM_RESULT SWTPM_IO_ServerSocket_Open(int *sock_fd);
#endif         /* TPM_UNIX_DOMAIN_SOCKET */


/*
  global variables
*/

static const char *port_str;    /* TPM command/response server port
                                   port number for TCP/IP
                                   domain file name for Unix domain socket */

/* platform dependent */

static int      sock_fd = -1;


/* SWTPM_IO_Read() reads a TPM command packet from the host

   Puts the result in 'buffer' up to 'bufferSize' bytes.

   On success, the number of bytes in the buffer is equal to 'bufferLength' bytes

   This function is intended to be platform independent.
*/

TPM_RESULT SWTPM_IO_Read(TPM_CONNECTION_FD *connection_fd,   /* read/write file descriptor */
                         unsigned char *buffer,   /* output: command stream */
                         uint32_t *bufferLength,  /* output: command stream length */
                         size_t bufferSize,       /* input: max size of output buffer */
                         void *mainLoopArgs,
                         bool readall)
{
    TPM_RESULT          rc = 0;
    uint32_t            headerSize;     /* minimum required bytes in command through paramSize */
    uint32_t            paramSize;      /* from command stream */
    ssize_t             n;

    /* check that the buffer can at least fit the command through the paramSize */
    if (rc == 0) {
        headerSize = sizeof(TPM_TAG) + sizeof(uint32_t);
        if (bufferSize < headerSize) {
            TPM_DEBUG("SWTPM_IO_Read: Error, buffer size %lu less than minimum %u\n",
                   (unsigned long)bufferSize, headerSize);
            rc = TPM_SIZE;
        }
    }
    if (rc == 0 && readall) {
        n = read(connection_fd->fd, buffer, bufferSize);
        if (n > 0)
            *bufferLength = n;
        else
            rc = TPM_IOERROR;
        return rc;
    }
    /* read the command through the paramSize from the socket stream */
    if (rc == 0) {
        mainLoopArgs = mainLoopArgs;            /* not used */
        rc = SWTPM_IO_ReadBytes(connection_fd, buffer, headerSize);
    }
    if (rc == 0) {
        TPM_PrintAll("  SWTPM_IO_Read: through paramSize", buffer, headerSize);
        /* extract the paramSize value, last field in header */
        paramSize = LOAD32(buffer, headerSize - sizeof(uint32_t));
        *bufferLength = headerSize + paramSize - (sizeof(TPM_TAG) + sizeof(uint32_t));
        if (bufferSize < *bufferLength) {
            TPM_DEBUG("SWTPM_IO_Read: Error, buffer size %lu is less than required %u\n",
                   (unsigned long)bufferSize, *bufferLength);
            rc = TPM_SIZE;
        }
    }
    /* read the rest of the command (already read tag and paramSize) */
    if (rc == 0) {
        rc = SWTPM_IO_ReadBytes(connection_fd,
                                buffer + headerSize,
                                paramSize - (sizeof(TPM_TAG) + sizeof(uint32_t)));
    }
    if (rc == 0) {
        TPM_PrintAll(" SWTPM_IO_Read:", buffer, *bufferLength);
    }
    return rc;
}


/* SWTPM_IO_SetSocketFD tells the IO layer that it's not necessary to open
   a server socket.
 */
TPM_RESULT SWTPM_IO_SetSocketFD(int fd)
{
    sock_fd = fd;
    return 0;
}

int SWTPM_IO_GetSocketFD(void)
{
    return sock_fd;
}


/* SWTPM_IO_Init initializes the TPM to host interface.

   This is the Unix platform dependent socket version.
*/

TPM_RESULT SWTPM_IO_Init(void)
{
    TPM_RESULT          rc = 0;
    int                 irc;
    unsigned short      port;


    TPM_DEBUG(" SWTPM_IO_Init:\n");

    if (sock_fd >= 0)
        return 0;

    /* get the socket port number */
    if (rc == 0) {
        port_str = getenv("TPM_PORT");
        if (port_str == NULL) {
            fprintf(stderr,
                    "SWTPM_IO_Init: Error, TPM_PORT environment variable not "
                    "set\n");
            rc = TPM_IOERROR;
        }
    }

    if (rc == 0) {
        irc = sscanf(port_str, "%hu", &port);
        if (irc != 1) {
            fprintf(stderr,
                    "SWTPM_IO_Init: Error, TPM_PORT environment variable "
                    "invalid\n");
            rc = TPM_IOERROR;
        }
    }
    /* create a socket */
    if (rc == 0) {
        rc = SWTPM_IO_ServerSocket_Open(&sock_fd,
                                        port,
                                        INADDR_ANY);
        if (rc != 0) {
            fprintf(stderr, "SWTPM_IO_Init: Warning, could not open TCP/IP "
                    "server socket.\n");
        }
    }

    if (rc == 0) {
        TPM_DEBUG("SWTPM_IO_Init: Waiting for connections on %s\n", port_str);
    }
    return rc;
}


/* Open a TCP Server socket given the provided parameters. Set it into
   listening mode so connections can be accepted on it.

   This is the Unix platform dependent socket version.
*/

static TPM_RESULT SWTPM_IO_ServerSocket_Open(int *sock_fd,
                                             short port,
                                             uint32_t in_addr)
{
    TPM_RESULT          rc = 0;
    int                 irc;
    int                 domain = AF_INET;
    struct sockaddr_in  serv_addr;
    int                 opt;

    /* create a socket */
    if (rc == 0) {
        TPM_DEBUG(" SWTPM_IO_ServerSocket_Open: Port %s\n", port_str);
        *sock_fd = socket(domain, SOCK_STREAM, 0);      /* socket */
        if (*sock_fd == -1) {
            TPM_DEBUG("SWTPM_IO_ServerSocket_Open: Error, server socket() %d %s\n",
                   errno, strerror(errno));
            rc = TPM_IOERROR;
        }
    }

    if (rc == 0) {
        memset((char *)&serv_addr, 0, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;                 /* Internet socket */
        serv_addr.sin_port = htons(port);               /* host to network byte order for short */
        serv_addr.sin_addr.s_addr = htonl(in_addr);     /* host to network byte order for long */
        opt = 1;
        /* Set SO_REUSEADDR before calling bind() for servers that bind to a fixed port number. */
        irc = setsockopt(*sock_fd, SOL_SOCKET, SO_REUSEADDR, &opt,
                         sizeof(opt));
        if (irc != 0) {
            fprintf(stderr,
                    "SWTPM_IO_ServerSocket_Open: Error, server setsockopt() "
                    "%d %s\n", errno, strerror(errno));
            rc = TPM_IOERROR;
        }
    }

    /* bind the (local) server port name to the socket */
    if (rc == 0) {
        irc = bind(*sock_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
        if (irc != 0) {
            close(*sock_fd);
            *sock_fd = -1;
            fprintf(stderr,
                    "SWTPM_IO_ServerSocket_Open: Error, server bind() %d "
                    "%s\n", errno, strerror(errno));
            rc = TPM_IOERROR;
        }
    }
    /* listen for a connection to the socket */
    if (rc == 0) {
        irc = listen(*sock_fd, SOMAXCONN);
        if (irc != 0) {
            close(*sock_fd);
            *sock_fd = -1;
            fprintf(stderr,
                    "SWTPM_IO_ServerSocket_Open: Error, server listen() %d "
                    "%s\n", errno, strerror(errno));
            rc = TPM_IOERROR;
        }
    }
    return rc;
}

/* SWTPM_IO_Connect() establishes a connection between the TPM server and the host client

   This is the Unix platform dependent socket version.
*/

TPM_RESULT SWTPM_IO_Connect(TPM_CONNECTION_FD *connection_fd,     /* read/write file descriptor */
                            int notify_fd,
                            void *mainLoopArgs)
{
    TPM_RESULT          rc = 0;
    socklen_t           cli_len;
    struct sockaddr_in  cli_addr;       /* Internet version of sockaddr */
    int                 max_fd = -1;
    fd_set              readfds;
    int                 n;

    mainLoopArgs = mainLoopArgs;        /* not used */

    while (rc == 0) {
        FD_ZERO(&readfds);

        FD_SET(sock_fd, &readfds);
        max_fd = sock_fd;

        FD_SET(notify_fd, &readfds);
        max_fd = (notify_fd > max_fd) ? notify_fd : max_fd;

        TPM_DEBUG("SWTPM_IO_Connect: Waiting for connections on port %s\n", port_str);

        n = select(max_fd + 1, &readfds, NULL, NULL, NULL);

        if (n > 0 && FD_ISSET(notify_fd, &readfds)) {
            rc = TPM_IOERROR;
            break;
        }

        if (n > 0 && FD_ISSET(sock_fd, &readfds)) {
            cli_len = sizeof(cli_addr);
            /* block until connection from client */
            TPM_DEBUG("\n SWTPM_IO_Connect: Accepting connection from port %s ...\n", port_str);
            connection_fd->fd = accept(sock_fd, (struct sockaddr *)&cli_addr, &cli_len);
            if (connection_fd->fd < 0) {
                fprintf(stderr,
                        "SWTPM_IO_Connect: Error, accept() %d %s\n",
                        errno, strerror(errno));
                rc = TPM_IOERROR;
            }
            break;
        }
    }

    return rc;
}

/* SWTPM_IO_ReadBytes() reads nbytes from connection_fd and puts them in buffer.

   The buffer has already been checked for sufficient size.

   This is the Unix platform dependent socket version.
*/

static TPM_RESULT SWTPM_IO_ReadBytes(TPM_CONNECTION_FD *connection_fd,    /* read/write file descriptor */
                                     unsigned char *buffer,
                                     size_t nbytes)
{
    TPM_RESULT rc = 0;
    ssize_t nread = 0;
    size_t nleft = nbytes;

    TPM_DEBUG("  SWTPM_IO_ReadBytes: Reading %lu bytes\n",
              (unsigned long)nbytes);
    /* read() is unspecified with nbytes too large */
    if (rc == 0) {
        if (nleft > SSIZE_MAX) {
            rc = TPM_BAD_PARAMETER;
        }
    }
    while ((rc == 0) && (nleft > 0)) {
        nread = read(connection_fd->fd, buffer, nleft);
        if (nread > 0) {
            nleft -= nread;
            buffer += nread;
        }
        else if (nread < 0) {       /* error */
            TPM_DEBUG("SWTPM_IO_ReadBytes: Error, read() error %d %s\n",
                   errno, strerror(errno));
            rc = TPM_IOERROR;
        }
        else if (nread == 0) {          /* EOF */
            TPM_DEBUG("SWTPM_IO_ReadBytes: Error, read EOF, read %lu bytes\n",
                   (unsigned long)(nbytes - nleft));
            rc = TPM_IOERROR;
        }
    }
    return rc;
}

/* SWTPM_IO_Write() writes 'buffer_length' bytes to the host.

   This is the Unix platform dependent socket version.
*/

TPM_RESULT SWTPM_IO_Write(TPM_CONNECTION_FD *connection_fd,       /* read/write file descriptor */
                          const unsigned char *buffer,
                          size_t buffer_length)
{
    TPM_RESULT  rc = 0;
    ssize_t     nwritten = 0;

    if (rc == 0) {
        TPM_PrintAll(" SWTPM_IO_Write:", buffer, buffer_length);
    }
    /* write() is unspecified with buffer_length too large */
    if (rc == 0) {
        if (buffer_length > SSIZE_MAX) {
            rc = TPM_BAD_PARAMETER;
        }
    }
    /* test that connection is open to write */
    if (rc == 0) {
        if (connection_fd->fd < 0) {
            fprintf(stderr,
                    "SWTPM_IO_Write: Error, connection not open, fd %d\n",
                   connection_fd->fd);
            rc = TPM_IOERROR;
        }
    }
    while ((rc == 0) && (buffer_length > 0)) {
        nwritten = write(connection_fd->fd, buffer, buffer_length);
        if (nwritten >= 0) {
            buffer_length -= nwritten;
            buffer += nwritten;
        }
        else {
            fprintf(stderr, "SWTPM_IO_Write: Error, write() %d %s\n",
                    errno, strerror(errno));
            rc = TPM_IOERROR;
        }
    }
    return rc;
}

/* SWTPM_IO_Disconnect() breaks the connection between the TPM server and the host client

   This is the Unix platform dependent socket version.
*/

TPM_RESULT SWTPM_IO_Disconnect(TPM_CONNECTION_FD *connection_fd)
{
    TPM_RESULT  rc = 0;

    /* close the connection to the client */
    if (connection_fd->fd >= 0) {
        close(connection_fd->fd);
        connection_fd->fd = -1;     /* mark the connection closed */
    }

    return rc;
}

