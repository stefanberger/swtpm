/********************************************************************************/
/*                                                                              */
/*                           TPM Main Program                                   */
/*                 Written by Ken Goldman, Stefan Berger                        */
/*                     IBM Thomas J. Watson Research Center                     */
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

#include <config.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>
#include <getopt.h>
#include <errno.h>
#include <poll.h>
#include <sys/stat.h>

#include <libtpms/tpm_error.h>
#include <libtpms/tpm_library.h>
#include <libtpms/tpm_memory.h>

#include "main.h"
#include "swtpm_debug.h"
#include "swtpm_io.h"
#include "swtpm_nvfile.h"
#include "common.h"
#include "logging.h"


/* local variables */
int notify_fd[2] = {-1, -1};
static TPM_BOOL terminate;
struct mainLoopParams;

/* local function prototypes */
static int mainLoop(struct mainLoopParams *mlp);
static TPM_RESULT install_sighandlers(void);

struct libtpms_callbacks callbacks = {
    .sizeOfStruct            = sizeof(struct libtpms_callbacks),
    .tpm_nvram_init          = SWTPM_NVRAM_Init,
    .tpm_nvram_loaddata      = SWTPM_NVRAM_LoadData,
    .tpm_nvram_storedata     = SWTPM_NVRAM_StoreData,
    .tpm_nvram_deletename    = SWTPM_NVRAM_DeleteName,
    .tpm_io_init             = SWTPM_IO_Init,
};


static inline int getTPMProperty(enum TPMLIB_TPMProperty prop)
{
    int result;
    TPM_RESULT res;

    res = TPMLIB_GetTPMProperty(prop, &result);

    assert(res == TPM_SUCCESS);

    return result;
}


static void usage(FILE *file, const char *prgname, const char *iface)
{
    fprintf(file,
    "Usage: %s %s [options]\n"
    "\n"
    "The following options are supported:\n"
    "\n"
    "-p|--port <port> : use the given port\n"
    "-i|--dir <dir>   : use the given directory\n"
    "-f|--fd <fd>     : use the given socket file descriptor\n"
    "-t|--terminate   : terminate the TPM once a connection has been lost\n"
    "-d|--daemon      : daemonize the TPM\n"
    "--log file=<path>|fd=<filedescriptor>\n"
    "                 :  write the TPM's log into the given file rather than\n"
    "                    to the console; provide '-' for path to avoid logging\n"
    "--key file=<path>[,mode=aes-cbc][,format=hex|binary][,remove=[true|false]]\n"
    "                 : use an AES key for the encryption of the TPM's state\n"
    "                   files; use the given mode for the block encryption;\n"
    "                   the key is to be provided as a hex string or in binary\n"
    "                   format; the keyfile can be automatically removed using\n"
    "                   the remove parameter\n"
    "--key pwdfile=<path>[,mode=aes-cbc][,remove=[true|false]]\n"
    "                 :  provide a passphrase in a file; the AES key will be\n"
    "                    derived from this passphrase\n"
    "-h|--help        : display this help screen and terminate\n"
    "\n",
    prgname, iface);
}


#define MAIN_LOOP_FLAG_TERMINATE  (1 << 0)
#define MAIN_LOOP_FLAG_USE_FD     (1 << 1)

struct mainLoopParams {
    uint32_t flags;
    int fd;
};

int swtpm_main(int argc, char **argv, const char *prgname, const char *iface)
{
    TPM_RESULT rc = 0;
    int daemonize = FALSE;
    int opt, longindex;
    struct stat statbuf;
    struct mainLoopParams mlp = {
        .flags = 0,
    };
    int initialized = FALSE;
    unsigned long val;
    char *end_ptr;
    char buf[20];
    char *keydata = NULL;
    char *logdata = NULL;
#ifdef DEBUG
    time_t              start_time;
#endif
    static struct option longopts[] = {
        {"daemon"    ,       no_argument, 0, 'd'},
        {"help"      ,       no_argument, 0, 'h'},
        {"port"      , required_argument, 0, 'p'},
        {"dir"       , required_argument, 0, 'i'},
        {"fd"        , required_argument, 0, 'f'},
        {"terminate" ,       no_argument, 0, 't'},
        {"log"       , required_argument, 0, 'l'},
        {"key"       , required_argument, 0, 'k'},
        {NULL        , 0                , 0, 0  },
    };

    while (TRUE) {
        opt = getopt_long(argc, argv, "dhp:i:f:tk:", longopts, &longindex);

        if (opt == -1)
            break;

        switch (opt) {
        case 'd':
            daemonize = TRUE;
            break;

        case 'p':
            errno = 0;
            val = strtoul(optarg, &end_ptr, 0);
            if (val != (unsigned int)val || errno || end_ptr[0] != '\0') {
                fprintf(stderr, "Cannot parse socket port number '%s'.\n",
                        optarg);
                exit(1);
            }
            if (val >= 0x10000) {
                fprintf(stderr, "Port is outside valid range.\n");
                exit(1);
            }
            snprintf(buf, sizeof(buf), "%lu", val);
            if (setenv("TPM_PORT", buf, 1) != 0) {
                fprintf(stderr, "Could not set port: %s\n", strerror(errno));
                exit(1);
            }
            break;

        case 'i':
            if (setenv("TPM_PATH", optarg, 1) != 0) {
                fprintf(stderr, "Could not set path: %s\n", strerror(errno));
                exit(1);
            }
            break;

        case 'f':
            val = strtoul(optarg, &end_ptr, 10);
            if (val != (unsigned int)val || errno || end_ptr[0] != '\0') {
                fprintf(stderr, "Cannot parse socket file descriptor.\n");
                exit(1);
            }
            mlp.fd = val;
            if (fstat(mlp.fd, &statbuf) != 0) {
                fprintf(stderr, "Cannot stat file descriptor: %s\n", 
                        strerror(errno));
                exit(1);
            }
            if (!S_ISSOCK(statbuf.st_mode)) {
                fprintf(stderr,
                        "Given file descriptor is not for a socket.\n");
                exit(1);
            }
            mlp.flags |= MAIN_LOOP_FLAG_TERMINATE | MAIN_LOOP_FLAG_USE_FD;
            SWTPM_IO_SetSocketFD(mlp.fd);

            break;

        case 't':
            mlp.flags |= MAIN_LOOP_FLAG_TERMINATE;
            break;

        case 'k':
            keydata = optarg;
            break;

        case 'l':
            logdata = optarg;
            break;

        case 'h':
            usage(stdout, prgname, iface);
            exit(EXIT_SUCCESS);

        default:
            usage(stderr, prgname, iface);
            exit(EXIT_FAILURE);
        }
    }

    if (handle_log_options(logdata) < 0 ||
        handle_key_options(keydata) < 0)
        return EXIT_FAILURE;

    if (daemonize) {
       if (0 != daemon(0, 0)) {
           logprintf(STDERR_FILENO, "Error: Could not daemonize.\n");
           return EXIT_FAILURE;
       }
    }

    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe */

#ifdef DEBUG
    /* initialization */
    start_time = time(NULL);
#endif

    TPM_DEBUG("main: Initializing TPM at %s", ctime(&start_time));

    TPM_DEBUG("Main: Compiled for %u auth, %u transport, and %u DAA session slots\n",
           getTPMProperty(TPMPROP_TPM_MIN_AUTH_SESSIONS),
           getTPMProperty(TPMPROP_TPM_MIN_TRANS_SESSIONS),
           getTPMProperty(TPMPROP_TPM_MIN_DAA_SESSIONS));
    TPM_DEBUG("Main: Compiled for %u key slots, %u owner evict slots\n",
           getTPMProperty(TPMPROP_TPM_KEY_HANDLES),
           getTPMProperty(TPMPROP_TPM_OWNER_EVICT_KEY_HANDLES));
    TPM_DEBUG("Main: Compiled for %u counters, %u saved sessions\n",
           getTPMProperty(TPMPROP_TPM_MIN_COUNTERS),
           getTPMProperty(TPMPROP_TPM_MIN_SESSION_LIST));
    TPM_DEBUG("Main: Compiled for %u family, %u delegate table entries\n",
           getTPMProperty(TPMPROP_TPM_NUM_FAMILY_TABLE_ENTRY_MIN),
           getTPMProperty(TPMPROP_TPM_NUM_DELEGATE_TABLE_ENTRY_MIN));
    TPM_DEBUG("Main: Compiled for %u total NV, %u savestate, %u volatile space\n",
           getTPMProperty(TPMPROP_TPM_MAX_NV_SPACE),
           getTPMProperty(TPMPROP_TPM_MAX_SAVESTATE_SPACE),
           getTPMProperty(TPMPROP_TPM_MAX_VOLATILESTATE_SPACE));
#if 0
    TPM_DEBUG("Main: Compiled for %u NV defined space\n",
           getTPMProperty(TPMPROP_TPM_MAX_NV_DEFINED_SIZE));
#endif

    if (rc == 0) {
        rc = TPMLIB_RegisterCallbacks(&callbacks);
    }
    /* TPM_Init transitions the TPM from a power-off state to one where the TPM begins an
       initialization process.  TPM_Init could be the result of power being applied to the platform
       or a hard reset. */
    if (rc == 0) {
        rc = TPMLIB_MainInit();
    }
    if (rc == 0) {
        initialized = TRUE;
    }
    if (rc == 0) {
        rc = install_sighandlers();
    }
    if (rc == 0) {
        rc = mainLoop(&mlp);
    }
    if (initialized) {
        TPMLIB_Terminate();
    }

    close(notify_fd[0]);
    notify_fd[0] = -1;
    close(notify_fd[1]);
    notify_fd[1] = -1;

    /* Fatal initialization errors cause the program to abort */
    if (rc == 0) {
        return EXIT_SUCCESS;
    }
    else {
        TPM_DEBUG("main: TPM initialization failure %08x, exiting\n", rc);
        return EXIT_FAILURE;
    }
}

/* mainLoop() is the main server loop.

   It reads a TPM request, processes the ordinal, and writes the response
*/

static int mainLoop(struct mainLoopParams *mlp)
{
    TPM_RESULT          rc = 0;
    TPM_CONNECTION_FD   connection_fd;             /* file descriptor for read/write */
    unsigned char       *command = NULL;           /* command buffer */
    uint32_t            command_length;            /* actual length of command bytes */
    uint32_t            max_command_length;        /* command buffer size */
    /* The response buffer is reused for each command. Thus it can grow but never shrink */
    unsigned char       *rbuffer = NULL;           /* actual response bytes */
    uint32_t            rlength = 0;               /* bytes in response buffer */
    uint32_t            rTotal = 0;                /* total allocated bytes */

    TPM_DEBUG("mainLoop:\n");

    max_command_length = getTPMProperty(TPMPROP_TPM_BUFFER_MAX);

    rc = TPM_Malloc(&command, max_command_length);
    if (rc != TPM_SUCCESS) {
        fprintf(stderr, "Could not allocate %u bytes for buffer.\n",
                max_command_length);
        return rc;
    }

    connection_fd.fd = -1;

    while (!terminate) {
        /* connect to the client */
        if (rc == 0) {
            if (!(mlp->flags & MAIN_LOOP_FLAG_USE_FD)) {
                rc = SWTPM_IO_Connect(&connection_fd,
                                      notify_fd[0],
                                      mlp);
            } else {
                connection_fd.fd = mlp->fd;
            }
        }
        /* was connecting successful? */
        while (rc == 0) {
            struct pollfd pollfds = {
                .fd = connection_fd.fd,
                .events = POLLIN | POLLHUP,
                .revents = 0,
            };

            /*
             * all these check (seem to) prevent that we get
             * stuck with a closed connection.
             */
            if (poll(&pollfds, 1, -1) < 0 ||
                (pollfds.revents & POLLHUP) != 0 ||
                (pollfds.revents & POLLIN) == 0 ) {
                SWTPM_IO_Disconnect(&connection_fd);
                break;
            }

            if (!(pollfds.revents & POLLIN))
                continue;

            /* Read the command.  The number of bytes is determined by 'paramSize' in the stream */
            if (rc == 0) {
                rc = SWTPM_IO_Read(&connection_fd, command, &command_length,
                                   max_command_length, mlp);
            }
            if (rc == 0) {
                rlength = 0;                                /* clear the response buffer */
                rc = TPMLIB_Process(&rbuffer,
                                    &rlength,
                                    &rTotal,
                                    command,                /* complete command array */
                                    command_length);        /* actual bytes in command */
            }
            /* write the results */
            if (rc == 0) {
                /* ignore return value since we will close anyway */
                SWTPM_IO_Write(&connection_fd, rbuffer, rlength);
            }
            /*
             * only allow a single command per connection, otherwise
             * we may get stuck in the poll() above.
             */
            break;
        }
        SWTPM_IO_Disconnect(&connection_fd);
        /* clear the response buffer, does not deallocate memory */
        rc = 0; /* A fatal TPM_Process() error should cause the TPM to enter shutdown.  IO errors
                   are outside the TPM, so the TPM does not shut down.  The main loop should
                   continue to function.*/
        if (mlp->flags & MAIN_LOOP_FLAG_TERMINATE)
            break;
    }

    TPM_Free(rbuffer);
    TPM_Free(command);

    return rc;
}


static void sigterm_handler(int sig __attribute__((unused)))
{
    TPM_DEBUG("Terminating...\n");
    if (write(notify_fd[1], "T", 1) < 0) {
        logprintf(STDERR_FILENO, "Error: sigterm notification failed: %s\n",
                  strerror(errno));
    }
    terminate = TRUE;
}

static TPM_RESULT install_sighandlers(void)
{
    if (pipe(notify_fd) < 0) {
        logprintf(STDERR_FILENO, "Error: Could not open pipe.\n");
        goto err_exit;
    }

    if (signal(SIGTERM, sigterm_handler) == SIG_ERR) {
        logprintf(STDERR_FILENO, "Could not install signal handler for SIGTERM.\n");
        goto err_close_pipe;
    }

    return 0;

err_close_pipe:
    close(notify_fd[0]);
    notify_fd[0] = -1;
    close(notify_fd[1]);
    notify_fd[1] = -1;

err_exit:
    return TPM_IOERROR;
}

