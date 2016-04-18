/********************************************************************************/
/*                                                                              */
/*                           TPM Main Program                                   */
/*                 Written by Ken Goldman, Stefan Berger                        */
/*                     IBM Thomas J. Watson Research Center                     */
/*                                                                              */
/* (c) Copyright IBM Corporation 2006, 2010, 2016.				*/
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
#include <getopt.h>
#include <errno.h>
#include <poll.h>
#include <sys/stat.h>
#include <stdbool.h>

#include <libtpms/tpm_error.h>
#include <libtpms/tpm_library.h>
#include <libtpms/tpm_memory.h>

#include "main.h"
#include "swtpm_debug.h"
#include "swtpm_io.h"
#include "swtpm_nvfile.h"
#include "server.h"
#include "common.h"
#include "logging.h"
#include "pidfile.h"
#include "tpmlib.h"
#include "utils.h"
#include "mainloop.h"

/* local variables */
static int notify_fd[2] = {-1, -1};

static struct libtpms_callbacks callbacks = {
    .sizeOfStruct            = sizeof(struct libtpms_callbacks),
    .tpm_nvram_init          = SWTPM_NVRAM_Init,
    .tpm_nvram_loaddata      = SWTPM_NVRAM_LoadData,
    .tpm_nvram_storedata     = SWTPM_NVRAM_StoreData,
    .tpm_nvram_deletename    = SWTPM_NVRAM_DeleteName,
    .tpm_io_init             = SWTPM_IO_Init,
    .tpm_io_getlocality      = mainloop_cb_get_locality,
};

static void sigterm_handler(int sig __attribute__((unused)))
{
    TPM_DEBUG("Terminating...\n");
    if (write(notify_fd[1], "T", 1) < 0) {
        logprintf(STDERR_FILENO, "Error: sigterm notification failed: %s\n",
                  strerror(errno));
    }
    mainloop_terminate = true;
}

static void usage(FILE *file, const char *prgname, const char *iface)
{
    fprintf(file,
    "Usage: %s %s [options]\n"
    "\n"
    "The following options are supported:\n"
    "\n"
    "-p|--port <port> : use the given port\n"
    "-f|--fd <fd>     : use the given socket file descriptor\n"
    "-t|--terminate   : terminate the TPM once a connection has been lost\n"
    "-d|--daemon      : daemonize the TPM\n"
    "--ctrl type=[unixio|tcp][,path=<path>][,port=<port>[,bindaddr=address[,ifname=ifname]]][,fd=<filedescriptor]\n"
    "                 : TPM control channel using either UnixIO or TCP sockets;\n"
    "                   the path is only valid for Unixio channels; the port must\n"
    "                   be given in case the type is TCP; the TCP socket is bound\n"
    "                   to 127.0.0.1 by default and other bind addresses can be\n"
    "                   given with the bindaddr parameter\n"
    "--log file=<path>|fd=<filedescriptor>\n"
    "                 : write the TPM's log into the given file rather than\n"
    "                   to the console; provide '-' for path to avoid logging\n"
    "--key file=<path>[,mode=aes-cbc][,format=hex|binary][,remove=[true|false]]\n"
    "                 : use an AES key for the encryption of the TPM's state\n"
    "                   files; use the given mode for the block encryption;\n"
    "                   the key is to be provided as a hex string or in binary\n"
    "                   format; the keyfile can be automatically removed using\n"
    "                   the remove parameter\n"
    "--key pwdfile=<path>[,mode=aes-cbc][,remove=[true|false]]\n"
    "                 : provide a passphrase in a file; the AES key will be\n"
    "                   derived from this passphrase\n"
    "--pid file=<path>\n"
    "                 : write the process ID into the given file\n"
    "--tpmstate dir=<dir>\n"
    "                 : set the directory where the TPM's state will be written\n"
    "                   into; the TPM_PATH environment variable can be used\n"
    "                   instead\n"
    "--server [type=tcp][,port=port][,fd=fd][,disconnect]\n"
    "                 : Expect TCP connections on the given port;\n"
    "                   if fd is provided, packets will be read from it directly;\n"
    "                   the disconnect parameter closes the connection after\n"
    "                   sending a response back to the client; the TCP socket is\n"
    "                   bound to 127.0.0.1 by default and other bind addresses\n"
    "                   can be given with the bindaddr parameter\n"
    "--server type=unixio[,path=path][,fd=fd]\n"
    "                 : Expect UnixIO connections on the given path; if fd is\n"
    "                   provided, packets wil be read from it directly;\n"
    "-r|--runas <user>: change to the given user\n"
    "-h|--help        : display this help screen and terminate\n"
    "\n",
    prgname, iface);
}

int swtpm_main(int argc, char **argv, const char *prgname, const char *iface)
{
    TPM_RESULT rc = 0;
    int daemonize = FALSE;
    int opt, longindex;
    struct stat statbuf;
    struct mainLoopParams mlp = {
        .flags = 0,
        .fd = -1,
    };
    struct server *server = NULL;
    unsigned long val;
    char *end_ptr;
    char buf[20];
    char *keydata = NULL;
    char *logdata = NULL;
    char *piddata = NULL;
    char *tpmstatedata = NULL;
    char *ctrlchdata = NULL;
    char *serverdata = NULL;
    char *runas = NULL;
#ifdef DEBUG
    time_t              start_time;
#endif
    static struct option longopts[] = {
        {"daemon"    ,       no_argument, 0, 'd'},
        {"help"      ,       no_argument, 0, 'h'},
        {"port"      , required_argument, 0, 'p'},
        {"fd"        , required_argument, 0, 'f'},
        {"server"   , required_argument, 0, 'c'},
        {"runas"     , required_argument, 0, 'r'},
        {"terminate" ,       no_argument, 0, 't'},
        {"log"       , required_argument, 0, 'l'},
        {"key"       , required_argument, 0, 'k'},
        {"pid"       , required_argument, 0, 'P'},
        {"tpmstate"  , required_argument, 0, 's'},
        {"ctrl"      , required_argument, 0, 'C'},
        {NULL        , 0                , 0, 0  },
    };

    while (TRUE) {
        opt = getopt_long(argc, argv, "dhp:f:tr:", longopts, &longindex);

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
            /*
             * test for wrong file types; anonymous fd's do not seem to be any of the wrong
             * ones but are also not character devices
             */
            if (S_ISREG(statbuf.st_mode) || S_ISDIR(statbuf.st_mode) || S_ISBLK(statbuf.st_mode)
                || S_ISLNK(statbuf.st_mode)) {
                fprintf(stderr,
                        "Given file descriptor type is not supported.\n");
                exit(1);
            }
            mlp.flags |= MAIN_LOOP_FLAG_TERMINATE | MAIN_LOOP_FLAG_USE_FD;
            SWTPM_IO_SetSocketFD(mlp.fd);

            break;

        case 'c':
            serverdata = optarg;
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

        case 'P':
            piddata = optarg;
            break;

        case 's':
            tpmstatedata = optarg;
            break;

        case 'C':
            ctrlchdata = optarg;
            break;

        case 'h':
            usage(stdout, prgname, iface);
            exit(EXIT_SUCCESS);

        case 'r':
            runas = optarg;
            break;

        default:
            usage(stderr, prgname, iface);
            exit(EXIT_FAILURE);
        }
    }

    /* change process ownership before accessing files */
    if (runas) {
        if (change_process_owner(runas) < 0)
            return EXIT_FAILURE;
    }

    if (handle_log_options(logdata) < 0 ||
        handle_key_options(keydata) < 0 ||
        handle_pid_options(piddata) < 0 ||
        handle_tpmstate_options(tpmstatedata) < 0 ||
        handle_ctrlchannel_options(ctrlchdata, &mlp.cc) < 0 ||
        handle_server_options(serverdata, &server))
        return EXIT_FAILURE;

    if (server) {
        if (server_get_fd(server) >= 0) {
            mlp.fd = server_get_fd(server);
            SWTPM_IO_SetSocketFD(mlp.fd);
        }

        mlp.flags |= MAIN_LOOP_FLAG_KEEP_CONNECTION;
        if ((server_get_flags(server) & SERVER_FLAG_DISCONNECT))
            mlp.flags &= ~MAIN_LOOP_FLAG_KEEP_CONNECTION;

        if ((server_get_flags(server) & SERVER_FLAG_FD_GIVEN))
            mlp.flags |= MAIN_LOOP_FLAG_TERMINATE | MAIN_LOOP_FLAG_USE_FD;
    }

    if (daemonize) {
        if (0 != daemon(0, 0)) {
            logprintf(STDERR_FILENO, "Error: Could not daemonize.\n");
            return EXIT_FAILURE;
        }
    }

    if (pidfile_write(getpid()) < 0) {
        return EXIT_FAILURE;
    }

    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe */

#ifdef DEBUG
    /* initialization */
    start_time = time(NULL);
#endif

    TPM_DEBUG("main: Initializing TPM at %s", ctime(&start_time));

    TPM_DEBUG("Main: Compiled for %u auth, %u transport, and %u DAA session slots\n",
           tpmlib_get_tpm_property(TPMPROP_TPM_MIN_AUTH_SESSIONS),
           tpmlib_get_tpm_property(TPMPROP_TPM_MIN_TRANS_SESSIONS),
           tpmlib_get_tpm_property(TPMPROP_TPM_MIN_DAA_SESSIONS));
    TPM_DEBUG("Main: Compiled for %u key slots, %u owner evict slots\n",
           tpmlib_get_tpm_property(TPMPROP_TPM_KEY_HANDLES),
           tpmlib_get_tpm_property(TPMPROP_TPM_OWNER_EVICT_KEY_HANDLES));
    TPM_DEBUG("Main: Compiled for %u counters, %u saved sessions\n",
           tpmlib_get_tpm_property(TPMPROP_TPM_MIN_COUNTERS),
           tpmlib_get_tpm_property(TPMPROP_TPM_MIN_SESSION_LIST));
    TPM_DEBUG("Main: Compiled for %u family, %u delegate table entries\n",
           tpmlib_get_tpm_property(TPMPROP_TPM_NUM_FAMILY_TABLE_ENTRY_MIN),
           tpmlib_get_tpm_property(TPMPROP_TPM_NUM_DELEGATE_TABLE_ENTRY_MIN));
    TPM_DEBUG("Main: Compiled for %u total NV, %u savestate, %u volatile space\n",
           tpmlib_get_tpm_property(TPMPROP_TPM_MAX_NV_SPACE),
           tpmlib_get_tpm_property(TPMPROP_TPM_MAX_SAVESTATE_SPACE),
           tpmlib_get_tpm_property(TPMPROP_TPM_MAX_VOLATILESTATE_SPACE));
#if 0
    TPM_DEBUG("Main: Compiled for %u NV defined space\n",
           tpmlib_get_tpm_property(TPMPROP_TPM_MAX_NV_DEFINED_SIZE));
#endif

    if ((rc = tpmlib_start(&callbacks, 0)))
        goto error_no_tpm;

    if (install_sighandlers(notify_fd, sigterm_handler) < 0)
        goto error_no_sighandlers;

    rc = mainLoop(&mlp, notify_fd[0], &callbacks);

error_no_sighandlers:
    TPMLIB_Terminate();

error_no_tpm:
    pidfile_remove();

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
