/********************************************************************************/
/*                                                                              */
/*                           TPM Main Program                                   */
/*                 Written by Ken Goldman, Stefan Berger                        */
/*                     IBM Thomas J. Watson Research Center                     */
/*                                                                              */
/* (c) Copyright IBM Corporation 2006, 2010, 2016, 2019.			*/
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
#include <sys/types.h>
#include <sys/socket.h>

#include <libtpms/tpm_error.h>
#include <libtpms/tpm_library.h>
#include <libtpms/tpm_memory.h>

#include "main.h"
#include "swtpm_debug.h"
#include "swtpm_io.h"
#include "swtpm_nvstore.h"
#include "server.h"
#include "common.h"
#include "logging.h"
#include "pidfile.h"
#include "tpmlib.h"
#include "utils.h"
#include "mainloop.h"
#include "ctrlchannel.h"
#include "tpmstate.h"
#include "sys_dependencies.h"
#include "osx.h"
#include "seccomp_profile.h"
#include "options.h"
#include "capabilities.h"

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
    "--ctrl type=[unixio|tcp][,path=<path>][,port=<port>[,bindaddr=address[,ifname=ifname]]][,fd=<filedescriptor>|clientfd=<filedescriptor>][,mode=0...][,uid=uid][,gid=gid]\n"
    "                 : TPM control channel using either UnixIO or TCP sockets;\n"
    "                   the path is only valid for Unixio channels; the port must\n"
    "                   be given in case the type is TCP; the TCP socket is bound\n"
    "                   to 127.0.0.1 by default and other bind addresses can be\n"
    "                   given with the bindaddr parameter; if fd is provided,\n"
    "                   it will be treated as a server socket and used for \n"
    "                   accepting client connections; if clientfd is provided,\n"
    "                   it will be treaded as client connection;\n"
    "                   NOTE: fd and clientfd are mutually exclusive and clientfd\n"
    "                   is only valid for UnixIO channels\n"
    "                   mode allows a user to set the file mode bits of a Unixio socket;\n"
    "                   the value must be given in octal number format\n"
    "                   uid and gid set the ownership of the Unixio socket's file;\n"
    "--migration-key file=<path>|fd=<fd>[,mode=aes-cbc|aes-256-cbc][,format=hex|binary][,remove=[true|false]]\n"
    "                 : use an AES key for the encryption of the TPM's state\n"
    "                   when it is retrieved from the TPM via ioctls;\n"
    "                   Setting this key ensures that the TPM's state will always\n"
    "                   be encrypted when migrated\n"
    "--migration-key pwdfile=<path>|pwdfd=<fd>[,mode=aes-cbc|aes-256-cbc][,remove=[true|false]][,kdf=sha512|pbkdf2]\n"
    "                 : provide a passphrase in a file; the AES key will be\n"
    "                   derived from this passphrase; default kdf is PBKDF2\n"
    "--log file=<path>|fd=<filedescriptor>[,level=n][,prefix=<prefix>][,truncate]\n"
    "                 : write the TPM's log into the given file rather than\n"
    "                   to the console; provide '-' for path to avoid logging\n"
    "                   log level 5 and higher will enable libtpms logging;\n"
    "                   all logged output will be prefixed with prefix;\n"
    "                   the log file can be reset (truncate)\n"
    "--key file=<path>|fd=<fd>[,mode=aes-cbc|aes-256-cbc][,format=hex|binary][,remove=[true|false]]\n"
    "                 : use an AES key for the encryption of the TPM's state\n"
    "                   files; use the given mode for the block encryption;\n"
    "                   the key is to be provided as a hex string or in binary\n"
    "                   format; the keyfile can be automatically removed using\n"
    "                   the remove parameter\n"
    "--key pwdfile=<path>|pwdfd=<fd>[,mode=aes-cbc|aes-256-cbc][,remove=[true|false]][,kdf=sha512|pbkdf2]\n"
    "                 : provide a passphrase in a file; the AES key will be\n"
    "                   derived from this passphrase; default kdf is PBKDF2\n"
    "--locality [reject-locality-4][,allow-set-locality]\n"
    "                 : reject-locality-4: reject any command in locality 4\n"
    "                   allow-set-locality: accept SetLocality command\n"
    "--pid file=<path>|fd=<filedescriptor>\n"
    "                 : write the process ID into the given file\n"
    "--tpmstate dir=<dir>[,mode=0...]|backend-uri=<uri>\n"
    "                 : set the directory or uri where the TPM's state will be written\n"
    "                   into; the TPM_PATH environment variable can be used\n"
    "                   instead dir option;\n"
    "                   mode allows a user to set the file mode bits of the state files;\n"
    "                   the default mode is 0640;\n"
    "--server [type=tcp][,port=port[,bindaddr=address[,ifname=ifname]]][,fd=fd][,disconnect]\n"
    "                 : Expect TCP connections on the given port;\n"
    "                   if fd is provided, packets will be read from it directly;\n"
    "                   the disconnect parameter closes the connection after\n"
    "                   sending a response back to the client; the TCP socket is\n"
    "                   bound to 127.0.0.1 by default and other bind addresses\n"
    "                   can be given with the bindaddr parameter\n"
    "--server type=unixio[,path=path][,fd=fd][,mode=0...][,uid=uid][,gid=gid]\n"
    "                 : Expect UnixIO connections on the given path; if fd is\n"
    "                   provided, packets will be read from it directly;\n"
    "                   mode allows a user to set the file mode bits of the socket; the\n"
    "                   value must be given in octal number format;\n"
    "                   uid and gid set the ownership of the Unixio socket's file;\n"
    "--flags [not-need-init][,startup-clear|startup-state|startup-deactivated|startup-none]\n"
    "                 : not-need-init: commands can be sent without needing to\n"
    "                   send an INIT via control channel;\n"
    "                   startup-...: send Startup command with this type;\n"
    "-r|--runas <user>: change to the given user\n"
    "--tpm2           : choose TPM2 functionality\n"
#ifdef WITH_SECCOMP
# ifndef SCMP_ACT_LOG
    "--seccomp action=none|kill\n"
# else
    "--seccomp action=none|kill|log\n"
# endif
    "                 : Choose the action of the seccomp profile when a\n"
    "                   blacklisted syscall is executed; default is kill\n"
#endif
    "--print-capabilites\n"
    "                 : print capabilities and terminate\n"
    "--print-states\n"
    "                 : print existing TPM states and terminate\n"
    "-h|--help        : display this help screen and terminate\n"
    "\n",
    prgname, iface);
}

static void swtpm_cleanup(struct ctrlchannel *cc, struct server *server)
{
    pidfile_remove();
    ctrlchannel_free(cc);
    server_free(server);
    log_global_free();
    tpmstate_global_free();
    SWTPM_NVRAM_Shutdown();
}

int swtpm_main(int argc, char **argv, const char *prgname, const char *iface)
{
    TPM_RESULT rc = 0;
    int daemonize = FALSE;
    int opt, longindex, ret;
    struct stat statbuf;
    struct mainLoopParams mlp = {
        .cc = NULL,
        .flags = 0,
        .fd = -1,
        .locality_flags = 0,
        .tpmversion = TPMLIB_TPM_VERSION_1_2,
        .startupType = _TPM_ST_NONE,
    };
    struct server *server = NULL;
    unsigned long val;
    char *end_ptr;
    char buf[20];
    char *keydata = NULL;
    char *migkeydata = NULL;
    char *logdata = NULL;
    char *piddata = NULL;
    char *localitydata = NULL;
    char *tpmstatedata = NULL;
    char *ctrlchdata = NULL;
    char *serverdata = NULL;
    char *flagsdata = NULL;
    char *seccompdata = NULL;
    char *runas = NULL;
    bool need_init_cmd = true;
#ifdef DEBUG
    time_t              start_time;
#endif
    unsigned int seccomp_action;
    bool printcapabilities = false;
    bool printstates = false;
    static struct option longopts[] = {
        {"daemon"    ,       no_argument, 0, 'd'},
        {"help"      ,       no_argument, 0, 'h'},
        {"port"      , required_argument, 0, 'p'},
        {"fd"        , required_argument, 0, 'f'},
        {"server"    , required_argument, 0, 'c'},
        {"runas"     , required_argument, 0, 'r'},
        {"terminate" ,       no_argument, 0, 't'},
        {"locality"  , required_argument, 0, 'L'},
        {"log"       , required_argument, 0, 'l'},
        {"key"       , required_argument, 0, 'k'},
        {"migration-key", required_argument, 0, 'K'},
        {"pid"       , required_argument, 0, 'P'},
        {"tpmstate"  , required_argument, 0, 's'},
        {"ctrl"      , required_argument, 0, 'C'},
        {"flags"     , required_argument, 0, 'F'},
        {"tpm2"      ,       no_argument, 0, '2'},
#ifdef WITH_SECCOMP
        {"seccomp"   , required_argument, 0, 'S'},
#endif
        {"print-capabilities"
                     ,       no_argument, 0, 'a'},
        {"print-states",     no_argument, 0, 'e'},
        {NULL        , 0                , 0, 0  },
    };

    log_set_prefix("swtpm: ");

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
                logprintf(STDERR_FILENO,
                          "Cannot parse socket port number '%s'.\n",
                          optarg);
                exit(EXIT_FAILURE);
            }
            if (val >= 0x10000) {
                logprintf(STDERR_FILENO, "Port is outside valid range.\n");
                exit(EXIT_FAILURE);
            }
            snprintf(buf, sizeof(buf), "%lu", val);
            if (setenv("TPM_PORT", buf, 1) != 0) {
                logprintf(STDERR_FILENO,
                          "Could not set port: %s\n", strerror(errno));
                exit(EXIT_FAILURE);
            }
            serverdata = "type=tcp,disconnect";
            break;

        case 'f':
            errno = 0;
            val = strtoul(optarg, &end_ptr, 10);
            if (val != (unsigned int)val || errno || end_ptr[0] != '\0') {
                logprintf(STDERR_FILENO,
                          "Cannot parse socket file descriptor.\n");
                exit(EXIT_FAILURE);
            }
            mlp.fd = val;
            if (fstat(mlp.fd, &statbuf) != 0) {
                logprintf(STDERR_FILENO, "Cannot stat file descriptor: %s\n", 
                          strerror(errno));
                exit(EXIT_FAILURE);
            }
            /*
             * test for wrong file types; anonymous fd's do not seem to be any of the wrong
             * ones but are also not character devices
             */
            if (S_ISREG(statbuf.st_mode) || S_ISDIR(statbuf.st_mode) ||
                S_ISBLK(statbuf.st_mode) || S_ISLNK(statbuf.st_mode)) {
                logprintf(STDERR_FILENO,
                          "Given file descriptor type is not supported.\n");
                exit(EXIT_FAILURE);
            }
            mlp.flags |= MAIN_LOOP_FLAG_TERMINATE | MAIN_LOOP_FLAG_USE_FD |
                         MAIN_LOOP_FLAG_KEEP_CONNECTION;

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

        case 'K':
            migkeydata = optarg;
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

        case 'L':
            localitydata = optarg;
            break;

        case 'F':
            flagsdata = optarg;
            break;

        case '2':
            mlp.tpmversion = TPMLIB_TPM_VERSION_2;
            break;

        case 'h':
            usage(stdout, prgname, iface);
            exit(EXIT_SUCCESS);

        case 'a':
            printcapabilities = true;
            break;

        case 'e':
            printstates = true;
            break;

        case 'r':
            runas = optarg;
            break;

        case 'S':
            seccompdata = optarg;
            break;

        default:
            usage(stderr, prgname, iface);
            exit(EXIT_FAILURE);
        }
    }

    if (optind < argc) {
        logprintf(STDERR_FILENO,
                  "Unknown parameter '%s'\n", argv[optind]);
        exit(EXIT_FAILURE);
    }

    /* change process ownership before accessing files */
    if (runas) {
        if (change_process_owner(runas) < 0)
            exit(EXIT_FAILURE);
    }

    if (handle_log_options(logdata) < 0)
        exit(EXIT_FAILURE);

    if (mlp.fd >= 0 && mlp.fd < 3) {
        /* no std{in,out,err} */
        logprintf(STDERR_FILENO,
            "Error: Cannot accept file descriptors with values 0, 1, or 2\n");
        exit(EXIT_FAILURE);
    }

    if (printcapabilities) {
        /*
         * Choose the TPM version so that getting/setting buffer size works.
         * Ignore failure, for backward compatibility when TPM 1.2 is disabled.
         */
        TPMLIB_ChooseTPMVersion(mlp.tpmversion);
        ret = capabilities_print_json(false);
        exit(ret ? EXIT_FAILURE : EXIT_SUCCESS);
    }

    if (TPMLIB_ChooseTPMVersion(mlp.tpmversion) != TPM_SUCCESS) {
        logprintf(STDERR_FILENO,
                  "Error: Could not choose TPM version.\n");
        exit(EXIT_FAILURE);
    }

    if (handle_ctrlchannel_options(ctrlchdata, &mlp.cc) < 0 ||
        handle_server_options(serverdata, &server) < 0) {
        goto exit_failure;
    }

    tpmstate_set_version(mlp.tpmversion);

    if (printstates) {
        if (handle_tpmstate_options(tpmstatedata) < 0)
            goto exit_failure;
        if (tpmstatedata == NULL) {
            logprintf(STDERR_FILENO,
                      "Error: --tpmstate option is required for --print-states\n");
            goto exit_failure;
        }
        ret = SWTPM_NVRAM_PrintJson();
        if (ret == 0)
            goto exit_success;
        else
            goto exit_failure;
    }

    if (handle_key_options(keydata) < 0 ||
        handle_migration_key_options(migkeydata) < 0 ||
        handle_pid_options(piddata) < 0 ||
        handle_locality_options(localitydata, &mlp.locality_flags) < 0 ||
        handle_tpmstate_options(tpmstatedata) < 0 ||
        handle_seccomp_options(seccompdata, &seccomp_action) < 0 ||
        handle_flags_options(flagsdata, &need_init_cmd,
                             &mlp.startupType) < 0) {
        goto exit_failure;
    }

    if (server) {
        if (server_get_fd(server) >= 0) {
            mlp.fd = server_set_fd(server, -1);
            SWTPM_IO_SetSocketFD(mlp.fd);
        }

        mlp.flags |= MAIN_LOOP_FLAG_KEEP_CONNECTION;
        if ((server_get_flags(server) & SERVER_FLAG_DISCONNECT))
            mlp.flags &= ~MAIN_LOOP_FLAG_KEEP_CONNECTION;

        if ((server_get_flags(server) & SERVER_FLAG_FD_GIVEN))
            mlp.flags |= MAIN_LOOP_FLAG_TERMINATE | MAIN_LOOP_FLAG_USE_FD;
    }

    if (daemonize) {
#ifdef __APPLE__
        if (0 != osx_daemon(0, 0)) {
#else
        if (0 != daemon(0, 0)) {
#endif
            logprintf(STDERR_FILENO, "Error: Could not daemonize.\n");
            goto exit_failure;
        }
    }

    if (pidfile_write(getpid()) < 0) {
        goto exit_failure;
    }

    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe */

#ifdef DEBUG
    /* initialization */
    start_time = time(NULL);
#endif

    TPM_DEBUG("main: Initializing TPM at %s", ctime(&start_time));

    tpmlib_debug_libtpms_parameters(mlp.tpmversion);

    if ((rc = tpmlib_register_callbacks(&callbacks)))
        goto error_no_tpm;

    if (!need_init_cmd) {
        if ((rc = tpmlib_start(0, mlp.tpmversion)))
            goto error_no_tpm;
        tpm_running = true;
    }

    if (install_sighandlers(notify_fd, sigterm_handler) < 0)
        goto error_no_sighandlers;

    if (create_seccomp_profile(false, seccomp_action) < 0)
        goto error_seccomp_profile;

    rc = mainLoop(&mlp, notify_fd[0]);

error_seccomp_profile:
    uninstall_sighandlers();

error_no_sighandlers:
    TPMLIB_Terminate();

error_no_tpm:
    close(notify_fd[0]);
    notify_fd[0] = -1;
    close(notify_fd[1]);
    notify_fd[1] = -1;

    swtpm_cleanup(mlp.cc, server);

    /* Fatal initialization errors cause the program to abort */
    if (rc == 0) {
        exit(EXIT_SUCCESS);
    }
    else {
        TPM_DEBUG("main: TPM initialization failure %08x, exiting\n", rc);
        exit(EXIT_FAILURE);
    }

exit_failure:
    swtpm_cleanup(mlp.cc, server);

    exit(EXIT_FAILURE);

exit_success:
    swtpm_cleanup(mlp.cc, server);

    exit(EXIT_SUCCESS);
}
