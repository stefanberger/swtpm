/********************************************************************************/
/*                                                                              */
/*                           TPM Main Program                                   */
/*                 Written by Ken Goldman, Stefan Berger                        */
/*                     IBM Thomas J. Watson Research Center                     */
/*                                                                              */
/* (c) Copyright IBM Corporation 2006, 2010, 2015, 2016, 2019			*/
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
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <getopt.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <libtpms/tpm_error.h>
#include <libtpms/tpm_library.h>
#include <libtpms/tpm_memory.h>

#include "main.h"
#include "swtpm_debug.h"
#include "swtpm_io.h"
#include "swtpm_nvstore.h"
#include "swtpm_utils.h"
#include "common.h"
#include "locality.h"
#include "logging.h"
#include "pidfile.h"
#include "tpmlib.h"
#include "utils.h"
#include "ctrlchannel.h"
#include "mainloop.h"
#ifdef WITH_VTPM_PROXY
#include "vtpm_proxy.h"
#endif
#include "tpmstate.h"
#include "daemonize.h"
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
    .tpm_io_init             = NULL,
    .tpm_io_getlocality      = mainloop_cb_get_locality,
};

static void sigterm_handler(int sig __attribute__((unused)))
{
    TPM_DEBUG("Terminating...\n");
    if (write(notify_fd[1], "T", 1) < 0) {
        logprintf(STDERR_FILENO, "Error: sigterm notification failed: %s\n",
                  strerror(errno));
    }
    g_mainloop_terminate = true;
}

#ifdef WITH_VTPM_PROXY
static int create_vtpm_proxy(struct vtpm_proxy_new_dev *vtpm_new_dev,
                             int *_errno)
{
    int fd, n, ret = 0;

    fd = open("/dev/vtpmx", O_RDWR);
    if (fd < 0) {
        logprintf(STDERR_FILENO, "Could not open /dev/vtpmx: %s\n",
                  strerror(errno));
        *_errno = errno;
        return -1;
    }

    n = ioctl(fd, VTPM_PROXY_IOC_NEW_DEV, vtpm_new_dev);
    if (n) {
        logprintf(STDERR_FILENO, "Ioctl to create vtpm proxy failed: %s\n",
                  strerror(errno));
        *_errno = errno;
        ret = -1;
    }
    close(fd);

    return ret;
}
#endif

static void usage(FILE *file, const char *prgname, const char *iface)
{
    fprintf(file,
    "Usage: %s %s [options]\n"
    "\n"
    "The following options are supported:\n"
    "\n"
    "-c|--chardev <device>\n"
    "                 : use the given character device\n"
    "-f|--fd <fd>     : use the given character device file descriptor\n"
    "-d|--daemon      : daemonize the TPM\n"
    "--ctrl type=[unixio|tcp][,path=<path>][,port=<port>[,bindaddr=address[,ifname=ifname]]][,fd=<filedescriptor|clientfd=<filedescriptor>][,mode=0...][,uid=uid][,gid=gid][,terminate]\n"
    "                 : TPM control channel using either UnixIO or TCP sockets;\n"
    "                   the path is only valid for Unixio channels; the port must\n"
    "                   be given in case the type is TCP; the TCP socket is bound\n"
    "                   to 127.0.0.1 by default and other bind addresses can be\n"
    "                   given with the bindaddr parameter; if fd is provided,\n"
    "                   it will be treated as a server socket and used for \n"
    "                   accepting client connections; if clientfd is provided,\n"
    "                   it will be treaded as client connection;\n"
    "                   NOTE: fd and clientfd are mutually exclusive and \n"
    "                   clientfd is only valid for UnixIO channels\n"
    "                   mode allows a user to set the file mode bits of a Unixio socket;\n"
    "                   the value must be given in octal number format\n"
    "                   uid and gid set the ownership of the Unixio socket's file;\n"
    "                   terminate terminates on ctrl channel connection loss;\n"
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
    "--pid file=<path>|fd=<filedescriptor>\n"
    "                 : write the process ID into the given file\n"
    "--tpmstate dir=<dir>|backend-uri=<uri>[,mode=0...][,lock][,backup][,fsync]\n"
    "                 : set the directory or uri where the TPM's state will be written\n"
    "                   into; the TPM_PATH environment variable can be used\n"
    "                   instead of dir option;\n"
    "                   mode allows a user to set the file mode bits of the state files;\n"
    "                   the default mode is 0640;\n"
    "                   lock enables file-locking by the storage backend;\n"
    "                   backup has the directory-backend create a backup of the\n"
    "                   permanent state file;\n"
    "                   with fsync the directory-backend ensures that all data have been\n"
    "                   transferred to disk before proceeding;\n"
    "-r|--runas <user>: change to the given user\n"
    "-R|--chroot <path>\n"
    "                 : chroot to the given directory at startup\n"
#ifdef WITH_VTPM_PROXY
    "--vtpm-proxy     : spawn a Linux vTPM proxy driver device and read TPM\n"
#endif
    "                   command from its anonymous file descriptor\n"
    "--locality [reject-locality-4][,allow-set-locality]\n"
    "                 : reject-locality-4: reject any command in locality 4\n"
    "                   allow-set-locality: accept SetLocality command\n"
    "--flags [not-need-init][,startup-clear|startup-state|startup-deactivated|startup-none][,disable-auto-shutdown]\n"
    "                 : not-need-init: commands can be sent without needing to\n"
    "                   send an INIT via control channel; not needed when using\n"
    "                   --vtpm-proxy\n"
    "                   startup-...: send Startup command with this type;\n"
    "                   when --vtpm-proxy is used, startup-clear is used\n"
    "                   disable-auto-shutdown disables automatic sending of\n"
    "                   TPM2_Shutdown before TPM 2 reset or swtpm termination;\n"
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
    "--migration [incoming][,release-lock-outgoing]\n"
    "                 : Incoming migration defers locking of storage backend\n"
    "                   until the TPM state is received; release-lock-outgoing\n"
    "                   releases the storage lock on outgoing migration\n"
    "--print-capabilities\n"
    "                 : print capabilities and terminate\n"
    "--print-states\n"
    "                 : print existing TPM states and terminate\n"
    "--profile name=<name>|profile=<json-profile>|file=<filename>|fd=<fd>[,remove-disabled=check|fips-host]\n"
    "                 : Set a profile on the TPM 2\n"
    "                   remove-disabled: On the 'custom' profile remove algorithms\n"
    "                   disabled by FIPS mode in OpenSSL; use 'check' to test the\n"
    "                   algorithms first\n"
    "--print-profiles\n"
    "                 : print all profiles supported by libtpms\n"
    "--print-info <info flags>\n"
    "                 : print information about the TPM and profiles and exit\n"
    "-h|--help        : display this help screen and terminate\n"
    "\n",
    prgname, iface);
}

static void swtpm_cleanup(struct mainLoopParams *mlp)
{
    free(mlp->json_profile);
    pidfile_remove();
    ctrlchannel_free(mlp->cc);
    log_global_free();
    tpmstate_global_free();
    SWTPM_NVRAM_Shutdown();
}

#ifdef WITH_VTPM_PROXY
static int swtpm_chardev_create_vtpm_proxy(struct mainLoopParams *mlp,
                                           bool *need_init_cmd) {
    struct vtpm_proxy_new_dev vtpm_new_dev = {
        .flags = 0,
    };
    int _errno;

    if (mlp->tpmversion == TPMLIB_TPM_VERSION_2)
        vtpm_new_dev.flags = VTPM_PROXY_FLAG_TPM2;

    /* Will be adjusted for TPM 2 */
    mlp->startupType = TPM_ST_CLEAR;
    *need_init_cmd = false;

    if (mlp->fd >= 0) {
        logprintf(STDERR_FILENO,
                  "Cannot use vTPM proxy with a provided device.\n");
        return -1;
    }

    if (create_vtpm_proxy(&vtpm_new_dev, &_errno))
        return -1;

    mlp->fd = vtpm_new_dev.fd;

    mlp->flags |= MAIN_LOOP_FLAG_TERMINATE | MAIN_LOOP_FLAG_USE_FD;
    SWTPM_IO_SetSocketFD(mlp->fd);

    fprintf(stdout, "New TPM device: /dev/tpm%u (major/minor = %u/%u)\n",
            vtpm_new_dev.tpm_num,
            vtpm_new_dev.major, vtpm_new_dev.minor);
    mlp->locality_flags |= LOCALITY_FLAG_ALLOW_SETLOCALITY;

    return 0;
}
#endif

int swtpm_chardev_main(int argc, char **argv, const char *prgname, const char *iface)
{
    TPM_RESULT rc = 0;
    int daemonize = FALSE;
    int opt, longindex, ret;
    struct stat statbuf;
    struct mainLoopParams mlp = {
        .cc = NULL,
        .fd = -1,
        .flags = 0,
        .locality_flags = 0,
        .tpmversion = TPMLIB_TPM_VERSION_1_2,
        .startupType = _TPM_ST_NONE,
        .lastCommand = TPM_ORDINAL_NONE,
        .disable_auto_shutdown = false,
        .incoming_migration = false,
        .storage_locked = false,
    };
    g_autofree gchar *jsoninfo = NULL;
    unsigned long val;
    char *end_ptr;
    char *keydata = NULL;
    char *migkeydata = NULL;
    char *logdata = NULL;
    char *piddata = NULL;
    char *localitydata = NULL;
    char *tpmstatedata = NULL;
    char *ctrlchdata = NULL;
    char *flagsdata = NULL;
    char *seccompdata = NULL;
    char *migrationdata = NULL;
    char *runas = NULL;
    char *chroot = NULL;
    char *profiledata = NULL;
#ifdef WITH_VTPM_PROXY
    bool use_vtpm_proxy = false;
#endif
#ifdef DEBUG
    time_t              start_time;
#endif
    bool need_init_cmd = true;
    unsigned int seccomp_action = SWTPM_SECCOMP_ACTION_KILL;
    bool printcapabilities = false;
    bool printstates = false;
    bool printprofiles = false;
    bool tpm_running = false;
    enum TPMLIB_InfoFlags infoflags = 0;
    static struct option longopts[] = {
        {"daemon"    ,       no_argument, 0, 'd'},
        {"help"      ,       no_argument, 0, 'h'},
        {"chardev"   , required_argument, 0, 'c'},
        {"fd"        , required_argument, 0, 'f'},
        {"runas"     , required_argument, 0, 'r'},
        {"chroot"    , required_argument, 0, 'R'},
        {"locality"  , required_argument, 0, 'L'},
        {"log"       , required_argument, 0, 'l'},
        {"key"       , required_argument, 0, 'k'},
        {"migration-key", required_argument, 0, 'K'},
        {"pid"       , required_argument, 0, 'P'},
        {"tpmstate"  , required_argument, 0, 's'},
        {"ctrl"      , required_argument, 0, 'C'},
        {"flags"     , required_argument, 0, 'F'},
#ifdef WITH_VTPM_PROXY
        {"vtpm-proxy",       no_argument, 0, 'v'},
#endif
        {"tpm2"      ,       no_argument, 0, '2'},
#ifdef WITH_SECCOMP
        {"seccomp"   , required_argument, 0, 'S'},
#endif
        {"migration" , required_argument, 0, 'i'},
        {"print-capabilities"
                     ,       no_argument, 0, 'a'},
        {"print-states",     no_argument, 0, 'e'},
        {"profile"   , required_argument, 0, 'I'},
        {"print-profiles",   no_argument, 0, 'N'},
        {"print-info", required_argument, 0, 'x'},
        {NULL        , 0                , 0, 0  },
    };

    log_set_prefix("swtpm: ");

    while (TRUE) {
        opt = getopt_long(argc, argv, "dhc:f:r:R:", longopts, &longindex);

        if (opt == -1)
            break;

        switch (opt) {
        case 'd':
            daemonize = TRUE;
            if (daemonize_prep() == -1) {
                logprintf(STDERR_FILENO,
                          "Could not prepare to daemonize: %s\n", strerror(errno));
                exit(EXIT_FAILURE);
            }
            break;

        case 'c':
            if (mlp.fd >= 0)
                continue;

            mlp.fd = open(optarg, O_RDWR);
            if (mlp.fd < 0) {
                logprintf(STDERR_FILENO, "Cannot open %s: %s\n",
                          optarg, strerror(errno));
                exit(EXIT_FAILURE);
            }
            mlp.flags |= MAIN_LOOP_FLAG_TERMINATE | MAIN_LOOP_FLAG_USE_FD;
            SWTPM_IO_SetSocketFD(mlp.fd);
            break;

        case 'f':
            if (mlp.fd >= 0)
                continue;

            errno = 0;
            val = strtoul(optarg, &end_ptr, 10);
            if (val != (unsigned int)val || errno || end_ptr[0] != '\0') {
                logprintf(STDERR_FILENO,
                          "Cannot parse character device file descriptor.\n");
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
            if (S_ISREG(statbuf.st_mode) || S_ISDIR(statbuf.st_mode) || S_ISBLK(statbuf.st_mode)
                || S_ISLNK(statbuf.st_mode)) {
                logprintf(STDERR_FILENO,
                          "Given file descriptor type is not supported.\n");
                exit(EXIT_FAILURE);
            }
            mlp.flags |= MAIN_LOOP_FLAG_TERMINATE | MAIN_LOOP_FLAG_USE_FD;
            SWTPM_IO_SetSocketFD(mlp.fd);

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

        case 'R':
            chroot = optarg;
            break;

#ifdef WITH_VTPM_PROXY
        case 'v':
            use_vtpm_proxy = true;
            break;
#endif

        case 'S':
            seccompdata = optarg;
            break;

        case 'i':
            migrationdata = optarg;
            break;

        case 'I':
            profiledata = optarg;
            break;

        case 'N': /* --print-profiles */
            printprofiles = true;
            break;

        case 'x': /* --print-info */
            errno = 0;
            infoflags = strtoul(optarg, &end_ptr, 0);
            if (infoflags != (unsigned int)infoflags || errno || end_ptr[0] != '\0') {
                logprintf(STDERR_FILENO,
                          "Cannot parse info value '%s'.\n", optarg);
                exit(EXIT_FAILURE);
            }
            if (mlp.fd < 0)
                mlp.fd = open("/dev/zero", O_RDWR);
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

    if (chroot) {
        if (do_chroot(chroot) < 0)
            exit(EXIT_FAILURE);
    }

    /* change process ownership before accessing files */
    if (runas) {
        if (change_process_owner(runas) < 0)
            exit(EXIT_FAILURE);
    }

    if (handle_log_options(logdata) < 0)
        exit(EXIT_FAILURE);

    if (handle_locality_options(localitydata, &mlp.locality_flags) < 0)
        exit(EXIT_FAILURE);

#ifdef WITH_VTPM_PROXY
    if (use_vtpm_proxy) {
        if (swtpm_chardev_create_vtpm_proxy(&mlp, &need_init_cmd) < 0)
            exit(EXIT_FAILURE);
    }
#endif

    if (printcapabilities) {
        /*
         * Choose the TPM version so that getting/setting buffer size works.
         * Ignore failure, for backward compatibility when TPM 1.2 is disabled.
         */
        ret = capabilities_print_json(false, mlp.tpmversion);
        exit(ret ? EXIT_FAILURE : EXIT_SUCCESS);
    }

    if (tpmlib_choose_tpm_version(mlp.tpmversion) != TPM_SUCCESS)
        exit(EXIT_FAILURE);

    tpmstate_set_version(mlp.tpmversion);

    if (printstates) {
        if (handle_tpmstate_options(tpmstatedata) < 0)
            exit(EXIT_FAILURE);
        if (tpmstatedata == NULL) {
            logprintf(STDERR_FILENO,
                      "Error: --tpmstate option is required for --print-states\n");
            exit(EXIT_FAILURE);
        }
        ret = SWTPM_NVRAM_PrintJson();
        if (ret)
            goto exit_failure;
        else
            goto exit_success;
    }

    if (printprofiles) {
        print_profiles();
        goto exit_success;
    }

    if (mlp.fd < 0) {
        logprintf(STDERR_FILENO,
                  "Error: Missing character device or file descriptor\n");
        exit(EXIT_FAILURE);
    } else if (mlp.fd < 3) {
        /* no std{in,out,err} */
        logprintf(STDERR_FILENO,
            "Error: Cannot accept file descriptors with values 0, 1, or 2\n");
        exit(EXIT_FAILURE);
    }

    if (handle_ctrlchannel_options(ctrlchdata, &mlp.cc, &mlp.flags) < 0) {
        goto exit_failure;
    }

    if (handle_key_options(keydata) < 0 ||
        handle_migration_key_options(migkeydata) < 0 ||
        handle_pid_options(piddata) < 0 ||
        handle_tpmstate_options(tpmstatedata) < 0 ||
        handle_seccomp_options(seccompdata, &seccomp_action) < 0 ||
        handle_flags_options(flagsdata, &need_init_cmd,
                             &mlp.startupType, &mlp.disable_auto_shutdown) < 0 ||
        handle_migration_options(migrationdata, &mlp.incoming_migration,
                                 &mlp.release_lock_outgoing) < 0 ||
        handle_profile_options(profiledata, &mlp.json_profile) < 0) {
        goto exit_failure;
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

    if (!need_init_cmd || (infoflags && tpmstate_get_backend_uri())) {
        mlp.storage_locked = !mlp.incoming_migration;

        if ((rc = tpmlib_start(0, mlp.tpmversion, mlp.storage_locked,
                               mlp.json_profile)))
            goto error_no_tpm;
        tpm_running = true;
        SWTPM_G_FREE(mlp.json_profile);
    }

    if (infoflags) {
        /* returns more information with tpmstate active */
        jsoninfo = TPMLIB_GetInfo(infoflags);
        printf("%s\n", jsoninfo);
        goto error_no_sighandlers;
    }

    if (install_sighandlers(notify_fd, sigterm_handler) < 0)
        goto error_no_sighandlers;

    if (create_seccomp_profile(false, seccomp_action) < 0)
        goto error_seccomp_profile;

    mlp.flags |= MAIN_LOOP_FLAG_USE_FD | MAIN_LOOP_FLAG_KEEP_CONNECTION | \
      MAIN_LOOP_FLAG_END_ON_HUP;

    if (daemonize) {
        daemonize_finish();
    }

    rc = mainLoop(&mlp, notify_fd[0], tpm_running);

error_seccomp_profile:
    uninstall_sighandlers();

error_no_sighandlers:
    TPMLIB_Terminate();

error_no_tpm:
    close(notify_fd[0]);
    notify_fd[0] = -1;
    close(notify_fd[1]);
    notify_fd[1] = -1;

    swtpm_cleanup(&mlp);

    /* Fatal initialization errors cause the program to abort */
    if (rc == 0) {
        exit(EXIT_SUCCESS);
    }
    else {
        TPM_DEBUG("main: TPM initialization failure %08x, exiting\n", rc);
        exit(EXIT_FAILURE);
    }

exit_failure:
    swtpm_cleanup(&mlp);

    exit(EXIT_FAILURE);

exit_success:
    swtpm_cleanup(&mlp);

    exit(EXIT_SUCCESS);
}
