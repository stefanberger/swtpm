/********************************************************************************/
/*                                                                              */
/*                            CUSE TPM                                          */
/*                     IBM Thomas J. Watson Research Center                     */
/*                                                                              */
/* (c) Copyright IBM Corporation 2014-2015.					*/
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

/*
 * Authors:
 *     Eric Richter, erichte@us.ibm.com
 *     Stefan Berger, stefanb@us.ibm.com
 *     David Safford, safford@us.ibm.com
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <pwd.h>
#include <grp.h>
#include <limits.h>

#include <fuse/cuse_lowlevel.h>

#include <glib.h>

#include "swtpm.h"
#include "common.h"
#include "tpmstate.h"
#include "pidfile.h"
#include "logging.h"

#define MAX_BUF_SIZE 128

static int example_size = sizeof("Hello World!\n");
static char example_buffer[MAX_BUF_SIZE] = "Hello World!\n";

#if GLIB_MAJOR_VERSION >= 2
# if GLIB_MINOR_VERSION >= 32

GCond thread_busy_signal;
GMutex thread_busy_lock;
GMutex file_ops_lock;
#  define THREAD_BUSY_SIGNAL &thread_busy_signal
#  define THREAD_BUSY_LOCK &thread_busy_lock
#  define FILE_OPS_LOCK &file_ops_lock

# else

GCond *thread_busy_signal;
GMutex *thread_busy_lock;
GMutex *file_ops_lock;
#  define THREAD_BUSY_SIGNAL thread_busy_signal
#  define THREAD_BUSY_LOCK thread_busy_lock
#  define FILE_OPS_LOCK file_ops_lock

# endif
#else

#error Unsupport glib version

#endif

struct cuse_param {
    char *runas;
    char *logging;
    char *keydata;
    char *migkeydata;
    char *piddata;
    char *tpmstatedata;
};

static const char *usage =
"usage: %s [options]\n"
"\n"
"The following options are supported:\n"
"\n"
"-n NAME|--name=NAME :  device name (mandatory)\n"
"-M MAJ|--maj=MAJ    :  device major number\n"
"-m MIN|--min=MIN    :  device minor number\n"
"--key file=<path>[,mode=aes-cbc][,format=hex|binary][,remove=[true|false]]\n"
"                    :  use an AES key for the encryption of the TPM's state\n"
"                       files; use the given mode for the block encryption;\n"
"                       the key is to be provided as a hex string or in binary\n"
"                       format; the keyfile can be automatically removed using\n"
"                       the remove parameter\n"
"--key pwdfile=<path>[,mode=aes-cbc][,remove=[true|false]]\n"
"                    :  provide a passphrase in a file; the AES key will be\n"
"                       derived from this passphrase\n"
"--migration-key file=<path>,[,mode=aes-cbc][,format=hex|binary][,remove=[true|false]]\n"
"                    :  use an AES key for the encryption of the TPM's state\n"
"                       when it is retrieved from the TPM via ioctls;\n"
"                       Setting this key ensures that the TPM's state will always\n"
"                       be encrypted when migrated\n"
"--migration-key pwdfile=<path>[,mode=aes-cbc][,remove=[true|false]]\n"
"                    :  provide a passphrase in a file; the AES key will be\n"
"                       derived from this passphrase\n"
"--log file=<path>|fd=<filedescriptor>\n"
"                    :  write the TPM's log into the given file rather than\n"
"                       to the console; provide '-' for path to avoid logging\n"
"--pid file=<path>   :  write the process ID into the given file\n"
"--tpmstate dir=<dir>\n"
"                    :  set the directory where the TPM's state will be written\n"
"                       into; the TPM_PATH environment variable can be used\n"
"                       instead\n"
""
"-h|--help           :  display this help screen and terminate\n"
"\n";

static void c_open(fuse_req_t req, struct fuse_file_info *fi)
{
    fuse_reply_open(req, fi);
}

// TODO: figure out what goes in this call...
static void c_release(fuse_req_t req, struct fuse_file_info * fi) {}

static void c_read(fuse_req_t req, size_t size, off_t off, struct fuse_file_info *fi)
{

    // TODO: Check offset

    fuse_reply_buf(req, example_buffer, example_size);

}

static void c_write(fuse_req_t req, const char * buf, size_t size, off_t off, struct fuse_file_info *fi)
{
    if (size > MAX_BUF_SIZE)
        fuse_reply_write(req, 0);

    memcpy(example_buffer, buf, size);
    example_size = size;
    fuse_reply_write(req, size);
}

static void c_ioctl(fuse_req_t req, int cmd, void *arg, struct fuse_file_info *fi, unsigned int flags, const void * in_buf, size_t in_bufsz, size_t out_butsz)
{

    switch(cmd) {
    // Random ioctl number for testing purposes
    case 424242:
        // Sets the internal buffer, check with a read
        sprintf(example_buffer, "424242 received\n");
        example_size = sizeof("424242 received\n");
        break;
    default:
        // some default action?
        break;
    }

}

static void ptm_init_done(void *userdata)
{
    struct cuse_param *param = userdata;
    struct passwd *passwd = NULL;

    /* at this point the entry in /dev/ is available */
    if (pidfile_write(getpid()) < 0) {
        exit(-13);
    }

    if (param->runas) {
        passwd = getpwnam(param->runas);
        if (!passwd) {
            logprintf(STDERR_FILENO,
                      "Error: User '%s' does not exist.\n",
                      param->runas);
            exit(-14);
        }
        if (initgroups(passwd->pw_name, passwd->pw_gid) < 0) {
            logprintf(STDERR_FILENO,
                      "Error: initgroups(%s, %d) failed.\n",
                      passwd->pw_name, passwd->pw_gid);
            exit(-10);
        }
        if (setgid(passwd->pw_gid) < 0) {
            logprintf(STDERR_FILENO,
                      "Error: setgid(%d) failed.\n",
                      passwd->pw_gid);
            exit(-11);
        }
        if (setuid(passwd->pw_uid) < 0) {
            logprintf(STDERR_FILENO,
                      "Error: setuid(%d) failed.\n",
                      passwd->pw_uid);
            exit(-12);
        }
    }
}

static const struct cuse_lowlevel_ops clops = {
    .open = c_open,
    .release = c_release,
    .read = c_read,
    .write = c_write,
    .ioctl = c_ioctl,
    .init_done = ptm_init_done,
};

int main(int argc, char **argv)
{
    int opt, longindex = 0;
    static struct option longopts[] = {
        {"maj"           , required_argument, 0, 'M'},
        {"min"           , required_argument, 0, 'm'},
        {"name"          , required_argument, 0, 'n'},
        {"runas"         , required_argument, 0, 'r'},
        {"log"           , required_argument, 0, 'l'},
        {"key"           , required_argument, 0, 'k'},
        {"migration-key" , required_argument, 0, 'K'},
        {"pid"           , required_argument, 0, 'p'},
        {"tpmstate"      , required_argument, 0, 's'},
        {"help"          ,       no_argument, 0, 'h'},
        {"version"       ,       no_argument, 0, 'v'},
        {NULL            , 0                , 0, 0  },
    };
    struct cuse_info cinfo;
    struct cuse_param param;
    const char *devname = NULL;
    char *cinfo_argv[1];
    unsigned int num;
    struct passwd *passwd;
    const char *tpmdir;
    int n, tpmfd;
    char path[PATH_MAX];

    memset(&cinfo, 0, sizeof(cinfo));
    memset(&param, 0, sizeof(param));

    while (true) {
        opt = getopt_long(argc, argv, "M:m:n:r:hv", longopts, &longindex);

        if (opt == -1)
            break;

        switch (opt) {
        case 'M': /* major */
            if (sscanf(optarg, "%u", &num) != 1) {
                fprintf(stderr, "Could not parse major number\n");
                return -1;
            }
            if (num < 0 || num > 65535) {
                fprintf(stderr, "Major number outside valid range [0 - 65535]\n");
                return -1;
            }
            cinfo.dev_major = num;
            break;
        case 'm': /* minor */
            if (sscanf(optarg, "%u", &num) != 1) {
                fprintf(stderr, "Could not parse major number\n");
                return -1;
            }
            if (num < 0 || num > 65535) {
                fprintf(stderr, "Major number outside valid range [0 - 65535]\n");
                return -1;
            }
            cinfo.dev_minor = num;
            break;
        case 'n': /* name */
            if (!cinfo.dev_info_argc) {
                cinfo_argv[0] = calloc(1, strlen("DEVNAME=") + strlen(optarg) + 1);
                if (!cinfo_argv[0]) {
                    fprintf(stderr, "Out of memory\n");
                    return -1;
                }
                devname = optarg;

                strcpy(cinfo_argv[0], "DEVNAME=");
                strcat(cinfo_argv[0], optarg);

                cinfo.dev_info_argc = 1;
                cinfo.dev_info_argv = (const char **)cinfo_argv;
            }
            break;
        case 'r': /* runas */
            param.runas = optarg;
            break;
        case 'l': /* log */
            param.logging = optarg;
            break;
        case 'k': /* key */
            param.keydata = optarg;
            break;
        case 'K': /* migration-key */
            param.migkeydata = optarg;
            break;
        case 'p': /* pid */
            param.piddata = optarg;
            break;
        case 's': /* tpmstate */
            param.tpmstatedata = optarg;
            break;
        case 'h': /* help */
            fprintf(stdout, usage, argv[0]);
            return 0;
        case 'v': /* version */
            fprintf(stdout, "TPM emulator CUSE interface version %d.%d.%d, "
                    "Copyright (c) 2014-2015 IBM Corp.\n",
                    SWTPM_VER_MAJOR,
                    SWTPM_VER_MINOR,
                    SWTPM_VER_MICRO);
            return 0;
        }
    }

    if (!cinfo.dev_info_argv) {
        fprintf(stderr, "Error: device name missing\n");
        return -2;
    }

    if (handle_log_options(param.logging) < 0 ||
        handle_key_options(param.keydata) < 0 ||
        handle_migration_key_options(param.migkeydata) < 0 ||
        handle_pid_options(param.piddata) < 0 ||
        handle_tpmstate_options(param.tpmstatedata) < 0)
        return -3;

    if (setuid(0)) {
        fprintf(stderr, "Error: Unable to setuid root. uid = %d, "
                "euid = %d, gid = %d\n", getuid(), geteuid(), getgid());
        return -4;
    }

    if (param.runas) {
        if (!(passwd = getpwnam(param.runas))) {
            fprintf(stderr, "User '%s' does not exist\n",
                    param.runas);
            return -5;
        }
    }

    tpmdir = tpmstate_get_dir();
    if (tpmdir == NULL) {
        fprintf(stderr,
                "Error: No TPM state directory is defined; TPM_PATH is not set\n");
        return -1;
    }

    n = snprintf(path, sizeof(path), "/dev/%s", devname);
    if (n < 0) {
        fprintf(stderr,
                "Error: Could not create device file name\n");
        return -1;
    }
    if (n >= (int)sizeof(path)) {
        fprintf(stderr,
                "Error: Buffer too small to create device file name\n");
        return -1;
    }

    tpmfd = open(path, O_RDWR);
    if (tpmfd >= 0) {
        close(tpmfd);
        fprintf(stderr,
                "Error: A device '%s' already exists.\n",
                path);
        return -1;
    }

#if GLIB_MINOR_VERSION >= 32
    g_mutex_init(THREAD_BUSY_LOCK);
    g_cond_init(THREAD_BUSY_SIGNAL);
    g_mutex_init(FILE_OPS_LOCK);
#else
    g_thread_init(NULL);
    THREAD_BUSY_LOCK = g_mutex_new();
    THREAD_BUSY_SIGNAL = g_cond_new();
    FILE_OPS_LOCK = g_mutex_new();
#endif

    return cuse_lowlevel_main(1, argv, &cinfo, &clops, &param);
}
