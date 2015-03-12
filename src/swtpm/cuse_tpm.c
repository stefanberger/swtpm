/*
 * ptm - CUSE based TPM PassThrough Multiplexer for QEMU.
 *
 * This program instantiates one /dev/vtpm* device, and
 * calls libtpms to handle requests
 *
 * The following code was derived from
 * http://fuse.sourceforge.net/doxygen/cusexmp_8c.html
 *
 * It's original header states:
 *
 * CUSE example: Character device in Userspace
 * Copyright (C) 2008-2009 SUSE Linux Products GmbH
 * Copyright (C) 2008-2009 Tejun Heo <tj@kernel.org>
 * This program can be distributed under the terms of the GNU GPL.
 * See the file COPYING.
 *
 *
 * Authors: David Safford safford@us.ibm.com
 *          Stefan Berger stefanb@us.ibm.com
 * 
 */

/*
 * Note: It's possible for multiple process to open access to
 * the same character device. Concurrency problems may arise
 * if those processes all write() to the device and then try
 * to pick up the results. Proper usage of the device is to
 * have one process (QEMU) use ioctl, read and write and have
 * other processes (libvirt, etc.) only use ioctl.
 */
#define FUSE_USE_VERSION 29

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/types.h>
#include <ctype.h>
#include <pwd.h>
#include <grp.h>
#include <arpa/inet.h>

#include <libtpms/tpm_library.h>
#include <libtpms/tpm_tis.h>
#include <libtpms/tpm_error.h>
#include <libtpms/tpm_memory.h>
#include <libtpms/tpm_nvfilename.h>

#include "cuse_lowlevel.h"
#include "fuse_opt.h"
#include "tpm_ioctl.h"
#include "swtpm.h"
#include "swtpm_nvfile.h"
#include "key.h"
#include "logging.h"
#include "main.h"
#include "common.h"

#include <glib.h>

#define TPM_REQ_MAX 4096
static unsigned char *ptm_req, *ptm_res;
static uint32_t ptm_req_len, ptm_res_len, ptm_res_tot;
static TPM_MODIFIER_INDICATOR locality;
static int tpm_running;
static int thread_busy;
static GThreadPool *pool;
static struct passwd *passwd;

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

struct ptm_param {
    unsigned major;
    unsigned minor;
    char *dev_name;
    int is_help;
    const char *prgname;
    char *runas;
    char *logging;
    char *keydata;
};


enum msg_type {
    MESSAGE_TPM_CMD = 1,
    MESSAGE_IOCTL,
};

struct thread_message {
    enum msg_type type;
    fuse_req_t    req;
};

#define min(a,b) ((a) < (b) ? (a) : (b))

struct stateblob {
    uint8_t type;
    uint8_t *data;
    uint32_t length;
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
"--log file=<path>|fd=<filedescriptor>\n"
"                    :  write the TPM's log into the given file rather than\n"
"                       to the console; provide '-' for path to avoid logging\n"
"-h|--help           :  display this help screen and terminate\n"
"\n"
"Make sure that TPM_PATH environment variable points to directory\n"
"where TPM's NV storage file is kept\n"
"\n";

const static unsigned char TPM_Resp_FatalError[] = {
    0x00, 0xC4,                     /* TPM Response */
    0x00, 0x00, 0x00, 0x0A,         /* length (10) */
    0x00, 0x00, 0x00, 0x09          /* TPM_FAIL */
};

const static unsigned char TPM_ResetEstablishmentBit[] = {
    0x00, 0xC1,                     /* TPM Request */
    0x00, 0x00, 0x00, 0x0A,         /* length (10) */
    0x40, 0x00, 0x00, 0x0B          /* TPM_ORD_ResetEstablishmentBit */
};

typedef struct TPM_Response_Header {
    uint16_t tag;
    uint32_t paramSize;
    uint32_t returnCode;
} __attribute__ ((packed)) TPM_Response_Header;

static TPM_RESULT
ptm_io_getlocality(TPM_MODIFIER_INDICATOR *loc, uint32_t tpmnum)
{
    *loc = locality;
    return TPM_SUCCESS;
}

static struct libtpms_callbacks cbs = {
    .sizeOfStruct           = sizeof(struct libtpms_callbacks),
    .tpm_nvram_init         = SWTPM_NVRAM_Init,
    .tpm_nvram_loaddata     = SWTPM_NVRAM_LoadData,
    .tpm_nvram_storedata    = SWTPM_NVRAM_StoreData,
    .tpm_nvram_deletename   = SWTPM_NVRAM_DeleteName,
    .tpm_io_getlocality     = ptm_io_getlocality,
};

static struct thread_message msg;

/* worker_thread_wait_done
 *
 * Wait while the TPM worker thread is busy
 */ 
static void worker_thread_wait_done(void)
{
    g_mutex_lock(THREAD_BUSY_LOCK);
    while (thread_busy) {
#if GLIB_MINOR_VERSION >= 32
        gint64 end_time = g_get_monotonic_time() +
            1 * G_TIME_SPAN_SECOND;
        g_cond_wait_until(THREAD_BUSY_SIGNAL,
                          THREAD_BUSY_LOCK,
                          end_time);
#else
        GTimeVal abs_time;
        /*
         * seems like occasionally the g_cond_signal did not wake up
         * the sleeping task; so we poll [TIS Test in BIOS]
         */
        abs_time.tv_sec = 1;
        abs_time.tv_usec = 0;
        g_cond_timed_wait(THREAD_BUSY_SIGNAL,
                          THREAD_BUSY_LOCK,
                          &abs_time);
#endif
    }
    g_mutex_unlock(THREAD_BUSY_LOCK);
}

/* worker_thread_mark_busy
 *
 * Mark the worker thread as busy; call this with the lock held
 */
static void worker_thread_mark_busy(void)
{
    g_mutex_lock(THREAD_BUSY_LOCK);
    thread_busy = 1;
    g_mutex_unlock(THREAD_BUSY_LOCK);
}

/* work_tread_mark_done
 *
 * Mark the worker thread as done and wake
 * up the waiting thread
 */
static void worker_thread_mark_done(void)
{
    g_mutex_lock(THREAD_BUSY_LOCK);
    thread_busy = 0;
    g_cond_signal(THREAD_BUSY_SIGNAL);
    g_mutex_unlock(THREAD_BUSY_LOCK);
}

/* worker_thread_is_busy
 *
 * Determine whether the worker thread is busy
 */
static int worker_thread_is_busy()
{
    return thread_busy;
}

static void worker_thread(gpointer data, gpointer user_data)
{
    struct thread_message *msg = (struct thread_message *)data;

    switch (msg->type) {
    case MESSAGE_TPM_CMD:
        TPMLIB_Process(&ptm_res, &ptm_res_len, &ptm_res_tot,
                       ptm_req, ptm_req_len);
        break;
    case MESSAGE_IOCTL:
        break;
    }

    /* results are ready */
    worker_thread_mark_done();
}

/* worker_thread_end
 *
 * finish the worker thread
 */
static void worker_thread_end()
{
    if (pool) {
        worker_thread_wait_done();
        g_thread_pool_free(pool, TRUE, TRUE);
        pool = NULL;
    }
}

/* _TPM_IO_TpmEstablished_Reset
 *
 * Reset the TPM Established bit
 */
static TPM_RESULT
_TPM_IO_TpmEstablished_Reset(fuse_req_t req,
                             struct fuse_file_info *fi,
                             TPM_MODIFIER_INDICATOR locty)
{
    TPM_RESULT res = TPM_FAIL;
    TPM_Response_Header *tpmrh;
    TPM_MODIFIER_INDICATOR orig_locality = locality;

    locality = locty;

    ptm_req_len = sizeof(TPM_ResetEstablishmentBit);
    memcpy(ptm_req, TPM_ResetEstablishmentBit, ptm_req_len);
    msg.type = MESSAGE_TPM_CMD;
    msg.req = req;

    worker_thread_mark_busy();

    g_thread_pool_push(pool, &msg, NULL);

    worker_thread_wait_done();

    if (ptm_res_len >= sizeof(TPM_Response_Header)) {
        tpmrh = (TPM_Response_Header *)ptm_res;
        res = ntohl(tpmrh->returnCode);
    }

    locality = orig_locality;

    return res;
}

static int tpm_start(uint32_t flags)
{
    DIR *dir;
    char * tpmdir = NULL;

    /* temporary - the backend script lacks the perms to do this */
    if (tpmdir == NULL) {
        tpmdir = getenv("TPM_PATH");
        if (!tpmdir) {
            logprintf(STDOUT_FILENO,
                      "Error: TPM_PATH is not set\n");
            return -1;
        }
    }
    dir = opendir(tpmdir);
    if (dir) {
        closedir(dir);
    } else {
        if (mkdir(tpmdir, 0775)) {
            logprintf(STDERR_FILENO,
                      "Error: Could not open TPM_PATH dir\n");
            return -1;
        }
    }

    pool = g_thread_pool_new(worker_thread,
                             NULL,
                             1,
                             TRUE,
                             NULL);
    if (!pool) {
        logprintf(STDERR_FILENO,
                  "Error: Could not create the thread pool.\n");
        return -1;
    }

    if (TPMLIB_RegisterCallbacks(&cbs) != TPM_SUCCESS) {
        logprintf(STDERR_FILENO,
                  "Error: Could not register the callbacks.\n");
        goto error_del_pool;
    }

    if (TPMLIB_MainInit() != TPM_SUCCESS) {
        logprintf(STDERR_FILENO,
                  "Error: Could not start the CUSE TPM.\n");
        goto error_del_pool;
    }

    if (flags & INIT_FLAG_DELETE_VOLATILE) {
        uint32_t tpm_number = 0;
        char *name = TPM_VOLATILESTATE_NAME;
        if (SWTPM_NVRAM_DeleteName(tpm_number,
                                   name,
                                   FALSE) != TPM_SUCCESS) {
            logprintf(STDERR_FILENO,
                      "Error: Could not delete the volatile "
                      "state of the TPM.\n");
            goto error_terminate;
        }
    }

    if(!ptm_req)
        ptm_req = malloc(4096);
    if(!ptm_req) {
        logprintf(STDERR_FILENO,
                  "Error: Could not allocate memory for request buffer.\n");
        goto error_terminate;
    }

    logprintf(STDOUT_FILENO,
              "CUSE TPM successfully initialized.\n");

    return 0;

error_del_pool:
    g_thread_pool_free(pool, TRUE, TRUE);
    pool = NULL;

error_terminate:
    TPMLIB_Terminate();
    return -1;
}

/*
 * convert the blobtype integer into a string that libtpms
 * understands
 */
static const char *ptm_get_blobname(uint8_t blobtype)
{
    switch (blobtype) {
    case PTM_BLOB_TYPE_PERMANENT:
        return TPM_PERMANENT_ALL_NAME;
    case PTM_BLOB_TYPE_VOLATILE:
        return TPM_VOLATILESTATE_NAME;
    case PTM_BLOB_TYPE_SAVESTATE:
        return TPM_SAVESTATE_NAME;
    default:
        return NULL;
    }
}

static void ptm_open(fuse_req_t req, struct fuse_file_info *fi)
{
    fuse_reply_open(req, fi);
}

/* ptm_write_fatal_error_response
 *
 * Write a fatal error response
 */
static void ptm_write_fatal_error_response(void)
{
    if (ptm_res == NULL ||
        ptm_res_tot < sizeof(TPM_Resp_FatalError)) {
        ptm_res_tot = sizeof(TPM_Resp_FatalError);
        TPM_Realloc(&ptm_res, ptm_res_tot);
    }
    if (ptm_res) {
        ptm_res_len = sizeof(TPM_Resp_FatalError);
        memcpy(ptm_res,
               TPM_Resp_FatalError,
               sizeof(TPM_Resp_FatalError));
    }
}

static void ptm_read(fuse_req_t req, size_t size, off_t off,
                     struct fuse_file_info *fi)
{
    int len;

    if (tpm_running) {
        /* wait until results are ready */
        worker_thread_wait_done();
    }

    len = ptm_res_len;

    if (ptm_res_len > size) {
        len = size;
        ptm_res_len -= size;
    } else {
        ptm_res_len = 0;
    }

    fuse_reply_buf(req, (const char *)ptm_res, len);
}

static void ptm_write(fuse_req_t req, const char *buf, size_t size,
                      off_t off, struct fuse_file_info *fi)
{
    ptm_req_len = size;
    ptm_res_len = 0;

    /* prevent other threads from writing or doing ioctls */
    g_mutex_lock(FILE_OPS_LOCK);

    if (tpm_running) {
        /* ensure that we only ever work on one TPM command */
        if (worker_thread_is_busy()) {
            fuse_reply_err(req, EBUSY);
            goto cleanup;
        }

        /* have command processed by thread pool */
        if (ptm_req_len > TPM_REQ_MAX)
            ptm_req_len = TPM_REQ_MAX;

        memcpy(ptm_req, buf, ptm_req_len);
        msg.type = MESSAGE_TPM_CMD;
        msg.req = req;

        worker_thread_mark_busy();

        g_thread_pool_push(pool, &msg, NULL);

        fuse_reply_write(req, ptm_req_len);
    } else {
        /* TPM not initialized; return error */
        ptm_write_fatal_error_response();
        fuse_reply_write(req, ptm_req_len);
    }

cleanup:
    g_mutex_unlock(FILE_OPS_LOCK);

    return;
}

static void ptm_ioctl(fuse_req_t req, int cmd, void *arg,
                      struct fuse_file_info *fi, unsigned flags,
                      const void *in_buf, size_t in_bufsz, size_t out_bufsz)
{
    TPM_RESULT res;
    bool exit_prg = FALSE;
    ptminit_t *init_p;
    static struct stateblob stateblob;

    if (flags & FUSE_IOCTL_COMPAT) {
        fuse_reply_err(req, ENOSYS);
        return;
    }

    /* some commands have to wait until the worker thread is done */
    switch(cmd) {
    case PTM_GET_CAPABILITY:
    case PTM_SET_LOCALITY:
    case PTM_CANCEL_TPM_CMD:
        /* no need to wait */
        break;
    case PTM_INIT:
    case PTM_SHUTDOWN:
    case PTM_GET_TPMESTABLISHED:
    case PTM_RESET_TPMESTABLISHED:
    case PTM_HASH_START:
    case PTM_HASH_DATA:
    case PTM_HASH_END:
    case PTM_STORE_VOLATILE:
    case PTM_GET_STATEBLOB:
    case PTM_SET_STATEBLOB:
        if (tpm_running)
            worker_thread_wait_done();
        break;
    }

    /* prevent other threads from writing or doing ioctls */
    g_mutex_lock(FILE_OPS_LOCK);

    switch (cmd) {
    case PTM_GET_CAPABILITY:
        if (!out_bufsz) {
            struct iovec iov = { arg, sizeof(uint8_t) };
            fuse_reply_ioctl_retry(req, &iov, 1, NULL, 0);
        } else {
            ptmcap_t ptm_caps;
            ptm_caps = PTM_CAP_INIT | PTM_CAP_SHUTDOWN
                | PTM_CAP_GET_TPMESTABLISHED
                | PTM_CAP_SET_LOCALITY
                | PTM_CAP_HASHING 
                | PTM_CAP_CANCEL_TPM_CMD
                | PTM_CAP_STORE_VOLATILE
                | PTM_CAP_RESET_TPMESTABLISHED
                | PTM_CAP_GET_STATEBLOB
                | PTM_CAP_SET_STATEBLOB ;
            fuse_reply_ioctl(req, 0, &ptm_caps, sizeof(ptm_caps));
        }
        break;

    case PTM_INIT:
        init_p = (ptminit_t *)in_buf;

        worker_thread_end();

        TPMLIB_Terminate();

        tpm_running = 0;
        if ((res = tpm_start(init_p->u.req.init_flags))) {
            logprintf(STDERR_FILENO,
                      "Error: Could not initialize the TPM.\n");
        } else {
            tpm_running = 1;
        }
        fuse_reply_ioctl(req, 0, &res, sizeof(res));
        break;

    case PTM_SHUTDOWN:
        worker_thread_end();

        res = TPM_SUCCESS;
        TPMLIB_Terminate();

        TPM_Free(ptm_res);
        ptm_res = NULL;

        fuse_reply_ioctl(req, 0, &res, sizeof(res));
        exit_prg = TRUE;

        break;

    case PTM_GET_TPMESTABLISHED:
        if (!tpm_running)
            goto error_not_running;

        if (!out_bufsz) {
            struct iovec iov = { arg, sizeof(uint8_t) };
            fuse_reply_ioctl_retry(req, &iov, 1, NULL, 0);
        } else {
            ptmest_t te;
            te.tpm_result = TPM_IO_TpmEstablished_Get(&te.bit);
            fuse_reply_ioctl(req, 0, &te, sizeof(te));
        }
        break;

    case PTM_RESET_TPMESTABLISHED:
        if (!tpm_running)
            goto error_not_running;

        if (!in_bufsz) {
            struct iovec iov = { arg, sizeof(uint32_t) };
            fuse_reply_ioctl_retry(req, &iov, 1, NULL, 0);
        } else {
            ptmreset_est_t *re = (ptmreset_est_t *)in_buf;
            if (re->u.req.loc < 0 || re->u.req.loc > 4) {
                res = TPM_BAD_LOCALITY;
            } else {
                res = _TPM_IO_TpmEstablished_Reset(req, fi, re->u.req.loc);
                fuse_reply_ioctl(req, 0, &res, sizeof(res));
            }
        }
        break;

    case PTM_SET_LOCALITY:
        if (!in_bufsz) {
            struct iovec iov = { arg, sizeof(uint32_t) };
            fuse_reply_ioctl_retry(req, &iov, 1, NULL, 0);
        } else {
            ptmloc_t *l = (ptmloc_t *)in_buf;
            if (l->u.req.loc < 0 || l->u.req.loc > 4) {
                res = TPM_BAD_LOCALITY;
            } else {
                res = 0;
                locality = l->u.req.loc;
            }
            fuse_reply_ioctl(req, 0, &res, sizeof(res));
        }
        break;

    case PTM_HASH_START:
        if (!tpm_running)
            goto error_not_running;

        res = TPM_IO_Hash_Start();
        fuse_reply_ioctl(req, 0, &res, sizeof(res));
        break;

    case PTM_HASH_DATA:
        if (!tpm_running)
            goto error_not_running;

        if (!in_bufsz) {
            struct iovec iov = { arg, sizeof(uint32_t) };
            fuse_reply_ioctl_retry(req, &iov, 1, NULL, 0);
        } else {
            ptmhdata_t *data = (ptmhdata_t *)in_buf;
            if (data->u.req.length <= sizeof(data->u.req.data)) {
                res = TPM_IO_Hash_Data(data->u.req.data,
                                       data->u.req.length);
            } else {
                res = TPM_FAIL;
            }
            fuse_reply_ioctl(req, 0, &res, sizeof(res));
        }
        break;

    case PTM_HASH_END:
        if (!tpm_running)
            goto error_not_running;

        res = TPM_IO_Hash_End();
        fuse_reply_ioctl(req, 0, &res, sizeof(res));
        break;

    case PTM_CANCEL_TPM_CMD:
        if (!tpm_running)
            goto error_not_running;

        /* for cancellation to work, the TPM would have to
         * execute in another thread that polls on a cancel
         * flag
         */
        res = TPM_FAIL;
        fuse_reply_ioctl(req, 0, &res, sizeof(res));
        break;

    case PTM_STORE_VOLATILE:
        if (!tpm_running)
            goto error_not_running;

        res = SWTPM_NVRAM_Store_Volatile();
        fuse_reply_ioctl(req, 0, &res, sizeof(res));
        break;

    case PTM_GET_STATEBLOB:
        if (!tpm_running)
            goto error_not_running;

        if (!in_bufsz) {
            struct iovec iov = { arg, sizeof(uint32_t) };
            fuse_reply_ioctl_retry(req, &iov, 1, NULL, 0);
        } else {
            ptm_getstate_t *pgs = (ptm_getstate_t *)in_buf;
            const char *blobname = ptm_get_blobname(pgs->u.req.type);
            unsigned char *data = NULL;
            uint32_t length = 0, to_copy, offset;
            TPM_BOOL decrypt = ((pgs->u.req.state_flags & STATE_FLAG_DECRYPTED)
                                != 0);
            TPM_BOOL is_encrypted;

            if (blobname) {
                offset = pgs->u.req.offset;

                res = SWTPM_NVRAM_GetStateBlob(&data, &length,
                                               pgs->u.req.tpm_number,
                                               blobname, decrypt,
                                               &is_encrypted);
                if (data != NULL && length > 0) {
                    to_copy = 0;
                    if (offset < length) {
                        to_copy = min(length - offset,
                                      sizeof(pgs->u.resp.data));
                        memcpy(&pgs->u.resp.data, &data[offset], to_copy);
                    }

                    pgs->u.resp.length = to_copy;
                    TPM_Free(data);
                    data = NULL;

                    pgs->u.resp.state_flags = 0;
                    if (is_encrypted) {
                        pgs->u.resp.state_flags |= STATE_FLAG_ENCRYPTED;
                    }
                } else {
                    pgs->u.resp.length = 0;
                }
            } else {
                res = TPM_BAD_PARAMETER;
            }
            pgs->u.resp.tpm_result = res;
            fuse_reply_ioctl(req, 0, pgs, sizeof(pgs->u.resp));
        }
        break;

    case PTM_SET_STATEBLOB:
        if (tpm_running)
            goto error_running;

        /* tpm state dir must be set */
        SWTPM_NVRAM_Init();

        if (!in_bufsz) {
            struct iovec iov = { arg, sizeof(uint32_t) };
            fuse_reply_ioctl_retry(req, &iov, 1, NULL, 0);
        } else {
            ptm_setstate_t *pss = (ptm_setstate_t *)in_buf;
            const char *blobname;
            TPM_BOOL is_encrypted =
                ((pss->u.req.state_flags & STATE_FLAG_ENCRYPTED) != 0);

            if (pss->u.req.length > sizeof(pss->u.req.data)) {
                pss->u.resp.tpm_result = TPM_BAD_PARAMETER;
                fuse_reply_ioctl(req, 0, pss, sizeof(*pss));
                break;
            }

            if (stateblob.type != pss->u.req.type) {
                /* clear old data */
                TPM_Free(stateblob.data);
                stateblob.data = NULL;
                stateblob.length = 0;
                stateblob.type = pss->u.req.type;
            }

            /* append */
            res = TPM_Realloc(&stateblob.data,
                              stateblob.length + pss->u.req.length);
            if (res != 0) {
                /* error */
                TPM_Free(stateblob.data);
                stateblob.data = NULL;
                stateblob.length = 0;
                stateblob.type = 0;

                pss->u.resp.tpm_result = res;
                fuse_reply_ioctl(req, 0, pss, sizeof(*pss));
                break;
            }

            memcpy(&stateblob.data[stateblob.length],
                   pss->u.req.data, pss->u.req.length);
            stateblob.length += pss->u.req.length;

            if (pss->u.req.length == sizeof(pss->u.req.data)) {
                /* full packet */
                pss->u.resp.tpm_result = 0;
                fuse_reply_ioctl(req, 0, pss, sizeof(*pss));
                break;
            }
            blobname = ptm_get_blobname(pss->u.req.type);

            if (blobname) {
                res = SWTPM_NVRAM_SetStateBlob(stateblob.data,
                                               stateblob.length,
                                               is_encrypted,
                                               pss->u.req.tpm_number,
                                               blobname);
            } else {
                res = TPM_BAD_PARAMETER;
            }
            TPM_Free(stateblob.data);
            stateblob.data = NULL;
            stateblob.length = 0;
            stateblob.type = 0;

            pss->u.resp.tpm_result = res;
            fuse_reply_ioctl(req, 0, pss, sizeof(*pss));
        }
        break;

    default:
        fuse_reply_err(req, EINVAL);
    }

cleanup:
    g_mutex_unlock(FILE_OPS_LOCK);

    if (exit_prg) {
        logprintf(STDOUT_FILENO,
                  "CUSE TPM is shutting down.\n");
        exit(0);
    }

    return;

error_running:
error_not_running:
    res = TPM_BAD_ORDINAL;
    fuse_reply_ioctl(req, 0, &res, sizeof(res));

    goto cleanup;
}

static void ptm_init_done(void *userdata) {
    if (passwd) {
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

static const struct cuse_lowlevel_ops ptm_clop = {
    .open      = ptm_open,
    .read      = ptm_read,
    .write     = ptm_write,
    .ioctl     = ptm_ioctl,
    .init_done = ptm_init_done,
};

#define PTM_OPT(t, p) { t, offsetof(struct ptm_param, p), 1 }

static const struct fuse_opt ptm_opts[] = {
    PTM_OPT("-M %u",      major),
    PTM_OPT("--maj=%u",   major),
    PTM_OPT("-m %u",      minor),
    PTM_OPT("--min=%u",   minor),
    PTM_OPT("-n %s",      dev_name),
    PTM_OPT("--name=%s",  dev_name),
    PTM_OPT("-r %s",      runas),
    PTM_OPT("--runas=%s", runas),
    PTM_OPT("--log %s",   logging),
    PTM_OPT("--key %s",   keydata),
    FUSE_OPT_KEY("-h",        0),
    FUSE_OPT_KEY("--help",    0),
    FUSE_OPT_KEY("-v",        1),
    FUSE_OPT_KEY("--version", 1),
    FUSE_OPT_END
};

static int ptm_process_arg(void *data, const char *arg, int key,
                           struct fuse_args *outargs)
{
    struct ptm_param *param = data;

    switch (key) {
    case 0:
        param->is_help = 1;
        fprintf(stdout, usage, param->prgname);
        return fuse_opt_add_arg(outargs, "-ho");
    case 1:
        param->is_help = 1;
        fprintf(stdout, "TPM emulator CUSE interface version %d.%d.%d, "
                "Copyright (c) 2014 IBM Corp.\n",
                SWTPM_VER_MAJOR,
                SWTPM_VER_MINOR,
                SWTPM_VER_MICRO);
        return 0;
    default:
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    struct ptm_param param = {
        .major = 0,
        .minor = 0,
        .dev_name = NULL,
        .is_help = 0,
        .prgname = argv[0],
        .runas = NULL,
        .logging = NULL,
        .keydata = NULL,
    };
    char dev_name[128] = "DEVNAME=";
    const char *dev_info_argv[] = { dev_name };
    struct cuse_info ci;
    int ret;

    if ((ret = fuse_opt_parse(&args, &param, ptm_opts, ptm_process_arg))) {
        fprintf(stderr, "Error: Could not parse option\n");
        return ret;
    }

    if (!param.is_help) {
        if (!param.dev_name) {
            fprintf(stderr, "Error: device name missing\n");
            return -2;
        }
        strncat(dev_name, param.dev_name, sizeof(dev_name) - 9);
    } else {
        return 0;
    }

    if (handle_log_options(param.logging) < 0 ||
        handle_key_options(param.keydata) < 0)
        return -3;

    if (setuid(0)) {
        fprintf(stderr, "Error: Unable to setuid root\n");
        return -4;
    }

    if (param.runas) {
        if (!(passwd = getpwnam(param.runas))) {
            fprintf(stderr, "User '%s' does not exist\n",
                    param.runas);
            return -5;
        }
    }

    memset(&ci, 0, sizeof(ci));
    ci.dev_major = param.major;
    ci.dev_minor = param.minor;
    ci.dev_info_argc = 1;
    ci.dev_info_argv = dev_info_argv;

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

    return cuse_lowlevel_main(args.argc, args.argv, &ci, &ptm_clop,
                              &param);
}

