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
#include <getopt.h>
#include <pwd.h>
#include <grp.h>
#include <limits.h>
#include <errno.h>
#include <arpa/inet.h>
#include <dirent.h>

#include <fuse/cuse_lowlevel.h>

#include <glib.h>

#include <libtpms/tpm_library.h>
#include <libtpms/tpm_tis.h>
#include <libtpms/tpm_error.h>
#include <libtpms/tpm_memory.h>

#include "swtpm.h"
#include "common.h"
#include "tpmstate.h"
#include "pidfile.h"
#include "locality.h"
#include "logging.h"
#include "tpm_ioctl.h"
#include "swtpm_nvstore.h"
#include "tpmlib.h"
#include "main.h"
#include "utils.h"
#include "threadpool.h"
#include "seccomp_profile.h"
#include "options.h"
#include "capabilities.h"
#include "swtpm_utils.h"

/* maximum size of request buffer */
#define TPM_REQ_MAX 4096

/* version of the TPM (1.2 or 2) */
static TPMLIB_TPMVersion tpmversion;

/* buffer containing the TPM request */
static unsigned char *ptm_request;

/* buffer containing the TPM response */
static unsigned char *ptm_response;

/* offset from where to read from; reset when ptm_response is set */
static size_t ptm_read_offset;

/* the sizes of the data in the buffers */
static uint32_t ptm_req_len, ptm_res_len, ptm_res_tot;

/* locality applied to TPM commands */
static TPM_MODIFIER_INDICATOR locality;

/* whether the TPM is running (TPM_Init was received) */
static bool tpm_running;

/* flags on how to handle locality */
static uint32_t locality_flags;

/* the fuse_session that we will signal an exit to to exit the prg. */
static struct fuse_session *ptm_fuse_session;

#if GLIB_MAJOR_VERSION >= 2
# if GLIB_MINOR_VERSION >= 32

static GMutex file_ops_lock;
#  define FILE_OPS_LOCK &file_ops_lock

# else

static GMutex *file_ops_lock;
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
    char *localitydata;
    char *seccompdata;
    unsigned int seccomp_action;
    char *flagsdata;
    uint16_t startupType;
};

/* single message to send to the worker thread */
static struct thread_message msg;

struct stateblob {
    uint8_t type;
    uint8_t *data;
    uint32_t length;
    TPM_BOOL is_encrypted;
};

typedef struct stateblob_desc {
    uint32_t blobtype;
    TPM_BOOL decrypt;
    TPM_BOOL is_encrypted;
    unsigned char *data;
    uint32_t data_length;
} stateblob_desc;

typedef enum tx_state_type {
    TX_STATE_RW_COMMAND = 1,
    TX_STATE_SET_STATE_BLOB = 2,
    TX_STATE_GET_STATE_BLOB = 3,
} tx_state_type;

typedef struct transfer_state {
    tx_state_type state;
    /* while in TX_STATE_GET/SET_STATEBLOB */
    uint32_t blobtype;
    TPM_BOOL blob_is_encrypted;
    /* while in TX_STATE_GET */
    uint32_t offset;
} transfer_state;

typedef struct TPM_Response_Header {
    uint16_t tag;
    uint32_t paramSize;
    uint32_t returnCode;
} __attribute__ ((packed)) TPM_Response_Header;

/*********************************** data *************************************/

static const char *usage =
"usage: %s %s [options]\n"
"\n"
"The following options are supported:\n"
"\n"
"-n NAME|--name=NAME :  device name (mandatory)\n"
"-M MAJ|--maj=MAJ    :  device major number\n"
"-m MIN|--min=MIN    :  device minor number\n"
"--key file=<path>|fd=<fd>[,mode=aes-cbc|aes-256-cbc][,format=hex|binary][,remove=[true|false]]\n"
"                    :  use an AES key for the encryption of the TPM's state\n"
"                       files; use the given mode for the block encryption;\n"
"                       the key is to be provided as a hex string or in binary\n"
"                       format; the keyfile can be automatically removed using\n"
"                       the remove parameter\n"
"--key pwdfile=<path>|pwdfd=<fd>[,mode=aes-cbc|aes-256-cbc][,remove=[true|false]][,kdf=sha512|pbkdf2]\n"
"                    :  provide a passphrase in a file; the AES key will be\n"
"                       derived from this passphrase; default kdf is PBKDF2\n"
"--locality [reject-locality-4][,allow-set-locality]\n"
"                    :  reject-locality-4: reject any command in locality 4\n"
"                       allow-set-locality: accept SetLocality command\n"
"--migration-key file=<path>|fd=<fd>[,mode=aes-cbc|aes-256-cbc][,format=hex|binary][,remove=[true|false]]\n"
"                    :  use an AES key for the encryption of the TPM's state\n"
"                       when it is retrieved from the TPM via ioctls;\n"
"                       Setting this key ensures that the TPM's state will always\n"
"                       be encrypted when migrated\n"
"--migration-key pwdfile=<path>|pwdfd=<fd>[,mode=aes-cbc|aes-256-cbc][,remove=[true|false]][,kdf=sha512|pbkdf2]\n"
"                    :  provide a passphrase in a file; the AES key will be\n"
"                       derived from this passphrase; default kdf is PBKDF2\n"
"--log file=<path>|fd=<filedescriptor>[,level=n][,prefix=<prefix>][,truncate]\n"
"                    :  write the TPM's log into the given file rather than\n"
"                       to the console; provide '-' for path to avoid logging\n"
"                       log level 5 and higher will enable libtpms logging;\n"
"                       all logged output will be prefixed with prefix;\n"
"                       the log file can be reset (truncate)\n"
"--pid file=<path>|fd=<filedescriptor>\n"
"                    :  write the process ID into the given file\n"
"--tpmstate dir=<dir>[,mode=0...]|backend-uri=<uri>\n"
"                    :  set the directory or uri where the TPM's state will be written\n"
"                       into; the TPM_PATH environment variable can be used\n"
"                       instead of dir option;\n"
"                       mode allows a user to set the file mode bits of the state\n"
"                       files; the default mode is 0640;\n"
"--flags [not-need-init][,startup-clear|startup-state|startup-deactivated|startup-none]\n"
"                    :  not-need-init: commands can be sent without needing to\n"
"                       send an INIT via control channel;\n"
"                       startup-...: send Startup command with this type;\n"
"-r|--runas <user>   :  after creating the CUSE device, change to the given\n"
"                       user\n"
"--tpm2              :  choose TPM2 functionality\n"
#ifdef WITH_SECCOMP
# ifndef SCMP_ACT_LOG
"--seccomp action=none|kill\n"
# else
"--seccomp action=none|kill|log\n"
# endif
"                    :  Choose the action of the seccomp profile when a\n"
"                       blacklisted syscall is executed; default is kill\n"
#endif
"--print-capabilites : print capabilities and terminate\n"
"--print-states      : print existing TPM states and terminate\n"
"-h|--help           :  display this help screen and terminate\n"
"\n";

static TPM_RESULT
ptm_io_getlocality(TPM_MODIFIER_INDICATOR *loc,
                   uint32_t tpmnum SWTPM_ATTR_UNUSED)
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

/* the current state the transfer interface is in */
static transfer_state tx_state;

/* function prototypes */
static void ptm_cleanup(void);

/************************* cached stateblob *********************************/

static stateblob_desc cached_stateblob;

/*
 * cached_stateblob_is_loaded: is the stateblob with the given properties
 *                             the one in the cache?
 */
static bool cached_stateblob_is_loaded(uint32_t blobtype,
                                       TPM_BOOL decrypt)
{
    return (cached_stateblob.data != NULL) &&
           (cached_stateblob.blobtype == blobtype) &&
           (cached_stateblob.decrypt == decrypt);
}

/*
 * cached_stateblob_free: Free any previously loaded state blob
 */
static void cached_stateblob_free(void)
{
    free(cached_stateblob.data);
    cached_stateblob.data = NULL;
    cached_stateblob.data_length = 0;
}

/*
 * cached_stateblob_get_bloblength: get the total length of the cached blob
 */
static uint32_t cached_stateblob_get_bloblength(void)
{
    return cached_stateblob.data_length;
}

/*
 * cached_statblob_get: get stateblob data without copying them
 *
 * @offset: at which offset to get the data
 * @bufptr: pointer to a buffer pointer used to return buffer start
 * @length: pointer used to return number of available bytes in returned buffer
 */
static int cached_stateblob_get(uint32_t offset,
                                unsigned char **bufptr, size_t *length)
{
    if (cached_stateblob.data == NULL ||
        offset > cached_stateblob.data_length)
        return -1;

    *bufptr = &cached_stateblob.data[offset];
    *length = cached_stateblob.data_length - offset;

    return 0;
}

/*
 * cached_stateblob_load: load a state blob into the cache
 *
 * blobtype: the type of blob
 * decrypt: whether the blob is to be decrypted
 */
static TPM_RESULT cached_stateblob_load(uint32_t blobtype, TPM_BOOL decrypt)
{
    TPM_RESULT res = 0;
    const char *blobname = tpmlib_get_blobname(blobtype);
    uint32_t tpm_number = 0;

    if (!blobname)
        return TPM_BAD_PARAMETER;

    cached_stateblob_free();

    if (blobtype == PTM_BLOB_TYPE_VOLATILE)
        res = SWTPM_NVRAM_Store_Volatile();

    if (res == 0)
        res = SWTPM_NVRAM_GetStateBlob(&cached_stateblob.data,
                                       &cached_stateblob.data_length,
                                       tpm_number, blobname, decrypt,
                                       &cached_stateblob.is_encrypted);

    /* make sure the volatile state file is gone */
    if (blobtype == PTM_BLOB_TYPE_VOLATILE)
        SWTPM_NVRAM_DeleteName(tpm_number, blobname, FALSE);

    if (res == 0) {
        cached_stateblob.blobtype = blobtype;
        cached_stateblob.decrypt = decrypt;
    }

    return res;
}

/*
 * cached_state_blob_copy: copy the cached state blob to a destination buffer
 *
 * dest: destination buffer
 * destlen: size of the buffer
 * srcoffset: offset to copy from
 * copied: variable to return the number of copied bytes
 * is_encrypted: variable to return whether the blob is encrypted
 */
static int cached_stateblob_copy(void *dest, size_t destlen,
                                 uint32_t srcoffset, uint32_t *copied,
                                 TPM_BOOL *is_encrypted)
{
    int ret = -1;

    *copied = 0;

    if (cached_stateblob.data != NULL && cached_stateblob.data_length > 0) {

        if (srcoffset < cached_stateblob.data_length) {
            *copied = min(cached_stateblob.data_length - srcoffset, destlen);

            memcpy(dest, &cached_stateblob.data[srcoffset], *copied);

            *is_encrypted = cached_stateblob.is_encrypted;
        }

        ret = 0;
    }

    return ret;
}

/************************* worker thread ************************************/

/*
 * worker_thread: the worker thread
 */
static void worker_thread(gpointer data, gpointer user_data SWTPM_ATTR_UNUSED)
{
    struct thread_message *msg = (struct thread_message *)data;

    switch (msg->type) {
    case MESSAGE_TPM_CMD:
        TPMLIB_Process(&ptm_response, &ptm_res_len, &ptm_res_tot,
                       ptm_request, ptm_req_len);
        ptm_read_offset = 0;
        break;
    case MESSAGE_IOCTL:
        break;
    }

    /* results are ready */
    worker_thread_mark_done();
}

/***************************** utility functions ****************************/

/*
 * tpm_start: Start the TPM
 *
 * Check whether the TPM's state directory exists and if it does
 * not exists, try to creat it. Start the thread pool, initilize
 * libtpms and allocate a global TPM request buffer.
 *
 * @flags: libtpms init flags
 * @l_tpmversion: the version of the TPM
 * @res: the result from starting the TPM
 */
static int tpm_start(uint32_t flags, TPMLIB_TPMVersion l_tpmversion,
                     TPM_RESULT *res)
{
    DIR *dir;
    const char *uri = tpmstate_get_backend_uri();
    const char *tpmdir = uri + strlen("dir://");

    *res = TPM_FAIL;

    dir = opendir(tpmdir);
    if (dir) {
        closedir(dir);
    } else {
        if (mkdir(tpmdir, 0775)) {
            logprintf(STDERR_FILENO,
                      "Error: Could not open tpmstate dir %s\n",
                      tpmdir);
            return -1;
        }
    }

    pool = g_thread_pool_new(worker_thread,
                             NULL,
                             1,
                             FALSE,
                             NULL);
    if (!pool) {
        logprintf(STDERR_FILENO,
                  "Error: Could not create the thread pool.\n");
        return -1;
    }

    if(!ptm_request)
        ptm_request = malloc(4096);
    if(!ptm_request) {
        logprintf(STDERR_FILENO,
                  "Error: Could not allocate memory for request buffer.\n");
        goto error_del_pool;
    }

    *res = tpmlib_start(flags, l_tpmversion);
    if (*res != TPM_SUCCESS)
        goto error_del_pool;

    logprintf(STDOUT_FILENO,
              "CUSE TPM successfully initialized.\n");

    return 0;

error_del_pool:
    g_thread_pool_free(pool, TRUE, TRUE);
    pool = NULL;

    return -1;
}

/*
 * ptm_write_fatal_error_response: Write fatal error response
 *
 * Write a fatal error response into the global ptm_response buffer.
 */
static void ptm_write_fatal_error_response(TPMLIB_TPMVersion l_tpmversion)
{
    tpmlib_write_fatal_error_response(&ptm_response,
                                      &ptm_res_len,
                                      &ptm_res_tot,
                                      l_tpmversion);
    ptm_read_offset = 0;
}

/*
 * ptm_send_startup: Send a TPM/TPM2_Startup
 */
static int ptm_send_startup(uint16_t startupType,
                            TPMLIB_TPMVersion l_tpmversion SWTPM_ATTR_UNUSED)
{
    uint32_t command_length;
    unsigned char command[sizeof(struct tpm_startup)];
    uint32_t max_command_length = sizeof(command);
    int ret = 0;
    TPM_RESULT rc = TPM_SUCCESS;

    command_length = tpmlib_create_startup_cmd(
                               startupType,
                               tpmversion,
                               command, max_command_length);
    if (command_length > 0) {
        rc = TPMLIB_Process(&ptm_response, &ptm_res_len, &ptm_res_tot,
                           (unsigned char *)command, command_length);
        ptm_read_offset = 0;
    }

    if (rc || command_length == 0) {
        if (rc) {
            logprintf(STDERR_FILENO, "Could not send Startup: 0x%x\n", rc);
            ret = -1;
        }
    }

    return ret;
}

/************************************ read() support ***************************/

/*
 * ptm_read_result: Return the TPM response packet
 *
 * @req: the fuse_req_t
 * @size: the max. number of bytes to return to the requester
 */
static void ptm_read_result(fuse_req_t req, size_t size)
{
    size_t len = 0;

    if (tpm_running) {
        /* wait until results are ready */
        worker_thread_wait_done();
    }

    if (ptm_read_offset < ptm_res_len) {
        len = ptm_res_len - ptm_read_offset;
        if (size < len)
           len = size;
    }

    fuse_reply_buf(req, (const char *)&ptm_response[ptm_read_offset], len);

    ptm_read_offset += len;
}

/*
 * ptm_read_stateblob: get a TPM stateblob via the read() interface
 *
 * @req: the fuse_req_t
 * @size: the number of bytes to read
 *
 * The internal offset into the buffer is advanced by the number
 * of bytes that were copied. We switch back to command read/write
 * mode if an error occurred or once all bytes were read.
 */
static void ptm_read_stateblob(fuse_req_t req, size_t size)
{
    unsigned char *bufptr = NULL;
    size_t numbytes;
    size_t tocopy;

    if (cached_stateblob_get(tx_state.offset, &bufptr, &numbytes) < 0) {
        fuse_reply_err(req, EIO);
        tx_state.state = TX_STATE_RW_COMMAND;
    } else {
        tocopy = MIN(size, numbytes);
        tx_state.offset += tocopy;

        fuse_reply_buf(req, (char *)bufptr, tocopy);
        /* last transfer indicated by less bytes available than requested */
        if (numbytes < size) {
            tx_state.state = TX_STATE_RW_COMMAND;
        }
    }
}

/*
 * ptm_read: interface to POSIX read()
 *
 * @req: fuse_req_t
 * @size: number of bytes to read
 * @off: offset (not used)
 * @fi: fuse_file_info (not used)
 *
 * Depending on the current state of the transfer interface (read/write)
 * return either the results of TPM commands or a data of a TPM state blob.
 */
static void ptm_read(fuse_req_t req, size_t size, off_t off SWTPM_ATTR_UNUSED,
                     struct fuse_file_info *fi SWTPM_ATTR_UNUSED)
{
    switch (tx_state.state) {
    case TX_STATE_RW_COMMAND:
        ptm_read_result(req, size);
        break;
    case TX_STATE_SET_STATE_BLOB:
        fuse_reply_err(req, EIO);
        tx_state.state = TX_STATE_RW_COMMAND;
        break;
    case TX_STATE_GET_STATE_BLOB:
        ptm_read_stateblob(req, size);
        break;
    }
}

/*************************read/write stateblob support ***********************/

/*
 * ptm_set_stateblob_append: Append a piece of TPM state blob and transfer to TPM
 *
 * blobtype: the type of blob
 * data: the data to append
 * length: length of the data
 * is_encrypted: whether the blob is encrypted
 * is_last: whether this is the last part of the TPM state blob; if it is, the TPM
 *          state blob will then be transferred to the TPM
 */
static TPM_RESULT
ptm_set_stateblob_append(uint32_t blobtype,
                         const unsigned char *data, uint32_t length,
                         bool is_encrypted, bool is_last)
{
    TPM_RESULT res = 0;
    static struct stateblob stateblob;
    unsigned char *tmp;

    if (stateblob.type != blobtype) {
        /* new blob; clear old data */
        free(stateblob.data);
        stateblob.data = NULL;
        stateblob.length = 0;
        stateblob.type = blobtype;
        stateblob.is_encrypted = is_encrypted;

        /*
         * on the first call for a new state blob we allow 0 bytes to be written
         * this allows the user to transfer via write()
         */
        if (length == 0)
            return 0;
    }

    /* append */
    tmp = realloc(stateblob.data, stateblob.length + length);
    if (!tmp) {
        logprintf(STDERR_FILENO,
                  "Could not allocate %u bytes.\n", stateblob.length + length);
        /* error */
        free(stateblob.data);
        stateblob.data = NULL;
        stateblob.length = 0;
        stateblob.type = 0;

        return TPM_FAIL;
    } else
        stateblob.data = tmp;

    memcpy(&stateblob.data[stateblob.length], data, length);
    stateblob.length += length;

    if (!is_last) {
        /* full packet -- expecting more data */
        return res;
    }

    res = SWTPM_NVRAM_SetStateBlob(stateblob.data,
                                   stateblob.length,
                                   stateblob.is_encrypted,
                                   0 /* tpm_number */,
                                   blobtype);

    logprintf(STDERR_FILENO,
              "Deserialized state type %d (%s), length=%d, res=%d\n",
              blobtype, tpmlib_get_blobname(blobtype),
              stateblob.length, res);

    free(stateblob.data);
    stateblob.data = NULL;
    stateblob.length = 0;
    stateblob.type = 0;

    /* transfer of blob is complete */
    tx_state.state = TX_STATE_RW_COMMAND;

    return res;
}

/*
 * ptm_set_stateblob: set part of a TPM state blob
 *
 * @req: fuse_req_t
 * pss: ptm_setstate provided via ioctl()
 */
static void
ptm_set_stateblob(fuse_req_t req, ptm_setstate *pss)
{
    TPM_RESULT res = 0;
    TPM_BOOL is_encrypted =
        ((pss->u.req.state_flags & PTM_STATE_FLAG_ENCRYPTED) != 0);
    bool is_last = (sizeof(pss->u.req.data) != pss->u.req.length);

    if (pss->u.req.length > sizeof(pss->u.req.data)) {
        res = TPM_BAD_PARAMETER;
        goto send_response;
    }

    /* transfer of blob initiated */
    tx_state.state = TX_STATE_SET_STATE_BLOB;
    tx_state.blobtype = pss->u.req.type;
    tx_state.blob_is_encrypted = is_encrypted;
    tx_state.offset = 0;

    res = ptm_set_stateblob_append(pss->u.req.type,
                                   pss->u.req.data,
                                   pss->u.req.length,
                                   is_encrypted,
                                   is_last);

    if (res)
        tx_state.state = TX_STATE_RW_COMMAND;

 send_response:
    pss->u.resp.tpm_result = res;

    fuse_reply_ioctl(req, 0, pss, sizeof(*pss));
}

/*
 * ptm_get_stateblob_part: get part of a state blob
 *
 * @blobtype: the type of blob to get
 * @buffer: the buffer this function will write the blob into
 * @buffer_size: the size of the buffer
 * @offset: the offset into the state blob
 * @copied: pointer to int to indicate the number of bytes that were copied
 * @is_encryped: returns whether the state blob is encrypted
 */
static TPM_RESULT
ptm_get_stateblob_part(uint32_t blobtype,
                       unsigned char *buffer, size_t buffer_size,
                       uint32_t offset, uint32_t *copied,
                       TPM_BOOL decrypt, TPM_BOOL *is_encrypted)
{
    TPM_RESULT res = 0;

    if (!cached_stateblob_is_loaded(blobtype, decrypt)) {
        res = cached_stateblob_load(blobtype, decrypt);
    }

    if (res == 0) {
        cached_stateblob_copy(buffer, buffer_size,
                              offset, copied, is_encrypted);
    }

    return res;
}

/*
 * ptm_get_stateblob: Get the state blob from the TPM using ioctl()
 */
static void
ptm_get_stateblob(fuse_req_t req, ptm_getstate *pgs)
{
    TPM_RESULT res = 0;
    uint32_t blobtype = pgs->u.req.type;
    TPM_BOOL decrypt =
        ((pgs->u.req.state_flags & PTM_STATE_FLAG_DECRYPTED) != 0);
    TPM_BOOL is_encrypted = FALSE;
    uint32_t copied = 0;
    uint32_t offset = pgs->u.req.offset;
    uint32_t totlength;

    res = ptm_get_stateblob_part(blobtype,
                                 pgs->u.resp.data, sizeof(pgs->u.resp.data),
                                 pgs->u.req.offset, &copied,
                                 decrypt, &is_encrypted);

    totlength = cached_stateblob_get_bloblength();

    pgs->u.resp.state_flags = 0;
    if (is_encrypted)
        pgs->u.resp.state_flags |= PTM_STATE_FLAG_ENCRYPTED;

    pgs->u.resp.length = copied;
    pgs->u.resp.totlength = totlength;
    pgs->u.resp.tpm_result = res;
    logprintf(STDERR_FILENO,
              "Serialized state type %d, length=%d, totlength=%d, res=%d\n",
              blobtype, copied, totlength, res);

    if (res == 0) {
        if (offset + copied < totlength) {
            /* last byte was not copied */
            tx_state.state = TX_STATE_GET_STATE_BLOB;
            tx_state.blobtype = pgs->u.req.type;
            tx_state.blob_is_encrypted = is_encrypted;
            tx_state.offset = copied;
        } else {
            /* last byte was copied */
            tx_state.state = TX_STATE_RW_COMMAND;
        }
    } else {
        /* error occurred */
        tx_state.state = TX_STATE_RW_COMMAND;
    }

    fuse_reply_ioctl(req, 0, pgs, sizeof(pgs->u.resp));
}

/*********************************** write() support *************************/

/*
 * ptm_write_stateblob: Write the state blob using the write() interface
 *
 * @req: the fuse_req_t
 * @buf: the buffer with the data
 * @size: the number of bytes in the buffer
 *
 * The data are appended to an existing buffer that was created with the
 * initial ioctl().
 */
static void ptm_write_stateblob(fuse_req_t req, const char *buf, size_t size)
{
    TPM_RESULT res;

    res = ptm_set_stateblob_append(tx_state.blobtype,
                                   (unsigned char *)buf, size,
                                   tx_state.blob_is_encrypted,
                                   (size == 0));
    if (res) {
        tx_state.state = TX_STATE_RW_COMMAND;
        fuse_reply_err(req, EIO);
    } else {
        fuse_reply_write(req, size);
    }
}

/*
 * ptm_write_cmd: User writing a TPM command
 *
 * req: fuse_req_t
 * buf: the buffer containing the TPM command
 * size: the size of the buffer
 * tpmversion: the version of the TPM
 */
static void ptm_write_cmd(fuse_req_t req, const char *buf, size_t size,
                          TPMLIB_TPMVersion l_tpmversion)
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

        if (ptm_req_len > TPM_REQ_MAX)
            ptm_req_len = TPM_REQ_MAX;

        /* process SetLocality command, if */
        tpmlib_process(&ptm_response, &ptm_res_len, &ptm_res_tot,
                       (unsigned char *)buf, ptm_req_len,
                       locality_flags, &locality, tpmversion);
        if (ptm_res_len) {
            ptm_read_offset = 0;
            goto skip_process;
        }

        if (tpmlib_is_request_cancelable(l_tpmversion,
                                         (const unsigned char*)buf,
                                         ptm_req_len)) {
            /* have command processed by thread pool */
            memcpy(ptm_request, buf, ptm_req_len);

            msg.type = MESSAGE_TPM_CMD;

            worker_thread_mark_busy();

            g_thread_pool_push(pool, &msg, NULL);
        } else {
            /* direct processing */
            TPMLIB_Process(&ptm_response, &ptm_res_len, &ptm_res_tot,
                           (unsigned char *)buf, ptm_req_len);
            ptm_read_offset = 0;
        }
    } else {
        /* TPM not initialized; return error */
        ptm_write_fatal_error_response(l_tpmversion);
    }

skip_process:
    fuse_reply_write(req, ptm_req_len);

cleanup:
    g_mutex_unlock(FILE_OPS_LOCK);

    return;
}

/*
 * ptm_write: low-level write() interface; calls approriate function depending
 *            on what is being transferred using the write()
 */
static void ptm_write(fuse_req_t req, const char *buf, size_t size,
                      off_t off SWTPM_ATTR_UNUSED,
                      struct fuse_file_info *fi SWTPM_ATTR_UNUSED)
{
    switch (tx_state.state) {
    case TX_STATE_RW_COMMAND:
        ptm_write_cmd(req, buf, size, tpmversion);
        break;
    case TX_STATE_GET_STATE_BLOB:
        fuse_reply_err(req, EIO);
        tx_state.state = TX_STATE_RW_COMMAND;
        break;
    case TX_STATE_SET_STATE_BLOB:
        ptm_write_stateblob(req, buf, size);
        break;
    }
}

/*
 * ptm_open: interface to POSIX open()
 */
static void ptm_open(fuse_req_t req, struct fuse_file_info *fi)
{
    tx_state.state = TX_STATE_RW_COMMAND;

    fuse_reply_open(req, fi);
}

/*
 * ptm_ioctl : ioctl execution
 *
 * req: the fuse_req_t used to send response with
 * cmd: the ioctl request code
 * arg: the pointer the application used for calling the ioctl (3rd param)
 * fi:
 * flags: some flags provided by fuse
 * in_buf: the copy of the input buffer
 * in_bufsz: size of the input buffer; provided by fuse and has size of
 *           needed buffer
 * out_bufsz: size of the output buffer; provided by fuse and has size of
 *            needed buffer
 */
static void ptm_ioctl(fuse_req_t req, int cmd, void *arg,
                      struct fuse_file_info *fi SWTPM_ATTR_UNUSED,
                      unsigned flags SWTPM_ATTR_UNUSED,
                      const void *in_buf, size_t in_bufsz, size_t out_bufsz)
{
    TPM_RESULT res = TPM_FAIL;
    bool exit_prg = FALSE;
    ptm_init *init_p;
    TPM_MODIFIER_INDICATOR orig_locality;

    /* some commands have to wait until the worker thread is done */
    switch(cmd) {
    case PTM_GET_CAPABILITY:
    case PTM_SET_LOCALITY:
    case PTM_CANCEL_TPM_CMD:
    case PTM_GET_CONFIG:
    case PTM_SET_BUFFERSIZE:
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
        if (out_bufsz != sizeof(ptm_cap)) {
            struct iovec iov = { arg, sizeof(uint8_t) };
            fuse_reply_ioctl_retry(req, &iov, 1, NULL, 0);
        } else {
            ptm_cap ptm_caps;
            switch (tpmversion) {
            case TPMLIB_TPM_VERSION_2:
                ptm_caps = PTM_CAP_INIT | PTM_CAP_SHUTDOWN
                    | PTM_CAP_GET_TPMESTABLISHED
                    | PTM_CAP_SET_LOCALITY
                    | PTM_CAP_HASHING
                    | PTM_CAP_CANCEL_TPM_CMD
                    | PTM_CAP_STORE_VOLATILE
                    | PTM_CAP_RESET_TPMESTABLISHED
                    | PTM_CAP_GET_STATEBLOB
                    | PTM_CAP_SET_STATEBLOB
                    | PTM_CAP_STOP
                    | PTM_CAP_GET_CONFIG
                    | PTM_CAP_SET_BUFFERSIZE
                    | PTM_CAP_GET_INFO;
                break;
            case TPMLIB_TPM_VERSION_1_2:
                ptm_caps = PTM_CAP_INIT | PTM_CAP_SHUTDOWN
                    | PTM_CAP_GET_TPMESTABLISHED
                    | PTM_CAP_SET_LOCALITY
                    | PTM_CAP_HASHING
                    | PTM_CAP_CANCEL_TPM_CMD
                    | PTM_CAP_STORE_VOLATILE
                    | PTM_CAP_RESET_TPMESTABLISHED
                    | PTM_CAP_GET_STATEBLOB
                    | PTM_CAP_SET_STATEBLOB
                    | PTM_CAP_STOP
                    | PTM_CAP_GET_CONFIG
                    | PTM_CAP_SET_BUFFERSIZE
                    | PTM_CAP_GET_INFO;
                break;
            }
            fuse_reply_ioctl(req, 0, &ptm_caps, sizeof(ptm_caps));
        }
        break;

    case PTM_INIT:
        if (in_bufsz != sizeof(ptm_init)) {
            struct iovec iov = { arg, sizeof(uint8_t) };
            fuse_reply_ioctl_retry(req, &iov, 1, NULL, 0);
        } else {
            init_p = (ptm_init *)in_buf;

            worker_thread_end();

            TPMLIB_Terminate();

            tpm_running = false;
            if (tpm_start(init_p->u.req.init_flags, tpmversion, &res) < 0) {
                logprintf(STDERR_FILENO,
                          "Error: Could not initialize the TPM.\n");
            } else {
                tpm_running = true;
            }
            init_p->u.resp.tpm_result = res;
            fuse_reply_ioctl(req, 0, init_p, sizeof(*init_p));
        }
        break;

    case PTM_STOP:
        worker_thread_end();

        res = TPM_SUCCESS;
        TPMLIB_Terminate();

        tpm_running = false;

        free(ptm_response);
        ptm_response = NULL;

        fuse_reply_ioctl(req, 0, &res, sizeof(res));

        break;

    case PTM_SHUTDOWN:
        worker_thread_end();

        res = TPM_SUCCESS;
        TPMLIB_Terminate();

        free(ptm_response);
        ptm_response = NULL;

        fuse_reply_ioctl(req, 0, &res, sizeof(res));
        exit_prg = TRUE;

        break;

    case PTM_GET_TPMESTABLISHED:
        if (!tpm_running)
            goto error_not_running;

        if (out_bufsz != sizeof(ptm_est)) {
            struct iovec iov = { arg, sizeof(uint8_t) };
            fuse_reply_ioctl_retry(req, &iov, 1, NULL, 0);
        } else {
            ptm_est te;
            memset(&te, 0, sizeof(te));
            te.u.resp.tpm_result = TPM_IO_TpmEstablished_Get(&te.u.resp.bit);
            fuse_reply_ioctl(req, 0, &te, sizeof(te));
        }
        break;

    case PTM_RESET_TPMESTABLISHED:
        if (!tpm_running)
            goto error_not_running;

        if (in_bufsz != sizeof(ptm_reset_est)) {
            struct iovec iov = { arg, sizeof(uint32_t) };
            fuse_reply_ioctl_retry(req, &iov, 1, NULL, 0);
        } else {
            ptm_reset_est *re = (ptm_reset_est *)in_buf;
            if (re->u.req.loc > 4) {
                res = TPM_BAD_LOCALITY;
            } else {
                /* set locality and reset flag in one command */
                orig_locality = locality;
                locality = re->u.req.loc;

                res = TPM_IO_TpmEstablished_Reset();

                locality = orig_locality;
                fuse_reply_ioctl(req, 0, &res, sizeof(res));
            }
        }
        break;

    case PTM_SET_LOCALITY:
        if (in_bufsz != sizeof(ptm_loc)) {
            struct iovec iov = { arg, sizeof(uint32_t) };
            fuse_reply_ioctl_retry(req, &iov, 1, NULL, 0);
        } else {
            ptm_loc *l = (ptm_loc *)in_buf;
            if (l->u.req.loc > 4 ||
                (l->u.req.loc == 4 &&
                 locality_flags & LOCALITY_FLAG_REJECT_LOCALITY_4)) {
                res = TPM_BAD_LOCALITY;
            } else {
                res = TPM_SUCCESS;
                locality = l->u.req.loc;
            }
            l->u.resp.tpm_result = res;
            fuse_reply_ioctl(req, 0, l, sizeof(*l));
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

        if (in_bufsz != sizeof(ptm_hdata)) {
            struct iovec iov = { arg, sizeof(uint32_t) };
            fuse_reply_ioctl_retry(req, &iov, 1, NULL, 0);
        } else {
            ptm_hdata *data = (ptm_hdata *)in_buf;
            if (data->u.req.length <= sizeof(data->u.req.data)) {
                res = TPM_IO_Hash_Data(data->u.req.data,
                                       data->u.req.length);
            } else {
                res = TPM_FAIL;
            }
            data->u.resp.tpm_result = res;
            fuse_reply_ioctl(req, 0, data, sizeof(*data));
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
        res = TPMLIB_CancelCommand();
        fuse_reply_ioctl(req, 0, &res, sizeof(res));
        break;

    case PTM_STORE_VOLATILE:
        if (!tpm_running)
            goto error_not_running;

        res = SWTPM_NVRAM_Store_Volatile();
        fuse_reply_ioctl(req, 0, &res, sizeof(res));

        cached_stateblob_free();
        break;

    case PTM_GET_STATEBLOB:
        if (!tpm_running)
            goto error_not_running;

        if (in_bufsz != sizeof(ptm_getstate)) {
            struct iovec iov = { arg, sizeof(uint32_t) };
            fuse_reply_ioctl_retry(req, &iov, 1, NULL, 0);
        } else {
            ptm_get_stateblob(req, (ptm_getstate *)in_buf);
        }
        break;

    case PTM_SET_STATEBLOB:
        if (tpm_running)
            goto error_running;

        /* tpm state dir must be set */
        SWTPM_NVRAM_Init();

        if (in_bufsz != sizeof(ptm_setstate)) {
            struct iovec iov = { arg, sizeof(uint32_t) };
            fuse_reply_ioctl_retry(req, &iov, 1, NULL, 0);
        } else {
            ptm_set_stateblob(req, (ptm_setstate *)in_buf);
        }
        break;

    case PTM_GET_CONFIG:
        if (out_bufsz != sizeof(ptm_getconfig)) {
            struct iovec iov = { arg, sizeof(uint32_t) };
            fuse_reply_ioctl_retry(req, &iov, 1, NULL, 0);
        } else {
            ptm_getconfig pgs;
            pgs.u.resp.tpm_result = 0;
            pgs.u.resp.flags = 0;
            if (SWTPM_NVRAM_Has_FileKey())
                pgs.u.resp.flags |= PTM_CONFIG_FLAG_FILE_KEY;
            if (SWTPM_NVRAM_Has_MigrationKey())
                pgs.u.resp.flags |= PTM_CONFIG_FLAG_MIGRATION_KEY;
            fuse_reply_ioctl(req, 0, &pgs, sizeof(pgs));
        }
        break;

    case PTM_SET_BUFFERSIZE:
        if (out_bufsz != sizeof(ptm_setbuffersize)) {
            struct iovec iov = { arg, sizeof(uint32_t) };
            fuse_reply_ioctl_retry(req, &iov, 1, NULL, 0);
        } else {
            ptm_setbuffersize *in_psbs = (ptm_setbuffersize *)in_buf;
            ptm_setbuffersize out_psbs;
            uint32_t buffersize, minsize, maxsize;

            buffersize = in_psbs->u.req.buffersize;

            if (buffersize > 0 && tpm_running)
                goto error_running;

            buffersize = TPMLIB_SetBufferSize(buffersize,
                                              &minsize,
                                              &maxsize);

            out_psbs.u.resp.tpm_result = TPM_SUCCESS;
            out_psbs.u.resp.buffersize = buffersize;
            out_psbs.u.resp.minsize = minsize;
            out_psbs.u.resp.maxsize = maxsize;
            fuse_reply_ioctl(req, 0, &out_psbs, sizeof(out_psbs));
        }
        break;

    case PTM_GET_INFO:
        if (out_bufsz != sizeof(ptm_getinfo)) {
            struct iovec iov = { arg, sizeof(uint32_t) };
            fuse_reply_ioctl_retry(req, &iov, 1, NULL, 0);
        } else {
            ptm_getinfo *in_pgi = (ptm_getinfo *)in_buf;
            ptm_getinfo out_pgi;
            char *info_data;
            uint32_t length, offset;

            info_data = TPMLIB_GetInfo(in_pgi->u.req.flags);
            if (!info_data)
                goto error_memory;

            offset = in_pgi->u.req.offset;
            if (offset >= strlen(info_data)) {
                free(info_data);
                goto error_bad_input;
            }

            length = min(strlen(info_data) + 1 - offset,
                         sizeof(out_pgi.u.resp.buffer));

            out_pgi.u.resp.tpm_result = 0;
            out_pgi.u.resp.totlength = strlen(info_data) + 1;
            out_pgi.u.resp.length = length;
            /* client has to collect whole string in case buffer is too small */
            memcpy(out_pgi.u.resp.buffer, &info_data[offset], length);
            free(info_data);

            fuse_reply_ioctl(req, 0, &out_pgi, sizeof(out_pgi));
        }
        break;

    default:
        fuse_reply_err(req, EINVAL);
    }

cleanup:
    g_mutex_unlock(FILE_OPS_LOCK);

    if (exit_prg) {
        logprintf(STDOUT_FILENO, "CUSE TPM is shutting down.\n");
        ptm_cleanup();
        fuse_session_exit(ptm_fuse_session);
    }

    return;

error_bad_input:
    res = TPM_BAD_PARAMETER;
    fuse_reply_ioctl(req, 0, &res, sizeof(res));

    goto cleanup;

error_running:
error_not_running:
    res = TPM_BAD_ORDINAL;
    fuse_reply_ioctl(req, 0, &res, sizeof(res));

    goto cleanup;

error_memory:
    res = TPM_SIZE;
    fuse_reply_ioctl(req, 0, &res, sizeof(res));

    goto cleanup;
}

static void ptm_init_done(void *userdata)
{
    struct cuse_param *param = userdata;
    int ret;

    /* at this point the entry in /dev/ is available */
    if (pidfile_write(getpid()) < 0) {
        ret = -13;
        goto error_exit;
    }

    if (param->runas) {
        ret = change_process_owner(param->runas);
        if (ret)
            goto error_exit;
    }

    if (create_seccomp_profile(true, param->seccomp_action) < 0) {
        ret = -14;
        goto error_exit;
    }

    return;

error_exit:
    ptm_cleanup();

    exit(ret);
}

static void ptm_cleanup(void)
{
    pidfile_remove();
    log_global_free();
    tpmstate_global_free();
    SWTPM_NVRAM_Shutdown();
}

static const struct cuse_lowlevel_ops clops = {
    .open = ptm_open,
    .read = ptm_read,
    .write = ptm_write,
    .ioctl = ptm_ioctl,
    .init_done = ptm_init_done,
};

/* ptm_cuse_lowlevel_main is like cuse_lowlevel_main with the difference that
 * it uses a global ptm_fuse_session so we can call fuse_session_exit() on it
 * for a graceful exit with cleanups.
 */
static int
ptm_cuse_lowlevel_main(int argc, char *argv[], const struct cuse_info *ci,
                       const struct cuse_lowlevel_ops *clop, void *userdata)
{
    int mt;
    int ret;
    struct cuse_param *param = userdata;

    ptm_fuse_session = cuse_lowlevel_setup(argc, argv, ci, clop, &mt,
                                           userdata);
    if (ptm_fuse_session == NULL)
        return 1;

    if (param->seccomp_action == SWTPM_SECCOMP_ACTION_NONE && mt)
        ret = fuse_session_loop_mt(ptm_fuse_session);
    else
        ret = fuse_session_loop(ptm_fuse_session);

    cuse_lowlevel_teardown(ptm_fuse_session);
    if (ret < 0)
        ret = 1;

    return ret;
}

#ifndef HAVE_SWTPM_CUSE_MAIN
int main(int argc, char **argv)
{
    const char *prgname = argv[0];
    const char *iface = "";
#else
int swtpm_cuse_main(int argc, char **argv, const char *prgname, const char *iface)
{
#endif
    int opt, longindex = 0;
    static struct option longopts[] = {
        {"maj"           , required_argument, 0, 'M'},
        {"min"           , required_argument, 0, 'm'},
        {"name"          , required_argument, 0, 'n'},
        {"runas"         , required_argument, 0, 'r'},
        {"log"           , required_argument, 0, 'l'},
        {"locality"      , required_argument, 0, 'L'},
        {"key"           , required_argument, 0, 'k'},
        {"migration-key" , required_argument, 0, 'K'},
        {"pid"           , required_argument, 0, 'p'},
        {"tpmstate"      , required_argument, 0, 's'},
        {"flags"         , required_argument, 0, 'F'},
        {"tpm2"          ,       no_argument, 0, '2'},
        {"help"          ,       no_argument, 0, 'h'},
        {"version"       ,       no_argument, 0, 'v'},
#ifdef WITH_SECCOMP
        {"seccomp"       , required_argument, 0, 'S'},
#endif
        {"print-capabilities"
                         ,       no_argument, 0, 'a'},
        {"print-states"  ,       no_argument, 0, 'e'},
        {NULL            , 0                , 0, 0  },
    };
    struct cuse_info cinfo;
    struct cuse_param param = {
        .startupType = _TPM_ST_NONE,
    };
    const char *devname = NULL;
    char *cinfo_argv[1] = { 0 };
    unsigned int num;
    struct passwd *passwd;
    const char *uri = NULL;
    int n, tpmfd;
    char path[PATH_MAX];
    int ret = 0;
    bool printcapabilities = false;
    bool printstates = false;
    bool need_init_cmd = true;
    TPM_RESULT res;

    memset(&cinfo, 0, sizeof(cinfo));
    memset(&param, 0, sizeof(param));

    log_set_prefix("swtpm: ");

    tpmversion = TPMLIB_TPM_VERSION_1_2;

    while (true) {
        opt = getopt_long(argc, argv, "M:m:n:r:hv", longopts, &longindex);

        if (opt == -1)
            break;

        switch (opt) {
        case 'M': /* major */
            if (sscanf(optarg, "%u", &num) != 1) {
                logprintf(STDERR_FILENO, "Could not parse major number\n");
                ret = -1;
                goto exit;
            }
            if (num > 65535) {
                logprintf(STDERR_FILENO,
                          "Major number outside valid range [0 - 65535]\n");
                ret = -1;
                goto exit;
            }
            cinfo.dev_major = num;
            break;
        case 'm': /* minor */
            if (sscanf(optarg, "%u", &num) != 1) {
                logprintf(STDERR_FILENO, "Could not parse major number\n");
                ret = -1;
                goto exit;
            }
            if (num > 65535) {
                logprintf(STDERR_FILENO,
                          "Major number outside valid range [0 - 65535]\n");
                ret = -1;
                goto exit;
            }
            cinfo.dev_minor = num;
            break;
        case 'n': /* name */
            if (!cinfo.dev_info_argc) {
                cinfo_argv[0] = calloc(1, strlen("DEVNAME=") + strlen(optarg) + 1);
                if (!cinfo_argv[0]) {
                    logprintf(STDERR_FILENO, "Out of memory\n");
                    ret = -1;
                    goto exit;
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
        case 'L':
            param.localitydata = optarg;
            break;
        case 'F':
            param.flagsdata = optarg;
            break;
        case '2':
            tpmversion = TPMLIB_TPM_VERSION_2;
            break;
        case 'S':
            param.seccompdata = optarg;
            break;
        case 'h': /* help */
            fprintf(stdout, usage, prgname, iface);
            goto exit;
        case 'a':
            printcapabilities = true;
            break;
        case 'e':
            printstates = true;
            break;
        case 'v': /* version */
            fprintf(stdout, "TPM emulator CUSE interface version %d.%d.%d, "
                    "Copyright (c) 2014-2015 IBM Corp.\n",
                    SWTPM_VER_MAJOR,
                    SWTPM_VER_MINOR,
                    SWTPM_VER_MICRO);
            goto exit;
        }
    }

    if (optind < argc) {
        logprintf(STDERR_FILENO,
                  "Unknown parameter '%s'\n", argv[optind]);
        ret = EXIT_FAILURE;
        goto exit;
    }

    if (setuid(0)) {
        logprintf(STDERR_FILENO, "Error: Unable to setuid root. uid = %d, "
                  "euid = %d, gid = %d\n", getuid(), geteuid(), getgid());
        ret = -4;
        goto exit;
    }

    if (param.runas) {
        if (!(passwd = getpwnam(param.runas))) {
            logprintf(STDERR_FILENO, "User '%s' does not exist\n",
                      param.runas);
            ret = -5;
            goto exit;
        }
    }

    if (handle_log_options(param.logging) < 0) {
        ret = EXIT_FAILURE;
        goto exit;
    }

    if (printcapabilities) {
        /*
         * Choose the TPM version so that getting/setting buffer size works.
         * Ignore failure, for backward compatibility when TPM 1.2 is disabled.
         */
        TPMLIB_ChooseTPMVersion(tpmversion);
        ret = capabilities_print_json(true) ? EXIT_FAILURE : EXIT_SUCCESS;
        goto exit;
    }

    if (TPMLIB_ChooseTPMVersion(tpmversion) != TPM_SUCCESS) {
        logprintf(STDERR_FILENO,
                  "Error: Could not choose TPM version.\n");
        ret = EXIT_FAILURE;
        goto exit;
    }

    tpmstate_set_version(tpmversion);

    if (printstates) {
        if (handle_tpmstate_options(param.tpmstatedata) < 0) {
            ret = EXIT_FAILURE;
            goto exit;
        }
        if (param.tpmstatedata == NULL) {
            logprintf(STDERR_FILENO,
                      "Error: --tpmstate option is required for --print-states\n");
            ret = EXIT_FAILURE;
            goto exit;
        }
        ret = SWTPM_NVRAM_PrintJson();
        ret = ret ? EXIT_FAILURE : EXIT_SUCCESS;
        goto exit;
    }

    if (!cinfo.dev_info_argv) {
        logprintf(STDERR_FILENO, "Error: device name missing\n");
        ret = -2;
        goto exit;
    }

    if (handle_key_options(param.keydata) < 0 ||
        handle_migration_key_options(param.migkeydata) < 0 ||
        handle_pid_options(param.piddata) < 0 ||
        handle_tpmstate_options(param.tpmstatedata) < 0 ||
        handle_seccomp_options(param.seccompdata, &param.seccomp_action) < 0 ||
        handle_locality_options(param.localitydata, &locality_flags) < 0 ||
        handle_flags_options(param.flagsdata, &need_init_cmd,
                             &param.startupType) < 0) {
        ret = -3;
        goto exit;
    }

    uri = tpmstate_get_backend_uri();
    if (uri == NULL) {
        logprintf(STDERR_FILENO,
                  "Error: No TPM state directory is defined; "
                  "TPM_PATH is not set\n");
        ret = -1;
        goto exit;
    }

    n = snprintf(path, sizeof(path), "/dev/%s", devname);
    if (n < 0) {
        logprintf(STDERR_FILENO,
                  "Error: Could not create device file name\n");
        ret = -1;
        goto exit;
    }
    if (n >= (int)sizeof(path)) {
        logprintf(STDERR_FILENO,
                  "Error: Buffer too small to create device file name\n");
        ret = -1;
        goto exit;
    }

    tpmfd = open(path, O_RDWR);
    if (tpmfd >= 0) {
        close(tpmfd);
        logprintf(STDERR_FILENO,
                  "Error: A device '%s' already exists.\n",
                  path);
        ret = -1;
        goto exit;
    }

    if (tpmlib_register_callbacks(&cbs) != TPM_SUCCESS) {
        ret = -1;
        goto exit;
    }

    worker_thread_init();

    if (!need_init_cmd) {
        if (tpm_start(0, tpmversion, &res) < 0) {
            ret = -1;
            goto exit;
        }
        tpm_running = true;
    }

    if (param.startupType != _TPM_ST_NONE) {
        if (ptm_send_startup(param.startupType, tpmversion) < 0) {
            ret = -1;
            goto exit;
        }
    }

#if GLIB_MINOR_VERSION >= 32
    g_mutex_init(FILE_OPS_LOCK);
#else
    FILE_OPS_LOCK = g_mutex_new();
#endif

    ret = ptm_cuse_lowlevel_main(1, argv, &cinfo, &clops, &param);

exit:
    ptm_cleanup();
    free(cinfo_argv[0]);

    return ret;
}
