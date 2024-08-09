/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * swtpm.c: Programming of a swtpm using communication via fd-passing
 *
 * Author: Stefan Berger, stefanb@linux.ibm.com
 *
 * Copyright (c) IBM Corporation, 2021
 */

#include "config.h"

#include <errno.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>

#include <glib.h>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
# include <openssl/core_names.h>
# include <openssl/param_build.h>
#else
# include <openssl/rsa.h>
#endif

#include "swtpm.h"
#include "swtpm_utils.h"
#include "tpm_ioctl.h"
#include "sys_dependencies.h"

#define AS2BE(VAL) (((VAL) >> 8) & 0xff), ((VAL) & 0xff)
#define AS4BE(VAL) AS2BE((VAL) >> 16), AS2BE(VAL)
#define AS8BE(VAL) AS4BE((VAL) >> 32), AS4BE(VAL)

#define CMD_DURATION_SHORT  2000 /* ms */

struct tpm_req_header {
    uint16_t tag;
    uint32_t size;
    uint32_t ordinal;
} __attribute__((packed));

struct tpm_resp_header {
    uint16_t tag;
    uint32_t size;
    uint32_t errcode;
} __attribute__((packed));

/* Close the ctrl and data file descriptors that were passed to the swtpm process.
 * If 'all' is true then also close the ones not passed to the process.
 */
static void swtpm_close_comm(struct swtpm *self, bool all)
{
    if (all)
        SWTPM_CLOSE(self->data_fds[0]);
    SWTPM_CLOSE(self->data_fds[1]);

    if (all)
        SWTPM_CLOSE(self->ctrl_fds[0]);
    SWTPM_CLOSE(self->ctrl_fds[1]);
}

static int swtpm_start(struct swtpm *self)
{
    g_autofree gchar *tpmstate = g_strdup_printf("backend-uri=%s", self->state_path);
    g_autofree gchar *json_profile = NULL;
    g_autofree gchar *pidfile_arg = NULL;
    g_autofree gchar *server_fd = NULL;
    g_autofree gchar *ctrl_fd = NULL;
    g_autofree gchar *keyopts = NULL;
    g_autofree gchar *logop = NULL;
    g_autofree gchar **argv = NULL;
    struct stat statbuf;
    gboolean success;
    GError *error = NULL;
    GSpawnFlags flags;
    unsigned ctr;
    int pidfile_fd;
    int ret = 1;
    char pidfile[] = "/tmp/.swtpm_setup.pidfile.XXXXXX";

    pidfile_fd = g_mkstemp_full(pidfile, O_EXCL|O_CREAT, 0600);
    if (pidfile_fd < 0) {
        logerr(self->logfile, "Could not create pidfile: %s\n", strerror(errno));
        goto error_no_pidfile;
    }
    // pass filename rather than fd (Cygwin)
    pidfile_arg = g_strdup_printf("file=%s", pidfile);

    argv = concat_arrays(self->swtpm_exec_l,
                         (gchar*[]){
                              "--flags", "not-need-init,startup-clear",
                              "--tpmstate", tpmstate,
                              "--pid", pidfile_arg,
#if 0
                              "--log", "file=/tmp/log,level=20",
#endif
                              NULL
                         }, FALSE);

    if (self->is_tpm2)
        argv = concat_arrays(argv, (gchar*[]){"--tpm2", NULL}, TRUE);

    if (self->keyopts != NULL) {
        keyopts = g_strdup(self->keyopts);
        argv = concat_arrays(argv, (gchar*[]){"--key", keyopts, NULL}, TRUE);
    }

    if (self->json_profile != NULL) {
        json_profile = g_strdup_printf("profile=%s", self->json_profile);
        argv = concat_arrays(argv, (gchar*[]){"--profile", json_profile, NULL}, TRUE);
        logit(self->logfile, "Apply profile: %s\n", self->json_profile);
    }

    if (gl_LOGFILE != NULL) {
        logop = g_strdup_printf("file=%s", gl_LOGFILE);
        argv = concat_arrays(argv, (gchar*[]){"--log", logop, NULL}, TRUE);
    }

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, self->ctrl_fds) != 0) {
        logerr(self->logfile, "Could not create socketpair: %s\n", strerror(errno));
        goto error;
    }
    ctrl_fd = g_strdup_printf("type=unixio,clientfd=%d", self->ctrl_fds[1]);

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, self->data_fds) != 0) {
        logerr(self->logfile, "Could not create socketpair: %s\n", strerror(errno));
        goto error;
    }
    server_fd = g_strdup_printf("type=tcp,fd=%d", self->data_fds[1]);

    argv = concat_arrays(argv, (gchar*[]){
                             "--server", server_fd,
                             "--ctrl", ctrl_fd,
                             NULL
                         }, TRUE);

#if 0
    {
        g_autofree gchar *join = g_strjoinv(" ", argv);
        logit(self->logfile, "Starting swtpm: %s\n", join);
    }
#endif

    flags = G_SPAWN_LEAVE_DESCRIPTORS_OPEN;
    if (gl_LOGFILE) {
        flags |= G_SPAWN_STDOUT_TO_DEV_NULL | G_SPAWN_STDERR_TO_DEV_NULL;
    } else {
#if GLIB_CHECK_VERSION(2, 74, 0)
        flags |= G_SPAWN_CHILD_INHERITS_STDOUT | G_SPAWN_CHILD_INHERITS_STDERR;
#endif
    }

    success = g_spawn_async(NULL, argv, NULL, flags,
                            NULL, NULL, &self->pid, &error);
    if (!success) {
        logerr(self->logfile, "Could not start swtpm: %s\n", error->message);
        g_error_free(error);
        goto error;
    }

    /* wait until the pidfile is written to or swtpm terminates */
    for (ctr = 0; ctr < 1000; ctr++) {
        if (kill(self->pid, 0) < 0) {
            /* swtpm terminated */
            self->pid = 0;
            logerr(self->logfile, "swtpm process terminated unexpectedly.\n");
            self->cops->stop(self);
            goto error;
        }
        if (fstat(pidfile_fd, &statbuf) == 0 && statbuf.st_size > 0) {
            printf("TPM is listening on Unix socket.\n");
            ret = 0;
            break;
        }
        usleep(5000);
    }

error:
    swtpm_close_comm(self, ret != 0);

    close(pidfile_fd);
    unlink(pidfile);

error_no_pidfile:
    return ret;
}

/* Stop a running swtpm instance and close all the file descriptors connecting to it */
static void swtpm_stop(struct swtpm *self)
{
    unsigned c;
    gboolean ended = FALSE;

    if (self->pid > 0) {
        self->cops->ctrl_shutdown(self);
        for (c = 0; c < 500; c++) {
            if (kill(self->pid, 0) < 0) {
                ended = TRUE;
                break;
            }
            usleep(1000);
        }
        if (!ended)
            kill(self->pid, SIGKILL);
        waitpid(self->pid, NULL, 0);

        self->pid = 0;
    }

    swtpm_close_comm(self, true);
}

/* Destroy a running swtpm instance */
static void swtpm_destroy(struct swtpm *self)
{
    self->cops->stop(self);
}

/* Send a command to swtpm and receive the response either via control or data channel */
static int transfer(struct swtpm *self, void *buffer, size_t buffer_len,
                    const char *cmdname, gboolean use_ctrl,
                    void *respbuffer, size_t *respbuffer_len, int timeout_ms)
{
    size_t offset;
    int sockfd;
    ssize_t n;
    unsigned char resp[4096];
    ssize_t resplen;
    uint32_t returncode;
    struct pollfd fds = {
        .events = POLLIN | POLLERR | POLLHUP,
    };

    if (use_ctrl) {
        sockfd = self->ctrl_fds[0];
        offset = 0;
    } else {
        sockfd = self->data_fds[0];
        offset = 6;
    }

    n = write(sockfd, buffer, buffer_len);
    if (n < 0) {
        logerr(self->logfile, "Could not send %s buffer to swtpm: %s\n",
               cmdname, strerror(errno));
        return 1;
    }
    if ((size_t)n != buffer_len) {
        logerr(self->logfile, "Could not send all bytes to swtpm: %zu < %zu\n",
               (size_t)n, buffer_len);
        return 1;
    }

    fds.fd = sockfd;
    n = poll(&fds, 1, timeout_ms);
    if (n != 1 || (fds.revents & POLLIN) == 0) {
        logerr(self->logfile, "Could not receive response to %s from swtpm: %s\n",
               cmdname, strerror(errno));
        return 1;
    }

    resplen = read(sockfd, resp, sizeof(resp));
    if (resplen < 0) {
        logerr(self->logfile, "Could not receive response to %s from swtpm: %s\n",
               cmdname, strerror(errno));
        return 1;
    }

    if (!use_ctrl) {
        if ((size_t)resplen < sizeof(struct tpm_resp_header)) {
            logerr(self->logfile,
                   "Response for %s has only %d bytes.\n", cmdname, resplen);
            return 1;
        }
    } else if ((size_t)resplen < 4) {
        logerr(self->logfile,
               "Response for %s has only %d bytes.\n", cmdname, resplen);
        return 1;
    }

    memcpy(&returncode, &resp[offset], sizeof(returncode));
    returncode = be32toh(returncode);
    if (returncode != 0) {
        logerr(self->logfile,
               "%s failed: 0x%x\n", cmdname, returncode);
        return 1;
    }

    if (respbuffer) {
        *respbuffer_len = min((size_t)resplen, *respbuffer_len);
        memcpy(respbuffer, resp, *respbuffer_len);
    }

    return 0;
}

/* Send a CMD_SHUTDOWN over the control channel */
static int swtpm_ctrl_shutdown(struct swtpm *self)
{
    uint32_t cmd = htobe32(CMD_SHUTDOWN);

    return transfer(self, &cmd, sizeof(cmd), "CMD_SHUTDOWN", TRUE,
                    NULL, NULL, CMD_DURATION_SHORT);
}

/* Get the TPM specification parameters over the control channel */
static int swtpm_ctrl_get_tpm_specs_and_attrs(struct swtpm *self, gchar **result)
{
    unsigned char req[] = {AS4BE(CMD_GET_INFO),
                           AS8BE(SWTPM_INFO_TPMSPECIFICATION | SWTPM_INFO_TPMATTRIBUTES),
                           AS4BE(0), AS4BE(0)};
    unsigned char tpmresp[1024];
    size_t tpmresp_len = sizeof(tpmresp);
    int ret;
    uint32_t length;

    ret = transfer(self, req, sizeof(req), "CMD_GET_INFO", TRUE,
                   tpmresp, &tpmresp_len, CMD_DURATION_SHORT);
    if (ret != 0)
        return 1;

    if (tpmresp_len < 8 + sizeof(length))
        goto err_too_short;
    memcpy(&length, &tpmresp[8], sizeof(length));
    length = htobe32(length);

    if (tpmresp_len < 12 + length)
        goto err_too_short;
    *result = g_strndup((gchar *)&tpmresp[12], length);

    return 0;

err_too_short:
    logerr(self->logfile, "Response from CMD_GET_INFO is too short!\n");

    return 1;
}

static const struct swtpm_cops swtpm_cops = {
    .start = swtpm_start,
    .stop = swtpm_stop,
    .destroy = swtpm_destroy,
    .ctrl_shutdown = swtpm_ctrl_shutdown,
    .ctrl_get_tpm_specs_and_attrs = swtpm_ctrl_get_tpm_specs_and_attrs,
};

/*
 * TPM 2 support
 */

#define TPM2_ST_NO_SESSIONS  0x8001
#define TPM2_ST_SESSIONS     0x8002

#define TPM2_CC_EVICTCONTROL   0x00000120
#define TPM2_CC_NV_DEFINESPACE 0x0000012a
#define TPM2_CC_PCR_ALLOCATE   0x0000012b
#define TPM2_CC_CREATEPRIMARY  0x00000131
#define TPM2_CC_NV_WRITE       0x00000137
#define TPM2_CC_NV_WRITELOCK   0x00000138
#define TPM2_CC_SHUTDOWN       0x00000145
#define TPM2_CC_FLUSHCONTEXT   0x00000165
#define TPM2_CC_GETCAPABILITY  0x0000017a

#define TPM2_SU_CLEAR        0x0000

#define TPM2_RH_OWNER        0x40000001
#define TPM2_RS_PW           0x40000009
#define TPM2_RH_ENDORSEMENT  0x4000000b
#define TPM2_RH_PLATFORM     0x4000000c

#define TPM2_ALG_RSA      0x0001
#define TPM2_ALG_SHA1     0x0004
#define TPM2_ALG_AES      0x0006
#define TPM2_ALG_SHA256   0x000b
#define TPM2_ALG_SHA384   0x000c
#define TPM2_ALG_SHA512   0x000d
#define TPM2_ALG_SHA3_256 0x0027
#define TPM2_ALG_SHA3_384 0x0028
#define TPM2_ALG_SHA3_512 0x0029
#define TPM2_ALG_NULL     0x0010
#define TPM2_ALG_SM3      0x0012
#define TPM2_ALG_ECDSA    0x0018
#define TPM2_ALG_ECC      0x0023
#define TPM2_ALG_CFB      0x0043

#define TPM2_CAP_PCRS     0x00000005

#define TPM2_ECC_NIST_P384 0x0004

#define TPMA_NV_PLATFORMCREATE 0x40000000
#define TPMA_NV_AUTHREAD       0x40000
#define TPMA_NV_NO_DA          0x2000000
#define TPMA_NV_PPWRITE        0x1
#define TPMA_NV_PPREAD         0x10000
#define TPMA_NV_OWNERREAD      0x20000
#define TPMA_NV_WRITEDEFINE    0x2000

// Use standard EK Cert NVRAM, EK and SRK handles per IWG spec.
// "TCG TPM v2.0 Provisioning Guide"; Version 1.0, Rev 1.0, March 15, 2017
// Table 2
#define TPM2_NV_INDEX_RSA2048_EKCERT         0x01c00002
#define TPM2_NV_INDEX_RSA2048_EKTEMPLATE     0x01c00004
#define TPM2_NV_INDEX_RSA3072_HI_EKCERT      0x01c0001c
#define TPM2_NV_INDEX_RSA3072_HI_EKTEMPLATE  0x01c0001d
// For ECC follow "TCG EK Credential Profile For TPM Family 2.0; Level 0"
// Specification Version 2.1; Revision 13; 10 December 2018
#define TPM2_NV_INDEX_PLATFORMCERT           0x01c08000

#define TPM2_NV_INDEX_ECC_SECP384R1_HI_EKCERT     0x01c00016
#define TPM2_NV_INDEX_ECC_SECP384R1_HI_EKTEMPLATE 0x01c00017

#define TPM2_NV_INDEX_IDEVID_SHA384  0x01c90011
#define TPM2_NV_INDEX_IAK_SHA384     0x01c90019

#define TPM2_EK_RSA_HANDLE           0x81010001
#define TPM2_EK_RSA3072_HANDLE       0x8101001c
#define TPM2_EK_ECC_SECP384R1_HANDLE 0x81010016
#define TPM2_SPK_HANDLE              0x81000001

#define TPM2_DURATION_SHORT     2000 /* ms */
#define TPM2_DURATION_MEDIUM    7500 /* ms */
#define TPM2_DURATION_LONG     15000 /* ms */

#define TPM_REQ_HEADER_INITIALIZER(TAG, SIZE, ORD) \
    { \
        .tag = htobe16(TAG), \
        .size = htobe32(SIZE), \
        .ordinal = htobe32(ORD), \
    }

struct tpm2_authblock {
    uint32_t auth;
    uint16_t foo; // FIXME
    uint8_t continueSession;
    uint16_t bar; // FIMXE
} __attribute__((packed));

#define TPM2_AUTHBLOCK_INITIALIZER(AUTH, FOO, CS, BAR) \
    { \
        .auth = htobe32(AUTH), \
        .foo = htobe16(FOO), \
        .continueSession = CS, \
        .bar = htobe16(BAR), \
    }

static const unsigned char NONCE_EMPTY[2] = {AS2BE(0)};
static const unsigned char NONCE_RSA2048[2+0x100] = {AS2BE(0x100), 0, };
static const unsigned char NONCE_RSA3072[2+0x180] = {AS2BE(0x180), 0, };
static const unsigned char NONCE_ECC_384[2+0x30] = {AS2BE(0x30), 0, };

static const struct bank_to_name {
    uint16_t hashAlg;
    const char *name;
} banks_to_names[] = {
    {TPM2_ALG_SHA1, "sha1"},
    {TPM2_ALG_SHA256, "sha256"},
    {TPM2_ALG_SHA384, "sha384"},
    {TPM2_ALG_SHA512, "sha512"},
    {TPM2_ALG_SM3, "sm3-256"},
    {TPM2_ALG_SHA3_256, "sha3-256"},
    {TPM2_ALG_SHA3_384, "sha3-384"},
    {TPM2_ALG_SHA3_512, "sha3-512"},
    {0, NULL},
};

/* function prototypes */
static int swtpm_tpm2_createprimary_rsa(struct swtpm *self, uint32_t primaryhandle, unsigned int keyflags,
                                        const unsigned char *symkeydata, size_t symkeydata_len,
                                        const unsigned char *authpolicy, size_t authpolicy_len,
                                        unsigned int rsa_keysize, gboolean havenonce, size_t off,
                                        uint32_t *curr_handle,
                                        unsigned char *ektemplate, size_t *ektemplate_len,
                                        gchar **ekparam, const gchar **key_description);

static int swtpm_tpm2_write_nvram(struct swtpm *self, uint32_t nvindex, uint32_t nvindexattrs,
                                  const unsigned char *data, size_t data_len, gboolean lock_nvram,
                                  const char *purpose);

/* Given a hash algo identifier, return the name of the hash bank */
static const char *get_name_for_bank(uint16_t hashAlg) {
    size_t i;

    for (i = 0; banks_to_names[i].name; i++) {
        if (banks_to_names[i].hashAlg == hashAlg)
            return banks_to_names[i].name;
    }
    return NULL;
}

/* Give the name of a hash bank, return its algo identifier */
static uint16_t get_hashalg_by_bankname(const char *name) {
    size_t i;

    for (i = 0; banks_to_names[i].name; i++) {
        if (strcmp(banks_to_names[i].name, name) == 0)
            return banks_to_names[i].hashAlg;
    }
    return 0;
}

/* Do an SU_CLEAR shutdown of the TPM 2 */
static int swtpm_tpm2_shutdown(struct swtpm *self)
{
    struct tpm2_shutdown_req {
        struct tpm_req_header hdr;
        uint16_t shutdownType;
    } __attribute__((packed)) req = {
        .hdr = TPM_REQ_HEADER_INITIALIZER(TPM2_ST_NO_SESSIONS, sizeof(req), TPM2_CC_SHUTDOWN),
        .shutdownType = htobe16(TPM2_SU_CLEAR)
    };

    return transfer(self, &req, sizeof(req), "TPM2_Shutdown", FALSE,
                    NULL, NULL, TPM2_DURATION_SHORT);
}

/* Get all available PCR banks */
static int swtpm_tpm2_get_all_pcr_banks(struct swtpm *self, gchar ***all_pcr_banks)
{
    struct tpm_req_header hdr = TPM_REQ_HEADER_INITIALIZER(TPM2_ST_NO_SESSIONS, 0, TPM2_CC_GETCAPABILITY);
    g_autofree unsigned char *req = NULL;
    ssize_t req_len;
    unsigned char tpmresp[256];
    size_t tpmresp_len = sizeof(tpmresp);
    uint16_t count, bank;
    const char *name;
    uint8_t length;
    size_t offset;
    size_t i;
    int ret;

    req_len = memconcat(&req,
                        &hdr, sizeof(hdr),
                        (unsigned char[]){AS4BE(TPM2_CAP_PCRS), AS4BE(0), AS4BE(64)}, (size_t)12,
                        NULL);
    if (req_len < 0) {
        logerr(self->logfile, "Internal error in %s: memconcat failed\n", __func__);
        return 1;
    }
    ((struct tpm_req_header *)req)->size = htobe32(req_len);

    ret = transfer(self, req, req_len, "TPM2_GetCapability", FALSE,
                   tpmresp, &tpmresp_len, TPM2_DURATION_MEDIUM);
    if (ret != 0)
        return 1;

    *all_pcr_banks = NULL;

    if (tpmresp_len < 17 + sizeof(count))
        goto err_too_short;
    memcpy(&count, &tpmresp[17], sizeof(count));
    count = be16toh(count);

    /* unreasonable number of PCR banks ? */
    if (count > 20)
        goto err_num_pcrbanks;

    *all_pcr_banks = g_malloc0(sizeof(char *) * (count + 1));

    offset = 19;

    for (i = 0; i < count; i++) {
        gchar *n;

        if (tpmresp_len < offset + sizeof(bank))
            goto err_too_short;
        memcpy(&bank, &tpmresp[offset], sizeof(bank));
        bank = be16toh(bank);

        if (tpmresp_len < offset + 2 + sizeof(length))
            goto err_too_short;
        length = tpmresp[offset + 2];

        name = get_name_for_bank(bank);
        if (name != NULL)
            n = g_strdup(name);
        else
            n = g_strdup_printf("%02x", bank);

        (*all_pcr_banks)[i] = n;

        offset += 2 + 1 + length;
    }
    return 0;

err_num_pcrbanks:
    logerr(self->logfile, "Unreasonable number of PCR banks (%u) returned.\n", count);
    goto err_exit;

err_too_short:
    logerr(self->logfile, "Response from TPM2_GetCapability is too short!\n");

err_exit:
    g_strfreev(*all_pcr_banks);
    *all_pcr_banks = NULL;

    return 1;
}

/* Activate all user-chosen PCR banks and deactivate all others */
static int swtpm_tpm2_set_active_pcr_banks(struct swtpm *self, gchar **pcr_banks,
                                           gchar **all_pcr_banks, gchar ***active)
{
    struct tpm_req_header hdr = TPM_REQ_HEADER_INITIALIZER(TPM2_ST_SESSIONS, 0, TPM2_CC_PCR_ALLOCATE);
    struct tpm2_authblock authblock = TPM2_AUTHBLOCK_INITIALIZER(TPM2_RS_PW, 0, 0, 0);
    unsigned char pcrselects[6 * 10]; // supports up to 10 PCR banks
    ssize_t pcrselects_len = 0;
    size_t count = 0;
    size_t idx, j;
    uint16_t hashAlg;
    g_autofree unsigned char *req = NULL;
    ssize_t req_len, len;
    int ret;
    uint64_t activated_mask = 0;

    for (idx = 0; pcr_banks[idx] != NULL; idx++)
        ;
    *active = g_malloc0(sizeof(char *) * (idx + 1));

    for (idx = 0; pcr_banks[idx] != NULL; idx++) {
        hashAlg = 0;
        // Is user-chosen pcr_banks[idx] available?
        for (j = 0; all_pcr_banks[j] != NULL; j++) {
            if (strcmp(pcr_banks[idx], all_pcr_banks[j]) == 0) {
                hashAlg = get_hashalg_by_bankname(pcr_banks[idx]);
                break;
            }
        }
        if (hashAlg != 0 && (activated_mask & ((uint64_t)1 << j)) == 0) {
            (*active)[count] = g_strdup(pcr_banks[idx]);
            len = concat(&pcrselects[pcrselects_len], sizeof(pcrselects) - pcrselects_len,
                         (unsigned char[]){AS2BE(hashAlg), 3, 0xff, 0xff, 0xff} , (size_t)6,
                         NULL);
            if (len < 0) {
                logerr(self->logfile, "Internal error in %s: pcrselects is too small\n", __func__);
                return 1;
            }
            pcrselects_len += len;
            count++;
            activated_mask |= ((uint64_t)1 << j);
        }
    }

    if (count == 0) {
        logerr(self->logfile,
               "No PCR banks could be allocated. None of the selected algorithms are supported.\n");
        goto error;
    }

    // disable all the other ones not chosen by the user
    for (idx = 0; all_pcr_banks[idx] != NULL; idx++) {
        gboolean found = FALSE;

        for (j = 0; pcr_banks[j] != NULL; j++) {
            if (strcmp(pcr_banks[j], all_pcr_banks[idx]) == 0) {
                found = TRUE;
                break;
            }
        }
        if (found)
            continue;

        /* not found, so not chosen by user */
        hashAlg = get_hashalg_by_bankname(all_pcr_banks[idx]);

        len = concat(&pcrselects[pcrselects_len], sizeof(pcrselects) - pcrselects_len,
                     (unsigned char[]){AS2BE(hashAlg), 3, 0, 0, 0}, (size_t)6,
                     NULL);
        if (len < 0) {
            logerr(self->logfile, "Internal error in %s: pcrselects is too small\n", __func__);
            goto error;
        }
        pcrselects_len += len;
        count++;
    }

    req_len = memconcat(&req,
                        &hdr, sizeof(hdr),
                        (unsigned char[]){
                             AS4BE(TPM2_RH_PLATFORM), AS4BE(sizeof(authblock))
                        }, (size_t)8,
                        &authblock, sizeof(authblock),
                        (unsigned char[]){AS4BE(count)}, (size_t)4,
                        pcrselects, pcrselects_len,
                        NULL);
    if (req_len < 0) {
        logerr(self->logfile, "Internal error in %s: req is too small\n", __func__);
        goto error;
    }
    ((struct tpm_req_header *)req)->size = htobe32(req_len);

    ret = transfer(self, req, req_len, "TPM2_PCR_Allocate", FALSE,
                   NULL, NULL, TPM2_DURATION_SHORT);
    if (ret != 0)
        goto error;

    return 0;

error:
    g_strfreev(*active);
    *active = NULL;

    return 1;
}

static int swtpm_tpm2_flushcontext(struct swtpm *self, uint32_t handle)
{
    struct tpm2_flushcontext_req {
        struct tpm_req_header hdr;
        uint32_t flushHandle;
    } __attribute__((packed)) req = {
        .hdr = TPM_REQ_HEADER_INITIALIZER(TPM2_ST_NO_SESSIONS, sizeof(req), TPM2_CC_FLUSHCONTEXT),
        .flushHandle = htobe32(handle),
    };

    return transfer(self, &req, sizeof(req), "TPM2_FlushContext", FALSE,
                    NULL, NULL, TPM2_DURATION_SHORT);
}

/* Make object at the curr_handler permanent with the perm_handle */
static int swtpm_tpm2_evictcontrol(struct swtpm *self, uint32_t curr_handle, uint32_t perm_handle)
{
    struct tpm2_evictcontrol_req {
        struct tpm_req_header hdr;
        uint32_t auth;
        uint32_t objectHandle;
        uint32_t authblockLen;
        struct tpm2_authblock authblock;
        uint32_t persistentHandle;
    } __attribute__((packed)) req = {
        .hdr = TPM_REQ_HEADER_INITIALIZER(TPM2_ST_SESSIONS, sizeof(req), TPM2_CC_EVICTCONTROL),
        .auth = htobe32(TPM2_RH_OWNER),
        .objectHandle = htobe32(curr_handle),
        .authblockLen = htobe32(sizeof(req.authblock)),
        .authblock = TPM2_AUTHBLOCK_INITIALIZER(TPM2_RS_PW, 0, 0, 0),
        .persistentHandle = htobe32(perm_handle),
    };

    return transfer(self, &req, sizeof(req), "TPM2_EvictControl", FALSE,
                    NULL, NULL, TPM2_DURATION_SHORT);
}

/* Create an RSA EK */
static int swtpm_tpm2_createprimary_ek_rsa(struct swtpm *self, unsigned int rsa_keysize,
                                           gboolean allowsigning, gboolean decryption,
                                           uint32_t *curr_handle,
                                           unsigned char *ektemplate, size_t *ektemplate_len,
                                           gchar **ekparam, const gchar **key_description)
{
    unsigned char authpolicy[48];
    size_t authpolicy_len;
    unsigned char symkeydata[6];
    size_t symkeydata_len;
    unsigned int keyflags;
    unsigned int symkeylen;
    gboolean havenonce;
    size_t addlen, off;

    if (rsa_keysize == 2048) {
        authpolicy_len = 32;
        memcpy(authpolicy, ((unsigned char []){
            0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc, 0x8d,
            0x46, 0xa5, 0xd7, 0x24, 0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64,
            0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14, 0x69, 0xaa
        }), authpolicy_len);
        keyflags = 0;
        symkeylen = 128;
        havenonce = TRUE;
        addlen = 0;
    } else if (rsa_keysize == 3072) {
        authpolicy_len = 48;
        memcpy(authpolicy, ((unsigned char []){
            0xB2, 0x6E, 0x7D, 0x28, 0xD1, 0x1A, 0x50, 0xBC, 0x53, 0xD8, 0x82, 0xBC,
            0xF5, 0xFD, 0x3A, 0x1A, 0x07, 0x41, 0x48, 0xBB, 0x35, 0xD3, 0xB4, 0xE4,
            0xCB, 0x1C, 0x0A, 0xD9, 0xBD, 0xE4, 0x19, 0xCA, 0xCB, 0x47, 0xBA, 0x09,
            0x69, 0x96, 0x46, 0x15, 0x0F, 0x9F, 0xC0, 0x00, 0xF3, 0xF8, 0x0E, 0x12
        }), authpolicy_len);
        keyflags = 0x40;
        symkeylen = 256;
        havenonce = FALSE;
        addlen = 16;
    } else {
        logerr(self->logfile, "Internal error in %s: unsupported RSA keysize %d.\n",
               __func__, rsa_keysize);
        return 1;
    }

    if (allowsigning && decryption) {
        // keyflags: fixedTPM, fixedParent, sensitiveDatOrigin,
        // adminWithPolicy, sign, decrypt
        keyflags |= 0x000600b2;
        // symmetric: TPM_ALG_NULL
        symkeydata_len = 2;
        memcpy(symkeydata, ((unsigned char[]) {AS2BE(TPM2_ALG_NULL)}), symkeydata_len);
        off = 72 + addlen;
    } else if (allowsigning) {
        // keyflags: fixedTPM, fixedParent, sensitiveDatOrigin,
        // adminWithPolicy, sign
        keyflags |= 0x000400b2;
        // symmetric: TPM_ALG_NULL
        symkeydata_len = 2;
        memcpy(symkeydata, ((unsigned char[]) {AS2BE(TPM2_ALG_NULL)}), symkeydata_len);
        off = 72 + addlen;
    } else {
        // keyflags: fixedTPM, fixedParent, sensitiveDatOrigin,
        // adminWithPolicy, restricted, decrypt
        keyflags |= 0x000300b2;
        // symmetric: TPM_ALG_AES, 128bit or 256bit, TPM_ALG_CFB
        symkeydata_len = 6;
        memcpy(symkeydata,
               ((unsigned char[]) {AS2BE(TPM2_ALG_AES), AS2BE(symkeylen), AS2BE(TPM2_ALG_CFB)}),
               symkeydata_len);
        off = 76 + addlen;
    }

    return swtpm_tpm2_createprimary_rsa(self, TPM2_RH_ENDORSEMENT, keyflags,
                                        symkeydata, symkeydata_len,
                                        authpolicy, authpolicy_len, rsa_keysize,
                                        havenonce, off, curr_handle,
                                        ektemplate, ektemplate_len, ekparam, key_description);
}

/* Create an RSA key with the given parameters */
static int swtpm_tpm2_createprimary_rsa(struct swtpm *self, uint32_t primaryhandle, unsigned int keyflags,
                                        const unsigned char *symkeydata, size_t symkeydata_len,
                                        const unsigned char *authpolicy, size_t authpolicy_len,
                                        unsigned int rsa_keysize, gboolean havenonce, size_t off,
                                        uint32_t *curr_handle,
                                        unsigned char *ektemplate, size_t *ektemplate_len,
                                        gchar **ekparam, const gchar **key_description)
{
    const unsigned char *nonce;
    size_t nonce_len;
    uint16_t hashalg;
    struct tpm_req_header hdr = TPM_REQ_HEADER_INITIALIZER(TPM2_ST_SESSIONS, 0, TPM2_CC_CREATEPRIMARY);
    struct tpm2_authblock authblock = TPM2_AUTHBLOCK_INITIALIZER(TPM2_RS_PW, 0, 0, 0);
    g_autofree unsigned char *public = NULL;
    ssize_t public_len;
    g_autofree unsigned char *createprimary = NULL;
    ssize_t createprimary_len;
    int ret;
    unsigned char tpmresp[2048];
    size_t tpmresp_len = sizeof(tpmresp);
    uint16_t modlen;

    if (rsa_keysize == 2048) {
        nonce = NONCE_RSA2048;
        nonce_len = sizeof(NONCE_RSA2048);
        hashalg = TPM2_ALG_SHA256;
        if (key_description)
            *key_description = "rsa2048";
    } else if (rsa_keysize == 3072) {
        if (!havenonce) {
           nonce = NONCE_EMPTY;
           nonce_len = sizeof(NONCE_EMPTY);
        } else {
           nonce = NONCE_RSA3072;
           nonce_len = sizeof(NONCE_RSA3072);
        }
        hashalg = TPM2_ALG_SHA384;
        if (key_description)
            *key_description = "rsa3072";
    } else {
        logerr(self->logfile, "Internal error in %s: unsupported RSA keysize %d.\n",
               __func__, rsa_keysize);
        return 1;
    }

    public_len =
        memconcat(&public,
                  (unsigned char[]) {
                      AS2BE(TPM2_ALG_RSA), AS2BE(hashalg),
                      AS4BE(keyflags), AS2BE(authpolicy_len)
                  }, (size_t)10,
                  authpolicy, authpolicy_len,
                  symkeydata, symkeydata_len,
                  (unsigned char[]) {
                      AS2BE(TPM2_ALG_NULL), AS2BE(rsa_keysize), AS4BE(0)
                  }, (size_t)8,
                  nonce, nonce_len,
                  NULL);
    if (public_len < 0) {
        logerr(self->logfile, "Internal error in %s: memconcat failed\n", __func__);
        return 1;
    }
    if (ektemplate) {
        if (*ektemplate_len < (size_t)public_len) {
            logerr(self->logfile, "Internal error in %s: Need %zu bytes for ektemplate (rsa) but got only %zu\n",
                   __func__, public_len, *ektemplate_len);
            return 1;
        }
        memcpy(ektemplate, public, public_len);
        *ektemplate_len = public_len;
    }

    createprimary_len =
        memconcat(&createprimary,
                  &hdr, sizeof(hdr),
                  (unsigned char[]) {AS4BE(primaryhandle), AS4BE(sizeof(authblock))}, (size_t)8,
                  &authblock, sizeof(authblock),
                  (unsigned char[]) {AS2BE(4), AS4BE(0), AS2BE(public_len)}, (size_t)8,
                  public, public_len,
                  (unsigned char[]) {AS4BE(0), AS2BE(0)}, (size_t)6,
                  NULL);
    if (createprimary_len < 0) {
        logerr(self->logfile, "Internal error in %s: memconcat failed\n", __func__);
        return 1;
    }
    ((struct tpm_req_header *)createprimary)->size = htobe32(createprimary_len);

    ret = transfer(self, createprimary, createprimary_len, "TPM2_CreatePrimary(RSA)", FALSE,
                   tpmresp, &tpmresp_len, TPM2_DURATION_LONG);
    if (ret != 0)
        return 1;

    if (curr_handle) {
        if (tpmresp_len < 10 + sizeof(*curr_handle))
            goto err_too_short;
        memcpy(curr_handle, &tpmresp[10], sizeof(*curr_handle));
        *curr_handle = be32toh(*curr_handle);
    }

    if (tpmresp_len < off + sizeof(modlen))
         goto err_too_short;
    memcpy(&modlen, &tpmresp[off], sizeof(modlen));
    modlen = be16toh(modlen);
    if (modlen != rsa_keysize >> 3) {
        logerr(self->logfile, "Internal error in %s: Getting modulus from wrong offset %zu\n",
               __func__, off);
        return 1;
    }
    if (ekparam) {
        if (tpmresp_len < off + 2 + modlen)
            goto err_too_short;
        *ekparam = print_as_hex(&tpmresp[off + 2], modlen);
    }

    return 0;

err_too_short:
    logerr(self->logfile, "Response from TPM2_CreatePrimary(RSA) is too short!\n");
    return 1;
}

/* Create an ECC key with the given parameters */
static int swtpm_tpm2_createprimary_ecc(struct swtpm *self, uint32_t primaryhandle, unsigned int keyflags,
                                        const unsigned char *symkeydata, size_t symkeydata_len,
                                        const unsigned char *authpolicy, size_t authpolicy_len,
                                        const unsigned char *schemedata, size_t schemedata_len,
                                        unsigned short curveid, unsigned short hashalg,
                                        const unsigned char *nonce, size_t nonce_len,
                                        size_t off, uint32_t *curr_handle,
                                        unsigned char *ektemplate, size_t *ektemplate_len,
                                        gchar **ekparam, const gchar **key_description)
{
    struct tpm_req_header hdr = TPM_REQ_HEADER_INITIALIZER(TPM2_ST_SESSIONS, 0, TPM2_CC_CREATEPRIMARY);
    struct tpm2_authblock authblock = TPM2_AUTHBLOCK_INITIALIZER(TPM2_RS_PW, 0, 0, 0);
    g_autofree unsigned char *public = NULL;
    ssize_t public_len;
    g_autofree unsigned char *createprimary = NULL;
    ssize_t createprimary_len;
    int ret;
    unsigned char tpmresp[2048];
    size_t tpmresp_len = sizeof(tpmresp);
    size_t off2;
    uint16_t exp_ksize, ksize1, ksize2;
    const char *cid;

    public_len =
        memconcat(&public,
                  (unsigned char[]){
                      AS2BE(TPM2_ALG_ECC), AS2BE(hashalg), AS4BE(keyflags), AS2BE(authpolicy_len)
                  }, (size_t)10,
                  authpolicy, authpolicy_len,
                  symkeydata, symkeydata_len,
                  schemedata, schemedata_len,
                  nonce, nonce_len,
                  nonce, nonce_len,
                  NULL);
    if (public_len < 0) {
        logerr(self->logfile, "Internal error in %s: memconcat failed\n", __func__);
        return 1;
    }
    if (ektemplate) {
        if (*ektemplate_len < (size_t)public_len) {
            logerr(self->logfile, "Internal error: Need %zu bytes for ektemplate (ecc) but got only %zu\n",
                   public_len, ektemplate_len);
            return 1;
        }
        memcpy(ektemplate, public, public_len);
        *ektemplate_len = public_len;
    }

    createprimary_len =
        memconcat(&createprimary,
                  &hdr, sizeof(hdr),
                  (unsigned char[]) {AS4BE(primaryhandle), AS4BE(sizeof(authblock))}, (size_t)8,
                  &authblock, sizeof(authblock),
                  (unsigned char[]) {AS2BE(4), AS4BE(0), AS2BE(public_len)}, (size_t)8,
                  public, public_len,
                  (unsigned char[]) {AS4BE(0), AS2BE(0)}, (size_t)6,
                  NULL);
    if (createprimary_len < 0) {
        logerr(self->logfile, "Internal error in %s: memconcat failed\n", __func__);
        return 1;
    }
    ((struct tpm_req_header *)createprimary)->size = htobe32(createprimary_len);

    ret = transfer(self, createprimary, createprimary_len, "TPM2_CreatePrimary(ECC)", FALSE,
                   tpmresp, &tpmresp_len, TPM2_DURATION_LONG);
    if (ret != 0)
        return 1;
#if 0
    {
        size_t x;
        for (x = 0; x < tpmresp_len; x++) {
            if (x % 0x10 == 0)
                printf("\n");
            printf("%02x ", tpmresp[x]);
        }
        printf("\n");
    }
#endif
    if (curr_handle) {
        if (tpmresp_len < 10 + sizeof(*curr_handle))
            goto err_too_short;
        memcpy(curr_handle, &tpmresp[10], sizeof(*curr_handle));
        *curr_handle = be32toh(*curr_handle);
    }

    if (curveid == TPM2_ECC_NIST_P384) {
        exp_ksize = 48;
        cid = "secp384r1";
        if (key_description)
            *key_description = cid;
    } else {
        logerr(self->logfile, "Unknown curveid 0x%x\n", curveid);
        return 1;
    }

    if (tpmresp_len < off + sizeof(ksize1))
        goto err_too_short;
    memcpy(&ksize1, &tpmresp[off], sizeof(ksize1));
    ksize1 = be16toh(ksize1);
    off2 = off + 2 + ksize1;

    if (tpmresp_len < off2 + sizeof(ksize2))
        goto err_too_short;
    memcpy(&ksize2, &tpmresp[off2], sizeof(ksize2));
    ksize2 = be16toh(ksize2);

    if (ksize1 != exp_ksize || ksize2 != exp_ksize) {
        logerr(self->logfile, "ECC: Getting key parameters from wrong offset\n");
        return 1;
    }

    if (ekparam) {
        unsigned char *xparam = &tpmresp[off + 2];
        unsigned char *yparam = &tpmresp[off2 + 2];
        if (tpmresp_len < off + 2 + ksize1 || tpmresp_len < off2 + 2 + ksize2)
            goto err_too_short;
        g_autofree gchar *xparam_str = print_as_hex(xparam, ksize1);
        g_autofree gchar *yparam_str = print_as_hex(yparam, ksize2);

        *ekparam = g_strdup_printf("x=%s,y=%s,id=%s", xparam_str, yparam_str, cid);
    }

    return 0;

err_too_short:
    logerr(self->logfile, "Response from TPM2_CreatePrimary(ECC) is too short!\n");
    return 1;
}

static int swtpm_tpm2_createprimary_spk_ecc_nist_p384(struct swtpm *self,
                                                      uint32_t *curr_handle)
{
    unsigned int keyflags = 0x00030472;
    const unsigned char authpolicy[0];
    size_t authpolicy_len = sizeof(authpolicy);
    const unsigned char symkeydata[] = {AS2BE(TPM2_ALG_AES), AS2BE(256), AS2BE(TPM2_ALG_CFB)};
    size_t symkeydata_len = sizeof(symkeydata);
    const unsigned char schemedata[] = {
        AS2BE(TPM2_ALG_NULL), AS2BE(TPM2_ECC_NIST_P384), AS2BE(TPM2_ALG_NULL)
    };
    size_t schemedata_len = sizeof(schemedata);
    size_t off = 42;

    return swtpm_tpm2_createprimary_ecc(self, TPM2_RH_OWNER, keyflags, symkeydata, symkeydata_len,
                                        authpolicy, authpolicy_len, schemedata, schemedata_len,
                                        TPM2_ECC_NIST_P384, TPM2_ALG_SHA384,
                                        NONCE_ECC_384, sizeof(NONCE_ECC_384), off, curr_handle,
                                        NULL, 0, NULL, NULL);
}

static int createprimary_iak_idevid_ecc_nist_p384(struct swtpm *self,
                                                  unsigned int keyflags,
                                                  const unsigned char *authpolicy, size_t authpolicy_len,
                                                  const unsigned char *id, size_t id_len,
                                                  size_t off, uint32_t *curr_handle,
                                                  gchar **keyparam, const gchar **key_description)
{
    const unsigned char symkeydata[] = {AS2BE(TPM2_ALG_NULL)};
    size_t symkeydata_len = sizeof(symkeydata);
    const unsigned char schemedata[] = {
        /* TPMS_ECC_PARAMS: TPMT_ECC_SCHEME .. TPMT_KDF_SCHEME */
        AS2BE(TPM2_ALG_ECDSA),
        AS2BE(TPM2_ALG_SHA384),    // hashAlg
        AS2BE(TPM2_ECC_NIST_P384), // curveID
        AS2BE(TPM2_ALG_NULL),      // kdf->scheme
    };
    size_t schemedata_len = sizeof(schemedata);

    return swtpm_tpm2_createprimary_ecc(self, TPM2_RH_ENDORSEMENT, keyflags,
                                        symkeydata, symkeydata_len,
                                        authpolicy, authpolicy_len,
                                        schemedata, schemedata_len,
                                        TPM2_ECC_NIST_P384, TPM2_ALG_SHA384,
                                        id, id_len, off, curr_handle,
                                        NULL, 0, keyparam, key_description);
}

static int
swtpm_tpm2_createprimary_idevid_ecc_nist_p384(struct swtpm *self,
                                              uint32_t *curr_handle,
                                              gchar **keyparam,
                                              const gchar **key_description)
{
    const unsigned char authpolicy[48] = {
        /* table 19: signing */
        0x4d, 0xb1, 0xaa, 0x83, 0x6d, 0x0b, 0x56, 0x15, 0xdf, 0x6e, 0xe5, 0x3a,
        0x40, 0xef, 0x70, 0xc6, 0x1c, 0x21, 0x7f, 0x43, 0x03, 0xd4, 0x46, 0x95,
        0x92, 0x59, 0x72, 0xbc, 0x92, 0x70, 0x06, 0xcf, 0xa5, 0xcb, 0xdf, 0x6d,
        0xc1, 0x8c, 0x4d, 0xbe, 0x32, 0x9b, 0x2f, 0x15, 0x42, 0xc3, 0xdd, 0x33
    };
    size_t authpolicy_len = sizeof(authpolicy);
    // 7.3.4.1 keyflags: fixedTPM, fixedParent, sensitiveDataOrigin, userWithAuth,
    // adminWithPolicy, sign
    unsigned int keyflags = 0x000400f2;
    const char id[2 + 6] = {AS2BE(6), 0x49, 0x44, 0x45, 0x56, 0x49, 0x44}; /* 7.3.1 Table 2*/
    size_t off = 0x58;

    return createprimary_iak_idevid_ecc_nist_p384(self, keyflags, authpolicy, authpolicy_len,
                                                  (const unsigned char *)id, sizeof(id),
                                                  off, curr_handle, keyparam, key_description);
}

static int
swtpm_tpm2_createprimary_iak_ecc_nist_p384(struct swtpm *self,
                                           uint32_t *curr_handle,
                                           gchar **keyparam,
                                           const gchar **key_description)
{
    const unsigned char authpolicy[48] = {
        /* table 19: attestation */
        0x12, 0x9d, 0x94, 0xeb, 0xf8, 0x45, 0x56, 0x65, 0x2c, 0x6e, 0xef, 0x43,
        0xbb, 0xb7, 0x57, 0x51, 0x2a, 0xc8, 0x7e, 0x52, 0xbe, 0x7b, 0x34, 0x9c,
        0xa6, 0xce, 0x4d, 0x82, 0x6f, 0x74, 0x9f, 0xcf, 0x67, 0x2f, 0x51, 0x71,
        0x6c, 0x5c, 0xbb, 0x60, 0x5f, 0x31, 0x3b, 0xf3, 0x45, 0xaa, 0xb3, 0x12
    };
    size_t authpolicy_len = sizeof(authpolicy);
    // 7.3.4.1 keyflags: fixedTPM, fixedParent, sensitiveDataOrigin, userWithAuth,
    // adminWithPolicy, restricted, sign
    unsigned int keyflags = 0x000500f2;
    const char id[2 + 3] = {AS2BE(3), 0x49, 0x41, 0x4b}; /* 7.3.1 Table 2 */
    size_t off = 0x58;

    return createprimary_iak_idevid_ecc_nist_p384(self, keyflags, authpolicy, authpolicy_len,
                                                  (const unsigned char *)id, sizeof(id),
                                                  off, curr_handle, keyparam, key_description);
}

static int swtpm_tpm2_createprimary_spk_rsa(struct swtpm *self, unsigned int rsa_keysize,
                                            uint32_t *curr_handle)
{
    unsigned int keyflags = 0x00030472;
    const unsigned char authpolicy[0];
    size_t authpolicy_len = sizeof(authpolicy);
    unsigned short symkeylen = 0;
    unsigned char symkeydata[6];
    size_t symkeydata_len;
    size_t off = 44;

    if (rsa_keysize == 2048)
        symkeylen = 128;
    else if (rsa_keysize == 3072)
        symkeylen = 256;

    symkeydata_len = 6;
    memcpy(symkeydata,
           ((unsigned char[]) {AS2BE(TPM2_ALG_AES), AS2BE(symkeylen), AS2BE(TPM2_ALG_CFB)}),
           symkeydata_len);

    return swtpm_tpm2_createprimary_rsa(self, TPM2_RH_OWNER, keyflags,
                                        symkeydata, symkeydata_len,
                                        authpolicy, authpolicy_len, rsa_keysize, TRUE,
                                        off, curr_handle, NULL, 0, NULL, NULL);
}

/* Create either an ECC or RSA storage primary key */
static int swtpm_tpm2_create_spk(struct swtpm *self, gboolean isecc, unsigned int rsa_keysize)
{
    int ret;
    uint32_t curr_handle;

    if (isecc)
        ret = swtpm_tpm2_createprimary_spk_ecc_nist_p384(self, &curr_handle);
    else
        ret = swtpm_tpm2_createprimary_spk_rsa(self, rsa_keysize, &curr_handle);

    if (ret != 0)
        return 1;

    ret = swtpm_tpm2_evictcontrol(self, curr_handle, TPM2_SPK_HANDLE);
    if (ret == 0)
        logit(self->logfile,
              "Successfully created storage primary key with handle 0x%x.\n", TPM2_SPK_HANDLE);

    ret = swtpm_tpm2_flushcontext(self, curr_handle);
    if (ret != 0) {
        logerr(self->logfile, "Could not flush storage primary key.\n");
        ret = 1;
    }

    return ret;
}

static int swtpm_tpm2_create_iak(struct swtpm *self, gchar **ekparam,
                                 const gchar **key_description)
{
    uint32_t curr_handle;
    int ret;

    ret = swtpm_tpm2_createprimary_iak_ecc_nist_p384(self, &curr_handle, ekparam,
                                                     key_description);
    if (ret != 0)
        return 1;

    return swtpm_tpm2_flushcontext(self, curr_handle);
}

static int swtpm_tpm2_create_idevid(struct swtpm *self, gchar **ekparam,
                                    const gchar **key_description)
{
    uint32_t curr_handle;
    int ret;

    ret = swtpm_tpm2_createprimary_idevid_ecc_nist_p384(self, &curr_handle, ekparam,
                                                        key_description);
    if (ret != 0)
        return 1;

    return swtpm_tpm2_flushcontext(self, curr_handle);
}


/* Create an ECC EK key that may be allowed to sign and/or decrypt */
static int swtpm_tpm2_createprimary_ek_ecc_nist_p384(struct swtpm *self, gboolean allowsigning,
                                                     gboolean decryption, uint32_t *curr_handle,
                                                     unsigned char *ektemplate, size_t *ektemplate_len,
                                                     gchar **ekparam, const char **key_description)
{
    unsigned char authpolicy[48]= {
        0xB2, 0x6E, 0x7D, 0x28, 0xD1, 0x1A, 0x50, 0xBC, 0x53, 0xD8, 0x82, 0xBC,
        0xF5, 0xFD, 0x3A, 0x1A, 0x07, 0x41, 0x48, 0xBB, 0x35, 0xD3, 0xB4, 0xE4,
        0xCB, 0x1C, 0x0A, 0xD9, 0xBD, 0xE4, 0x19, 0xCA, 0xCB, 0x47, 0xBA, 0x09,
        0x69, 0x96, 0x46, 0x15, 0x0F, 0x9F, 0xC0, 0x00, 0xF3, 0xF8, 0x0E, 0x12
    };
    const unsigned char schemedata[] = {
        AS2BE(TPM2_ALG_NULL), AS2BE(TPM2_ECC_NIST_P384), AS2BE(TPM2_ALG_NULL)
    };
    size_t schemedata_len = sizeof(schemedata);
    size_t authpolicy_len = 48;
    unsigned char symkeydata[6];
    size_t symkeydata_len;
    unsigned int keyflags;
    size_t off;
    int ret;

    if (allowsigning && decryption) {
        // keyflags: fixedTPM, fixedParent, sensitiveDatOrigin,
        // userWithAuth, adminWithPolicy, sign, decrypt
        keyflags = 0x000600f2;
        // symmetric: TPM_ALG_NULL
        symkeydata_len = 2;
        memcpy(symkeydata, ((unsigned char[]){AS2BE(TPM2_ALG_NULL)}), symkeydata_len);
        off = 86;
    } else if (allowsigning) {
        // keyflags: fixedTPM, fixedParent, sensitiveDatOrigin,
        // userWithAuth, adminWithPolicy, sign
        keyflags = 0x000400f2;
        // symmetric: TPM_ALG_NULL
        symkeydata_len = 2;
        memcpy(symkeydata, ((unsigned char[]){AS2BE(TPM2_ALG_NULL)}), symkeydata_len);
        off = 86;
    } else {
        // keyflags: fixedTPM, fixedParent, sensitiveDatOrigin,
        // userWithAuth, adminWithPolicy, restricted, decrypt
        keyflags = 0x000300f2;
        // symmetric: TPM_ALG_AES, 256bit, TPM_ALG_CFB
        symkeydata_len = 6;
        memcpy(symkeydata,
               ((unsigned char[]){ AS2BE(TPM2_ALG_AES), AS2BE(256), AS2BE(TPM2_ALG_CFB)}),
               symkeydata_len);
        off = 90;
    }

    ret = swtpm_tpm2_createprimary_ecc(self, TPM2_RH_ENDORSEMENT, keyflags,
                                       symkeydata, symkeydata_len,
                                       authpolicy, authpolicy_len,
                                       schemedata, schemedata_len,
                                       TPM2_ECC_NIST_P384, TPM2_ALG_SHA384,
                                       NONCE_EMPTY, sizeof(NONCE_EMPTY), off, curr_handle,
                                       ektemplate, ektemplate_len, ekparam, key_description);
    if (ret != 0)
       logerr(self->logfile, "%s failed\n", __func__);

    return ret;
}

/* Create an ECC or RSA EK */
static int swtpm_tpm2_create_ek(struct swtpm *self, gboolean isecc, unsigned int rsa_keysize,
                                gboolean allowsigning, gboolean decryption, gboolean lock_nvram,
                                gchar **ekparam, const  gchar **key_description)
{
    uint32_t tpm2_ek_handle, nvindex, curr_handle;
    const char *keytype;
    int ret;
    unsigned char ektemplate[512];
    size_t ektemplate_len = sizeof(ektemplate);

    if (isecc) {
        tpm2_ek_handle = TPM2_EK_ECC_SECP384R1_HANDLE;
        keytype = "ECC";
        nvindex = TPM2_NV_INDEX_ECC_SECP384R1_HI_EKTEMPLATE;
    } else {
        if (rsa_keysize == 2048) {
            tpm2_ek_handle = TPM2_EK_RSA_HANDLE;
            keytype = "RSA 2048";
            nvindex = TPM2_NV_INDEX_RSA2048_EKTEMPLATE;
        } else if (rsa_keysize == 3072) {
            tpm2_ek_handle = TPM2_EK_RSA3072_HANDLE;
            keytype = "RSA 3072";
            nvindex = TPM2_NV_INDEX_RSA3072_HI_EKTEMPLATE;
        } else {
            logerr(self->logfile, "Internal error: Unsupported RSA keysize %u.\n", rsa_keysize);
            return 1;
        }
    }
    if (isecc)
        ret = swtpm_tpm2_createprimary_ek_ecc_nist_p384(self, allowsigning, decryption, &curr_handle,
                                                        ektemplate, &ektemplate_len, ekparam,
                                                        key_description);
    else
        ret = swtpm_tpm2_createprimary_ek_rsa(self, rsa_keysize, allowsigning, decryption, &curr_handle,
                                              ektemplate, &ektemplate_len, ekparam, key_description);

    if (ret == 0)
        ret = swtpm_tpm2_evictcontrol(self, curr_handle, tpm2_ek_handle);
    if (ret != 0) {
        logerr(self->logfile, "create_ek failed: 0x%x\n", ret);
        return 1;
    }

    logit(self->logfile,
          "Successfully created %s EK with handle 0x%x.\n", keytype, tpm2_ek_handle);

    if (allowsigning) {
        uint32_t nvindexattrs = TPMA_NV_PLATFORMCREATE | \
                TPMA_NV_AUTHREAD | \
                TPMA_NV_OWNERREAD | \
                TPMA_NV_PPREAD | \
                TPMA_NV_PPWRITE | \
                TPMA_NV_NO_DA | \
                TPMA_NV_WRITEDEFINE;
        ret = swtpm_tpm2_write_nvram(self, nvindex, nvindexattrs, ektemplate, ektemplate_len,
                                     lock_nvram, "EK template");
        if (ret == 0)
            logit(self->logfile,
                  "Successfully created NVRAM area 0x%x for %s EK template.\n",
                  nvindex, keytype);
    }

    return ret;
}

static int swtpm_tpm2_nvdefinespace(struct swtpm *self, uint32_t nvindex, uint32_t nvindexattrs,
                                    uint16_t data_len)
{
    struct tpm_req_header hdr = TPM_REQ_HEADER_INITIALIZER(TPM2_ST_SESSIONS, 0, TPM2_CC_NV_DEFINESPACE);
    struct tpm2_authblock authblock = TPM2_AUTHBLOCK_INITIALIZER(TPM2_RS_PW, 0, 0, 0);
    g_autofree unsigned char *nvpublic = NULL;
    ssize_t nvpublic_len;
    g_autofree unsigned char *req = NULL;
    ssize_t req_len;

    nvpublic_len = memconcat(&nvpublic,
                             (unsigned char[]){
                                 AS4BE(nvindex), AS2BE(TPM2_ALG_SHA256), AS4BE(nvindexattrs),
                                 AS2BE(0), AS2BE(data_len)}, (size_t)14,
                             NULL);
    if (nvpublic_len < 0) {
        logerr(self->logfile, "Internal error in %s: memconcat failed\n", __func__);
        return 1;
    }

    req_len = memconcat(&req,
                        &hdr, sizeof(hdr),
                        (unsigned char[]){AS4BE(TPM2_RH_PLATFORM), AS4BE(sizeof(authblock))}, (size_t)8,
                        &authblock, sizeof(authblock),
                        (unsigned char[]){AS2BE(0), AS2BE(nvpublic_len)}, (size_t)4,
                        nvpublic, nvpublic_len,
                        NULL);
    if (req_len < 0) {
        logerr(self->logfile, "Internal error in %s: memconcat failed\n", __func__);
        return 1;
    }

    ((struct tpm_req_header *)req)->size = htobe32(req_len);

    return transfer(self, req, req_len, "TPM2_NV_DefineSpace", FALSE,
                    NULL, NULL, TPM2_DURATION_SHORT);
}

/* Write the data into the given NVIndex */
static int swtpm_tpm2_nv_write(struct swtpm *self, uint32_t nvindex,
                               const unsigned char *data, size_t data_len)
{
    struct tpm_req_header hdr = TPM_REQ_HEADER_INITIALIZER(TPM2_ST_SESSIONS, 0, TPM2_CC_NV_WRITE);
    struct tpm2_authblock authblock = TPM2_AUTHBLOCK_INITIALIZER(TPM2_RS_PW, 0, 0, 0);
    g_autofree unsigned char *req = NULL;
    ssize_t req_len;
    size_t offset = 0, txlen;
    int ret;

    while (offset < data_len) {
        txlen = min(data_len - offset, 1024);

        g_free(req);
        req_len = memconcat(&req,
                            &hdr, sizeof(hdr),
                            (unsigned char[]){
                                AS4BE(TPM2_RH_PLATFORM), AS4BE(nvindex), AS4BE(sizeof(authblock))
                            }, (size_t)12,
                            &authblock, sizeof(authblock),
                            (unsigned char[]){AS2BE(txlen)}, (size_t)2,
                            &data[offset], txlen,
                            (unsigned char[]){AS2BE(offset)}, (size_t)2,
                            NULL);
        if (req_len < 0) {
            logerr(self->logfile, "Internal error in %s: memconcat failed\n", __func__);
            return 1;
        }
        ((struct tpm_req_header *)req)->size = htobe32(req_len);

        ret = transfer(self, req, req_len, "TPM2_NV_Write", FALSE,
                       NULL, NULL, TPM2_DURATION_SHORT);
        if (ret != 0)
            return 1;

        offset += txlen;
    }
    return 0;
}

static int swtpm_tpm2_nv_writelock(struct swtpm *self, uint32_t nvindex)
{
    struct tpm_req_header hdr = TPM_REQ_HEADER_INITIALIZER(TPM2_ST_SESSIONS, 0, TPM2_CC_NV_WRITELOCK);
    struct tpm2_authblock authblock = TPM2_AUTHBLOCK_INITIALIZER(TPM2_RS_PW, 0, 0, 0);
    g_autofree unsigned char *req;
    ssize_t req_len;

    req_len = memconcat(&req,
                        &hdr, sizeof(hdr),
                        (unsigned char[]){
                           AS4BE(TPM2_RH_PLATFORM), AS4BE(nvindex), AS4BE(sizeof(authblock))
                        }, (size_t)12,
                        &authblock, sizeof(authblock),
                        NULL);
    if (req_len < 0) {
        logerr(self->logfile, "Internal error in %s: memconcat failed\n", __func__);
        return 1;
    }

    ((struct tpm_req_header *)req)->size = htobe32(req_len);

    return transfer(self, req, req_len, "TPM2_NV_WriteLock", FALSE,
                    NULL, NULL, TPM2_DURATION_SHORT);
}

static int swtpm_tpm2_write_nvram(struct swtpm *self, uint32_t nvindex, uint32_t nvindexattrs,
                                  const unsigned char *data, size_t data_len, gboolean lock_nvram,
                                  const char *certtype)
{
    int ret = swtpm_tpm2_nvdefinespace(self, nvindex, nvindexattrs, data_len);
    if (ret != 0) {
        logerr(self->logfile, "Could not create NVRAM area 0x%x for %s.\n", nvindex, certtype);
        return 1;
    }

    ret = swtpm_tpm2_nv_write(self, nvindex, data, data_len);
    if (ret != 0) {
        logerr(self->logfile,
               "Could not write %s into NVRAM area 0x%x.\n", certtype, nvindex);
        return 1;
    }

    if (lock_nvram) {
        ret = swtpm_tpm2_nv_writelock(self, nvindex);
        if (ret != 0) {
            logerr(self->logfile, "Could not lock EK template NVRAM area 0x%x.\n", nvindex);
            return 1;
        }
    }

    return 0;
}

static int swtpm_tpm2_write_cert_nvram(struct swtpm *self, uint32_t nvindex,
                                       uint32_t nvindexattrs,
                                       const unsigned char *data, size_t data_len,
                                       gboolean lock_nvram, const char *keytype,
                                       const char *certtype)
{
    int ret;

    ret = swtpm_tpm2_write_nvram(self, nvindex, nvindexattrs, data, data_len, lock_nvram,
                                 certtype);
    if (ret == 0)
        logit(self->logfile,
              "Successfully created NVRAM area 0x%x for %s%s.\n",
              nvindex, keytype, certtype);

    return ret;
}

/* Write the platform certificate into an NVRAM area */
static int swtpm_tpm2_write_ek_cert_nvram(struct swtpm *self, gboolean isecc,
                                           unsigned int rsa_keysize, gboolean lock_nvram,
                                           const unsigned char *data, size_t data_len)
{
    uint32_t nvindex = 0;
    g_autofree gchar *keytype = NULL;
    uint32_t nvindexattrs = TPMA_NV_PLATFORMCREATE |
            TPMA_NV_AUTHREAD |
            TPMA_NV_OWNERREAD |
            TPMA_NV_PPREAD |
            TPMA_NV_PPWRITE |
            TPMA_NV_NO_DA |
            TPMA_NV_WRITEDEFINE;

    if (!isecc) {
        if (rsa_keysize == 2048)
            nvindex = TPM2_NV_INDEX_RSA2048_EKCERT;
        else if (rsa_keysize == 3072)
            nvindex = TPM2_NV_INDEX_RSA3072_HI_EKCERT;
        keytype = g_strdup_printf("RSA %d ", rsa_keysize);
    } else {
        nvindex = TPM2_NV_INDEX_ECC_SECP384R1_HI_EKCERT;
        keytype = g_strdup("ECC ");
    }

    return swtpm_tpm2_write_cert_nvram(self, nvindex, nvindexattrs, data, data_len,
                                       lock_nvram, keytype, "EK certificate");
}

static int swtpm_tpm2_write_platform_cert_nvram(struct swtpm *self, gboolean lock_nvram,
                                                const unsigned char *data, size_t data_len)
{
    uint32_t nvindex = TPM2_NV_INDEX_PLATFORMCERT;
    uint32_t nvindexattrs = TPMA_NV_PLATFORMCREATE |
            TPMA_NV_AUTHREAD |
            TPMA_NV_OWNERREAD |
            TPMA_NV_PPREAD |
            TPMA_NV_PPWRITE |
            TPMA_NV_NO_DA |
            TPMA_NV_WRITEDEFINE;

    return swtpm_tpm2_write_cert_nvram(self, nvindex, nvindexattrs, data, data_len,
                                       lock_nvram, "", "platform certificate");
}

static int swtpm_tpm2_write_iak_cert_nvram(struct swtpm *self, gboolean lock_nvram,
                                           const unsigned char *data, size_t data_len)
{
    uint32_t nvindex = TPM2_NV_INDEX_IAK_SHA384;
    uint32_t nvindexattrs = TPMA_NV_PLATFORMCREATE |
            TPMA_NV_AUTHREAD |
            TPMA_NV_OWNERREAD |
            TPMA_NV_PPREAD |
            TPMA_NV_PPWRITE |
            TPMA_NV_NO_DA |
            TPMA_NV_WRITEDEFINE; // FIXME: fix flags?

    return swtpm_tpm2_write_cert_nvram(self, nvindex, nvindexattrs, data, data_len,
                                       lock_nvram, "", "IAK certificate");
}

static int swtpm_tpm2_write_idevid_cert_nvram(struct swtpm *self, gboolean lock_nvram,
                                              const unsigned char *data, size_t data_len)
{
    uint32_t nvindex = TPM2_NV_INDEX_IDEVID_SHA384;
    uint32_t nvindexattrs = TPMA_NV_PLATFORMCREATE |
            TPMA_NV_AUTHREAD |
            TPMA_NV_OWNERREAD |
            TPMA_NV_PPREAD |
            TPMA_NV_PPWRITE |
            TPMA_NV_NO_DA |
            TPMA_NV_WRITEDEFINE; // FIXME: fix flags?

    return swtpm_tpm2_write_cert_nvram(self, nvindex, nvindexattrs, data, data_len,
                                       lock_nvram, "", "IDevID certificate");
}

static int swtpm_tpm2_get_capability(struct swtpm *self, uint32_t cap, uint32_t prop,
                                     uint32_t *res)
{
    struct tpm2_get_capability_req {
        struct tpm_req_header hdr;
        uint32_t cap;
        uint32_t prop;
        uint32_t count;
    } __attribute__((packed)) req = {
        .hdr = TPM_REQ_HEADER_INITIALIZER(TPM2_ST_NO_SESSIONS, sizeof(req), TPM2_CC_GETCAPABILITY),
        .cap = htobe32(cap),
        .prop = htobe32(prop),
        .count = htobe32(1),
    };
    unsigned char tpmresp[27];
    size_t tpmresp_len = sizeof(tpmresp);
    uint32_t val;
    int ret;

    ret = transfer(self, &req, sizeof(req), "TPM2_GetCapability", FALSE,
                   tpmresp, &tpmresp_len, TPM2_DURATION_SHORT);
    if (ret != 0)
        return 1;

    memcpy(&val, &tpmresp[23], sizeof(val));
    *res = be32toh(val);

    return 0;
}

static const struct swtpm2_ops swtpm_tpm2_ops = {
    .shutdown = swtpm_tpm2_shutdown,
    .create_iak = swtpm_tpm2_create_iak,
    .create_idevid = swtpm_tpm2_create_idevid,
    .create_spk = swtpm_tpm2_create_spk,
    .create_ek = swtpm_tpm2_create_ek,
    .get_all_pcr_banks = swtpm_tpm2_get_all_pcr_banks,
    .set_active_pcr_banks = swtpm_tpm2_set_active_pcr_banks,
    .write_ek_cert_nvram = swtpm_tpm2_write_ek_cert_nvram,
    .write_platform_cert_nvram = swtpm_tpm2_write_platform_cert_nvram,
    .write_iak_cert_nvram = swtpm_tpm2_write_iak_cert_nvram,
    .write_idevid_cert_nvram = swtpm_tpm2_write_idevid_cert_nvram,
    .get_capability = swtpm_tpm2_get_capability,
};

/*
 * TPM 1.2 support
 */
#define TPM_TAG_RQU_COMMAND       0x00c1
#define TPM_TAG_RQU_AUTH1_COMMAND 0x00c2

#define TPM_ORD_OIAP                     0x0000000A
#define TPM_ORD_TAKE_OWNERSHIP           0x0000000D
#define TPM_ORD_PHYSICAL_ENABLE          0x0000006F
#define TPM_ORD_PHYSICAL_SET_DEACTIVATED 0x00000072
#define TPM_ORD_NV_DEFINE_SPACE          0x000000CC
#define TPM_ORD_NV_WRITE_VALUE           0x000000CD
#define TSC_ORD_PHYSICAL_PRESENCE        0x4000000A

#define TPM_ST_CLEAR 0x0001

#define TPM_PHYSICAL_PRESENCE_CMD_ENABLE  0x0020
#define TPM_PHYSICAL_PRESENCE_PRESENT     0x0008

#define TPM_ALG_RSA 0x00000001

#define TPM_KEY_STORAGE 0x0011

#define TPM_AUTH_ALWAYS 0x01

#define TPM_PID_OWNER  0x0005

#define TPM_ES_RSAESOAEP_SHA1_MGF1 0x0003
#define TPM_SS_NONE 0x0001

#define TPM_TAG_PCR_INFO_LONG   0x0006
#define TPM_TAG_NV_ATTRIBUTES   0x0017
#define TPM_TAG_NV_DATA_PUBLIC  0x0018
#define TPM_TAG_KEY12           0x0028

#define TPM_LOC_ZERO   0x01
#define TPM_LOC_ALL    0x1f

#define TPM_NV_INDEX_D_BIT        0x10000000
#define TPM_NV_INDEX_EKCERT       0xF000
#define TPM_NV_INDEX_PLATFORMCERT 0xF002

#define TPM_NV_INDEX_LOCK 0xFFFFFFFF

#define TPM_NV_PER_OWNERREAD   0x00020000
#define TPM_NV_PER_OWNERWRITE  0x00000002

#define TPM_ET_OWNER 0x02
#define TPM_ET_NV    0x0b

#define TPM_KH_EK    0x40000006

#define TPM_DURATION_SHORT     2000  /* ms */
#define TPM_DURATION_MEDIUM    7500  /* ms */
#define TPM_DURATION_LONG     15000  /* ms */

static int swtpm_tpm12_tsc_physicalpresence(struct swtpm *self, uint16_t physicalpresence)
{
    struct tpm12_tsc_physicalpresence {
        struct tpm_req_header hdr;
        uint16_t pp;
    } req = {
        .hdr = TPM_REQ_HEADER_INITIALIZER(TPM_TAG_RQU_COMMAND, sizeof(req), TSC_ORD_PHYSICAL_PRESENCE),
        .pp = htobe16(physicalpresence),
    };

    /* use medium duration to avoid t/o on busy system */
    return transfer(self, &req, sizeof(req), "TSC_PhysicalPresence", FALSE,
                    NULL, NULL, TPM_DURATION_MEDIUM);
}

static int swtpm_tpm12_physical_enable(struct swtpm *self)
{
    struct tpm_req_header req = TPM_REQ_HEADER_INITIALIZER(TPM_TAG_RQU_COMMAND, sizeof(req), TPM_ORD_PHYSICAL_ENABLE);

    return transfer(self, &req, sizeof(req), "TPM_PhysicalEnable", FALSE,
                    NULL, NULL, TPM_DURATION_SHORT);
}

static int swtpm_tpm12_physical_set_deactivated(struct swtpm *self, uint8_t state)
{
    struct tpm12_tsc_physical_set_deactivated {
        struct tpm_req_header hdr;
        uint8_t state;
    } req = {
        .hdr = TPM_REQ_HEADER_INITIALIZER(TPM_TAG_RQU_COMMAND, sizeof(req), TPM_ORD_PHYSICAL_SET_DEACTIVATED),
        .state = state,
    };

    return transfer(self, &req, sizeof(req), "TSC_PhysicalSetDeactivated", FALSE,
                    NULL, NULL, TPM_DURATION_SHORT);
}

/* Initialize the TPM1.2 */
static int swtpm_tpm12_run_swtpm_bios(struct swtpm *self)
{
    if (swtpm_tpm12_tsc_physicalpresence(self, TPM_PHYSICAL_PRESENCE_CMD_ENABLE) ||
        swtpm_tpm12_tsc_physicalpresence(self, TPM_PHYSICAL_PRESENCE_PRESENT) ||
        swtpm_tpm12_physical_enable(self) ||
        swtpm_tpm12_physical_set_deactivated(self, 0))
        return 1;

    return 0;
}

static int swptm_tpm12_create_endorsement_keypair(struct swtpm *self,
                                                  gchar **pubek, size_t *pubek_len)
{
    unsigned char req[] = {
        0x00, 0xc1, 0x00, 0x00, 0x00, 0x36, 0x00, 0x00, 0x00, 0x78, 0x38, 0xf0, 0x30, 0x81, 0x07, 0x2b,
        0x0c, 0xa9, 0x10, 0x98, 0x08, 0xc0, 0x4B, 0x05, 0x11, 0xc9, 0x50, 0x23, 0x52, 0xc4, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x03, 0x00, 0x02, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
        0x00, 0x02, 0x00, 0x00, 0x00, 0x00
    };
    unsigned char tpmresp[512];
    size_t tpmresp_len = sizeof(tpmresp);
    uint32_t length;
    int ret;

    ret = transfer(self, &req, sizeof(req), "TPM_CreateEndorsementKeyPair", FALSE,
                   &tpmresp, &tpmresp_len, TPM_DURATION_LONG);
    if (ret != 0)
        return 1;

    if (tpmresp_len < 34 + sizeof(length))
        goto err_too_short;
    memcpy(&length, &tpmresp[34], sizeof(length));
    length = be32toh(length);
    if (length != 256) {
        logerr(self->logfile, "Offset to EK Public key is wrong.\n");
        return 1;
    }

    *pubek_len = 256;
    if (tpmresp_len < 38 + *pubek_len)
        goto err_too_short;
    *pubek = g_malloc(256);
    memcpy(*pubek, &tpmresp[38], *pubek_len);

    return 0;

err_too_short:
    logerr(self->logfile, "Response from TPM_CreateEndorsementKeyPair is too short!\n");
    return 1;
}

/* Create an OIAP session */
static int swtpm_tpm12_oiap(struct swtpm *self, uint32_t *authhandle, unsigned char nonce_even[SHA_DIGEST_LENGTH])
{
    struct tpm_req_header req = TPM_REQ_HEADER_INITIALIZER(TPM_TAG_RQU_COMMAND, sizeof(req), TPM_ORD_OIAP);
    unsigned char tpmresp[64];
    size_t tpmresp_len = sizeof(tpmresp);
    int ret;

    ret = transfer(self, &req, sizeof(req), "TPM_OIAP", FALSE,
                   &tpmresp, &tpmresp_len, TPM_DURATION_SHORT);
    if (ret != 0)
        return ret;

    if (tpmresp_len < 10 + sizeof(*authhandle) || tpmresp_len < 14 + SHA_DIGEST_LENGTH)
        goto err_too_short;
    memcpy(authhandle, &tpmresp[10], sizeof(*authhandle));
    *authhandle = be32toh(*authhandle);
    memcpy(nonce_even, &tpmresp[14], SHA_DIGEST_LENGTH);

    return 0;

err_too_short:
    logerr(self->logfile, "Response from TPM_OIAP is too short!\n");
    return 1;
}

static int swtpm_tpm12_take_ownership(struct swtpm *self, const unsigned char ownerpass_digest[SHA_DIGEST_LENGTH],
                                      const unsigned char srkpass_digest[SHA_DIGEST_LENGTH],
                                      const unsigned char *pubek, size_t pubek_len)
{
    struct tpm_req_header hdr = TPM_REQ_HEADER_INITIALIZER(TPM_TAG_RQU_AUTH1_COMMAND, 0, TPM_ORD_TAKE_OWNERSHIP);
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    BIGNUM *exp = BN_new();
    BIGNUM *mod = NULL;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    RSA *rsakey = RSA_new();
#endif
    int ret = 1;
    const EVP_MD *sha1 = EVP_sha1();
    g_autofree unsigned char *enc_owner_auth = g_malloc(pubek_len);
    size_t enc_owner_auth_len = pubek_len;
    g_autofree unsigned char *enc_srk_auth = g_malloc(pubek_len);
    size_t enc_srk_auth_len = pubek_len;
    uint32_t auth_handle;
    unsigned char nonce_even[SHA_DIGEST_LENGTH];
    unsigned char nonce_odd[SHA_DIGEST_LENGTH] = {1, 2, 3, 4, 5, 6, };
    g_autofree unsigned char *tpm_rsa_key_parms = NULL;
    ssize_t tpm_rsa_key_parms_len;
    g_autofree unsigned char *tpm_key_parms = NULL;
    ssize_t tpm_key_parms_len;
    g_autofree unsigned char *tpm_key12 = NULL;
    ssize_t tpm_key12_len;
    g_autofree unsigned char *in_auth_setup_params = NULL;
    ssize_t in_auth_setup_params_len;
    g_autofree unsigned char *macinput = NULL;
    ssize_t macinput_len;
    unsigned char in_param_digest[SHA_DIGEST_LENGTH];
    unsigned char owner_auth[SHA_DIGEST_LENGTH];
    unsigned int owner_auth_len = sizeof(owner_auth);
    uint8_t continue_auth_session = 0;
    unsigned char req[1024];
    ssize_t req_len, len;
    struct tpm_req_header *trh;

    mod = BN_bin2bn((const unsigned char *)pubek, pubek_len, NULL);
    if (exp == NULL || mod == NULL ||
        BN_hex2bn(&exp, "10001") == 0) {
        logerr(self->logfile, "Could not create public RSA key!\n");
        goto error_free_bn;
    }

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "rsa", NULL);
    if (ctx != NULL) {
        OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
        OSSL_PARAM *params;

        if (bld == NULL ||
            OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, exp) != 1 ||
            OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, mod) != 1 ||
            (params = OSSL_PARAM_BLD_to_param(bld)) == NULL) {
            OSSL_PARAM_BLD_free(bld);
            goto error_free_bn;
        }
        OSSL_PARAM_BLD_free(bld);

        if (EVP_PKEY_fromdata_init(ctx) != 1 ||
            EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) != 1) {
            logerr(self->logfile, "Could not set pkey parameters!\n");
            OSSL_PARAM_free(params);
            goto error_free_bn;
        }
        OSSL_PARAM_free(params);

        EVP_PKEY_CTX_free(ctx);
    } else {
        logerr(self->logfile, "Could not create key creation context!\n");
        goto error_free_bn;
    }
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if (ctx == NULL)
        goto error_free_bn;
#else
    pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        logerr(self->logfile, "Could not allocate pkey!\n");
        goto error_free_bn;
    }

# if OPENSSL_VERSION_NUMBER < 0x10100000
    rsakey->n = mod;
    rsakey->e = exp;
# else
    if (RSA_set0_key(rsakey, mod, exp, NULL) != 1) {
        logerr(self->logfile, "Could not create public RSA key!\n");
        goto error_free_bn;
    }
# endif
    if (EVP_PKEY_assign_RSA(pkey, rsakey) != 1) {
        logerr(self->logfile, "Could not create public RSA key!\n");
        goto error_free_pkey_and_rsa;
    }

    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (ctx == NULL)
        goto error_free_pkey;
#endif /* OPENSSL_VERSION_NUMBER >= 0x30000000L */

    if (EVP_PKEY_encrypt_init(ctx) < 1 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) < 1 ||
        EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, sha1) < 1 ||
        EVP_PKEY_CTX_set_rsa_oaep_md(ctx, sha1) < 1 ||
        EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, g_strdup("TCPA"), 4) < 1 ||
        EVP_PKEY_encrypt(ctx, enc_owner_auth, &enc_owner_auth_len,
                         ownerpass_digest, SHA_DIGEST_LENGTH) < 1||
        EVP_PKEY_encrypt(ctx, enc_srk_auth, &enc_srk_auth_len,
                         srkpass_digest, SHA_DIGEST_LENGTH) < 1) {
        logerr(self->logfile, "Internal error in %s: encryption failed\n", __func__);
        goto error;
    }
    ret = swtpm_tpm12_oiap(self, &auth_handle, nonce_even);
    if (ret != 0)
        goto error;

    tpm_rsa_key_parms_len = memconcat(&tpm_rsa_key_parms,
                                      (unsigned char[]){
                                          AS4BE(2048), AS4BE(2), AS4BE(0)
                                      }, (size_t)12,
                                      NULL);
    if (tpm_rsa_key_parms_len < 0) {
        logerr(self->logfile, "Internal error in %s: out of memory\n");
        goto error;
    }

    tpm_key_parms_len = memconcat(&tpm_key_parms,
                                  (unsigned char[]){
                                      AS4BE(TPM_ALG_RSA),
                                      AS2BE(TPM_ES_RSAESOAEP_SHA1_MGF1),
                                      AS2BE(TPM_SS_NONE),
                                      AS4BE(tpm_rsa_key_parms_len)}, (size_t)12,
                                  tpm_rsa_key_parms, tpm_rsa_key_parms_len,
                                  NULL);
    if (tpm_key_parms_len < 0) {
        logerr(self->logfile, "Internal error in %s: out of memory\n");
        goto error;
    }

    tpm_key12_len = memconcat(&tpm_key12,
                              (unsigned char[]){
                                  AS2BE(TPM_TAG_KEY12), AS2BE(0),
                                  AS2BE(TPM_KEY_STORAGE), AS4BE(0), TPM_AUTH_ALWAYS
                              }, (size_t)11,
                              tpm_key_parms, tpm_key_parms_len,
                              (unsigned char[]){AS4BE(0), AS4BE(0), AS4BE(0)}, (size_t)12,
                              NULL);
    if (tpm_key12_len < 0) {
        logerr(self->logfile, "Internal error in %s: out of memory\n");
        goto error;
    }

    req_len = concat(req, sizeof(req),
                     &hdr, sizeof(hdr),
                     (unsigned char[]){AS2BE(TPM_PID_OWNER), AS4BE(enc_owner_auth_len)}, (size_t)6,
                     enc_owner_auth, enc_owner_auth_len,
                     (unsigned char[]){AS4BE(enc_srk_auth_len)}, (size_t)4,
                     enc_srk_auth, enc_srk_auth_len,
                     tpm_key12, tpm_key12_len,
                     NULL);
    if (req_len < 0) {
        logerr(self->logfile, "Internal error in %s: req is too small\n");
        goto error;
    }
    SHA1(&req[6], req_len - 6, in_param_digest);

    in_auth_setup_params_len = memconcat(&in_auth_setup_params,
                                         nonce_even, sizeof(nonce_even),
                                         nonce_odd, sizeof(nonce_odd),
                                         &continue_auth_session, (size_t)1,
                                         NULL);
    if (in_auth_setup_params_len < 0) {
        logerr(self->logfile, "Internal error in %s: out of memory\n");
        goto error;
    }

    macinput_len = memconcat(&macinput,
                             in_param_digest, sizeof(in_param_digest),
                             in_auth_setup_params, in_auth_setup_params_len,
                             NULL);
    if (macinput_len < 0) {
        logerr(self->logfile, "Internal error in %s: out of memory\n");
        goto error;
    }

    HMAC(sha1, ownerpass_digest, SHA_DIGEST_LENGTH, macinput, macinput_len,
         owner_auth, &owner_auth_len);

    len = concat(&req[req_len], sizeof(req) - req_len,
                 (unsigned char[]){AS4BE(auth_handle)}, (size_t)4,
                 nonce_odd, sizeof(nonce_odd),
                 &continue_auth_session, (size_t)1,
                 owner_auth, owner_auth_len,
                 NULL);
    if (len < 0) {
        logerr(self->logfile, "Internal error in %s: req is too small\n");
        goto error;
    }
    req_len += len;

    trh = (struct tpm_req_header *)req; /* old gcc type-punned pointer */
    trh->size = htobe32(req_len);

    ret = transfer(self, req, req_len, "TPM_TakeOwnership", FALSE,
                   NULL, NULL, TPM_DURATION_LONG);

error:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    BN_free(exp);
    BN_free(mod);
#endif
    return ret;

error_free_bn:
    BN_free(exp);
    BN_free(mod);

#if OPENSSL_VERSION_NUMBER < 0x30000000L
error_free_pkey_and_rsa:
    RSA_free(rsakey);
error_free_pkey:
#else
    EVP_PKEY_CTX_free(ctx);
#endif
    EVP_PKEY_free(pkey);

    return 1;
}

static int swtpm_tpm12_nv_define_space(struct swtpm *self, uint32_t nvindex,
                                       uint32_t nvindexattrs, size_t size)
{
    struct tpm_req_header hdr = TPM_REQ_HEADER_INITIALIZER(TPM_TAG_RQU_COMMAND, 0, TPM_ORD_NV_DEFINE_SPACE);
    g_autofree unsigned char *pcr_info_short = NULL;
    ssize_t pcr_info_short_len;
    g_autofree unsigned char *nv_data_public = NULL;
    ssize_t nv_data_public_len;
    g_autofree unsigned char *req = NULL;
    ssize_t req_len;
    unsigned char zeroes[SHA_DIGEST_LENGTH] = {0, };

    pcr_info_short_len = memconcat(&pcr_info_short,
                                   (unsigned char[]){AS2BE(3), 0, 0, 0, TPM_LOC_ALL}, (size_t)6,
                                   zeroes, sizeof(zeroes),
                                   NULL);
    if (pcr_info_short_len < 0) {
        logerr(self->logfile, "Internal error in %s: out of memory\n");
        return 1;
    }

    nv_data_public_len = memconcat(&nv_data_public,
                                   (unsigned char[]){
                                       AS2BE(TPM_TAG_NV_DATA_PUBLIC), AS4BE(nvindex)
                                   }, (size_t)6,
                                   pcr_info_short, pcr_info_short_len,
                                   pcr_info_short, pcr_info_short_len,
                                   (unsigned char[]){
                                       AS2BE(TPM_TAG_NV_ATTRIBUTES), AS4BE(nvindexattrs),
                                       0, 0, 0, AS4BE(size)
                                   }, (size_t)13,
                                   NULL);
    if (nv_data_public_len < 0) {
        logerr(self->logfile, "Internal error in %s: out of memory\n");
        return 1;
    }

    req_len = memconcat(&req,
                        &hdr, sizeof(hdr),
                        nv_data_public, nv_data_public_len,
                        zeroes, sizeof(zeroes),
                        NULL);
    if (req_len < 0) {
        logerr(self->logfile, "Internal error in %s: out of memory\n");
        return 1;
    }

    ((struct tpm_req_header *)req)->size = htobe32(req_len);

    return transfer(self, req, req_len, "TPM_NV_DefineSpace", FALSE,
                    NULL, NULL, TPM_DURATION_SHORT);
}

static int swtpm_tpm12_nv_write_value(struct swtpm *self, uint32_t nvindex,
                                      const unsigned char *data, size_t data_len)
{
    struct tpm_req_header hdr = TPM_REQ_HEADER_INITIALIZER(TPM_TAG_RQU_COMMAND, 0, TPM_ORD_NV_WRITE_VALUE);
    g_autofree unsigned char *req = NULL;
    ssize_t req_len;

    req_len = memconcat(&req,
                        &hdr, sizeof(hdr),
                        (unsigned char[]){AS4BE(nvindex), AS4BE(0), AS4BE(data_len)}, (size_t)12,
                        data, data_len,
                        NULL);
    if (req_len < 0) {
        logerr(self->logfile, "Internal error in %s: out of memory\n");
        return 1;
    }

    ((struct tpm_req_header *)req)->size = htobe32(req_len);

    return transfer(self, req, req_len, "TPM_NV_DefineSpace", FALSE,
                    NULL, NULL, TPM_DURATION_SHORT);
}

/* Write the EK Certificate into NVRAM */
static int swtpm_tpm12_write_ek_cert_nvram(struct swtpm *self,
                                           const unsigned char *data, size_t data_len)
{
    uint32_t nvindex = TPM_NV_INDEX_EKCERT | TPM_NV_INDEX_D_BIT;
    int ret = swtpm_tpm12_nv_define_space(self, nvindex,
                                          TPM_NV_PER_OWNERREAD | TPM_NV_PER_OWNERWRITE, data_len);
    if (ret != 0)
        return 1;

    ret = swtpm_tpm12_nv_write_value(self, nvindex, data, data_len);
    if (ret != 0)
        return 1;

    return 0;
}

/* Write the Platform Certificate into NVRAM */
static int swtpm_tpm12_write_platform_cert_nvram(struct swtpm *self,
                                                 const unsigned char *data, size_t data_len)
{
    uint32_t nvindex = TPM_NV_INDEX_PLATFORMCERT | TPM_NV_INDEX_D_BIT;
    int ret = swtpm_tpm12_nv_define_space(self, nvindex,
                                          TPM_NV_PER_OWNERREAD | TPM_NV_PER_OWNERWRITE, data_len);
    if (ret != 0)
        return 1;

    ret = swtpm_tpm12_nv_write_value(self, nvindex, data, data_len);
    if (ret != 0)
        return 1;

    return 0;
}

static int swtpm_tpm12_nv_lock(struct swtpm *self)
{
    return swtpm_tpm12_nv_define_space(self, TPM_NV_INDEX_LOCK, 0, 0);
}

static const struct swtpm12_ops swtpm_tpm12_ops = {
    .run_swtpm_bios = swtpm_tpm12_run_swtpm_bios,
    .create_endorsement_key_pair = swptm_tpm12_create_endorsement_keypair,
    .take_ownership = swtpm_tpm12_take_ownership,
    .write_ek_cert_nvram = swtpm_tpm12_write_ek_cert_nvram,
    .write_platform_cert_nvram = swtpm_tpm12_write_platform_cert_nvram,
    .nv_lock = swtpm_tpm12_nv_lock,
};

static void swtpm_init(struct swtpm *swtpm,
                       gchar **swtpm_exec_l, const gchar *state_path,
                       const gchar *keyopts, const gchar *logfile,
                       int *fds_to_pass, size_t n_fds_to_pass,
                       gboolean is_tpm2, const gchar *json_profile)
{
    swtpm->cops = &swtpm_cops;
    swtpm->swtpm_exec_l = swtpm_exec_l;
    swtpm->state_path = state_path;
    swtpm->keyopts = keyopts;
    swtpm->logfile = logfile;
    swtpm->fds_to_pass = fds_to_pass;
    swtpm->n_fds_to_pass = n_fds_to_pass;
    swtpm->is_tpm2 = is_tpm2;
    swtpm->json_profile = json_profile;

    swtpm->pid = -1;
    swtpm->ctrl_fds[0] = swtpm->ctrl_fds[1] = -1;
    swtpm->data_fds[0] = swtpm->data_fds[1] = -1;
}

struct swtpm12 *swtpm12_new(gchar **swtpm_exec_l, const gchar *state_path,
                            const gchar *keyopts, const gchar *logfile,
                            int *fds_to_pass, size_t n_fds_to_pass)
{
    struct swtpm12 *swtpm12 = g_malloc0(sizeof(struct swtpm12));

    swtpm_init(&swtpm12->swtpm, swtpm_exec_l, state_path, keyopts, logfile,
               fds_to_pass, n_fds_to_pass, FALSE, NULL);
    swtpm12->ops = &swtpm_tpm12_ops;

    return swtpm12;
}

struct swtpm2 *swtpm2_new(gchar **swtpm_exec_l, const gchar *state_path,
                         const gchar *keyopts, const gchar *logfile,
                         int *fds_to_pass, size_t n_fds_to_pass,
                         const gchar *json_profile)
{
    struct swtpm2 *swtpm2 = g_malloc0(sizeof(struct swtpm2));

    swtpm_init(&swtpm2->swtpm, swtpm_exec_l, state_path, keyopts, logfile,
               fds_to_pass, n_fds_to_pass, TRUE, json_profile);
    swtpm2->ops = &swtpm_tpm2_ops;

    return swtpm2;
}

void swtpm_free(struct swtpm *swtpm) {
    if (!swtpm)
        return;
    g_free(swtpm);
}

