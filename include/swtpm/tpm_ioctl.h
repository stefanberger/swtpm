/*
 * tpm_ioctl.h
 *
 * (c) Copyright IBM Corporation 2014, 2015.
 *
 * This file is licensed under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 */

#include <stdint.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/ioctl.h>

/*
 * Every response from a command involving a TPM command execution must hold
 * the ptmres_t as the first element.
 * ptmres_t corresponds to the error code of a command executed by the TPM.
 */

typedef uint32_t ptmres_t;

/* PTM_GET_TPMESTABLISHED */
struct ptmest {
    ptmres_t tpm_result;
    unsigned char bit; /* TPM established bit */
};

/* PTM_RESET_PTMESTABLIHSED: reset establishment bit */
struct ptmreset_est {
    union {
        struct {
            uint8_t loc; /* locality to use */
        } req;
        struct {
            ptmres_t tpm_result;
        } resp;
    } u;
};

/* PTM_INIT */
struct ptminit {
    union {
        struct {
            uint32_t init_flags; /* see definitions below */
        } req;
        struct {
            ptmres_t tpm_result;
        } resp;
    } u;
};

/* above init_flags */
#define INIT_FLAG_DELETE_VOLATILE (1 << 0)
    /* delete volatile state file after reading it */

/* PTM_SET_LOCALITY */
struct ptmloc {
    union {
        struct {
            uint8_t loc; /* locality to set */
        } req;
        struct {
            ptmres_t tpm_result;
        } resp;
    } u;
};

/* PTM_HASH_DATA: hash given data */
struct ptmhdata {
    union {
        struct {
            uint32_t length;
            uint8_t data[4096];
        } req;
        struct {
            ptmres_t tpm_result;
        } resp;
    } u;
};

/*
 * size of the TPM state blob to transfer; x86_64 can handle 8k, ppc64le only ~7k
 * keep the response below a 4k page size
 */
#define STATE_BLOB_SIZE (3 * 1024)

/*
 * Data structure to get state blobs from the TPM. If the size of the
 * blob exceeds the STATE_BLOB_SIZE, multiple reads with
 * adjusted offset are necessary. The last packet is indicated by
 * the length being smaller than the STATE_BLOB_SIZE.
 */
struct ptm_getstate {
    union {
        struct {
            uint32_t state_flags; /* may be: STATE_FLAG_DECRYPTED */
            uint32_t tpm_number;  /* always set to zero */
            uint8_t type;         /* which blob to pull */
            uint32_t offset;      /* offset from where to read */
        } req;
        struct {
            ptmres_t tpm_result;
            uint32_t state_flags; /* may be: STATE_FLAG_ENCRYPTED */
            uint32_t length;
            uint8_t  data[STATE_BLOB_SIZE];
        } resp;
    } u;
};

/* TPM state blob types */
#define PTM_BLOB_TYPE_PERMANENT  1
#define PTM_BLOB_TYPE_VOLATILE   2
#define PTM_BLOB_TYPE_SAVESTATE  3

/* state_flags above : */
#define STATE_FLAG_DECRYPTED     1 /* on input:  get decrypted state */
#define STATE_FLAG_ENCRYPTED     2 /* on output: state is encrytped */

/*
 * Data structure to set state blobs in the TPM. If the size of the
 * blob exceeds the STATE_BLOB_SIZE, multiple 'writes' are necessary.
 * The last packet is indicated by the length being smaller than the
 * STATE_BLOB_SIZE.
 */
struct ptm_setstate {
    union {
        struct {
            uint32_t state_flags; /* may be STATE_FLAG_ENCRYPTED */
            uint32_t tpm_number;  /* always set to 0 */
            uint8_t type;         /* which blob to set */
            uint32_t length;
            uint8_t data[STATE_BLOB_SIZE];
        } req;
        struct {
            ptmres_t tpm_result;
        } resp;
    } u;
};

/*
 * Data structure to get runtime configuration information
 * such as which keys are applied.
 */
struct ptm_getconfig {
    union {
        struct {
            ptmres_t tpm_result;
            uint32_t flags;
        } resp;
    } u;
};

#define CONFIG_FLAG_FILE_KEY        0x1
#define CONFIG_FLAG_MIGRATION_KEY   0x2


typedef uint64_t ptmcap_t;
typedef struct ptmest  ptmest_t;
typedef struct ptmreset_est ptmreset_est_t;
typedef struct ptmloc  ptmloc_t;
typedef struct ptmhdata ptmhdata_t;
typedef struct ptminit ptminit_t;
typedef struct ptm_getstate ptm_getstate_t;
typedef struct ptm_setstate ptm_setstate_t;
typedef struct ptm_getconfig ptm_getconfig_t;

/* capability flags returned by PTM_GET_CAPABILITY */
#define PTM_CAP_INIT               (1)
#define PTM_CAP_SHUTDOWN           (1<<1)
#define PTM_CAP_GET_TPMESTABLISHED (1<<2)
#define PTM_CAP_SET_LOCALITY       (1<<3)
#define PTM_CAP_HASHING            (1<<4)
#define PTM_CAP_CANCEL_TPM_CMD     (1<<5)
#define PTM_CAP_STORE_VOLATILE     (1<<6)
#define PTM_CAP_RESET_TPMESTABLISHED (1<<7)
#define PTM_CAP_GET_STATEBLOB      (1<<8)
#define PTM_CAP_SET_STATEBLOB      (1<<9)
#define PTM_CAP_STOP               (1<<10)
#define PTM_CAP_GET_CONFIG         (1<<11)

enum {
    PTM_GET_CAPABILITY     = _IOR('P', 0, ptmcap_t),
    PTM_INIT               = _IOWR('P', 1, ptminit_t),
    PTM_SHUTDOWN           = _IOR('P', 2, ptmres_t),
    PTM_GET_TPMESTABLISHED = _IOR('P', 3, ptmest_t),
    PTM_SET_LOCALITY       = _IOWR('P', 4, ptmloc_t),
    PTM_HASH_START         = _IOR('P', 5, ptmres_t),
    PTM_HASH_DATA          = _IOWR('P', 6, ptmhdata_t),
    PTM_HASH_END           = _IOR('P', 7, ptmres_t),
    PTM_CANCEL_TPM_CMD     = _IOR('P', 8, ptmres_t),
    PTM_STORE_VOLATILE     = _IOR('P', 9, ptmres_t),
    PTM_RESET_TPMESTABLISHED = _IOWR('P', 10, ptmreset_est_t),
    PTM_GET_STATEBLOB      = _IOWR('P', 11, ptm_getstate_t),
    PTM_SET_STATEBLOB      = _IOWR('P', 12, ptm_setstate_t),
    PTM_STOP               = _IOR('P', 13, ptmres_t),
    PTM_GET_CONFIG         = _IOR('P', 14, ptm_getconfig_t),
};
