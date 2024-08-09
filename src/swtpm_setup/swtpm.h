/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * swtpm.h: Header file for swtpm.c
 *
 * Author: Stefan Berger, stefanb@linux.ibm.com
 *
 * Copyright (c) IBM Corporation, 2021
 */

#ifndef SWTPM_SETUP_SWTPM_H
#define SWTPM_SETUP_SWTPM_H

#include <glib.h>
#include <pwd.h>

#include <openssl/sha.h>

struct swtpm;

/* common swtpm ops for TPM 1.2 & TPM 2 */
struct swtpm_cops {
    int (*start)(struct swtpm *);
    void (*stop)(struct swtpm *);
    void (*destroy)(struct swtpm *);

    int (*ctrl_shutdown)(struct swtpm *);
    int (*ctrl_get_tpm_specs_and_attrs)(struct swtpm *, gchar **);
};

/* TPM 1.2 specific ops */
struct swtpm12_ops {
    int (*run_swtpm_bios)(struct swtpm *self);
    int (*create_endorsement_key_pair)(struct swtpm *, gchar **pubkey, size_t *pubek_len);
    int (*take_ownership)(struct swtpm *self,
                          const unsigned char ownerpass_digest[SHA_DIGEST_LENGTH],
                          const unsigned char srkpass_digest[SHA_DIGEST_LENGTH],
                          const unsigned char *pubek, size_t pubek_len);
    int (*write_ek_cert_nvram)(struct swtpm *self,
                               const unsigned char *data, size_t data_len);
    int (*write_platform_cert_nvram)(struct swtpm *self,
                                     const unsigned char *data, size_t data_len);
    int (*nv_lock)(struct swtpm *self);
};

/* TPM 2 specific ops */
struct swtpm2_ops {
    int (*shutdown)(struct swtpm *);
    int (*create_iak)(struct swtpm *self, gchar **ekparam, const gchar **key_description);
    int (*create_idevid)(struct swtpm *self, gchar **ekparam, const gchar **key_description);
    int (*create_spk)(struct swtpm *self, gboolean isecc, unsigned int rsa_keysize);
    int (*create_ek)(struct swtpm *self, gboolean isecc, unsigned int rsa_keysize,
                     gboolean allowsigning, gboolean decryption, gboolean lock_nvram,
                     gchar **ekparam, const gchar **key_description);
    int (*get_all_pcr_banks)(struct swtpm *self, gchar ***all_pcr_banks);
    int (*set_active_pcr_banks)(struct swtpm *self, gchar **pcr_banks_l, gchar **all_pcr_banks,
                                gchar ***active);
    int (*write_ek_cert_nvram)(struct swtpm *self, gboolean isecc, unsigned int rsa_keysize,
                               gboolean lock_nvram, const unsigned char *data, size_t data_len);
    int (*write_platform_cert_nvram)(struct swtpm *self, gboolean lock_nvram,
                                     const unsigned char *data, size_t data_len);
    int (*write_iak_cert_nvram)(struct swtpm *self, gboolean lock_nvram,
                                const unsigned char *data, size_t data_len);
    int (*write_idevid_cert_nvram)(struct swtpm *self, gboolean lock_nvram,
                                   const unsigned char *data, size_t data_len);
    int (*get_capability)(struct swtpm *self, uint32_t cap, uint32_t prop, uint32_t *res);
};

/* common structure for swtpm object */
struct swtpm {
    const struct swtpm_cops *cops;
    gchar **swtpm_exec_l;
    const gchar *state_path;
    const gchar *keyopts;
    const gchar *logfile;
    const int *fds_to_pass;
    size_t n_fds_to_pass;
    gboolean is_tpm2;
    const char *json_profile;

    GPid pid;
    int ctrl_fds[2];
    int data_fds[2];
};

struct swtpm12 {
    struct swtpm swtpm;
    const struct swtpm12_ops *ops;
};

struct swtpm2 {
    struct swtpm swtpm;
    const struct swtpm2_ops *ops;
};

struct swtpm12 *swtpm12_new(gchar **swtpm_prg_l, const gchar *tpm_state_path,
                            const gchar *swtpm_keyopts, const gchar *logfile,
                            int *fds_to_pass, size_t n_fds_to_pass);

struct swtpm2 *swtpm2_new(gchar **swtpm_prg_l, const gchar *tpm_state_path,
                         const gchar *swtpm_keyopts, const gchar *logfile,
                         int *fds_to_pass, size_t n_fds_to_pass,
                         const gchar *profile_rules);

void swtpm_free(struct swtpm *);

/* backend-specific implementations */
struct swtpm_backend_ops {
    void* (*parse_backend)(const gchar* uri);
    int (*check_access)(void *backend, int mode, const struct passwd *curr_user);
    int (*delete_state)(void *backend);
    void (*free_backend)(void *backend);
};

extern struct swtpm_backend_ops swtpm_backend_dir;
extern struct swtpm_backend_ops swtpm_backend_file;

#endif /* SWTPM_SETUP_SWTPM_H */
