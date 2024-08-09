/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * swtpm_setup.c: Tool to simulate TPM 1.2 & TPM 2 manufacturing
 *
 * Author: Stefan Berger, stefanb@linux.ibm.com
 *
 * Copyright (c) IBM Corporation, 2021
 */

#include "config.h"

#include <errno.h>
#include <getopt.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <glib.h>
#include <glib/gstdio.h>
#include <glib/gprintf.h>

#include <glib-object.h>
#include <json-glib/json-glib.h>

#include <libtpms/tpm_nvfilename.h>

#include <gnutls/x509.h>

#include "profile.h"
#include "swtpm.h"
#include "swtpm_conf.h"
#include "swtpm_utils.h"
#include "swtpm_setup.h"
#include "swtpm_setup_utils.h"

#include <openssl/sha.h>

/* default values for passwords */
#define DEFAULT_OWNER_PASSWORD "ooo"
#define DEFAULT_SRK_PASSWORD   "sss"

#define SETUP_CREATE_EK_F           (1 << 0)
#define SETUP_TAKEOWN_F             (1 << 1)
#define SETUP_EK_CERT_F             (1 << 2)
#define SETUP_PLATFORM_CERT_F       (1 << 3)
#define SETUP_LOCK_NVRAM_F          (1 << 4)
#define SETUP_SRKPASS_ZEROS_F       (1 << 5)
#define SETUP_OWNERPASS_ZEROS_F     (1 << 6)
#define SETUP_STATE_OVERWRITE_F     (1 << 7)
#define SETUP_STATE_NOT_OVERWRITE_F (1 << 8)
#define SETUP_TPM2_F                (1 << 9)
#define SETUP_ALLOW_SIGNING_F       (1 << 10)
#define SETUP_TPM2_ECC_F            (1 << 11)
#define SETUP_CREATE_SPK_F          (1 << 12)
#define SETUP_DISPLAY_RESULTS_F     (1 << 13)
#define SETUP_DECRYPTION_F          (1 << 14)
#define SETUP_WRITE_EK_CERT_FILES_F (1 << 15)
#define SETUP_RECONFIGURE_F         (1 << 16)
#define SETUP_RSA_KEYSIZE_BY_USER_F (1 << 17)
#define SETUP_IAK_F                 (1 << 18)
#define SETUP_IDEVID_F              (1 << 19)

/* default configuration file */
#define SWTPM_SETUP_CONF "swtpm_setup.conf"

/* Default logging goes to stderr */
gchar *gl_LOGFILE = NULL;

#define DEFAULT_RSA_KEYSIZE 2048


static const struct flag_to_certfile {
    unsigned long flag;
    const char *filename;
    const char *type;
} flags_to_certfiles[] = {
    {.flag = SETUP_EK_CERT_F      , .filename = "ek.cert",       .type = "ek" },
    {.flag = SETUP_PLATFORM_CERT_F, .filename = "platform.cert", .type = "platform" },
    {.flag = SETUP_IAK_F,           .filename = "iak.cert",      .type = "iak" },
    {.flag = SETUP_IDEVID_F,        .filename = "idevid.cert",   .type = "idevid" },
    {.flag = 0,                     .filename = NULL,            .type = NULL},
};

/* initialize the path of the config_file */
static int init(gchar **config_file)
{
    const gchar *configdir = g_get_user_config_dir();

    *config_file = g_build_filename(configdir, SWTPM_SETUP_CONF, NULL);
    if (access(*config_file, R_OK) != 0) {
        g_free(*config_file);
        *config_file = g_build_filename(SYSCONFDIR, SWTPM_SETUP_CONF, NULL);
    }

    return 0;
}

/* Get the spec and attributes parameters from swtpm */
static int tpm_get_specs_and_attributes(struct swtpm *swtpm, gchar ***params)
{
    int ret;
    g_autofree gchar *json = NULL;
    JsonParser *jp = NULL;
    GError *error = NULL;
    JsonReader *jr = NULL;
    JsonNode *root;
    static const struct parse_rule {
         const char *node1;
         const char *node2;
         gboolean is_int;
         const char *optname;
    } parser_rules[7] = {
         {"TPMSpecification", "family", FALSE, "--tpm-spec-family"},
         {"TPMSpecification", "level", TRUE, "--tpm-spec-level"},
         {"TPMSpecification", "revision", TRUE, "--tpm-spec-revision"},
         {"TPMAttributes", "manufacturer", FALSE, "--tpm-manufacturer"},
         {"TPMAttributes", "model", FALSE, "--tpm-model"},
         {"TPMAttributes", "version", FALSE, "--tpm-version"},
         {NULL, NULL, FALSE, NULL},
    };
    size_t idx;

    ret = swtpm->cops->ctrl_get_tpm_specs_and_attrs(swtpm, &json);
    if (ret != 0) {
        logerr(gl_LOGFILE, "Could not get the TPM spec and attribute parameters.\n");
        return 1;
    }

    jp = json_parser_new();

    if (!json_parser_load_from_data(jp, json, -1, &error)) {
        logerr(gl_LOGFILE, "JSON parser failed: %s\n", error->message);
        g_error_free(error);
        goto error;
    }

    *params = NULL;
    root = json_parser_get_root(jp);

    for (idx = 0; parser_rules[idx].node1 != NULL; idx++) {
        jr = json_reader_new(root);
        if (json_reader_read_member(jr, parser_rules[idx].node1) &&
            json_reader_read_member(jr, parser_rules[idx].node2)) {
            gchar *str;

            if (parser_rules[idx].is_int)
                str = g_strdup_printf("%ld", (long)json_reader_get_int_value(jr));
            else
                str = g_strdup(json_reader_get_string_value(jr));

            *params = concat_arrays(*params,
                                    (gchar*[]){
                                        g_strdup(parser_rules[idx].optname),
                                        str,
                                        NULL
                                    }, TRUE);
        } else {
            logerr(gl_LOGFILE, "Could not find [%s][%s] in '%s'\n",
                   parser_rules[idx].node1, parser_rules[idx].node2, json);
            ret = 1;
            break;
        }
        g_object_unref(jr);
        jr = NULL;
    }

    if (ret) {
        g_strfreev(*params);
        *params = NULL;
        g_object_unref(jr);
    }
error:
    g_object_unref(jp);

    return ret;
}

/* Call an external tool to create the certificates */
static int call_create_certs(unsigned long flags, unsigned int cert_flags,
                             const gchar *configfile, const gchar *certsdir,
                             const gchar *key_params, const gchar *vmid,
                             const gchar *tpm_serial_num, struct swtpm *swtpm)
{
    gchar **config_file_lines = NULL; /* must free */
    g_autofree gchar *create_certs_tool = NULL;
    g_autofree gchar *create_certs_tool_config = NULL;
    g_autofree gchar *create_certs_tool_options = NULL;
    g_autofree gchar **cmd = NULL;
    gchar **params = NULL; /* must free */
    g_autofree gchar *prgname = NULL;
    const char *key_opt = "--key";
    gboolean success;
    gint exit_status;
    size_t idx, j;
    gchar *s;
    int ret;

    ret = tpm_get_specs_and_attributes(swtpm, &params);
    if (ret != 0)
        goto error;

    ret = read_file_lines(configfile, &config_file_lines);
    if (ret != 0)
        goto error;

    create_certs_tool = get_config_value(config_file_lines, "create_certs_tool");
    create_certs_tool_config = get_config_value(config_file_lines, "create_certs_tool_config");
    create_certs_tool_options = get_config_value(config_file_lines, "create_certs_tool_options");

    ret = 0;

    if (create_certs_tool != NULL) {
        g_autofree gchar *create_certs_tool_path = g_find_program_in_path(create_certs_tool);
        if (create_certs_tool_path == NULL) {
            logerr(gl_LOGFILE, "Could not find %s in PATH.\n", create_certs_tool);
            ret = 1;
            goto error;
        }

        if (flags & SETUP_TPM2_F) {
            params = concat_arrays(params,
                                (gchar*[]){
                                    g_strdup("--tpm2"),
                                    NULL
                                }, TRUE);
        }

        /* use the old --ek option when the ek is passed */
        if (cert_flags & (SETUP_EK_CERT_F | SETUP_PLATFORM_CERT_F))
            key_opt = "--ek";

        cmd = concat_arrays((gchar*[]) {
                                create_certs_tool_path,
                                "--type", "_",  /* '_' must be at index '2' ! */
                                (gchar *)key_opt, (gchar *)key_params,
                                "--dir", (gchar *)certsdir,
                                NULL
                            }, NULL, FALSE);
        if (gl_LOGFILE != NULL)
            cmd = concat_arrays(cmd, (gchar*[]){"--logfile", (gchar *)gl_LOGFILE, NULL}, TRUE);
        if (vmid != NULL)
            cmd = concat_arrays(cmd, (gchar*[]){"--vmid", (gchar *)vmid, NULL}, TRUE);
        cmd = concat_arrays(cmd, params, TRUE);
        if (create_certs_tool_config != NULL)
            cmd = concat_arrays(cmd, (gchar*[]){"--configfile", create_certs_tool_config, NULL}, TRUE);
        if (create_certs_tool_options != NULL)
            cmd = concat_arrays(cmd, (gchar*[]){"--optsfile", create_certs_tool_options, NULL}, TRUE);
        if (tpm_serial_num) /* required for IAK & IDevID */
            cmd = concat_arrays(cmd, (gchar*[]){"--tpm-serial-num", (gchar *)tpm_serial_num, NULL}, TRUE);

        s = g_strrstr(create_certs_tool, G_DIR_SEPARATOR_S);
        if (s)
            prgname = strdup(&s[1]);
        else
            prgname = strdup(create_certs_tool);

        for (idx = 0; flags_to_certfiles[idx].filename != NULL; idx++) {
            if (cert_flags & flags_to_certfiles[idx].flag) {
                g_autofree gchar *standard_output = NULL;
                g_autofree gchar *standard_error = NULL;
                GError *error = NULL;
                gchar **lines;

                cmd[2] = (gchar *)flags_to_certfiles[idx].type; /* replaces the "_" above */

                s = g_strjoinv(" ", cmd);
                logit(gl_LOGFILE, "  Invoking %s\n", s);
                g_free(s);

                success = g_spawn_sync(NULL, cmd, NULL, 0, NULL, NULL,
                                       &standard_output, &standard_error, &exit_status, &error);
                if (!success) {
                    logerr(gl_LOGFILE, "An error occurred running %s: %s\n",
                           create_certs_tool, error->message);
                    g_error_free(error);
                    ret = 1;
                    break;
                } else if (exit_status != 0) {
                    logerr(gl_LOGFILE, "%s exit with status %d: %s\n",
                           prgname, WEXITSTATUS(exit_status), standard_error);
                    ret = 1;
                    break;
                }

                lines = g_strsplit(standard_output, "\n", -1);
                for (j = 0; lines[j] != NULL; j++) {
                    if (strlen(lines[j]) > 0)
                        logit(gl_LOGFILE, "%s: %s\n", prgname, lines[j]);
                }
                g_strfreev(lines);

                SWTPM_G_FREE(standard_output);
                SWTPM_G_FREE(standard_error);
            }
        }
    }

error:
    g_strfreev(config_file_lines);
    g_strfreev(params);

    return ret;
}

static char *create_certfile_name(const gchar *user_certsdir,
                                  const gchar *key_type,
                                  const gchar *key_description)
{
    g_autofree gchar *filename = g_strdup_printf("%s-%s.crt", key_type, key_description);

    return g_strjoin(G_DIR_SEPARATOR_S, user_certsdir, filename, NULL);
}

/*
 * Remove the cert file unless the user wants a copy of it.
 */
static int certfile_move_or_delete(unsigned long flags, gboolean preserve, const gchar *certfile,
                                   const gchar *user_certsdir, const gchar *key_type,
                                   const gchar *key_description)
{
    g_autofree gchar *content = NULL;
    g_autofree gchar *cf = NULL;
    gsize content_length;
    GError *error = NULL;
    size_t offset = 0;

    if (preserve && (flags & SETUP_WRITE_EK_CERT_FILES_F) && user_certsdir != NULL) {
        if (!g_file_get_contents(certfile, &content, &content_length, &error))
            goto error;

        cf = create_certfile_name(user_certsdir, key_type, key_description);
        if (!(flags & SETUP_TPM2_F)) {
            /* A TPM 1.2 certificate has a 7 byte header at the beginning
             * that we now remove */
            if (content_length >= 8)
                offset = 7;
        }
        if (!g_file_set_contents(cf, &content[offset], content_length - offset,
                                 &error))
            goto error;
        if (g_chmod(cf, S_IRUSR | S_IWUSR | S_IRGRP) < 0) {
            logerr(gl_LOGFILE, "Failed to chmod file '%s': %s\n", cf, strerror(errno));
            goto error_unlink;
        }
    }
    unlink(certfile);

    return 0;

error:
    logerr(gl_LOGFILE, "%s\n", error->message);
    g_error_free(error);

error_unlink:
    unlink(certfile);

    return 1;
}

static int read_certificate_file(const gchar *certsdir, const gchar *filename,
                                 gchar **filecontent, size_t *filecontent_len,
                                 gchar **certfile)
{
    *certfile = g_strjoin(G_DIR_SEPARATOR_S, certsdir, filename, NULL);

    return read_file(*certfile, filecontent, filecontent_len);
}

/* data extracted from EK certificate */
struct ek_certificate_data {
    unsigned char id[64];
    size_t id_len;
    unsigned char serial[20];
    size_t serial_len;
};

static int tpm2_extract_certificate_data(gchar *certdata, size_t certdata_len,
                                         struct ek_certificate_data *ecd)
{
    gnutls_x509_crt_t cert;
    gnutls_datum_t data = {
        .data = (unsigned char *)certdata,
        .size = certdata_len,
    };
    int err;
    int ret = 1;

    if ((err = gnutls_x509_crt_init(&cert)) < 0) {
        logerr(gl_LOGFILE, "gnutls_x509_crt_init() failed: %s\n",
               gnutls_strerror(err));
        return 1;
    }
    if ((err = gnutls_x509_crt_import(cert, &data, GNUTLS_X509_FMT_DER)) < 0) {
        logerr(gl_LOGFILE, "gnutls_x509_crt_import() failed: %s\n",
               gnutls_strerror(err));
        goto cleanup;
    }
    if ((err = gnutls_x509_crt_get_authority_key_id(cert, ecd->id, &ecd->id_len, NULL)) < 0) {
        logerr(gl_LOGFILE, "gnutls_x509_crt_get_authority_key_id() failed: %s\n",
               gnutls_strerror(err));
        goto cleanup;
    }
    if ((err = gnutls_x509_crt_get_serial(cert, ecd->serial, &ecd->serial_len)) < 0) {
        logerr(gl_LOGFILE, "gnutls_x509_crt_get_serial() failed: %s\n",
               gnutls_strerror(err));
        goto cleanup;
    }
    ret = 0;

cleanup:
    gnutls_x509_crt_deinit(cert);
    return ret;
}

/*
 * Read the certificate from the file where swtpm_cert left it.
 * Write the file into the TPM's NVRAM and, if the user wants it,
 * copy it into a user-provided directory.
 */
static int tpm2_persist_certificate(unsigned long flags, const gchar *certsdir,
                                    const struct flag_to_certfile *ftc,
                                    unsigned int rsa_keysize, struct swtpm2 *swtpm2,
                                    const gchar *user_certsdir, const gchar *key_type,
                                    const gchar *key_description,
                                    struct ek_certificate_data *ecd)
{
    g_autofree gchar *filecontent = NULL;
    g_autofree gchar *certfile = NULL;
    size_t filecontent_len;
    gboolean preserve;
    int ret;

    ret = read_certificate_file(certsdir, ftc->filename,
                                &filecontent, &filecontent_len, &certfile);
    if (ret != 0)
        goto error_unlink;

    if (ecd) {
        ret = tpm2_extract_certificate_data(filecontent, filecontent_len, ecd);
        if (ret != 0)
            goto error_unlink;
    }

    if (ftc->flag == SETUP_IAK_F) {
        ret = swtpm2->ops->write_iak_cert_nvram(&swtpm2->swtpm,
                                     !!(flags & SETUP_LOCK_NVRAM_F),
                                     (const unsigned char*)filecontent, filecontent_len);
    } else if (ftc->flag == SETUP_IDEVID_F) {
        ret = swtpm2->ops->write_idevid_cert_nvram(&swtpm2->swtpm,
                                     !!(flags & SETUP_LOCK_NVRAM_F),
                                     (const unsigned char *)filecontent, filecontent_len);
    } else if (ftc->flag == SETUP_EK_CERT_F) {
        ret = swtpm2->ops->write_ek_cert_nvram(&swtpm2->swtpm,
                                     !!(flags & SETUP_TPM2_ECC_F), rsa_keysize,
                                     !!(flags & SETUP_LOCK_NVRAM_F),
                                     (const unsigned char*)filecontent, filecontent_len);
    } else {
        ret = swtpm2->ops->write_platform_cert_nvram(&swtpm2->swtpm,
                                     !!(flags & SETUP_LOCK_NVRAM_F),
                                     (const unsigned char *)filecontent, filecontent_len);
    }

    if (ret != 0)
        goto error_unlink;

    preserve = !!(ftc->flag & (SETUP_EK_CERT_F | SETUP_IAK_F | SETUP_IDEVID_F));

    return certfile_move_or_delete(flags, preserve,
                                   certfile, user_certsdir,
                                   key_type, key_description);

error_unlink:
    unlink(certfile);
    return 1;
}

/* Create EK and certificate for a TPM 2 */
static int tpm2_create_ek_and_cert(unsigned long flags, const gchar *config_file,
                                   const gchar *certsdir, const gchar *vmid,
                                   unsigned int rsa_keysize, struct swtpm2 *swtpm2,
                                   const gchar *user_certsdir,
                                   struct ek_certificate_data *ecd)
{
    g_autofree gchar *key_params = NULL;
    struct ek_certificate_data *ecd_dup;
    const char *key_description;
    unsigned long cert_flags;
    const gchar *key_type;
    size_t idx;
    int ret;

    if (flags & SETUP_CREATE_EK_F) {
        ret = swtpm2->ops->create_ek(&swtpm2->swtpm, !!(flags & SETUP_TPM2_ECC_F), rsa_keysize,
                                     !!(flags & SETUP_ALLOW_SIGNING_F),
                                     !!(flags & SETUP_DECRYPTION_F),
                                     !!(flags & SETUP_LOCK_NVRAM_F),
                                     &key_params, &key_description);
        if (ret != 0)
            return 1;
    }

    /* Only look at ek and platform certs here */
    cert_flags = flags & (SETUP_EK_CERT_F | SETUP_PLATFORM_CERT_F);
    if (cert_flags) {
        ret = call_create_certs(flags, cert_flags, config_file, certsdir, key_params,
                                vmid, NULL, &swtpm2->swtpm);
        if (ret != 0)
            return 1;

        for (idx = 0; flags_to_certfiles[idx].filename; idx++) {
            if (cert_flags & flags_to_certfiles[idx].flag) {

                ecd_dup = NULL;
                if (flags_to_certfiles[idx].flag & SETUP_EK_CERT_F) {
                    key_type = "ek";
                    if (rsa_keysize)
                        ecd_dup = ecd;
                } else {
                    key_type = "";
                }

                ret = tpm2_persist_certificate(flags, certsdir, &flags_to_certfiles[idx],
                                               rsa_keysize, swtpm2, user_certsdir,
                                               key_type, key_description, ecd_dup);
                if (ret)
                    return 1;
            }
        }
    }

    return 0;
}

/* Create endorsement keys and certificates for a TPM 2 */
static int tpm2_create_eks_and_certs(unsigned long flags, const gchar *config_file,
                                     const gchar *certsdir, const gchar *vmid,
                                     unsigned int rsa_keysize, struct swtpm2 *swtpm2,
                                     const gchar *user_certsdir,
                                     struct ek_certificate_data *ecd)
{
     int ret;

     /* 1st key will be RSA */
     flags = flags & ~SETUP_TPM2_ECC_F;
     ret = tpm2_create_ek_and_cert(flags, config_file, certsdir, vmid, rsa_keysize, swtpm2,
                                   user_certsdir, ecd);
     if (ret != 0)
         return 1;

     /* 2nd key will be an ECC; no more platform cert */
     flags = (flags & ~SETUP_PLATFORM_CERT_F) | SETUP_TPM2_ECC_F;
     return tpm2_create_ek_and_cert(flags, config_file, certsdir, vmid, rsa_keysize, swtpm2,
                                    user_certsdir, NULL);
}

static gchar *tpm2_create_tpm_serial_num(struct swtpm2 *swtpm2, const struct ek_certificate_data *ecd)
{
    struct swtpm *swtpm = &swtpm2->swtpm;
    g_autofree gchar *cert_ser = NULL;
    g_autofree gchar *ca_akid = NULL;
    uint32_t res;
    char code[sizeof(res) + 1];
    size_t i;
    int ret;

    ret = swtpm2->ops->get_capability(swtpm, TPM_CAP_TPM_PROPERTIES, TPM_PT_MANUFACTURER, &res);
    if (ret != 0) {
        logerr(gl_LOGFILE, "TPM_GetCapability failed\n");
        return NULL;
    }

    ca_akid = print_as_hex(ecd->id, ecd->id_len);
    cert_ser = print_as_hex(ecd->serial, ecd->serial_len);
    for (i = 0; i < sizeof(res); i++)
        code[i] = res >> (8 * (3 - i));
    code[4] = 0;

    return g_strdup_printf("%s:%s:%s", code, ca_akid, cert_ser);
}

/* Create the IAK and cert */
static int tpm2_create_iak_idevid_and_certs(unsigned long flags, const gchar *config_file,
                                            const gchar *certsdir, const char *vmid,
                                            struct swtpm2 *swtpm2, const gchar *user_certsdir,
                                            const struct ek_certificate_data *ecd)
{
    g_autofree gchar *tpm_serial_num = NULL;
    g_autofree gchar *key_params = NULL;
    const char *key_description;
    const char *key_type = NULL;
    unsigned long cert_flags;
    size_t idx;
    int ret;

    /* Only look at IAK and IDevID certs here */
    cert_flags = flags & (SETUP_IAK_F | SETUP_IDEVID_F);
    if (!cert_flags)
        return 0;

    tpm_serial_num = tpm2_create_tpm_serial_num(swtpm2, ecd);

    for (idx = 0; flags_to_certfiles[idx].filename; idx++) {
        if (cert_flags & flags_to_certfiles[idx].flag) {

            SWTPM_G_FREE(key_params);

            if (flags_to_certfiles[idx].flag == SETUP_IAK_F) {
                key_type = "iak";
                ret = swtpm2->ops->create_iak(&swtpm2->swtpm, &key_params, &key_description);
            } else if (flags_to_certfiles[idx].flag == SETUP_IDEVID_F) {
                key_type = "idevid";
                ret = swtpm2->ops->create_idevid(&swtpm2->swtpm, &key_params, &key_description);
            }
            if (ret != 0)
                return 1;

            ret = call_create_certs(flags, flags_to_certfiles[idx].flag, config_file,
                                    certsdir, key_params, vmid, tpm_serial_num,
                                    &swtpm2->swtpm);
            if (ret != 0)
                return 1;

            ret = tpm2_persist_certificate(flags, certsdir, &flags_to_certfiles[idx],
                                           0, swtpm2, user_certsdir,
                                           key_type, key_description, NULL);
            if (ret)
                return 1;
        }
    }

    return 0;
}

/* Get the default PCR banks from the config file and if nothing can
   be found there use the DEFAULT_PCR_BANKS #define.
 */
static gchar *get_default_pcr_banks(gchar *const *config_file_lines)
{
    gchar *pcr_banks;

    if (!config_file_lines)
        return NULL;

    pcr_banks = get_config_value(config_file_lines, "active_pcr_banks");
    if (pcr_banks)
        g_strstrip(pcr_banks);
    if (pcr_banks == NULL || strlen(pcr_banks) == 0) {
        g_free(pcr_banks);
        pcr_banks = g_strdup(DEFAULT_PCR_BANKS);
    }
    return pcr_banks;
}

/* Get the default RSA keysize from the config file */
static gchar *get_default_rsa_keysize(gchar *const *config_file_lines)
{
    gchar *rsa_keysize;

    if (!config_file_lines)
        return NULL;

    rsa_keysize = get_config_value(config_file_lines, "rsa_keysize");
    if (rsa_keysize)
        g_strstrip(rsa_keysize);
    if (rsa_keysize == NULL || strlen(rsa_keysize) == 0) {
        g_free(rsa_keysize);
        rsa_keysize = g_strdup_printf("%d", DEFAULT_RSA_KEYSIZE);
    }
    return rsa_keysize;
}

/* Get the default policy from the config file */
static gchar *get_default_profile(gchar *const *config_file_lines)
{
    gchar *profile;

    profile = get_config_value(config_file_lines, "profile");
    if (profile)
        g_strstrip(profile);
    return profile;
}

/* Activate the given list of PCR banks. If pcr_banks is '-' then leave
 * the configuration as-is.
 */
static int tpm2_activate_pcr_banks(struct swtpm2 *swtpm2,
                                   const gchar *pcr_banks)
{
    g_autofree gchar *active_pcr_banks_join = NULL;
    g_autofree gchar *all_pcr_banks_join = NULL;
    g_auto(GStrv) active_pcr_banks = NULL;
    g_auto(GStrv) all_pcr_banks = NULL;
    g_auto(GStrv) pcr_banks_l = NULL;
    struct swtpm *swtpm = &swtpm2->swtpm;
    int ret = 0;

    if (g_str_equal(pcr_banks, "-"))
        return 0;

    ret = swtpm2->ops->get_all_pcr_banks(swtpm, &all_pcr_banks);
    if (ret != 0)
        return ret;

    pcr_banks_l = g_strsplit(pcr_banks, ",", -1);
    ret = swtpm2->ops->set_active_pcr_banks(swtpm, pcr_banks_l, all_pcr_banks,
                                            &active_pcr_banks);
    if (ret != 0)
        return ret;

    active_pcr_banks_join = g_strjoinv(",", active_pcr_banks);
    all_pcr_banks_join = g_strjoinv(",", all_pcr_banks);
    logit(gl_LOGFILE, "Successfully activated PCR banks %s among %s.\n",
          active_pcr_banks_join, all_pcr_banks_join);

    return 0;
}

/* Simulate manufacturing a TPM 2: create keys and certificates */
static int init_tpm2(unsigned long flags, gchar **swtpm_prg_l, const gchar *config_file,
                     const gchar *tpm2_state_path, const gchar *vmid, const gchar *pcr_banks,
                     const gchar *swtpm_keyopt, int *fds_to_pass, size_t n_fds_to_pass,
                     unsigned int rsa_keysize, const gchar *certsdir,
                     const gchar *user_certsdir, const gchar *json_profile)
{
    struct ek_certificate_data ecd = {
        .id_len = sizeof(ecd.id),
        .serial_len = sizeof(ecd.serial),
    };
    struct swtpm2 *swtpm2;
    struct swtpm *swtpm;
    int ret;

    swtpm2 = swtpm2_new(swtpm_prg_l, tpm2_state_path, swtpm_keyopt, gl_LOGFILE,
                        fds_to_pass, n_fds_to_pass, json_profile);
    if (swtpm2 == NULL)
        return 1;
    swtpm = &swtpm2->swtpm;

    ret = swtpm->cops->start(swtpm);
    if (ret != 0) {
        logerr(gl_LOGFILE, "Could not start the TPM 2.\n");
        goto error;
    }

    if (!(flags & SETUP_RECONFIGURE_F)) {
        if ((flags & SETUP_CREATE_SPK_F)) {
            ret = swtpm2->ops->create_spk(swtpm, !!(flags & SETUP_TPM2_ECC_F), rsa_keysize);
            if (ret != 0)
                goto destroy;
        }

        ret = tpm2_create_eks_and_certs(flags, config_file, certsdir, vmid, rsa_keysize, swtpm2,
                                        user_certsdir, &ecd);
        if (ret != 0)
            goto destroy;

        ret = tpm2_create_iak_idevid_and_certs(flags, config_file, certsdir, vmid,
                                               swtpm2, user_certsdir, &ecd);
        if (ret != 0)
            goto destroy;
    }

    ret = tpm2_activate_pcr_banks(swtpm2, pcr_banks);
    if (ret != 0)
        goto destroy;

    ret = swtpm2->ops->shutdown(swtpm);

destroy:
    swtpm->cops->destroy(swtpm);

error:
    swtpm_free(swtpm);

    return ret;
}

/* Create the owner password digest */
static void tpm12_get_ownerpass_digest(unsigned long flags, const gchar *ownerpass,
                                       unsigned char ownerpass_digest[SHA_DIGEST_LENGTH])
{
    const gchar zeros[SHA_DIGEST_LENGTH]= {0, };
    size_t len;

    if (ownerpass == NULL) {
        if (flags & SETUP_OWNERPASS_ZEROS_F) {
            ownerpass = zeros;
            len = sizeof(zeros);
        } else {
            ownerpass = DEFAULT_OWNER_PASSWORD;
            len = strlen(ownerpass);
        }
    } else {
        len = strlen(ownerpass);
    }
    SHA1((const unsigned char *)ownerpass, len, ownerpass_digest);
}

/* Create the SRK password digest */
static void tpm12_get_srkpass_digest(unsigned long flags, const gchar *srkpass,
                                     unsigned char srkpass_digest[SHA_DIGEST_LENGTH])
{
    const gchar zeros[SHA_DIGEST_LENGTH]= {0, };
    size_t len;

    if (srkpass == NULL) {
        if (flags & SETUP_SRKPASS_ZEROS_F) {
            srkpass = zeros;
            len = sizeof(zeros);
        } else {
            srkpass = DEFAULT_SRK_PASSWORD;
            len = strlen(srkpass);
        }
    } else {
        len = strlen(srkpass);
    }
    SHA1((const unsigned char *)srkpass, len, srkpass_digest);
}

/* Take ownership of a TPM 1.2 */
static int tpm12_take_ownership(unsigned long flags, const gchar *ownerpass,
                                const gchar *srkpass, gchar *pubek, size_t pubek_len,
                                struct swtpm12 *swtpm12)
{
    unsigned char ownerpass_digest[SHA_DIGEST_LENGTH];
    unsigned char srkpass_digest[SHA_DIGEST_LENGTH];

    tpm12_get_ownerpass_digest(flags, ownerpass, ownerpass_digest);
    tpm12_get_srkpass_digest(flags, srkpass, srkpass_digest);

    return swtpm12->ops->take_ownership(&swtpm12->swtpm, ownerpass_digest, srkpass_digest,
                                        (const unsigned char *)pubek, pubek_len);
}

/* Create the certificates for a TPM 1.2 */
static int tpm12_create_certs(unsigned long flags, const gchar *config_file,
                              const gchar *certsdir, const gchar *ekparam,
                              const gchar *vmid, struct swtpm12 *swtpm12,
                              const gchar *user_certsdir)
{
    g_autofree gchar *filecontent = NULL;
    g_autofree gchar *certfile = NULL;
    unsigned int cert_flags;
    const gchar *key_type;
    gsize filecontent_len;
    size_t idx;
    int ret;

    /* TPM 1.2 only has ek and platform certs */
    cert_flags = flags & (SETUP_EK_CERT_F | SETUP_PLATFORM_CERT_F);

    ret = call_create_certs(flags, cert_flags, config_file, certsdir, ekparam,
                            vmid, NULL, &swtpm12->swtpm);
    if (ret != 0)
        return 1;

    for (idx = 0; flags_to_certfiles[idx].filename; idx++) {
        if (cert_flags & flags_to_certfiles[idx].flag) {
            SWTPM_G_FREE(filecontent);
            SWTPM_G_FREE(certfile);

            ret = read_certificate_file(certsdir, flags_to_certfiles[idx].filename,
                                        &filecontent, &filecontent_len, &certfile);
            if (ret != 0)
                return 1;

            if (flags_to_certfiles[idx].flag == SETUP_EK_CERT_F) {
                ret = swtpm12->ops->write_ek_cert_nvram(&swtpm12->swtpm,
                                                (const unsigned char*)filecontent, filecontent_len);
                if (ret == 0)
                    logit(gl_LOGFILE, "Successfully created NVRAM area for EK certificate.\n");
            } else {
                ret = swtpm12->ops->write_platform_cert_nvram(&swtpm12->swtpm,
                                                  (const unsigned char*)filecontent, filecontent_len);
                if (ret == 0)
                    logit(gl_LOGFILE, "Successfully created NVRAM area for Platform certificate.\n");
            }

            if (ret != 0) {
                unlink(certfile);
                return 1;
            }

            key_type = flags_to_certfiles[idx].flag & SETUP_EK_CERT_F ? "ek" : "";

            if (certfile_move_or_delete(flags, !!(flags_to_certfiles[idx].flag & SETUP_EK_CERT_F),
                                        certfile, user_certsdir, key_type, "rsa2048") != 0)
                return 1;
        }
    }

    return 0;
}

/* Simulate manufacturing a TPM 1.2: create keys and certificate and possibly take ownership */
static int init_tpm(unsigned long flags, gchar **swtpm_prg_l, const gchar *config_file,
                    const gchar *tpm_state_path, const gchar *ownerpass, const gchar *srkpass,
                    const gchar *vmid, const gchar *swtpm_keyopt,
                    int *fds_to_pass, size_t n_fds_to_pass, const gchar *certsdir,
                    const gchar *user_certsdir)
{
    struct swtpm12 *swtpm12;
    struct swtpm *swtpm;
    g_autofree gchar *pubek = NULL;
    size_t pubek_len = 0;
    int ret = 1;

    swtpm12 = swtpm12_new(swtpm_prg_l, tpm_state_path, swtpm_keyopt, gl_LOGFILE,
                          fds_to_pass, n_fds_to_pass);
    if (swtpm12 == NULL)
        return 1;
    swtpm = &swtpm12->swtpm;

    ret = swtpm->cops->start(swtpm);
    if (ret != 0) {
        logerr(gl_LOGFILE, "Could not start the TPM 1.2.\n");
        goto error;
    }

    ret = swtpm12->ops->run_swtpm_bios(swtpm);
    if (ret != 0)
         goto destroy;

    if ((flags & SETUP_CREATE_EK_F)) {
        ret = swtpm12->ops->create_endorsement_key_pair(swtpm, &pubek, &pubek_len);
        if (ret != 0)
            goto destroy;

        logit(gl_LOGFILE, "Successfully created EK.\n");

        /* can only take owernship if created an EK */
        if ((flags & SETUP_TAKEOWN_F)) {
            ret = tpm12_take_ownership(flags, ownerpass, srkpass, pubek, pubek_len, swtpm12);
            if (ret != 0)
                goto destroy;

            logit(gl_LOGFILE, "Successfully took ownership of the TPM.\n");
        }

        /* can only create EK cert if created an EK */
        if ((flags & SETUP_EK_CERT_F)) {
            g_autofree gchar *ekparam = print_as_hex((unsigned char *)pubek, pubek_len);

            ret = tpm12_create_certs(flags, config_file, certsdir, ekparam, vmid, swtpm12,
                                     user_certsdir);
            if (ret != 0)
                goto destroy;
        }
    }

    if ((flags & SETUP_LOCK_NVRAM_F)) {
        ret = swtpm12->ops->nv_lock(swtpm);
        if (ret == 0)
            logit(gl_LOGFILE, "Successfully locked NVRAM access.\n");
    }

destroy:
    swtpm->cops->destroy(swtpm);

error:
    swtpm_free(swtpm);

    return ret;
}

/* Check whether we are allowed to overwrite existing state.
 * This function returns 2 if the state exists but flag is set to not to overwrite it,
 * 0 in case we can overwrite it, 1 if the state exists.
 */
static int check_state_overwrite(gchar **swtpm_prg_l, unsigned int flags,
                                 const char *tpm_state_path)
{
    gboolean success;
    g_autofree gchar *standard_output = NULL;
    int exit_status = 0;
    g_autoptr(GError) error = NULL;
    g_autofree gchar **argv = NULL;
    g_autofree gchar *statearg = g_strdup_printf("backend-uri=%s", tpm_state_path);
    g_autofree gchar *logop = NULL;
    g_autofree gchar **my_argv = NULL;

    my_argv = concat_arrays((gchar*[]) {
                                "--print-states",
                                "--tpmstate",
                                statearg,
                                NULL
                            }, NULL, FALSE);

    if (flags & SETUP_TPM2_F)
        my_argv = concat_arrays(my_argv, (gchar*[]) { "--tpm2", NULL }, TRUE);

    if (gl_LOGFILE != NULL) {
        logop = g_strdup_printf("file=%s", gl_LOGFILE);
        my_argv = concat_arrays(my_argv, (gchar*[]){"--log", logop, NULL}, TRUE);
    }

    argv = concat_arrays(swtpm_prg_l, my_argv, FALSE);

    success = g_spawn_sync(NULL, argv, NULL, G_SPAWN_STDERR_TO_DEV_NULL, NULL, NULL,
                           &standard_output, NULL, &exit_status, &error);
    if (!success) {
        logerr(gl_LOGFILE, "Could not start swtpm '%s': %s\n", swtpm_prg_l[0], error->message);
        return 1;
    }

    if (exit_status != 0) {
        logerr(gl_LOGFILE, "%s exit with status %d: %s\n",
               swtpm_prg_l[0], exit_status, standard_output);
        return 1;
    }

    if (g_strstr_len(standard_output, -1, TPM_PERMANENT_ALL_NAME) != NULL) {
        /* State file exists */
        if (flags & SETUP_STATE_NOT_OVERWRITE_F) {
            logit(gl_LOGFILE, "Not overwriting existing state file.\n");
            return 2;
        }
        if (flags & SETUP_STATE_OVERWRITE_F)
            return 0;
        logerr(gl_LOGFILE, "Found existing TPM state '%s'.\n", TPM_PERMANENT_ALL_NAME);
        return 1;
    }

    return 0;
}

static void versioninfo(void)
{
    printf("TPM emulator setup tool version %d.%d.%d\n",
           SWTPM_VER_MAJOR, SWTPM_VER_MINOR, SWTPM_VER_MICRO);
}

static void usage(const char *prgname, const char *default_config_file)
{
    versioninfo();
    printf(
        "Usage: %s [options]\n"
        "\n"
        "The following options are supported:\n"
        "\n"
        "--runas <user>   : Run this program under the given user's account.\n"
        "\n"
        "--tpm-state <dir>: Path where the TPM's state will be written to;\n"
        "                   this is a mandatory argument. Prefix with dir:// to\n"
        "                   use directory backend, or file:// to use linear file.\n"
        "\n"
        "--tpmstate <dir> : This is an alias for --tpm-state <dir>.\n"
        "\n"
        "--tpm <executable>\n"
        "                 : Path to the TPM executable; this is an optional argument and\n"
        "                   by default 'swtpm' in the PATH is used.\n"
        "\n"
        "--swtpm_ioctl <executable>\n"
        "                 : Path to the swtpm_ioctl executable; this is deprecated\n"
        "                   argument.\n"
        "\n"
        "--tpm2           : Setup a TPM 2; by default a TPM 1.2 is setup.\n"
        "\n"
        "--createek       : Create the EK; for a TPM 2 an RSA and ECC EK will be\n"
        "                   created\n"
        "\n"
        "--allow-signing  : Create an EK that can be used for signing;\n"
        "                   this option requires --tpm2.\n"
        "                   Note: Careful, this option will create a non-standard EK!\n"
        "\n"
        "--decryption     : Create an EK that can be used for key encipherment;\n"
        "                   this is the default unless --allow-signing is given;\n"
        "                   this option requires --tpm2.\n"
        "\n"
        "--ecc            : This option allows to create a TPM 2's ECC key as storage\n"
        "                   primary key; a TPM 2 always gets an RSA and an ECC EK key.\n"
        "\n"
        "--take-ownership : Take ownership; this option implies --createek\n"
        "  --ownerpass  <password>\n"
        "                 : Provide custom owner password; default is %s\n"
        "  --owner-well-known:\n"
        "                 : Use an owner password of 20 zero bytes\n"
        "  --srkpass <password>\n"
        "                 : Provide custom SRK password; default is %s\n"
        "  --srk-well-known:\n"
        "                 : Use an SRK password of 20 zero bytes\n"
        "--create-ek-cert : Create an EK certificate; this implies --createek\n"
        "\n"
        "--create-platform-cert\n"
        "                 : Create a platform certificate; this implies --create-ek-cert\n"
        "\n"
        "--create-spk     : Create storage primary key; this requires --tpm2\n"
        "\n"
        "--lock-nvram     : Lock NVRAM access\n"
        "\n"
        "--display        : At the end display as much info as possible about the\n"
        "                   configuration of the TPM\n"
        "\n"
        "--config <config file>\n"
        "                 : Path to configuration file; default is %s\n"
        "\n"
        "--logfile <logfile>\n"
        "                 : Path to log file; default is logging to stderr\n"
        "\n"
        "--keyfile <keyfile>\n"
        "                 : Path to a key file containing the encryption key for the\n"
        "                   TPM to encrypt its persistent state with. The content\n"
        "                   must be a 32 hex digit number representing a 128bit AES key.\n"
        "                   This parameter will be passed to the TPM using\n"
        "                   '--key file=<file>'.\n"
        "\n"
        "--keyfile-fd <fd>: Like --keyfile but a file descriptor is given to read the\n"
        "                   encryption key from.\n"
        "\n"
        "--pwdfile <pwdfile>\n"
        "                 : Path to a file containing a passphrase from which the\n"
        "                   TPM will derive the 128bit AES key. The passphrase can be\n"
        "                   32 bytes long.\n"
        "                   This parameter will be passed to the TPM using\n"
        "                   '--key pwdfile=<file>'.\n"
        "\n"
        "--pwdfile-fd <fd>: Like --pwdfile but a file descriptor is given to to read\n"
        "                   the passphrase from.\n"
        "\n"
        "--cipher <cipher>: The cipher to use; either aes-128-cbc or aes-256-cbc;\n"
        "                   the default is aes-128-cbc; the same cipher must be\n"
        "                   used on the swtpm command line\n"
        "\n"
        "--overwrite      : Overwrite existing TPM state by re-initializing it; if this\n"
        "                   option is not given, this program will return an error if\n"
        "                   existing state is detected\n"
        "\n"
        "--not-overwrite  : Do not overwrite existing TPM state but silently end\n"
        "\n"
        "--vmid <vm id>   : Unique (VM) identifier to use as common name in certificate\n"
        "\n"
        "--pcr-banks <banks>\n"
        "                 : Set of PCR banks to activate. Provide a comma separated list\n"
        "                   like 'sha1,sha256'. '-' to skip and leave all banks active.\n"
        "                   Default: %s\n"
        "\n"
        "--rsa-keysize <keysize>\n"
        "                 : The RSA key size of the EK key; 3072 bits may be supported\n"
        "                   if libtpms supports it.\n"
        "                   Default: %u\n"
        "\n"
        "--write-ek-cert-files <directory>\n"
        "                 : Write EK cert files into the given directory\n"
        "\n"
        "--tcsd-system-ps-file <file>\n"
        "                 : This option is deprecated and has no effect.\n"
        "\n"
        "--print-capabilities\n"
        "                 : Print JSON formatted capabilities added after v0.1 and exit.\n"
        "\n"
        "--create-config-files [[overwrite][,root]]\n"
        "                 : Create swtpm_setup and swtpm-localca config files for a\n"
        "                   user account.\n"
        "                   overwrite: overwrite any existing files\n"
        "                   root: allow to create files under root's home directory\n"
        "                   skip-if-exist: if any file exists exit without error\n"
        "\n"
        "--reconfigure    : Reconfigure an existing swtpm by reusing existing state.\n"
        "                   The active PCR banks can be changed but no new keys will\n"
        "                   be created.\n"
        "\n"
        "--profile <json-profile>\n"
        "                 : Configure swtpm with the given profile.\n"
        "--no-iak         : Do not create IAK and IDevID keys and related certificates.\n"
        "\n"
        "--version        : Display version and exit\n"
        "\n"
        "--help,-h        : Display this help screen\n\n",
            prgname,
            DEFAULT_OWNER_PASSWORD,
            DEFAULT_SRK_PASSWORD,
            default_config_file,
            DEFAULT_PCR_BANKS,
            DEFAULT_RSA_KEYSIZE
        );
}

static int get_swtpm_capabilities(gchar **swtpm_prg_l, gboolean is_tpm2,
                                  gchar **standard_output)
{
    gchar *my_argv[] = { "--print-capabilities", is_tpm2 ? "--tpm2" : NULL, NULL };
    g_autofree gchar *logop = NULL;
    g_autoptr(GError) error = NULL;
    g_autofree gchar **argv = NULL;
    int exit_status = 0;
    gboolean success;
    int ret = 1;

    argv = concat_arrays(swtpm_prg_l, my_argv, FALSE);

    if (gl_LOGFILE != NULL) {
        logop = g_strdup_printf("file=%s", gl_LOGFILE);
        argv = concat_arrays(argv, (gchar*[]){"--log", logop, NULL}, TRUE);
    }

    success = g_spawn_sync(NULL, argv, NULL, G_SPAWN_STDERR_TO_DEV_NULL, NULL, NULL,
                           standard_output, NULL, &exit_status, &error);
    if (!success) {
        logerr(gl_LOGFILE, "Could not start swtpm '%s': %s\n", swtpm_prg_l[0], error->message);
        goto error;
    }
    ret = 0;

error:
    return ret;
}

static int get_supported_tpm_versions(gchar **swtpm_prg_l, gboolean *swtpm_has_tpm12,
                                      gboolean *swtpm_has_tpm2)
{
    g_autofree gchar *standard_output = NULL;
    int ret;

    ret = get_swtpm_capabilities(swtpm_prg_l, FALSE, &standard_output);
    if (ret)
        return ret;

    *swtpm_has_tpm12 = g_strstr_len(standard_output, -1, "\"tpm-1.2\"") != NULL;
    *swtpm_has_tpm2 = g_strstr_len(standard_output, -1, "\"tpm-2.0\"") != NULL;

    return 0;
}

/* Get the support RSA key sizes.
 *  This function returns an array of ints like the following
 *  - [ 1024, 2048, 3072 ]
 *  - [] (empty array, indicating only 2048 bit RSA keys are supported)
 */
static int get_rsa_keysizes(unsigned long flags, gchar **swtpm_prg_l,
                            unsigned int **keysizes, size_t *n_keysizes)
{
    g_autofree gchar *standard_output = NULL;
    const gchar *needle = "\"rsa-keysize-";
    unsigned int keysize;
    int ret = 1;
    char *p;
    int n;

    *n_keysizes = 0;

    if (flags & SETUP_TPM2_F) {
        ret = get_swtpm_capabilities(swtpm_prg_l, TRUE, &standard_output);
        if (ret)
            goto error;

        p = standard_output;
        /* A crude way of parsing the json output just looking for "rsa-keysize-%u" */
        while ((p = g_strstr_len(p, -1, needle)) != NULL) {
            p += strlen(needle);
            n = sscanf(p, "%u\"", &keysize);
            if (n == 1) {
                *keysizes = g_realloc(*keysizes, (*n_keysizes + 1) * sizeof(unsigned int));
                (*keysizes)[*n_keysizes] = keysize;
                (*n_keysizes)++;
            }
        }
    }
    ret = 0;

error:
    return ret;
}

/* Return the RSA key size capabilities in a NULL-terminated array */
static int get_rsa_keysize_caps(unsigned long flags, gchar **swtpm_prg_l,
                                gchar ***keysize_strs)
{
    unsigned int *keysizes = NULL;
    size_t n_keysizes = 0;
    size_t i, j;
    int ret = get_rsa_keysizes(flags, swtpm_prg_l, &keysizes, &n_keysizes);
    if (ret)
        return ret;

    *keysize_strs = g_malloc0(sizeof(char *) * (n_keysizes + 1));
    for (i = 0, j = 0; i < n_keysizes; i++) {
        if (keysizes[i] >= 2048)
            (*keysize_strs)[j++] = g_strdup_printf("tpm2-rsa-keysize-%u", keysizes[i]);
    }

    g_free(keysizes);

    return 0;
}

static int validate_json_profile(gchar **swtpm_prg_l, const char *json_profile)
{
    g_autofree gchar *standard_output = NULL;
    int ret;

    ret = get_swtpm_capabilities(swtpm_prg_l, TRUE, &standard_output);
    if (ret)
        return ret;

    return check_json_profile(standard_output, json_profile);
}

/* Print the JSON object of swtpm_setup's capabilities */
static int print_capabilities(char **swtpm_prg_l, gboolean swtpm_has_tpm12,
                              gboolean swtpm_has_tpm2)
{
    g_autofree gchar *standard_output = NULL;
    g_autofree gchar *param = g_strdup("");
    g_autofree gchar *profile_list = NULL;
    gchar **profile_names = NULL;
    gchar **keysize_strs = NULL;
    gchar *tmp;
    size_t i;
    int ret = 0;

    ret = get_rsa_keysize_caps(SETUP_TPM2_F, swtpm_prg_l, &keysize_strs);
    if (ret)
        return 1;

    for (i = 0; keysize_strs[i] != NULL; i++) {
        tmp = g_strdup_printf("%s, \"%s\"", param, keysize_strs[i]);
        g_free(param);
        param = tmp;
    }

    if (swtpm_has_tpm2) {
        ret = get_swtpm_capabilities(swtpm_prg_l, TRUE, &standard_output);
        if (ret)
            goto error;
        ret = get_profile_names(standard_output, &profile_names);
        if (ret)
            goto error;

        if (g_strv_length(profile_names) > 0) {
            tmp = g_strjoinv("\", \"", profile_names);
            profile_list = g_strdup_printf(" \"%s\" ", tmp);
            g_free(tmp);
        }
    }

    printf("{ \"type\": \"swtpm_setup\", "
           "\"features\": [ %s%s\"cmdarg-keyfile-fd\", \"cmdarg-pwdfile-fd\", \"tpm12-not-need-root\""
           ", \"cmdarg-write-ek-cert-files\", \"cmdarg-create-config-files\""
           ", \"cmdarg-reconfigure-pcr-banks\""
           "%s"
           ", \"cmdarg-profile\", \"cmdarg-no-iak\", \"creates-iak-idevid\""
           " ], "
           "\"profiles\": [%s], "
           "\"version\": \"" VERSION "\" "
           "}\n",
           swtpm_has_tpm12 ? "\"tpm-1.2\", " : "",
           swtpm_has_tpm2  ? "\"tpm-2.0\", " : "",
           param,
           profile_list ? profile_list : ""
           );

error:
    g_strfreev(keysize_strs);
    g_strfreev(profile_names);

    return ret;
}

static int change_process_owner(const char *user)
{
    char *endptr;
    unsigned long long uid = strtoull(user, &endptr, 10);
    gid_t gid;
    struct passwd *passwd;
    int ret = 1;

    if (*endptr != '\0') {
        /* assuming a name */
        passwd = getpwnam(user);
        if (passwd == NULL) {
            logerr(gl_LOGFILE, "Error: User '%s' does not exist.\n", user);
            goto error;
        }

        if (initgroups(passwd->pw_name, passwd->pw_gid) != 0) {
            logerr(gl_LOGFILE, "Error: initgroups() failed: %s\n", strerror(errno));
            goto error;
        }

        gid = passwd->pw_gid;
        uid = passwd->pw_uid;
    } else {
        if (uid > 0xffffffff) {
            logerr(gl_LOGFILE, "Error: uid %s outside valid range.\n", user);
            goto error;
        }
        gid = (gid_t)uid;
    }

    if (setgid(gid) != 0) {
        logerr(gl_LOGFILE, "Error: setgid(%d) failed: %s\n", gid, strerror(errno));
        goto error;
    }

    if (setuid(uid) != 0) {
        logerr(gl_LOGFILE, "Error: setuid(%d) failed: %s\n", uid, strerror(errno));
        goto error;
    }

    ret = 0;

error:
    return ret;
}

static int handle_create_config_files(const char *optarg)
{
    g_auto(GStrv) tokens = NULL;
    gboolean overwrite = FALSE;
    gboolean root_flag = FALSE;
    gboolean skip_if_exist = FALSE;

    if (optarg) {
        tokens = g_strsplit_set(optarg, ", ", -1);
        overwrite = g_strv_contains((const gchar **)tokens, "overwrite");
        root_flag = g_strv_contains((const gchar **)tokens, "root");
        skip_if_exist = g_strv_contains((const gchar **)tokens, "skip-if-exist");
        if (overwrite && skip_if_exist) {
            fprintf(stderr, "Error: overwrite and skip-if-exist cannot both be used\n");
            return 1;
        }
    }

    return create_config_files(overwrite, root_flag, skip_if_exist);
}

int main(int argc, char *argv[])
{
    int opt, option_index = 0;
    static const struct option long_options[] = {
        {"tpm-state", required_argument, NULL, 't'},
        {"tpmstate", required_argument, NULL, 't'}, /* alias for tpm-state */
        {"tpm", required_argument, NULL, 'T'},
        {"swtpm_ioctl", required_argument, NULL, '_'},
        {"tpm2", no_argument, NULL, '2'},
        {"ecc", no_argument, NULL, 'e'},
        {"createek", no_argument, NULL, 'c'},
        {"create-spk", no_argument, NULL, 'C'},
        {"take-ownership", no_argument, NULL, 'o'},
        {"ownerpass", required_argument, NULL, 'O'},
        {"owner-well-known", no_argument, NULL, 'w'},
        {"srkpass", required_argument, NULL, 'S'},
        {"srk-well-known", no_argument, NULL, 's'},
        {"create-ek-cert", no_argument, NULL, 'E'},
        {"create-platform-cert", no_argument, NULL, 'P'},
        {"lock-nvram", no_argument, NULL, 'L'},
        {"display", no_argument, NULL, 'i'},
        {"config", required_argument, NULL, 'f'},
        {"vmid", required_argument, NULL, 'm'},
        {"keyfile", required_argument, NULL, 'x'},
        {"keyfile-fd", required_argument, NULL, 'X'},
        {"pwdfile", required_argument, NULL, 'k'},
        {"pwdfile-fd", required_argument, NULL, 'K'},
        {"cipher", required_argument, NULL, 'p'},
        {"runas", required_argument, NULL, 'r'},
        {"logfile", required_argument, NULL, 'l'},
        {"overwrite", no_argument, NULL, 'v'},
        {"not-overwrite", no_argument, NULL, 'V'},
        {"allow-signing", no_argument, NULL, 'a'},
        {"decryption", no_argument, NULL, 'd'},
        {"pcr-banks", required_argument, NULL, 'b'},
        {"rsa-keysize", required_argument, NULL, 'A'},
        {"write-ek-cert-files", required_argument, NULL, '3'},
        {"create-config-files", optional_argument, NULL, 'u'},
        {"tcsd-system-ps-file", required_argument, NULL, 'F'},
        {"version", no_argument, NULL, '1'},
        {"print-capabilities", no_argument, NULL, 'y'},
        {"reconfigure", no_argument, NULL, 'R'},
        {"profile", required_argument, NULL, 'I'},
        {"no-iak", no_argument, NULL, 'n'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };
    unsigned long flags = 0;
    g_auto(GStrv) config_file_lines = NULL;
    g_autofree gchar *swtpm_prg = NULL;
    g_autofree gchar *tpm_state_path = NULL;
    struct swtpm_backend_ops *backend_ops = &swtpm_backend_dir;
    void *backend_state = NULL;
    g_autofree gchar *config_file = NULL;
    g_autofree gchar *ownerpass = NULL;
    gboolean got_ownerpass = FALSE;
    g_autofree gchar *srkpass = NULL;
    gboolean got_srkpass = FALSE;
    g_autofree gchar *vmid = NULL;
    g_autofree gchar *pcr_banks = NULL;
    gboolean printcapabilities = FALSE;
    g_autofree gchar *keyfile = NULL;
    long int keyfile_fd = -1;
    g_autofree gchar *pwdfile = NULL;
    long int pwdfile_fd = -1;
    g_autofree gchar *cipher = g_strdup("aes-128-cbc");
    g_autofree gchar *rsa_keysize_str = NULL;
    unsigned int rsa_keysize;
    g_autofree gchar *swtpm_keyopt = NULL;
    g_autofree gchar *runas = NULL;
    g_autofree gchar *certsdir = NULL;
    g_autofree gchar *user_certsdir = NULL;
    g_autofree gchar *json_profile = NULL;
    gchar *tmp;
    gchar **swtpm_prg_l = NULL;
    gchar **tmp_l = NULL;
    size_t i, n;
    struct stat statbuf;
    const struct passwd *curr_user;
    struct group *curr_grp;
    char *endptr;
    gboolean swtpm_has_tpm12 = FALSE;
    gboolean swtpm_has_tpm2 = FALSE;
    int fds_to_pass[1] = { -1 };
    unsigned n_fds_to_pass = 0;
    char tmpbuffer[200];
    gboolean no_iak = FALSE;
    time_t now;
    struct tm *tm;
    int ret = 1;
    g_autoptr(GError) error = NULL;

    setvbuf(stdout, 0, _IONBF, 0);

    if (init(&config_file) < 0)
        goto error;

    swtpm_prg = g_find_program_in_path("swtpm");
    if (swtpm_prg) {
        tmp = g_strconcat(swtpm_prg, " socket", NULL);
        g_free(swtpm_prg);
        swtpm_prg = tmp;
    }

    while ((opt = getopt_long(argc, argv, "h?",
                              long_options, &option_index)) != -1) {
        switch (opt) {
        case 't': /* --tpmstate, --tpm-state */
            g_free(tpm_state_path);
            if (strncmp(optarg, "dir://", 6) == 0) {
                tpm_state_path = g_strdup(optarg);
            } else if (strncmp(optarg, "file://", 7) == 0) {
                tpm_state_path = g_strdup(optarg);
                backend_ops = &swtpm_backend_file;
            } else {
                /* always prefix with dir:// so we can pass verbatim to swtpm */
                tpm_state_path = g_strconcat("dir://", optarg, NULL);
            }
            break;
        case 'T': /* --tpm */
            g_free(swtpm_prg);
            swtpm_prg = g_strdup(optarg);
            break;
        case '_': /* --swtpm_ioctl */
            fprintf(stdout, "Warning: --swtpm_ioctl is deprecated and has no effect.");
            break;
        case '2': /* --tpm2 */
            flags |= SETUP_TPM2_F;
            break;
        case 'e': /* --ecc */
            flags |= SETUP_TPM2_ECC_F;
            break;
        case 'c': /* --createek */
            flags |= SETUP_CREATE_EK_F;
            break;
        case 'C': /* --create-spk */
            flags |= SETUP_CREATE_SPK_F;
            break;
        case 'o': /* --take-ownership */
            flags |= SETUP_CREATE_EK_F | SETUP_TAKEOWN_F;
            break;
        case 'O': /* --ownerpass */
            g_free(ownerpass);
            ownerpass = g_strdup(optarg);
            got_ownerpass = TRUE;
            break;
        case 'w': /* --owner-well-known */
            flags |= SETUP_OWNERPASS_ZEROS_F;
            got_ownerpass = TRUE;
            break;
        case 'S': /* --srk-pass */
            g_free(srkpass);
            srkpass = g_strdup(optarg);
            got_srkpass = TRUE;
            break;
        case 's': /* --srk-well-known */
            flags |= SETUP_SRKPASS_ZEROS_F;
            got_srkpass = TRUE;
            break;
        case 'E': /* --create-ek-cert */
            flags |= SETUP_CREATE_EK_F | SETUP_EK_CERT_F;
            break;
        case 'P': /* --create-platform-cert */
            flags |= SETUP_CREATE_EK_F | SETUP_PLATFORM_CERT_F;
            break;
        case 'L': /* --lock-nvram */
            flags |= SETUP_LOCK_NVRAM_F;
            break;
        case 'i': /* --display */
            flags |= SETUP_DISPLAY_RESULTS_F;
            break;
        case 'f': /* --config */
            g_free(config_file);
            config_file = g_strdup(optarg);
            break;
        case 'm': /* --vmid */
            g_free(vmid);
            vmid = g_strdup(optarg);
            break;
        case 'x': /* --keyfile */
            g_free(keyfile);
            keyfile = g_strdup(optarg);
            break;
        case 'X': /* --pwdfile-fd' */
            keyfile_fd = strtoull(optarg, &endptr, 10);
            if (*endptr != '\0' && keyfile_fd >= INT_MAX) {
                fprintf(stderr, "Invalid file descriptor '%s'\n", optarg);
                goto error;
            }
            break;
        case 'k': /* --pwdfile */
            g_free(pwdfile);
            pwdfile = g_strdup(optarg);
            break;
        case 'K': /* --pwdfile-fd' */
            pwdfile_fd = strtoull(optarg, &endptr, 10);
            if (*endptr != '\0' || pwdfile_fd >= INT_MAX) {
                fprintf(stderr, "Invalid file descriptor '%s'\n", optarg);
                goto error;
            }
            break;
        case 'p': /* --cipher */
            g_free(cipher);
            cipher = g_strdup(optarg);
            break;
        case 'r': /* --runas */
            g_free(runas);
            runas = g_strdup(optarg);
            break;
        case 'l': /* --logfile */
            g_free(gl_LOGFILE);
            gl_LOGFILE = g_strdup(optarg);
            break;
        case 'v': /* --overwrite */
            flags |= SETUP_STATE_OVERWRITE_F;
            break;
        case 'V': /* --not-overwrite */
            flags |= SETUP_STATE_NOT_OVERWRITE_F;
            break;
        case 'a': /* --allow-signing */
            flags |= SETUP_ALLOW_SIGNING_F;
            break;
        case 'd': /* --decryption */
            flags |= SETUP_DECRYPTION_F;
            break;
        case 'b': /* --pcr-banks */
            tmp = g_strconcat(pcr_banks ? pcr_banks: "",
                              pcr_banks ? "," : "", g_strstrip(optarg), NULL);
            g_free(pcr_banks);
            pcr_banks = tmp;
            break;
        case 'A': /* --rsa-keysize */
            g_free(rsa_keysize_str);
            rsa_keysize_str = strdup(optarg);
            flags |= SETUP_RSA_KEYSIZE_BY_USER_F;
            break;
        case '3': /* --write-ek-cert-files */
            g_free(user_certsdir);
            user_certsdir = g_strdup(optarg);
            flags |= SETUP_WRITE_EK_CERT_FILES_F;
            break;
        case 'u':
            if (optarg == NULL && optind < argc && argv[optind][0] != '0')
                optarg = argv[optind++];
            ret = handle_create_config_files(optarg);
            goto out;
        case 'F': /* --tcsd-system-ps-file */
            printf("Warning: --tcsd-system-ps-file is deprecated and has no effect.");
            break;
        case '1': /* --version */
            versioninfo();
            ret = 0;
            goto out;
        case 'y': /* --print-capabilities */
            printcapabilities = TRUE;
            break;
        case 'R': /* --reconfigure */
            flags |= SETUP_RECONFIGURE_F;
            break;
        case 'I': /* --profile */
            g_free(json_profile);
            json_profile = g_strdup(optarg);
            break;
        case 'n': /* --no-iak */
            no_iak = TRUE;
            break;
        case '?':
        case 'h': /* --help */
            usage(argv[0], config_file);
            if (opt == 'h')
                ret = 0;
            goto out;
        default:
            fprintf(stderr, "Unknown option code %d\n", opt);
            usage(argv[0], config_file);
            goto error;
        }
    }

    if (swtpm_prg == NULL) {
        logerr(gl_LOGFILE,
               "Default TPM 'swtpm' could not be found and was not provided using --tpm.\n");
        goto error;
    }

    swtpm_prg_l = split_cmdline(swtpm_prg);
    tmp = g_find_program_in_path(swtpm_prg_l[0]);
    if (!tmp) {
        logerr(gl_LOGFILE, "swtpm at %s is not an executable.\n", swtpm_prg_l[0]);
        goto error;
    }
    g_free(tmp);

    ret = get_supported_tpm_versions(swtpm_prg_l, &swtpm_has_tpm12, &swtpm_has_tpm2);
    if (ret != 0)
        goto error;

    if (printcapabilities) {
        ret = print_capabilities(swtpm_prg_l, swtpm_has_tpm12, swtpm_has_tpm2);
        goto out;
    }

    if ((flags & SETUP_TPM2_F) != 0 && !swtpm_has_tpm2) {
        logerr(gl_LOGFILE, "swtpm at %s does not support TPM 2\n", swtpm_prg_l[0]);
        goto error;
    } else if ((flags & SETUP_TPM2_F) == 0 && !swtpm_has_tpm12){
        logerr(gl_LOGFILE, "swtpm at %s does not support TPM 1.2\n", swtpm_prg_l[0]);
        goto error;
    }

    if (runas) {
        ret = change_process_owner(runas);
        if (ret != 0)
            goto error;
    }

    if (!got_ownerpass)
        ownerpass = g_strdup(DEFAULT_OWNER_PASSWORD);
    if (!got_srkpass)
        srkpass = g_strdup(DEFAULT_SRK_PASSWORD);

    if (gl_LOGFILE != NULL) {
        FILE *tmpfile;
        if (stat(gl_LOGFILE, &statbuf) == 0 &&
            (statbuf.st_mode & S_IFMT) == S_IFLNK) {
            fprintf(stderr, "Logfile must not be a symlink.\n");
            goto error;
        }
        tmpfile = fopen(gl_LOGFILE, "a");
        if (tmpfile == NULL) {
            fprintf(stderr, "Cannot write to logfile %s.\n", gl_LOGFILE);
            goto error;
        }
        fclose(tmpfile);
    }

    curr_user = getpwuid(getuid());

    // Check tpm_state_path directory and access rights
    if (tpm_state_path == NULL) {
        logerr(gl_LOGFILE, "--tpm-state must be provided\n");
        goto error;
    }

    backend_state = backend_ops->parse_backend(tpm_state_path);
    if (!backend_state)
        goto error;

    if (backend_ops->check_access(backend_state, R_OK|W_OK, curr_user) != 0)
        goto error;

    if ((flags & SETUP_WRITE_EK_CERT_FILES_F)) {
        if (check_directory_access(user_certsdir, W_OK, curr_user) != 0)
            goto error;
    }

    if (flags & SETUP_TPM2_F) {
        if (flags & SETUP_TAKEOWN_F) {
            logerr(gl_LOGFILE, "Taking ownership is not supported for TPM 2.\n");
            goto error;
        }
    } else {
        if (flags & SETUP_TPM2_ECC_F) {
            logerr(gl_LOGFILE, "--ecc requires --tpm2.\n");
            goto error;
        }
        if (flags & SETUP_CREATE_SPK_F) {
            logerr(gl_LOGFILE, "--create-spk requires --tpm2.\n");
            goto error;
        }
        if (flags & SETUP_RECONFIGURE_F) {
            logerr(gl_LOGFILE, "--reconfigure requires --tpm2.\n");
            goto error;
        }
        if (flags & SETUP_ALLOW_SIGNING_F) {
            logerr(gl_LOGFILE, "--allow-signing requires --tpm2.\n");
            goto error;
        }
        if (flags & SETUP_DECRYPTION_F) {
            logerr(gl_LOGFILE, "--decryption requires --tpm2.\n");
            goto error;
        }
        if (pcr_banks) {
            logerr(gl_LOGFILE, "--pcr-banks requires --tpm2.\n");
            goto error;
        }
    }

    if (!(flags & SETUP_RECONFIGURE_F)) {
        ret = check_state_overwrite(swtpm_prg_l, flags, tpm_state_path);
        if (ret == 1) {
            goto error;
        } else if (ret == 2) {
            ret = 0;
            goto out;
        }

        ret = backend_ops->delete_state(backend_state);
        if (ret != 0)
            goto error;
    }

    if (access(config_file, R_OK) != 0) {
        logerr(gl_LOGFILE, "User %s cannot read config file %s.\n",
               curr_user ? curr_user->pw_name : "<unknown>", config_file);
        goto error;
    }

    /* read the config file; ignore errors here now */
    read_file_lines(config_file, &config_file_lines);

    /* check pcr_banks; read from config file if not given */
    tmp_l = g_strsplit(pcr_banks ? pcr_banks : "", ",", -1);
    for (i = 0, n = 0; tmp_l[i]; i++) {
        g_strstrip(tmp_l[i]);
        n += strlen(tmp_l[i]);
    }
    g_strfreev(tmp_l);
    if (n == 0) {
        g_free(pcr_banks);
        pcr_banks = get_default_pcr_banks(config_file_lines);
    }

    /* read default profile from swtpm_setup.conf */
    if ((flags & SETUP_TPM2_F) != 0 && json_profile == NULL)
        json_profile = get_default_profile(config_file_lines);

    if ((flags & SETUP_TPM2_F) != 0 && json_profile) {
        if (validate_json_profile(swtpm_prg_l, json_profile) != 0)
            goto error;
    } else if (json_profile) {
        logerr(gl_LOGFILE, "There's no --profile support for TPM 1.2\n");
        goto error;
    }

    if (cipher != NULL) {
        if (strcmp(cipher, "aes-128-cbc") != 0 &&
            strcmp(cipher, "aes-cbc") != 0 &&
            strcmp(cipher, "aes-256-cbc") != 0) {
            logerr(gl_LOGFILE, "Unsupported cipher %s.\n", cipher);
            goto error;
        }
        tmp = g_strdup_printf(",mode=%s", cipher);
        g_free(cipher);
        cipher = tmp;
    }

    if (keyfile != NULL) {
        if (access(keyfile, R_OK) != 0) {
            logerr(gl_LOGFILE, "User %s cannot read keyfile %s.\n",
                   curr_user ? curr_user->pw_name : "<unknown>", keyfile);
            goto error;
        }
        swtpm_keyopt = g_strdup_printf("file=%s%s", keyfile, cipher);
        logit(gl_LOGFILE, "  The TPM's state will be encrypted with a provided key.\n");
    } else if (pwdfile != NULL) {
        if (access(pwdfile, R_OK) != 0) {
            logerr(gl_LOGFILE, "User %s cannot read passphrase file %s.\n",
                   curr_user ? curr_user->pw_name : "<unknown>", pwdfile);
            goto error;
        }
        swtpm_keyopt = g_strdup_printf("pwdfile=%s%s", pwdfile, cipher);
        logit(gl_LOGFILE, "  The TPM's state will be encrypted using a key derived from a passphrase.\n");
    } else if (keyfile_fd >= 0) {
        fds_to_pass[n_fds_to_pass++] = keyfile_fd;
        swtpm_keyopt = g_strdup_printf("fd=%ld%s", keyfile_fd, cipher);
        logit(gl_LOGFILE, "  The TPM's state will be encrypted with a provided key (fd).\n");
    } else if (pwdfile_fd >= 0) {
        fds_to_pass[n_fds_to_pass++] = pwdfile_fd;
        swtpm_keyopt = g_strdup_printf("pwdfd=%ld%s", pwdfile_fd, cipher);
        logit(gl_LOGFILE, "  The TPM's state will be encrypted using a key derived from a passphrase (fd).\n");
    }

    if ((flags & SETUP_RSA_KEYSIZE_BY_USER_F) == 0)
        rsa_keysize_str = get_default_rsa_keysize(config_file_lines);

    if (strcmp(rsa_keysize_str, "max") == 0) {
        unsigned int *keysizes = NULL;
        size_t n_keysizes;

        ret = get_rsa_keysizes(flags, swtpm_prg_l, &keysizes, &n_keysizes);
        if (ret)
            goto error;
        g_free(rsa_keysize_str);
        if (n_keysizes > 0) {
            /* last one is the biggest one */
            rsa_keysize_str = g_strdup_printf("%u", keysizes[n_keysizes - 1]);
        } else {
            rsa_keysize_str = g_strdup("2048");
        }
        g_free(keysizes);
    }
    if (strcmp(rsa_keysize_str, "2048") == 0 || strcmp(rsa_keysize_str, "3072") == 0) {
        unsigned int *keysizes = NULL;
        size_t n_keysizes;
        gboolean found = FALSE;

        ret = get_rsa_keysizes(flags, swtpm_prg_l, &keysizes, &n_keysizes);
        if (ret)
            goto error;

        rsa_keysize = strtoull(rsa_keysize_str, NULL, 10);
        for (i = 0; i < n_keysizes && found == FALSE; i++)
            found = (keysizes[i] == rsa_keysize);
        if (!found && rsa_keysize != 2048) {
            logerr(gl_LOGFILE, "%u bit RSA keys are not supported by libtpms.\n", rsa_keysize);
            goto error;
        }
        g_free(keysizes);
    } else {
        logit(gl_LOGFILE, "Unsupported RSA key size %s.\n", rsa_keysize_str);
        goto error;
    }

    if (flags & SETUP_RECONFIGURE_F) {
        if (flags & (SETUP_CREATE_EK_F | SETUP_EK_CERT_F | SETUP_PLATFORM_CERT_F)) {
            logerr(gl_LOGFILE, "Reconfiguration is not supported with creation of EK or certificates\n");
            goto error;
        }
    }

    now = time(NULL);
    tm = localtime(&now);
    if (strftime(tmpbuffer, sizeof(tmpbuffer), "%a %d %h %Y %I:%M:%S %p %Z", tm) == 0) {
        logerr(gl_LOGFILE, "Could not format time/date string.\n");
        goto error;
    }
    curr_grp = getgrgid(getgid());
    logit(gl_LOGFILE, "Starting vTPM %s as %s:%s @ %s\n",
          flags & SETUP_RECONFIGURE_F ? "reconfiguration" : "manufacturing",
          curr_user ? curr_user->pw_name : "<unknown>",
          curr_grp ? curr_grp->gr_name : "<unknown>",
          tmpbuffer);

    if (flags & (SETUP_EK_CERT_F | SETUP_PLATFORM_CERT_F)) {
        certsdir = g_dir_make_tmp("swtpm_setup.certs.XXXXXX", &error);
        if (certsdir == NULL) {
            logerr(gl_LOGFILE, "Could not create temporary directory for certs: %s\n",
                   error->message);
            goto error;
        }
        if (!no_iak)
            flags |= SETUP_IAK_F | SETUP_IDEVID_F;
    }

    if ((flags & SETUP_TPM2_F) == 0) {
        ret = init_tpm(flags, swtpm_prg_l, config_file, tpm_state_path, ownerpass, srkpass, vmid,
                       swtpm_keyopt, fds_to_pass, n_fds_to_pass, certsdir, user_certsdir);
    } else {
        ret = init_tpm2(flags, swtpm_prg_l, config_file, tpm_state_path, vmid, pcr_banks,
                       swtpm_keyopt, fds_to_pass, n_fds_to_pass, rsa_keysize, certsdir,
                       user_certsdir, json_profile);
    }

    if (ret == 0) {
        logit(gl_LOGFILE, "Successfully authored TPM state.\n");
    } else {
        logerr(gl_LOGFILE, "An error occurred. Authoring the TPM state failed.\n");
        backend_ops->delete_state(backend_state);
    }

    now = time(NULL);
    tm = localtime(&now);
    if (strftime(tmpbuffer, sizeof(tmpbuffer), "%a %d %h %Y %I:%M:%S %p %Z", tm) == 0) {
        logerr(gl_LOGFILE, "Could not format time/date string.\n");
        goto error;
    }
    logit(gl_LOGFILE, "Ending vTPM manufacturing @ %s\n",
          tmpbuffer);

out:
    if (certsdir && g_rmdir(certsdir) != 0)
        logerr(gl_LOGFILE, "Could not remove temporary directory for certs: %s\n",
               strerror(errno));

    if (backend_ops && backend_state)
        backend_ops->free_backend(backend_state);
    g_strfreev(swtpm_prg_l);
    g_free(gl_LOGFILE);

    return ret;

error:
    ret = 1;
    goto out;
}
