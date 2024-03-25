/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * swtpm_localca.c: A tool for creating TPM 1.2 and TPM 2 certificates locally or using pkcs11
 *
 * Author: Stefan Berger, stefanb@linux.ibm.com
 *
 * Copyright (c) IBM Corporation, 2021
 */

#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <pwd.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <glib.h>

#include <gmp.h>

#include "swtpm_conf.h"
#include "swtpm_utils.h"
#include "swtpm_localca_utils.h"

#define SETUP_TPM2_F    1
/* for TPM 2 EK */
#define ALLOW_SIGNING_F 2
#define DECRYPTION_F    4

/* Default logging goes to stderr */
gchar *gl_LOGFILE = NULL;

#define LOCALCA_OPTIONS "swtpm-localca.options"
#define LOCALCA_CONFIG  "swtpm-localca.conf"

#if defined __APPLE__
# define CERTTOOL_NAME "gnutls-certtool"
#else
# define CERTTOOL_NAME "certtool"
#endif

/* initialize the path of the options and config files */
static int init(gchar **options_file, gchar **config_file)
{
    const gchar *configdir = g_get_user_config_dir();

    *options_file = g_build_filename(configdir, LOCALCA_OPTIONS, NULL);
    if (access(*options_file, R_OK) != 0) {
        g_free(*options_file);
        *options_file = g_build_filename(SYSCONFDIR, LOCALCA_OPTIONS, NULL);
    }

    *config_file = g_build_filename(configdir, LOCALCA_CONFIG, NULL);
    if (access(*config_file, R_OK) != 0) {
        g_free(*config_file);
        *config_file = g_build_filename(SYSCONFDIR, LOCALCA_CONFIG, NULL);
    }

    return 0;
}

/* Run the certtool command line prepared in cmd. Display error message
 * in case of failure and also display the keyfile if something goes wrong.
 */
static int run_certtool(gchar **cmd, gchar **env, const char *msg, gchar *keyfile)
{
    g_autofree gchar *standard_error = NULL;
    gint exit_status;
    GError *error = NULL;
    gboolean success;

    success = g_spawn_sync(NULL, cmd, env, G_SPAWN_STDOUT_TO_DEV_NULL, NULL, NULL,
                           NULL, &standard_error, &exit_status, &error);
    if (!success || exit_status != 0) {
        logerr(gl_LOGFILE, "%s" , msg);
        if (keyfile)
            logerr(gl_LOGFILE, " %s:", keyfile);
        if (!success) {
            logerr(gl_LOGFILE, "%s\n", error->message);
            g_error_free(error);
        } else {
            logerr(gl_LOGFILE, "%s\n", standard_error);
        }
        return 1;
    }
    return 0;
}

/* Create a root CA key and cert and a local CA key and cert. The latter will be
 * used for signing the TPM certs.
 */
static int create_localca_cert(const gchar *lockfile, const gchar *statedir,
                               const gchar *signkey, const gchar *signkey_password,
                               const gchar *issuercert)
{
    int lockfd;
    int ret = 1;
    struct stat statbuf;
    int template1_file_fd = -1;
    int template2_file_fd = -1;
    g_autofree gchar *template1_file = NULL;
    g_autofree gchar *template2_file = NULL;
    gchar **certtool_env = NULL;

    lockfd = lock_file(lockfile);
    if (lockfd < 0)
        return 1;

    if (stat(statedir, &statbuf) != 0) {
        if (makedir(statedir, "statedir") != 0)
            goto error;
    }

    if (access(signkey, R_OK) != 0 || access(issuercert, R_OK) != 0) {
        g_autofree gchar *directory = g_path_get_dirname(signkey);
        g_autofree gchar *cakey = g_strjoin(G_DIR_SEPARATOR_S, directory, "swtpm-localca-rootca-privkey.pem", NULL);
        g_autofree gchar *cacert = g_strjoin(G_DIR_SEPARATOR_S, directory, "swtpm-localca-rootca-cert.pem", NULL);
        const gchar *swtpm_rootca_password = g_getenv("SWTPM_ROOTCA_PASSWORD");
        g_autofree gchar *certtool = g_find_program_in_path(CERTTOOL_NAME);
        g_autofree gchar **cmd = NULL;
        g_autofree gchar *fc = NULL;
        const char *filecontent;

        if (certtool == NULL) {
            logerr(gl_LOGFILE, "Could not find %s in PATH.\n", CERTTOOL_NAME);
            goto error;
        }

        /* generate the root-CA's private key */
        cmd = concat_arrays(cmd, (gchar*[]){
                                (gchar *)certtool, "--generate-privkey", "--outfile", cakey, NULL
                            }, TRUE);
        if (swtpm_rootca_password != NULL)
            cmd = concat_arrays(cmd, (gchar*[]){
                                   "--password", (gchar *)swtpm_rootca_password, NULL
                                }, TRUE);
        if (run_certtool(cmd, certtool_env, "Could not create root-CA key", cakey))
            goto error;

        if (chmod(cakey, S_IRUSR | S_IWUSR | S_IRGRP) != 0) {
            logerr(gl_LOGFILE, "Could not chmod %s: %s\n", cakey, strerror(errno));
            goto error;
        }

        certtool_env = g_environ_setenv(NULL, "PATH", g_getenv("PATH"), TRUE);

        /* create the root-CA's cert */
        filecontent = "cn=swtpm-localca-rootca\n"
                      "ca\n"
                      "cert_signing_key\n"
                      "expiration_days = -1\n";
        template1_file_fd = write_to_tempfile(&template1_file,
                                              (const unsigned char *)filecontent, strlen(filecontent));
        if (template1_file_fd < 0)
            goto error;

        g_free(cmd);
        cmd = concat_arrays(NULL,
                            (gchar *[]) {
                                certtool,
                                "--generate-self-signed",
                                "--template", template1_file,
                                "--outfile", cacert,
                                "--load-privkey", cakey,
                                NULL
                            }, FALSE);
        if (swtpm_rootca_password != NULL)
            certtool_env = g_environ_setenv(certtool_env, "GNUTLS_PIN", swtpm_rootca_password, TRUE);

        if (run_certtool(cmd, certtool_env, "Could not create root-CA:", NULL))
            goto error;

        g_free(cmd);

        /* create the intermediate CA's key */
        cmd = concat_arrays(NULL,
                            (gchar *[]) {
                                certtool, "--generate-privkey", "--outfile", (gchar *)signkey, NULL
                            }, FALSE);
        if (signkey_password != NULL)
            cmd = concat_arrays(cmd, (gchar *[]){
                                    "--password", (gchar *)signkey_password, NULL},
                                TRUE);
        if (run_certtool(cmd, certtool_env, "Could not create local-CA key", cakey))
            goto error;

        if (chmod(signkey, S_IRUSR | S_IWUSR | S_IRGRP) != 0) {
            logerr(gl_LOGFILE, "Could not chmod %s: %s\n", signkey, strerror(errno));
            goto error;
        }

        filecontent = "cn=swtpm-localca\n"
                      "ca\n"
                      "cert_signing_key\n"
                      "expiration_days = -1\n";
        if (swtpm_rootca_password != NULL && signkey_password != NULL)
            fc = g_strdup_printf("%spassword = %s\n", filecontent, swtpm_rootca_password);
        else
            fc = g_strdup(filecontent);

        template2_file_fd = write_to_tempfile(&template2_file,
                                              (const unsigned char *)fc, strlen(fc));
        if (template2_file_fd < 0)
            goto error;

        g_free(cmd);
        cmd = concat_arrays(NULL,
                            (gchar *[]) {
                                certtool,
                                "--generate-certificate",
                                "--template", template2_file,
                                "--outfile", (gchar *)issuercert,
                                "--load-privkey", (gchar *)signkey,
                                "--load-ca-privkey", cakey,
                                "--load-ca-certificate", cacert,
                                NULL
                            }, FALSE);
        if (signkey_password != NULL)
            certtool_env = g_environ_setenv(certtool_env, "GNUTLS_PIN", signkey_password, TRUE);
        else if (swtpm_rootca_password != NULL)
            certtool_env = g_environ_setenv(certtool_env, "GNUTLS_PIN", swtpm_rootca_password, TRUE);

        if (run_certtool(cmd, certtool_env, "Could not create local-CA:", NULL))
            goto error;
    }

    ret = 0;

error:
    if (template1_file_fd >= 0)
        close(template1_file_fd);
    if (template1_file != NULL)
        unlink(template1_file);

    if (template2_file_fd >= 0)
        close(template2_file_fd);
    if (template2_file != NULL)
        unlink(template2_file);
    g_strfreev(certtool_env);

    unlock_file(lockfd);

    return ret;
}

/* Extract the ECC parameters from a string like x=12,y=34,id=secp384r1.
 * This function returns 1  on error, 2 if the ECC parameters could be extracted
 * and 0 if no parameters could be extracted (likely a modulus).
 */
static gboolean extract_ecc_params(const gchar *key_params, gchar **ecc_x, gchar **ecc_y, gchar **ecc_curveid)
{
    regmatch_t pmatch[5];
    regex_t preg;
    int ret;

    if (regcomp(&preg, "x=([0-9A-Fa-f]+),y=([0-9A-Fa-f]+)(,id=([^,]+))?",
                REG_EXTENDED) != 0) {
        logerr(gl_LOGFILE, "Internal error: Could not compile regex\n");
        return 1;
    }

    ret = 0;
    if (regexec(&preg, key_params, 5, pmatch, 0) == 0) {
        *ecc_x = g_strndup(&key_params[pmatch[1].rm_so],
                           pmatch[1].rm_eo - pmatch[1].rm_so);
        *ecc_y = g_strndup(&key_params[pmatch[2].rm_so],
                           pmatch[2].rm_eo - pmatch[2].rm_so);
        if (pmatch[4].rm_so > 0 && pmatch[4].rm_eo > 0)
            *ecc_curveid = g_strndup(&key_params[pmatch[4].rm_so],
                                     pmatch[4].rm_eo - pmatch[4].rm_so);
        ret = 2;
    }

    regfree(&preg);

    return ret;
}

/* Create a random ASCII decimal number of given length.
 * The buffer is not NUL terminated.
 */
static void get_random_serial(char *buffer, size_t length)
{
    GRand *grand = g_rand_new();
    size_t i;

    buffer[0] = '0' + g_rand_int_range(grand, 1, 9);
    for (i = 1; i < length; i++)
        buffer[i] = '0' + g_rand_int_range(grand, 0, 9);

    g_rand_free(grand);
}

/* Get the next serial number from the certserial file; if it contains
 * a non-numeric content start over with a random 20 digit serial number.
 * Up to 20 bytes of serial number are supported. The max.
 * serial number is decimal: 1461501637330902918203684832716283019655932542975
 * This decimal number is 49 digits long.
 * This function will write back the used serial number that the next
 * caller must increase by '1' to be allowed to use it.
 */
static int get_next_serial(const gchar *certserial, const gchar *lockfile,
                           gchar **serial_str)
{
    g_autofree gchar *buffer = NULL;
    char serialbuffer[50];
    size_t buffer_len;
    mpz_t serial;
    int lockfd;
    int ret = 1;

    lockfd = lock_file(lockfile);
    if (lockfd < 0)
        return 1;

    if (access(certserial, R_OK) != 0) {
        get_random_serial(serialbuffer, 20);
        write_file(certserial, (unsigned char *)serialbuffer, 20);
    }
    if (read_file(certserial, &buffer, &buffer_len) != 0)
        goto error;

    mpz_init(serial);

    if (buffer_len > 0 && buffer_len <= 49) {
        memcpy(serialbuffer, buffer, buffer_len);
        serialbuffer[buffer_len] = 0;

        if (gmp_sscanf(serialbuffer, "%Zu", serial) != 1)
            goto new_serial;
        mpz_add_ui(serial, serial, 1);

        if ((mpz_sizeinbase(serial, 2) + 7) / 8 > 20)
            goto new_serial;

        if (gmp_snprintf(serialbuffer,
                         sizeof(serialbuffer),
                         "%Zu", serial) >= (int)sizeof(serialbuffer))
            goto new_serial;
    } else {
new_serial:
        /* start with random serial number */
        buffer_len = 20;
        get_random_serial(serialbuffer, buffer_len);
        serialbuffer[buffer_len] = 0;
    }
    *serial_str = g_strdup(serialbuffer);
    write_file(certserial, (unsigned char *)*serial_str, strlen(*serial_str));
    ret = 0;

    mpz_clear(serial);

error:
    unlock_file(lockfd);

    return ret;
}

/* Create a TPM 1.2 or TPM 2 EK or platform cert */
static int create_cert(unsigned long flags, const gchar *typ, const gchar *directory,
                       gchar *key_params, const gchar *vmid, gchar **tpm_spec_params,
                       gchar **tpm_attr_params, const gchar *signkey,
                       const gchar *signkey_password, const gchar *issuercert,
                       const gchar *parentkey_password, gchar **swtpm_cert_env,
                       const gchar *certserial, gchar *tpm_serial_num,
                       const gchar *lockfile, const gchar *optsfile)
{
    gchar ** optsfile_lines = NULL;
    g_autofree gchar **options = NULL;
    g_autofree gchar **keyparams = NULL;
    g_autofree gchar **cmd = NULL;
    g_autofree gchar *subject = NULL;
    g_autofree gchar *ecc_x = NULL;
    g_autofree gchar *ecc_y = NULL;
    g_autofree gchar *ecc_curveid = NULL;
    g_autofree gchar *certfile = NULL;
    g_autofree gchar *serial_str = NULL;
    gchar **to_free = NULL;
    gchar **split;
    const char *certtype;
    int signkey_pwd_fd = -1;
    int parentkey_pwd_fd  = -1;
    g_autofree gchar *signkey_pwd_file = NULL;
    g_autofree gchar *signkey_pwd_file_param = NULL;
    g_autofree gchar *parentkey_pwd_file = NULL;
    g_autofree gchar *parentkey_pwd_file_param = NULL;
    gboolean success;
    g_autofree gchar *tmp_typ = g_strdup(typ);
    g_autofree gchar *standard_output = NULL;
    g_autofree gchar *standard_error = NULL;
    g_autofree gchar *swtpm_cert_path = NULL;
    GError *error = NULL;
    gint exit_status;
    int ret = 1;
    size_t i, j;

    swtpm_cert_path = g_find_program_in_path("swtpm_cert");
    if (swtpm_cert_path == NULL) {
        logerr(gl_LOGFILE, "Could not find swtpm_cert in PATH.\n");
        return 1;
    }

    if (get_next_serial(certserial, lockfile, &serial_str) != 0)
        return 1;

    /* try to read the optsfile - failure to read is fine */
    read_file_lines(optsfile, &optsfile_lines);

    /* split each line from the optsfile and add the stripped parameters to options */
    for (i = 0; optsfile_lines != NULL && optsfile_lines[i] != NULL; i++) {
        gchar *chomped = g_strchomp(optsfile_lines[i]);
        if (strlen(chomped) == 0)
            continue;

        split = g_strsplit(chomped, " ", -1);
        for (j = 0; split[j] != NULL; j++) {
            chomped = g_strchomp(split[j]);
            if (strlen(chomped) > 0) {
                gchar *to_add = g_strdup(chomped);
                options = concat_arrays(options, (gchar *[]){to_add, NULL}, TRUE);
                /* need to collect this also to free later on */
                to_free = concat_arrays(to_free, (gchar *[]){to_add, NULL}, TRUE);
            }
        }
        g_strfreev(split);
    }

    if (strcmp(typ, "ek") == 0 || strcmp(typ, "platform") == 0) {
        subject = g_strdup_printf("CN=%s",
                                  vmid ? vmid : "unknown");
    } else if (strcmp(typ, "iak") == 0 || strcmp(typ, "idevid") == 0) {
        subject = g_strdup_printf("serialNumber=%s",
                                  vmid ? vmid : "unknown");
    }

    if ((flags & SETUP_TPM2_F) && tpm_serial_num)
        options = concat_arrays(options,
                                (gchar *[]){
                                    "--tpm-serial-num",
                                    tpm_serial_num,
                                    NULL
                                }, TRUE);

    if (flags & SETUP_TPM2_F)
        options = concat_arrays(options, (gchar *[]){"--tpm2", NULL}, TRUE);
    else
        options = concat_arrays(options, (gchar *[]){"--add-header", NULL}, TRUE);

    if (strcmp(typ, "ek") == 0) {
        if (flags & ALLOW_SIGNING_F)
            options = concat_arrays(options, (gchar *[]){"--allow-signing", NULL}, TRUE);
        if (flags & DECRYPTION_F)
            options = concat_arrays(options, (gchar *[]){"--decryption", NULL}, TRUE);
    }

    switch (extract_ecc_params(key_params, &ecc_x, &ecc_y, &ecc_curveid)) {
    case 1:
        goto error;
    case 2:
        keyparams = concat_arrays((gchar *[]){
                                      "--ecc-x", ecc_x,
                                      "--ecc-y", ecc_y,
                                      NULL
                                  },
                                  NULL, FALSE);
        if (ecc_curveid != NULL)
           keyparams = concat_arrays(keyparams,
                                     (gchar *[]){
                                         "--ecc-curveid", ecc_curveid,
                                         NULL
                                     }, TRUE);
        break;
    case 0:
        keyparams = concat_arrays((gchar *[]){
                                      "--modulus", key_params,
                                      NULL},
                                   NULL, FALSE);
        break;
    }

    cmd = concat_arrays((gchar *[]){
                            swtpm_cert_path, "--subject", subject, NULL
                        }, options, FALSE);

    if (signkey_password != NULL) {
        signkey_pwd_fd = write_to_tempfile(&signkey_pwd_file,
                                           (unsigned char *)signkey_password, strlen(signkey_password));
        if (signkey_pwd_fd < 0)
            goto error;

        signkey_pwd_file_param = g_strdup_printf("file:%s", signkey_pwd_file);
        cmd = concat_arrays(cmd, (gchar*[]){"--signkey-pwd", signkey_pwd_file_param, NULL}, TRUE);
    }
    if (parentkey_password != NULL) {
        parentkey_pwd_fd = write_to_tempfile(&parentkey_pwd_file,
                                             (unsigned char *)parentkey_password, strlen(parentkey_password));
        if (parentkey_pwd_fd < 0)
            goto error;

        parentkey_pwd_file_param = g_strdup_printf("file:%s", parentkey_pwd_file);
        cmd = concat_arrays(cmd, (gchar*[]){"--parentkey-pwd", parentkey_pwd_file_param, NULL}, TRUE);
    }

    if (strcmp(typ, "ek") == 0)
        cmd = concat_arrays(cmd, tpm_spec_params, TRUE);

    cmd = concat_arrays(cmd, tpm_attr_params, TRUE);

    if (strcmp(typ, "platform") == 0 || strcmp(typ, "iak") == 0 || strcmp(typ, "idevid") == 0) {
        g_autofree gchar *certfn = g_strconcat(typ, ".cert", NULL);

        certfile = g_strjoin(G_DIR_SEPARATOR_S, directory, certfn, NULL);
        cmd = concat_arrays(cmd,
                            (gchar *[]){
                                "--type", tmp_typ,
                                "--out-cert", certfile,
                                NULL},
                            TRUE);
    } else {
        certfile = g_strjoin(G_DIR_SEPARATOR_S, directory, "ek.cert", NULL);
        cmd = concat_arrays(cmd,
                            (gchar *[]){
                                "--out-cert", certfile,
                                NULL
                            }, TRUE);
    }

    cmd = concat_arrays(cmd, keyparams, TRUE);
    cmd = concat_arrays(cmd, (gchar *[]){
                            "--signkey", (gchar *)signkey,
                            "--issuercert", (gchar *)issuercert,
                            "--days", "-1",
                            "--serial", (gchar *)serial_str,
                            NULL
                        }, TRUE);

    if (strcmp(typ, "ek") == 0)
        certtype = "EK";
    else
        certtype = typ;
#if 0
    {
        g_autofree gchar *join = g_strjoinv(" ", cmd);
        fprintf(stderr, "Starting: %s\n", join);
    }
#endif
    success = g_spawn_sync(NULL, cmd, swtpm_cert_env, G_SPAWN_DEFAULT, NULL, NULL,
                           &standard_output, &standard_error, &exit_status, &error);
    if (!success) {
        logerr(gl_LOGFILE, "Could not run swtpm_cert: %s\n", error);
        g_error_free(error);
        goto error;
    }
    if (exit_status != 0) {
        logerr(gl_LOGFILE, "Could not create %s certificate locally\n", certtype);
        logerr(gl_LOGFILE, "%s\n", standard_error);
        goto error;
    }

    logit(gl_LOGFILE, "Successfully created %s certificate locally.\n", certtype);
    ret = 0;

error:
    g_strfreev(optsfile_lines);
    g_strfreev(to_free);

    if (signkey_pwd_fd >= 0)
       close(signkey_pwd_fd);
    if (signkey_pwd_file)
       unlink(signkey_pwd_file);

    if (parentkey_pwd_fd >= 0)
       close(parentkey_pwd_fd);
    if (parentkey_pwd_file)
       unlink(parentkey_pwd_file);

    return ret;
}

static void usage(const char *prgname)
{
   printf(
        "Usage: %s [options]\n"
        "\n"
        "The following options are supported:\n"
        "\n"
        "--type type           The type of certificate to create: 'ek' or 'platform'\n"
        "--ek key-param        The modulus of an RSA key or x=...,y=,... for an EC key\n"
        "--key key-param       Alias for --ek\n"
        "--dir directory       The directory to write the resulting certificate into\n"
        "--vmid vmid           The ID of the virtual machine\n"
        "--optsfile file       A file containing options to pass to swtpm_cert\n"
        "--configfile file     A file containing configuration parameters for directory,\n"
        "                      signing key and password and certificate to use\n"
        "--logfile file        A file to write a log into\n"
        "--tpm-spec-family s   The implemented spec family, e.g., '2.0'\n"
        "--tpm-spec-revision i The spec revision of the TPM as integer; e.g., 146\n"
        "--tpm-spec-level i    The spec level of the TPM; must be an integer; e.g. 0\n"
        "--tpm-manufacturer s  The manufacturer of the TPM; e.g., id:00001014\n"
        "--tpm-model s         The model of the TPM; e.g., 'swtpm'\n"
        "--tpm-version i       The (firmware) version of the TPM; e.g., id:20160511\n"
        "--tpm-serial-num s    The string representing the serial number of the TPM\n"
        "--tpm2                Generate a certificate for a TPM 2\n"
        "--allow-signing       The TPM 2's EK can be used for signing\n"
        "--decryption          The TPM 2's EK can be used for decryption\n"
        "--help, -h            Display this help screen and exit\n"
        "\n"
        "\n"
        "The following environment variables are supported:\n"
        "\n"
        "SWTPM_ROOTCA_PASSWORD  The root CA's private key password\n"
        "\n", prgname);
}

int main(int argc, char *argv[])
{
    int opt, option_index = 0;
    static const struct option long_options[] = {
        {"type", required_argument, NULL, 't'},
        {"ek", required_argument, NULL, 'e'},
        {"key", required_argument, NULL, 'e'}, /* alias for --ek */
        {"dir", required_argument, NULL, 'd'},
        {"vmid", required_argument, NULL, 'v'},
        {"optsfile", required_argument, NULL, 'o'},
        {"configfile", required_argument, NULL, 'c'},
        {"logfile", required_argument, NULL, 'l'},
        {"tpm-spec-family", required_argument, NULL, 'f'},
        {"tpm-spec-revision", required_argument, NULL, 'r'},
        {"tpm-spec-level", required_argument, NULL, '1'},
        {"tpm-manufacturer", required_argument, NULL, 'a'},
        {"tpm-model", required_argument, NULL, 'm'},
        {"tpm-version", required_argument, NULL, 's'},
        {"tpm-serial-num", required_argument, NULL, 'S'},
        {"tpm2", no_argument, NULL, '2'},
        {"allow-signing", no_argument, NULL, 'i'},
        {"decryption", no_argument, NULL, 'y'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0},
    };
    g_autofree gchar *default_options_file = NULL;
    g_autofree gchar *default_config_file = NULL;
    g_autofree gchar *optsfile = NULL;
    g_autofree gchar *configfile = NULL;
    unsigned long flags = 0;
    g_autofree gchar *typ =g_strdup("");
    g_autofree gchar *key_params = g_strdup("");
    g_autofree gchar *directory = g_strdup("."); /* default to current directory */
    g_autofree gchar *vmid = NULL;
    g_autofree gchar *lockfile = NULL;
    g_autofree gchar *statedir = NULL;
    g_autofree gchar *signkey = NULL;
    g_autofree gchar *signkey_password = NULL;
    g_autofree gchar *parentkey_password = NULL;
    g_autofree gchar *issuercert = NULL;
    g_autofree gchar *certserial = NULL;
    g_autofree gchar *tpm_serial_num = NULL;
    gchar **tpm_spec_params = NULL;
    gchar **tpm_attr_params = NULL;
    gchar **config_file_lines = NULL;
    gchar **swtpm_cert_env = NULL;
    const struct passwd *curr_user;
    struct stat statbuf;
    int ret = 1;

    setvbuf(stdout, 0, _IONBF, 0);

    if (init(&default_options_file, &default_config_file) < 0)
        goto error;
    optsfile = g_strdup(default_options_file);
    configfile = g_strdup(default_config_file);

    while ((opt = getopt_long(argc, argv, "h?",
                              long_options, &option_index)) != -1) {
        switch (opt) {
        case 't': /* --type */
            g_free(typ);
            typ = g_strdup(optarg);
            break;
        case 'e': /* --ek or --key */
            g_free(key_params);
            key_params = g_strdup(optarg);
            break;
        case 'd': /* --dir */
            g_free(directory);
            directory = g_strdup(optarg);
            break;
        case 'v': /* --vmid */
            g_free(vmid);
            vmid = g_strdup(optarg);
            vmid_replacechars(vmid);
            break;
        case 'o': /* --optsfile */
            g_free(optsfile);
            optsfile = g_strdup(optarg);
            break;
        case 'c': /* --configfile */
            g_free(configfile);
            configfile = g_strdup(optarg);
            break;
        case 'l': /* --logfile */
            g_free(gl_LOGFILE);
            gl_LOGFILE = g_strdup(optarg);
            break;
        case 'f': /* --tpm-spec-family */
        case 'r': /* --tpm-spec-revision */
        case '1': /* --tpm-spec-level */
            tpm_spec_params = concat_arrays(tpm_spec_params,
                          (gchar *[]) {
                              g_strdup_printf("--%s", long_options[option_index].name), g_strdup(optarg), NULL
                          }, TRUE);
            break;
        case 'a': /* --tpm-manufacturer */
        case 'm': /* --tpm-model */
        case 's': /* --tpm-version */
            tpm_attr_params = concat_arrays(tpm_attr_params,
                          (gchar *[]) {
                              g_strdup_printf("--%s", long_options[option_index].name), g_strdup(optarg), NULL
                          }, TRUE);
            break;
        case 'S': /* --tpm-serial-num */
            g_free(tpm_serial_num);
            tpm_serial_num = g_strdup(optarg);
            break;
        case '2': /* --tpm2 */
            flags |= SETUP_TPM2_F;
            break;
        case 'i': /* --allow-signing */
            flags |= ALLOW_SIGNING_F;
            break;
        case 'y': /* --decryption */
            flags |= DECRYPTION_F;
            break;
        case '?':
        case 'h': /* --help */
            usage(argv[0]);
            if (opt == 'h')
                ret = 0;
            goto out;
        default:
            fprintf(stderr, "Unknown option code %d\n", opt);
            usage(argv[0]);
            goto error;
        }
    }

    curr_user = getpwuid(getuid());

    if (gl_LOGFILE != NULL) {
        FILE *tmpfile;

        if (stat(gl_LOGFILE, &statbuf) == 0 &&
            (statbuf.st_mode & S_IFMT) == S_IFLNK) {
            fprintf(stderr, "Logfile must not be a symlink.\n");
            goto error;
        }
        tmpfile = fopen(gl_LOGFILE, "a"); // do not truncate
        if (tmpfile == NULL) {
            fprintf(stderr, "Cannot write to logfile %s.\n", gl_LOGFILE);
            goto error;
        }
        fclose(tmpfile);
    }

    if (access(optsfile, R_OK) != 0) {
        logerr(gl_LOGFILE, "Need read rights on options file %s for user %s.\n",
               optsfile, curr_user ? curr_user->pw_name : "<unknown>");
        goto error;
    }

    if (access(configfile, R_OK) != 0) {
        logerr(gl_LOGFILE, "Need read rights on config file %s for user %s.\n",
               configfile, curr_user ? curr_user->pw_name : "<unknown>");
        goto error;
    }

    if (read_file_lines(configfile, &config_file_lines) != 0)
        goto error;

    statedir = get_config_value(config_file_lines, "statedir", NULL);
    if (statedir == NULL) {
        logerr(gl_LOGFILE, "Missing 'statedir' config value in config file %s.\n", configfile);
        goto error;
    }
    if (makedir(statedir, "statedir") != 0)
        goto error;
    if (access(statedir, W_OK | R_OK) != 0) {
        logerr(gl_LOGFILE, "Need read/write rights on statedir %s for user %s.\n",
               statedir, curr_user ? curr_user->pw_name : "<unknown>");
        goto error;
    }

    lockfile = g_strjoin(G_DIR_SEPARATOR_S, statedir, ".lock.swtpm-localca", NULL);
    if (stat(lockfile, &statbuf) == 0 &&
        access(lockfile, W_OK | R_OK) != 0) {
        logerr(gl_LOGFILE, "Need read/write rights on %s for user %s.\n",
               lockfile, curr_user ? curr_user->pw_name : "<unknown>");
        goto error;
    }

    signkey = get_config_value(config_file_lines, "signingkey", NULL);
    if (signkey == NULL) {
        logerr(gl_LOGFILE, "Missing 'signingkey' config value in config file %s.\n",
               configfile);
        goto error;
    }

    if (!g_str_has_prefix(signkey, "tpmkey:file=") &&
        !g_str_has_prefix(signkey, "tpmkey:uuid=") &&
        !g_str_has_prefix(signkey, "pkcs11:")) {
        g_autofree gchar *d = g_path_get_dirname(signkey);
        if (makedir(d, "signkey") != 0)
            goto error;
    }

    signkey_password = get_config_value(config_file_lines, "signingkey_password", NULL);
    parentkey_password = get_config_value(config_file_lines, "parentkey_password", NULL);

    issuercert = get_config_value(config_file_lines, "issuercert", NULL);
    if (issuercert == NULL) {
        logerr(gl_LOGFILE, "Missing 'issuercert' config value in config file %s.\n", configfile);
        goto error;
    }
    {
       g_autofree gchar *d = g_path_get_dirname(issuercert);
       if (makedir(d, "issuercert") != 0)
           goto error;
    }

    swtpm_cert_env = g_get_environ();

    // TPM keys are GNUTLS URIs...
    if (g_str_has_prefix(signkey, "tpmkey:file=") || g_str_has_prefix(signkey, "tpmkey:uuid=")) {
        g_autofree gchar *tss_tcsd_hostname = NULL;
        g_autofree gchar *tss_tcsd_port = NULL;

        tss_tcsd_hostname = get_config_value(config_file_lines,
                                             "TSS_TCSD_HOSTNAME", "localhost");
        tss_tcsd_port = get_config_value(config_file_lines,
                                         "TSS_TCSD_PORT", "30003");
        swtpm_cert_env = g_environ_setenv(swtpm_cert_env,
                                          "TSS_TCSD_HOSTNAME", tss_tcsd_hostname, TRUE);
        swtpm_cert_env = g_environ_setenv(swtpm_cert_env,
                                          "TSS_TCSD_PORT", tss_tcsd_port, TRUE);

        logit(gl_LOGFILE, "CA uses a GnuTLS TPM key; using TSS_TCSD_HOSTNAME=%s " \
                          "TSS_TCSD_PORT=%s\n", tss_tcsd_hostname, tss_tcsd_port);
    } else if (g_str_has_prefix(signkey, "pkcs11:")) {
        gchar *tmp = str_replace(signkey, "\\;", ";"); /* historical reasons ... */
        g_free(signkey);
        signkey = tmp;

        if (signkey_password != NULL) {
            swtpm_cert_env = g_environ_setenv(swtpm_cert_env,
                                              "SWTPM_PKCS11_PIN", g_strdup(signkey_password), TRUE);
            logit(gl_LOGFILE, "CA uses a PKCS#11 key; using SWTPM_PKCS11_PIN\n");
        } else {
            g_autofree gchar *swtpm_pkcs11_pin = NULL;

            swtpm_pkcs11_pin = get_config_value(config_file_lines,
                                                "SWTPM_PKCS11_PIN", "swtpm-tpmca");
            swtpm_cert_env = g_environ_setenv(swtpm_cert_env,
                                              "SWTPM_PKCS11_PIN", swtpm_pkcs11_pin, TRUE);
            logit(gl_LOGFILE, "CA uses a PKCS#11 key; using SWTPM_PKCS11_PIN\n");
        }
        ret = get_config_envvars(config_file_lines, &swtpm_cert_env);
        if (ret != 0)
            goto error;
    } else {
        int create_certs = 0;

        /* create certificate if either the signing key or issuer cert are missing */
        if (access(signkey, R_OK) != 0) {
            if (stat(signkey, &statbuf) == 0) {
                logerr(gl_LOGFILE, "Need read rights on signing key %s for user %s.\n",
                       signkey, curr_user ? curr_user->pw_name : "<unknown>");
                goto error;
            }
            create_certs = 1;
        }

        if (access(issuercert, R_OK) != 0) {
            if (stat(issuercert, &statbuf) == 0) {
                logerr(gl_LOGFILE, "Need read rights on issuer certificate %s for user %s.\n",
                       issuercert, curr_user ? curr_user->pw_name : "<unknown>");
                goto error;
            }
            create_certs = 1;
        }

        if (create_certs) {
            logit(gl_LOGFILE, "Creating root CA and a local CA's signing key and issuer cert.\n");
            if (create_localca_cert(lockfile, statedir, signkey, signkey_password,
                                    issuercert) != 0) {
                logerr(gl_LOGFILE, "Error creating local CA's signing key and cert.\n");
                goto error;
            }

            if (access(signkey, R_OK) != 0) {
                logerr(gl_LOGFILE, "Need read rights on signing key %s for user %s.\n",
                       signkey, curr_user ? curr_user->pw_name : "<unknown>");
                goto error;
            }
        }
    }

    if (access(issuercert, R_OK) != 0) {
        logerr(gl_LOGFILE, "Need read rights on issuer certificate %s for user %s.\n",
               issuercert, curr_user ? curr_user->pw_name : "<unknown>");
        goto error;
    }

    {
        g_autofree gchar *d = NULL;
        g_autofree gchar *p = g_strjoin(G_DIR_SEPARATOR_S, statedir, "certserial", NULL);

        certserial = get_config_value(config_file_lines, "certserial", p);
        d = g_path_get_dirname(certserial);
        if (makedir(d, "certserial") != 0)
            goto error;
    }

    ret = create_cert(flags, typ, directory, key_params, vmid, tpm_spec_params, tpm_attr_params,
                      signkey, signkey_password, issuercert, parentkey_password, swtpm_cert_env,
                      certserial, tpm_serial_num, lockfile, optsfile);

out:
error:
    g_strfreev(config_file_lines);
    g_strfreev(swtpm_cert_env);
    g_strfreev(tpm_attr_params);
    g_strfreev(tpm_spec_params);

    return ret;
}
