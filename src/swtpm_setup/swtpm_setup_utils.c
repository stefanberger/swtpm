/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * swtpm_setup_utils.c: Utility functions for swtpm_setup
 *
 * Author: Stefan Berger, stefanb@linux.ibm.com
 *
 * Copyright (c) IBM Corporation, 2021
 */

#include "config.h"

#include <errno.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <glib.h>

#include "swtpm_setup_conf.h"
#include "swtpm_setup_utils.h"
#include "swtpm_utils.h"

/* Get a configuration value given its name */
gchar *get_config_value(gchar **config_file_lines, const gchar *configname)
{
    g_autofree gchar *regex = g_strdup_printf("^%s[[:space:]]*=[[:space:]]*([^#\n]*).*",
                                              configname);
    gchar *result = NULL;
    regmatch_t pmatch[2];
    regex_t preg;
    size_t idx;

    if (regcomp(&preg, regex, REG_EXTENDED) != 0) {
        logerr(gl_LOGFILE, "Internal error: Could not compile regex\n");
        return NULL;
    }

    for (idx = 0; config_file_lines[idx] != NULL; idx++) {
        const gchar *line = config_file_lines[idx];
        if (regexec(&preg, line, 2, pmatch, 0) == 0) {
            g_autofree gchar *tmp = NULL;

            tmp = g_strndup(&line[pmatch[1].rm_so],
                            pmatch[1].rm_eo - pmatch[1].rm_so);
            /* coverity: g_strchmop modifies in-place */
            tmp = g_strchomp(tmp);
            result = resolve_string(tmp);
            break;
        }
    }

    regfree(&preg);

    return result;
}

/* Create swtpm_setup and swtpm-localca config files for a user
 *
 * @overwrite: TRUE:  overwrite any existing config files
 *             FALSE: return error if any file exists
 * @root_flag: TRUE:  create the config files under root's home
 *                    directory shadowing any existing config files in /etc/
 *             FALSE: refuse to create config files as root
 * @skip_if_exist: TRUE  if any one config files exists return with no error
 *
 */
int create_config_files(gboolean overwrite, gboolean root_flag,
                        gboolean skip_if_exist)
{
    enum {
        SWTPM_SETUP_CONF = 0,
        SWTPM_LOCALCA_CONF = 1,
        SWTPM_LOCALCA_OPTIONS = 2,
        NUM_FILES = 3,
    };
    const gchar *filenames[NUM_FILES] = {
        "swtpm_setup.conf",
        "swtpm-localca.conf",
        "swtpm-localca.options"
    };
    const gchar *configdir = g_get_user_config_dir();
    g_autofree gchar *create_certs_tool = NULL;
    g_autofree gchar *swtpm_localca_dir = NULL;
    g_autofree gchar *signkey = NULL;
    g_autofree gchar *issuercert = NULL;
    g_autofree gchar *certserial = NULL;
    g_autofree gchar *platform_manufacturer = NULL;
    g_autofree gchar *platform_version = NULL;
    g_autofree gchar *platform_model = NULL;
    g_autoptr(GError) error = NULL;
    gboolean delete_files = FALSE;
    g_auto(GStrv) configfiles = NULL;
    g_auto(GStrv) filedata = NULL;
    struct utsname utsname;
    int ret = 1;
    size_t i;

    if (getuid() == 0 && !root_flag) {
        fprintf(stderr, "Requiring the 'root' flag since the configuration "
                        "files will shadow those in %s.\n", SYSCONFDIR);
        goto error;
    }

    configfiles = g_new0(gchar *, NUM_FILES + 1);
    for (i = 0; i < NUM_FILES; i++) {
        configfiles[i] = g_build_filename(configdir, filenames[i], NULL);
        if (!overwrite && g_file_test(configfiles[i], G_FILE_TEST_EXISTS)) {
            if (skip_if_exist) {
                ret = 0;
            } else {
                fprintf(stderr, "File %s already exists. Refusing to overwrite.\n",
                        configfiles[i]);
            }
            goto out;
        }
    }

    swtpm_localca_dir = g_build_filename(configdir,
                                         "var", "lib", "swtpm-localca", NULL);
    if (g_mkdir_with_parents(swtpm_localca_dir, 0775) < 0) {
        fprintf(stderr, "Could not create %s: %s\n",
                swtpm_localca_dir, strerror(errno));
        goto error;
    }

    filedata = g_new0(gchar *, NUM_FILES + 1);

    /* setpm_setup.conf */
    create_certs_tool = g_build_filename(DATAROOTDIR,
                                         "swtpm", "swtpm-localca", NULL);
    filedata[SWTPM_SETUP_CONF] = g_strdup_printf(
        "create_certs_tool = %s\n"
        "create_certs_tool_config = %s\n"
        "create_certs_tool_options = %s\n",
        create_certs_tool,
        configfiles[SWTPM_LOCALCA_CONF],
        configfiles[SWTPM_LOCALCA_OPTIONS]
    );

    /* swtpm-localca.conf */
    signkey = g_build_filename(swtpm_localca_dir, "signkey.pem", NULL);
    issuercert = g_build_filename(swtpm_localca_dir, "issuercert.pem", NULL);
    certserial = g_build_filename(swtpm_localca_dir, "certserial", NULL);
    filedata[SWTPM_LOCALCA_CONF] = g_strdup_printf(
        "statedir = %s\n"
        "signingkey = %s\n"
        "issuercert = %s\n"
        "certserial = %s\n",
        swtpm_localca_dir,
        signkey,
        issuercert,
        certserial
    );

    /* swtpm-localca.options */
    if (uname(&utsname) < 0) {
        fprintf(stderr, "uname failed: %s\n", strerror(errno));
        goto error;
    }

    platform_manufacturer = str_replace(utsname.sysname, " ", "_");
    platform_version = str_replace(utsname.version, " ", "_");
    platform_model = str_replace(utsname.sysname, " ", "_");

    filedata[SWTPM_LOCALCA_OPTIONS] = g_strdup_printf(
        "--platform-manufacturer %s\n"
        "--platform-version %s\n"
        "--platform-model %s\n",
        platform_manufacturer,
        platform_version,
        platform_model
    );

    for (i = 0; i < NUM_FILES; i++) {
        fprintf(stdout, "Writing %s.\n", configfiles[i]);
        if (!g_file_set_contents(configfiles[i], filedata[i], -1, &error)) {
            fprintf(stderr,
                    "Could not write to %s: %s\n",
                    configfiles[i], strerror(errno));
            delete_files = TRUE;
            goto error;
        }
    }

    ret = 0;

error:
    if (delete_files) {
        for (i = 0; i < NUM_FILES; i++)
            unlink(configfiles[i]);
    }

out:
    return ret;
}
