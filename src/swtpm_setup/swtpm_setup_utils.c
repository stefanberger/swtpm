/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * swtpm_setup_utils.c: Utility functions for swtpm_setup
 *
 * Author: Stefan Berger, stefanb@linux.ibm.com
 *
 * Copyright (c) IBM Corporation, 2021
 */

#include "config.h"

#include <regex.h>

#include <glib.h>

#include "swtpm_setup_utils.h"
#include "swtpm_utils.h"

/* Get a configuration value given its name */
gchar *get_config_value(gchar **config_file_lines, const gchar *configname)
{
    g_autofree gchar *regex = g_strdup_printf("^%s\\s*=\\s*([^#\n]*).*", configname);
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
