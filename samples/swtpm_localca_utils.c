/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * swtpm_localca_utils.c: Utility functions
 *
 * Author: Stefan Berger, stefanb@linux.ibm.com
 *
 * Copyright (c) IBM Corporation, 2021
 */

#include "config.h"

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <regex.h>
#include <errno.h>
#include <sys/file.h>

#include "swtpm_utils.h"
#include "swtpm_localca.h"
#include "swtpm_localca_utils.h"

/* Create a directory pat (and all its predecessors) if it doesn't exist */
int makedir(const char *dirname, const char *purpose)
{
    struct stat statbuf;

    if (stat(dirname, &statbuf) != 0) {
        logit(gl_LOGFILE, "Creating swtpm-localca dir '%s'.\n", dirname);
        if (g_mkdir_with_parents(dirname, S_IRWXU | S_IRWXG | S_IXGRP | S_IRGRP) == -1) {
            logerr(gl_LOGFILE, "Could not create directory for '%s': %s\n",
                   purpose, strerror(errno));
            return 1;
        }
    }
    return 0;
}

/* Get a configuration value given its name */
gchar *get_config_value(gchar **config_file_lines, const gchar *configname, const gchar *fallback)
{
    g_autofree gchar *regex = g_strdup_printf("^%s[[:space:]]*=[[:space:]]*([^#\n]*).*", configname);
    gchar *result = NULL;
    regex_t preg;
    size_t idx;
    regmatch_t pmatch[2];

    if (regcomp(&preg, regex, REG_EXTENDED) != 0) {
        logerr(gl_LOGFILE, "Internal error: Could not compile regex\n");
        goto error;
    }

    for (idx = 0; config_file_lines[idx] != NULL; idx++) {
        const gchar *line = config_file_lines[idx];
        if (regexec(&preg, line, 2, pmatch, 0) == 0) {
            result = g_strndup(&line[pmatch[1].rm_so],
                               pmatch[1].rm_eo - pmatch[1].rm_so);
            /* coverity: g_strchmop modifies in-place */
            result = g_strchomp(result);
            break;
        }
    }
    regfree(&preg);

error:
    if (result == NULL)
        result = g_strdup(fallback);
    //printf("Found match for %s: |%s|\n", configname, result);

    return result;
}

/* Extract all environment variables from the config file and add them to
 * the given environent.
 * Environment variable lines must start with 'env:' and must not contain
 * trailing spaces or a comment starting with '#'
 */
int get_config_envvars(gchar **config_file_lines, gchar ***env)
{
    const char *regex = "^env:([a-zA-Z_][a-zA-Z_0-9]*)[[:space:]]*=[[:space:]]*([^\n]*)";
    regex_t preg;
    size_t idx;
    regmatch_t pmatch[3];

    if (regcomp(&preg, regex, REG_EXTENDED) != 0) {
        logerr(gl_LOGFILE, "Internal error: Could not compile regex\n");
        return 1;
    }

    for (idx = 0; config_file_lines[idx] != NULL; idx++) {
        const gchar *line = config_file_lines[idx];
        if (regexec(&preg, line, 3, pmatch, 0) == 0) {
            g_autofree gchar *key = NULL, *value = NULL;

            key = g_strndup(&line[pmatch[1].rm_so],
                            pmatch[1].rm_eo - pmatch[1].rm_so);
            value = g_strndup(&line[pmatch[2].rm_so],
                              pmatch[2].rm_eo - pmatch[2].rm_so);
            *env = g_environ_setenv(*env, key, value, TRUE);
        }
    }

    regfree(&preg);

    return 0;
}

/* flock a file; the file descriptor for the file to unlock later on is returned */
int lock_file(const gchar *lockfile)
{
    int lockfd;
    mode_t mode = S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH;

    lockfd = open(lockfile, O_RDWR | O_CREAT, mode);
    if (lockfd < 0) {
        logerr(gl_LOGFILE, "Could not open lockfile %s: %s\n", lockfile, strerror(errno));
        return -1;
    }

    if (flock(lockfd, LOCK_EX) < 0) {
        logerr(gl_LOGFILE, "Could not lock file %s: %s\n", lockfile, strerror(errno));
        close(lockfd);
        return -1;
    }
    return lockfd;
}

/* unlock a file previously locked using lock_file */
void unlock_file(int lockfd) {
    if (lockfd >= 0) {
        flock(lockfd, LOCK_UN);
        close(lockfd);
    }
}
