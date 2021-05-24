/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * swtpm_localca_utils.h: Header file for swtpm_localca_utils.c
 *
 * Author: Stefan Berger, stefanb@linux.ibm.com
 *
 * Copyright (c) IBM Corporation, 2021
 */

#ifndef SWTPM_LOCALCA_UTILS_H
#define SWTPM_LOCALCA_UTILS_H

#include <glib.h>

gchar *get_config_value(gchar **config_file_lines, const gchar *varname, const gchar *fallback);
int get_config_envvars(gchar **config_file_lines, gchar  ***env);

int makedir(const char *dirname, const char *purpose);

int lock_file(const gchar *lockfile);
void unlock_file(int lockfd);

#endif /* SWTPM_LOCALCA_UTILS_H */
