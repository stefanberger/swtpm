/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * swtpm_setup_utils.h: Header for swtpm_setup_utils.c
 *
 * Author: Stefan Berger, stefanb@linux.ibm.com
 *
 * Copyright (c) IBM Corporation, 2021
 */

#ifndef SWTPM_SETUP_UTILS_H
#define SWTPM_SETUP_UTILS_H

#include <glib.h>

gchar *get_config_value(gchar **config_file_lines, const gchar *configname);
int create_config_files(gboolean overwrite, gboolean root_flag,
                        gboolean skip_if_exist);

#endif /* SWPTM_SETUP_UTILS_H */
