/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * profile.h: TPM 2 profile handling
 *
 * Author: Stefan Berger, stefanb@linux.ibm.com
 *
 * Copyright (c) IBM Corporation, 2022
 */

#ifndef SWTPM_SETUP_PROFILE_H
#define SWTPM_SETUP_PROFILE_H

#include <glib.h>

int get_profile_names(const gchar *swtpm_capabilities_json, gchar ***profile_names);
int check_json_profile(const gchar *swtpm_capabilities_json, const char *json_profile);

int profile_name_check(const gchar *profile_name);
int profile_get_by_name(gchar *const *config_file_lines,
                        const gchar *json_profile_name,
                        gchar **json_profile_file,
                        gchar **json_profile);

int profile_printall(const gchar **swtpm_prg_l,
                     gchar *const *config_file_lines);

#endif /* SWTPM_SETUP_PROFILE_H */
