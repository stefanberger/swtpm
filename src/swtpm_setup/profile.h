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

int check_json_profile(const gchar *swtpm_capabilities_json, const char *json_profile);

#endif /* SWTPM_SETUP_PROFILE_H */
