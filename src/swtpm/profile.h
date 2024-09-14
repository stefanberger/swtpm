/* SPDX-License-Identifier: BSD-3-Clause */

/*
 * profile.h: Header for profile.c
 *
 * Author: Stefan Berger, stefanb@linux.ibm.com
 *
 * Copyright (c) IBM Corporation, 2024
 */

#ifndef _SWTPM_PROFILE_H_
#define _SWTPM_PROFILE_H_

#include <glib.h>

int profile_remove_fips_disabled_algorithms(char **json_profile,
                                            gboolean check);

#endif /* _SWTPM_PROFILE_H_ */
