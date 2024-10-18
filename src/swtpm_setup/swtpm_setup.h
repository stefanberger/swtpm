/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * swtpm_setup.h: Header for swtpm_setup.c
 *
 * Author: Stefan Berger, stefanb@linux.ibm.com
 *
 * Copyright (c) IBM Corporation, 2021
 */

#ifndef SWTPM_SETUP_H
#define SWTPM_SETUP_H

#include <glib.h>

extern gchar *gl_LOGFILE;

#define TPM_CAP_TPM_PROPERTIES 6
#define TPM_PT_MANUFACTURER 0x105

#endif /* SWTPM_SETUP_H */
