/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * compiler_dependencies.h: Compiler-dependent defines etc.
 *
 * Author: Stefan Berger, stefanb@linux.ibm.com
 *
 * Copyright (c) IBM Corporation, 2021
 */

#ifndef _SWTPM_COMPILER_DEPENDENCIES_H
#define _SWTPM_COMPILER_DEPENDENCIES_H

#ifdef __GNUC__ /* gcc and clang */
# define SWTPM_ATTR_UNUSED __attribute__((unused))
#endif

#endif /* _SWTPM_COMPILER_DEPENDENCIES_H */
