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

#ifndef __clang__
# define SWTPM_ATTRIBUTE_FORMAT(STRING_IDX, FIRST_TO_CHECK) \
  __attribute__((format (printf, STRING_IDX, FIRST_TO_CHECK)))
#else
# define SWTPM_ATTRIBUTE_FORMAT(STRING_IDX, FIRST_TO_CHECK) \
  __attribute__((__format__ (__printf__, STRING_IDX, FIRST_TO_CHECK)))
#endif

#ifdef __GNUC__ /* gcc and clang */
# define SWTPM_ATTR_UNUSED __attribute__((unused))
#endif

#endif /* _SWTPM_COMPILER_DEPENDENCIES_H */
