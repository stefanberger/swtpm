// SPDX-License-Identifier: BSD-3-Clause

#ifndef SWTPM_ARCH_SPECIFICS_H
#define SWTPM_ARCH_SPECIFICS_H

#if defined (__m68k__)

/* Very slow processing on QEMU; apply a factor of '10' */
# define ARCH_PROCESSING_DELAY_FACTOR 10

#endif

#ifndef ARCH_PROCESSING_DELAY_FACTOR
# define ARCH_PROCESSING_DELAY_FACTOR 1
#endif

#endif /* SWTPM_ARCH_SPECIFICS_H */
