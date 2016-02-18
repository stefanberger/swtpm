/*
 * tpm_bios.  --  Header file for tpm_bios.c
 *
 * Authors: Stefan Berger <stefanb@us.ibm.com>
 *
 * (c) Copyright IBM Corporation 2016.
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * Neither the names of the IBM Corporation nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _SWTPM_BIOS_H
#define _SWTPM_BIOS_H

#include <stdint.h>

/* constants for TPM 1.2 */

#define TPM_TAG_RQU_COMMAND  0x00c1

#define TPM_ST_CLEAR         0x0001
#define TPM_ST_STATE         0x0002
#define TPM_ST_DEACTIVATED   0x0003

#define TPM_ORD_ContinueSelfTest        0x00000053
#define TPM_ORD_GetCapability           0x00000065
#define TPM_ORD_PhysicalEnable          0x0000006f
#define TPM_ORD_PhysicalDisable         0x00000070
#define TPM_ORD_PhysicalSetDeactivated  0x00000072
#define TPM_ORD_Startup                 0x00000099
#define TPM_ORD_PhysicalPresence        0x4000000a

#define TPM_PHYSICAL_PRESENCE_PRESENT      0x0008
#define TPM_PHYSICAL_PRESENCE_LOCK         0x0004
#define TPM_PHYSICAL_PRESENCE_NOTPRESENT   0x0010
#define TPM_PHYSICAL_PRESENCE_CMD_ENABLE   0x0020

#define TPM_CAP_FLAG                    0x00000004
#define TPM_CAP_FLAG_PERMANENT          0x00000108

#define TPM_PERM_FLAG_DEACTIVATED_IDX   2

/* data structures for TPM 1.2 */

struct tpm_header {
	uint16_t tag;
	uint32_t length;
	uint32_t ordinal;
} __attribute__((packed));

struct tpm_resp_header {
	uint16_t tag;
	uint32_t length;
	uint32_t result;
} __attribute__((packed));

struct tpm_startup {
	struct tpm_header hdr;
	uint16_t startup_type;
} __attribute__((packed));

struct tsc_physical_presence {
	struct tpm_header hdr;
	uint16_t physical_presence;
} __attribute__((packed));

struct tpm_physical_enable {
	struct tpm_header hdr;
} __attribute__((packed));

struct tpm_physical_set_deactivated {
	struct tpm_header hdr;
	uint8_t state;
} __attribute__((packed));

struct tpm_continue_selftest {
	struct tpm_header hdr;
} __attribute__((packed));

struct tpm_get_capability_subcap {
	struct tpm_header hdr;
	uint32_t cap;
	uint32_t subcap_size;
	uint32_t subcap;
} __attribute__((packed));

struct tpm_get_capability_permflags_res {
	struct tpm_resp_header hdr;
	uint32_t size;
	uint16_t tag;
	uint8_t flags[20];
} __attribute__((packed));

#endif /* _SWTPM_BIOS_H */
