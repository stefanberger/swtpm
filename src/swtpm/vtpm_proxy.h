/*
 * vtpm_proxy.h -- The Linux VTPM proxy device
 *
 * (c) Copyright IBM Corporation 2017
 *
 * Author: Stefan Berger <stefanb@us.ibm.com>
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
#ifndef _SWTPM_VTPM_PROXY_H_
#define _SWTPM_VTPM_PROXY_H_

#include <linux/ioctl.h>

struct vtpm_proxy_new_dev {
    uint32_t flags;    /* in */
    uint32_t tpm_num;  /* out */
    uint32_t fd;       /* out */
    uint32_t major;    /* out */
    uint32_t minor;    /* out */
};

#define VTPM_PROXY_FLAG_TPM2   1

/* vendor specific commands to set locality */
#define TPM2_CC_SET_LOCALITY 0x20001000
#define TPM_CC_SET_LOCALITY  0x20001000

#define VTPM_PROXY_IOC_NEW_DEV _IOWR(0xa1, 0x00, struct vtpm_proxy_new_dev)

#endif /* _SWTPM_VTPM_PROXY_H_ */
