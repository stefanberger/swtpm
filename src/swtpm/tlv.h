/*
 * tlv.h -- tag-length-value
 *
 * (c) Copyright IBM Corporation 2018.
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

#ifndef _SWTPM_TLV_H_
#define _SWTPM_TLV_H_

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

#include <libtpms/tpm_types.h>

typedef struct tlv_header {
    uint16_t tag;
    uint32_t length; /* length of the data to follow excluding this header */
    /* uint8_t data[0]; */
} __attribute((packed)) tlv_header;

#define TAG_DATA                     1
#define TAG_ENCRYPTED_DATA           2
#define TAG_HMAC                     3
#define TAG_MIGRATION_DATA           4
#define TAG_ENCRYPTED_MIGRATION_DATA 5
#define TAG_IVEC_ENCRYPTED_DATA      6
#define TAG_IVEC_ENCRYPTED_MIGRATION_DATA  7

typedef struct tlv_data {
    struct tlv_header tlv;
    bool is_const_ptr;
    union {
        uint8_t *ptr;
        const uint8_t *const_ptr;
    } u;
} tlv_data;

#define _TLV_DATA(TAG, LENGTH, IS_CONST_PTR, PTR_FIELD) \
    (tlv_data) { \
        .tlv.tag = TAG, \
        .tlv.length = LENGTH, \
        .is_const_ptr = IS_CONST_PTR, \
        PTR_FIELD, \
    }

#define TLV_DATA(TAG, LENGTH, PTR)       _TLV_DATA(TAG, LENGTH, false,\
                                                   .u.ptr = PTR)
#define TLV_DATA_CONST(TAG, LENGTH, PTR) _TLV_DATA(TAG, LENGTH, true ,\
                                                   .u.const_ptr = PTR)

void tlv_data_free(tlv_data *td, size_t td_len);

TPM_RESULT tlv_data_append(unsigned char **buffer, uint32_t *buffer_len,
                           tlv_data *td, size_t td_len);

const unsigned char *tlv_data_find_tag(const unsigned char *buffer,
                                       uint32_t buffer_len,
                                       uint16_t tag, tlv_data *td);

#endif /* _SWTPM_TLV_H_ */
