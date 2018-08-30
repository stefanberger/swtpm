/*
 * tlc.v -- tag-length-value
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

#include "config.h"

#include "tlv.h"
#include "logging.h"
#include "sys_dependencies.h"

#include <string.h>

#include <libtpms/tpm_library.h>
#include <libtpms/tpm_memory.h>
#include <libtpms/tpm_error.h>

void
tlv_data_free(tlv_data *td, size_t td_len)
{
    size_t i;

    for (i = 0; i < td_len; i++) {
        if (!td[i].is_const_ptr)
            free(td[i].u.ptr);
        memset(&td[i], 0, sizeof(*td));
    }
}

/*
 * tlv_data_append: append data in tlv_data array to a buffer
 * @buffer: pointer to a pointer to a buffer or NULL if new buffer
 * @buffer_len: length of existing buffer; will hold size of new buffer on return
 * @td: array of tlv_data
 * @td_len: length of td array
 */
TPM_RESULT
tlv_data_append(unsigned char **buffer, uint32_t *buffer_len,
                tlv_data *td, size_t td_len)
{
    size_t i;
    tlv_header tlv;
    uint32_t totlen;
    size_t addlen = 0;
    unsigned char *ptr;
    unsigned char *tmp;

    for (i = 0; i < td_len; i++)
        addlen += sizeof(tlv) + td[i].tlv.length;

    if (*buffer)
        totlen = *buffer_len + addlen;
    else
        totlen = addlen;

    tmp = realloc(*buffer, totlen);
    if (!tmp) {
         logprintf(STDERR_FILENO, "Could not allocate %u bytes.\n", totlen);
         return TPM_FAIL;
    }
    *buffer = tmp;

    ptr = *buffer + *buffer_len;
    *buffer_len = totlen;

    for (i = 0; i < td_len; i++) {
        tlv.tag = htobe16(td[i].tlv.tag);
        tlv.length = htobe32(td[i].tlv.length);

        memcpy(ptr, &tlv, sizeof(tlv));
        ptr += sizeof(tlv);

        if (td[i].is_const_ptr)
            memcpy(ptr, td[i].u.const_ptr, td[i].tlv.length);
        else
            memcpy(ptr, td[i].u.ptr, td[i].tlv.length);
        ptr += td[i].tlv.length;
    }

    return 0;
}

/* tlv_data_find_tag: in a byte stream that starts with a tlv_header,
                      find a tlv_header with a given tag
 * @buffer: the buffer to search; must start with a tlv_header
 * @buffer_len: the length of the buffer
 * @tag: the tag to search for
 * @td: tlv_data pointer to receive the result in,
 *
 * Returns NULL if nothing was found, the pointer to the data corresponding
 * to the tag otherwise.
 */
const unsigned char *
tlv_data_find_tag(const unsigned char *buffer, uint32_t buffer_len,
                  uint16_t tag, tlv_data *td)
{
    uint32_t offset = 0;

    while (offset < buffer_len) {
        if (offset + sizeof(td->tlv) > buffer_len)
            return NULL;

        memcpy(&td->tlv, buffer + offset, sizeof(td->tlv));
        offset += sizeof(td->tlv);

        td->tlv.length = be32toh(td->tlv.length);
        if (offset + td->tlv.length > buffer_len)
            return NULL;

        td->tlv.tag = be16toh(td->tlv.tag);
        if (td->tlv.tag == tag) {
            td->is_const_ptr = true;
            td->u.const_ptr = &buffer[offset];
            return buffer;
        }
        offset += td->tlv.length;
    }
    return NULL;
}

