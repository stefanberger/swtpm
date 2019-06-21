/*
 * key.h -- Header file for key handling functions for swtpm and swtpm_cuse
 *
 * (c) Copyright IBM Corporation 2014.
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

#ifndef _SWTPM_KEY_H
#define _SWTPM_KEY_H

enum key_format {
    KEY_FORMAT_UNKNOWN = 0,
    KEY_FORMAT_BINARY = 1,
    KEY_FORMAT_HEX = 2,
};

enum encryption_mode {
    ENCRYPTION_MODE_UNKNOWN = 0,
    ENCRYPTION_MODE_AES_CBC = 1,
};

enum kdf_identifier {
    KDF_IDENTIFIER_UNKNOWN = 0,
    KDF_IDENTIFIER_SHA512 = 1,
    KDF_IDENTIFIER_PBKDF2 = 2,
};

enum key_format key_format_from_string(const char *format);
enum encryption_mode encryption_mode_from_string(const char *mode,
                                                 size_t *keylen);
enum kdf_identifier kdf_identifier_from_string(const char *kdf);
int key_load_key(const char *filename, enum key_format keyformat,
                 unsigned char *key, size_t *keylen, size_t maxkeylen);
int key_load_key_fd(int fd, enum key_format keyformat,
                    unsigned char *key, size_t *keylen, size_t maxkeylen);
int key_from_pwdfile(const char *pwdfile, unsigned char *key, size_t *keylen,
                     size_t maxkeylen, enum kdf_identifier kdfid);
int key_from_pwdfile_fd(int pwdfile_fd, unsigned char *key, size_t *keylen,
                        size_t maxkeylen, enum kdf_identifier kdfid);

#endif /* _SWTPM_KEY_H */

