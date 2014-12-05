/*
 * key.c -- Common key handling code for swtpm and swtpm_cuse
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

#include "config.h"

#include <blapi.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "key.h"


enum key_format
key_format_from_string(const char *format)
{
    if (!strcmp(format, "hex")) {
        return KEY_FORMAT_HEX;
    } else if (!strcmp(format, "binary")) {
        return KEY_FORMAT_BINARY;
    }
    fprintf(stderr, "Unknown key format '%s'.\n", format);

    return KEY_FORMAT_UNKNOWN;
}

enum encryption_mode
encryption_mode_from_string(const char *mode)
{
    if (!strcmp(mode, "aes-cbc")) {
        return ENCRYPTION_MODE_AES_CBC;
    }

    return ENCRYPTION_MODE_UNKNOWN;
}

static ssize_t
key_stream_to_bin(const char *input, unsigned char *bin, size_t bin_size)
{
    ssize_t digits = 0;
    int n, num;

    while (input[digits] &&
           !isspace(input[digits]) &&
           bin_size > (size_t)digits / 2) {
        num = sscanf(&input[digits], "%2hhx%n", &bin[digits/2], &n);
        if (num != 1 || n != 2)
            return -1;
        digits += 2;
    }

    if (input[digits] && !isspace(input[digits]))
        return -1;

    return (digits != 0) ? digits : -1;
}

static int
key_parse_as_hexkey(const char *rawkey,
                    unsigned char *key, size_t *keylen, size_t maxkeylen)
{
    ssize_t digits;
    off_t offset = 0;

    if (!strncmp(rawkey, "0x", 2))
        offset = 2;

    digits = key_stream_to_bin(&rawkey[offset], key, maxkeylen);
    if (digits < 0) {
        fprintf(stderr, "Could not parse key hex string into %zu byte buffer.\n",
                maxkeylen);
        return -1;
    } else if (digits == 128/4) {
        *keylen = 128/8;
    } else {
        fprintf(stderr, "Unsupported key length with %zu digits.\n",
                digits);
        return -1;
    }

    return 0;
}

int
key_load_key(const char *filename, enum key_format keyformat,
             unsigned char *key, size_t *keylen, size_t maxkeylen)
{
    int ret = -1;
    int fd;
    char filebuffer[2 + 128/4 + 1 + 1];
    size_t len;

    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Unable to open file %s: %s\n",
                filename, strerror(errno));
        return -1;
    }
    len = read(fd, filebuffer, sizeof(filebuffer) - 1);
    close(fd);
    if (len < 0) {
        fprintf(stderr, "Unable to read key: %s\n",
                strerror(errno));
        return -1;
    }
    filebuffer[len] = 0;

    switch (keyformat) {
    case KEY_FORMAT_BINARY:
        *keylen = len;
        if (maxkeylen < len) {
            fprintf(stderr, "Key is larger than buffer (%zu > %zu).\n",
                    len, maxkeylen);
            return -1;
        }
        memcpy(key, filebuffer, len);
        ret = 0;
        break;
    case KEY_FORMAT_HEX:
        if (key_parse_as_hexkey(filebuffer, key, keylen, maxkeylen) < 0)
            return -1;
        ret = 0;
        break;
    case KEY_FORMAT_UNKNOWN:
        break;
    }

    return ret;
}

int
key_from_pwdfile(const char *filename, unsigned char *key, size_t *keylen,
                 size_t maxkeylen)
{
    unsigned char filebuffer[32];
    int fd;
    size_t len;
    unsigned char hashbuf[SHA512_BLOCK_LENGTH];

    if (maxkeylen > sizeof(hashbuf)) {
        fprintf(stderr, "Request keylength is too big (%zu > %zu)\n",
                maxkeylen, sizeof(hashbuf));
        return -1;
    }

    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Unable to open file %s : %s\n",
                filename, strerror(errno));
        return -1;
    }
    len = read(fd, filebuffer, sizeof(filebuffer));
    close(fd);

    if (len < 0) {
        fprintf(stderr, "Unable to read passphrase: %s\n",
                strerror(errno));
        return -1;
    }

    if (SHA512_HashBuf(hashbuf, filebuffer, len) != SECSuccess) {
        fprintf(stderr, "Could not hash the passphrase");
        return -1;
    }

    *keylen = maxkeylen;
    memcpy(key, hashbuf, *keylen);

    return 0;
}

