/*
 * key.c -- Common key handling code for swtpm and swtpm_cuse
 *
 * (c) Copyright IBM Corporation 2014, 2015.
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

#ifdef USE_FREEBL_CRYPTO_LIBRARY
# include <blapi.h>
#else
# ifdef USE_OPENSSL_CRYPTO_LIBRARY
#  include <openssl/sha.h>
# else
#  error "Unsupported crypto library."
# endif
#endif

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "key.h"


/*
 * key_format_from_string:
 * Convert the string into a key format identifier
 * @format: either 'hex' or 'binary'
 *
 * Returns a key format identifier
 */
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

/*
 * encryption_mode_from_string:
 * Convert the string into a encryption mode identifier
 * @mode: string describing encryption mode
 *
 * Returns an encryption mode identifier
 */
enum encryption_mode
encryption_mode_from_string(const char *mode)
{
    if (!strcmp(mode, "aes-cbc")) {
        return ENCRYPTION_MODE_AES_CBC;
    }

    return ENCRYPTION_MODE_UNKNOWN;
}

/*
 * key_stream_to_bin
 * Convert a stream of ASCII hex digits into a key; convert a maximum of
 * bin_size bytes;
 *
 * @input: input data holding hex digits
 * @bin: output field of bin_size
 * @bin_size: max. number of bytes to convert
 *
 * Returns the number of digits that were converted.
 */
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

/*
 * key_parse_as_hexkey:
 * Parse the raw key data as a key in ASCII hex format; they key may
 * have a leading '0x'.
 * @rawkey: ASCII data for a hex key with possible leading '0x'
 * @key: buffer for key
 * @keylen: actual key len returned by this function
 * @maxkeylen: the max. size of the key; this is equivalent to the size of
 *             the key buffer
 * Returns 0 on success, -1 on failure
 */
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

/*
 * key_load_key:
 * Load the raw key data from a file and convert it to a key.
 * @filename: file holding the raw key data
 * @keyformat: the format the raw key data are in; may either indicate
 *             binary data or hex string
 * @key: the buffer for holding the converted key
 * @keylen: the actual key len of the converted key returned by this
 *          function
 * @maxkeylen: the max. size of the key; corresponds to the size of the
 *             key buffer
 */
int
key_load_key(const char *filename, enum key_format keyformat,
             unsigned char *key, size_t *keylen, size_t maxkeylen)
{
    int ret = -1;
    int fd;
    char filebuffer[2 + 128/4 + 1 + 1];
    ssize_t len;

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
        if (maxkeylen < (size_t)len) {
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

/*
 * key_from_pwdfile:
 * Read the key from the given password file, convert the password into
 * a key by applying a SHA512 on the password and use the first bytes
 * of the hash as the key.
 * @filename: name of the file holding the password
 * @key: the buffer for holding the key
 * @keylen: the actual number of bytes used in the buffer
 * @keylen: the actual key len of the converted key returned by this
 *          function
 * @maxkeylen: the max. size of the key; corresponds to the size of the
 *             key buffer
 */
int
key_from_pwdfile(const char *filename, unsigned char *key, size_t *keylen,
                 size_t maxkeylen)
{
    unsigned char filebuffer[32];
    int fd;
    ssize_t len;
#ifdef USE_FREEBL_CRYPTO_LIBRARY
    unsigned char hashbuf[SHA512_BLOCK_LENGTH];
#else
    unsigned char hashbuf[SHA512_DIGEST_LENGTH];
#endif

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

#ifdef USE_FREEBL_CRYPTO_LIBRARY
    if (SHA512_HashBuf(hashbuf, filebuffer, len) != SECSuccess) {
        fprintf(stderr, "Could not hash the passphrase");
        return -1;
    }
#else
    SHA512(filebuffer, len, hashbuf);
#endif

    *keylen = maxkeylen;
    memcpy(key, hashbuf, *keylen);

    return 0;
}
