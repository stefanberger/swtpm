/*
 * check_algos.c -- Check availability of OpenSSL crypto algorithms
 *
 * (c) Copyright IBM Corporation 2024.
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

#include <string.h>

#include "check_algos.h"
#include "utils.h"
#include "swtpm_utils.h"
#include "logging.h"
#include "compiler_dependencies.h"

#include <openssl/rsa.h>
#include <openssl/evp.h>

#define MAX_RSA_KEYSIZE 2048

static const unsigned char rsa2048_der[] = {
  0x30, 0x82, 0x04, 0xbd, 0x02, 0x01, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a,
  0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x04, 0x82,
  0x04, 0xa7, 0x30, 0x82, 0x04, 0xa3, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01,
  0x01, 0x00, 0xa8, 0xe1, 0x43, 0x8e, 0xd8, 0x75, 0x71, 0x30, 0x94, 0xb4,
  0xf0, 0x42, 0x12, 0x43, 0x5a, 0xc6, 0xb3, 0x17, 0xff, 0x30, 0x29, 0x34,
  0xf1, 0x39, 0x24, 0x2b, 0xae, 0x60, 0xf8, 0x1f, 0xb3, 0x29, 0xc1, 0xf7,
  0x7a, 0x07, 0xbc, 0x0a, 0x97, 0x23, 0x34, 0x05, 0x20, 0xb8, 0xd4, 0xba,
  0x18, 0xf6, 0xa7, 0xe7, 0x6c, 0x5a, 0x75, 0xae, 0xe8, 0xd7, 0xb9, 0xc5,
  0x5b, 0x64, 0xd7, 0xcf, 0xd7, 0x29, 0x63, 0x5e, 0x00, 0x65, 0x1d, 0xe4,
  0x73, 0x7a, 0x18, 0x25, 0x05, 0x41, 0x09, 0x32, 0xfe, 0xc8, 0xc6, 0x2c,
  0x1b, 0x58, 0x43, 0x80, 0xbb, 0xeb, 0xfd, 0xf7, 0x26, 0x21, 0xa3, 0x2d,
  0xee, 0xdd, 0x73, 0xd6, 0x3a, 0xad, 0xd8, 0x71, 0x70, 0x58, 0xc0, 0x19,
  0x82, 0xec, 0xd8, 0x4e, 0xe0, 0xfb, 0x14, 0xa5, 0x0a, 0xb9, 0x23, 0x07,
  0x1d, 0x90, 0xae, 0xcd, 0x67, 0x54, 0x0b, 0x2c, 0x40, 0xac, 0xf9, 0x1e,
  0x28, 0x15, 0x21, 0x2c, 0xc3, 0x52, 0x44, 0xad, 0xac, 0x3f, 0xe4, 0xc5,
  0x8c, 0xdc, 0xd6, 0xfe, 0x40, 0xb3, 0x0c, 0x40, 0x96, 0xb2, 0x12, 0xbf,
  0x51, 0xea, 0xd2, 0x0b, 0x60, 0x5a, 0x17, 0x0f, 0x22, 0x7e, 0xb4, 0x83,
  0x19, 0x1e, 0xd5, 0xf3, 0xf1, 0xbb, 0xdc, 0x3b, 0x61, 0xa2, 0xd9, 0x6e,
  0x52, 0x9b, 0xe4, 0x24, 0xda, 0xe2, 0x55, 0xfa, 0x09, 0xe8, 0x9b, 0xf2,
  0x3e, 0x14, 0x89, 0xe7, 0x2e, 0xca, 0x91, 0xb8, 0x51, 0xe2, 0xa5, 0x73,
  0x26, 0x91, 0x15, 0x63, 0xe0, 0x5a, 0x8b, 0xe0, 0xda, 0x51, 0x6d, 0xe7,
  0x1f, 0xbd, 0x60, 0x16, 0x1a, 0xa5, 0x86, 0x23, 0xd7, 0x7a, 0xcd, 0xd1,
  0x09, 0xc4, 0x3f, 0x2b, 0xf1, 0x6b, 0x44, 0x15, 0xa8, 0x6b, 0xc8, 0xe4,
  0x84, 0xe8, 0x03, 0x80, 0xf5, 0x76, 0x2e, 0x47, 0x9e, 0xa5, 0xeb, 0xe1,
  0x21, 0x34, 0x7d, 0x41, 0x6b, 0x19, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02,
  0x82, 0x01, 0x00, 0x05, 0x69, 0x7c, 0xad, 0x03, 0xfe, 0x55, 0x83, 0x89,
  0x4c, 0x78, 0x23, 0xa1, 0xea, 0xb3, 0x2a, 0xc9, 0x7c, 0x04, 0x23, 0x52,
  0xba, 0xbd, 0xdd, 0x47, 0x2d, 0xb8, 0x2f, 0xa6, 0xdb, 0xfb, 0x35, 0xa4,
  0x1f, 0xee, 0x72, 0xf7, 0x81, 0x7e, 0x60, 0xf4, 0x2e, 0x92, 0xe3, 0x21,
  0x7c, 0x1a, 0x47, 0x33, 0x4f, 0xcd, 0x0e, 0xe4, 0x15, 0x18, 0x24, 0xab,
  0xb1, 0x29, 0xb1, 0xe4, 0x61, 0xa6, 0x83, 0x4e, 0xca, 0x29, 0x28, 0x94,
  0x69, 0xe9, 0x12, 0x79, 0x5a, 0x1c, 0x5e, 0x3e, 0x71, 0x7a, 0x2d, 0x4c,
  0x7e, 0x86, 0xdc, 0xd0, 0x02, 0xfc, 0xe2, 0xbd, 0xf7, 0x90, 0xeb, 0x04,
  0x8b, 0xf9, 0x0a, 0xf3, 0x46, 0xa3, 0x08, 0x45, 0xb6, 0xb2, 0xf3, 0x41,
  0x2a, 0xc0, 0x21, 0x9f, 0x77, 0xfd, 0xa9, 0x46, 0x3a, 0xd8, 0xca, 0x60,
  0x97, 0x3e, 0x89, 0x0f, 0xb5, 0x08, 0xf1, 0xee, 0x4e, 0xbb, 0x7e, 0xd2,
  0x44, 0x3b, 0x17, 0x42, 0x36, 0xb1, 0xe2, 0x50, 0xe1, 0x99, 0x12, 0xec,
  0xa5, 0x6e, 0x51, 0xd4, 0x0a, 0xb0, 0x27, 0xcd, 0x17, 0x76, 0xb2, 0x4e,
  0x11, 0x32, 0x58, 0x8e, 0xe9, 0x57, 0xe7, 0x0b, 0xa0, 0x0d, 0xd8, 0xf6,
  0xdf, 0x03, 0xec, 0xfa, 0xf3, 0x84, 0xa5, 0x78, 0x8b, 0x7f, 0x64, 0xf8,
  0xe9, 0xe0, 0x45, 0x9d, 0xe4, 0x69, 0xd5, 0x6c, 0x36, 0xa6, 0x91, 0x42,
  0x24, 0x97, 0x73, 0xc7, 0x25, 0x28, 0x12, 0xa8, 0x34, 0x3c, 0x32, 0xc1,
  0x13, 0xe2, 0xb9, 0xf1, 0x55, 0x64, 0xf0, 0xe3, 0xf3, 0xf7, 0x60, 0x4c,
  0xb7, 0x07, 0xef, 0xbf, 0x69, 0x7c, 0x44, 0x1c, 0xde, 0xf2, 0x91, 0xa7,
  0x4d, 0x5d, 0x83, 0x78, 0xc4, 0x57, 0xdb, 0xf1, 0x77, 0x0c, 0xcb, 0xb5,
  0xd8, 0x84, 0xfc, 0x10, 0x46, 0xcc, 0x2d, 0x44, 0xb9, 0xde, 0x01, 0x01,
  0x0a, 0x05, 0x2f, 0x11, 0x2d, 0xd7, 0x05, 0x02, 0x81, 0x81, 0x00, 0xd0,
  0xf5, 0x53, 0x16, 0x00, 0xa5, 0x37, 0xd0, 0x2b, 0x01, 0x83, 0x5b, 0xcc,
  0xe4, 0xcb, 0x9d, 0x1a, 0xee, 0xb4, 0xf1, 0xd9, 0x8b, 0x8b, 0x3e, 0xba,
  0xbb, 0x8d, 0xac, 0x98, 0xa1, 0x73, 0x5d, 0x34, 0x7f, 0x71, 0x29, 0xb5,
  0x3f, 0xd6, 0x3b, 0xe6, 0x22, 0x72, 0x22, 0x72, 0xf4, 0x54, 0x96, 0xfe,
  0xe4, 0x21, 0xdc, 0x63, 0x13, 0xe7, 0xdb, 0xb8, 0x19, 0xac, 0xe4, 0xfe,
  0xca, 0xed, 0xf2, 0x4e, 0xc2, 0x91, 0x87, 0x81, 0xa3, 0x36, 0xcb, 0xc5,
  0x63, 0xa5, 0xbc, 0x74, 0xf9, 0x37, 0xb9, 0x03, 0x46, 0xba, 0x27, 0xdd,
  0xbd, 0x4d, 0x23, 0xfb, 0xc3, 0x2b, 0xa5, 0x20, 0x95, 0x39, 0x25, 0x02,
  0xe6, 0x24, 0x7b, 0xaa, 0xa0, 0x24, 0x1e, 0xb1, 0x1b, 0xe2, 0x1e, 0xb7,
  0x37, 0x8e, 0xb5, 0x6d, 0xd4, 0x26, 0xf0, 0x32, 0x81, 0x37, 0xd5, 0x21,
  0x47, 0x3a, 0x8d, 0xf7, 0xde, 0xaf, 0x75, 0x02, 0x81, 0x81, 0x00, 0xce,
  0xe6, 0x25, 0x1c, 0x38, 0xc2, 0xc5, 0x8e, 0x9f, 0x65, 0x87, 0xa0, 0xa1,
  0x72, 0xdf, 0xfe, 0xa1, 0xb3, 0x30, 0xa4, 0x9d, 0x7b, 0x34, 0x01, 0xdc,
  0xc0, 0xc4, 0x9b, 0xae, 0xc6, 0x8d, 0xf5, 0x1c, 0x72, 0x71, 0x3e, 0xf8,
  0x22, 0x77, 0x92, 0xf6, 0x18, 0x8c, 0x6d, 0xf6, 0xea, 0xf8, 0x63, 0xba,
  0xbe, 0xb3, 0xd7, 0x86, 0xe9, 0xcb, 0x85, 0xdd, 0x47, 0xe7, 0xc4, 0x4b,
  0xf6, 0x64, 0x98, 0xc1, 0xe6, 0x93, 0x78, 0xf7, 0x2b, 0x45, 0x72, 0x90,
  0x63, 0x63, 0x3b, 0x6f, 0x0a, 0x5c, 0xc7, 0xd1, 0xef, 0xbe, 0x6f, 0x55,
  0x8e, 0x07, 0x48, 0x62, 0x40, 0xfe, 0x78, 0x3a, 0x85, 0xc2, 0x20, 0xc9,
  0x3d, 0x41, 0x45, 0x02, 0xe1, 0x1c, 0x18, 0xc3, 0x00, 0x53, 0x2c, 0xa8,
  0xd2, 0x6e, 0xe3, 0xa8, 0xcc, 0x59, 0xfc, 0xfd, 0x9e, 0x07, 0x25, 0xbe,
  0x60, 0xf3, 0x78, 0x01, 0x92, 0x9c, 0x95, 0x02, 0x81, 0x81, 0x00, 0x8c,
  0xe8, 0x82, 0x28, 0xda, 0x32, 0x8f, 0xda, 0x9e, 0xc5, 0x9c, 0x71, 0x31,
  0x50, 0x30, 0x46, 0x37, 0x3d, 0x35, 0x63, 0xc9, 0xd1, 0xa2, 0x0a, 0xa1,
  0x1d, 0x8c, 0xc2, 0x11, 0x02, 0xfe, 0xaa, 0xa1, 0x96, 0x37, 0x17, 0x6b,
  0x14, 0x2b, 0x41, 0xa5, 0x45, 0x21, 0x36, 0x3d, 0xd2, 0xa9, 0xa0, 0x51,
  0x2e, 0x41, 0xef, 0x3e, 0x18, 0xd4, 0x47, 0x84, 0x74, 0x3b, 0xf5, 0x08,
  0x24, 0x8c, 0x24, 0xd4, 0x1b, 0xbc, 0xcb, 0x66, 0x0e, 0x4c, 0x0b, 0x49,
  0x86, 0x92, 0xe2, 0xec, 0xf6, 0x8a, 0x2f, 0x07, 0x18, 0x90, 0xbc, 0x05,
  0x79, 0x7c, 0x25, 0x81, 0xc6, 0xf1, 0x0d, 0x9f, 0x55, 0x41, 0x7d, 0xc5,
  0xe0, 0xb0, 0x45, 0x7c, 0xa0, 0x14, 0xfb, 0x65, 0x6f, 0x6a, 0x22, 0x50,
  0x66, 0xf4, 0xa3, 0x3f, 0xf6, 0xca, 0x73, 0x3b, 0x7b, 0x8b, 0xcc, 0xfb,
  0x6d, 0xee, 0xfc, 0x81, 0x63, 0xf7, 0x69, 0x02, 0x81, 0x80, 0x41, 0xf2,
  0x37, 0x57, 0xe4, 0x7b, 0xa8, 0x6e, 0x8a, 0x3d, 0xd9, 0x5a, 0x08, 0xbb,
  0xcd, 0xcb, 0xa2, 0x8c, 0xb3, 0xef, 0x74, 0x46, 0xa5, 0xd0, 0x06, 0x25,
  0xe7, 0x44, 0xdc, 0x13, 0x6b, 0x81, 0xf9, 0xfc, 0x3c, 0x3e, 0x5e, 0xe6,
  0xd5, 0x88, 0x21, 0x2a, 0xb7, 0xf0, 0x00, 0xe8, 0xea, 0x1d, 0x17, 0x93,
  0xdb, 0x4c, 0xd2, 0x32, 0xc8, 0xed, 0x35, 0x17, 0xcb, 0x36, 0xd5, 0x23,
  0x86, 0xf2, 0xed, 0xb2, 0xe9, 0xc4, 0x7f, 0xbb, 0xea, 0x19, 0xd7, 0x0d,
  0xe6, 0xbe, 0x35, 0xe9, 0x6e, 0xa3, 0x3e, 0x36, 0x15, 0x53, 0xf5, 0x48,
  0x1c, 0xe8, 0x24, 0x71, 0x24, 0xea, 0xfb, 0x74, 0x50, 0xe9, 0x14, 0x5b,
  0x92, 0xe7, 0x45, 0x40, 0xad, 0x2c, 0xf3, 0x52, 0xb2, 0x30, 0x24, 0xeb,
  0x55, 0xee, 0xf8, 0x89, 0x92, 0x11, 0x42, 0x61, 0x51, 0x53, 0xe5, 0x77,
  0x8f, 0x82, 0xeb, 0xb5, 0x68, 0x75, 0x02, 0x81, 0x80, 0x11, 0xed, 0xeb,
  0x12, 0x3f, 0x64, 0x47, 0x62, 0xb2, 0x20, 0xb0, 0x10, 0x89, 0x97, 0xdc,
  0x48, 0x2a, 0xdf, 0xdd, 0x2b, 0x2a, 0x2c, 0xa3, 0x10, 0xf1, 0x4f, 0x4f,
  0xe2, 0x73, 0x16, 0x3a, 0x1d, 0x1e, 0x56, 0x74, 0xa5, 0xd4, 0x48, 0x0e,
  0xb2, 0x14, 0x68, 0xc5, 0xda, 0x7a, 0xe9, 0x76, 0x21, 0xe2, 0x50, 0x39,
  0x06, 0xd8, 0x35, 0x5b, 0x3b, 0x82, 0x9f, 0x84, 0x1e, 0xb9, 0x42, 0x01,
  0x1d, 0xd5, 0x33, 0x57, 0x7a, 0x3b, 0xe1, 0x63, 0xf6, 0x76, 0xfa, 0x93,
  0x99, 0x03, 0x57, 0xe4, 0x73, 0xc2, 0x8c, 0x55, 0x9e, 0x78, 0x4c, 0x4d,
  0xa4, 0xc0, 0xf6, 0xee, 0xad, 0x73, 0x43, 0x20, 0x89, 0x31, 0x34, 0xe4,
  0x8f, 0x97, 0xe6, 0xff, 0xbb, 0xf3, 0x3b, 0x19, 0x74, 0xf6, 0xf8, 0xf1,
  0x26, 0x57, 0xb6, 0x1e, 0xb4, 0x3a, 0xa7, 0x1f, 0xdd, 0x59, 0x05, 0x66,
  0x92, 0xa0, 0x80, 0xf1, 0x89
};

unsigned char rsa1024_der[] = {
  0x30, 0x82, 0x02, 0x76, 0x02, 0x01, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a,
  0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x04, 0x82,
  0x02, 0x60, 0x30, 0x82, 0x02, 0x5c, 0x02, 0x01, 0x00, 0x02, 0x81, 0x81,
  0x00, 0xae, 0xdd, 0xf4, 0x44, 0x9c, 0x38, 0x77, 0x9c, 0xda, 0x15, 0xcb,
  0x64, 0xba, 0x50, 0xe1, 0x40, 0xf9, 0x91, 0xf0, 0x52, 0x37, 0x24, 0xfd,
  0x5e, 0x7f, 0x29, 0x34, 0xd4, 0xb7, 0xdf, 0x18, 0xcb, 0x20, 0xc3, 0x81,
  0x2d, 0x66, 0xfd, 0x56, 0xcc, 0x7d, 0x7b, 0x5a, 0x95, 0xc4, 0x97, 0x20,
  0x81, 0x38, 0xd3, 0x90, 0x71, 0xc2, 0xdc, 0x02, 0x13, 0x36, 0xda, 0x2d,
  0x83, 0x1f, 0x5f, 0xd0, 0xb5, 0xab, 0x93, 0x21, 0xf7, 0xd9, 0x4b, 0xb5,
  0x3d, 0x51, 0x10, 0x94, 0x00, 0x53, 0xf2, 0x09, 0xf4, 0x2a, 0x6a, 0xe7,
  0x77, 0x7c, 0x10, 0x0f, 0x7c, 0x92, 0x82, 0x9b, 0x44, 0xfe, 0x26, 0x88,
  0x44, 0xf8, 0xa8, 0x9f, 0x59, 0x3a, 0xd3, 0x4f, 0x92, 0xb2, 0x06, 0xf6,
  0x59, 0xe4, 0x92, 0xca, 0xdb, 0x7c, 0xe4, 0xa5, 0x29, 0x78, 0x58, 0x71,
  0x20, 0xaf, 0x93, 0x95, 0xc1, 0x0f, 0x03, 0xff, 0x83, 0x02, 0x03, 0x01,
  0x00, 0x01, 0x02, 0x81, 0x80, 0x01, 0x5d, 0x0b, 0xad, 0x89, 0x46, 0x4b,
  0x70, 0x76, 0xa6, 0xda, 0xda, 0x23, 0x35, 0xc4, 0x3b, 0xdc, 0x76, 0x4d,
  0xd8, 0x66, 0x43, 0xac, 0x92, 0x13, 0x0d, 0xc0, 0x32, 0xb4, 0x68, 0x51,
  0xea, 0x2b, 0x8c, 0x3a, 0xb2, 0x9e, 0xed, 0xf4, 0xc2, 0x4d, 0x6c, 0x2b,
  0xcd, 0xa5, 0x25, 0xc4, 0x84, 0x1d, 0x6c, 0x50, 0xe1, 0x02, 0x32, 0xf2,
  0xf5, 0x31, 0x65, 0x4c, 0x1b, 0x8c, 0xa0, 0x13, 0xa1, 0x83, 0xb3, 0x18,
  0x08, 0xf0, 0x5b, 0xd2, 0x7f, 0xe8, 0x3b, 0x9d, 0x50, 0x5a, 0xdf, 0xde,
  0x0c, 0xef, 0x59, 0x42, 0x07, 0x28, 0xee, 0x69, 0x2e, 0x83, 0xc9, 0xb0,
  0x1e, 0xdf, 0x87, 0x2c, 0xf1, 0x1e, 0xe6, 0x5c, 0x17, 0x5c, 0x48, 0x01,
  0x8f, 0x6e, 0x44, 0x13, 0x13, 0x87, 0xba, 0x6c, 0xc5, 0xaa, 0x6e, 0xc2,
  0x13, 0xc5, 0xb8, 0x88, 0xae, 0x62, 0x09, 0xf3, 0xbf, 0xf6, 0x12, 0x50,
  0x31, 0x02, 0x41, 0x00, 0xd8, 0x4b, 0xa4, 0x8b, 0xfc, 0x92, 0xee, 0xd2,
  0x0c, 0x54, 0xa8, 0xe6, 0xbe, 0x7f, 0x52, 0x87, 0xdc, 0x93, 0xc3, 0xe4,
  0xaf, 0x5e, 0x80, 0xfd, 0x83, 0x2a, 0x70, 0x6c, 0x9e, 0x97, 0x50, 0x77,
  0xf5, 0x7d, 0x44, 0x79, 0x30, 0x87, 0x8e, 0xe8, 0x32, 0xed, 0x04, 0xca,
  0x92, 0x6a, 0x92, 0xba, 0xbd, 0xdd, 0x79, 0x70, 0x85, 0x68, 0x46, 0xf1,
  0xa5, 0x0e, 0x3c, 0x6b, 0xc8, 0xd6, 0x02, 0x6b, 0x02, 0x41, 0x00, 0xce,
  0xf7, 0x77, 0x64, 0xa6, 0xbc, 0x5a, 0x57, 0xdd, 0x45, 0x69, 0xdc, 0xde,
  0xfb, 0x05, 0x2c, 0x7a, 0xd4, 0xf2, 0x44, 0xaa, 0xd7, 0x93, 0x0a, 0xd9,
  0x23, 0x1c, 0x09, 0x24, 0xeb, 0xa9, 0xe0, 0x20, 0xfc, 0xc4, 0xb8, 0xc6,
  0xfb, 0x2c, 0xa8, 0x94, 0x63, 0xea, 0xbe, 0x82, 0xc6, 0x47, 0x1c, 0xa2,
  0xc2, 0xc8, 0x43, 0x51, 0xf8, 0x7a, 0xe2, 0x07, 0xd9, 0x1e, 0x42, 0xd3,
  0xd1, 0xad, 0x49, 0x02, 0x41, 0x00, 0xaf, 0xd3, 0x95, 0xd8, 0x82, 0x22,
  0x83, 0x67, 0x56, 0xc4, 0xbf, 0x64, 0x8b, 0xb8, 0xfe, 0xc3, 0x18, 0xc9,
  0x39, 0xf6, 0x3d, 0xa5, 0x0a, 0x20, 0x8b, 0x2e, 0xc5, 0xa3, 0x56, 0xac,
  0x54, 0xaa, 0x9f, 0x72, 0x0c, 0x66, 0xa3, 0xcf, 0x9e, 0x99, 0x1d, 0x44,
  0xd5, 0x9f, 0x42, 0xb4, 0xc5, 0xc0, 0x6e, 0x35, 0x8a, 0xd1, 0xb0, 0x71,
  0x1b, 0x32, 0xb6, 0x65, 0x43, 0x32, 0xaf, 0x59, 0x61, 0x2f, 0x02, 0x40,
  0x60, 0x42, 0x66, 0xac, 0x50, 0x84, 0x4f, 0xfc, 0x87, 0xb4, 0x6e, 0x1d,
  0x45, 0x34, 0x38, 0xde, 0xcc, 0x2e, 0x58, 0x93, 0xa9, 0x65, 0xe4, 0x44,
  0xea, 0x62, 0xd2, 0xfa, 0x49, 0xca, 0xb5, 0xd2, 0xc1, 0x64, 0xee, 0xd6,
  0x05, 0xed, 0xf2, 0x82, 0x61, 0xa9, 0xeb, 0x17, 0x3a, 0x59, 0x9f, 0xdf,
  0x68, 0xaf, 0xf1, 0x56, 0xa6, 0x3c, 0x4c, 0x62, 0xee, 0x45, 0x84, 0x36,
  0x8e, 0xaf, 0xf9, 0xc9, 0x02, 0x40, 0x73, 0x18, 0x28, 0x64, 0x81, 0xf7,
  0x7c, 0xe8, 0x43, 0x95, 0x91, 0x13, 0xb0, 0x33, 0x81, 0xe0, 0xc6, 0x8e,
  0x82, 0xef, 0xaa, 0xd5, 0x3a, 0x58, 0xf1, 0x23, 0x75, 0xea, 0xdf, 0x56,
  0x37, 0xb8, 0xc3, 0x3e, 0xa7, 0xab, 0x8e, 0x8f, 0xd0, 0x71, 0x75, 0x02,
  0xde, 0x7b, 0x91, 0x57, 0xbe, 0x72, 0x6d, 0xf8, 0xd0, 0x88, 0x41, 0x33,
  0xea, 0xe6, 0xf3, 0xfb, 0x37, 0xfc, 0x8f, 0x60, 0xae, 0x29
};

static int check_cipher(const char *ciphername,
                        unsigned int unused1 SWTPM_ATTR_UNUSED,
                        unsigned int unused2 SWTPM_ATTR_UNUSED)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, ciphername, NULL);

    EVP_CIPHER_free(c);
    return c == NULL;
#else
    const unsigned char key[] = { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                                  0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
                                  0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33,
                                  0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31};
    const EVP_CIPHER *c = EVP_get_cipherbyname(ciphername);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char ciphertext[32];
    int len = 0;
    int bad;

    bad = (!ctx || !c ||
           EVP_EncryptInit_ex(ctx, c, NULL, key, key) != 1 ||
           EVP_EncryptUpdate(ctx, ciphertext, &len, NULL, 0) != 1);

    EVP_CIPHER_CTX_free(ctx);

    return bad;
#endif
}

static EVP_PKEY *get_rsakey(unsigned int size)
{
    const unsigned char *p;
    size_t len;

    switch (size) {
    case 1024:
        p = rsa1024_der;
        len = sizeof(rsa1024_der);
        break;
    case 2048:
        p = rsa2048_der;
        len = sizeof(rsa2048_der);
        break;
    default:
        return NULL;
    }
    return d2i_PrivateKey(EVP_PKEY_RSA, NULL, &p, len);
}

/* TPM_ALG_RSAES == RSA_PKCS1_PADDING */
static int check_rsaes(const char *unused SWTPM_ATTR_UNUSED,
                       unsigned int unused2 SWTPM_ATTR_UNUSED,
                       unsigned int unused3 SWTPM_ATTR_UNUSED)
{
    unsigned char buffer[MAX_RSA_KEYSIZE / 8];
    size_t bufferlen = sizeof(buffer);
    EVP_PKEY *pkey = get_rsakey(2048);
    EVP_PKEY_CTX *ctx =  EVP_PKEY_CTX_new(pkey, NULL);
    int bad;

    bad = (!pkey || !ctx ||
           EVP_PKEY_encrypt_init(ctx) <= 0 ||
           EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0 ||
           EVP_PKEY_encrypt(ctx, buffer, &bufferlen, (void *)".", 1) <= 0);

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    return bad;
}

static int check_rsasign(const char *hashname, unsigned int keysize,
                         unsigned int padding SWTPM_ATTR_UNUSED)
{
    EVP_PKEY *pkey = get_rsakey(keysize);
    EVP_PKEY_CTX *ctx =  EVP_PKEY_CTX_new(pkey, NULL);
    const EVP_MD *md = EVP_get_digestbyname(hashname);
    unsigned char signature[MAX_RSA_KEYSIZE / 8];
    unsigned char hash[512 / 8] = { 0, };
    size_t siglen = sizeof(signature);
    int bad;

    bad = (!pkey || !ctx || !md ||
           EVP_PKEY_sign_init(ctx) <= 0 ||
           EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) <= 0 ||
           EVP_PKEY_CTX_set_signature_md(ctx, md) <= 0 ||
           EVP_PKEY_sign(ctx, signature, &siglen, hash, EVP_MD_size(md)) <= 0);

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    return bad;
}

/*
 * List of OpenSSL configuration-disabled and 'fips=yes'-disabled algorithms
 * that TPM 2 may enable with a profile.
 *
 * fips=yes disables the following:
 * - camellia
 * - tdes
 * - rsaes (RSA encryption with pkcs1 padding)
 * - RSA keys with less than 2048 bits cannot be used
 * - EC keys with less than 224 bits (?)
 *
 * More recent versions of OpenSSL may also disable signatures with SHA1:
 * - RSA signing with SHA1 using any key size
 *
 * Per openssl-ciphers man page it should be possible to disable the following
 * algorithms used by cipher-suites:
 *
 * - AES128, AES256, AES
 * - CAMELLIA128, CAMELLIA256, CAMELLIA
 * - 3DES
 * - SHA1, SHA, SHA256, SHA384
 * - CBC
 */
typedef int (*AlgorithmTest)(const char *, unsigned int size, unsigned int);
static const struct algorithms_tests {
    unsigned int disabled_type;
    const char **names;     // all of these must be found enabled in profile
    const char *algname;    // string to use for OpenSSL
    unsigned int keysize;  // keysize
    unsigned int padding;  // padding
    AlgorithmTest testfn;   // function to call
    const char *display;    // display to user
    unsigned int fix_flags; // tell the caller how to fix it
} ossl_config_disabled[] = {
    {
      .disabled_type = DISABLED_BY_FIPS | DISABLED_BY_CONFIG,
      .names = (const char *[]){"camellia", NULL},
      .algname = "CAMELLIA-128-CFB",
      .testfn = check_cipher,
      .display = "camellia-128",
      .fix_flags = FIX_DISABLE_FIPS,
    }, {
      .disabled_type = DISABLED_BY_FIPS | DISABLED_BY_CONFIG,
      .names = (const char *[]){"camellia", NULL},
      .algname = "CAMELLIA-256-CFB",
      .testfn = check_cipher,
      .display = "camellia-256",
      .fix_flags = FIX_DISABLE_FIPS,
    }, {
      .disabled_type = DISABLED_BY_FIPS | DISABLED_BY_CONFIG,
      .names= (const char *[]){"tdes", NULL},
      .algname = "DES-EDE3-CFB",
      .testfn = check_cipher,
      .fix_flags = FIX_DISABLE_FIPS,
    }, {
      .disabled_type = DISABLED_BY_FIPS,
      .names = (const char *[]){"rsaes", NULL},
      .testfn = check_rsaes,
      .fix_flags = FIX_DISABLE_FIPS,
    }, {
      .disabled_type = DISABLED_SHA1_SIGNATURES,
      .names = (const char *[]){"rsa", "sha1", "rsapss", NULL},
      .algname = "SHA1",
      .keysize = 1024,
      .padding = RSA_PKCS1_PSS_PADDING,
      .testfn = check_rsasign,
      .display = "RSA-1024-sign(SHA1, pkcs1-pss)",
      .fix_flags = FIX_ENABLE_SHA1_SIGNATURES,
    }, {
      .disabled_type = DISABLED_SHA1_SIGNATURES,
      .names = (const char *[]){"rsa", "sha1", "rsassa", NULL},
      .algname = "SHA1",
      .keysize = 1024,
      .padding = RSA_PKCS1_PADDING,
      .testfn = check_rsasign,
      .display = "RSA-1024-sign(SHA1, pkcs1)",
      .fix_flags = FIX_ENABLE_SHA1_SIGNATURES,
    }, {
      .disabled_type = DISABLED_SHA1_SIGNATURES,
      .names = (const char *[]){"rsa", "sha1", "rsapss", NULL},
      .algname = "SHA1",
      .keysize = 2048,
      .padding = RSA_PKCS1_PSS_PADDING,
      .testfn = check_rsasign,
      .display = "RSA-2048-sign(SHA1, pkcs1-pss)",
      .fix_flags = FIX_ENABLE_SHA1_SIGNATURES,
    }, {
      .disabled_type = DISABLED_SHA1_SIGNATURES,
      .names = (const char *[]){"rsa", "sha1", "rsapss", NULL},
      .algname = "SHA1",
      .keysize = 2048,
      .padding = RSA_PKCS1_PADDING,
      .testfn = check_rsasign,
      .display = "RSA-2048-sign(SHA1, pkcs1)",
      .fix_flags = FIX_ENABLE_SHA1_SIGNATURES,
    }, {
      .names = NULL,
    }
};

/* list of minimum required key sizes for FIPS */
static const struct key_sizes {
    const char **names;     // all of these must be found enabled in profile
    const char *keyword;
    unsigned int min_size;
} fips_key_sizes[] = {
    {
        .names = (const char *[]){"ecc-nist", NULL}, //keyword only matters if this is given
        .keyword = "ecc-min-size=",
        .min_size = 224,
    }, {
        .names = (const char *[]){"rsa", NULL}, //keyword only matters if this is given
        .keyword = "rsa-min-size=",
        .min_size = 2048,
    }, {
        // keep last
    }
};

/* Determine whether any of the algorithms in the array are FIPS-disable */
static unsigned int _ossl_algorithms_are_disabled(const gchar *const*algorithms,
                                                  const struct algorithms_tests *ossl_config_disabled_algos,
                                                  const struct key_sizes *key_sizes,
                                                  unsigned int disabled_filter,          // filter by these flags (optional)
                                                  bool stop_on_first_disabled
                                                 )
{
    unsigned int disabled_type;
    unsigned int fix_flags = 0;
    const char *display;
    unsigned long v;
    size_t i, l;
    int j;

    for (i = 0; ossl_config_disabled_algos[i].names != NULL; i++) {
        disabled_type = ossl_config_disabled_algos[i].disabled_type;

        if (disabled_filter != 0 &&
            (disabled_type & disabled_filter) == 0) {
            continue;
        }

        /* skip it if no new fix_flag can be determined */
        if (stop_on_first_disabled &&
            (ossl_config_disabled_algos[i].fix_flags & ~fix_flags) == 0) {
            continue;
        }

        if (strv_contains_all(algorithms, ossl_config_disabled_algos[i].names)) {
            int rc = ossl_config_disabled_algos[i].testfn(
                          ossl_config_disabled_algos[i].algname,
                          ossl_config_disabled_algos[i].keysize,
                          ossl_config_disabled_algos[i].padding);
            if (ossl_config_disabled_algos[i].display)
                display = ossl_config_disabled_algos[i].display;
            else
                display = ossl_config_disabled_algos[i].names[0];

            if (rc) {
                fix_flags |= ossl_config_disabled_algos[i].fix_flags;

                logprintf(STDERR_FILENO,
                          "Warning%s: Profile-enabled algorithms contain disabled '%s'\n",
                          disabled_type & DISABLED_BY_FIPS ? "(FIPS)" : "",
                          display);
            } else {
                logprintf(STDOUT_FILENO, " Tested: %s\n", display);
            }
        }
    }

    if ((disabled_filter & DISABLED_BY_FIPS) && (fix_flags & FIX_DISABLE_FIPS) == 0) {
        for (i = 0; key_sizes[i].keyword; i++) {
            if (strv_contains_all(algorithms, key_sizes[i].names)) {
                l = strlen(key_sizes[i].keyword);
                j = strv_strncmp(algorithms, key_sizes[i].keyword, l);
                if (j >= 0) {
                    v = strtoul(&(algorithms[j][l]), NULL, 10);
                    if (v < key_sizes[i].min_size) {
                        logprintf(STDERR_FILENO,
                                  "Warning(FIPS): Enabled key sizes %s%lu is smaller than required %u.\n",
                                  key_sizes[i].keyword, v, key_sizes[i].min_size);
                        fix_flags |= FIX_DISABLE_FIPS;
                        break;
                    }
                } else {
                    logprintf(STDERR_FILENO,
                              "Warning(FIPS): Missing statement '%s%u' to restrict key size.\n",
                              key_sizes[i].keyword, key_sizes[i].min_size);
                }
            }
        }
    }
    return fix_flags;
}

/* Determine whether the algorithms in the given array contain any algorithms
 * that OpenSSL disables when the host is in FIPS mode. If any of these
 * algorithms are found to be disabled (unusable for libtpms), then
 * FIX_DISABLE_FIPS is set. Similarly, test whether signing and verification of
 * signatures with SHA1 are disabled and if so this function will set the
 * FIX_ENABLE_SHA1_SIGNATURES flag.
 */
unsigned int ossl_algorithms_are_disabled(const gchar *const*algorithms,
                                          unsigned int disabled_filter,
                                          bool stop_on_first_disabled)
{
    return _ossl_algorithms_are_disabled(algorithms, ossl_config_disabled, fips_key_sizes,
                                         disabled_filter,
                                         stop_on_first_disabled);
}
