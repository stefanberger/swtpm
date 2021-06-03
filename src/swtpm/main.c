/*
 * main.c -- The TPM Emulator's main function
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "main.h"
#include "swtpm.h"

static void usage(FILE *stream, const char *prgname)
{
    fprintf(stream,
        "TPM emulator with choice of interface.\n"
        "\n"
        "Usage: %s socket"
#ifdef WITH_CHARDEV
                        "|chardev"
#endif
#ifdef WITH_CUSE
                                "|cuse"
#endif
                                     " [options]\n"
        "       %s -v|--version\n"
        "\n"
        "Use the --help option to see the help screen for each interface type.\n"
        "Use the --version options to see version information.\n",
        prgname,prgname);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Missing TPM interface type.\n");
        return 1;
    }
    if (!strcmp(argv[1], "socket")) {
        return swtpm_main(argc-1, &argv[1], argv[0], "socket");
#ifdef WITH_CHARDEV
    } else if (!strcmp(argv[1], "chardev")) {
        return swtpm_chardev_main(argc-1, &argv[1], argv[0], "chardev");
#endif
#ifdef WITH_CUSE
    } else if (!strcmp(argv[1], "cuse")) {
        return swtpm_cuse_main(argc-1, &argv[1], argv[0], "cuse");
#endif
    } else if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) {
        usage(stdout, argv[0]);
    } else if (!strcmp(argv[1], "-v") || !strcmp(argv[1], "--version")) {
        fprintf(stdout, "TPM emulator version %d.%d.%d, "
                "Copyright (c) 2014-2021 IBM Corp.\n",
                SWTPM_VER_MAJOR,
                SWTPM_VER_MINOR,
                SWTPM_VER_MICRO);
    } else {
        fprintf(stderr, "Unsupported TPM interface type '%s'.\n", argv[1]);
        usage(stderr, argv[0]);
        return 1;
    }
    return 0;
}

