/********************************************************************************/
/*                                                                              */
/*                         TPM Debug Utilities                                  */
/*                           Written by Ken Goldman                             */
/*                     IBM Thomas J. Watson Research Center                     */
/*            $Id: tpm_debug.c 4179 2010-11-10 20:10:24Z kgoldman $             */
/*                                                                              */
/* (c) Copyright IBM Corporation 2006, 2010.					*/
/*										*/
/* All rights reserved.								*/
/* 										*/
/* Redistribution and use in source and binary forms, with or without		*/
/* modification, are permitted provided that the following conditions are	*/
/* met:										*/
/* 										*/
/* Redistributions of source code must retain the above copyright notice,	*/
/* this list of conditions and the following disclaimer.			*/
/* 										*/
/* Redistributions in binary form must reproduce the above copyright		*/
/* notice, this list of conditions and the following disclaimer in the		*/
/* documentation and/or other materials provided with the distribution.		*/
/* 										*/
/* Neither the names of the IBM Corporation nor the names of its		*/
/* contributors may be used to endorse or promote products derived from		*/
/* this software without specific prior written permission.			*/
/* 										*/
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		*/
/* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		*/
/* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR	*/
/* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		*/
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	*/
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		*/
/* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,	*/
/* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY	*/
/* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		*/
/* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE	*/
/* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		*/
/********************************************************************************/

#include <config.h>

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>

#include "swtpm_debug.h"
#include "logging.h"

/*
 * SWTPM_AppendPrintf() print and append to buffer
 *
 * @buffer: pointer to existing buffer or pointer to NULL to start a new buffer
 * @fmt: typical printf fmt
 * @...: varagr printf parameters
 *
 */
static int SWTPM_AppendPrintf(char **buffer, const char *fmt, ...)
{
    va_list ap;
    int n, len = 0;
    char *dest = NULL, *nbuffer;

    va_start(ap, fmt);
    n = vasprintf(&dest, fmt, ap);
    va_end(ap);
    if (n < 0)
        return n;

    if (*buffer)
        len = strlen(*buffer);

    nbuffer = malloc(len + n + 1);
    if (!nbuffer) {
        free(dest);
        return -1;
    }
    if (*buffer)
        memcpy(nbuffer, *buffer, len);
    memcpy(&nbuffer[len], dest, n);
    nbuffer[len + n] = 0;

    free(dest);
    free(*buffer);
    *buffer = nbuffer;

    return len + n;
}

/* SWTPM_PrintAll() prints 'string', the length, and then the entire byte array
 */
void SWTPM_PrintAll(const char *string, const char *indentation,
                    const unsigned char* buff, uint32_t length)
{
    uint32_t i;
    int indent;
    char *linebuffer = NULL;

    indent = log_check_string(string);
    if (indent < 0)
        return;

    if (buff != NULL) {
        logprintf(STDERR_FILENO, "%s length %u\n", string, length);

        SWTPM_AppendPrintf(&linebuffer, "%s", indentation);
        for (i = 0 ; i < length ; i++) {
            if (i && !( i % 16 )) {
                SWTPM_AppendPrintf(&linebuffer, "\n");

                logprintfA(STDERR_FILENO, 0, linebuffer);

                free(linebuffer);
                linebuffer = NULL;
                SWTPM_AppendPrintf(&linebuffer, "%s", indentation);
            }

            SWTPM_AppendPrintf(&linebuffer, "%.2X ", buff[i]);
        }
        SWTPM_AppendPrintf(&linebuffer, "\n");
        logprintf(STDERR_FILENO, "%s", linebuffer);
        free(linebuffer);
    }
    else {
        logprintf(STDERR_FILENO, "%s null\n", string);
    }
    return;
}

