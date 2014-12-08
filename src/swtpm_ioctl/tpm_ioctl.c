/*
 * tpm_ioctl  --  ioctl utility for the CUSE TPM
 *
 * Authors: David Safford <safford@us.ibm.com>
 *          Stefan Berger <stefanb@us.ibm.com>
 *
 * (c) Copyright IBM Corporation 2014.
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
/*
 * tool for using 'swtpm cuse' ioctls
 *
 * cuse_tpm_ioctl [ -c | -i | -s | -e | -l num ] devicepath
 *     -c get ptm capabilities
 *     -i do a hardware TPM_Init
 *     -s shutdown tpm_server_cuse
 *     -e get tpmEstablished bit
 *     -l set locality to num
 *     -h hash the given data
 *     -v store volatile data to file
 *     -C cancel an ongoing TPM command
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include <swtpm/tpm_ioctl.h>

static void usage(const char *prgname)
{
    fprintf(stdout,
"Usage: %s command <device path>\n"
"\n"
"The following commands are supported:\n"
"-c       : get ptm capabilities\n"
"-i       : do a hardware TPM_Init; if volatile state is found, it will\n"
"           resume the TPM with it and delete it afterwards\n"
"-s       : shutdown the CUSE tpm\n"
"-e       : get the tpmEstablished bit\n"
"-r       : reset the tpmEstablished bit\n"
"-v       : store the TPM's volatile data\n"
"-C       : cancel an ongoing TPM command\n"
"-l <num> : set the locality to the given number; valid numbers are 0-4\n"
"-h <data>: hash the given data; if data is '-' then data are read from\n"
"           stdin\n\n"
    ,prgname);
}

int main(int argc, char *argv[])
{
    int fd;
    int devindex, n;
    ptmest_t est;
    ptmreset_est_t reset_est;
    ptmloc_t loc;
    ptmcap_t cap;
    ptmhdata_t hdata;
    ptmres_t res;
    ptminit_t init;
    size_t idx;

    if (argc < 2) {
        fprintf(stderr, "Error: Missing command.\n\n");
        usage(argv[0]);
        return 1;
    }

    switch (argv[1][1]) {
        case 'l':
        case 'h':
        case 'r':
            devindex = 3;
            break;
        default:
            devindex = 2;
            break;
    }

    if (devindex >= argc) {
        fprintf(stderr, "Error: Not enough parameters.\n\n");
        usage(argv[0]);
        return 1;
    }

    fd = open(argv[devindex], O_RDWR);
    if (fd < 0) {
            fprintf(stderr,
                    "Could not open CUSE TPM device %s: %s\n",
                    argv[devindex], strerror(errno));
                return -1;
    }

    switch (argv[1][1]) {
    case 'c':
        n = ioctl(fd, PTM_GET_CAPABILITY, &cap);
        if (n < 0) {
            fprintf(stderr,
                    "Could not execute ioctl PTM_GET_CAPABILITY: "
                    "%s\n", strerror(errno));
            return 1;
        }
        /* no tpm_result here */
        printf("ptm capability is 0x%lx\n",cap);
        break;

    case 'i':
        init.u.req.init_flags = INIT_FLAG_DELETE_VOLATILE;
        n = ioctl(fd, PTM_INIT, &init);
        if (n < 0) {
            fprintf(stderr,
                    "Could not execute ioctl PTM_INIT: "
                    "%s\n", strerror(errno));
            return 1;
        }
        res = init.u.resp.tpm_result;
        if (res != 0) {
            fprintf(stderr,
                    "TPM result from PTM_INIT: 0x%x\n", res);
            return 1;
        }
        break;

    case 'e':
        n = ioctl(fd, PTM_GET_TPMESTABLISHED, &est);
        if (n < 0) {
            fprintf(stderr,
                    "Could not execute ioctl PTM_GET_ESTABLISHED: "
                    "%s\n", strerror(errno));
            return 1;
        }
        res = est.tpm_result;
        if (res != 0) {
            fprintf(stderr,
                    "TPM result from PTM_GET_TPMESTABLISHED: 0x%x\n", res);
            return 1;
        }
        printf("tpmEstablished is %d\n",est.bit);
        break;

    case 'r':
        reset_est.u.req.loc = atoi(argv[2]);
        if (reset_est.u.req.loc < 0 || reset_est.u.req.loc > 4) {
            fprintf(stderr,
                    "Locality must be a number from 0 to 4.\n");
            return 1;
        }
        n = ioctl(fd, PTM_RESET_TPMESTABLISHED, &reset_est);
        if (n < 0) {
            fprintf(stderr,
                    "Could not execute ioctl PTM_RESET_ESTABLISHED: "
                    "%s\n", strerror(errno));
            return 1;
        }
        res = reset_est.u.resp.tpm_result;
        if (res != 0) {
            fprintf(stderr,
                    "TPM result from PTM_RESET_TPMESTABLISHED: 0x%x\n", res);
            return 1;
        }
        break;

    case 's':
        n = ioctl(fd, PTM_SHUTDOWN, &res);
        if (n < 0) {
            fprintf(stderr,
                    "Could not execute ioctl PTM_SHUTDOWN: "
                    "%s\n", strerror(errno));
            return 1;
        }
        if (res != 0) {
            fprintf(stderr,
                    "TPM result from PTM_SHUTDOWN: 0x%x\n", res);
            return 1;
        }
        break;

    case 'l':
        loc.u.req.loc = atoi(argv[2]);
        if (loc.u.req.loc < 0 || loc.u.req.loc > 4) {
            fprintf(stderr,
                    "Locality must be a number from 0 to 4.\n");
            return 1;
        }
        n = ioctl(fd, PTM_SET_LOCALITY, &loc);
        if (n < 0) {
            fprintf(stderr,
                    "Could not execute ioctl PTM_SET_LOCALITY: "
                    "%s\n", strerror(errno));
            return 1;
        }
        res = loc.u.resp.tpm_result;
        if (res != 0) {
            fprintf(stderr,
                    "TPM result from PTM_SET_LOCALITY: 0x%x\n", res);
            return 1;
        }
        break;

    case 'h':
        /* hash string given on command line */
        n = ioctl(fd, PTM_HASH_START, &res);
        if (n < 0) {
            fprintf(stderr,
                    "Could not execute ioctl PTM_HASH_START: "
                    "%s\n", strerror(errno));
            return 1;
        }
        if (res != 0) {
            fprintf(stderr,
                    "TPM result from PTM_HASH_START: 0x%x\n", res);
            return 1;
        }
        if (strlen(argv[2]) == 1 && argv[2][0] == '-') {
            /* read data from stdin */
            while (1) {
                idx = 0;
                int c = 0;
                while (idx < sizeof(hdata.u.req.data)) {
                    c = fgetc(stdin);
                    if (c == EOF)
                        break;
                    hdata.u.req.data[idx] = (char)c;
                    idx++;
                }
                hdata.u.req.length = idx;
                n = ioctl(fd, PTM_HASH_DATA, &hdata);
                res = hdata.u.resp.tpm_result;
                if (n != 0 || res != 0 || c == EOF)
                    break;
            }
        } else {
            idx = 0;
            while (idx < strlen(argv[2])) {
                size_t tocopy = strlen(argv[2]) - idx;
                if (tocopy > sizeof(hdata.u.req.data))
                    tocopy = sizeof(hdata.u.req.data);
                hdata.u.req.length = tocopy;
                memcpy(hdata.u.req.data, &(argv[2])[idx],
                       tocopy);
                idx += tocopy;
                n = ioctl(fd, PTM_HASH_DATA, &hdata);
                res = hdata.u.resp.tpm_result;
                if (n != 0 || res != 0)
                    break;
            }
                }
        if (n != 0) {
            fprintf(stderr,
                    "Could not execute ioctl PTM_HASH_DATA: "
                    "%s\n", strerror(errno));
            return 1;
        }
        if (res != 0) {
            fprintf(stderr,
                   "TPM result from PTM_HASH_DATA: 0x%x\n", res);
            return 1;
        }
        n = ioctl(fd, PTM_HASH_END, &res);
        if (n < 0) {
            fprintf(stderr,
                    "Could not execute ioctl PTM_HASH_END: "
                    "%s\n", strerror(errno));
            return 1;
        }
        if (res != 0) {
            fprintf(stderr,
                    "TPM result from PTM_HASH_END: 0x%x\n", res);
            return 1;
        }
        break;

        case 'C':
        n = ioctl(fd, PTM_CANCEL_TPM_CMD, &res);
        if (n < 0) {
            fprintf(stderr,
                    "Could not execute ioctl PTM_CANCEL_TPM_CMD: "
                    "%s\n", strerror(errno));
            return 1;
        }
        if (res != 0) {
            fprintf(stderr,
                    "TPM result from PTM_CANCEL_TPM_CMD: 0x%x\n",
                    res);
            return 1;
        }
        break;

        case 'v':
        n = ioctl(fd, PTM_STORE_VOLATILE, &res);
        if (n < 0) {
            fprintf(stderr,
                    "Could not execute ioctl PTM_STORE_VOLATILE: "
                    "%s\n", strerror(errno));
            return 1;
        }
        if (res != 0) {
            fprintf(stderr,
                    "TPM result from PTM_STORE_VOLATILE: 0x%x\n",
                    res);
            return 1;
        }
        break;

    default:
        usage(argv[0]);
        return 1;
    }
    return 0;
}
