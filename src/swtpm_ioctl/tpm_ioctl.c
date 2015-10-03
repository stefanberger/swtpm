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
 * cuse_tpm_ioctl [ -c | -i | -s | -e | -l num | -C | -v ] devicepath
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
#include <stdbool.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include <swtpm/tpm_ioctl.h>

#include <libtpms/tpm_error.h>


/*
 * Do PTM_HASH_START, PTM_HASH_DATA, PTM_HASH_END on the
 * data.
 */
static int do_hash_start_data_end(int fd, const char *input)
{
    ptm_res res;
    int n;
    size_t idx;
    ptm_hdata hdata;

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
    if (strlen(input) == 1 && input[0] == '-') {
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
        while (idx < strlen(input)) {
            size_t tocopy = strlen(input) - idx;

            if (tocopy > sizeof(hdata.u.req.data))
                tocopy = sizeof(hdata.u.req.data);

            hdata.u.req.length = tocopy;
            memcpy(hdata.u.req.data, &input[idx], tocopy);
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

    return 0;
}

static uint32_t get_blobtype(const char *blobname)
{
    if (!strcmp(blobname, "permanent"))
        return PTM_BLOB_TYPE_PERMANENT;
    if (!strcmp(blobname, "volatile"))
        return PTM_BLOB_TYPE_VOLATILE;
    if (!strcmp(blobname, "savestate"))
        return PTM_BLOB_TYPE_SAVESTATE;
    return 0;
}

/*
 * do_save_state_blob: Get a state blob from the TPM and store it into the
 *                     given file
 * @fd: file descriptor to talk to the CUSE TPM
 * @blobtype: the name of the blobtype
 * @filename: name of the file to store the blob into
 *
 */
static int do_save_state_blob(int fd, const char *blobtype,
                              const char *filename, size_t buffersize)
{
    int file_fd;
    ptm_res res;
    ptm_getstate pgs;
    uint16_t offset;
    ssize_t numbytes;
    bool had_error;
    int n;
    uint32_t bt;
    unsigned char *buffer =  NULL;

    bt = get_blobtype(blobtype);
    if (!bt) {
        fprintf(stderr,
                "Unknown TPM state type '%s'", blobtype);
        return 1;
    }

    file_fd = open(filename, O_WRONLY|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR);
    if (file_fd < 0) {
        fprintf(stderr,
                "Could not open file '%s' for writing: %s\n",
                filename, strerror(errno));
        return 1;
    }

    had_error = false;
    offset = 0;

    while (true) {
        /* fill out request every time since response may change it */
        pgs.u.req.state_flags = PTM_STATE_FLAG_DECRYPTED;
        pgs.u.req.type = bt;
        pgs.u.req.offset = offset;

        n = ioctl(fd, PTM_GET_STATEBLOB, &pgs);
        if (n < 0) {
            fprintf(stderr,
                    "Could not execute ioctl PTM_GET_STATEBLOB: "
                    "%s\n", strerror(errno));
            had_error = true;
            break;
        }
        res = pgs.u.resp.tpm_result;
        if (res != 0 && (res & TPM_NON_FATAL) == 0) {
            fprintf(stderr,
                    "TPM result from PTM_GET_STATEBLOB: 0x%x\n",
                    res);
            had_error = true;
            break;
        }
        numbytes = write(file_fd, pgs.u.resp.data, pgs.u.resp.length);

        if (numbytes != pgs.u.resp.length) {
            fprintf(stderr,
                    "Could not write to file '%s': %s\n",
                    filename, strerror(errno));
            had_error = true;
            break;
        }
        /* done when the last byte was received */
        if (offset + pgs.u.resp.length >= pgs.u.resp.totlength)
            break;

        if (buffersize) {
            /* continue with the read interface */
            buffer = malloc(buffersize);
            if (!buffer) {
                fprintf(stderr,
                        "Could not allocate buffer with %zu bytes.",
                        buffersize);
                had_error = true;
                break;
            }

            while (true) {
                /* read from TPM */
                n = read(fd, buffer, buffersize);
                if (n < 0) {
                    fprintf(stderr,
                            "Could not read from TPM: %s\n",
                            strerror(errno));
                    had_error = true;
                    break;
                }
                numbytes = write(file_fd, buffer, n);
                if (numbytes < 0) {
                    fprintf(stderr,
                            "Could not write to file '%s': %s\n",
                            filename, strerror(errno));
                    had_error = true;
                    break;
                }
                if ((size_t)n < buffersize)
                    break;
            }

            break;
        } else {
            offset += pgs.u.resp.length;
        }
    }

    close(file_fd);

    free(buffer);

    if (had_error)
        return 1;

    return 0;
}

/*
 * do_load_state_blob: Load a TPM state blob from a file and load it into the
 *                     TPM
 * @fd: file descriptor to talk to the CUSE TPM
 * @blobtype: the name of the blobtype
 * @filename: name of the file to store the blob into
 * @buffersize: the size of the buffer to use via write() interface
 */
static int do_load_state_blob(int fd, const char *blobtype,
                              const char *filename,
                              size_t buffersize)
{
    int file_fd;
    ptm_res res;
    ptm_setstate pss;
    ssize_t numbytes;
    bool had_error;
    int n;
    uint32_t bt;
    unsigned char *buffer = NULL;

    bt = get_blobtype(blobtype);
    if (!bt) {
        fprintf(stderr,
                "Unknown TPM state type '%s'", blobtype);
        return 1;
    }

    file_fd = open(filename, O_RDONLY);
    if (file_fd < 0) {
        fprintf(stderr,
                "Could not open file '%s' for reading: %s\n",
                filename, strerror(errno));
        return 1;
    }

    had_error = false;

    if (!buffersize) {
        /* use only the ioctl interface for the transfer */
        while (true) {
            /* fill out request every time since response may change it */
            pss.u.req.state_flags = 0;
            pss.u.req.type = bt;

            numbytes = read(file_fd, pss.u.req.data, sizeof(pss.u.req.data));
            if (numbytes < 0) {
                fprintf(stderr,
                        "Could not read from file '%s': %s\n",
                        filename, strerror(errno));
               had_error = true;
               break;
            }
            pss.u.req.length = numbytes;

            n = ioctl(fd, PTM_SET_STATEBLOB, &pss);
            if (n < 0) {
                fprintf(stderr,
                        "Could not execute ioctl PTM_SET_STATEBLOB: "
                        "%s\n", strerror(errno));
                had_error = true;
                break;
            }
            res = pss.u.resp.tpm_result;
            if (res != 0) {
                fprintf(stderr,
                        "TPM result from PTM_SET_STATEBLOB: 0x%x\n",
                        res);
                had_error = true;
                break;
            }
            if ((size_t)numbytes < sizeof(pss.u.req.data))
                break;
        }
    } else {
        buffer = malloc(buffersize);
        if (!buffer) {
            fprintf(stderr,
                    "Could not allocate buffer with %zu bytes.",
                    buffersize);
            had_error = true;
            goto cleanup;
        }

        pss.u.req.state_flags = 0;
        pss.u.req.type = bt;
        pss.u.req.length = 0; /* will use write interface */

        n = ioctl(fd, PTM_SET_STATEBLOB, &pss);
        if (n < 0) {
            fprintf(stderr,
                    "Could not execute ioctl PTM_SET_STATEBLOB: "
                    "%s\n", strerror(errno));
            had_error = 1;
            goto cleanup;
        }
        res = pss.u.resp.tpm_result;
        if (res != 0) {
            fprintf(stderr,
                    "TPM result from PTM_SET_STATEBLOB: 0x%x\n",
                    res);
            had_error = 1;
            goto cleanup;
        }

        while (true) {
            n = read(file_fd, buffer, buffersize);
            if (n < 0) {
                fprintf(stderr, "Could not read from file: %s\n",
                        strerror(errno));
                had_error = 1;
                goto cleanup;
            }
            if (n != write(fd, buffer, n)) {
                fprintf(stderr, "Could not write to file: %s\n",
                        strerror(errno));
                had_error = 1;
                goto cleanup;
            }
            if ((size_t)n < buffersize) {
                /* close transfer with the ioctl() */
                pss.u.req.state_flags = 0;
                pss.u.req.type = bt;
                pss.u.req.length = 0; /* end the transfer */

                n = ioctl(fd, PTM_SET_STATEBLOB, &pss);
                if (n < 0) {
                    fprintf(stderr,
                            "Could not execute ioctl PTM_SET_STATEBLOB: "
                            "%s\n", strerror(errno));
                    had_error = 1;
                    goto cleanup;
                }
                res = pss.u.resp.tpm_result;
                if (res != 0) {
                    fprintf(stderr,
                            "TPM result from PTM_SET_STATEBLOB: 0x%x\n",
                            res);
                    had_error = 1;
                    goto cleanup;
                }
                break;
            }
        }
    }

 cleanup:
    close(file_fd);

    free(buffer);

    if (had_error)
        return 1;

    return 0;
}

static void usage(const char *prgname)
{
    fprintf(stdout,
"Usage: %s command <device path>\n"
"\n"
"The following commands are supported:\n"
"-c       : get ptm capabilities\n"
"-i       : do a hardware TPM_Init; if volatile state is found, it will\n"
"           resume the TPM with it and delete it afterwards\n"
"--stop   : stop the CUSE tpm without exiting\n"
"-s       : shutdown the CUSE tpm; stops and exists\n"
"-e       : get the tpmEstablished bit\n"
"-r <loc> : reset the tpmEstablished bit; use the given locality\n"
"-v       : store the TPM's volatile data\n"
"-C       : cancel an ongoing TPM command\n"
"-l <num> : set the locality to the given number; valid numbers are 0-4\n"
"-h <data>: hash the given data; if data is '-' then data are read from\n"
"           stdin\n"
"--save <type> <file> : store the TPM state blob of given type in a file;\n"
"                       type may be one of volatile, permanent, or savestate\n"
"--load <type> <file> : load the TPM state blob of given type from a file;\n"
"                       type may be one of volatile, permanent, or savestate\n"
"-g       : get configuration flags indicating which keys are in use\n"
"\n"
    ,prgname);
}

int main(int argc, char *argv[])
{
    int fd;
    int devindex, n;
    ptm_est est;
    ptm_reset_est reset_est;
    ptm_loc loc;
    ptm_cap cap;
    ptm_res res;
    ptm_init init;
    ptm_getconfig cfg;
    char *tmp;
    size_t buffersize = 0;

    if (argc < 2) {
        fprintf(stderr, "Error: Missing command.\n\n");
        usage(argv[0]);
        return 1;
    }

    if (!strcmp(argv[1], "--save") ||
        !strcmp(argv[1], "--load")) {
        devindex = 4;
    } else if (!strcmp(argv[1], "-l") ||
        !strcmp(argv[1], "-h") ||
        !strcmp(argv[1], "-r")) {
        devindex = 3;
    } else {
        devindex = 2;
    }

    if (devindex >= argc) {
        fprintf(stderr, "Error: Not enough parameters.\n\n");
        usage(argv[0]);
        return 1;
    }

    tmp = getenv("SWTPM_IOCTL_BUFFERSIZE");
    if (tmp) {
        if (sscanf(tmp, "%zu", &buffersize) != 1 || buffersize < 1)
            buffersize = 1;
    }

    fd = open(argv[devindex], O_RDWR);
    if (fd < 0) {
        fprintf(stderr,
                "Could not open CUSE TPM device %s: %s\n",
                argv[devindex], strerror(errno));
        return -1;
    }

    if (!strcmp(argv[1], "-c")) {
        n = ioctl(fd, PTM_GET_CAPABILITY, &cap);
        if (n < 0) {
            fprintf(stderr,
                    "Could not execute ioctl PTM_GET_CAPABILITY: "
                    "%s\n", strerror(errno));
            return 1;
        }
        /* no tpm_result here */
        printf("ptm capability is 0x%lx\n",cap);

    } else if (!strcmp(argv[1], "-i")) {
        init.u.req.init_flags = PTM_INIT_FLAG_DELETE_VOLATILE;
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

    } else if (!strcmp(argv[1], "-e")) {
        n = ioctl(fd, PTM_GET_TPMESTABLISHED, &est);
        if (n < 0) {
            fprintf(stderr,
                    "Could not execute ioctl PTM_GET_ESTABLISHED: "
                    "%s\n", strerror(errno));
            return 1;
        }
        res = est.u.resp.tpm_result;
        if (res != 0) {
            fprintf(stderr,
                    "TPM result from PTM_GET_TPMESTABLISHED: 0x%x\n", res);
            return 1;
        }
        printf("tpmEstablished is %d\n",est.u.resp.bit);

    } else if (!strcmp(argv[1], "-r")) {
        reset_est.u.req.loc = atoi(argv[2]);
        if (reset_est.u.req.loc > 4) {
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

    } else if (!strcmp(argv[1], "-s")) {
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

    } else if (!strcmp(argv[1], "--stop")) {
        n = ioctl(fd, PTM_STOP, &res);
        if (n < 0) {
            fprintf(stderr,
                    "Could not execute ioctl PTM_STOP: "
                    "%s\n", strerror(errno));
            return 1;
        }
        if (res != 0) {
            fprintf(stderr,
                    "TPM result from PTM_STOP: 0x%x\n", res);
            return 1;
        }

    } else if (!strcmp(argv[1], "-l")) {
        loc.u.req.loc = atoi(argv[2]);
        if (loc.u.req.loc > 4) {
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

    } else if (!strcmp(argv[1], "-h")) {
        if (do_hash_start_data_end(fd, argv[2])) {
            return 1;
        }

    } else if (!strcmp(argv[1], "-C")) {
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

    } else if (!strcmp(argv[1], "-v")) {
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

    } else if (!strcmp(argv[1], "--save")) {
        if (do_save_state_blob(fd, argv[2], argv[3], buffersize))
            return 1;

    } else if (!strcmp(argv[1], "--load")) {
        if (do_load_state_blob(fd, argv[2], argv[3], buffersize))
            return 1;

    } else if (!strcmp(argv[1], "-g")) {
        n = ioctl(fd, PTM_GET_CONFIG, &cfg);
        if (n < 0) {
            fprintf(stderr,
                    "Could not execute ioctl PTM_GET_CONFIG: "
                    "%s\n", strerror(errno));
            return 1;
        }
        if (cfg.u.resp.tpm_result != 0) {
            fprintf(stderr,
                    "TPM result from PTM_GET_CONFIG: 0x%x\n",
                    cfg.u.resp.tpm_result);
            return 1;
        }
        printf("ptm configuration flags: 0x%x\n",cfg.u.resp.flags);
    } else {
        usage(argv[0]);
        return 1;
    }
    return 0;
}
