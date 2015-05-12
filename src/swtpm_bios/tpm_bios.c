/*
 * tpm_bios  --  
 *
 * Authors: Ken Goldman <kgoldman@us.ibm.com>
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
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <netdb.h>
#include <sys/un.h>

static int open_connection(void)
{
	int fd = -1, tcp_device_port;
	char *tcp_device_hostname = NULL;
	char *tcp_device_port_string = NULL;

	if (getenv("TCSD_USE_TCP_DEVICE")) {
		if ((tcp_device_hostname = getenv("TCSD_TCP_DEVICE_HOSTNAME")) == NULL)
			tcp_device_hostname = "localhost";
		if ((tcp_device_port_string = getenv("TCSD_TCP_DEVICE_PORT")) != NULL)
			tcp_device_port = atoi(tcp_device_port_string);
		else
			tcp_device_port = 6545;

		fd = socket(AF_INET, SOCK_STREAM, 0);
		if (fd >= 0) {
			struct hostent *host = gethostbyname(tcp_device_hostname);
			if (host != NULL) {
				struct sockaddr_in addr;
				memset(&addr, 0x0, sizeof(addr));
				addr.sin_family = host->h_addrtype;
				addr.sin_port   = htons(tcp_device_port);
				memcpy(&addr.sin_addr,
						host->h_addr,
						host->h_length);
				if (connect(fd,	(struct sockaddr *)&addr,
					    sizeof(addr)) < 0) {
					close(fd);
					fd = -1;
				}
			} else {
				close (fd);
				fd = -1;
			}
		}

		if (fd < 0) {
			printf("Could not connect using TCP socket.\n");
		}
	} else {
	        char *devname = getenv("TPM_DEVICE");
	        if (!devname)
	                devname = "/dev/tpm0";

		fd = open(devname, O_RDWR );
		if ( fd < 0 ) {
			printf( "Unable to open device '%s'.\n", devname );
		}
	}

	return fd;
}


static int talk(const unsigned char *buf, size_t count, int *tpm_errcode)
{
	ssize_t len;
	unsigned int pkt_len;
	int rc = -1;
	int fd;
	unsigned char buffer[1024];

	fd = open_connection();
	if (fd < 0) {
		goto err_exit;
	}

	len = write(fd, buf, count);
	if (len < 0 || (size_t)len != count) {
		printf("Write to file descriptor failed.\n");
		goto err_close_fd;
	}

	len = read(fd, buffer, sizeof(buffer));
	if (len < 0) {
		printf("Read from file descriptor failed.\n");
		goto err_close_fd;
	}

	if (len < 10) {
		printf("Returned packet is too short.\n");
		goto err_close_fd;
	}

	pkt_len = ntohl( *((uint32_t *)(buffer + 2)));
	if ((unsigned int)len != pkt_len) {
		printf("Malformed response.\n");
		goto err_close_fd;
	}

	*tpm_errcode = ntohl( *((uint32_t *)(buffer + 6)));

	rc = 0;

err_close_fd:
	close(fd);
	fd = -1;

err_exit:
	return rc;
}


static int TPM_Startup(unsigned char parm, int *tpm_errcode)
{
	unsigned char tpm_startup[] = {
		0x00, 0xc1, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x99,
		0x00, 0x01
	};
	tpm_startup[11] = parm;

	return talk(tpm_startup, sizeof(tpm_startup), tpm_errcode);
}


static int TSC_PhysicalPresence(unsigned short parm, int *tpm_errcode)
{
	unsigned char tsc_pp[] = {
		0x00, 0xc1, 0x00, 0x00, 0x00, 0x0c, 0x40, 0x00, 0x00, 0x0a,
		0x00, 0x20
	};
	tsc_pp[10] = parm >> 8;
	tsc_pp[11] = parm;

	return talk(tsc_pp, sizeof(tsc_pp), tpm_errcode);
}

static int TPM_PhysicalEnable(int *tpm_errcode)
{
	unsigned char tpm_pe[] = {
		0x00, 0xc1, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x6f
	};

	return talk(tpm_pe, sizeof(tpm_pe), tpm_errcode);
}

static int TPM_PhysicalSetDeactivated(unsigned char parm, int *tpm_errcode)
{
	unsigned char tpm_psd[] = {
		0x00, 0xc1, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x72,
		0x00
	};
	tpm_psd[10] = parm;

	return talk(tpm_psd, sizeof(tpm_psd), tpm_errcode);
}

static int TPM_ContinueSelfTest(int *tpm_errcode)
{
	unsigned char tpm_cst[] = {
		0x00, 0xc1, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x53
	};

	return talk(tpm_cst, sizeof(tpm_cst), tpm_errcode);
}

static void print_usage(const char *prgname)
{
	printf(
"\n"
"%s [options]\n"
"\n"
"Runs TPM_Startup (unless -n), then (unless -o) sets PP, enable, activate \n"
"\n"
"The following options are supported:\n"
"\t-c  startup clear (default)\n"
"\t-s  startup state\n"
"\t-d  startup deactivate\n"
"\t-n  no startup\n"
"\t-o  startup only\n"
"\t-cs run TPM_ContinueSelfTest\n",
prgname);
	return;
}

int main(int argc, char *argv[])
{
	int   ret = 0;
	int   i;			/* argc iterator */
	int   do_more = 1;
	int   contselftest = 0;
	unsigned char  startupparm = 0x1;      /* parameter for TPM_Startup(); */
	int   tpm_errcode = 0;

	/* command line argument defaults */

	for (i=1 ; (i<argc) && (ret == 0) ; i++) {
		if (strcmp(argv[i],"-c") == 0) {
			startupparm = 0x01;
			do_more = 1;
		} else if (strcmp(argv[i],"-d") == 0) {
			do_more = 0;
			startupparm = 0x03;
		} else if (strcmp(argv[i],"-h") == 0) {
			print_usage(argv[0]);
			exit(EXIT_SUCCESS);
		} else if (strcmp(argv[i],"-n") == 0) {
			startupparm = 0xff;
			do_more = 1;
		} else if (strcmp(argv[i],"-s") == 0) {
			startupparm = 0x2;
			do_more = 1;
		} else if (strcmp(argv[i],"-o") == 0) {
			do_more = 0;
		} else if (strcmp(argv[i],"-cs") == 0) {
			contselftest = 1;
		} else {
			printf("\n%s is not a valid option\n", argv[i]);
			print_usage(argv[0]);
			exit(EXIT_FAILURE);
		}
	}
	if (ret == 0) {
		if (0xff != startupparm) {
			ret = TPM_Startup(startupparm, &tpm_errcode);
			if (tpm_errcode != 0) {
				printf("TPM_Startup returned error code "
				       "0x%08x\n", ret);
			}
		}
	}

	/* Sends the TSC_PhysicalPresence command to turn on physicalPresenceCMDEnable */
	if ((ret == 0) && do_more) {
		TSC_PhysicalPresence(0x20, &tpm_errcode);
	}

	/* Sends the TSC_PhysicalPresence command to turn on physicalPresence */
	if ((ret == 0) && do_more) {
		ret = TSC_PhysicalPresence(0x08, &tpm_errcode);
		if (tpm_errcode != 0) {
			printf("TSC_PhysicalPresence returned error code "
			       "0x%08x\n", tpm_errcode);
		}
	}
	/* Sends the TPM_Process_PhysicalEnable command to clear disabled */
	if ((ret == 0) && do_more) {
		ret = TPM_PhysicalEnable(&tpm_errcode);
		if (tpm_errcode != 0) {
			printf("TPM_PhysicalEnable returned error "
			       "code 0x%08x\n", tpm_errcode);
		}
	}
	/* Sends the TPM_Process_PhysicalSetDeactivated command to clear deactivated */
	if ((ret == 0) && do_more) {
		ret = TPM_PhysicalSetDeactivated(0, &tpm_errcode);
		if (tpm_errcode != 0) {
			printf("TPM_PhysicalSetDeactivated returned error "
			       "code 0x%08x\n", tpm_errcode);
		}
	}

	if ((ret == 0) && contselftest) {
		ret = TPM_ContinueSelfTest(&tpm_errcode);
		if (tpm_errcode != 0) {
			printf("TPM_ContinueSelfTest returned error "
			       "code 0x%08x\n", tpm_errcode);
		}
	}

	return ret;
}

