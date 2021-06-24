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
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <sys/un.h>
#include <getopt.h>
#include <signal.h>

#include "sys_dependencies.h"
#include "swtpm.h"
#include "tpm_bios.h"

/*
 * durations of the commands
 * On slow machines with much concurrency short timeouts may result in
 * errors; so we scale them up by 10.
 */
#define TPM_DURATION_SHORT   (2 * 10) /* seconds */
#define TPM_DURATION_MEDIUM (20 * 10) /* seconds */
#define TPM_DURATION_LONG   (60 * 10) /* seconds */

#define MIN(A, B) ((A) < (B) ? (A) : (B))

#define DEFAULT_TCP_PORT 6545

static char *tpm_device; /* e.g., /dev/tpm0 */

static char *tcp_hostname;
static int tcp_port = DEFAULT_TCP_PORT;

static char *unix_path;

static int parse_tcp_optarg(char *optarg, char **tcp_hostname, int *tcp_port)
{
	char *pos = strrchr(optarg, ':');
	int n;

	*tcp_port = DEFAULT_TCP_PORT;

	if (!pos) {
		/* <server> */
		*tcp_hostname = strdup(optarg);
		if (*tcp_hostname == NULL) {
			fprintf(stderr, "Out of memory.\n");
			return -1;
		}
		return 0;
	} else if (pos == optarg) {
		if (strlen(&pos[1]) != 0) {
			/* :<port>  (not just ':') */
			n = sscanf(&pos[1], "%u", tcp_port);
			if (n != 1) {
				fprintf(stderr, "Invalid port '%s'\n", &pos[1]);
				return -1;
			}
			if (*tcp_port >= 65536) {
				fprintf(stderr, "Port '%s' outside valid range.\n",
					&optarg[1]);
				return -1;
			}
		}

		*tcp_hostname = strdup("127.0.0.1");
		if (*tcp_hostname == NULL) {
			fprintf(stderr, "Out of memory.\n");
			return -1;
		}
	} else {
		/* <server>:<port> */
		n = sscanf(&pos[1], "%u", tcp_port);
		if (n != 1) {
			fprintf(stderr, "Invalid port '%s'\n", &pos[1]);
			return -1;
		}
		if (*tcp_port >= 65536) {
			fprintf(stderr, "Port '%s' outside valid range.\n",
				&optarg[1]);
			return -1;
		}

		*tcp_hostname = strndup(optarg, pos - optarg);
		if (*tcp_hostname == NULL) {
			fprintf(stderr, "Out of memory.\n");
			return -1;
		}
	}
	return 0;
}

static int open_connection(char *devname, char *tcp_device_hostname,
                           int tcp_device_port, const char *unix_path)
{
	int fd = -1;
	char *tcp_device_port_string = NULL;

	if (devname)
		goto use_device;

	if (tcp_device_hostname)
		goto use_tcp;

	if (unix_path) {
		struct sockaddr_un addr;
		size_t unix_path_len = strlen(unix_path) + 1;

		if (unix_path_len > sizeof(addr.sun_path)) {
			fprintf(stderr, "Socket path is too long.\n");
			return -1;
		}

		fd = socket(AF_UNIX, SOCK_STREAM, 0);
		if (fd > 0) {
			addr.sun_family = AF_UNIX;
			strncpy(addr.sun_path, unix_path, unix_path_len);

			if (connect(fd,
				    (struct sockaddr*)&addr, sizeof(addr)) < 0) {
				close(fd);
				fd = -1;
			}
		}

		if (fd < 0) {
			fprintf(stderr, "Could not connect using UnixIO socket.\n");
		}
		return fd;
	}

	if (getenv("TCSD_USE_TCP_DEVICE")) {
		struct addrinfo hints;
		struct addrinfo *ais = NULL, *ai;
		char portstr[10];
		int err;

		if ((tcp_device_hostname = getenv("TCSD_TCP_DEVICE_HOSTNAME")) == NULL)
			tcp_device_hostname = "localhost";
		if ((tcp_device_port_string = getenv("TCSD_TCP_DEVICE_PORT")) != NULL)
			tcp_device_port = atoi(tcp_device_port_string);
		else
			tcp_device_port = DEFAULT_TCP_PORT;

use_tcp:
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;

		snprintf(portstr, sizeof(portstr), "%u", tcp_device_port);

		err = getaddrinfo(tcp_device_hostname, portstr, &hints, &ais);
		if (err != 0) {
			fprintf(stderr, "getaddrinfo failed on host '%s': %s\n",
			        tcp_device_hostname, gai_strerror(err));
			return -1;
		}

		for (ai = ais; ai != NULL; ai = ai->ai_next) {
			fd = socket(ai->ai_family, ai->ai_socktype, 0);
			if (fd < 0)
				continue;

			if (connect(fd, (struct sockaddr *)ai->ai_addr,
			            ai->ai_addrlen) == 0)
				break;

			close(fd);
			fd = -1;
		}
		freeaddrinfo(ais);

		if (fd < 0) {
			fprintf(stderr, "Could not connect using TCP socket.\n");
		}
	} else {
use_device:
		if (!devname)
			devname = getenv("TPM_DEVICE");
		if (!devname)
			devname = "/dev/tpm0";

		fd = open(devname, O_RDWR);
		if (fd < 0) {
			fprintf(stderr, "Unable to open device '%s'.\n", devname );
		}
	}

	return fd;
}


static int talk(const void *cmd, size_t count, int *tpm_errcode,
		unsigned int to_seconds,
		struct tpm_resp_header *res, size_t res_size)
{
	ssize_t len;
	size_t pkt_len;
	int rc = -1;
	int fd, n;
	unsigned char buffer[1024];
	struct timeval timeout = {
		.tv_sec = to_seconds,
		.tv_usec = 0,
	};
	fd_set rfds;
	struct tpm_resp_header *hdr;

	fd = open_connection(tpm_device, tcp_hostname, tcp_port, unix_path);
	if (fd < 0) {
		goto err_exit;
	}

	len = write(fd, cmd, count);
	if (len < 0 || (size_t)len != count) {
		fprintf(stderr, "Write to file descriptor failed.\n");
		goto err_close_fd;
	}

	FD_ZERO(&rfds);
	FD_SET(fd, &rfds);

	n = select(fd + 1, &rfds, NULL, NULL, &timeout);
	if (n == 0) {
		fprintf(stderr, "TPM did not respond after %u seconds.\n",
			to_seconds);
		goto err_close_fd;
	} else if (n < 0) {
		fprintf(stderr, "Error on select call: %s\n", strerror(errno));
		goto err_close_fd;
	}

	len = read(fd, buffer, sizeof(buffer));
	if (len < 0) {
		fprintf(stderr, "Read from file descriptor failed.\n");
		goto err_close_fd;
	}

	if (len < 10) {
		fprintf(stderr, "Returned packet is too short.\n");
		goto err_close_fd;
	}

	hdr = (struct tpm_resp_header *)buffer;
	pkt_len = be32toh(hdr->length);
	if ((unsigned int)len != pkt_len) {
		fprintf(stderr, "Malformed response.\n");
		goto err_close_fd;
	}

	if (res)
		memcpy(res, buffer, MIN(pkt_len, res_size));

	*tpm_errcode = be32toh(hdr->result);

	rc = 0;

err_close_fd:
	close(fd);
	fd = -1;

err_exit:
	return rc;
}

static int TPM_Startup(unsigned char parm, int *tpm_errcode)
{
	struct tpm_startup tss  = {
		.hdr = {
			.tag = htobe16(TPM_TAG_RQU_COMMAND),
			.length = htobe32(sizeof(tss)),
			.ordinal = htobe32(TPM_ORD_Startup),
		},
		.startup_type = htobe16(parm),
	};

	return talk(&tss, sizeof(tss), tpm_errcode, TPM_DURATION_SHORT,
		    NULL, 0);
}

static int TSC_PhysicalPresence(unsigned short physical_presence,
				int *tpm_errcode)
{
	struct tsc_physical_presence tpp = {
		.hdr = {
			.tag = htobe16(TPM_TAG_RQU_COMMAND),
			.length = htobe32(sizeof(tpp)),
			.ordinal = htobe32(TPM_ORD_PhysicalPresence),
		},
		.physical_presence = htobe16(physical_presence),
	};

	return talk(&tpp, sizeof(tpp), tpm_errcode, TPM_DURATION_SHORT,
		    NULL, 0);
}

static int TPM_GetCapability_Subcap(uint32_t cap, uint32_t subcap,
				    struct tpm_resp_header *res, size_t res_size,
				    int *tpm_errcode)
{
	struct tpm_get_capability_subcap tgc = {
		.hdr = {
			.tag = htobe16(TPM_TAG_RQU_COMMAND),
			.length = htobe32(sizeof(tgc)),
			.ordinal = htobe32(TPM_ORD_GetCapability),
		},
		.cap = htobe32(cap),
		.subcap_size = htobe32(sizeof(tgc.subcap)),
		.subcap = htobe32(subcap),
	};

	return talk(&tgc, sizeof(tgc), tpm_errcode, TPM_DURATION_SHORT,
		    res, res_size);
}

static int TPM_PhysicalEnable(int *tpm_errcode)
{
	struct tpm_physical_enable tpe = {
		.hdr = {
			.tag = htobe16(TPM_TAG_RQU_COMMAND),
			.length = htobe32(sizeof(tpe)),
			.ordinal = htobe32(TPM_ORD_PhysicalEnable),
		},
	};

	return talk(&tpe, sizeof(tpe), tpm_errcode, TPM_DURATION_SHORT,
		    NULL, 0);
}

static int TPM_PhysicalSetDeactivated(unsigned char parm, int *tpm_errcode)
{
	struct tpm_physical_set_deactivated tpsd = {
		.hdr = {
			.tag = htobe16(TPM_TAG_RQU_COMMAND),
			.length = htobe32(sizeof(tpsd)),
			.ordinal = htobe32(TPM_ORD_PhysicalSetDeactivated),
		},
		.state = parm,
	};

	return talk(&tpsd, sizeof(tpsd), tpm_errcode, TPM_DURATION_SHORT,
		    NULL, 0);
}

static int TPM_ContinueSelfTest(int *tpm_errcode)
{
	struct tpm_continue_selftest tcs = {
		.hdr = {
			.tag = htobe16(TPM_TAG_RQU_COMMAND),
			.length = htobe32(sizeof(tcs)),
			.ordinal = htobe32(TPM_ORD_ContinueSelfTest),
		},
	};

	return talk(&tcs, sizeof(tcs), tpm_errcode, TPM_DURATION_LONG,
		    NULL, 0);
}

static int TPM2_Startup(unsigned short startup_type, int *tpm_errcode)
{
	struct tpm2_startup ts = {
		.hdr = {
			.tag = htobe16(TPM2_ST_NO_SESSIONS),
			.length = htobe32(sizeof(ts)),
			.ordinal = htobe32(TPM2_CC_Startup),
		},
		.startup_type = htobe16(startup_type),
	};

	return talk(&ts, sizeof(ts), tpm_errcode,
		    TPM_DURATION_SHORT, NULL, 0);
}

static int TPM2_IncrementalSelfTest(int *tpm_errcode)
{
	struct tpm2_incremental_selftest ts = {
		.hdr = {
			.tag = htobe16(TPM2_ST_NO_SESSIONS),
			.length = htobe32(sizeof(ts)),
			.ordinal = htobe32(TPM2_CC_IncrementalSelfTest),
		},
		.to_test = {
			.num_entries = htobe32(1),
			.algids = {
				htobe16(TPM2_ALG_SHA1),
			},
		},
	};

	return talk(&ts, sizeof(ts), tpm_errcode,
		    TPM_DURATION_SHORT, NULL, 0);
}

static int TPM2_HierarchyChangeAuth(int *tpm_errcode)
{
	struct tpm2_hierarchy_change_auth thca = {
		.hdr = {
			.tag = htobe16(TPM2_ST_SESSIONS),
			.length = htobe32(sizeof(thca)),
			.ordinal = htobe32(TPM2_CC_HierarchyChangeAuth),
		},
		.authhandle = htobe32(TPM2_RH_PLATFORM),
		.authblock_size = htobe32(sizeof(thca.authblock)),
		.authblock = {
			.handle = htobe32(TPM2_RS_PW),
			.nonce_size = htobe16(0),
			.cont = 1,
			.password_size = htobe16(0),
		},
		.newauth = {
			.size = htobe16(sizeof(thca.newauth.buffer)),
		},
	};

	int fd = open("/dev/urandom", O_RDONLY);
	if (fd >= 0) {
		ssize_t n = read(fd, &thca.newauth.buffer,
				sizeof(thca.newauth.buffer));
		close(fd);
		if (n != sizeof(thca.newauth.buffer)) {
				printf("Read of bytes from /dev/urandom failed");
			if (n < 0)
				printf(": %s", strerror(errno));
			printf("\n");
			return -1;
		}
	} else {
		printf("Could not open /dev/urandom: %s\n", strerror(errno));
		return -1;
	}

	return talk(&thca, sizeof(thca), tpm_errcode,
		    TPM_DURATION_SHORT, NULL, 0);
}

static int tpm12_bios(int do_more, int contselftest, unsigned char startupparm,
		      int unassert_pp, int ensure_activated)
{
	int ret = 0;
	int tpm_errcode;
	int tpm_error = 0;
	unsigned short physical_presence;
	struct tpm_get_capability_permflags_res perm_flags;

	if (ret == 0) {
		if (0xff != startupparm) {
			ret = TPM_Startup(startupparm, &tpm_errcode);
			if (tpm_errcode != 0) {
				tpm_error = 1;
				fprintf(stderr, "TPM_Startup(0x%02x) returned "
					"error code 0x%08x\n",
					startupparm, tpm_errcode);
			}
		}
	}

	/* Sends the TSC_PhysicalPresence command to turn on physicalPresenceCMDEnable */
	if ((ret == 0) && do_more) {
		physical_presence = TPM_PHYSICAL_PRESENCE_CMD_ENABLE;
		ret = TSC_PhysicalPresence(physical_presence, &tpm_errcode);
		if (tpm_errcode != 0) {
			tpm_error = 1;
			fprintf(stderr, "TSC_PhysicalPresence(CMD_ENABLE) "
				"returned error code 0x%08x\n", tpm_errcode);
		}
	}

	/* Sends the TSC_PhysicalPresence command to turn on physicalPresence */
	if ((ret == 0) && do_more) {
		physical_presence = TPM_PHYSICAL_PRESENCE_PRESENT;
		ret = TSC_PhysicalPresence(physical_presence, &tpm_errcode);
		if (tpm_errcode != 0) {
			tpm_error = 1;
			fprintf(stderr, "TSC_PhysicalPresence(PRESENT) "
				"returned error code 0x%08x\n", tpm_errcode);
		}
	}
	/* Determine the permanent flags */
	if ((ret == 0) && do_more && ensure_activated) {
		ret = TPM_GetCapability_Subcap(TPM_CAP_FLAG, TPM_CAP_FLAG_PERMANENT,
					       &perm_flags.hdr, sizeof(perm_flags),
					       &tpm_errcode);
		if (tpm_errcode != 0) {
			tpm_error = 1;
			fprintf(stderr, "TPM_GetCapability() returned error "
				"code 0x%08x\n", tpm_errcode);
		}
	}
	/* Sends the TPM_Process_PhysicalEnable command to clear disabled */
	if ((ret == 0) && do_more) {
		ret = TPM_PhysicalEnable(&tpm_errcode);
		if (tpm_errcode != 0) {
			tpm_error = 1;
			fprintf(stderr, "TPM_PhysicalEnable returned error "
				"code 0x%08x\n", tpm_errcode);
		}
	}
	/* Sends the TPM_Process_PhysicalSetDeactivated command to clear deactivated */
	if ((ret == 0) && do_more) {
		ret = TPM_PhysicalSetDeactivated(0, &tpm_errcode);
		if (tpm_errcode != 0) {
			tpm_error = 1;
			fprintf(stderr, "TPM_PhysicalSetDeactivated returned "
				"error code 0x%08x\n", tpm_errcode);
		}
		if (ensure_activated) {
			/* activation will require resetting the TPM */
			if (perm_flags.flags[TPM_PERM_FLAG_DEACTIVATED_IDX]) {
				ret = 0x81;
				printf("TPM requires a reset\n");
			}
		}
	}

	if ((ret == 0) && contselftest) {
		ret = TPM_ContinueSelfTest(&tpm_errcode);
		if (tpm_errcode != 0) {
			tpm_error = 1;
			fprintf(stderr, "TPM_ContinueSelfTest returned error "
				"code 0x%08x\n", tpm_errcode);
		}
	}

	/* Sends the TSC_PhysicalPresence command to turn on physicalPresenceCMDEnable */
	if ((ret == 0) && unassert_pp) {
		physical_presence = TPM_PHYSICAL_PRESENCE_CMD_ENABLE;
		ret = TSC_PhysicalPresence(physical_presence, &tpm_errcode);
		if (tpm_errcode != 0) {
			tpm_error = 1;
			fprintf(stderr,
				"TSC_PhysicalPresence(CMD_ENABLE) returned "
				"error code 0x%08x\n", tpm_errcode);
		}
	}

	/* Sends the TSC_PhysicalPresence command to unassert physical presence and lock it */
	if ((ret == 0) && unassert_pp) {
		physical_presence = TPM_PHYSICAL_PRESENCE_NOTPRESENT |
				    TPM_PHYSICAL_PRESENCE_LOCK;
		ret = TSC_PhysicalPresence(physical_presence, &tpm_errcode);
		if (tpm_errcode != 0) {
			tpm_error = 1;
			fprintf(stderr, "TSC_PhysicalPresence(NOT_PRESENT|LOCK) "
				"returned error code 0x%08x\n", tpm_errcode);
		}
	}

	if (!ret && tpm_error)
		ret = 0x80;

	return ret;
}

static int tpm2_bios(int contselftest, unsigned char startupparm,
		     int set_password)
{
	int ret = 0;
	int tpm_errcode;
	int tpm_error = 0;

	if (ret == 0) {
		if (0xff != startupparm) {
			ret = TPM2_Startup(startupparm, &tpm_errcode);
			if (tpm_errcode != 0) {
				tpm_error = 1;
				printf("TPM2_Startup returned error code "
				       "0x%08x\n", tpm_errcode);
			}
		}
	}

	if ((ret == 0) && contselftest) {
		ret = TPM2_IncrementalSelfTest(&tpm_errcode);
		if (tpm_errcode != 0) {
			tpm_error = 1;
			printf("TPM2_ImcrementalSelfTest returned error "
			       "code 0x%08x\n", tpm_errcode);
		}
	}

	if ((ret == 0) && set_password) {
		ret = TPM2_HierarchyChangeAuth(&tpm_errcode);
		if (tpm_errcode != 0) {
			tpm_error = 1;
			printf("TPM2_HierarchyChangeAuth returned error "
			       "code 0x%08x\n", tpm_errcode);
		}
	}

	if (!ret && tpm_error)
		ret = 0x80;

	return ret;
}

static void versioninfo(void)
{
	printf(
"TPM emulator BIOS emulator version %d.%d.%d, Copyright (c) 2015 IBM Corp.\n"
,SWTPM_VER_MAJOR, SWTPM_VER_MINOR, SWTPM_VER_MICRO);
}

static void print_usage(const char *prgname)
{
	versioninfo();
	printf(
"\n"
"%s [options]\n"
"\n"
"Runs TPM_Startup (unless -n), then (unless -o) sets PP, enable, activate \n"
"and finally (using -u) gives up physical presence (PP)\n"
"\n"
"The following options are supported:\n"
"\t--tpm-device <device>  use the given device; default is /dev/tpm0\n"
"\t--tcp [<host>]:[<prt>] connect to TPM on given host and port;\n"
"\t                       default host is 127.0.0.1, default port is %u\n"
"\t--unix <path>          connect to TPM using UnixIO socket\n"
"\t--tpm2                 initialize a TPM2\n"
"\t-c                     startup clear (default)\n"
"\t-s                     startup state\n"
"\t-d                     startup deactivate (no effect on TPM2)\n"
"\t-n                     no startup\n"
"\t-o                     startup only\n"
"\t-cs                    run TPM_ContinueSelfTest on TPM1.2\n"
"\t                       run TPM2_IncrementalSelfTest on TPM2\n"
"\t-ea                    make sure that the TPM 1.2 is activated;\n"
"\t                       terminate with exit code 129 if the TPM\n"
"\t                       needs to be reset\n"
"\t-u                     give up physical presence\n"
"\t                       on TPM 2 set the platform hierarchy to a\n"
"\t                       random password\n"
"\t-v                     display version and exit\n"
"\t-h                     display this help screen and exit\n"
, prgname, DEFAULT_TCP_PORT);
}

int main(int argc, char *argv[])
{
	int   ret = 0;
	int   do_more = 1;
	int   ensure_activated = 0;
	int   contselftest = 0;
	unsigned char  startupparm = 0x1;      /* parameter for TPM_Startup(); */
	unsigned char  startupparm_tpm2 = 0x00;
	int   unassert_pp = 0;
	int   tpm2 = 0;
	static struct option long_options[] = {
		{"tpm-device", required_argument, NULL, 'D'},
		{"tcp", required_argument, NULL, 'T'},
		{"unix", required_argument, NULL, 'U'},
		{"c", no_argument, NULL, 'c'},
		{"d", no_argument, NULL, 'd'},
		{"h", no_argument, NULL, 'h'},
		{"v", no_argument, NULL, 'v'},
		{"n", no_argument, NULL, 'n'},
		{"s", no_argument, NULL, 's'},
		{"o", no_argument, NULL, 'o'},
		{"cs", no_argument, NULL, 'C'},
		{"ea", no_argument, NULL, 'E'},
		{"u", no_argument, NULL, 'u'},
		{"tpm2", no_argument, NULL, '2'},
		{NULL, 0, NULL, 0},
	};
	int opt, option_index = 0;

#ifdef __NetBSD__
	while ((opt = getopt_long(argc, argv, "D:T:U:cdhvnsoCEu2", long_options,
				&option_index)) != -1) {
#else
	while ((opt = getopt_long_only(argc, argv, "", long_options,
				&option_index)) != -1) {
#endif
		switch (opt) {
		case 'D':
			tpm_device = strdup(optarg);
			if (!tpm_device) {
				fprintf(stderr, "Out of memory.");
				return EXIT_FAILURE;
			}
			break;
		case 'T':
			if (parse_tcp_optarg(optarg, &tcp_hostname, &tcp_port) < 0) {
				return EXIT_FAILURE;
			}
			break;
		case 'U':
			unix_path = strdup(optarg);
			if (!unix_path) {
				fprintf(stderr, "Out of memory.\n");
				return EXIT_FAILURE;
			}
			break;
		case 'c':
			startupparm = TPM_ST_CLEAR;
			startupparm_tpm2 = TPM2_SU_CLEAR;
			do_more = 1;
			break;
		case 'd':
			startupparm = TPM_ST_DEACTIVATED;
			startupparm_tpm2 = 0xff;
			do_more = 0;
			break;
		case 'h':
			print_usage(argv[0]);
			return EXIT_SUCCESS;
		case 'n':
			startupparm = 0xff;
			startupparm_tpm2 = 0xff;
			do_more = 1;
			break;
		case 's':
			startupparm = TPM_ST_STATE;
			startupparm_tpm2 = TPM2_SU_STATE;
			do_more = 1;
			break;
		case 'o':
			do_more = 0;
			break;
		case 'C':
			contselftest = 1;
			break;
		case 'E':
			ensure_activated = 1;
			break;
		case 'u':
			unassert_pp = 1;
			break;
                case '2':
                        tpm2 = 1;
                        break;
		default:
			print_usage(argv[0]);
			return EXIT_FAILURE;
		}
	}

	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
		fprintf(stderr, "Could not install signal handler for SIGPIPE.");
		return EXIT_FAILURE;
	}

	if (tpm2) {
		ret = tpm2_bios(contselftest, startupparm_tpm2,
				unassert_pp);
	} else {
		ret = tpm12_bios(do_more, contselftest, startupparm,
				 unassert_pp, ensure_activated);
	}

	return ret;
}
