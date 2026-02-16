/* SPDX-License-Identifier: BSD-3-Clause */

/*
 * (c) Copyright IBM Corporation 2026
 *
 * Author: Stefan Berger <stefanb@linux.ibm.com>
 */

#ifndef _SWTPM_PCAP_H
#define _SWTPM_PCAP_H

struct pcap_state {
    int fd;
    unsigned int flags;
#define PCAP_CHECKSUMS_F (1 << 0)
    uint32_t cseq;
    uint32_t sseq;
    uint32_t cport; // client port
    uint32_t tpmport;
};

void pcap_state_init(struct pcap_state *ps);
void pcap_state_fd_set(struct pcap_state *ps, int fd);
void pcap_state_fd_close(struct pcap_state *ps);
void pcap_state_flags_set(struct pcap_state *ps, unsigned int flags);
int pcap_file_new(struct pcap_state *ps);
int pcap_packet_record_write(struct pcap_state *ps,
                             void *tpm_packet, uint32_t tpm_packet_len,
                             bool to_tpm);

#endif /* _SWTPM_PCAP_H */
