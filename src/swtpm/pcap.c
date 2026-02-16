/* SPDX-License-Identifier: BSD-3-Clause */

/*
 * (c) Copyright IBM Corporation 2026
 *
 * Author: Stefan Berger <stefanb@linux.ibm.com>
 */

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/uio.h>
#include <arpa/inet.h>

#include <glib.h>

#include "pcap.h"
#include "utils.h"
#include "swtpm_utils.h"

/* ethernet header - not defined on Cygwin */
struct ethhdr
{
    uint8_t eth_dhost[6];
    uint8_t eth_shost[6];
    uint16_t eth_type;
#define ETHERTYPE_IP 0x0800
} __attribute__((packed));

struct section_header_block
{
    uint32_t block_type;
#define BLOCK_TYPE_SHB 0x0a0d0d0a
    uint32_t block_total_length;
    uint32_t byte_order_magic;
#define BYTE_ORDER_MAGIC 0x1a2b3c4d
    uint16_t major;
    uint16_t minor;
    uint64_t section_length;
    /* no options */
    uint32_t block_total_length2;
} __attribute__((packed));

struct enhanced_packet_block_hdr
{
    uint32_t block_type;
#define BLOCK_TYPE_EPB 0x00000006
    uint32_t block_total_length;
    uint32_t interface_id;
    uint32_t ts_hi;
    uint32_t ts_lo;
    uint32_t capture_len;
    uint32_t original_len;
};

struct interface_description_block
{
    uint32_t block_type;
#define BLOCK_TYPE_IDB 0x000000001
    uint32_t block_total_length;
    uint16_t link_type;
    uint16_t reserved;
    uint32_t snap_len;
    uint32_t block_total_length2;
}  __attribute__((packed));

struct packet {
    struct enhanced_packet_block_hdr epb_hdr;
    struct ethhdr ethhdr;
    struct ip     iphdr; // Cygwin has 'struct ip' but not 'struct iphdr'
    struct tcphdr tcphdr;
} __attribute__((packed));

static __attribute__((noinline)) uint32_t calc_checksum(void *array, size_t array_len)
{
     unsigned odd = array_len & 1;
     uint8_t *array8 = array;
     uint32_t check = 0;
     size_t i;

     array_len &= ~1;

     for (i = 0; i < array_len; i += 2)
         check += ((array8[i] << 8) + array8[i + 1]);

     if (odd)
         check += (array8[array_len] << 8);

     return check;
}

static void calc_ip_checksum(struct packet *packet)
{
    uint32_t check = 0;

    packet->iphdr.ip_sum = 0;

    check = calc_checksum(&packet->iphdr, sizeof(packet->iphdr));
    check = (check & 0xffff) + (check >> 16);

    packet->iphdr.ip_sum = htons(~check);
}

static void calc_tcp_checksum(struct packet *packet,
                              void *payload, size_t payload_len)
{
    struct {
        uint32_t saddr;
        uint32_t daddr;
        uint8_t  reserved;
        uint8_t  protocol;
        uint16_t tcpseglength;
    } pseudo = {
        .saddr = packet->iphdr.ip_src.s_addr,
        .daddr = packet->iphdr.ip_dst.s_addr,
        .reserved = 0,
        .protocol = packet->iphdr.ip_p,
        .tcpseglength = htons(sizeof(struct tcphdr) + payload_len),
    };
    uint32_t check;

    packet->tcphdr.th_sum = 0;

    check = calc_checksum(&pseudo, sizeof(pseudo)) +
            calc_checksum(&packet->tcphdr, sizeof(packet->tcphdr)) +
            calc_checksum(payload, payload_len);

    check = (check & 0xffff) + (check >> 16);
    packet->tcphdr.th_sum = htons(~check);
}

/* Calculate TCP and IP checksums on a packet */
static void calc_checksums(struct packet *packet,
                           void *payload, size_t payload_len,
                           struct pcap_state *ps)
{
    if ((ps->flags & PCAP_CHECKSUMS_F)) {
        calc_tcp_checksum(packet, payload, payload_len);
        calc_ip_checksum(packet);
    }
}

void pcap_state_init(struct pcap_state *ps)
{
    ps->fd = -1;
    ps->cseq = g_random_int();
    ps->sseq = g_random_int();
    ps->cport = g_random_int_range(50000, 55000);
    ps->tpmport = 2321;
}

void pcap_state_fd_set(struct pcap_state *ps, int fd)
{
    ps->fd = fd;
}

void pcap_state_flags_set(struct pcap_state *ps, unsigned int flags)
{
    ps->flags = flags;
}

/* Write the PCAP file header */
static int pcap_file_header_write(int fd)
{
    struct section_header_block shb = {
         .block_type = BLOCK_TYPE_SHB,
         .block_total_length = sizeof(shb),
         .byte_order_magic = BYTE_ORDER_MAGIC,
         .major = 1,
         .minor = 0,
         .section_length = 0,
         .block_total_length2 = sizeof(shb),
    };

    return write_full(fd, &shb, sizeof(shb));
}

static int pcap_packet_fill(struct packet *packet, bool to_tpm,
                            uint32_t tpm_packet_len, uint32_t orig_len,
                            struct pcap_state *ps)
{
    struct timespec ts;
    size_t hdrs_len;
    uint64_t ms;

    if (clock_gettime(CLOCK_REALTIME, &ts) < 0)
        return -1;

    ms = ts.tv_sec * 1000 * 1000 + ts.tv_nsec / 1000;
    hdrs_len = sizeof(struct ethhdr) + sizeof(struct ip) + sizeof(struct tcphdr);

    *packet = (struct packet){
        .epb_hdr = {
            .block_type = BLOCK_TYPE_EPB,
            .ts_hi = ms >> 32,
            .ts_lo = ms,
            .capture_len = hdrs_len + tpm_packet_len,
            .original_len = hdrs_len + orig_len,
        },
        .ethhdr = {
            .eth_type = htons(ETHERTYPE_IP),
        },
        .iphdr = {
            .ip_hl = sizeof(struct ip) >> 2,
            .ip_v = 4,
            .ip_tos = 0x10,
            .ip_len = htons(sizeof(struct ip) +
                            sizeof(struct tcphdr) +
                            tpm_packet_len),
            .ip_id = htons(0x069b),
            .ip_off = htons(IP_DF),
            .ip_ttl = 64,
            .ip_p = 6, /* TCP */
            .ip_sum = 0,
            .ip_src.s_addr = htonl(0x7f000001),
            .ip_dst.s_addr = htonl(0x7f000001),
        },
        .tcphdr =  {
            .th_sport = to_tpm ? htons(ps->cport) : htons(ps->tpmport),
            .th_dport = to_tpm ? htons(ps->tpmport) : htons(ps->cport),
            .th_seq = to_tpm ? htonl(ps->cseq) : htonl(ps->sseq),
            .th_ack = to_tpm ? htonl(ps->sseq) : htonl(ps->cseq),
            .th_off = sizeof(struct tcphdr) >> 2,
            .th_win = htons(0xffc4),
        },
    };
    return 0;
}

/*
 * Write a packet to the file. Take care of unaligned packets to due unaligned
 * overall size (32bit alignment). Also write a block_total_len at the end.
 */
static int pcap_write(int fd, struct packet *packet,
                      void *tpm_packet, uint32_t tpm_packet_len)
{
    size_t packet_len = sizeof(*packet);
    size_t filler_len = 4 - ((packet_len + tpm_packet_len) & 3);
    uint32_t block_total_len;
    uint8_t filler[3] = { 0, };
    struct iovec iov[4] =  {
         { .iov_base = packet,           .iov_len = packet_len },
         { .iov_base = tpm_packet,       .iov_len = tpm_packet_len },
         { .iov_base = filler,           .iov_len = filler_len },
         { .iov_base = &block_total_len, .iov_len = sizeof(block_total_len) },
    };
    size_t num_iov = ARRAY_LEN(iov);

    if (filler_len == 4) {
        /* no alignment needed */
        filler_len = 0;
        iov[2] = iov[3];
        num_iov--;
    }

    block_total_len = packet_len + tpm_packet_len + filler_len + sizeof(uint32_t);
    packet->epb_hdr.block_total_length = block_total_len;

    return writev_full(fd, iov, num_iov);
}

static int pcap_file_write_idb(struct pcap_state *ps)
{
    struct interface_description_block idb = {
        .block_total_length = sizeof(idb),
        .block_type = BLOCK_TYPE_IDB,
        .link_type = 1, // Ethernet
        .block_total_length2 = sizeof(idb),
    };

    return write_full(ps->fd, &idb, sizeof(idb));
}

/* Write a simulated TCP SYN/SYN+ACK/ACK or FIN/FIN+ACK/ACK exchange */
static int pcap_file_tcp_flags(struct pcap_state *ps, uint8_t flag)
{
    struct packet packet;

    pcap_packet_fill(&packet, true, 0, 0, ps);
    packet.tcphdr.th_flags = flag;
    if (flag == TH_SYN)
        packet.tcphdr.th_ack = 0;
    calc_checksums(&packet, NULL, 0, ps);

    if (pcap_write(ps->fd, &packet, NULL, 0) < 0)
        return -1;

    ps->cseq++;

    pcap_packet_fill(&packet, false, 0, 0, ps);
    packet.tcphdr.th_flags = flag | TH_ACK;
    calc_checksums(&packet, NULL, 0, ps);

    if (pcap_write(ps->fd, &packet, NULL, 0) < 0)
        return -1;

    ps->sseq++;

    pcap_packet_fill(&packet, true, 0, 0, ps);
    packet.tcphdr.th_flags = TH_ACK;
    calc_checksums(&packet, NULL, 0, ps);

    if (pcap_write(ps->fd, &packet, NULL, 0) < 0)
        return -1;

    return 0;
}

/* Write a simulated TCP SYN/SYN+ACK/ACK exchange */
static int pcap_file_tcp_start(struct pcap_state *ps)
{
    return pcap_file_tcp_flags(ps, TH_SYN);
}

/* Write a simulated TCP FIN/FIN+ACK/ACK exchange */
static int pcap_file_tcp_end(struct pcap_state *ps)
{
    return pcap_file_tcp_flags(ps, TH_FIN);
}

/*
 * Close the TPM command/response sequence with a simulated TCP FIN/FIN+ACK/ACK
 * and then close the pcap file descriptor.
 */
void pcap_state_fd_close(struct pcap_state *ps)
{
    if (ps->fd < 0)
        return;

    pcap_file_tcp_end(ps);

    close(ps->fd);
    ps->fd = -1;
}

/* Start writing to the pcap file */
int pcap_file_new(struct pcap_state *ps)
{
    if (ps->fd < 0)
        return -1;

    /* write the file header */
    if (pcap_file_header_write(ps->fd) < 0)
        return -1;

    if (pcap_file_write_idb(ps) < 0)
        return -1;

    return pcap_file_tcp_start(ps);
}

/*
 * Write a TPM packet to the pcap file. @to_tpm indicates whether it was sent
 * by the client (true; packet goes to TPM) or by the TPM (false).
 */
int pcap_packet_record_write(struct pcap_state *ps,
                             void *tpm_packet, uint32_t tpm_packet_len,
                             bool to_tpm)
{
    struct packet packet;
    int ret;

    if (ps->fd < 0)
        return 0;

    if (pcap_packet_fill(&packet, to_tpm,
                         tpm_packet_len, tpm_packet_len, ps) < 0)
        return -1;

    calc_checksums(&packet, tpm_packet, tpm_packet_len, ps);

    ret = pcap_write(ps->fd, &packet, tpm_packet, tpm_packet_len);
    if (ret < 0)
        return ret;

    if (to_tpm)
        ps->cseq += tpm_packet_len;
    else
        ps->sseq += tpm_packet_len;

    return 0;
}
