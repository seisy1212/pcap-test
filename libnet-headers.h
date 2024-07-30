#ifndef LIBNET_HEADERS_H
#define LIBNET_HEADERS_H

#include <stdint.h>
#include <netinet/in.h>

// Ethernet header
struct libnet_ethernet_hdr {
    uint8_t  ether_dhost[6]; // destination host address
    uint8_t  ether_shost[6]; // source host address
    uint16_t ether_type;     // IP? ARP? RARP? etc
};

// IP header
struct libnet_ipv4_hdr {
    uint8_t  ip_hl_v;        // header length and version combined
    uint8_t  ip_tos;         // type of service
    uint16_t ip_len;         // total length
    uint16_t ip_id;          // identification
    uint16_t ip_off;         // fragment offset field
    uint8_t  ip_ttl;         // time to live
    uint8_t  ip_p;           // protocol
    uint16_t ip_sum;         // checksum
    struct   in_addr ip_src, ip_dst; // source and dest address
};

// TCP header
struct libnet_tcp_hdr {
    uint16_t th_sport;       // source port
    uint16_t th_dport;       // destination port
    uint32_t th_seq;         // sequence number
    uint32_t th_ack;         // acknowledgement number
    uint8_t  th_off_x2;      // data offset and reserved bits
    uint8_t  th_flags;       // control flags
    uint16_t th_win;         // window
    uint16_t th_sum;         // checksum
    uint16_t th_urp;         // urgent pointer
};

#endif // LIBNET_HEADERS_H

