#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <arpa/inet.h> 
#include "libnet-headers.h"

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;

        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        printf("%u bytes captured\n", header->caplen);

        struct libnet_ethernet_hdr *eth_hdr = (struct libnet_ethernet_hdr *) packet;
        const u_char* packet_ptr = packet + sizeof(struct libnet_ethernet_hdr);

        struct libnet_ipv4_hdr *ipv4_hdr = (struct libnet_ipv4_hdr *) packet_ptr;
        packet_ptr += (ipv4_hdr->ip_hl_v & 0x0F) * 4; 

        struct libnet_tcp_hdr *tcp_hdr = (struct libnet_tcp_hdr *) packet_ptr;

        if(ipv4_hdr->ip_p != 6)
            continue;

        printf("--------------------------------- ");
        printf("Ethernet Header\n");
        printf(" Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                eth_hdr->ether_shost[0], eth_hdr->ether_shost[1], eth_hdr->ether_shost[2],
                eth_hdr->ether_shost[3], eth_hdr->ether_shost[4], eth_hdr->ether_shost[5]);
        printf(" Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1], eth_hdr->ether_dhost[2],
                eth_hdr->ether_dhost[3], eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5]);
        printf("\n");
        printf("--------------------------------- ");

        printf("IP Header\n");
        printf(" Source IP: %s\n", inet_ntoa(ipv4_hdr->ip_src));
        printf(" Destination IP: %s\n", inet_ntoa(ipv4_hdr->ip_dst));
        printf("\n");
        printf("--------------------------------- ");

        printf("TCP Header\n");
        printf(" Source Port: %d\n", ntohs(tcp_hdr->th_sport));
        printf(" Destination Port: %d\n", ntohs(tcp_hdr->th_dport));
        printf("\n");
        printf("--------------------------------- ");
        
        u_int8_t data = (sizeof(struct libnet_ethernet_hdr) + (ipv4_hdr->ip_hl_v & 0x0F) * 4 + (tcp_hdr->th_off_x2 >> 4) * 4);

        printf("Payload data \n");
        for (int i = 0; i < 20; i++) {
            printf(" %02x", packet[data + i]);
        }
        printf("\n\n\n");
    }

    pcap_close(pcap);
    return 0;
}
