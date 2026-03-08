#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include "../include/packet.h"

void parse_packet(const unsigned char *packet) {

    // Ethernet header
    struct ethernet_header *eth = (struct ethernet_header *)packet;

    printf("Source MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           eth->src_mac[0], eth->src_mac[1], eth->src_mac[2],
           eth->src_mac[3], eth->src_mac[4], eth->src_mac[5]);

    printf("Destination MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           eth->dest_mac[0], eth->dest_mac[1], eth->dest_mac[2],
           eth->dest_mac[3], eth->dest_mac[4], eth->dest_mac[5]);

    // IP header
    struct ip_header *ip = (struct ip_header *)(packet + sizeof(struct ethernet_header));
    uint8_t protocol = ip->protocol;

    // Calculate the IP header length in bytes
    int ip_header_len = (ip->version_ihl & 0x0F) * 4;

    printf("Source IP: %s\n", inet_ntoa(*(struct in_addr *)&ip->src_ip));
    printf("Destination IP: %s\n", inet_ntoa(*(struct in_addr *)&ip->dst_ip));

    // TCP / UDP / ICMP parsing
    switch(protocol) {
        case 6: { // TCP
            struct tcp_header *tcp = (struct tcp_header *)(packet + sizeof(struct ethernet_header) + ip_header_len);
            printf("Protocol: TCP\n");
            printf("Source Port: %d\n", ntohs(tcp->src_port));
            printf("Destination Port: %d\n", ntohs(tcp->dst_port));
            break;
        }
        case 17: { // UDP
            struct udp_header *udp = (struct udp_header *)(packet + sizeof(struct ethernet_header) + ip_header_len);
            printf("Protocol: UDP\n");
            printf("Source Port: %d\n", ntohs(udp->src_port));
            printf("Destination Port: %d\n", ntohs(udp->dst_port));
            break;
        }
        case 1: { // ICMP
            struct icmp_header *icmp = (struct icmp_header *)(packet + sizeof(struct ethernet_header) + ip_header_len);
            printf("Protocol: ICMP\n");
            printf("ICMP Type: %d, Code: %d\n", icmp->type, icmp->code);
            break;
        }
        default:
            printf("Protocol: Other (%d)\n", protocol);
    }

    printf("\n");
}