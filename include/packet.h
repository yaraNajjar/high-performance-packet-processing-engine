#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>
#include <netinet/if_ether.h>

#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN ETH_ALEN
#endif

struct ethernet_header {

    uint8_t dest_mac[ETHER_ADDR_LEN];

    uint8_t src_mac[ETHER_ADDR_LEN];

    uint16_t ether_type;

};

struct ip_header {

    uint8_t version_ihl;

    uint8_t tos;

    uint16_t total_length;

    uint16_t identification;

    uint16_t flags_fragment;

    uint8_t ttl;

    uint8_t protocol;

    uint16_t header_checksum;

    uint32_t src_ip;

    uint32_t dst_ip;

};

struct tcp_header {

    uint16_t src_port;

    uint16_t dst_port;

    uint32_t seq_number;

    uint32_t ack_number;

    uint16_t offset_reserved_flags;

    uint16_t window;

    uint16_t checksum;

    uint16_t urgent_pointer;

};

// UDP Header
struct udp_header {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
};

// ICMP Header
struct icmp_header {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint32_t rest_of_header; 
};

void parse_packet(const unsigned char *packet);

#endif