#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>

#define ETHER_ADDR_LEN 6

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

#endif