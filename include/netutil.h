#ifndef _OSH_NETUTIL_H
#define _OSH_NETUTIL_H

#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>

// IPv4 definitions

// ARP packet structure for IPv4 ARP request/reply
struct __attribute__((packed)) arp_v4r {
    uint16_t hw_type;
    uint16_t proto_type;
    uint8_t  hw_addr_length;
    uint8_t  proto_addr_length;
    uint16_t operation;

    uint8_t  sender_hw_addr[6];
    uint32_t sender_proto_addr;
    uint8_t  target_hw_addr[6];
    uint32_t target_proto_addr;
};

// IPv6 definitions

// IPv6 header
struct __attribute__((packed)) ipv6_hdr {
    uint32_t flow_label;
    uint16_t payload_length;
    uint8_t  next_header;
    uint8_t  hop_limit;
    uint8_t  src_addr[16];
    uint8_t  dst_addr[16];
};

// IPv6 pseudo-header used with ICMP6 checksum
struct __attribute__((packed)) ipv6_pseudo {
    struct in6_addr src;
    struct in6_addr dst;
    uint32_t length;
    uint32_t next;
};

// IPv6 Neighbor Sollicitation
struct __attribute__((packed)) ipv6_icmp_ns {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;

    uint32_t reserved;
    uint8_t  target_address[16];
};

struct __attribute__((packed)) ipv6_icmp_ns_pkt {
    struct ipv6_hdr hdr;
    struct ipv6_icmp_ns icmp;
};

// IPv6 Neighbor Advertisement
struct __attribute__((packed)) ipv6_icmp_na {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;

    uint32_t flags;
    uint8_t  target_address[16];

    uint8_t  mac_addr_type;
    uint8_t  length;
    uint8_t  mac_addr[6];
};

struct __attribute__((packed)) ipv6_icmp_na_pkt {
    struct ipv6_hdr hdr;
    struct ipv6_icmp_na icmp;
};

// Defined in netutil/icmp.c
uint16_t icmp4_checksum(const void *data, size_t data_len);
uint16_t icmp6_checksum(const struct ipv6_pseudo *pseudo, const void *data,
    size_t data_len);

#endif
