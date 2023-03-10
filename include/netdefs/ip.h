#ifndef _OSH_NETDEFS_IP_H
#define _OSH_NETDEFS_IP_H

#include "sock.h"
#include <stdint.h>

// Return the IP version from an IP packet header
// The pointer must have at least one byte allocated
static inline uint8_t IP_HDR_VERSION(const void *ip_pkt)
{
    return (((const uint8_t *) ip_pkt)[0] & 0xF0u) >> 4;
}

// IPv4 header
struct __attribute__((packed)) ipv4_hdr {
    uint8_t     version_ihl;
    uint8_t     tos;
    uint16_t    total_length;
    uint16_t    id;
    uint16_t    frag_offset;
    uint8_t     ttl;
    uint8_t     proto;
    uint16_t    checksum;
    uint32_t    saddr;
    uint32_t    daddr;
};

// IPv6 header
struct __attribute__((packed)) ipv6_hdr {
    uint32_t        flow_label;
    uint16_t        payload_length;
    uint8_t         next_header;
    uint8_t         hop_limit;
    struct in6_addr src_addr;
    struct in6_addr dst_addr;
};

// IPv6 pseudo-header (for ICMP6 checksum)
struct __attribute__((packed)) ipv6_pseudo {
    struct in6_addr src;
    struct in6_addr dst;
    uint32_t        length;
    uint8_t         zero[3];
    uint8_t         next_header;
};

// Get the traffic class from ipv6_hdr->flow_label (host byte order)
#define ipv6_hdr_traffic_class(fl) (((fl) >> 24) & 0xFF)

// Get the flow label from ipv6_hdr->flow_label (host byte order)
#define ipv6_hdr_flow_label(fl) ((fl) & 0xFFFFFF)

#endif
