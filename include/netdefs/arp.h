#ifndef _OSH_NETDEFS_ARP_H
#define _OSH_NETDEFS_ARP_H

#include "netdefs/ether.h"
#include "netdefs/ip.h"
#include <stdbool.h>

// ARP hardware type and length
#define ARP_HW_ETHER        1
#define ARP_HW_ETHER_LEN    ETH_ALEN

// ARP protocol type and length
#define ARP_PROTO_IP        ETH_P_IP
#define ARP_PROTO_IP_LEN    sizeof(struct in_addr)

// ARP operations
#define ARP_OP_REQUEST      1
#define ARP_OP_REPLY        2

// ARP header
struct __attribute__((packed)) arp_hdr {
    uint16_t hw;            // hardware address type
    uint16_t proto;         // protocol address type
    uint8_t  hw_len;        // hardware address length
    uint8_t  proto_len;     // protocol address length
    uint16_t op;            // ARP operation
    // followed by:
    //    sender hardware address
    //    sender protocol address
    //    target hardware address
    //    target protocol address
};

// Define ARP packet with given hardware/protocol types
// Packet structure:
//   struct arp_HW_PROTO
//
// Function that checks if a packet has the correct hardware/protocol types and
// valid lengths (packet fields must be in network byte order):
//   static inline bool arp_is_HW_PROTO(...)
#define _ARP_DEFINE_PACKET(HW_TYPE, HW_LEN, HW_NAME,                            \
                           PROTO_TYPE, PROTO_LEN, PROTO_NAME)                   \
    struct __attribute__((packed)) arp_ ## HW_NAME ## _ ## PROTO_NAME {         \
        struct arp_hdr hdr;                                                     \
        uint8_t s_hwaddr[HW_LEN];                                               \
        uint8_t s_protoaddr[PROTO_LEN];                                         \
        uint8_t t_hwaddr[HW_LEN];                                               \
        uint8_t t_protoaddr[PROTO_LEN];                                         \
    };                                                                          \
                                                                                \
    static inline bool arp_is_ ## HW_NAME ## _ ## PROTO_NAME (                  \
        const struct arp_ ## HW_NAME ## _ ## PROTO_NAME *pkt,                   \
        const size_t pkt_size)                                                  \
    {                                                                           \
        return pkt_size             == sizeof(*pkt)                             \
            && pkt->hdr.hw          == htons(HW_TYPE)                           \
            && pkt->hdr.proto       == htons(PROTO_TYPE)                        \
            && pkt->hdr.hw_len      == HW_LEN                                   \
            && pkt->hdr.proto_len   == PROTO_LEN;                               \
    }

_ARP_DEFINE_PACKET(ARP_HW_ETHER, ARP_HW_ETHER_LEN, ether, ARP_PROTO_IP, ARP_PROTO_IP_LEN, ip)

#endif
