#ifndef _OSH_NETDEFS_ETHER_H
#define _OSH_NETDEFS_ETHER_H

#include "netdefs/ethertypes.h"
#include <stdint.h>

#ifndef ETH_ALEN
// Ethernet address length
#define ETH_ALEN        6
#endif

#ifndef ETH_HLEN
// Ethernet header length (without FCS)
#define ETH_HLEN        14
#endif

// Ethernet address
struct __attribute__((packed)) eth_addr {
    uint8_t addr[ETH_ALEN];
};

// Ethernet header (without FCS)
struct __attribute__((packed)) eth_hdr {
    struct eth_addr dest;
    struct eth_addr src;
    uint16_t ethertype;
};

#endif
