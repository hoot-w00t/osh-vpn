#ifndef _OSH_NETPACKET_H
#define _OSH_NETPACKET_H

#include "netaddr.h"

typedef struct netpacket {
    netaddr_t src;  // Packet source address
    netaddr_t dest; // Packet destination address
    uint8_t *data;  // Actual packet data
} netpacket_t;

bool netpacket_from_data(netpacket_t *packet, uint8_t *data, bool tap);

#endif