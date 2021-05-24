#ifndef _OSH_NETPACKET_H
#define _OSH_NETPACKET_H

#include "netaddr.h"

typedef struct netpacket {
    uint16_t flags; // TUN/TAP packet flags
    uint16_t proto; // TUN/TAP packet protocol
    netaddr_t src;  // Packet source address
    netaddr_t dest; // Packet destination address
    uint8_t *data;  // Packet data
} netpacket_t;

bool netpacket_from_data(netpacket_t *packet, uint8_t *data, const bool tap);

#endif