#include "netpacket.h"
#include <netinet/ether.h>
#include <string.h>

static const uint8_t ETH_DEST_OFFSET = 4;
static const uint8_t ETH_SRC_OFFSET  = 10;
static const uint8_t IP4_DEST_OFFSET = 20;
static const uint8_t IP4_SRC_OFFSET  = 16;
static const uint8_t IP6_DEST_OFFSET = 28;
static const uint8_t IP6_SRC_OFFSET  = 12;

// Decode TUN/TAP packet header into *packet
// tap should be true if the device uses layer 2 (TAP)
bool netpacket_from_data(netpacket_t *packet, uint8_t *data, const bool tap)
{
    packet->data = data;
    packet->flags = (data[0] << 8) | data[1];
    packet->proto = (data[2] << 8) | data[3];

    if (tap) {
        return    netaddr_dton(&packet->dest, MAC, data + ETH_DEST_OFFSET)
               && netaddr_dton(&packet->src,  MAC, data + ETH_SRC_OFFSET);
    } else if (packet->proto == ETH_P_IP) {
        return    netaddr_dton(&packet->dest, IP4, data + IP4_DEST_OFFSET)
               && netaddr_dton(&packet->src,  IP4, data + IP4_SRC_OFFSET);
    } else if (packet->proto == ETH_P_IPV6) {
        return    netaddr_dton(&packet->dest, IP6, data + IP6_DEST_OFFSET)
               && netaddr_dton(&packet->src,  IP6, data + IP6_SRC_OFFSET);
    } else {
        memset(&packet->dest, 0, sizeof(netaddr_t));
        memset(&packet->src,  0, sizeof(netaddr_t));
        return false;
    }
}