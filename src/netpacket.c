#include "netpacket.h"
#include <string.h>

static const uint8_t ETH_DEST_OFFSET = 0;
static const uint8_t ETH_SRC_OFFSET  = 6;
static const uint8_t IP4_DEST_OFFSET = 16;
static const uint8_t IP4_SRC_OFFSET  = 12;
static const uint8_t IP6_DEST_OFFSET = 24;
static const uint8_t IP6_SRC_OFFSET  = 8;

#define ip_hdr_version(ip_pkt) (((ip_pkt)[0] & 0xF0) >> 4)

// Decode TUN/TAP packet header into *packet
// tap should be true if the device uses layer 2 (TAP)
bool netpacket_from_data(netpacket_t *packet, uint8_t *data, bool tap)
{
    packet->data = data;
    if (tap) {
        // Ethernet frame
        return    netaddr_dton(&packet->dest, MAC, data + ETH_DEST_OFFSET)
               && netaddr_dton(&packet->src,  MAC, data + ETH_SRC_OFFSET);
    } else {
        const uint8_t ip_version = ip_hdr_version(data);

        if (ip_version == 4) {
            // IPv4 packet
            return    netaddr_dton(&packet->dest, IP4, data + IP4_DEST_OFFSET)
                   && netaddr_dton(&packet->src,  IP4, data + IP4_SRC_OFFSET);
        } else if (ip_version == 6) {
            // IPv6 packet
            return    netaddr_dton(&packet->dest, IP6, data + IP6_DEST_OFFSET)
                   && netaddr_dton(&packet->src,  IP6, data + IP6_SRC_OFFSET);
        } else {
            // Invalid packet
            memset(&packet->dest, 0, sizeof(netaddr_t));
            memset(&packet->src,  0, sizeof(netaddr_t));
            return false;
        }
    }
}