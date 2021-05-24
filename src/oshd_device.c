#include "oshd.h"
#include "oshd_route.h"
#include "node.h"
#include "netpacket.h"
#include "logger.h"
#include <string.h>
#include <errno.h>
#include <unistd.h>

// Read a network packet from TUN/TAP device and send it to its destinations
void oshd_read_tuntap_pkt(void)
{
    ssize_t pkt_size;
    uint8_t pkt[OSHPACKET_PAYLOAD_MAXSIZE];
    netpacket_t pkt_hdr;
    char pkt_src[INET6_ADDRSTRLEN];
    char pkt_dest[INET6_ADDRSTRLEN];
    netroute_t *route;

    if ((pkt_size = read(oshd.tuntap_fd, pkt, sizeof(pkt))) <= 0) {
        logger(LOG_CRIT, "%s: read(): %s", oshd.tuntap_dev, strerror(errno));
        oshd.run = false;
        return;
    }
    if (!netpacket_from_data(&pkt_hdr, pkt, oshd.is_tap)) {
        logger(LOG_ERR, "%s: Failed to parse network packet", oshd.tuntap_dev);
        return;
    }

    netaddr_ntop(pkt_src, sizeof(pkt_src), &pkt_hdr.src);
    netaddr_ntop(pkt_dest, sizeof(pkt_dest), &pkt_hdr.dest);

    // If the source address was not in our local routes, broadcast the new
    // route to the network
    if (netroute_add_local(&pkt_hdr.src))
        node_queue_add_route_broadcast(NULL, &pkt_hdr.src, 1);

    if ((route = netroute_find(&pkt_hdr.dest))) {
        // We have a route for this network destination
        logger(LOG_DEBUG, "%s: %s: %s -> %s (%i bytes, to %s)",
            oshd.tuntap_dev, oshd.name, pkt_src, pkt_dest, pkt_size,
            route->dest_node->name);
        node_queue_packet(route->dest_node->next_hop, route->dest_node->name,
            DATA, pkt, (uint16_t) pkt_size);
    } else {
        // We don't have a route for this network destination so we broadcast it
        logger(LOG_DEBUG, "%s: %s: %s -> %s (%i bytes, broadcast)",
            oshd.tuntap_dev, oshd.name, pkt_src, pkt_dest, pkt_size);
        node_queue_packet_broadcast(NULL, DATA, pkt, (uint16_t) pkt_size);
    }
}

// Write network packet to the TUN/TAP device
// Returns true on success, false on error
bool oshd_write_tuntap_pkt(uint8_t *data, uint16_t data_len)
{
    ssize_t written;

    if ((written = write(oshd.tuntap_fd, data, data_len)) != data_len) {
        if (written < 0) {
            // TODO: Only notify the user of the error if it is a non-fatal error
            logger(LOG_ERR, "%s: write(): %s", oshd.tuntap_dev, strerror(errno));
        } else {
            logger(LOG_ERR, "%s: write(): %i/%u bytes written", oshd.tuntap_dev, written, data_len);
        }

        // TODO: Only exit the program if we can no longer read/write to the TUN/TAP device
        oshd.run = false;
        return false;
    }
    return true;
}