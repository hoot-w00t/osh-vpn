#include "oshd.h"
#include "oshd_route.h"
#include "oshd_device_mode.h"
#include "node.h"
#include "netpacket.h"
#include "logger.h"
#include <string.h>
#include <errno.h>
#include <unistd.h>

// Return the name of the device mode
const char *device_mode_name(device_mode_t devmode)
{
    switch (devmode) {
        case MODE_NODEVICE: return "NoDevice";
        case MODE_TAP     : return "TAP";
        case MODE_TUN     : return "TUN";
             default      : return "Unknown mode";
    }
}

// Returns true if the device mode is a TAP device
bool device_mode_is_tap(device_mode_t devmode)
{
    switch (devmode) {
        case MODE_TAP:
            return true;

        default:
            return false;
    }
}

// Read network packets from the TUN/TAP device and send them to its destinations
void oshd_read_tuntap_pkt(void)
{
    size_t pkt_size;
    uint8_t pkt[OSHPACKET_PAYLOAD_MAXSIZE];
    netpacket_t pkt_hdr;
    oshd_route_t *route;

read_again:
    if (!tuntap_read(oshd.tuntap, pkt, sizeof(pkt), &pkt_size)) {
        oshd_stop();
        return;
    }

    if (pkt_size == 0) return;

    if (!netpacket_from_data(&pkt_hdr, pkt, oshd.tuntap->is_tap)) {
        logger(LOG_CRIT, "%s: Failed to parse network packet",
            oshd.tuntap->dev_name);
        return;
    }

    // If the source address was not in our local routes, broadcast the new
    // route to the network
    if (!oshd_route_find_local(oshd.routes, &pkt_hdr.src)) {
        oshd_route_add(oshd.routes, &pkt_hdr.src, node_id_find_local(), true);
        node_queue_route_add_local(NULL, &pkt_hdr.src, 1);
    }

    if ((route = oshd_route_find_remote(oshd.routes, &pkt_hdr.dest))) {
        // We have a route for this network destination
        node_queue_packet(route->dest_node->next_hop, route->dest_node->name,
            DATA, pkt, (uint16_t) pkt_size);
    } else {
        // We don't have a route for this network destination so we broadcast it
        node_queue_packet_broadcast(NULL, DATA, pkt, (uint16_t) pkt_size);
    }

    if (logger_is_debugged(DBG_TUNTAP)) {
        char pkt_src[INET6_ADDRSTRLEN];
        char pkt_dest[INET6_ADDRSTRLEN];

        netaddr_ntop(pkt_src, sizeof(pkt_src), &pkt_hdr.src);
        netaddr_ntop(pkt_dest, sizeof(pkt_dest), &pkt_hdr.dest);

        if (route) {
            logger_debug(DBG_TUNTAP, "%s: %s: %s -> %s (%zi bytes, to %s)",
                oshd.tuntap->dev_name, oshd.name, pkt_src, pkt_dest, pkt_size,
                route->dest_node->name);
        } else {
            logger_debug(DBG_TUNTAP, "%s: %s: %s -> %s (%zi bytes, broadcast)",
                oshd.tuntap->dev_name, oshd.name, pkt_src, pkt_dest, pkt_size);
        }
    }

    // This is the same as having a while(1) loop on the whole function, in the
    // current case I find using goto cleaner than while
    goto read_again;
}