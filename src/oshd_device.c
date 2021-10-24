#include "oshd.h"
#include "oshd_route.h"
#include "oshd_device_mode.h"
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

// Error callback for the TUN/TAP device
// Stops the daemon on any error
static void device_aio_error(aio_event_t *event, aio_poll_event_t revents)
{
    logger(LOG_CRIT, "TUN/TAP device error (fd: %i, revents: %i)",
        event->fd, revents);
    aio_event_del(event);
    oshd_stop();
}

// Read callback the TUN/TAP device
// Read available packets from the device and route them on the network
// TODO: Refactor this to use the TUN/TAP device from userdata instead of the
//       global one
//       Not sure why Osh would ever need to manage multiple TUN/TAP devices but
//       it would be cleaner anyways
static void device_aio_read(__attribute__((unused)) aio_event_t *event)
{
    // Only process packets from the TUN/TAP device if the daemon is running
    if (!oshd.run)
        return;

    size_t pkt_size;
    uint8_t pkt[OSHPACKET_PAYLOAD_MAXSIZE];
    netpacket_t pkt_hdr;
    oshd_route_t *route;

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
            logger_debug(DBG_TUNTAP, "%s: %s: %s -> %s (%zu bytes, to %s)",
                oshd.tuntap->dev_name, oshd.name, pkt_src, pkt_dest, pkt_size,
                route->dest_node->name);
        } else {
            logger_debug(DBG_TUNTAP, "%s: %s: %s -> %s (%zu bytes, broadcast)",
                oshd.tuntap->dev_name, oshd.name, pkt_src, pkt_dest, pkt_size);
        }
    }
}

// Add an aio event for the TUN/TAP device
void oshd_device_add(tuntap_t *tuntap)
{
    aio_event_add_inl(oshd.aio,
        tuntap_pollfd(tuntap),
        AIO_READ,
        NULL,
        NULL,
        NULL,
        device_aio_read,
        NULL,
        device_aio_error);
}