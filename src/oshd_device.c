#include "oshd.h"
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
    logger(LOG_CRIT, "TUN/TAP device error (fd: %i, revents: " AIO_PE_FMT ")",
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
    const netroute_t *route;
    node_id_t *me = node_id_find_local();

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

    // Lookup the source address in the routing table, if it doesn't exist or
    // another node owns it, take ownership and advertise it
    route = netroute_lookup(oshd.route_table, &pkt_hdr.src);
    if (!route || (route->owner != me && route->owner != NULL)) {
        netroute_add(oshd.route_table, &pkt_hdr.src,
            netaddr_max_prefixlen(pkt_hdr.src.type), me, true);
        node_queue_route_add_local(NULL, &pkt_hdr.src, 1);
    }

    // Lookup the destination address, if there is no route or we own it, drop
    // the packet
    route = netroute_lookup(oshd.route_table, &pkt_hdr.dest);
    if (!route || route->owner == me)
        return;

    if (route->owner) {
        // We have a node to send this packet to
        // next_hop should always be a valid node_t
        node_queue_packet(route->owner->next_hop, route->owner, DATA,
            pkt, pkt_size);
    } else {
        // This route is a broadcast
        node_queue_packet_broadcast(NULL, DATA, pkt, pkt_size);
    }

    if (logger_is_debugged(DBG_TUNTAP)) {
        char pkt_src[INET6_ADDRSTRLEN];
        char pkt_dest[INET6_ADDRSTRLEN];

        netaddr_ntop(pkt_src, sizeof(pkt_src), &pkt_hdr.src);
        netaddr_ntop(pkt_dest, sizeof(pkt_dest), &pkt_hdr.dest);

        logger_debug(DBG_TUNTAP, "%s: %s: %s -> %s (%zu bytes, to %s)",
            oshd.tuntap->dev_name, oshd.name, pkt_src, pkt_dest, pkt_size,
            netroute_owner_name(route));
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