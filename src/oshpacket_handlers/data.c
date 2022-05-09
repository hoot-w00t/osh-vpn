#include "oshd.h"
#include "logger.h"
#include "netpacket.h"

bool oshpacket_handler_data(node_t *node, node_id_t *src,
    oshpacket_hdr_t *hdr, void *payload)
{
    netpacket_t netpkt;

    // If we don't have a TUN/TAP device, ignore the packet
    if (!oshd.tuntap)
        return true;

    // Decode the network packet
    if (!netpacket_from_data(&netpkt, payload, oshd.tuntap->is_tap)) {
        logger(LOG_ERR, "%s: %s: Failed to decode received tunnel packet",
            node->addrw, node->id->name);
        return false;
    }

    // Log it
    if (logger_is_debugged(DBG_TUNTAP)) {
        char netpkt_src[INET6_ADDRSTRLEN];
        char netpkt_dest[INET6_ADDRSTRLEN];

        netaddr_ntop(netpkt_src, sizeof(netpkt_src), &netpkt.src);
        netaddr_ntop(netpkt_dest, sizeof(netpkt_dest), &netpkt.dest);
        logger_debug(DBG_TUNTAP, "%s: %s: %s <- %s (%u bytes, from %s)",
            node->addrw, node->id->name, netpkt_dest, netpkt_src,
            hdr->payload_size, src->name);
    }

    // Write it
    return tuntap_write(oshd.tuntap, payload, hdr->payload_size);
}