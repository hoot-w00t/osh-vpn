#include "oshd.h"
#include "logger.h"

bool oshpacket_handler_data(client_t *c, node_id_t *src, oshpacket_t *pkt)
{
    tuntap_packethdr_t netpkt_hdr;

    // If we don't have a TUN/TAP device, ignore the packet
    if (!oshd.tuntap)
        return true;

    // Decode the network packet
    if (!tuntap_parse_packethdr(oshd.tuntap, &netpkt_hdr, pkt->payload, pkt->payload_size)) {
        logger(LOG_ERR, "%s: %s: Failed to decode received tunnel packet",
            c->addrw, c->id->name);
        return false;
    }

    // Log it
    if (logger_is_debugged(DBG_TUNTAP_TRAFFIC)) {
        char netpkt_hdr_src[INET6_ADDRSTRLEN];
        char netpkt_hdr_dest[INET6_ADDRSTRLEN];

        netaddr_ntop(netpkt_hdr_src, sizeof(netpkt_hdr_src), &netpkt_hdr.src);
        netaddr_ntop(netpkt_hdr_dest, sizeof(netpkt_hdr_dest), &netpkt_hdr.dest);
        logger_debug(DBG_TUNTAP_TRAFFIC, "%s: %s: %s <- %s (%zu bytes, from %s)",
            c->addrw, c->id->name, netpkt_hdr_dest, netpkt_hdr_src,
            pkt->payload_size, src->name);
    }

    // Write it
    return tuntap_write(oshd.tuntap, pkt->payload, pkt->payload_size);
}
