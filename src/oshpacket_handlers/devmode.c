#include "oshd.h"
#include "logger.h"
#include <string.h>

bool oshpacket_handler_devmode(node_t *node, __attribute__((unused)) node_id_t *src,
    __attribute__((unused)) oshpacket_hdr_t *hdr, void *payload)
{
    const oshpacket_devmode_t *pkt = (const oshpacket_devmode_t *) payload;

    // The payload size is variable so we must verify it here
    if (   hdr->payload_size != sizeof(oshpacket_devmode_t)
        && hdr->payload_size != sizeof(oshpacket_devmode_dynamic_t))
    {
        logger(LOG_ERR, "%s: %s: Invalid DEVMODE size (%u bytes)",
            node->addrw, node->id->name, hdr->payload_size);
        return false;
    }

    // If both nodes have a TUN/TAP device but don't use the same mode
    // they are incompatible
    if (   oshd.device_mode != MODE_NODEVICE
        && pkt->devmode     != MODE_NODEVICE
        && pkt->devmode     != oshd.device_mode)
    {
        logger(LOG_ERR, "%s: %s: Incompatible device modes (local: %s, remote: %s)",
            node->addrw, node->id->name, device_mode_name(oshd.device_mode),
            device_mode_name(pkt->devmode));
        return node_queue_goodbye(node);
    }

    // If the device mode is dynamic we have to verify that both nodes share the
    // same network name and prefixes
    if (pkt->devmode == MODE_DYNAMIC) {
        const oshpacket_devmode_dynamic_t *pkt_dyn = (const oshpacket_devmode_dynamic_t *) payload;

        if (hdr->payload_size != sizeof(oshpacket_devmode_dynamic_t)) {
            logger(LOG_ERR, "%s: %s: Invalid dynamic DEVMODE size (%u bytes)",
                node->addrw, node->id->name, hdr->payload_size);
            return false;
        }

        if (memcmp(pkt_dyn->network_name, oshd.network_name, NODE_NAME_SIZE)) {
            logger(LOG_ERR, "%s: %s: Network name does not match",
                node->addrw, node->id->name);
            return false;
        }

        if (memcmp(&pkt_dyn->prefix6.ip6, &oshd.dynamic_prefix6.data.ip6,
                sizeof(oshd.dynamic_prefix6.data.ip6)))
        {
            logger(LOG_ERR, "%s: %s: Dynamic IPv6 prefix does not match",
                node->addrw, node->id->name);
            return false;
        }

        if (pkt_dyn->prefixlen6 != oshd.dynamic_prefixlen6) {
            logger(LOG_ERR, "%s: %s: Dynamic IPv6 prefix length does not match",
                node->addrw, node->id->name);
            return false;
        }

        if (memcmp(&pkt_dyn->prefix4.ip4, &oshd.dynamic_prefix4.data.ip4,
                sizeof(oshd.dynamic_prefix4.data.ip4)))
        {
            logger(LOG_ERR, "%s: %s: Dynamic IPv4 prefix does not match",
                node->addrw, node->id->name);
            return false;
        }

        if (pkt_dyn->prefixlen4 != oshd.dynamic_prefixlen4) {
            logger(LOG_ERR, "%s: %s: Dynamic IPv4 prefix length does not match",
                node->addrw, node->id->name);
            return false;
        }
    }

    return true;
}