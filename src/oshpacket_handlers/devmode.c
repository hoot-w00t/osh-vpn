#include "oshd.h"
#include "logger.h"
#include <string.h>

bool oshpacket_handler_devmode(
    client_t *c,
    __attribute__((unused)) node_id_t *src,
    oshpacket_t *pkt)
{
    const oshpacket_devmode_t *payload = (const oshpacket_devmode_t *) pkt->payload;

    // The payload size is variable so we must verify it here
    if (   pkt->payload_size != sizeof(oshpacket_devmode_t)
        && pkt->payload_size != sizeof(oshpacket_devmode_dynamic_t))
    {
        logger(LOG_ERR, "%s: %s: Invalid DEVMODE size (%zu bytes)",
            c->addrw, c->id->name, pkt->payload_size);
        return false;
    }

    // If both nodes have a TUN/TAP device but don't use the same mode
    // they are incompatible
    if (   oshd.device_mode     != MODE_NODEVICE
        && payload->devmode     != MODE_NODEVICE
        && payload->devmode     != oshd.device_mode)
    {
        logger(LOG_ERR, "%s: %s: Incompatible device modes (local: %s, remote: %s)",
            c->addrw, c->id->name, device_mode_name(oshd.device_mode),
            device_mode_name(payload->devmode));
        return client_queue_goodbye(c);
    }

    // If the device mode is dynamic we have to verify that both nodes share the
    // same network name and prefixes
    if (payload->devmode == MODE_DYNAMIC) {
        const oshpacket_devmode_dynamic_t *payload_dyn = (const oshpacket_devmode_dynamic_t *) pkt->payload;

        if (pkt->payload_size != sizeof(oshpacket_devmode_dynamic_t)) {
            logger(LOG_ERR, "%s: %s: Invalid dynamic DEVMODE size (%zu bytes)",
                c->addrw, c->id->name, pkt->payload_size);
            return false;
        }

        if (memcmp(payload_dyn->network_name, oshd.network_name, NODE_NAME_SIZE)) {
            logger(LOG_ERR, "%s: %s: Network name does not match",
                c->addrw, c->id->name);
            return false;
        }

        if (memcmp(&payload_dyn->prefix6.ip6, &oshd.dynamic_prefix6.data.ip6,
                sizeof(oshd.dynamic_prefix6.data.ip6)))
        {
            logger(LOG_ERR, "%s: %s: Dynamic IPv6 prefix does not match",
                c->addrw, c->id->name);
            return false;
        }

        if (payload_dyn->prefixlen6 != oshd.dynamic_prefixlen6) {
            logger(LOG_ERR, "%s: %s: Dynamic IPv6 prefix length does not match",
                c->addrw, c->id->name);
            return false;
        }

        if (memcmp(&payload_dyn->prefix4.ip4, &oshd.dynamic_prefix4.data.ip4,
                sizeof(oshd.dynamic_prefix4.data.ip4)))
        {
            logger(LOG_ERR, "%s: %s: Dynamic IPv4 prefix does not match",
                c->addrw, c->id->name);
            return false;
        }

        if (payload_dyn->prefixlen4 != oshd.dynamic_prefixlen4) {
            logger(LOG_ERR, "%s: %s: Dynamic IPv4 prefix length does not match",
                c->addrw, c->id->name);
            return false;
        }
    }

    return true;
}
