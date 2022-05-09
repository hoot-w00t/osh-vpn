#include "oshd.h"
#include "logger.h"

bool oshpacket_handler_devmode(node_t *node, __attribute__((unused)) node_id_t *src,
    __attribute__((unused)) oshpacket_hdr_t *hdr, void *payload)
{
    const oshpacket_devmode_t *pkt = (const oshpacket_devmode_t *) payload;

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

    return true;
}