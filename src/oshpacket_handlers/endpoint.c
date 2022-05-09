#include "node.h"
#include "logger.h"
#include <string.h>

bool oshpacket_handler_endpoint(node_t *node, __attribute__((unused)) node_id_t *src,
    oshpacket_hdr_t *hdr, void *payload)
{
    if (node->state_exg) {
        // Broadcast the endpoints to our end of the network
        logger_debug(DBG_STATEEXG,
            "%s: %s: State exchange: Relaying ENDPOINT packet",
            node->addrw, node->id->name);
        node_queue_packet_broadcast(node, ENDPOINT, payload,
            hdr->payload_size);
    }

    const size_t count = hdr->payload_size / sizeof(oshpacket_endpoint_t);
    const oshpacket_endpoint_t *endpoints = (const oshpacket_endpoint_t *) payload;
    char node_name[NODE_NAME_SIZE + 1];

    memset(node_name, 0, sizeof(node_name));
    for (size_t i = 0; i < count; ++i) {
        memcpy(node_name, endpoints[i].node_name, NODE_NAME_SIZE);

        // Verify the node's name
        if (!node_valid_name(node_name)) {
            logger(LOG_ERR, "%s: %s: Endpoint: Invalid name",
                node->addrw, node->id->name);
            return false;
        }

        node_id_t *id = node_id_add(node_name);
        netaddr_t addr;
        netarea_t area;
        uint16_t hport;
        char hostname[INET6_ADDRSTRLEN];

        // Parse the endpoint address
        if (!netaddr_dton(&addr,
                          endpoints[i].addr_type,
                          &endpoints[i].addr_data))
        {
            logger(LOG_ERR, "%s: %s: Endpoint: Invalid endpoint type",
                node->addrw, node->id->name);
            return false;
        }

        // Format and add the endpoint
        netaddr_ntop(hostname, sizeof(hostname), &addr);
        area = netaddr_area(&addr);
        hport = ntohs(endpoints[i].port);

        logger_debug(DBG_ENDPOINTS, "%s: %s: Adding %s endpoint %s:%u to %s",
            node->addrw, node->id->name, netarea_name(area),
            hostname, hport, id->name);
        endpoint_group_add(id->endpoints, hostname,
            hport, area, true);
    }

    return true;
}