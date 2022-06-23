#include "node.h"
#include "logger.h"
#include <string.h>

bool oshpacket_handler_endpoint(client_t *c, __attribute__((unused)) node_id_t *src,
    oshpacket_hdr_t *hdr, void *payload)
{
    if (c->state_exg) {
        // Broadcast the endpoints to our end of the network
        logger_debug(DBG_STATEEXG,
            "%s: %s: State exchange: Relaying ENDPOINT packet",
            c->addrw, c->id->name);
        client_queue_packet_broadcast(c, ENDPOINT, payload,
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
                c->addrw, c->id->name);
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
                c->addrw, c->id->name);
            return false;
        }

        // Format and add the endpoint
        netaddr_ntop(hostname, sizeof(hostname), &addr);
        area = netaddr_area(&addr);
        hport = ntohs(endpoints[i].port);

        logger_debug(DBG_ENDPOINTS, "%s: %s: Adding %s endpoint %s:%u to %s",
            c->addrw, c->id->name, netarea_name(area),
            hostname, hport, id->name);
        endpoint_group_add(id->endpoints, hostname,
            hport, area, true);
    }

    return true;
}
