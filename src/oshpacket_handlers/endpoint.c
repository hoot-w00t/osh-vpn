#include "node.h"
#include "logger.h"
#include <string.h>

bool oshpacket_handler_endpoint(
    client_t *c,
    __attribute__((unused)) node_id_t *src,
    oshpacket_t *pkt)
{
    const oshpacket_endpoint_t *payload = (const oshpacket_endpoint_t *) pkt->payload;
    const endpoint_data_t *data = (const endpoint_data_t *) (payload + 1);
    size_t data_size;
    char owner_name[NODE_NAME_SIZE + 1];
    endpoint_t *endpoint;
    node_id_t *owner;

    // Verify that we at least have a full header
    if (pkt->payload_size <= sizeof(*payload)) {
        logger(LOG_ERR, "%s: %s: %s: %s", c->addrw, c->id->name, "Endpoint",
            "Invalid size");
        return false;
    }

    // Get the attached data's size
    data_size = pkt->payload_size - sizeof(*payload);

    // Verify the owner name
    memset(owner_name, 0, sizeof(owner_name));
    memcpy(owner_name, payload->owner_name, NODE_NAME_SIZE);
    if (!node_valid_name(owner_name)) {
        logger(LOG_ERR, "%s: %s: %s: %s", c->addrw, c->id->name, "Endpoint",
            "Invalid owner name");
        return false;
    }

    // Try to create an endpoint from the packet's data
    endpoint = endpoint_from_packet(payload, data, data_size);
    if (!endpoint) {
        // This is not an error, other nodes may know endpoint types which we
        // don't
        logger_debug(DBG_ENDPOINTS,
            "%s: %s: Ignoring unknown or invalid endpoint type %u of %zu bytes",
            c->addrw, c->id->name, payload->type, data_size);
        return true;
    }

    // Find the owner node and add the endpoint
    owner = node_id_add(owner_name);
    logger_debug(DBG_ENDPOINTS, "%s: %s: Adding endpoint %s to %s",
        c->addrw, c->id->name, endpoint->addrstr, owner->name);

    endpoint_group_insert_sorted(owner->endpoints, endpoint);
    endpoint_free(endpoint);
    return true;
}
