#include "node.h"
#include "logger.h"
#include <string.h>

bool oshpacket_handler_endpoint(client_t *c,
    __attribute__((unused)) node_id_t *src, oshpacket_t *pkt)
{
    const oshpacket_endpoint_t *payload = (const oshpacket_endpoint_t *) pkt->payload;
    const endpoint_data_t *data = (const endpoint_data_t *) (payload + 1);
    size_t data_size;
    char owner_name[NODE_NAME_SIZE + 1];

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

    endpoint_t *endpoint;
    node_id_t *owner;
    const char *action;

    // Try to create an endpoint from the packet's data
    endpoint = endpoint_from_packet(payload, data, data_size);
    if (!endpoint) {
        // This is not an error, other nodes may know endpoint types that we don't
        logger_debug(DBG_ENDPOINTS,
            "%s: %s: Ignoring unknown or invalid endpoint type %u of %zu bytes",
            c->addrw, c->id->name, payload->type, data_size);
        return true;
    }

    // Find the owner node
    owner = node_id_add(owner_name);

    // Ephemeral endpoints are considered unreachable and expire very fast,
    // we will only use them to discover external network addresses but we won't
    // add them to the known endpoints directly
    //
    // All other endpoints are added to their owner's known endpoints
    if (endpoint->flags & ENDPOINT_FLAG_EPHEMERAL) {
        action = "Ignored ephemeral";
    } else {
        action = endpoint_group_insert_sorted(owner->endpoints, endpoint, NULL)
               ? "Added"
               : "Updated";
    }

    logger_debug(DBG_ENDPOINTS, "%s: %s: %s endpoint %s owned by %s",
        c->addrw, c->id->name, action, endpoint->addrstr, owner->name);

    // ENDPOINT_DISC packets are used to exchange remote/local endpoints related
    // to the current connection
    if (pkt->hdr->type == OSHPKT_ENDPOINT_DISC) {
        if ((endpoint->flags & ENDPOINT_FLAG_EXTERNAL) && owner->local_node) {
            client_set_external_endpoint(c, endpoint);
        } else if ((endpoint->flags & ENDPOINT_FLAG_INTERNAL) && owner == c->id) {
            client_set_internal_endpoint(c, endpoint);
        }
    }

    endpoint_free(endpoint);
    return true;
}
