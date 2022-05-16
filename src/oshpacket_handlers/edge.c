#include "node.h"
#include "logger.h"
#include <stdlib.h>
#include <string.h>

// Iterate through all edges in *payload and add/delete them
static bool process_edge(node_t *node, oshpacket_hdr_t *pkt,
    oshpacket_edge_t *payload, bool add)
{
    const char *action_name = add ? "Add" : "Delete";
    void (*action)(node_id_t *, node_id_t *) = add ? &node_id_add_edge : &node_id_del_edge;
    const size_t entries = pkt->payload_size / sizeof(oshpacket_edge_t);
    char src_name[NODE_NAME_SIZE + 1], dest_name[NODE_NAME_SIZE + 1];
    node_id_t *src, *dest;

    memset(src_name, 0, sizeof(src_name));
    memset(dest_name, 0, sizeof(dest_name));
    for (size_t i = 0; i < entries; ++i) {
        memcpy(src_name, payload[i].src_node, NODE_NAME_SIZE);
        memcpy(dest_name, payload[i].dest_node, NODE_NAME_SIZE);

        // Verify the names
        if (!node_valid_name(src_name) || !node_valid_name(dest_name)) {
            logger(LOG_ERR, "%s: %s: %s edge: Invalid edge names", node->addrw,
                node->id->name, action_name);
            return false;
        }

        src = node_id_add(src_name);
        dest = node_id_add(dest_name);

        // Skip our own edges (as they are handled with direct connections)
        if (src->local_node || dest->local_node) {
            logger_debug(DBG_NODETREE, "%s: %s: %s edge: %s <=> %s (skipped, local)",
                node->addrw, node->id->name, action_name, src_name, dest_name);
            continue;
        }

        logger_debug(DBG_NODETREE, "%s: %s: %s edge: %s <=> %s", node->addrw,
            node->id->name, action_name, src_name, dest_name);
        action(src, dest);
    }
    return true;
}

bool oshpacket_handler_edge_add(node_t *node, __attribute__((unused)) node_id_t *src,
    oshpacket_hdr_t *hdr, void *payload)
{
    bool success;

    if (node->state_exg) {
        // Broadcast remote node's edges to our end of the network
        logger_debug(DBG_STATEEXG,
            "%s: %s: State exchange: Relaying EDGE_ADD packet",
            node->addrw, node->id->name);
        node_queue_packet_broadcast(node, EDGE_ADD, payload, hdr->payload_size);
    }

    success = process_edge(node, hdr, (oshpacket_edge_t *) payload, true);
    node_tree_update();
    return success;
}

bool oshpacket_handler_edge_del(node_t *node, __attribute__((unused)) node_id_t *src,
    oshpacket_hdr_t *hdr, void *payload)
{
    bool success;

    success = process_edge(node, hdr, (oshpacket_edge_t *) payload, false);
    node_tree_update();
    return success;
}