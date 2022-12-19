#include "oshd.h"
#include "logger.h"
#include <stdlib.h>
#include <string.h>

// Returns true if we have a direct connection with *oth
static bool local_edge_exists(const node_id_t *oth)
{
    client_t *c;

    for (size_t i = 0; i < oshd.clients_count; ++i) {
        c = oshd.clients[i];
        if (c->authenticated && c->id == oth)
            return true;
    }
    return false;
}

// Process EDGE_ADD
static void process_edge_add(client_t *c, node_id_t *src_node, node_id_t *dest_node)
{
    // A node cannot have a connection to itself
    if (src_node == dest_node) {
        logger_debug(DBG_NODETREE, "%s: %s: Add edge: %16s <=> %-16s (skipped, same node)",
            c->addrw, c->id->name, src_node->name, dest_node->name);
        return;
    }

    // If this edge is one of ours we will verify if it is valid
    if (src_node->local_node || dest_node->local_node) {
        logger_debug(DBG_NODETREE, "%s: %s: Add edge: %16s <=> %-16s (skipped, local)",
            c->addrw, c->id->name, src_node->name, dest_node->name);

        // If this edge doesn't exist, we have to send the correct information
        // to the mesh
        if (!local_edge_exists(src_node->local_node ? dest_node : src_node)) {
            logger_debug(DBG_NODETREE, "Rectifying invalid edge add %16s <=> %-16s",
                src_node->name, dest_node->name);

            node_id_del_edge(src_node, dest_node);
            client_queue_edge_broadcast(NULL, EDGE_DEL,
                src_node->name, dest_node->name);
        }
        return;
    }

    // Add the edge
    logger_debug(DBG_NODETREE, "%s: %s: Add edge: %16s <=> %-16s",
        c->addrw, c->id->name, src_node->name, dest_node->name);
    node_id_add_edge(src_node, dest_node);
}

// Process EDGE_DEL
static void process_edge_del(client_t *c, node_id_t *src_node, node_id_t *dest_node)
{
    // If this edge is one of ours we will verify if it is valid
    if (src_node->local_node || dest_node->local_node) {
        logger_debug(DBG_NODETREE, "%s: %s: Del edge: %16s <=> %-16s (skipped, local)",
            c->addrw, c->id->name, src_node->name, dest_node->name);

        // If this edge exists, we have to send the correct information
        // to the mesh
        if (local_edge_exists(src_node->local_node ? dest_node : src_node)) {
            logger_debug(DBG_NODETREE, "Rectifying invalid edge del %16s <=> %-16s",
                src_node->name, dest_node->name);

            node_id_add_edge(src_node, dest_node);
            client_queue_edge_broadcast(NULL, EDGE_ADD,
                src_node->name, dest_node->name);
        }
        return;
    }

    // Delete the edge
    logger_debug(DBG_NODETREE, "%s: %s: Del edge: %16s <=> %-16s",
        c->addrw, c->id->name, src_node->name, dest_node->name);
    node_id_del_edge(src_node, dest_node);
}

// Iterate through all edges of EDGE_ADD/EDGE_DEL packet
static bool process_edge(client_t *c, const oshpacket_t *pkt,
    void (*action)(client_t *, node_id_t *, node_id_t *))
{
    const oshpacket_edge_t *payload = (const oshpacket_edge_t *) pkt->payload;
    const size_t payload_count = pkt->payload_size / sizeof(oshpacket_edge_t);
    char src_name[NODE_NAME_SIZE + 1], dest_name[NODE_NAME_SIZE + 1];
    node_id_t *src, *dest;

    memset(src_name, 0, sizeof(src_name));
    memset(dest_name, 0, sizeof(dest_name));
    for (size_t i = 0; i < payload_count; ++i) {
        memcpy(src_name, payload[i].src_node, NODE_NAME_SIZE);
        memcpy(dest_name, payload[i].dest_node, NODE_NAME_SIZE);

        // Verify the names
        if (!node_valid_name(src_name) || !node_valid_name(dest_name)) {
            logger(LOG_ERR, "%s: %s: %s: Invalid node names",
                c->addrw, c->id->name, oshpacket_type_name(pkt->hdr->type));
            return false;
        }

        src = node_id_add(src_name);
        dest = node_id_add(dest_name);
        action(c, src, dest);
    }
    return true;
}

bool oshpacket_handler_edge_add(
    client_t *c,
    __attribute__((unused)) node_id_t *src,
    oshpacket_t *pkt)
{
    bool success;

    success = process_edge(c, pkt, process_edge_add);
    node_tree_update();
    return success;
}

bool oshpacket_handler_edge_del(
    client_t *c,
    __attribute__((unused)) node_id_t *src,
    oshpacket_t *pkt)
{
    bool success;

    success = process_edge(c, pkt, process_edge_del);
    node_tree_update();
    return success;
}
