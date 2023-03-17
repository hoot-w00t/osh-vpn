#include "oshd.h"
#include "xalloc.h"
#include "logger.h"
#include <stdlib.h>
#include <string.h>

// Queues a packet with client_queue_packet_exg
// The packet type must support fragmentation, the payload will be fragmented if
// necessary
// Returns false on any error
static bool queue_exg_fragmented(client_t *c, oshpacket_type_t type,
    const void *payload, const size_t payload_size)
{
    const oshpacket_def_t *def = oshpacket_lookup(type);

    // The packet type must be valid and support fragmentation
    // If this triggers there is an error in the code
    if (!def || def->payload_size_type != OSHPACKET_PAYLOAD_SIZE_FRAGMENTED) {
        logger(LOG_CRIT, "%s:%i:%s: invalid packet type 0x%02X",
            __FILE__, __LINE__, __func__, type);
        abort();
    }

    // Calculate the total number of payloads and how many we can send at once
    const size_t total_payload_count = payload_size / def->payload_size;
    const size_t max_payload_count = OSHPACKET_PAYLOAD_MAXSIZE / def->payload_size;

    for (size_t i = 0; i < total_payload_count; i += max_payload_count) {
        size_t send_count = total_payload_count - i;

        // Send max_payload_count entries at most in a single packet
        if (send_count > max_payload_count)
            send_count = max_payload_count;

        if (!client_queue_packet_exg(c, type,
                ((const uint8_t *) payload) + (i * def->payload_size),
                send_count * def->payload_size))
        {
            return false;
        }
    }

    return true;
}

// Exchange known public keys with the client
bool client_queue_pubkey_exg(client_t *c)
{
    oshpacket_pubkey_t *pkt = xalloc(oshd.node_tree_count * sizeof(*pkt));
    size_t count = 0;
    bool success;

    for (size_t i = 0; i < oshd.node_tree_count; ++i) {
        // Only exchange public keys from online nodes
        if (   !oshd.node_tree[i]->online
            || !oshd.node_tree[i]->pubkey
            || !oshd.node_tree[i]->pubkey_raw
            ||  oshd.node_tree[i]->pubkey_raw_size != NODE_PUBKEY_SIZE)
        {
            continue;
        }

        logger_debug(DBG_STATEEXG, "%s: %s: Exchanging public key of %s",
            c->addrw, c->id->name, oshd.node_tree[i]->name);

        memcpy(pkt[count].node_name, oshd.node_tree[i]->name, NODE_NAME_SIZE);
        memcpy(pkt[count].node_pubkey, oshd.node_tree[i]->pubkey_raw, NODE_PUBKEY_SIZE);
        count += 1;
    }

    success = queue_exg_fragmented(c, OSHPKT_PUBKEY, pkt, count * sizeof(*pkt));
    free(pkt);
    return success;
}

// Send an endpoint owned by group->owner_name to the client
static bool client_queue_endpoint_exg_internal(client_t *c,
    const endpoint_t *endpoint, const node_id_t *owner)
{
    uint8_t buf[sizeof(oshpacket_endpoint_t) + sizeof(endpoint_data_t)];
    oshpacket_endpoint_t *pkt = (oshpacket_endpoint_t *) buf;
    endpoint_data_t *data = (endpoint_data_t *) (pkt + 1);
    size_t data_size;
    size_t total_size;

    memset(buf, 0, sizeof(buf));
    if (!endpoint_to_packet(endpoint, pkt, data, &data_size)) {
        logger(LOG_ERR,
            "%s: %s: Failed to exchange incompatible endpoint %s owned by %s",
            c->addrw, c->id->name, endpoint->addrstr, owner->name);
        return false;
    }

    memcpy(pkt->owner_name, owner->name, NODE_NAME_SIZE);
    total_size = sizeof(*pkt) + data_size;

    logger_debug(DBG_STATEEXG, "%s: %s: Exchanging endpoint %s owned by %s",
        c->addrw, c->id->name, endpoint->addrstr, owner->name);
    return client_queue_packet_exg(c, OSHPKT_ENDPOINT, &buf, total_size);
}

// Exchange all known endpoints with the client
// Endpoints from the configuration file will be skipped if ShareEndpoints is
// not enabled
bool client_queue_endpoint_exg(client_t *c)
{
    for (size_t i = 0; i < oshd.node_tree_count; ++i) {
        const node_id_t *owner = oshd.node_tree[i];
        const endpoint_group_t *group = owner->endpoints;

        foreach_endpoint_const(endpoint, group) {
            // If ShareEndpoints was not set in the configuration file,
            // endpoints that don't expire will not be shared
            if (!endpoint_can_expire(endpoint) && !oshd.shareendpoints)
                continue;

            // Don't exchange ephemeral endpoints
            if (endpoint->flags & ENDPOINT_FLAG_EPHEMERAL)
                continue;

            if (!client_queue_endpoint_exg_internal(c, endpoint, owner))
                return false;
        }
    }
    return true;
}

// Dynamically append edges to *buf
// If NODE_NAME_SIZE changes the format modifiers must be updated
static void append_edge(oshpacket_edge_t **buf, size_t *buf_count,
    const node_id_t *src_node, const node_id_t *dest_node,
    const node_id_t *remote_node)
{
    const size_t alloc_count = OSHPACKET_PAYLOAD_MAXSIZE / sizeof(oshpacket_edge_t);

    // A node cannot have a connection to itself
    if (src_node == dest_node) {
        logger_debug(DBG_STATEEXG, "    Skipped: %16s <=> %-16s (same)",
            src_node->name, dest_node->name);
        return;
    }

    // Skip the new connection between our node and the other, as both nodes
    // will broadcast this information separately
    if (   ( src_node->local_node && dest_node == remote_node)
        || (dest_node->local_node &&  src_node == remote_node))
    {
        logger_debug(DBG_STATEEXG, "    Skipped: %16s <=> %-16s (current edge)",
            src_node->name, dest_node->name);
        return;
    }

    // Skip repeating edges
    // Source and destination edges will be linked bidirectionally so we can
    // skip the ones which we already added (with reversed source/destination)
    for (size_t i = 0; i < (*buf_count); ++i) {
        if (   !strcmp((*buf)[i].src_node, dest_node->name)
            && !strcmp((*buf)[i].dest_node, src_node->name))
        {
            logger_debug(DBG_STATEEXG,
                "    Skipped: %16s <=> %-16s (repeating index %zu)",
                src_node->name, dest_node->name, i);
            return;
        }
    }

    // Dynamically allocate alloc_count more items when we reach the end of the
    // buffer
    if ((*buf_count) % alloc_count == 0)
        *buf = xreallocarray(*buf, (*buf_count) + alloc_count, sizeof(oshpacket_edge_t));

    // Add this edge to the buffer
    logger_debug(DBG_STATEEXG, "    Adding:  %16s <=> %-16s (index %zu)",
        src_node->name, dest_node->name, *buf_count);

    memcpy((*buf)[*buf_count].src_node, src_node->name, NODE_NAME_SIZE);
    memcpy((*buf)[*buf_count].dest_node, dest_node->name, NODE_NAME_SIZE);
    *buf_count += 1;
}

// Exchange our network map with the client
bool client_queue_edge_exg(client_t *c)
{
    oshpacket_edge_t *pkt = NULL;
    size_t count = 0;
    size_t min_hops = 0;
    bool success;

    logger_debug(DBG_STATEEXG, "%s: %s: Searching edges to exchange",
        c->addrw, c->id->name);

    // We have to exchange edges from the closest to the farthest nodes (from
    // our point of view) to prevent sending orphan edges to the other node
    //
    // If we don't we can end up in a situation where all the edges sent in a
    // single packet are orphan (from the remote node's point of view), and it
    // will erroneously clear them right after processing the packet
    for (size_t i = oshd.node_tree_count; i > 0; --i) {
        const node_id_t *src_node = oshd.node_tree_ordered_hops[i - 1];

        // This should never happen
        if (src_node->hops_count < min_hops) {
            logger(LOG_CRIT, "%s:%i: %s: invalid hops count ordering",
                __FILE__, __LINE__, __func__);
            abort();
        }

        if (src_node->hops_count > min_hops)
            min_hops = src_node->hops_count;

        for (ssize_t j = 0; j < src_node->edges_count; ++j)
            append_edge(&pkt, &count, src_node, src_node->edges[j], c->id);
    }
    logger_debug(DBG_STATEEXG, "%s: %s: Exchanging %zu edges",
        c->addrw, c->id->name, count);

    success = queue_exg_fragmented(c, OSHPKT_EDGE_ADD, pkt, count * sizeof(*pkt));
    free(pkt);
    return success;
}

// Exchange all known routes with the client
bool client_queue_route_exg(client_t *c)
{
    const size_t total_count = oshd.route_table->total_owned_routes;
    oshpacket_route_t *pkt;
    netaddr_data_t addr_data;
    size_t i;
    bool success;

    logger_debug(DBG_STATEEXG, "%s: %s: Exchanging %zu routes",
        c->addrw, c->id->name, total_count);

    if (total_count == 0)
        return true;

    pkt = xalloc(sizeof(oshpacket_route_t) * total_count);
    i = 0;

    // Format all known routes into oshpacket_route_t payloads
    foreach_netroute_const(route, oshd.route_table, route_iter) {
        if (!route->owner)
            continue;

        // This should never happen, if it does there is either an error in this
        // loop or in the routing table's counter
        if (i >= total_count) {
            logger(LOG_CRIT, "%s:%i:%s: buffer overflowing",
                __FILE__, __LINE__, __func__);
            abort();
        }

        memcpy(pkt[i].owner_name, route->owner->name, NODE_NAME_SIZE);
        pkt[i].type = route->addr.type;
        pkt[i].prefixlen = route->prefixlen;
        netaddr_cpy_data(&addr_data, &route->addr);
        pkt[i].addr = addr_data;
        pkt[i].can_expire = route->can_expire;
        ++i;
    }

    // This should never happen, the number of copied routes should always match
    // the total_count
    if (i != total_count) {
        logger(LOG_CRIT, "%s:%i:%s: copied %zu routes but expected %zu",
            __FILE__, __LINE__, __func__, i, total_count);
        abort();
    }

    success = queue_exg_fragmented(c, OSHPKT_ROUTE_ADD, pkt, total_count * sizeof(*pkt));
    free(pkt);
    return success;
}
