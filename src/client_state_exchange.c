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
    const oshpacket_t *def = oshpacket_lookup(type);

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
                payload + (i * def->payload_size),
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
            ||  oshd.node_tree[i]->pubkey_raw_size != PUBLIC_KEY_SIZE)
        {
            continue;
        }

        logger_debug(DBG_STATEEXG, "%s: %s: Exchanging public key of %s",
            c->addrw, c->id->name, oshd.node_tree[i]->name);

        memcpy(pkt[count].node_name, oshd.node_tree[i]->name, NODE_NAME_SIZE);
        memcpy(pkt[count].node_pubkey, oshd.node_tree[i]->pubkey_raw, PUBLIC_KEY_SIZE);
        count += 1;
    }

    success = queue_exg_fragmented(c, PUBKEY, pkt, count * sizeof(*pkt));
    free(pkt);
    return success;
}

// Send an endpoint owned by group->owner_name to the client
static bool client_queue_endpoint_exg_internal(client_t *c,
    const endpoint_t *endpoint, const endpoint_group_t *group)
{
    oshpacket_endpoint_t pkt;
    netaddr_t addr;

    if (!group->has_owner) {
        logger(LOG_ERR, "%s: Failed to queue endpoint %s:%u: No owner (%s)",
            c->addrw, endpoint->hostname, endpoint->port, group->owner_name);
        return false;
    }
    if (!netaddr_lookup(&addr, endpoint->hostname)) {
        logger(LOG_WARN,
            "%s: Failed to queue endpoint %s:%u owned by %s (lookup failed)",
            c->addrw, endpoint->hostname, endpoint->port, group->owner_name);
        return true;
    }

    memset(&pkt, 0, sizeof(pkt));
    for (size_t i = 0; (group->owner_name[i] != 0) && (i < NODE_NAME_SIZE); ++i)
        pkt.node_name[i] = group->owner_name[i];
    pkt.addr_type = addr.type;
    netaddr_cpy_data(&pkt.addr_data, &addr);
    pkt.port = htons(endpoint->port);

    logger_debug(DBG_STATEEXG, "%s: %s: Exchanging endpoint %s:%u owned by %s",
        c->addrw, c->id->name, endpoint->hostname, endpoint->port, group->owner_name);
    return client_queue_packet_exg(c, ENDPOINT, &pkt, sizeof(pkt));
}

// Exchange all known endpoints with the client
// Endpoints from the configuration file will be skipped if ShareRemotes is
// not enabled
// TODO: Rewrite this function to send multiple endpoints in a single payload
bool client_queue_endpoint_exg(client_t *c)
{
    for (size_t i = 0; i < oshd.node_tree_count; ++i) {
        endpoint_group_t *group = oshd.node_tree[i]->endpoints;

        foreach_endpoint(endpoint, group) {
            // If ShareRemotes was not set in the configuration file,
            // endpoints that don't expire will not be shared
            if (!endpoint->can_expire && !oshd.shareremotes)
                continue;

            if (!client_queue_endpoint_exg_internal(c, endpoint, group))
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

    success = queue_exg_fragmented(c, EDGE_ADD, pkt, count * sizeof(*pkt));
    free(pkt);
    return success;
}

// Exchange all known routes with the client
bool client_queue_route_exg(client_t *c)
{
    const size_t total_count = oshd.route_table->total_owned_routes;
    oshpacket_route_t *pkt;
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
        netaddr_cpy_data(&pkt[i].addr, &route->addr);
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

    success = queue_exg_fragmented(c, ROUTE_ADD, pkt, total_count * sizeof(*pkt));
    free(pkt);
    return success;
}