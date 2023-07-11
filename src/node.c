#include "node.h"
#include "oshd.h"
#include "logger.h"
#include "events.h"
#include "xalloc.h"
#include "crypto/hash.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

// Calculate the node's ID hash (name + public key + salt) and write it to *hash
// Returns false on any error (no public key, invalid salt, hashing failure)
// *hash must have a size of NODE_ID_HASH_SIZE bytes
bool node_id_gen_hash(const node_id_t *nid, const uint8_t *salt,
    size_t salt_size, uint8_t *hash)
{
    bool success;
    hash_ctx_t *ctx;

    // The node must have a public key of the correct size
    if (!nid->pubkey_raw)
        return false;
    if (nid->pubkey_raw_size != HANDSHAKE_PUBKEY_SIZE) {
        // This should never happen
        logger(LOG_CRIT, "node_id_gen_hash: %s has an invalid public key size %zu",
            nid->name, nid->pubkey_raw_size);
        return false;
    }

    // There must be a salt to generate the ID hash
    if (salt_size == 0) {
        // This should never happen
        logger(LOG_CRIT, "node_id_gen_hash: empty salt");
        return false;
    }

    // Initialize SHA3-512 context
    success = false;
    ctx = hash_ctx_create(HASH_SHA3_512);
    if (!ctx)
        goto end;

    // Hash the node's name, public key and the salt
    if (!hash_ctx_update(ctx, nid->name, NODE_NAME_SIZE))
        goto end;
    if (!hash_ctx_update(ctx, nid->pubkey_raw, HANDSHAKE_PUBKEY_SIZE))
        goto end;
    if (!hash_ctx_update(ctx, salt, salt_size))
        goto end;

    success = hash_ctx_final(ctx, hash, NODE_ID_HASH_SIZE);

end:
    hash_ctx_free(ctx);
    return success;
}

// Find node_id_t with the corresponding ID hash in the node tree
// *hash must be a valid pointer, its length is not checked
node_id_t *node_id_find_by_hash(const uint8_t *hash,
    const uint8_t *salt, size_t salt_size)
{
    uint8_t nid_hash[NODE_ID_HASH_SIZE];

    for (size_t i = 0; i < oshd.node_tree_count; ++i) {
        if (!node_id_gen_hash(oshd.node_tree[i], salt, salt_size, nid_hash))
            continue;

        if (!memcmp(nid_hash, hash, NODE_ID_HASH_SIZE))
            return oshd.node_tree[i];
    }
    return NULL;
}

// Find node_id_t with *name in the node tree
node_id_t *node_id_find(const char *name)
{
    for (size_t i = 0; i < oshd.node_tree_count; ++i) {
        if (!strncmp(name, oshd.node_tree[i]->name, NODE_NAME_SIZE))
            return oshd.node_tree[i];
    }
    return NULL;
}

// Find the local node in the node tree
// As of now the local node is always the first node in the tree
node_id_t *node_id_find_local(void)
{
    return oshd.node_tree[0];
}

// Sort oshd.node_tree_ordered_hops from highest to lowest hops_count
// (bubble-sort)
static void node_id_sort_hops(void)
{
    node_id_t **tree = oshd.node_tree_ordered_hops;
    bool sorted = false;

    while (!sorted) {
        sorted = true;
        for (size_t i = 1; i < oshd.node_tree_count; ++i) {
            if (tree[i - 1]->hops_count < tree[i]->hops_count) {
                node_id_t *tmp = tree[i - 1];

                tree[i - 1] = tree[i];
                tree[i] = tmp;
                sorted = false;
            }
        }
    }
}

// Add node_id_t with *name to the node tree (doesn't do anything if it already
// exists)
node_id_t *node_id_add(const char *name)
{
    node_id_t *id;

    if (!(id = node_id_find(name))) {
        size_t new_count = oshd.node_tree_count + 1;

        // Create the new node ID
        id = xzalloc(sizeof(node_id_t));

        // Expand the main node tree and other lists ordered differently to hold
        // the new ID
        oshd.node_tree = xreallocarray(oshd.node_tree, new_count,
            sizeof(node_id_t *));
        oshd.node_tree_ordered_hops = xreallocarray(oshd.node_tree_ordered_hops,
            new_count, sizeof(node_id_t *));

        oshd.node_tree[oshd.node_tree_count] = id;

        // We don't need to sort this new ID by hops_count as it will be
        // initialized to 0 and this list will always end with hops count of 0
        oshd.node_tree_ordered_hops[oshd.node_tree_count] = id;

        oshd.node_tree_count = new_count;

        strncpy(id->name, name, NODE_NAME_SIZE);
        id->endpoints = endpoint_group_create(id->name, "known");
        id->connect_endpoints = endpoint_group_create(id->name, "connect");
    }
    return id;
}

// Free resources allocated to *nid and the structure
void node_id_free(node_id_t *nid)
{
    event_cancel(nid->connect_event);

    pkey_free(nid->pubkey);
    free(nid->pubkey_raw);
    free(nid->edges);
    endpoint_group_free(nid->endpoints);
    endpoint_group_free(nid->connect_endpoints);
    free(nid->seen_brd_id);
    free(nid);
}

// Returns index of an edge or -1 if the edge is not in *nid
static ssize_t node_id_find_edge(node_id_t *nid, node_id_t *edge)
{
    for (ssize_t i = 0; i < nid->edges_count; ++i) {
        if (nid->edges[i] == edge)
            return i;
    }
    return -1;
}

// Add *edge to nid->edges (doesn't do anything if *edge already exists)
static void node_id_add_edge_internal(node_id_t *nid, node_id_t *edge)
{
    ssize_t i = node_id_find_edge(nid, edge);

    if (i < 0) {
        nid->edges = xreallocarray(nid->edges, nid->edges_count + 1,
            sizeof(node_id_t *));
        i = nid->edges_count;
        nid->edges_count += 1;
    }
    nid->edges[i] = edge;
}

// Delete *edge from nid->edges (doesn't do anything if *edge doesn't exist)
static void node_id_del_edge_internal(node_id_t *nid, node_id_t *edge)
{
    ssize_t i = node_id_find_edge(nid, edge);

    if (i >= 0) {
        if (i + 1 < nid->edges_count) {
            memmove(&nid->edges[i], &nid->edges[i + 1],
                sizeof(node_id_t *) * (nid->edges_count - i - 1));
        }
        nid->edges_count -= 1;
        nid->edges = xreallocarray(nid->edges, nid->edges_count, sizeof(node_id_t *));
    }
}

// Add edge between *src and *dest (in both directions)
void node_id_add_edge(node_id_t *src, node_id_t *dest)
{
    node_id_add_edge_internal(src, dest);
    node_id_add_edge_internal(dest, src);
}

// Delete edge between *src and *dest (in both directions)
void node_id_del_edge(node_id_t *src, node_id_t *dest)
{
    node_id_del_edge_internal(src, dest);
    node_id_del_edge_internal(dest, src);
}

// Load a remote public key for *nid
// If a public key was already loaded it will be replaced only if pubkey_local
// is false; local public keys cannot be replaced
bool node_id_set_pubkey(node_id_t *nid, const uint8_t *pubkey,
    size_t pubkey_size)
{
    EVP_PKEY *new_key;

    if (nid->pubkey_local) {
        logger_debug(DBG_HANDSHAKE,
            "Ignoring new public key for %s: A local public key is already loaded",
            nid->name);
        return true;
    }

    new_key = pkey_load_ed25519_pubkey(pubkey, pubkey_size);
    if (!new_key)
        return false;

    pkey_free(nid->pubkey);
    nid->pubkey = new_key;
    free(nid->pubkey_raw);
    nid->pubkey_raw = xmemdup(pubkey, pubkey_size);
    nid->pubkey_raw_size = pubkey_size;
    nid->pubkey_local = false;
    return true;
}

// Link a client to a node
// If a client is already linked it will be disconnected and the node tree will
// be updated to remove obsolete references to it
// Returns the previously linked client, or NULL if there was none
client_t *node_id_link_client(node_id_t *nid, client_t *c)
{
    client_t *prev = node_id_linked_client(nid);

    logger_debug(DBG_NODETREE, "Linking client %s to %s", c->addrw, nid->name);
    node_id_linked_client(nid) = c;

    if (prev) {
        logger_debug(DBG_NODETREE, "Unlinked client %s from %s",
            prev->addrw, nid->name);

        client_reconnect_disable(prev);

        // We don't gracefully terminate the connection because both nodes
        // should do it at the same time, this can suspend the connection until
        // it times out
        aio_event_del(prev->aio_event);

        // Update the node tree since the next hops can reference the previous
        // client
        node_tree_update();
    }

    return prev;
}

// Unlink a client from a node
// If a different client is linked this doesn't do anything
// The node tree must be updated after a client is unlinked since nodes' next
// hops can still reference it
// Returns true if the client was unlinked
bool node_id_unlink_client(node_id_t *nid, const client_t *c)
{
    const bool unlink = node_id_linked_client(nid) == c;

    if (unlink) {
        logger_debug(DBG_NODETREE, "Unlinking client %s from %s",
            node_id_linked_client(nid)->addrw, nid->name);
        node_id_linked_client(nid) = NULL;
    }
    return unlink;
}

static client_t *node_id_find_next_hop(node_id_t *dest_node)
{
    const size_t queue_maxcount = oshd.node_tree_count;
    client_t *next_hop = NULL;
    node_id_t **queue;
    size_t queue_count;

    // We clear visited status for every node
    for (size_t i = 0; i < oshd.node_tree_count; ++i)
        oshd.node_tree[i]->visited = false;

    // Initialize the queue with our destination node as the starting node
    queue = xalloc(queue_maxcount * sizeof(node_id_t *));
    queue[0] = dest_node;
    queue_count = 1;
    dest_node->visited = 1;

    // Iterate through the current queue to find a direct connection
    // Break if we reach the end or if the next hop was found
    for (size_t i = 0; i < queue_count && next_hop == NULL; ++i) {
        for (ssize_t j = 0; j < queue[i]->edges_count; ++j) {
            // If the edge was not visited yet, append it to the queue
            if (!queue[i]->edges[j]->visited) {
                assert(queue_count < queue_maxcount);
                queue[queue_count] = queue[i]->edges[j];
                queue_count += 1;
                queue[i]->edges[j]->visited = true;

                // If we have a direct connection to this node it is a candidate
                // for being the next hop
                if (node_id_linked_client(queue[i]->edges[j])) {
                    // If we don't have a next_hop, set it to this direct connection
                    // If we do have a next_hop already, replace it with this
                    // direct connection if its latency is higher
                    if (   !next_hop
                        ||  next_hop->rtt > node_id_linked_client(queue[i]->edges[j])->rtt)
                    {
                        next_hop = node_id_linked_client(queue[i]->edges[j]);
                    }
                }
            }
        }
    }

    free(queue);
    return next_hop;
}

// Return the node's next_hop (searches it first after node_tree_update())
client_t *node_id_next_hop(node_id_t *id)
{
    if (!id->next_hop_searched) {
        logger_debug(DBG_NODETREE, "Searching next hop of %s", id->name);
        id->next_hop = node_id_find_next_hop(id);
        id->next_hop_searched = true;
    }
    return id->next_hop;
}

// Digraph dump to *out
static void node_tree_dump_digraph_to(FILE *out)
{
    char addr[NETADDR_ADDRSTRLEN];

    fprintf(out, "digraph osh_node_tree {\n");

    // We start by defining and labeling every node on the network
    for (size_t i = 0; i < oshd.node_tree_count; ++i) {
        const char *color;
        const char *style;
        char route[64];

        if (oshd.node_tree[i]->local_node) {
            // The local node is fully green
            color = "green";
            style = "filled";
            snprintf(route, sizeof(route), "(local)");
        } else if (oshd.node_tree[i]->online) {
            // Direct and indirect nodes are outlined in either green or turquoise
            style = "solid";
            if (node_id_linked_client(oshd.node_tree[i])) {
                color = "green";
                snprintf(route, sizeof(route), "(direct, %ims, %zu hops)",
                    node_id_linked_client(oshd.node_tree[i])->rtt,
                    oshd.node_tree[i]->hops_count);
            } else {
                color = "turquoise";
                snprintf(route, sizeof(route), "(indirect through %s, %zu hops)",
                    oshd.node_tree[i]->next_hop ? oshd.node_tree[i]->next_hop->id->name : "(unknown)",
                    oshd.node_tree[i]->hops_count);
            }
        } else {
            // Orphan nodes are outlined in red
            color = "red";
            style = "solid";
            snprintf(route, sizeof(route), "(no route)");
        }

        fprintf(out, "    \"%s\" [label=\"%s\\n%s\", color=%s, style=%s];\n",
            oshd.node_tree[i]->name, oshd.node_tree[i]->name, route, color, style);
    }

    // We define and label all routes
    hashtable_foreach_const(item, oshd.route_table->ht, i) {
        const netroute_t *route = (const netroute_t *) item->value;

        if (!route->owner)
            continue;

        netaddr_ntop(addr, sizeof(addr), &route->addr);
        fprintf(out, "    \"%s/%u\" [label=\"%s/%u%s\", color=grey, style=solid];\n",
            addr, route->prefixlen, addr, route->prefixlen,
            route->can_expire ? "" : " (static)");
    }

    // We defined all nodes on the graph, now we just need to connect them all
    // to the right ends

    // We then iterate over all the edges of every node (including us) and
    // make the bi-directionnal connections
    for (size_t i = 0; i < oshd.node_tree_count; ++i) {
        for (ssize_t j = 0; j < oshd.node_tree[i]->edges_count; ++j) {
            fprintf(out, "    \"%s\" -> \"%s\";\n", oshd.node_tree[i]->name,
                oshd.node_tree[i]->edges[j]->name);
        }
    }

    // We connect all nodes to their routes
    hashtable_foreach_const(item, oshd.route_table->ht, i) {
        const netroute_t *route = (const netroute_t *) item->value;

        if (!route->owner)
            continue;

        netaddr_ntop(addr, sizeof(addr), &route->addr);
        fprintf(out, "    \"%s\" -> \"%s/%u\";\n", netroute_owner_name(route),
            addr, route->prefixlen);
    }

    fprintf(out, "}\n");
    fflush(out);
}

// Digraph dump
void node_tree_dump_digraph(void)
{
    if (oshd.digraph_file) {
        FILE *fout = fopen(oshd.digraph_file, "w");

        if (!fout) {
            logger(LOG_ERR, "Failed to dump digraph to %s: %s", oshd.digraph_file,
                strerror(errno));
            return;
        }
        logger_debug(DBG_OSHD, "Dumping digraph to '%s'", oshd.digraph_file);
        node_tree_dump_digraph_to(fout);
        fclose(fout);
    } else {
        node_tree_dump_digraph_to(stdout);
    }
}

// Dump the node tree
void node_tree_dump(void)
{
    printf("Node tree (%s):\n", oshd.name);

    // Skip our local node, our edges are the direct connections
    // We start at 1 because the first element will always be our local node
    for (size_t i = 1; i < oshd.node_tree_count; ++i) {
        printf("    %s (%s, next hop: %s, %zu hops): %zi edges: ",
            oshd.node_tree[i]->name,
            node_id_linked_client(oshd.node_tree[i]) ? "direct" : "indirect",
            oshd.node_tree[i]->next_hop ? oshd.node_tree[i]->next_hop->id->name : "(unknown)",
            oshd.node_tree[i]->hops_count,
            oshd.node_tree[i]->edges_count);

        for (ssize_t j = 0; j < oshd.node_tree[i]->edges_count; ++j) {
            printf("%s", oshd.node_tree[i]->edges[j]->name);
            if ((j + 1) < oshd.node_tree[i]->edges_count)
                printf(", ");
        }
        printf("\n");
    }
    printf("%zu nodes in the tree\n", oshd.node_tree_count);
}

// Calculate the hops_count from our local node for all nodes in the tree
// This updates the state of all nodes
// Sorts oshd.node_tree_ordered_hops before returning
// Returns the maximum hops_count
static size_t node_tree_calc_hops_count(void)
{
    node_id_t *local_node = node_id_find_local();
    const size_t queue_maxcount = oshd.node_tree_count;
    node_id_t **queue;
    size_t queue_count;
    size_t hops_count;

    // Reset the state of all nodes
    for (size_t i = 0; i < oshd.node_tree_count; ++i) {
        oshd.node_tree[i]->hops_count = 0;
        oshd.node_tree[i]->visited = false;
        oshd.node_tree[i]->next_hop = NULL;
        oshd.node_tree[i]->next_hop_searched = false;
        oshd.node_tree[i]->online = false;
    }

    // Initialize the queue with our local node as the starting node
    queue = xalloc(queue_maxcount * sizeof(node_id_t *));
    queue[0] = local_node;
    queue_count = 1;
    hops_count = 0;
    local_node->visited = 1;
    local_node->hops_count = hops_count;
    local_node->online = true;

    // Iterate through the current queue to find a direct connection
    for (size_t i = 0; i < queue_count; ++i) {
        for (ssize_t j = 0; j < queue[i]->edges_count; ++j) {
            // If the edge was not visited yet, append it to the queue
            if (!queue[i]->edges[j]->visited) {
                assert(queue_count < queue_maxcount);
                queue[queue_count] = queue[i]->edges[j];
                queue_count += 1;
                queue[i]->edges[j]->visited = true;
                queue[i]->edges[j]->hops_count = queue[i]->hops_count + 1;
                queue[i]->edges[j]->online = true;

                // If we have a direct connection to this node, set its next_hop
                // now
                if (node_id_linked_client(queue[i]->edges[j])) {
                    queue[i]->edges[j]->next_hop = node_id_linked_client(queue[i]->edges[j]);
                    queue[i]->edges[j]->next_hop_searched = true;
                }
            }
        }
    }

    free(queue);

    // Before returning, sort the node IDs with their updated hops count
    node_id_sort_hops();
    return hops_count;
}

static void node_tree_clear_orphan_nodes(void)
{
    logger_debug(DBG_NODETREE, "Clearing orphan nodes");

    // The first node is us and this task is handled by our direct connections
    // so we can skip it
    for (size_t i = 1; i < oshd.node_tree_count; ++i) {
        // If this node was not visited by the hop count BFS, there is no route
        // to it, the node is offline
        if (!oshd.node_tree[i]->visited) {
            logger_debug(DBG_NODETREE, "Clearing edges from orphan node %s",
                oshd.node_tree[i]->name);

            free(oshd.node_tree[i]->edges);
            oshd.node_tree[i]->edges = NULL;
            oshd.node_tree[i]->edges_count = 0;
        }
    }
}

void node_tree_update(void)
{
    logger_debug(DBG_NODETREE, "Node tree updated");

    // Calculate the hops_count of all nodes in the tree
    node_tree_calc_hops_count();

    // Clear the orphan nodes
    node_tree_clear_orphan_nodes();

    if (netroute_del_orphan_owners(oshd.route_table)) {
        if (logger_is_debugged(DBG_ROUTING)) {
            printf("Routing table (%zu):\n", oshd.route_table->total_routes);
            netroute_dump(oshd.route_table);
        }
    }

    if (logger_is_debugged(DBG_NODETREE))
        node_tree_dump();
}

// Returns true if the node name is valid
bool node_valid_name(const char *name)
{
    const char valid_charset[] = \
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-";
    const size_t name_len = strlen(name);

    return    name_len > 0
           && name_len <= NODE_NAME_SIZE
           && name_len == strspn(name, valid_charset);
}

// Returns true if this node has a trusted public key
// Returns false if it does not have a public key, or we don't trust it
bool node_has_trusted_pubkey(const node_id_t *nid)
{
    if (!nid->pubkey)
        return false;
    return nid->pubkey_local || oshd.remote_auth;
}

// Push the broadcast ID to the end of the seen broadcast IDs array
void node_brd_id_push(node_id_t *nid, const oshpacket_brd_id_t brd_id)
{
    const size_t idx = nid->seen_brd_id_count;

    nid->seen_brd_id_count += 1;
    nid->seen_brd_id = xreallocarray(nid->seen_brd_id,
        nid->seen_brd_id_count, sizeof(struct node_brd_id));
    nid->seen_brd_id[idx].brd_id = brd_id;
    oshd_gettime(&nid->seen_brd_id[idx].seen_at);
}

// Pop the first broadcast IDs from the array
void node_brd_id_pop(node_id_t *nid, size_t amount)
{
    if (amount >= nid->seen_brd_id_count) {
        free(nid->seen_brd_id);
        nid->seen_brd_id = NULL;
        nid->seen_brd_id_count = 0;
        return;
    }

    nid->seen_brd_id_count -= amount;
    memmove(nid->seen_brd_id, nid->seen_brd_id + amount,
        nid->seen_brd_id_count * sizeof(struct node_brd_id));
    nid->seen_brd_id = xreallocarray(nid->seen_brd_id,
        nid->seen_brd_id_count, sizeof(struct node_brd_id));
}

// Returns true if the broadcast ID was seen already
// The ID will be marked as seen if it was not
bool node_brd_id_was_seen(node_id_t *nid, const oshpacket_brd_id_t brd_id)
{
    for (size_t i = nid->seen_brd_id_count; i > 0; --i) {
        // If any value in the seen_brd_id array is the same as brd_id it means
        // that we have already seen and processed this packet
        if (nid->seen_brd_id[i - 1].brd_id == brd_id)
            return true;
    }

    // The broadcast ID was not seen before
    node_brd_id_push(nid, brd_id);
    return false;
}

// Returns a valid delay within the reconnection delay limits
static time_t reconnect_delay_limit(const time_t delay)
{
    if (delay < oshd.reconnect_delay_min)
        return oshd.reconnect_delay_min;

    if (delay > oshd.reconnect_delay_max)
        return oshd.reconnect_delay_max;

    return delay;
}

// Returns the next increased delay after a connection attempt failed
static time_t reconnect_delay_next(const time_t delay)
{
    return reconnect_delay_limit(reconnect_delay_limit(delay) * 2);
}

// Increment the node's reconnection delay
static void node_connect_delay_increment(node_id_t *nid)
{
    nid->connect_delay = reconnect_delay_next(nid->connect_delay);
}

// Returns true if the endpoint type can be used to connect to a node
static bool connect_endpoint_type_compatible(const endpoint_type_t type)
{
    switch (type) {
        case ENDPOINT_TYPE_HOSTNAME:
        case ENDPOINT_TYPE_IP4:
        case ENDPOINT_TYPE_IP6:
            return true;

        default:
            return false;
    }
}

// Find a matching connect endpoint (with the same value, port and protocol)
// Returns NULL if the endpoint does not exist
static endpoint_t *node_connect_endpoints_find(node_id_t *nid,
    const endpoint_t *endpoint, const endpoint_proto_t proto)
{
    endpoint_t *it = endpoint_group_find(nid->connect_endpoints, endpoint);

    while (it) {
        // If the protocols match too, we found a matching endpoint
        if (it->proto == proto)
            return it;

        // Find the next occurrence of the endpoint
        it = endpoint_group_find_after(it, endpoint);
    }

    // No matching endpoint was found
    return NULL;
}

// Insert endpoint if it is compatible with the protocol
static void node_connect_setup_endpoints_insert(node_id_t *nid,
    const endpoint_t *endpoint, const endpoint_proto_t proto)
{
    const endpoint_proto_t insert_proto = endpoint->proto & proto;
    endpoint_t *inserted;

    if (    insert_proto
        && !node_connect_endpoints_find(nid, endpoint, insert_proto))
    {
        logger_debug(DBG_ENDPOINTS, "%s: Inserting endpoint %s",
            nid->connect_endpoints->debug_id, endpoint->addrstr);

        inserted = endpoint_group_insert_back(nid->connect_endpoints, endpoint);
        inserted->proto = insert_proto;
    }
}

// Initialize nid->connect_endpoints for a new connection attempt
// Copies all the currently known valid endpoints, selects the first one
// Returns false if there are no endpoints to connect to
static bool node_connect_setup_endpoints(node_id_t *nid)
{
    endpoint_group_clear(nid->connect_endpoints);
    foreach_endpoint_const(endpoint, nid->endpoints) {
        if (!connect_endpoint_type_compatible(endpoint->type))
            continue;

        node_connect_setup_endpoints_insert(nid, endpoint, ENDPOINT_PROTO_TCP);
    }
    endpoint_group_select_first(nid->connect_endpoints);

    return endpoint_group_selected(nid->connect_endpoints) != NULL;
}

// Returns true if a connection attempt to this node is in progress
bool node_connect_in_progress(const node_id_t *nid)
{
    return endpoint_group_is_connecting(nid->connect_endpoints);
}

// Try connecting to this node
// If now is true, the connection will be queued right away, otherwise it will
// be queued after the minimum reconnection delay
// Returns true if the connection attempt has successfully began
// Returns false on any error:
// - A connection attempt to this node is already in progress
// - No endpoints can be used to connect
// - We cannot authenticate this node (no public key)
bool node_connect(node_id_t *nid, const bool now)
{
    // Don't queue an attempt if one is already in progress
    if (node_connect_in_progress(nid)) {
        logger(LOG_WARN, "Duplicate connection attempt to %s", nid->name);
        return false;
    }

    // Authentication will fail later if we don't have the node's public key
    if (!node_has_trusted_pubkey(nid)) {
        logger(LOG_WARN, "Cannot connect to %s: %s", nid->name, "No trusted public key");
        return false;
    }

    // Setup the endpoints to connect to
    if (!node_connect_setup_endpoints(nid)) {
        logger(LOG_WARN, "Cannot connect to %s: %s", nid->name, "No known endpoints");
        return false;
    }

    nid->connect_delay = oshd.reconnect_delay_min;
    endpoint_group_set_is_connecting(nid->connect_endpoints, true);

    if (now) {
        event_queue_connect(nid, EVENT_QUEUE_NOW);
    } else {
        event_queue_connect(nid, nid->connect_delay);
        node_connect_delay_increment(nid);
    }
    return true;
}

// Continue trying to connect to a node
void node_connect_continue(node_id_t *nid)
{
    // We cannot do anything if a connection attempt is not in progress
    if (!node_connect_in_progress(nid)) {
        logger(LOG_WARN, "Cannot continue connection attempt to %s: %s",
            nid->name, "Not in progress");
        return;
    }

    // Select the next endpoint in the group to try connecting to
    if (endpoint_group_select_next(nid->connect_endpoints)) {
        // We have another endpoint, try connecting to it now
        event_queue_connect(nid, EVENT_QUEUE_NOW);
    } else {
        // All endpoints have been tried

        // If we don't have to retry forever, end the attempt here
        if (!nid->endpoints->always_retry) {
            node_connect_end(nid, false, NULL);
            return;
        }

        // Reset and setup the endpoints again for the next attempt
        if (!node_connect_setup_endpoints(nid)) {
            node_connect_end(nid, false, "No known endpoints");
            return;
        }

        event_queue_connect(nid, nid->connect_delay);
        node_connect_delay_increment(nid);
    }
}

// Quit trying to connect to a node
void node_connect_end(node_id_t *nid, const bool success, const char *reason)
{
    if (!success && node_connect_in_progress(nid)) {
        if (reason) {
            logger(LOG_WARN, "Giving up trying to connect to %s: %s", nid->name, reason);
        } else {
            logger(LOG_WARN, "Giving up trying to connect to %s", nid->name);
        }
    }

    event_cancel(nid->connect_event);
    endpoint_group_clear(nid->connect_endpoints);
    endpoint_group_set_is_connecting(nid->connect_endpoints, false);
}
