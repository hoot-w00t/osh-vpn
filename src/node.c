#include "node.h"
#include "oshd.h"
#include "logger.h"
#include "xalloc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

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
        id->endpoints = endpoint_group_create(id->name);
    }
    return id;
}

// Free resources allocated to *nid and the structure
void node_id_free(node_id_t *nid)
{
    pkey_free(nid->pubkey);
    free(nid->pubkey_raw);
    free(nid->edges);
    endpoint_group_free(nid->endpoints);
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
        logger_debug(DBG_AUTHENTICATION,
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
                // Safety check, this should never happen but
                if (queue_count >= queue_maxcount) {
                    logger(LOG_CRIT, "%s: queue_count >= queue_maxcount", __func__);
                    abort();
                }

                queue[queue_count] = queue[i]->edges[j];
                queue_count += 1;
                queue[i]->edges[j]->visited = true;

                // If we have a direct connection to this node it is a candidate
                // for being the next hop
                if (queue[i]->edges[j]->node_socket) {
                    // If we don't have a next_hop, set it to this direct connection
                    // If we do have a next_hop already, replace it with this
                    // direct connection if its latency is higher
                    if (   !next_hop
                        ||  next_hop->rtt > queue[i]->edges[j]->node_socket->rtt)
                    {
                        next_hop = queue[i]->edges[j]->node_socket;
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
    char addr[INET6_ADDRSTRLEN];

    fprintf(out, "digraph osh_node_tree {\n");

    // We start by defining and labeling every node on the network
    for (size_t i = 0; i < oshd.node_tree_count; ++i) {
        char *color;
        char *style;
        char route[64];

        if (oshd.node_tree[i]->local_node) {
            // The local node is fully green
            color = "green";
            style = "filled";
            snprintf(route, sizeof(route), "(local)");
        } else if (oshd.node_tree[i]->online) {
            // Direct and indirect nodes are outlined in either green or turquoise
            style = "solid";
            if (oshd.node_tree[i]->node_socket) {
                color = "green";
                snprintf(route, sizeof(route), "(direct, %ims, %zu hops)",
                    oshd.node_tree[i]->node_socket->rtt,
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
    foreach_netroute_const(route, oshd.route_table, i) {
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
    foreach_netroute_const(route, oshd.route_table, i) {
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
            oshd.node_tree[i]->node_socket ? "direct" : "indirect",
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
                // Safety check, this should never happen but
                if (queue_count >= queue_maxcount) {
                    logger(LOG_CRIT, "%s: queue_count >= queue_maxcount", __func__);
                    abort();
                }
                queue[queue_count] = queue[i]->edges[j];
                queue_count += 1;
                queue[i]->edges[j]->visited = true;
                queue[i]->edges[j]->hops_count = queue[i]->hops_count + 1;
                queue[i]->edges[j]->online = true;

                // If we have a direct connection to this node, set its next_hop
                // now
                if (queue[i]->edges[j]->node_socket) {
                    queue[i]->edges[j]->next_hop = queue[i]->edges[j]->node_socket;
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
