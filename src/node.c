#include "node.h"
#include "oshd.h"
#include "events.h"
#include "logger.h"
#include "xalloc.h"
#include "random.h"
#include "crypto/hash.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
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

// Update the node_id's edges_hash
static void node_id_update_edges_hash(node_id_t *nid)
{
    // Format: node_id_name edge_name edge2_name edge3_name
    const char separator[] = " ";
    const size_t buf_size = ((nid->edges_count + 1) * (NODE_NAME_SIZE + 1)) + 1;
    char *buf = xzalloc(buf_size);
    node_id_t **ordered_edges = xmemdup(nid->edges, nid->edges_count * sizeof(node_id_t *));

    // Order the edges by name using the bubble-sort
    bool sorted = false;
    while (!sorted) {
        sorted = true;
        for (ssize_t i = 1; i < nid->edges_count; ++i) {
            if (strcmp(ordered_edges[i - 1]->name, ordered_edges[i]->name) > 0) {
                node_id_t *tmp = ordered_edges[i - 1];

                ordered_edges[i - 1] = ordered_edges[i];
                ordered_edges[i] = tmp;
                sorted = false;
            }
        }
    }

    // Create a checksum of the ordered edges
    strcat(buf, nid->name);
    strcat(buf, separator);
    for (ssize_t i = 0; i < nid->edges_count; ++i) {
        strcat(buf, ordered_edges[i]->name);
        if ((i + 1) < nid->edges_count)
            strcat(buf, separator);
    }
    free(ordered_edges);

    // Compute the SHA3-512 hash of this checksum
    if (!hash_sha3_512((uint8_t *) buf, strlen(buf),
            nid->edges_hash, &nid->edges_hash_size))
    {
        logger(LOG_CRIT, "Edges hash could not be computed for %s", nid->name);
        memset(nid->edges_hash, 0, sizeof(nid->edges_hash));
        nid->edges_hash_size = 0;
    }
    free(buf);

    hash_hexdump(nid->edges_hash, nid->edges_hash_size, nid->edges_hash_hex, false);
    logger_debug(DBG_NODETREE, "Edges hash of %s is %s", nid->name, nid->edges_hash_hex);
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
        id->endpoints = endpoint_group_create(id);
        gettimeofday(&id->endpoints_last_update, NULL);
        gettimeofday(&id->endpoints_next_retry, NULL);

        node_id_update_edges_hash(id);
    }
    return id;
}

// Free resources allocated to *nid and the structure
void node_id_free(node_id_t *nid)
{
    pkey_free(nid->pubkey);
    free(nid->pubkey_raw);
    free(nid->edges);
    free(nid->resolver_routes);
    endpoint_group_free(nid->endpoints);
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
// If a public key was already loaded it will not be loaded
bool node_id_set_pubkey(node_id_t *nid, const uint8_t *pubkey,
    size_t pubkey_size)
{
    if (nid->pubkey) {
        logger_debug(DBG_AUTHENTICATION, "Ignoring new public key for %s: One is already loaded", nid->name);
        return true;
    }

    if (!(nid->pubkey = pkey_load_ed25519_pubkey(pubkey, pubkey_size)))
        return false;

    free(nid->pubkey_raw);
    nid->pubkey_raw = xmemdup(pubkey, pubkey_size);
    nid->pubkey_raw_size = pubkey_size;
    nid->pubkey_local = false;
    return true;
}

// Append internal IP to a node
void node_id_add_resolver_route(node_id_t *nid, const netaddr_t *addr)
{
    // MAC addresses cannot be resolved
    if (addr->type == MAC)
        return;

    // Make sure that the route doesn't exist already
    for (size_t i = 0; i < nid->resolver_routes_count; ++i) {
        if (netaddr_eq(&nid->resolver_routes[i], addr))
            return;
    }

    if (logger_is_debugged(DBG_RESOLVER)) {
        char addrp[INET6_ADDRSTRLEN];

        netaddr_ntop(addrp, sizeof(addrp), addr);
        logger_debug(DBG_RESOLVER, "Adding %s to %s", addrp, nid->name);
    }

    nid->resolver_routes = xreallocarray(nid->resolver_routes,
        nid->resolver_routes_count + 1, sizeof(netaddr_t));
    netaddr_cpy(&nid->resolver_routes[nid->resolver_routes_count], addr);
    nid->resolver_routes_count += 1;
    oshd_resolver_append(addr, nid->name);
}

// Clear all internal IPs from a node
void node_id_clear_resolver_routes(node_id_t *nid)
{
    if (nid->resolver_routes) {
        logger_debug(DBG_RESOLVER, "Clearing routes from %s", nid->name);
        free(nid->resolver_routes);
        nid->resolver_routes = NULL;
        nid->resolver_routes_count = 0;
        oshd_resolver_update();
    }
}

// Clear remote endpoints from a node
void node_id_expire_endpoints(node_id_t *nid)
{
    logger_debug(DBG_ENDPOINTS, "%s: Expiring remote endpoints",
        nid->name);
    endpoint_group_clear(nid->endpoints);
    if (nid->endpoints_local)
        endpoint_group_add_group(nid->endpoints, nid->endpoints_local);
    gettimeofday(&nid->endpoints_last_update, NULL);
}

// Dynamically resize array and add *n to the end, then increment the count
static void node_id_array_append(node_id_t ***arr, size_t *count, node_id_t *n)
{
    const size_t alloc_count = 16;

    if ((*count) % alloc_count == 0)
        *arr = xreallocarray(*arr, (*count) + alloc_count, sizeof(node_id_t *));
    (*arr)[(*count)] = n;
    *count += 1;
}

/*
TODO: Maybe implement another algorithm to calculate and choose the lowest
      latency route instead of the shortest
*/
static node_t *node_id_find_next_hop(node_id_t *dest_node)
{
    // We clear visited status for every node
    for (size_t i = 0; i < oshd.node_tree_count; ++i)
        oshd.node_tree[i]->visited = false;

    // If we have a direct connection to the destination node we don't need to
    // search for the route (obviously)
    if (dest_node->node_socket)
        return dest_node->node_socket;

    // We visited the destination node
    dest_node->visited = 1;


    // Search through all edges of the node for a route
    // This is the current queue that we will explore
    node_id_t **queue = NULL;
    size_t queue_count = 0;

    // This is the next queue that will be populated with
    node_id_t **next_queue = NULL;
    size_t next_queue_count = 0;

    // This is a list of shortest routes
    // If there are more than one the next hop will be the route with the lowest
    // latency (RTT)
    node_id_t **routes = NULL;
    size_t routes_count = 0;
    node_t *next_hop = NULL;

    // We initialize our current queue with the current edges
    queue_count = (size_t) dest_node->edges_count;
    queue = xmemdup(dest_node->edges, sizeof(node_id_t *) * queue_count);

iterate_queue:
    // Iterate through the current queue to find a direct connection
    for (size_t i = 0; i < queue_count; ++i) {
        // If the node has a direct connection, we have a new route
        if (queue[i]->node_socket)
            node_id_array_append(&routes, &routes_count, queue[i]);
        queue[i]->visited = true;
    }

    // We found one or more routes
    if (routes_count) {
        next_hop = routes[0]->node_socket;

        // Select the lowest latency route if we have multiple routes
        for (size_t i = 1; i < routes_count; ++i) {
            if (routes[i]->node_socket->rtt < next_hop->rtt)
                next_hop = routes[i]->node_socket;
        }
    } else {
        // Iterate through the visited current queue again to queue the next
        // unvisited nodes
        for (size_t i = 0; i < queue_count; ++i) {
            for (ssize_t j = 0; j < queue[i]->edges_count; ++j) {
                if (!queue[i]->edges[j]->visited) {
                    node_id_array_append(&next_queue, &next_queue_count,
                        queue[i]->edges[j]);
                }
            }
        }

        // If we have more edges to explore, queue them and loop
        if (next_queue_count) {
            free(queue);
            queue = next_queue;
            queue_count = next_queue_count;
            next_queue = NULL;
            next_queue_count = 0;
            goto iterate_queue;
        }
    }

    // Free the temporary allocated memory
    free(queue);
    free(next_queue);
    free(routes);

    return next_hop;
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
        } else if (oshd.node_tree[i]->next_hop) {
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
                    oshd.node_tree[i]->next_hop->id->name,
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

    // We define and label our local routes
    for (size_t i = 0; i < oshd.local_routes_count; ++i) {
        netaddr_ntop(addr, sizeof(addr), &oshd.local_routes[i]);
        fprintf(out, "    \"%s\" [label=\"%s\", color=grey, style=solid];\n",
            addr, addr);
    }

    // We define and label the remote routes
    for (size_t i = 0; i < oshd.routes_count; ++i) {
        netaddr_ntop(addr, sizeof(addr), &oshd.routes[i]->addr);
        fprintf(out, "    \"%s\" [label=\"%s\", color=grey, style=solid];\n",
            addr, addr);
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

    // We connect our local node to its routes
    for (size_t i = 0; i < oshd.local_routes_count; ++i) {
        netaddr_ntop(addr, sizeof(addr), &oshd.local_routes[i]);
        fprintf(out, "    \"%s\" -> \"%s\";\n", oshd.name, addr);
    }

    // We connect the remote routes to their destination nodes
    for (size_t i = 0; i < oshd.routes_count; ++i) {
        netaddr_ntop(addr, sizeof(addr), &oshd.routes[i]->addr);
        fprintf(out, "    \"%s\" -> \"%s\";\n", oshd.routes[i]->dest_node->name, addr);
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
            oshd.node_tree[i]->next_hop ? oshd.node_tree[i]->next_hop->id->name : "(no route)",
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
// Sorts oshd.node_tree_ordered_hops before returning
// Returns the maximum hops_count
static size_t node_tree_calc_hops_count(void)
{
    node_id_t *local_node = node_id_find_local();

    // We clear visited status for every node
    for (size_t i = 0; i < oshd.node_tree_count; ++i) {
        // Nodes to which we don't have a route have a distance of 0
        if (!oshd.node_tree[i]->next_hop)
            oshd.node_tree[i]->hops_count = 0;

        oshd.node_tree[i]->visited = false;
    }

    // We visited our local node
    local_node->visited = 1;

    // This is the current queue that we will explore
    node_id_t **queue = NULL;
    size_t queue_count = 0;

    // This is the next queue that will be populated with
    node_id_t **next_queue = NULL;
    size_t next_queue_count = 0;

    // This is the current hops_count
    size_t hops_count = 0;

    // We initialize our current queue with the current edges
    queue_count = (size_t) local_node->edges_count;
    queue = xmemdup(local_node->edges, sizeof(node_id_t *) * queue_count);

iterate_queue:
    // Iterate through the current queue to find a direct connection
    for (size_t i = 0; i < queue_count; ++i) {
        queue[i]->hops_count = hops_count;
        queue[i]->visited = true;
    }

    // Iterate through the visited current queue again to queue the next
    // unvisited nodes
    for (size_t i = 0; i < queue_count; ++i) {
        for (ssize_t j = 0; j < queue[i]->edges_count; ++j) {
            if (!queue[i]->edges[j]->visited) {
                node_id_array_append(&next_queue, &next_queue_count,
                    queue[i]->edges[j]);
            }
        }
    }

    // If we have more edges to explore, queue them and loop
    if (next_queue_count) {
        free(queue);
        queue = next_queue;
        queue_count = next_queue_count;
        next_queue = NULL;
        next_queue_count = 0;
        hops_count += 1;
        goto iterate_queue;
    }

    // Free the temporary allocated memory
    free(queue);
    free(next_queue);

    // Before returning, sort the node IDs with their updated hops count
    node_id_sort_hops();
    return hops_count;
}

static void node_tree_update_next_hops(void)
{
    logger_debug(DBG_NODETREE, "Updating next hops");

    // We will never have to update the next hop or the edges or our local node,
    // so we skip by starting with the second element in the tree, because the
    // first will always be our local node
    for (size_t i = 1; i < oshd.node_tree_count; ++i) {
        oshd.node_tree[i]->next_hop = node_id_find_next_hop(oshd.node_tree[i]);

        /*
           If we have no route for this destination then we clear its edges
           If we don't we go out of sync
        */
        if (!oshd.node_tree[i]->next_hop)
        {
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

    // Re-compute the edges hash of every node (including our local node)
    for (size_t i = 0; i < oshd.node_tree_count; ++i)
        node_id_update_edges_hash(oshd.node_tree[i]);

    // After the node tree gets updated we need to re-calculate the next hops
    // of all nodes
    node_tree_update_next_hops();

    // Calculate the hops_count of all nodes in the tree
    node_tree_calc_hops_count();

    // We also need to delete all routes to orphan nodes
    oshd_route_del_orphan_routes();

    if (logger_is_debugged(DBG_NODETREE))
        node_tree_dump();
}

// Gracefully disconnect a node, sets the finish_and_disconnect flag to
// disconnect the node automatically after the send queue is emptied
// Unsets the POLLIN from the node's pfd events to drop all incoming packets
void node_graceful_disconnect(node_t *node)
{
    node->finish_and_disconnect = true;
    node_pollin_unset(node);
}

// Disconnect node
void node_disconnect(node_t *node)
{
    if (node->authenticated) {
        // Find our two nodes
        node_id_t *src = node_id_find_local();
        node_id_t *dest = node_id_find(node->id->name);

        // Make sure that we don't have a direct connection to this node
        node->id->node_socket = NULL;

        // We delete the edges between the local and the remote node
        node_id_del_edge(src, dest);

        // We broadcast this change to the rest of the network
        node_queue_edge_broadcast(node, EDGE_DEL, oshd.name, node->id->name);
        node_tree_update();
    }

    if (node->fd > 0) {
        logger(LOG_INFO, "Disconnecting %s", node->addrw);
        if (shutdown(node->fd, SHUT_RDWR) < 0) {
            logger_debug(DBG_SOCKETS, "%s: shutdown(%i): %s", node->addrw,
                node->fd, strerror(errno));
        }

        while (close(node->fd) < 0) {
            logger(LOG_ERR, "%s: close(%i): %s", node->addrw, node->fd,
                strerror(errno));
            if (errno != EINTR)
                break;
        }
        node->fd = -1;
    } else {
        logger(LOG_WARN, "%s: Already disconnected", node->addrw);
    }

    node_reconnect(node);
}

// Free the send/recv keys and ciphers and reset their values to NULL
static void node_reset_ciphers(node_t *node)
{
    pkey_free(node->send_key);
    cipher_free(node->send_cipher);
    pkey_free(node->recv_key);
    cipher_free(node->recv_cipher);
    node->send_key = NULL;
    node->send_cipher = NULL;
    node->recv_key = NULL;
    node->recv_cipher = NULL;
}

// Free a node and all its resources
void node_destroy(node_t *node)
{
    if (node->auth_timeout_event)
        event_cancel(node->auth_timeout_event);

    node_disconnect(node);
    free(node->hello_chall);
    free(node->io.recvbuf);
    netbuffer_free(node->io.sendq);
    node_reset_ciphers(node);
    free(node);
}

// Create and initialize a new node
node_t *node_init(int fd, bool initiator, netaddr_t *addr, uint16_t port)
{
    node_t *node = xzalloc(sizeof(node_t));
    char addrp[INET6_ADDRSTRLEN];

    node->fd = fd;
    node->initiator = initiator;

    // Write the node's address:port
    netaddr_ntop(addrp, sizeof(addrp), addr);
    snprintf(node->addrw, sizeof(node->addrw),
        (addr->type == IP6) ? "[%s]:%u" : "%s:%u", addrp, port);

    // Initialize network buffers
    node->io.recvbuf = xalloc(NODE_RECVBUF_SIZE);
    node->io.sendq = netbuffer_create(NODE_SENDQ_MIN_SIZE, NODE_SENDQ_ALIGNMENT);

    // Queue the authentication timeout event for the node
    // When it triggers if the socket is not authenticated it will be
    // disconnected
    event_queue_node_auth_timeout(node, NODE_AUTH_TIMEOUT);

    return node;
}

// Returns a valid delay within the minimum and maximum reconnection delays
time_t node_reconnect_delay_limit(time_t delay)
{
    // If delay is too small, return the minimum delay
    if (delay < oshd.reconnect_delay_min)
        return oshd.reconnect_delay_min;

    // If it is too big, return the maximum
    if (delay > oshd.reconnect_delay_max)
        return oshd.reconnect_delay_max;

    // Otherwise the delay is already within the limits, return it
    return delay;
}

// Set the node socket's reconnection delay
void node_reconnect_delay(node_t *node, time_t delay)
{
    node->reconnect_delay = node_reconnect_delay_limit(delay);
}

// Set the node's socket reconnection endpoints
// Destroys the previous endpoints if there were some
void node_reconnect_to(node_t *node, endpoint_group_t *reconnect_endpoints,
    time_t delay)
{
    if (!reconnect_endpoints) {
        // If this warning appears something in the code should be using
        // node_reconnect_disable instead of this function, this situation
        // should not happen
        logger(LOG_WARN, "%s: node_reconnect_to called without any endpoints",
            node->addrw);
        node->reconnect_endpoints = NULL;
    } else {
        node->reconnect_endpoints = reconnect_endpoints;
    }
    node_reconnect_delay(node, delay);
}

// Disable the node's reconnection
void node_reconnect_disable(node_t *node)
{
    node->reconnect_endpoints = NULL;
    node_reconnect_delay(node, oshd.reconnect_delay_min);
}

// Queue a reconnection to one or multiple endpoints with delay seconds between
// each loop
// Doubles the delay for future reconnections
void node_reconnect_endpoints(endpoint_group_t *reconnect_endpoints, time_t delay)
{
    time_t event_delay = node_reconnect_delay_limit(delay);

    if (endpoint_group_selected_ep(reconnect_endpoints)) {
        // We still have an endpoint, queue a reconnection to it
        event_queue_connect(reconnect_endpoints, event_delay, event_delay);
    } else {
        // We don't have an endpoint, this means that we reached the end of the
        // list

        if (endpoint_group_select_start(reconnect_endpoints) > 0) {
            // There are endpoints in the group, maybe try to reconnect

            // If this endpoint group doesn't have userdata it is a local endpoint
            // group, we will always retry to connect
            // If it has a userdata (node_id_t *) and its endpoints_local is true,
            // it also means that this is a local endpoint group
            // However if there is userdata and its endpoints_local is false, we
            // will give up trying to connect after several tries

            node_id_t *id = (node_id_t *) reconnect_endpoints->userdata;

            if (id && !id->endpoints_local) {
                logger(LOG_INFO, "Giving up trying to reconnect to %s", id->name);
            } else {
                // Increment the delay and go back to the start of the list
                event_delay = node_reconnect_delay_limit(delay * 2);
                event_queue_connect(reconnect_endpoints, event_delay, event_delay);
            }
        } else {
            // The group is empty, there is nothing to do
        }
    }
}

// Selects the next endpoint in the list before calling node_reconnect_endpoints
void node_reconnect_endpoints_next(endpoint_group_t *reconnect_endpoints, time_t delay)
{
    endpoint_group_select_next(reconnect_endpoints);
    node_reconnect_endpoints(reconnect_endpoints, delay);
}

// If node has a reconnect_endpoints, queue a reconnection
// If the previous reconnection was a success, start from the beginning of the
// list, otherwise choose the next endpoint in the list
void node_reconnect(node_t *node)
{
    if (node->reconnect_endpoints) {
        if (node->reconnect_success) {
            node->reconnect_success = false;
            endpoint_group_select_start(node->reconnect_endpoints);
            node_reconnect_endpoints(node->reconnect_endpoints, node->reconnect_delay);

            // If this node's reconnect endpoints is linked to a node ID and it
            // only has endpoints exchanged on the network, set the next retry
            // timestamp to prevent the endpoints event from queuing the same
            // group again
            node_id_t *id = (node_id_t *) node->reconnect_endpoints->userdata;

            if (id && !id->endpoints_local) {
                // The delay before retrying to connect is the maximum time one
                // endpoint can take to connect multiplied by the number of
                // endpoints in the group
                time_t delay_per_endpoint = node->reconnect_delay + NODE_AUTH_TIMEOUT;
                time_t group_delay = delay_per_endpoint * node->reconnect_endpoints->endpoints_count;

                gettimeofday(&id->endpoints_next_retry, NULL);
                id->endpoints_next_retry.tv_sec += group_delay;
            }
        } else {
            node_reconnect_endpoints_next(node->reconnect_endpoints, node->reconnect_delay);
        }
    }
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

// Queue a packet to the *node socket for *dest node
bool node_queue_packet(node_t *node, const char *dest, oshpacket_type_t type,
    uint8_t *payload, uint16_t payload_size)
{
    const size_t packet_size = OSHPACKET_HDR_SIZE + payload_size;
    uint8_t *slot = netbuffer_reserve(node->io.sendq, packet_size);
    oshpacket_hdr_t *hdr = (oshpacket_hdr_t *) slot;

    // Public part of the header
    hdr->magic = OSHPACKET_MAGIC;
    hdr->payload_size = htons(payload_size);

    // Private part of the header
    hdr->type = type;
    hdr->counter = htonl(node->send_counter);

    // Increment the node's send_counter for next packets
    node->send_counter += 1;

    memcpy(hdr->src_node, oshd.name, sizeof(hdr->src_node));
    memset(hdr->dest_node, 0, sizeof(hdr->dest_node));
    if (dest) memcpy(hdr->dest_node, dest, strlen(dest));

    // Copy the packet's payload to the buffer
    memcpy(slot + OSHPACKET_HDR_SIZE, payload, payload_size);

    if (node->send_cipher) {
        // The node expects all traffic to be encrypted
        size_t original_size = OSHPACKET_PRIVATE_HDR_SIZE + payload_size;
        size_t out_size;
        logger_debug(DBG_ENCRYPTION, "%s: Encrypting packet of %zu bytes",
            node->addrw, original_size);

        // We are encrypting everything that comes after the public header
        // The public header is never encrypted, it is the required minimum
        // to correctly receive and decode all packets
        // The private header part as well as the payload will be decrypted
        // after successful reception before being processed.
        // This is to protect more data, like the counter (used to prevent
        // replay attacks) and the source and destination nodes
        // If these aren't encrypted a MITM attack could modify those fields
        // to cause trouble or spy on/target specific nodes
        if (!cipher_encrypt(node->send_cipher, slot + OSHPACKET_PUBLIC_HDR_SIZE,
                &out_size, slot + OSHPACKET_PUBLIC_HDR_SIZE, original_size))
        {
            logger(LOG_ERR, "%s: Failed to encrypt packet", node->addrw);
            netbuffer_cancel(node->io.sendq, packet_size);
            return false;
        }
        if (out_size != original_size) {
            // TODO: Handle this correctly for ciphers that pad encrypted data
            logger(LOG_ERR, "%s: Encrypted packet has a different size (original: %zu, encrypted %zu)",
                node->addrw, original_size, out_size);
            netbuffer_cancel(node->io.sendq, packet_size);
            return false;
        }
    } else if (type != HANDSHAKE) {
        // The node does not have a cipher to encrypt traffic
        // This should only happen when sending HANDSHAKE packets which will
        // initialize the ciphers
        // Otherwise drop the packet
        // GOODBYE packets should close the connection so if there's no data
        // queued after a failed GOODBYE we can remove the node
        logger(LOG_CRIT, "%s: Cannot queue unencrypted %s packet",
            node->addrw, oshpacket_type_name(type));
        netbuffer_cancel(node->io.sendq, packet_size);

        if (type == GOODBYE) {
            if (netbuffer_data_size(node->io.sendq) == 0)
                event_queue_node_remove(node);
        }
        return false;
    }
    node_pollout_set(node);
    return true;
}

// Queue a forwarded packet without altering the source and destination nodes
bool node_queue_packet_forward(node_t *node, oshpacket_hdr_t *pkt)
{
    const size_t packet_size = OSHPACKET_HDR_SIZE + pkt->payload_size;
    uint8_t *slot;
    oshpacket_hdr_t *hdr;

    // Forwarded packets should never be unencrypted, so if we can't encrypt it,
    // drop it
    if (!node->send_cipher) {
        logger(LOG_WARN, "%s: Dropping forwarded %s packet of %u bytes: No send_cipher",
            node->addrw, oshpacket_type_name(pkt->type), pkt->payload_size);
        return false;
    }

    slot = netbuffer_reserve(node->io.sendq, packet_size);
    hdr = (oshpacket_hdr_t *) slot;

    // Copy the packet's data to the slot
    memcpy(slot, pkt, packet_size);

    // Write the payload size in the correct order
    hdr->payload_size = htons(pkt->payload_size);

    // The counter is not preserved, it is always set to the node we're
    // sending the packet to
    hdr->counter = htonl(node->send_counter);

    // Increment the node's send_counter for next packets
    node->send_counter += 1;

    // The node expects all traffic to be encrypted
    size_t original_size = OSHPACKET_PRIVATE_HDR_SIZE + pkt->payload_size;
    size_t out_size;
    logger_debug(DBG_ENCRYPTION, "%s: Encrypting forwarded packet of %zu bytes",
        node->addrw, original_size);

    // We are encrypting everything that comes after the public header
    // The public header is never encrypted, it is the required minimum
    // to correctly receive and decode all packets
    // The private header part as well as the payload will be decrypted
    // after successful reception before being processed.
    // This is to protect more data, like the counter (used to prevent
    // replay attacks) and the source and destination nodes
    // If these aren't encrypted a MITM attack could modify those fields
    // to cause trouble or spy on/target specific nodes
    if (!cipher_encrypt(node->send_cipher, slot + OSHPACKET_PUBLIC_HDR_SIZE,
            &out_size, slot + OSHPACKET_PUBLIC_HDR_SIZE, original_size))
    {
        logger(LOG_ERR, "%s: Failed to encrypt forwarded packet", node->addrw);
        netbuffer_cancel(node->io.sendq, packet_size);
        return false;
    }
    if (out_size != original_size) {
        // TODO: Handle this correctly for ciphers that pad encrypted data
        logger(LOG_ERR, "%s: Encrypted forwarded packet has a different size (original: %zu, encrypted %zu)",
            node->addrw, original_size, out_size);
        netbuffer_cancel(node->io.sendq, packet_size);
        return false;
    }
    node_pollout_set(node);
    return true;
}

// Broadcast a packet to all nodes
// If exclude is not NULL the packet will not be queued for the excluded node
bool node_queue_packet_broadcast(node_t *exclude, oshpacket_type_t type,
    uint8_t *payload, uint16_t payload_size)
{
    // We will never broadcast a packet to the local node, so skip it by
    // starting with the second element, the first one will always be our local
    // node
    for (size_t i = 1; i < oshd.node_tree_count; ++i) {
        if (    oshd.node_tree[i]->next_hop
            &&  oshd.node_tree[i]->next_hop != exclude)
        {
            logger_debug(DBG_SOCKETS,
                "Broadcasting %s packet for %s through %s (%s, %u bytes)",
                oshpacket_type_name(type),
                oshd.node_tree[i]->name,
                oshd.node_tree[i]->next_hop->id->name,
                oshd.node_tree[i]->next_hop->addrw,
                payload_size);
            node_queue_packet(oshd.node_tree[i]->next_hop, oshd.node_tree[i]->name,
                type, payload, payload_size);
        }
    }
    return true;
}

// Queue packet with a fragmented payload
// If the payload is too big for one packet it will be fragmented and sent with
// as many packets as needed
// This can only be used for repeating payloads, like edges and routes which
// are processed as a flat array
// If broadcast is true, *node is a node to exclude from the broadcast (can be
// NULL)
// Otherwise the fragmented packet will be sent to *node (should be
// authenticated)
static bool node_queue_packet_fragmented(node_t *node, oshpacket_type_t type,
    void *payload, size_t payload_size, size_t entry_size, bool broadcast)
{
    size_t max_entries = OSHPACKET_PAYLOAD_MAXSIZE / entry_size;
    size_t remaining_entries = payload_size / entry_size;
    uint8_t *curr_buf = (uint8_t *) payload;

    while (remaining_entries > 0) {
        size_t entries;
        size_t size;

        // Calculate how many entries from the payload we can send
        if (remaining_entries > max_entries)
            entries = max_entries;
        else
            entries = remaining_entries;

        // Calculate the fragmented payload size
        size = entries * entry_size;

        // Send the fragmented packet
        if (broadcast) {
            logger_debug(DBG_SOCKETS, "Broadcasting fragmented %s packet with %zu entries (%zu bytes)",
                oshpacket_type_name(type), entries, size);
            if (!node_queue_packet_broadcast(node, type, curr_buf, size))
                return false;
        } else {
            logger_debug(DBG_SOCKETS, "%s: %s: Queuing fragmented %s packet with %zu entries (%zu bytes)",
                node->addrw, node->id->name, oshpacket_type_name(type), entries, size);
            if (!node_queue_packet(node, node->id->name, type, curr_buf, size))
                return false;
        }

        // Iterate to the next entries
        remaining_entries -= entries;
        curr_buf += size;
    }
    return true;
}

// Queue HANDSHAKE request
bool node_queue_handshake(node_t *node, bool initiator)
{
    oshpacket_handshake_t packet;

    node->handshake_initiator = initiator;
    logger_debug(DBG_HANDSHAKE, "Creating HANDSHAKE packet for %s", node->addrw);

    // Make sure that there are no memory leaks
    node_reset_ciphers(node);

    // Generate random keys
    logger_debug(DBG_HANDSHAKE, "%s: Generating send_key", node->addrw);
    if (!(node->send_key = pkey_generate_x25519()))
        return false;
    logger_debug(DBG_HANDSHAKE, "%s: Generating recv_key", node->addrw);
    if (!(node->recv_key = pkey_generate_x25519()))
        return false;

    uint8_t *pubkey;
    size_t pubkey_size;

    // Export the keys to the packet
    logger_debug(DBG_HANDSHAKE, "%s: Exporting send_key", node->addrw);
    if (!pkey_save_x25519_pubkey(node->send_key, &pubkey, &pubkey_size))
        return false;
    if (pubkey_size != sizeof(packet.send_pubkey)) {
        free(pubkey);
        logger(LOG_ERR, "%s: send_key size is invalid (%zu, but expected %zu)",
            node->addrw, pubkey_size, sizeof(packet.send_pubkey));
        return false;
    }
    memcpy(packet.send_pubkey, pubkey, pubkey_size);
    free(pubkey);

    logger_debug(DBG_HANDSHAKE, "%s: Exporting recv_key", node->addrw);
    if (!pkey_save_x25519_pubkey(node->recv_key, &pubkey, &pubkey_size))
        return false;
    if (pubkey_size != sizeof(packet.recv_pubkey)) {
        free(pubkey);
        logger(LOG_ERR, "%s: recv_key size is invalid (%zu, but expected %zu)",
            node->addrw, pubkey_size, sizeof(packet.recv_pubkey));
        return false;
    }
    memcpy(packet.recv_pubkey, pubkey, pubkey_size);
    free(pubkey);

    return node_queue_packet(node, NULL, HANDSHAKE, (uint8_t *) &packet, sizeof(packet));
}

// Queue HELLO_CHALLENGE request
bool node_queue_hello_challenge(node_t *node)
{
    free(node->hello_chall);
    node->hello_chall = xalloc(sizeof(oshpacket_hello_challenge_t));

    memcpy(node->hello_chall->node_name, oshd.name, NODE_NAME_SIZE);
    if (!read_random_bytes(node->hello_chall->challenge, sizeof(node->hello_chall->challenge)))
        return false;

    return node_queue_packet(node, NULL, HELLO_CHALLENGE, (uint8_t *) node->hello_chall,
        sizeof(oshpacket_hello_challenge_t));
}

// Queue HELLO_END packet
bool node_queue_hello_end(node_t *node)
{
    oshpacket_hello_end_t packet;

    if (node->hello_auth) {
        logger_debug(DBG_AUTHENTICATION, "%s: Successful HELLO_END",
            node->addrw);
        packet.hello_success = 1;
    } else {
        logger_debug(DBG_AUTHENTICATION, "%s: Failed HELLO_END",
            node->addrw);
        packet.hello_success = 0;
        node_graceful_disconnect(node);
    }
    return node_queue_packet(node, NULL, HELLO_END,
        (uint8_t *) &packet, sizeof(packet));
}

// Queue DEVMODE packet
bool node_queue_devmode(node_t *node)
{
    oshpacket_devmode_t packet;

    packet.devmode = oshd.device_mode;
    return node_queue_packet(node, node->id->name, DEVMODE,
        (uint8_t *) &packet, sizeof(packet));
}

// Queue STATEEXG_END packet
bool node_queue_stateexg_end(node_t *node)
{
    uint8_t buf = 0;

    return node_queue_packet(node, node->id->name, STATEEXG_END, &buf, sizeof(buf));
}

// Queue GOODBYE request
bool node_queue_goodbye(node_t *node)
{
    uint8_t buf = 0;

    node_graceful_disconnect(node);
    return node_queue_packet(node, node->id->name, GOODBYE, &buf, sizeof(buf));
}

// Queue PING request
bool node_queue_ping(node_t *node)
{
    uint8_t buf = 0;

    gettimeofday(&node->rtt_ping, NULL);
    return node_queue_packet(node, node->id->name, PING, &buf, 1);
}

// Queue PONG request
bool node_queue_pong(node_t *node)
{
    uint8_t buf = 0;

    return node_queue_packet(node, node->id->name, PONG, &buf, 1);
}

// Broadcast a node's public key
bool node_queue_pubkey_broadcast(node_t *exclude, node_id_t *id)
{
    oshpacket_pubkey_t packet;

    if (   !id->pubkey
        || !id->pubkey_raw
        || id->pubkey_raw_size != PUBLIC_KEY_SIZE)
    {
        logger(LOG_ERR, "Failed to broadcast public key of %s: No public key",
            id->name);
        return false;
    }

    logger_debug(DBG_AUTHENTICATION, "Public keys exchange: Broadcasting %s", id->name);
    memcpy(packet.node_name, id->name, NODE_NAME_SIZE);
    memcpy(packet.node_pubkey, id->pubkey_raw, PUBLIC_KEY_SIZE);

    return node_queue_packet_broadcast(exclude, PUBKEY, (uint8_t *) &packet,
        sizeof(packet));
}

// Queue PUBKEY exchange packet
bool node_queue_pubkey_exg(node_t *node)
{
    oshpacket_pubkey_t *pubkeys = NULL;
    size_t count = 0;
    bool success;

    for (size_t i = 0; i < oshd.node_tree_count; ++i) {
        // Only exchange public keys from online nodes
        if (   !oshd.node_tree[i]->next_hop
            || !oshd.node_tree[i]->pubkey
            || !oshd.node_tree[i]->pubkey_raw
            ||  oshd.node_tree[i]->pubkey_raw_size != PUBLIC_KEY_SIZE)
        {
            continue;
        }

        logger_debug(DBG_AUTHENTICATION, "Public keys exchange: Adding %s", oshd.node_tree[i]->name);
        pubkeys = xreallocarray(pubkeys, count + 1, sizeof(oshpacket_pubkey_t));
        memcpy(pubkeys[count].node_name, oshd.node_tree[i]->name, NODE_NAME_SIZE);
        memcpy(pubkeys[count].node_pubkey, oshd.node_tree[i]->pubkey_raw, PUBLIC_KEY_SIZE);
        count += 1;
    }

    success = node_queue_packet_fragmented(node, PUBKEY, pubkeys,
        sizeof(oshpacket_pubkey_t) * count, sizeof(oshpacket_pubkey_t), false);
    free(pubkeys);
    return success;
}

// Broadcast local endpoints
bool node_queue_local_endpoint_broadcast(node_t *exclude)
{
    node_id_t *local_id = node_id_find_local();
    oshpacket_endpoint_t *endpoints;
    size_t count = local_id->endpoints->endpoints_count;
    bool expire_success, broadcast_success;

    if (count == 0)
        return true;

    endpoints = xalloc(count * sizeof(oshpacket_endpoint_t));
    for (size_t i = 0; i < count; ++i) {
        netaddr_t addr;

        if (!netaddr_lookup(&addr, local_id->endpoints->endpoints[i].hostname)) {
            logger(LOG_WARN,
                "Skipping local endpoint %s:%u in endpoint broadcast (lookup failed)",
                local_id->endpoints->endpoints[i].hostname,
                local_id->endpoints->endpoints[i].port);
            continue;
        }

        memcpy(endpoints[i].node_name, local_id->name, NODE_NAME_SIZE);
        endpoints[i].addr_type = addr.type;
        memcpy(endpoints[i].addr_data, addr.data, 16);
        endpoints[i].port = htons(local_id->endpoints->endpoints[i].port);
    }

    oshpacket_endpoint_expire_t expire;

    memcpy(expire.node_name, local_id->name, NODE_NAME_SIZE);

    expire_success = node_queue_packet_broadcast(exclude, ENDPOINT_EXPIRE,
        (uint8_t *) &expire, sizeof(expire));
    broadcast_success = node_queue_packet_fragmented(exclude, ENDPOINT, endpoints,
        sizeof(oshpacket_endpoint_t) * count, sizeof(oshpacket_endpoint_t), true);

    free(endpoints);
    return expire_success && broadcast_success;
}

// Queue ENDPOINT exchange packet
bool node_queue_endpoint_exg(node_t *node)
{
    oshpacket_endpoint_t *endpoints = NULL;
    size_t count = 0;
    bool success;

    for (size_t i = 0; i < oshd.node_tree_count; ++i) {
        // If we don't share our endpoints, skip our local node
        if (oshd.node_tree[i]->local_node && !oshd.shareendpoints)
            continue;

        for (size_t j = 0; j < oshd.node_tree[i]->endpoints->endpoints_count; ++j) {
            netaddr_t addr;

            if (!netaddr_lookup(&addr, oshd.node_tree[i]->endpoints->endpoints[j].hostname)) {
                logger(LOG_WARN,
                    "%s: %s: Skipping endpoint %s:%u in endpoint exchange (lookup failed)",
                    node->addrw,
                    node->id->name,
                    oshd.node_tree[i]->endpoints->endpoints[j].hostname,
                    oshd.node_tree[i]->endpoints->endpoints[j].port);
                continue;
            }

            endpoints = xreallocarray(endpoints, count + 1, sizeof(oshpacket_endpoint_t));

            memcpy(endpoints[count].node_name, oshd.node_tree[i]->name, NODE_NAME_SIZE);
            endpoints[count].addr_type = addr.type;
            memcpy(endpoints[count].addr_data, addr.data, 16);
            endpoints[count].port = htons(oshd.node_tree[i]->endpoints->endpoints[j].port);
            count += 1;
        }
    }

    success = node_queue_packet_fragmented(node, ENDPOINT, endpoints,
        sizeof(oshpacket_endpoint_t) * count, sizeof(oshpacket_endpoint_t), false);
    free(endpoints);
    return success;
}

// Queue EDGE_ADD or EDGE_DEL request
bool node_queue_edge(node_t *node, oshpacket_type_t type,
    const char *src, const char *dest)
{
    oshpacket_edge_t buf;

    switch (type) {
        case EDGE_ADD:
        case EDGE_DEL:
            memcpy(buf.src_node, src,  NODE_NAME_SIZE);
            memcpy(buf.dest_node, dest, NODE_NAME_SIZE);
            return node_queue_packet(node, node->id->name, type,
                        (uint8_t *) &buf, sizeof(oshpacket_edge_t));

        default:
            logger(LOG_ERR, "node_queue_edge: Invalid type %s",
                oshpacket_type_name(type));
            return false;
    }
}

// Broadcast EDGE_ADD or EDGE_DEL request
bool node_queue_edge_broadcast(node_t *exclude, oshpacket_type_t type,
    const char *src, const char *dest)
{
    oshpacket_edge_t buf;

    switch (type) {
        case EDGE_ADD:
        case EDGE_DEL:
            memcpy(buf.src_node, src,  NODE_NAME_SIZE);
            memcpy(buf.dest_node, dest, NODE_NAME_SIZE);
            return node_queue_packet_broadcast(exclude, type,
                    (uint8_t *) &buf, sizeof(oshpacket_edge_t));

        default:
            logger(LOG_ERR, "node_queue_edge: Invalid type %s",
                oshpacket_type_name(type));
            return false;
    }
}

// Dynamically append edges to *buf
static void edge_exg_append(oshpacket_edge_t **buf, size_t *buf_count,
    const char *src_node, const char *dest_node, const char *edge_type,
    node_id_t *remote_node)
{
    const size_t alloc_count = 16;

    // Trim edges of the remote node with which we are exchanging states, it
    // will already know its edges
    if (   !strcmp(src_node, remote_node->name)
        || !strcmp(dest_node, remote_node->name))
    {
        // This edge is owned by the remote node, it already knows about it
        logger_debug(DBG_NODETREE, "    Skipped: %s: %s <=> %s (remote)",
            edge_type, src_node, dest_node);
        return;
    }

    // Trim repeating edges
    // Including src -> dest and dest -> src
    // The source and destination edges will be linked bidirectionally so we can
    // send one direction only
    for (size_t i = 0; i < (*buf_count); ++i) {
        if (   !strcmp((*buf)[i].src_node, dest_node)
            && !strcmp((*buf)[i].dest_node, src_node))
        {
            // This edge is already in the list in the other direction
            logger_debug(DBG_NODETREE, "    Skipped: %s: %s <=> %s (repeating)",
                edge_type, src_node, dest_node);
            return;
        }
    }

    // Add this edge to the buffer
    logger_debug(DBG_NODETREE, "    Adding : %s: %s <=> %s",
        edge_type, src_node, dest_node);

    // Reallocate more alloc_count items in the buffer when we need more memory
    if ((*buf_count) % alloc_count == 0)
        *buf = xreallocarray(*buf, (*buf_count) + alloc_count, sizeof(oshpacket_edge_t));

    memcpy((*buf)[(*buf_count)].src_node, src_node, NODE_NAME_SIZE);
    memcpy((*buf)[(*buf_count)].dest_node, dest_node, NODE_NAME_SIZE);
    *buf_count += 1;
}

// Queue EDGE_ADD packets for *node with the whole network map
bool node_queue_edge_exg(node_t *node)
{
    size_t buf_count = 0;
    oshpacket_edge_t *buf = NULL;

    /*
       TODO: We can also optimize this more by creating/updating this buffer
             on after a node_tree_update() instead of doing it here
    */

    logger_debug(DBG_NODETREE, "%s: %s: Creating EDGE_ADD packets (state exchange)",
        node->addrw, node->id->name);

    // We skip the local node because it is useless, by starting with the
    // second element, because the first one will always be our local node
    for (size_t i = 1; i < oshd.node_tree_count; ++i) {
        // Direct edge
        if (oshd.node_tree[i]->node_socket)
            edge_exg_append(&buf, &buf_count, oshd.name, oshd.node_tree[i]->name,
                "Direct", node->id);

        // Indirect edges
        for (ssize_t j = 0; j < oshd.node_tree[i]->edges_count; ++j) {
            edge_exg_append(&buf, &buf_count, oshd.node_tree[i]->name,
                oshd.node_tree[i]->edges[j]->name, "Indirect", node->id);
        }
    }

    size_t buf_size = buf_count * sizeof(oshpacket_edge_t);
    bool success = node_queue_packet_fragmented(node, EDGE_ADD, buf, buf_size,
        sizeof(oshpacket_edge_t), false);

    // We need to free the memory before returning
    free(buf);
    return success;
}

// Broadcast ROUTE_ADD request with one or more local routes
bool node_queue_route_add_local(node_t *exclude, const netaddr_t *addrs,
    size_t count)
{
    if (count == 0)
        return true;

    size_t buf_size = sizeof(oshpacket_route_t) * count;
    oshpacket_route_t *buf = xalloc(buf_size);

    // Format the addresses's type and data into buf
    for (size_t i = 0; i < count; ++i) {
        memcpy(buf[i].node_name, oshd.name, NODE_NAME_SIZE);
        buf[i].addr_type = addrs[i].type;
        memcpy(buf[i].addr_data, addrs[i].data, 16);
    }

    bool success = node_queue_packet_fragmented(exclude, ROUTE_ADD, buf, buf_size,
        sizeof(oshpacket_route_t), true);

    // We need to free the memory before returning
    free(buf);
    return success;
}

// Queue ROUTE_ADD request with all our known routes
bool node_queue_route_exg(node_t *node)
{
    size_t count = oshd.local_routes_count + oshd.routes_count;

    if (count == 0)
        return true;

    size_t buf_size = sizeof(oshpacket_route_t) * count;
    oshpacket_route_t *buf = xalloc(buf_size);

    // Format the addresses's type and data into buf
    size_t i = 0;

    // Copy our local routes first
    for (size_t j = 0; j < oshd.local_routes_count; ++j, ++i) {
        memcpy(buf[i].node_name, oshd.name, NODE_NAME_SIZE);
        buf[i].addr_type = oshd.local_routes[j].type;
        memcpy(buf[i].addr_data, oshd.local_routes[j].data, 16);
    }

    // Copy all other routes
    for (size_t j = 0; j < oshd.routes_count; ++j, ++i) {
        memcpy(buf[i].node_name, oshd.routes[j]->dest_node->name, NODE_NAME_SIZE);
        buf[i].addr_type = oshd.routes[j]->addr.type;
        memcpy(buf[i].addr_data, oshd.routes[j]->addr.data, 16);
    }

    // If we our device is in TAP mode we should also exchange IPv4/6 routes for
    // the resolver
    // This will append all the resolver routes to the packet
    if (oshd.tuntap && oshd.tuntap->is_tap) {
        for (size_t j = 0; j < oshd.node_tree_count; ++j) {
            for (size_t k = 0; k < oshd.node_tree[j]->resolver_routes_count; ++k, ++i) {
                buf_size += sizeof(oshpacket_route_t);
                buf = xrealloc(buf, buf_size);
                memcpy(buf[i].node_name, oshd.node_tree[j]->name, NODE_NAME_SIZE);
                buf[i].addr_type = oshd.node_tree[j]->resolver_routes[k].type;
                memcpy(buf[i].addr_data, oshd.node_tree[j]->resolver_routes[k].data, 16);
            }
        }
    }

    bool success = node_queue_packet_fragmented(node, ROUTE_ADD, buf, buf_size,
        sizeof(oshpacket_route_t), false);

    // We need to free the memory before returning
    free(buf);
    return success;
}