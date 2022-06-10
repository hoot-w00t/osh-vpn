#include "node.h"
#include "oshd.h"
#include "events.h"
#include "logger.h"
#include "xalloc.h"
#include "random.h"
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

static node_t *node_id_find_next_hop(node_id_t *dest_node)
{
    const size_t queue_maxcount = oshd.node_tree_count;
    node_t *next_hop = NULL;
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
node_t *node_id_next_hop(node_id_t *id)
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

// Gracefully disconnect a node, sets the finish_and_disconnect flag to
// disconnect the node automatically after the send queue is emptied
// Disables AIO_READ from the node's poll_events to drop all incoming packets
void node_graceful_disconnect(node_t *node)
{
    node->finish_and_disconnect = true;
    aio_disable_poll_events(node->aio_event, AIO_READ);
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

// Free all send/recv keys and ciphers and reset their values to NULL
static void node_reset_ciphers(node_t *node)
{
    pkey_free(node->send_key);
    cipher_free(node->send_cipher);
    pkey_free(node->recv_key);
    cipher_free(node->recv_cipher);
    cipher_free(node->recv_cipher_next);
    node->send_key = NULL;
    node->send_cipher = NULL;
    node->recv_key = NULL;
    node->recv_cipher = NULL;
    node->recv_cipher_next = NULL;
}

// Free a node and all its resources
void node_destroy(node_t *node)
{
    event_cancel(node->handshake_renew_event);
    event_cancel(node->handshake_timeout_event);
    event_cancel(node->auth_timeout_event);

    node_disconnect(node);
    free(node->unauth_handshake);
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

    node->fd = fd;
    node->initiator = initiator;

    // Write the node's address:port
    if (!netaddr_ntop2(node->addrw, sizeof(node->addrw), addr, port))
        snprintf(node->addrw, sizeof(node->addrw), "(invalid address)");

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

    if (endpoint_group_selected(reconnect_endpoints)) {
        // We still have an endpoint, queue a reconnection to it
        event_queue_connect(reconnect_endpoints, event_delay, event_delay);
    } else {
        // We don't have an endpoint, this means that we reached the end of the
        // list
        if (endpoint_group_select_first(reconnect_endpoints)) {
            // There are endpoints in the group, maybe try to reconnect
            if (reconnect_endpoints->always_retry) {
                // Increment the delay and go back to the start of the list
                event_delay = node_reconnect_delay_limit(delay * 2);
                event_queue_connect(reconnect_endpoints, event_delay, event_delay);
            } else {
                logger(LOG_INFO, "Giving up trying to reconnect to %s",
                    reconnect_endpoints->owner_name);
                endpoint_group_set_is_connecting(reconnect_endpoints, false);
            }
        } else {
            // The group is empty, there is nothing to do
            logger(LOG_INFO, "Giving up trying to reconnect to %s (no endpoints)",
                reconnect_endpoints->owner_name);
            endpoint_group_set_is_connecting(reconnect_endpoints, false);
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
        if (endpoint_group_is_connecting(node->reconnect_endpoints)) {
            node_reconnect_endpoints_next(node->reconnect_endpoints, node->reconnect_delay);
        } else {
            endpoint_group_select_first(node->reconnect_endpoints);
            node_reconnect_endpoints(node->reconnect_endpoints, node->reconnect_delay);
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

// Returns true if the broadcast ID was seen already
// The ID will be marked as seen if it was not
bool node_has_seen_brd_id(node_id_t *nid, const oshpacket_brd_id_t brd_id)
{
    for (size_t i = 0; i < nid->seen_brd_id_count; ++i) {
        // If any value in the seen_brd_id array is the same as brd_id it means
        // that we have already seen and processed this packet
        if (nid->seen_brd_id[i] == brd_id)
            return true;
    }

    // Shift all values in the array and insert the new broadcast ID
    memmove(nid->seen_brd_id + 1, nid->seen_brd_id + 0,
        sizeof(nid->seen_brd_id) - sizeof(oshpacket_brd_id_t));

    nid->seen_brd_id[0] = brd_id;

    if (nid->seen_brd_id_count < seen_brd_id_maxsize)
        nid->seen_brd_id_count += 1;

    return false;
}

// Returns true if the DATA packet should be dropped (when the send queue is
// full or filling up too fast)
static bool data_packet_should_drop(node_t *node)
{
    if (netbuffer_data_size(node->io.sendq) >= NODE_SENDQ_DATA_SIZE_MIN) {
        const size_t random_drop_above = rand() % NODE_SENDQ_DATA_SIZE_MAX;

        // Randomly drop packets with an increasing chance as the queue size
        // gets closer to the maximum.
        // When the queue size is at or above the maximum we drop every packet
        if (netbuffer_data_size(node->io.sendq) >= random_drop_above) {
            logger_debug(DBG_TUNTAP,
                "%s: Data packet should drop: queue at %zu/%i bytes (%zu%%, drop above: %zu)",
                node->addrw,
                netbuffer_data_size(node->io.sendq),
                NODE_SENDQ_DATA_SIZE_MAX,
                (netbuffer_data_size(node->io.sendq) * 100 / NODE_SENDQ_DATA_SIZE_MAX),
                random_drop_above);
            return true;
        }
    }
    return false;
}

// Actually queue a packet
// The private part of the header must be initialized before calling this
// function, but not the public part as it will be initialized here
// This function also takes care of dropping DATA packets when needed
// Returns false if the packet was not queued (for any error/reason)
//
// Warning: If the payload is NULL but the payload size is different than 0
//          there will be uninitialized bytes sent as the payload
static bool node_queue_packet_internal(
    node_t *node,
    const oshpacket_hdr_t *hdr,
    const void *payload,
    const size_t payload_size)
{
    const size_t packet_size = OSHPACKET_HDR_SIZE + payload_size;
    uint8_t *slot;

    // Drop packet if its size exceeds the limit
    if (packet_size > OSHPACKET_MAXSIZE) {
        logger(LOG_ERR,
            "%s: Dropping %s packet of %zu bytes (exceeds size limit)",
            node->addrw, oshpacket_type_name(hdr->type), packet_size);
        return false;
    }

    // Drop DATA packets if the send queue exceeds a limit
    // This is a very basic way to handle network congestion, but without it the
    // send queue can accumulate an infinite amount of packets and this could
    // create a denial of service between two nodes until we can catch up and
    // the send queue flushes all of its data (this could take days in the worst
    // cases)
    if (   hdr->type == DATA
        && data_packet_should_drop(node))
    {
        logger_debug(DBG_TUNTAP, "%s: Dropping %s packet of %zu bytes",
            node->addrw, oshpacket_type_name(hdr->type), payload_size);
        return false;
    }

    slot = netbuffer_reserve(node->io.sendq, packet_size);

    // Initialize the public part of the header
    OSHPACKET_HDR(slot)->payload_size = htons(((uint16_t) payload_size));

    // Copy the private part of the header which was initialized by the caller
    memcpy(OSHPACKET_PRIVATE_HDR(slot), OSHPACKET_PRIVATE_HDR_CONST(hdr),
        OSHPACKET_PRIVATE_HDR_SIZE);

    // Copy the packet's payload to the buffer (if there is one)
    if (payload)
        memcpy(OSHPACKET_PAYLOAD(slot), payload, payload_size);

    if (node->send_cipher) {
        // The socket has a send_cipher, so the packet will be encrypted

        // We encrypt the private header and the payload but not the public
        // header as it is required to properly receive and decode the packet
        const size_t orig_size = OSHPACKET_PRIVATE_HDR_SIZE + payload_size;
        size_t encr_size;

        logger_debug(DBG_ENCRYPTION, "%s: Encrypting packet of %zu bytes",
            node->addrw, orig_size);

        if (!cipher_encrypt(node->send_cipher,
                OSHPACKET_PRIVATE_HDR(slot), &encr_size,
                OSHPACKET_PRIVATE_HDR(slot), orig_size,
                OSHPACKET_HDR(slot)->tag))
        {
            logger(LOG_ERR, "%s: Failed to encrypt packet", node->addrw);
            netbuffer_cancel(node->io.sendq, packet_size);
            return false;
        }

        // The encrypted data must have the same size as the original
        if (encr_size != orig_size) {
            logger(LOG_ERR,
                "%s: Encrypted packet has a different size (original: %zu, encrypted %zu)",
                node->addrw, orig_size, encr_size);
            netbuffer_cancel(node->io.sendq, packet_size);
            return false;
        }

    } else if (hdr->type == HANDSHAKE) {
        // The socket does not have a send cipher yet but the packet is a
        // HANDSHAKE, we only allow this type of packet to be sent unencrypted
        // as it will initialize encryption ciphers

        // Zero the source and destination as they will not be taken into
        // account yet; this prevents leaking the nodes' names in plain text
        memset(OSHPACKET_HDR(slot)->src_node, 0,
            sizeof(OSHPACKET_HDR(slot)->src_node));
        memset(&OSHPACKET_HDR(slot)->dest, 0,
            sizeof(OSHPACKET_HDR(slot)->dest));

        // Zero the authentication tag as there is no encryption
        memset(OSHPACKET_HDR(slot)->tag, 0, sizeof(OSHPACKET_HDR(slot)->tag));

    } else {
        // The socket does not have a send cipher yet and it cannot be sent
        // unencrypted, we drop it
        // This should never happen, if it does there is a bug in the code
        logger(LOG_CRIT, "%s: Cannot queue unencrypted %s packet",
            node->addrw, oshpacket_type_name(hdr->type));
        netbuffer_cancel(node->io.sendq, packet_size);

        // GOODBYE packets should close the connection so if there's no data
        // queued after a failed GOODBYE we can remove the node
        if (hdr->type == GOODBYE) {
            if (netbuffer_data_size(node->io.sendq) == 0)
                aio_event_del(node->aio_event);
        }

        return false;
    }

    aio_enable_poll_events(node->aio_event, AIO_WRITE);
    return true;
}

// Queue a packet to the *node socket for *dest node
bool node_queue_packet(node_t *node, node_id_t *dest, oshpacket_type_t type,
    const void *payload, size_t payload_size)
{
    oshpacket_hdr_t hdr;

    hdr.type = type;
    hdr.flags.u = 0;
    memcpy(hdr.src_node, oshd.name, sizeof(hdr.src_node));
    if (dest) {
        memcpy(hdr.dest.unicast.dest_node, dest->name, NODE_NAME_SIZE);
    } else {
        memset(&hdr.dest.unicast, 0, sizeof(hdr.dest.unicast));
    }
    return node_queue_packet_internal(node, &hdr, payload, payload_size);
}

// Forward an existing packet to another socket
bool node_queue_packet_forward(node_t *node, const oshpacket_hdr_t *hdr,
    const void *payload, size_t payload_size)
{
    return node_queue_packet_internal(node, hdr, payload, payload_size);
}

// Broadcast a packet to all authenticated direct connections
// If exclude is not NULL the packet will not be queued for the excluded node
bool node_queue_packet_broadcast(node_t *exclude, oshpacket_type_t type,
    const void *payload, size_t payload_size)
{
    oshpacket_hdr_t hdr;

    hdr.type = type;
    hdr.flags.u = 0;
    hdr.flags.s.broadcast = 1;
    memcpy(hdr.src_node, oshd.name, sizeof(hdr.src_node));
    memset(&hdr.dest.broadcast, 0, sizeof(hdr.dest.broadcast));
    hdr.dest.broadcast.id = random_xoshiro256();

    logger_debug(DBG_SOCKETS,
        "Broadcasting %s packet of %zu bytes (id: %" PRI_BRD_ID ")",
        oshpacket_type_name(type), payload_size, hdr.dest.broadcast.id);

    for (size_t i = 0; i < oshd.nodes_count; ++i) {
        if (   !oshd.nodes[i]->authenticated
            ||  oshd.nodes[i] == exclude)
        {
            continue;
        }

        node_queue_packet_internal(oshd.nodes[i], &hdr, payload, payload_size);
    }

    return true;
}

// Forward an existing broadcast packet to all authenticated direct connections
// excluding the source socket
// exclude must not be NULL
bool node_queue_packet_broadcast_forward(node_t *exclude, const oshpacket_hdr_t *hdr,
    const void *payload, size_t payload_size)
{
    logger_debug(DBG_SOCKETS,
        "Broadcasting %s packet of %zu bytes (id: %" PRI_BRD_ID ", from %s)",
        oshpacket_type_name(hdr->type), payload_size, hdr->dest.broadcast.id,
        exclude->addrw);

    for (size_t i = 0; i < oshd.nodes_count; ++i) {
        if (   !oshd.nodes[i]->authenticated
            ||  oshd.nodes[i] == exclude)
        {
            continue;
        }

        node_queue_packet_internal(oshd.nodes[i], hdr, payload, payload_size);
    }

    return true;
}

// Queue packet with a fragmented payload
// If the payload size is bigger than OSHPACKET_PAYLOAD_MAXSIZE it will be
// fragmented and sent with multiple packets (as many as needed)
// This can only be used for repeating payloads, like edges and routes which
// are processed as a flat array
// If broadcast is true, *node is a node to exclude from the broadcast (can be
// NULL)
// Otherwise the fragmented packet will be sent to *node (it is expected to be
// authenticated)
static bool node_queue_packet_fragmented(
    node_t *node,
    oshpacket_type_t type,
    const void *payload,
    const size_t payload_size,
    const size_t entry_size,
    bool broadcast)
{
    const size_t max_entries = OSHPACKET_PAYLOAD_MAXSIZE / entry_size;
    size_t remaining_entries = payload_size / entry_size;
    const void *curr_buf = payload;

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
            if (!node_queue_packet(node, node->id, type, curr_buf, size))
                return false;
        }

        // Iterate to the next entries
        remaining_entries -= entries;
        curr_buf += size;
    }

    return true;
}

// Queue HANDSHAKE request
bool node_queue_handshake(node_t *node)
{
    oshpacket_handshake_t packet;

    logger_debug(DBG_HANDSHAKE, "Creating HANDSHAKE packet for %s", node->addrw);
    if (node->handshake_in_progress) {
        logger(LOG_ERR,
            "%s: Failed to create HANDSHAKE: Another one is in progress",
            node->addrw);
        return false;
    }

    // We are now currently shaking hands
    // After completion node->send_key/recv_key will be freed and NULLed
    node->handshake_in_progress = true;

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
    if (!pkey_save_pubkey(node->send_key, &pubkey, &pubkey_size))
        return false;
    if (pubkey_size != sizeof(packet.keys.k.send)) {
        free(pubkey);
        logger(LOG_ERR, "%s: send_key size is invalid (%zu, but expected %zu)",
            node->addrw, pubkey_size, sizeof(packet.keys.k.send));
        return false;
    }
    memcpy(packet.keys.k.send, pubkey, pubkey_size);
    free(pubkey);

    logger_debug(DBG_HANDSHAKE, "%s: Exporting recv_key", node->addrw);
    if (!pkey_save_pubkey(node->recv_key, &pubkey, &pubkey_size))
        return false;
    if (pubkey_size != sizeof(packet.keys.k.recv)) {
        free(pubkey);
        logger(LOG_ERR, "%s: recv_key size is invalid (%zu, but expected %zu)",
            node->addrw, pubkey_size, sizeof(packet.keys.k.recv));
        return false;
    }
    memcpy(packet.keys.k.recv, pubkey, pubkey_size);
    free(pubkey);

    // Sign the keys
    uint8_t *sig;
    size_t sig_size;

    if (!pkey_sign(oshd.privkey,
            packet.keys.both, sizeof(packet.keys.both),
            &sig, &sig_size))
    {
        logger(LOG_ERR, "%s: Failed to sign handshake keys", node->addrw);
        return false;
    }

    if (sig_size != sizeof(packet.sig)) {
        free(sig);
        logger(LOG_ERR, "%s: Invalid handshake signature size (%zu bytes)",
            node->addrw, sig_size);
        return false;
    }

    memcpy(packet.sig, sig, sizeof(packet.sig));
    free(sig);

    // If we are authenticateed we need to handle handshake timeouts
    // When unauthenticated the authentication timeout event takes care of this
    if (node->authenticated)
        event_queue_handshake_timeout(node, HANDSHAKE_TIMEOUT);

    return node_queue_packet(node, node->id, HANDSHAKE, &packet, sizeof(packet));
}

// Queue HANDSHAKE_END packet
bool node_queue_handshake_end(node_t *node)
{
    return node_queue_packet_empty(node, node->id, HANDSHAKE_END);
}

// Queue a HANDSHAKE packet to renew the encryption keys
// If a handshake is already in progress, nothing is done
// If packet cannot be queued the connection is terminated
void node_renew_handshake(node_t *node)
{
    if (!node->handshake_in_progress) {
        if (!node_queue_handshake(node))
            aio_event_del(node->aio_event);
    }
}

// Queue HELLO_CHALLENGE request
bool node_queue_hello_challenge(node_t *node)
{
    free(node->hello_chall);
    node->hello_chall = xalloc(sizeof(oshpacket_hello_challenge_t));

    if (!random_bytes(node->hello_chall->challenge, sizeof(node->hello_chall->challenge)))
        return false;

    return node_queue_packet(node, NULL, HELLO_CHALLENGE, node->hello_chall,
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
    return node_queue_packet(node, NULL, HELLO_END, &packet, sizeof(packet));
}

// Queue DEVMODE packet
bool node_queue_devmode(node_t *node)
{
    if (oshd.device_mode == MODE_DYNAMIC) {
        oshpacket_devmode_dynamic_t packet;

        packet.devmode_pkt.devmode = oshd.device_mode;
        memcpy(packet.network_name, oshd.network_name, NODE_NAME_SIZE);
        netaddr_cpy_data(&packet.prefix6, &oshd.dynamic_prefix6);
        packet.prefixlen6 = oshd.dynamic_prefixlen6;
        netaddr_cpy_data(&packet.prefix4, &oshd.dynamic_prefix4);
        packet.prefixlen4 = oshd.dynamic_prefixlen4;

        return node_queue_packet(node, node->id, DEVMODE, &packet, sizeof(packet));
    } else {
        oshpacket_devmode_t packet;

        packet.devmode = oshd.device_mode;
        return node_queue_packet(node, node->id, DEVMODE, &packet, sizeof(packet));
    }
}

// Queue STATEEXG_END packet
bool node_queue_stateexg_end(node_t *node)
{
    return node_queue_packet_empty(node, node->id, STATEEXG_END);
}

// Queue GOODBYE request
bool node_queue_goodbye(node_t *node)
{
    node_graceful_disconnect(node);
    return node_queue_packet_empty(node, node->id, GOODBYE);
}

// Queue PING request
bool node_queue_ping(node_t *node)
{
    if (node->rtt_await) {
        logger_debug(DBG_SOCKETS, "%s: %s: Dropping PING request, another was not answered yet",
            node->addrw, node->id->name);
        return true;
    }

    oshd_gettime(&node->rtt_ping);
    node->rtt_await = true;
    return node_queue_packet_empty(node, node->id, PING);
}

// Queue PONG request
bool node_queue_pong(node_t *node)
{
    return node_queue_packet_empty(node, node->id, PONG);
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

    return node_queue_packet_broadcast(exclude, PUBKEY, &packet, sizeof(packet));
}

// Queue PUBKEY exchange packet
bool node_queue_pubkey_exg(node_t *node)
{
    oshpacket_pubkey_t *pubkeys = NULL;
    size_t count = 0;
    bool success;

    for (size_t i = 0; i < oshd.node_tree_count; ++i) {
        // Only exchange public keys from online nodes
        if (    oshd.node_tree[i]->online
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

// Broadcast an endpoint owned by group->owner_name
bool node_queue_endpoint_broadcast(node_t *exclude, const endpoint_t *endpoint,
    const endpoint_group_t *group)
{
    oshpacket_endpoint_t pkt;
    netaddr_t addr;

    if (!group->has_owner) {
        logger(LOG_ERR, "Failed to broadcast endpoint %s:%u: No owner (%s)",
            endpoint->hostname, endpoint->port, group->owner_name);
        return false;
    }
    if (!netaddr_lookup(&addr, endpoint->hostname)) {
        logger(LOG_WARN,
            "Failed to broadcast endpoint %s:%u owned by %s (lookup failed)",
            endpoint->hostname, endpoint->port, group->owner_name);
        return false;
    }

    memset(&pkt, 0, sizeof(pkt));
    for (size_t i = 0; (group->owner_name[i] != 0) && (i < NODE_NAME_SIZE); ++i)
        pkt.node_name[i] = group->owner_name[i];
    pkt.addr_type = addr.type;
    netaddr_cpy_data(&pkt.addr_data, &addr);
    pkt.port = htons(endpoint->port);

    logger_debug(DBG_ENDPOINTS, "Broadcasting endpoint %s:%u owned by %s",
        endpoint->hostname, endpoint->port, group->owner_name);
    return node_queue_packet_broadcast(exclude, ENDPOINT, &pkt, sizeof(pkt));
}

// Send an endpoint owned by group->owner_name to node
static bool node_queue_endpoint(node_t *node, const endpoint_t *endpoint,
    const endpoint_group_t *group)
{
    oshpacket_endpoint_t pkt;
    netaddr_t addr;

    if (!group->has_owner) {
        logger(LOG_ERR, "%s: Failed to queue endpoint %s:%u: No owner (%s)",
            node->addrw, endpoint->hostname, endpoint->port, group->owner_name);
        return false;
    }
    if (!netaddr_lookup(&addr, endpoint->hostname)) {
        logger(LOG_WARN,
            "%s: Failed to queue endpoint %s:%u owned by %s (lookup failed)",
            node->addrw, endpoint->hostname, endpoint->port, group->owner_name);
        return false;
    }

    memset(&pkt, 0, sizeof(pkt));
    for (size_t i = 0; (group->owner_name[i] != 0) && (i < NODE_NAME_SIZE); ++i)
        pkt.node_name[i] = group->owner_name[i];
    pkt.addr_type = addr.type;
    netaddr_cpy_data(&pkt.addr_data, &addr);
    pkt.port = htons(endpoint->port);

    logger_debug(DBG_ENDPOINTS, "%s: Queuing endpoint %s:%u owned by %s",
        node->addrw, endpoint->hostname, endpoint->port, group->owner_name);
    return node_queue_packet(node, node->id, ENDPOINT, &pkt, sizeof(pkt));
}

// Queue ENDPOINT exchange packets
// Exchanges all endpoints with another node
// Endpoints from the configuration file will be skipped if ShareRemotes is
// not enabled
bool node_queue_endpoint_exg(node_t *node)
{
    for (size_t i = 0; i < oshd.node_tree_count; ++i) {
        endpoint_group_t *group = oshd.node_tree[i]->endpoints;

        foreach_endpoint(endpoint, group) {
            // If ShareRemotes was not set in the configuration file,
            // endpoints that don't expire will not be shared
            if (!endpoint->can_expire && !oshd.shareremotes)
                continue;

            if (!node_queue_endpoint(node, endpoint, group))
                return false;
        }
    }
    return true;
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
            return node_queue_packet(node, node->id, type,
                &buf, sizeof(oshpacket_edge_t));

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
                    &buf, sizeof(oshpacket_edge_t));

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
    size_t count, bool can_expire)
{
    if (count == 0)
        return true;

    size_t buf_size = sizeof(oshpacket_route_t) * count;
    oshpacket_route_t *buf = xalloc(buf_size);

    // Format the addresses's type and data into buf
    for (size_t i = 0; i < count; ++i) {
        memcpy(buf[i].owner_name, oshd.name, NODE_NAME_SIZE);
        buf[i].type = addrs[i].type;
        buf[i].prefixlen = netaddr_max_prefixlen(addrs[i].type);
        netaddr_cpy_data(&buf[i].addr, &addrs[i]);
        buf[i].can_expire = can_expire;
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
    const size_t total_count = oshd.route_table->total_owned_routes;

    if (total_count == 0)
        return true;

    size_t buf_size = sizeof(oshpacket_route_t) * total_count;
    oshpacket_route_t *buf = xalloc(buf_size);

    // Format all routes' addresses into buf
    size_t i = 0;

    foreach_netroute_const(route, oshd.route_table, route_iter) {
        if (route->owner) {
            memcpy(buf[i].owner_name, route->owner->name, NODE_NAME_SIZE);
            buf[i].type = route->addr.type;
            buf[i].prefixlen = route->prefixlen;
            netaddr_cpy_data(&buf[i].addr, &route->addr);
            buf[i].can_expire = route->can_expire;
            ++i;
        }
    }

    bool success = false;

    if (i == total_count) {
        success = node_queue_packet_fragmented(node, ROUTE_ADD, buf, buf_size,
            sizeof(oshpacket_route_t), false);
    } else {
        logger(LOG_CRIT, "%s: %s: Route exchange copied %zu routes but expected %zu (this should never happen)",
            node->addrw, node->id->name, i, total_count);
    }

    // We need to free the memory before returning
    free(buf);
    return success;
}
