#include "node.h"
#include "oshd.h"
#include "events.h"
#include "logger.h"
#include "xalloc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Find node_id_t with *name in the node tree
node_id_t *node_id_find(const char *name)
{
    for (size_t i = 0; i < oshd.node_tree_count; ++i) {
        if (!strcmp(name, oshd.node_tree[i]->name))
            return oshd.node_tree[i];
    }
    return NULL;
}

// Add node_id_t with *name to the node tree (doesn't do anything if it already
// exists)
node_id_t *node_id_add(const char *name)
{
    node_id_t *id;

    if (!(id = node_id_find(name))) {
        id = xzalloc(sizeof(node_id_t));
        oshd.node_tree = xrealloc(oshd.node_tree,
            sizeof(node_id_t *) * (oshd.node_tree_count + 1));

        oshd.node_tree[oshd.node_tree_count] = id;
        oshd.node_tree_count += 1;

        strncpy(id->name, name, NODE_NAME_SIZE);
        id->local_node = !strcmp(id->name, oshd.name);
    }
    return id;
}

// Free resources allocated to *nid and the structure
void node_id_free(node_id_t *nid)
{
    free(nid->edges);
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
        nid->edges = xrealloc(nid->edges,
            sizeof(node_id_t *) * (nid->edges_count + 1));
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
        nid->edges = xrealloc(nid->edges, sizeof(node_id_t *) * nid->edges_count);
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

// Dynamically resize array and add *n to the end, then increment the count
// TODO: Optimize this, allocating memory for each item is very slow
static void node_id_array_append(node_id_t ***arr, size_t *count, node_id_t *n)
{
    *arr = xrealloc(*arr, sizeof(node_id_t *) * ((*count) + 1));
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
    queue = xalloc(sizeof(node_id_t *) * queue_count);
    memcpy(queue, dest_node->edges, sizeof(node_id_t *) * queue_count);

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

// Digraph dump
void node_tree_dump_digraph(void)
{
    char addr[INET6_ADDRSTRLEN];

    printf("digraph %s_network_map {\n", oshd.name);

    // We start by defining and labeling every node on the network
    for (size_t i = 0; i < oshd.node_tree_count; ++i) {
        char *color;
        char *style;
        char route[40];

        if (oshd.node_tree[i]->local_node) {
            // The local node is fully green
            color = "green";
            style = "filled";
            snprintf(route, sizeof(route), "(local)");
        } else if (oshd.node_tree[i]->next_hop) {
            // Direct and indirect nodes are outlined in green
            color = "green";
            style = "solid";
            if (oshd.node_tree[i]->node_socket) {
                snprintf(route, sizeof(route), "(direct, %ims)",
                    oshd.node_tree[i]->node_socket->rtt);
            } else {
                snprintf(route, sizeof(route), "(indirect through %s)",
                    oshd.node_tree[i]->next_hop->id->name);
            }
        } else {
            // Orphan nodes are outlined in red
            color = "red";
            style = "solid";
            snprintf(route, sizeof(route), "(no route)");
        }

        printf("    %s [label=\"%s\\n%s\", color=%s, style=%s];\n", oshd.node_tree[i]->name,
            oshd.node_tree[i]->name, route, color, style);
    }

    // We define and label our local routes
    for (size_t i = 0; i < oshd.local_routes_count; ++i) {
        netaddr_ntop(addr, sizeof(addr), &oshd.local_routes[i]);
        printf("    \"%s\" [label=\"%s\", color=blue, style=solid];\n",
            addr, addr);
    }

    // We define and label the remote routes
    for (size_t i = 0; i < oshd.routes_count; ++i) {
        netaddr_ntop(addr, sizeof(addr), &oshd.routes[i]->addr);
        printf("    \"%s\" [label=\"%s\", color=purple, style=solid];\n",
            addr, addr);
    }

    // We defined all nodes on the graph, now we just need to connect them all
    // to the right ends

    // We then iterate over all the edges of every node (including us) and
    // make the bi-directionnal connections
    for (size_t i = 0; i < oshd.node_tree_count; ++i) {
        for (ssize_t j = 0; j < oshd.node_tree[i]->edges_count; ++j) {
            printf("    %s -> %s;\n", oshd.node_tree[i]->name,
                oshd.node_tree[i]->edges[j]->name);
        }
    }

    // We connect our local node to its routes
    for (size_t i = 0; i < oshd.local_routes_count; ++i) {
        netaddr_ntop(addr, sizeof(addr), &oshd.local_routes[i]);
        printf("    %s -> \"%s\";\n", oshd.name, addr);
    }

    // We connect the remote routes to their destination nodes
    for (size_t i = 0; i < oshd.routes_count; ++i) {
        netaddr_ntop(addr, sizeof(addr), &oshd.routes[i]->addr);
        printf("    %s -> \"%s\";\n", oshd.routes[i]->dest_node->name, addr);
    }

    printf("}\n");
}

// Dump the node tree
void node_tree_dump(void)
{
    printf("Node tree (%s):\n", oshd.name);
    for (size_t i = 0; i < oshd.node_tree_count; ++i) {
        // Skip our local node, our edges are the direct connections
        if (oshd.node_tree[i]->local_node)
            continue;

        printf("    %s (%s, next hop: %s): %zi edges: ",
            oshd.node_tree[i]->name,
            oshd.node_tree[i]->node_socket ? "direct" : "indirect",
            oshd.node_tree[i]->next_hop ? oshd.node_tree[i]->next_hop->id->name : "(no route)",
            oshd.node_tree[i]->edges_count);

        for (ssize_t j = 0; j < oshd.node_tree[i]->edges_count; ++j) {
            printf("%s%c", oshd.node_tree[i]->edges[j]->name,
                ((j + 1) < oshd.node_tree[i]->edges_count) ? ',' : '\n');
        }
    }
    printf("%zu nodes in the tree\n", oshd.node_tree_count);
}

static void node_tree_update_next_hops(void)
{
    logger_debug(DBG_NODETREE, "Updating next hops");
    for (size_t i = 0; i < oshd.node_tree_count; ++i) {
        oshd.node_tree[i]->next_hop = node_id_find_next_hop(oshd.node_tree[i]);

        /*
           If we have no route for this destination then we clear its edges
           If we don't we go out of sync

           The local node will never have a route because it's local, so we
           never need to clear its edges
        */
        if (   !oshd.node_tree[i]->next_hop
            && !oshd.node_tree[i]->local_node)
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

    // After the node tree gets updated we need to re-calculate the next hops
    // of all nodes
    node_tree_update_next_hops();

    // We also need to delete all routes to orphan nodes
    netroute_del_orphan_routes();

    if (logger_is_debugged(DBG_NODETREE))
        node_tree_dump();
}

// Disconnect node
void node_disconnect(node_t *node)
{
    if (node->authenticated) {
        // Find our two nodes
        node_id_t *src = node_id_find(oshd.name);
        node_id_t *dest = node_id_find(node->id->name);

        // Make sure that we don't have a direct connection to this node
        node->id->node_socket = NULL;

        // We delete the edges between the local and the remote node
        node_id_del_edge(src, dest);

        // We broadcast this change to the rest of the network
        node_queue_edge_broadcast(node, DEL_EDGE, oshd.name, node->id->name);
        node_tree_update();
    }

    if (node->fd > 0) {
        logger(LOG_INFO, "Disconnecting %s", node->addrw);
        close(node->fd);
        node->fd = -1;
    } else {
        logger(LOG_WARN, "%s: Already disconnected", node->addrw);
    }

    if (node->reconnect_addr) {
        logger(LOG_INFO, "Retrying to connect to %s:%u in %li seconds",
            node->reconnect_addr, node->reconnect_port,
            node->reconnect_delay);
        event_queue_connect(node->reconnect_addr, node->reconnect_port,
            node->reconnect_delay * 2, node->reconnect_delay);
    }
}

// Free a node and all its resources
void node_destroy(node_t *node)
{
    node_disconnect(node);
    free(node->io.recvbuf);
    netbuffer_free(node->io.sendq);
    free(node->reconnect_addr);
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
    snprintf(node->addrw, sizeof(node->addrw), "%s:%u", addrp, port);

    // Initialize network buffers
    node->io.recvbuf = xalloc(OSHPACKET_MAXSIZE);
    node->io.recvd_hdr = false;
    node->io.recv_bytes = 0;
    node->io.recv_packet_size = OSHPACKET_HDR_SIZE;
    node->io.sendq = netbuffer_alloc(NODE_SENDQ_SLOTS, OSHPACKET_MAXSIZE);
    node->io.sendq_ptr = NULL;
    node->io.sendq_packet_size = 0;

    return node;
}

// Set the node socket's reconnection delay
void node_reconnect_delay(node_t *node, time_t delay)
{
    if (delay < oshd.reconnect_delay_min) {
        node->reconnect_delay = oshd.reconnect_delay_min;
    } else if (delay > oshd.reconnect_delay_max) {
        node->reconnect_delay = oshd.reconnect_delay_max;
    } else {
        node->reconnect_delay = delay;
    }
}

// Set the node's socket reconnection information
void node_reconnect_to(node_t *node, const char *addr, uint16_t port,
    time_t delay)
{
    free(node->reconnect_addr);
    node->reconnect_addr = addr ? xstrdup(addr) : NULL;
    node->reconnect_port = port;
    node_reconnect_delay(node, delay);
}

// Returns true if the node name is valid
bool node_valid_name(const char *name)
{
    const char valid_charset[] = \
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-";

    return strspn(name, valid_charset) == strlen(name);
}

// Queue a packet to the *node socket for *dest node
bool node_queue_packet(node_t *node, const char *dest, oshpacket_type_t type,
    uint8_t *payload, uint16_t payload_size)
{
    uint8_t *slot;

    if ((slot = netbuffer_reserve(node->io.sendq))) {
        ((oshpacket_hdr_t *) slot)->magic = OSHPACKET_MAGIC;
        ((oshpacket_hdr_t *) slot)->type = type;
        ((oshpacket_hdr_t *) slot)->payload_size = htons(payload_size);
        memcpy(((oshpacket_hdr_t *) slot)->src_node, oshd.name, NODE_NAME_SIZE);
        if (dest)
            memcpy(((oshpacket_hdr_t *) slot)->dest_node, dest, NODE_NAME_SIZE);
        else
            memset(((oshpacket_hdr_t *) slot)->dest_node, 0, NODE_NAME_SIZE);
        memcpy(slot + OSHPACKET_HDR_SIZE, payload, payload_size);

        // If there is no packet in the queue, put this one
        // Otherwise let the queue handle it
        if (!node->io.sendq_ptr) {
            node->io.sendq_ptr = slot;
            node->io.sendq_packet_size = OSHPACKET_HDR_SIZE + payload_size;
        }

        return true;
    } else {
        logger(LOG_WARN, "%s: Dropping %s packet of %u bytes: send queue is full",
            oshpacket_type_name(type), node->addrw, payload_size);
        return false;
    }
}

// Queue a forwarded packet without altering the source and destination nodes
bool node_queue_packet_forward(node_t *node, oshpacket_hdr_t *pkt)
{
    const uint16_t pkt_size = OSHPACKET_HDR_SIZE + pkt->payload_size;
    uint8_t *slot;

    if ((slot = netbuffer_reserve(node->io.sendq))) {
        // If there is no packet in the queue, put this one
        // Otherwise let the queue handle it
        memcpy(slot, pkt, pkt_size);
        ((oshpacket_hdr_t *) slot)->payload_size = htons(pkt->payload_size);

        if (!node->io.sendq_ptr) {
            node->io.sendq_ptr = slot;
            node->io.sendq_packet_size = pkt_size;
        }
        return true;
    } else {
        logger(LOG_WARN, "%s: Dropping forwarded %s packet of %u bytes: send queue is full",
            oshpacket_type_name(pkt->type), node->addrw, pkt->payload_size);
        return false;
    }
}

// Broadcast a packet to all nodes
// If exclude is not NULL the packet will not be queued for the excluded node
bool node_queue_packet_broadcast(node_t *exclude, oshpacket_type_t type,
    uint8_t *payload, uint16_t payload_size)
{
    for (size_t i = 0; i < oshd.node_tree_count; ++i) {
        if (   !oshd.node_tree[i]->local_node
            &&  oshd.node_tree[i]->next_hop
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

// Queue HELLO request
bool node_queue_hello(node_t *node)
{
    return node_queue_packet(node, node->id->name, HELLO,
        (uint8_t *) oshd.name, strlen(oshd.name));
}

// Queue GOODBYE request
bool node_queue_goodbye(node_t *node)
{
    uint8_t buf = 0;

    node->finish_and_disconnect = true;
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

// Queue ADD_EDGE or DEL_EDGE request
bool node_queue_edge(node_t *node, oshpacket_type_t type,
    const char *src, const char *dest)
{
    char buf[(NODE_NAME_SIZE * 2)];

    switch (type) {
        case ADD_EDGE:
        case DEL_EDGE:
            memcpy(buf,                  src,  NODE_NAME_SIZE);
            memcpy(buf + NODE_NAME_SIZE, dest, NODE_NAME_SIZE);
            return node_queue_packet(node, node->id->name, type,
                        (uint8_t *) buf, sizeof(buf));

        default:
            logger(LOG_ERR, "node_queue_edge: Invalid type %s",
                oshpacket_type_name(type));
            return false;
    }
}

// Broadcast ADD_EDGE or DEL_EDGE request
bool node_queue_edge_broadcast(node_t *exclude, oshpacket_type_t type,
    const char *src, const char *dest)
{
    char buf[(NODE_NAME_SIZE * 2)];

    switch (type) {
        case ADD_EDGE:
        case DEL_EDGE:
            memcpy(buf,                  src,  NODE_NAME_SIZE);
            memcpy(buf + NODE_NAME_SIZE, dest, NODE_NAME_SIZE);
            return node_queue_packet_broadcast(exclude, type,
                    (uint8_t *) buf, sizeof(buf));

        default:
            logger(LOG_ERR, "node_queue_edge: Invalid type %s",
                oshpacket_type_name(type));
            return false;
    }
}

// Queue EDGE_EXG packets for *node with the whole network map
bool node_queue_edge_exg(node_t *node)
{
    const size_t entry_size = NODE_NAME_SIZE * 2;
    size_t buf_count = 0;
    char *buf = NULL;

    /*
       TODO: We can also optimize this more by creating/updating this buffer
             on after a node_tree_update() instead of doing it here
       TODO: We can optimize A LOT by allocating more entries at a time
             to minimize memory reallocation latency
       TODO: We can also trim repeating edges
    */
    logger_debug(DBG_NODETREE, "node_queue_edge_exg: Creating the edge map");
    for (size_t i = 0; i < oshd.node_tree_count; ++i) {
        // Skip the local node because it is useless
        if (oshd.node_tree[i]->local_node)
            continue;

        // Direct edge
        if (oshd.node_tree[i]->node_socket) {
            logger_debug(DBG_NODETREE, "    Direct  : %s <=> %s",
                oshd.name, oshd.node_tree[i]->name);

            // Allocate memory to store the new edge and copy the edge names
            buf = xrealloc(buf, entry_size * (buf_count + 1));
            memcpy(buf + (buf_count * entry_size), oshd.name, NODE_NAME_SIZE);
            memcpy(buf + (buf_count * entry_size) + NODE_NAME_SIZE,
                oshd.node_tree[i]->name, NODE_NAME_SIZE);
            ++buf_count;
        }

        // Indirect edges
        for (ssize_t j = 0; j < oshd.node_tree[i]->edges_count; ++j) {
            logger_debug(DBG_NODETREE, "    Indirect: %s <=> %s",
                oshd.node_tree[i]->name, oshd.node_tree[i]->edges[j]->name);

            // Allocate memory to store the new edge and copy the edge names
            buf = xrealloc(buf, entry_size * (buf_count + 1));
            memcpy(buf + (buf_count * entry_size),
                oshd.node_tree[i]->name, NODE_NAME_SIZE);
            memcpy(buf + (buf_count * entry_size) + NODE_NAME_SIZE,
                oshd.node_tree[i]->edges[j]->name, NODE_NAME_SIZE);
            ++buf_count;
        }
    }

    // Calculate the maximum number of edges we can send in one packet
    size_t max_entries = OSHPACKET_PAYLOAD_MAXSIZE / entry_size;
    size_t remaining_entries = buf_count;
    char *curr_buf = buf;
    bool success = true;

    logger_debug(DBG_NODETREE,
        "    Queuing EDGE_EXG packets for %zu edges (%zu bytes)",
        buf_count, entry_size * buf_count);

    // Queue all edges in the buffer
    while (remaining_entries > 0) {
        size_t entries;
        size_t size;

        // Calculate how many entries to send on the packet
        if (remaining_entries > max_entries)
            entries = max_entries;
        else
            entries = remaining_entries;

        // Calculate the payload size
        size = entries * entry_size;

        // Queue the packet
        if (node_queue_packet(node, node->id->name, EDGE_EXG, (uint8_t *) curr_buf, size)) {
            logger_debug(DBG_NODETREE,
                "    Queued EDGE_EXG with %zu edges (%zu bytes)", entries, size);
        } else {
            success = false;
        }

        // Iterate to the next entries
        remaining_entries -= entries;
        curr_buf += size;
    }

    // We need to free the memory before returning
    free(buf);
    return success;
}

// Broadcast ADD_ROUTE request
bool node_queue_add_route_broadcast(node_t *exclude, const netaddr_t *addrs,
    size_t count)
{
    if (count == 0)
        return true;

    const size_t entry_size = 17;
    size_t buf_size = entry_size * count;
    uint8_t *buf = xalloc(buf_size);

    // Format the addresses's type and data into buf
    for (size_t i = 0; i < count; ++i) {
        buf[(i * entry_size)] = addrs[i].type;
        memcpy(&buf[(i * entry_size) + 1], addrs[i].data, 16);
    }

    size_t max_entries = OSHPACKET_PAYLOAD_MAXSIZE / entry_size;
    size_t remaining_entries = count;
    uint8_t *curr_buf = buf;
    bool success = true;

    // Queue all edges in the buffer
    while (remaining_entries > 0) {
        size_t entries;
        size_t size;

        // Calculate how many entries to send on the packet
        if (remaining_entries > max_entries)
            entries = max_entries;
        else
            entries = remaining_entries;

        // Calculate the payload size
        size = entries * entry_size;

        // Broadcast the packet
        if (node_queue_packet_broadcast(exclude, ADD_ROUTE, curr_buf, size)) {
            logger_debug(DBG_ROUTING, "Broadcast ADD_ROUTE with %zu routes (%zu bytes)",
                entries, size);
        } else {
            success = false;
        }

        // Iterate to the next entries
        remaining_entries -= entries;
        curr_buf += size;
    }

    // We need to free the memory before returning
    free(buf);
    return success;
}