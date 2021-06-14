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
    }
    return id;
}

// Free resources allocated to *nid and the structure
void node_id_free(node_id_t *nid)
{
    pkey_free(nid->pubkey);
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

// Load a remote public key for *nid
// If a public key was already loaded it will not be loaded
bool node_id_set_pubkey(node_id_t *nid, const uint8_t *pubkey,
    size_t pubkey_size)
{
    if (nid->pubkey)
        return true;
    nid->pubkey = pkey_load_ed25519_pubkey(pubkey, pubkey_size);
    nid->pubkey_local = false;
    return nid->pubkey != NULL;
}

// Dynamically resize array and add *n to the end, then increment the count
static void node_id_array_append(node_id_t ***arr, size_t *count, node_id_t *n)
{
    const size_t alloc_count = 16;

    if ((*count) % alloc_count == 0)
        *arr = xrealloc(*arr, sizeof(node_id_t *) * ((*count) + alloc_count));
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

// Digraph dump to *out
static void node_tree_dump_digraph_to(FILE *out)
{
    char addr[INET6_ADDRSTRLEN];

    fprintf(out, "digraph osh_node_tree {\n");

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
            // Direct and indirect nodes are outlined in either green or turquoise
            style = "solid";
            if (oshd.node_tree[i]->node_socket) {
                color = "green";
                snprintf(route, sizeof(route), "(direct, %ims)",
                    oshd.node_tree[i]->node_socket->rtt);
            } else {
                color = "turquoise";
                snprintf(route, sizeof(route), "(indirect through %s)",
                    oshd.node_tree[i]->next_hop->id->name);
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
        printf("    %s (%s, next hop: %s): %zi edges: ",
            oshd.node_tree[i]->name,
            oshd.node_tree[i]->node_socket ? "direct" : "indirect",
            oshd.node_tree[i]->next_hop ? oshd.node_tree[i]->next_hop->id->name : "(no route)",
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

    // After the node tree gets updated we need to re-calculate the next hops
    // of all nodes
    node_tree_update_next_hops();

    // We also need to delete all routes to orphan nodes
    oshd_route_del_orphan_routes();

    if (logger_is_debugged(DBG_NODETREE))
        node_tree_dump();
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
            logger(LOG_ERR, "%s: shutdown(%i): %s", node->addrw, node->fd,
                strerror(errno));
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

    if (node->reconnect_addr) {
        logger(LOG_INFO, "Retrying to connect to %s:%u in %li seconds",
            node->reconnect_addr, node->reconnect_port,
            node->reconnect_delay);
        event_queue_connect(node->reconnect_addr, node->reconnect_port,
            node->reconnect_delay * 2, node->reconnect_delay);
    }
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
    node_disconnect(node);
    free(node->hello_chall);
    free(node->io.recvbuf);
    netbuffer_free(node->io.sendq);
    node_reset_ciphers(node);
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
    snprintf(node->addrw, sizeof(node->addrw),
        (addr->type == IP6) ? "[%s]:%u" : "%s:%u", addrp, port);

    // Initialize network buffers
    node->io.recvbuf = xalloc(NODE_RECVBUF_SIZE);
    node->io.sendq = netbuffer_create(NODE_SENDQ_MIN_SIZE, NODE_SENDQ_ALIGNMENT);

    // Queue the authentication timeout event for the node
    // When it triggers if the socket is not authenticated it will be
    // disconnected
    event_queue_node_auth_timeout(node, 30);

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

// Queue HANDSHAKE request
bool node_queue_handshake(node_t *node, bool initiator)
{
    oshpacket_handshake_t packet;

    node->handshake_initiator = initiator;
    logger_debug(DBG_HANDSHAKE, "Creating HANDSHAKE packet for %s", node->addrw);

    // Make sure that there are no memory leaks
    node_reset_ciphers(node);

    // Generate random keys
    logger_debug(DBG_HANDSHAKE, "%s: Handshake: Generating send_key", node->addrw);
    if (!(node->send_key = pkey_generate_x25519()))
        return false;
    logger_debug(DBG_HANDSHAKE, "%s: Handshake: Generating recv_key", node->addrw);
    if (!(node->recv_key = pkey_generate_x25519()))
        return false;

    uint8_t *pubkey;
    size_t pubkey_size;

    // Export the keys to the packet
    logger_debug(DBG_HANDSHAKE, "%s: Handshake: Exporting send_key", node->addrw);
    if (!pkey_save_x25519_pubkey(node->send_key, &pubkey, &pubkey_size))
        return false;
    if (pubkey_size != sizeof(packet.send_pubkey)) {
        free(pubkey);
        logger(LOG_ERR, "%s: send_key size is invalid (%zu, but expected %u)",
            pubkey_size, sizeof(packet.send_pubkey));
        return false;
    }
    memcpy(packet.send_pubkey, pubkey, pubkey_size);
    free(pubkey);

    logger_debug(DBG_HANDSHAKE, "%s: Handshake: Exporting recv_key", node->addrw);
    if (!pkey_save_x25519_pubkey(node->recv_key, &pubkey, &pubkey_size))
        return false;
    if (pubkey_size != sizeof(packet.recv_pubkey)) {
        free(pubkey);
        logger(LOG_ERR, "%s: recv_key size is invalid (%zu, but expected %u)",
            pubkey_size, sizeof(packet.recv_pubkey));
        return false;
    }
    memcpy(packet.recv_pubkey, pubkey, pubkey_size);
    free(pubkey);

    return node_queue_packet(node, NULL, HANDSHAKE, (uint8_t *) &packet, sizeof(packet));
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
    const char *src_node, const char *dest_node, const char *edge_type)
{
    const size_t alloc_count = 16;

    // Trim repeating edges
    // Including src -> dest and dest -> src
    // The source and destination edges will be linked bidirectionally so we can
    // send one direction only
    for (size_t i = 0; i < (*buf_count); ++i) {
        if (   !strcmp((*buf)[i].src_node, dest_node)
            && !strcmp((*buf)[i].dest_node, src_node))
        {
            // This edge is already in the list in the other direction
            logger_debug(DBG_NODETREE, "    %s: %s <=> %s (skipped, repeating)",
                edge_type, src_node, dest_node);
            return;
        }
    }

    // Add this edge to the buffer
    logger_debug(DBG_NODETREE, "    %s: %s <=> %s", edge_type, src_node, dest_node);

    // Reallocate more alloc_count items in the buffer when we need more memory
    if ((*buf_count) % alloc_count == 0)
        *buf = xrealloc(*buf, sizeof(oshpacket_edge_t) * ((*buf_count) + alloc_count));

    memcpy((*buf)[(*buf_count)].src_node, src_node, NODE_NAME_SIZE);
    memcpy((*buf)[(*buf_count)].dest_node, dest_node, NODE_NAME_SIZE);
    *buf_count += 1;
}

// Queue EDGE_EXG packets for *node with the whole network map
bool node_queue_edge_exg(node_t *node)
{
    size_t buf_count = 0;
    oshpacket_edge_t *buf = NULL;

    /*
       TODO: We can also optimize this more by creating/updating this buffer
             on after a node_tree_update() instead of doing it here
    */

    logger_debug(DBG_NODETREE, "node_queue_edge_exg: Creating the edge map");

    // We skip the local node because it is useless, by starting with the
    // second element, because the first one will always be our local node
    for (size_t i = 1; i < oshd.node_tree_count; ++i) {
        // Direct edge
        if (oshd.node_tree[i]->node_socket)
            edge_exg_append(&buf, &buf_count, oshd.name, oshd.node_tree[i]->name, "Direct");

        // Indirect edges
        for (ssize_t j = 0; j < oshd.node_tree[i]->edges_count; ++j) {
            edge_exg_append(&buf, &buf_count, oshd.node_tree[i]->name,
                oshd.node_tree[i]->edges[j]->name, "Indirect");
        }
    }

    // Calculate the maximum number of edges we can send in one packet
    size_t max_entries = OSHPACKET_PAYLOAD_MAXSIZE / sizeof(oshpacket_edge_t);
    size_t remaining_entries = buf_count;
    uint8_t *curr_buf = (uint8_t *) buf;
    bool success = true;

    logger_debug(DBG_NODETREE,
        "    Queuing EDGE_EXG packets for %zu edges (%zu bytes)",
        buf_count, sizeof(oshpacket_edge_t) * buf_count);

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
        size = entries * sizeof(oshpacket_edge_t);

        // Queue the packet
        if (node_queue_packet(node, node->id->name, EDGE_EXG, curr_buf, size)) {
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

    size_t max_entries = OSHPACKET_PAYLOAD_MAXSIZE / sizeof(oshpacket_route_t);
    size_t remaining_entries = count;
    uint8_t *curr_buf = (uint8_t *) buf;
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
        size = entries * sizeof(oshpacket_route_t);

        // Broadcast the packet
        if (node_queue_packet_broadcast(exclude, ROUTE_ADD, curr_buf, size)) {
            logger_debug(DBG_ROUTING, "Broadcast ROUTE_ADD with %zu local routes (%zu bytes)",
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