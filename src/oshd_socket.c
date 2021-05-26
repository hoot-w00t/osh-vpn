#include "oshd.h"
#include "oshd_device.h"
#include "oshd_route.h"
#include "node.h"
#include "events.h"
#include "netpacket.h"
#include "tcp.h"
#include "logger.h"
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

// Set network socket options
static bool oshd_setsockopts(int s)
{
    uint32_t optval;

    // Enable keep alive probing on the socket
    optval = 1;
    if (setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval)) < 0) {
        logger(LOG_ERR, "Failed to set SO_KEEPALIVE option on socket %i", s);
        return false;
    }

    // Set the socket to non-blocking
    if (set_nonblocking(s) < 0) {
        logger(LOG_ERR, "Failed to set socket %i to non-blocking", s);
        return -1;
    }
    return true;
}

// Accept incoming connection
bool oshd_accept(void)
{
    node_t *node;
    netaddr_t addr;
    uint16_t port;
    struct sockaddr_in6 sin;
    socklen_t sin_len = sizeof(sin);
    int client_fd;

    // Accept the incoming socket
    if ((client_fd = accept(oshd.server_fd, (struct sockaddr *) &sin, &sin_len)) < 0) {
        logger(LOG_ERR, "accept: %s", strerror(errno));
        return false;
    }

    // Get the remote socket's address and port
    if (((struct sockaddr *) &sin)->sa_family == AF_INET6) {
        netaddr_dton(&addr, IP6, &sin.sin6_addr);
        port = sin.sin6_port;
    } else {
        netaddr_dton(&addr, IP4, &((struct sockaddr_in *) &sin)->sin_addr);
        port = ((struct sockaddr_in *) &sin)->sin_port;
    }

    // Set all the socket options
    oshd_setsockopts(client_fd);

    // Initialize the node we the newly created socket
    node = node_init(client_fd, false, &addr, port);
    node->connected = true;

    logger(LOG_INFO, "Accepted connection from %s", node->addrw);
    event_queue_node_add(node);
    return true;
}

// Queue node connection (non-blocking connect)
bool oshd_connect_queue(const char *address, const uint16_t port, time_t delay)
{
    node_t *node;
    int client_fd;
    char d_addr[128];
    netaddr_t naddr;
    struct sockaddr_in6 d_sin;
    socklen_t d_sin_len = sizeof(struct sockaddr_in6);

    // Initialize and create a socket to connect to address:port
    memset(d_addr, 0, sizeof(d_addr));
    memset(&d_sin, 0, d_sin_len);
    client_fd = tcp_outgoing_socket(address, port, d_addr, sizeof(d_addr),
        (struct sockaddr *) &d_sin, d_sin_len);

    if (client_fd < 0)
        return false;

    // The socket was created successfully, we can initialize some of the node's
    // socket information
    netaddr_pton(&naddr, d_addr);
    node = node_init(client_fd, true, &naddr, port);
    node_reconnect_to(node, address, port, delay);
    memcpy(&node->sin, &d_sin, d_sin_len);

    // Set all the socket options
    oshd_setsockopts(client_fd);

    event_queue_node_add(node);

    logger(LOG_INFO, "Trying to connect to %s...", node->addrw);
    return true;
}

// Try to connect the socket of *node
// Should be called after a non-blocking oshd_connect_queue() until node->connected is
// set to true
bool oshd_connect_async(node_t *node)
{
    // We try to connect the socket
    if (connect(node->fd, (struct sockaddr *) &node->sin, sizeof(node->sin)) < 0) {
        // If the error is EINPROGRESS or EALREADY we just need to wait longer
        // for the socket to finish connecting
        if (errno != EINPROGRESS && errno != EALREADY) {
            // Otherwise something is wrong with the socket
            logger(LOG_ERR, "connect: %s: %s", node->addrw, strerror(errno));
            event_queue_node_remove(node);
            return false;
        }
    } else {
        // We did not have an error, so the socket has finished connecting
        logger(LOG_INFO, "Established connection with %s", node->addrw);
        node->connected = true;

        // We can reset the reconnection delay to the minimum
        node_reconnect_delay(node, oshd.reconnect_delay_min);

        // We are the initiator, so we initiate the authentication
        return node_queue_hello(node);
    }
    return true;
}

// Try to connect to a node (blocking)
bool oshd_connect(const char *address, const uint16_t port, time_t delay)
{
    node_t *node;
    int client_fd;
    char d_addr[128];
    netaddr_t naddr;

    // These are the same steps as in the oshd_connect_queue function
    // but here we will have a connected socket when returning
    memset(d_addr, 0, sizeof(d_addr));
    if ((client_fd = tcp_connect(address, port, d_addr, sizeof(d_addr))) < 0)
        return false;
    netaddr_pton(&naddr, d_addr);
    node = node_init(client_fd, true, &naddr, port);
    node_reconnect_to(node, address, port, delay);
    node->connected = true;
    oshd_setsockopts(client_fd);
    event_queue_node_add(node);
    return node_queue_hello(node);
}

// Send queued data to node
// If netbuffer is complete free netbuffer and skip
// to next
bool node_send_queued(node_t *node)
{
    ssize_t sent_size;

    if (node->io.sendq_packet_size > OSHPACKET_MAXSIZE) {
        logger(LOG_ERR, "%s: Invalid packet size (send, %u bytes)",
            node->addrw, node->io.sendq_packet_size);
        event_queue_node_remove(node);
        return false;
    }

    sent_size = send(node->fd, node->io.sendq_ptr, node->io.sendq_packet_size,
        MSG_NOSIGNAL);

    if (sent_size > 0) {
        node->io.sendq_packet_size -= sent_size;
        if (node->io.sendq_packet_size == 0) {
            // We're done sending the current packet
            // Move to the next packet in queue
            if ((node->io.sendq_ptr = netbuffer_next(node->io.sendq))) {
                // If we do have another packet in queue, retrieve its size
                node->io.sendq_packet_size = OSHPACKET_HDR_SIZE + ntohs(((oshpacket_hdr_t *) node->io.sendq_ptr)->payload_size);
            } else {
                // The send queue is empty
                // If we should disconnect, do it
                if (node->finish_and_disconnect) {
                    logger(LOG_INFO, "Gracefully disconnecting %s", node->addrw);
                    event_queue_node_remove(node);
                    return false;
                }
            }
        } else {
            // We're not done sending this packet, shift pointer to the remaining data
            node->io.sendq_ptr += sent_size;
        }
    } else if (sent_size < 0) {
        // There was a send() error
        logger(LOG_ERR, "%s: send: %s", node->addrw, strerror(errno));
        event_queue_node_remove(node);
        return false;
    }
    return true;
}

// Receive data from node
// Process the packet when received completely
bool node_recv_queued(node_t *node)
{
    ssize_t recvd_size;
    oshpacket_hdr_t *pkt = (oshpacket_hdr_t *) node->io.recvbuf;

    recvd_size = recv(node->fd, node->io.recvbuf + node->io.recv_bytes,
        node->io.recv_packet_size - node->io.recv_bytes, MSG_NOSIGNAL);

    if (recvd_size > 0) {
        node->io.recv_bytes += recvd_size;
        if (!node->io.recvd_hdr) {
            if (node->io.recv_bytes >= OSHPACKET_HDR_SIZE) {
                // Switch payload size to host byte order
                pkt->payload_size = ntohs(pkt->payload_size);

                node->io.recv_packet_size = OSHPACKET_HDR_SIZE + pkt->payload_size;
                if (node->io.recv_packet_size <= OSHPACKET_HDR_SIZE || node->io.recv_packet_size > OSHPACKET_MAXSIZE) {
                    logger(LOG_ERR, "%s: Invalid packet size (recv, %u bytes)", node->addrw, node->io.recv_packet_size);
                    event_queue_node_remove(node);
                    return false;
                }
                node->io.recvd_hdr = true;
            }
        } else if (node->io.recv_bytes == node->io.recv_packet_size) {
            if (!oshd_process_packet(node)) {
                // There was an error while processing the packet, we drop the
                // connection
                event_queue_node_remove(node);
                return false;
            }

            // Prepare to receive the next packet
            node->io.recvd_hdr = false;
            node->io.recv_packet_size = OSHPACKET_HDR_SIZE;
            node->io.recv_bytes = 0;
        }
    } else if (recvd_size < 0) {
        logger(LOG_ERR, "%s: recv: %s", node->addrw, strerror(errno));
        event_queue_node_remove(node);
        return false;
    }
    return true;
}

// Iterate through all edges in *payload and add/delete them
static bool oshd_process_edge(node_t *node, oshpacket_hdr_t *pkt,
    uint8_t *payload, bool add)
{
    char *action_name = add ? "Add" : "Delete";
    void (*action)(node_id_t *, node_id_t *) = add ? &node_id_add_edge
                                                   : &node_id_del_edge;

    const size_t entry_size = NODE_NAME_SIZE * 2;
    const size_t edges = pkt->payload_size / entry_size;
    char src_name[NODE_NAME_SIZE + 1];
    char dest_name[NODE_NAME_SIZE + 1];
    node_id_t *src;
    node_id_t *dest;

    for (size_t i = 0; i < edges; ++i) {
        memcpy(src_name,
            payload + (entry_size * i),
            NODE_NAME_SIZE);
        memcpy(dest_name,
            payload + (entry_size * i) + NODE_NAME_SIZE,
            NODE_NAME_SIZE);

        if (!node_valid_name(src_name) || !node_valid_name(dest_name)) {
            logger(LOG_ERR, "%s: %s: %s edge: Invalid edge names", node->addrw,
                node->id->name, action_name);
            return false;
        }

        src = node_id_add(src_name);
        dest = node_id_add(dest_name);

        logger(LOG_DEBUG, "%s: %s: %s edge: %s <=> %s", node->addrw,
            node->id->name, action_name, src_name, dest_name);
        action(src, dest);
    }
    return true;
}

// Process a packet from a node that is not authenticated yet
static bool oshd_process_unauthenticated(node_t *node, oshpacket_hdr_t *pkt,
    uint8_t *payload)
{
    switch (pkt->type) {
        case HELLO: {
            if (pkt->payload_size > NODE_NAME_SIZE) {
                logger(LOG_ERR, "%s: Invalid HELLO size: %u bytes", node->addrw,
                    pkt->payload_size);
                return false;
            }
            if (!node->initiator) {
                if (!node_queue_hello(node))
                    return false;
            }

            char name[NODE_NAME_SIZE + 1];
            memset(name, 0, sizeof(name));
            memcpy(name, payload, pkt->payload_size);

            if (!node_valid_name(name)) {
                logger(LOG_ERR, "%s: Invalid name", node->addrw);
                return false;
            }

            node_id_t *id = node_id_add(name);

            if (id->node_socket) {
                // Disconnect the current socket if node is already authenticated
                logger(LOG_CRIT, "%s: Another socket is already authenticated as %s",
                    node->addrw, name);
                return false;
            }

            node_id_t *me = node_id_add(oshd.name);

            id->node_socket = node;
            node->id = id;
            node->authenticated = true;

            node_id_add_edge(me, id);
            node_tree_update();

            logger(LOG_INFO, "%s: Authenticated: %s", node->addrw, node->id->name);
            if (!node_queue_ping(node))
                return false;

            logger(LOG_INFO, "%s: %s: Exchanging the local network map", node->addrw, node->id->name);
            if (!node_queue_edge_exg(node))
                return false;
            if (!node_queue_edge_broadcast(node, ADD_EDGE, oshd.name, name))
                return false;

            return true;
        }

        case GOODBYE:
            logger(LOG_INFO, "%s: Gracefully disconnecting", node->addrw);
            return false;

        default:
            logger(LOG_ERR, "%s: Received %s packet but the node is not authenticated",
                node->addrw, oshpacket_type_name(pkt->type));
            return false;
    }
}

// Process a packet with our local node as destination, from an authenticated
// node
static bool oshd_process_authenticated(node_t *node, oshpacket_hdr_t *pkt,
    uint8_t *payload, node_id_t *src_node)
{
    switch (pkt->type) {
        case HELLO:
            logger(LOG_ERR, "%s: %s: Already authenticated but received HELLO",
                node->addrw, node->id->name);
            return false;

        case GOODBYE:
            logger(LOG_INFO, "%s: %s: Gracefully disconnecting", node->addrw,
                node->id->name);
            return false;

        case PING: return node_queue_pong(node);
        case PONG:
            gettimeofday(&node->rtt_pong, NULL);
            node->rtt = (node->rtt_pong.tv_usec - node->rtt_ping.tv_usec) / 1000;
            logger(LOG_DEBUG, "%s: %s: RTT %ims", node->addrw,
                node->id->name, node->rtt);

            return true;

        case EDGE_EXG:
        case ADD_EDGE:
        case DEL_EDGE: {
            if (    pkt->payload_size < (NODE_NAME_SIZE * 2)
                || (pkt->payload_size % (NODE_NAME_SIZE * 2)) != 0)
            {
                logger(LOG_ERR, "%s: Invalid %s size: %u bytes", node->addrw,
                    oshpacket_type_name(pkt->type), pkt->payload_size);
                return false;
            }

            bool success;

            if (pkt->type == EDGE_EXG) {
                // TODO: Only do it if our map doesn't share any edge with the
                //       remote node's map
                // Broadcast remote node's edges to our end of the network
                node_queue_packet_broadcast(node, ADD_EDGE, payload,
                    pkt->payload_size);

                success = oshd_process_edge(node, pkt, payload, true);
            } else if (pkt->type == ADD_EDGE) {
                success = oshd_process_edge(node, pkt, payload, true);
            } else {
                success = oshd_process_edge(node, pkt, payload, false);
            }
            node_tree_update();

            // Make sure that all nodes's routing tables are up to date with our
            // local routes
            node_queue_add_route_broadcast(NULL, oshd.local_routes,
                oshd.local_routes_count);
            return success;
        }

        case ADD_ROUTE: {
            const size_t entry_size = 17;

            if (    pkt->payload_size < entry_size
                || (pkt->payload_size % entry_size) != 0)
            {
                logger(LOG_ERR, "%s: Invalid ADD_ROUTE size: %u bytes",
                    node->addrw, pkt->payload_size);
                return false;
            }

            size_t entries = pkt->payload_size / entry_size;
            netaddr_t addr;

            for (size_t i = 0; i < entries; ++i) {
                addr.type = payload[(i * entry_size)];
                if (addr.type > IP6) {
                    logger(LOG_ERR, "%s: Invalid ADD_ROUTE address type",
                        node->addrw);
                    return false;
                }
                memcpy(addr.data, &payload[(i * entry_size) + 1], 16);
                netroute_add(&addr, src_node);
            }
            return true;
        }

        case DATA: {
            if (!oshd.tuntap_used)
                return true;

            netpacket_t netpkt;
            char netpkt_src[INET6_ADDRSTRLEN];
            char netpkt_dest[INET6_ADDRSTRLEN];

            if (!netpacket_from_data(&netpkt, payload, oshd.is_tap)) {
                logger(LOG_ERR, "%s: Failed to decode received tunnel packet", node->addrw);
                return false;
            }

            netaddr_ntop(netpkt_src, sizeof(netpkt_src), &netpkt.src);
            netaddr_ntop(netpkt_dest, sizeof(netpkt_dest), &netpkt.dest);

            logger(LOG_DEBUG, "%s: %s: %s <- %s (%u bytes, from %s)", node->addrw,
                node->id->name, netpkt_dest, netpkt_src, pkt->payload_size,
                src_node->name);

            if (!oshd_write_tuntap_pkt(payload, pkt->payload_size))
                return false;
            return true;
        }

        default:
            logger(LOG_ERR, "%s: %s: Received invalid packet type: 0x%X",
                node->addrw, node->id->name, pkt->type);
            return false;

    }
}

// Returns true if packet was processed without an error
// Returns false if node should be disconnected
bool oshd_process_packet(node_t *node)
{
    oshpacket_hdr_t *pkt = (oshpacket_hdr_t *) node->io.recvbuf;
    uint8_t *payload = node->io.recvbuf + OSHPACKET_HDR_SIZE;

    // If the magic number is invalid the packet is probably broken
    if (pkt->magic != OSHPACKET_MAGIC) {
        logger(LOG_ERR, "%s: Received invalid magic number 0x%X",
            node->addrw, pkt->magic);
        return false;
    }

    // If the node is unauthenticated we only accept authentication packets,
    // nothing else will be accepted or forwarded, if the authentication encounters
    // an error the connection is terminated
    if (!node->authenticated)
        return oshd_process_unauthenticated(node, pkt, payload);

    // We extract the destination node id from the packet header and see if the
    // packet is meant for us or if we need to forward it
    char src_node[NODE_NAME_SIZE + 1];
    char dest_node[NODE_NAME_SIZE + 1];
    memset(src_node, 0, sizeof(src_node));
    memset(dest_node, 0, sizeof(dest_node));
    strncpy(src_node, pkt->src_node, NODE_NAME_SIZE);
    strncpy(dest_node, pkt->dest_node, NODE_NAME_SIZE);

    if (!node_valid_name(src_node)) {
        logger(LOG_ERR, "%s: %s: Invalid source node", node->addrw,
            node->id->name);
        return false;
    }
    if (!node_valid_name(dest_node)) {
        logger(LOG_ERR, "%s: %s: Invalid destination node", node->addrw,
            node->id->name);
        return false;
    }

    // If the source node doesn't exist in the tree the remote node sent us
    // invalid data, we drop the connection
    node_id_t *src = node_id_find(src_node);
    if (!src) {
        logger(LOG_ERR, "%s: %s: Unknown source node: %s", node->addrw,
            node->id->name, src_node);
        return false;
    }

    // If the destination node is not the local node we'll forward this packet
    if (strcmp(dest_node, oshd.name)) {
        node_id_t *dest = node_id_find(dest_node);

        if (dest) {
            if (dest->next_hop) {
                logger(LOG_DEBUG, "Forwarding %s packet from %s to %s through %s",
                    oshpacket_type_name(pkt->type), src_node, dest_node, dest->next_hop->id->name);
                node_queue_packet_forward(dest->next_hop, pkt);
            } else {
                logger(LOG_INFO, "Dropping %s packet from %s to %s: No route",
                    oshpacket_type_name(pkt->type), src_node, dest_node);
            }
        } else {
            logger(LOG_WARN, "Dropping %s packet from %s to %s: Unknown destination",
                oshpacket_type_name(pkt->type), src_node, dest_node);
        }
        return true;
    }

    // Otherwise the packet is for us
    return oshd_process_authenticated(node, pkt, payload, src);
}