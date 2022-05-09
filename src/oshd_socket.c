#include "oshd.h"
#include "oshd_process_packet.h"
#include "events.h"
#include "xalloc.h"
#include "tcp.h"
#include "logger.h"
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/tcp.h>

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

    // Set socket timeout to 30 seconds
    // The timeout value is in milliseconds
    optval = 30000;
    if (setsockopt(s, SOL_TCP, TCP_USER_TIMEOUT, &optval, sizeof(optval)) < 0) {
        logger(LOG_ERR, "Failed to set TCP_USER_TIMEOUT option on socket %i", s);
        return false;
    }

    // Set the socket to non-blocking
    if (set_nonblocking(s) < 0) {
        logger(LOG_ERR, "Failed to set socket %i to non-blocking", s);
        return false;
    }
    return true;
}

// Add callback for nodes
// Adds node to the nodes list
// If the connections are limited and the limit is reached, deletes the event
// without adding it to the list
static void node_aio_add(aio_event_t *event)
{
    node_t *node = (node_t *) event->userdata;

    if (oshd_nodes_limited()) {
        logger(LOG_WARN, "Simultaneous connections limited to %zu, disconnecting %s",
            oshd.nodes_count_max, node->addrw);
        aio_event_del(node->aio_event);
    } else {
        oshd.nodes = xreallocarray(oshd.nodes, oshd.nodes_count + 1, sizeof(node_t *));
        oshd.nodes[oshd.nodes_count] = node;
        oshd.nodes_count += 1;
    }
}

// Delete callback for nodes
// Frees the node and removes it from the nodes list
static void node_aio_delete(aio_event_t *event)
{
    node_t *node = (node_t *) event->userdata;
    size_t i;

    // Free the node
    node_destroy(node);

    // Search the index of the node in the list
    for (i = 0; i < oshd.nodes_count && oshd.nodes[i] != node; ++i);

    // If the node is not in the list then we are done
    if (i >= oshd.nodes_count)
        return;

    // Otherwise if the node is not last in the list we have to shift the
    // ones that come after before resizing the array
    if ((i + 1) < oshd.nodes_count) {
        memmove(&oshd.nodes[i], &oshd.nodes[i + 1],
            sizeof(node_t *) * (oshd.nodes_count - i - 1));
    }
    oshd.nodes_count -= 1;
    oshd.nodes = xreallocarray(oshd.nodes, oshd.nodes_count, sizeof(node_t *));
}

// Read callback for nodes
// Reads available data from the socket and processes packets that are fully
// received
static void node_aio_read(aio_event_t *event)
{
    node_t *node = (node_t *) event->userdata;
    ssize_t recvd_size;

    // Receive available data
    recvd_size = recv(node->fd, node->io.recvbuf + node->io.recvbuf_size,
        NODE_RECVBUF_SIZE - node->io.recvbuf_size, MSG_NOSIGNAL);

    if (recvd_size > 0) {
        logger_debug(DBG_SOCKETS, "%s: Received %zi bytes", node->addrw, recvd_size);
        node->io.recvbuf_size += recvd_size;
    } else if (recvd_size < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            logger(LOG_ERR, "%s: recv: %s", node->addrw, strerror(errno));
            aio_event_del(node->aio_event);
            return;
        }
    } else {
        logger(LOG_ERR, "%s: recv: socket closed", node->addrw);
        aio_event_del(node->aio_event);
        return;
    }

    // Process packets in the buffer
    uint8_t *curr_packet = node->io.recvbuf;
    oshpacket_hdr_t *curr_hdr = OSHPACKET_HDR(curr_packet);
    size_t remaining_size = node->io.recvbuf_size;

    while (1) {
        if (!node->io.recvd_hdr) {
            // If we have enough data to decode the next header, we decode it
            if (remaining_size >= OSHPACKET_PUBLIC_HDR_SIZE) {
                // If the magic number is invalid something is wrong
                if (curr_hdr->magic != OSHPACKET_MAGIC) {
                    logger(LOG_ERR, "%s: Received invalid magic number 0x%X",
                        node->addrw, curr_hdr->magic);
                    aio_event_del(node->aio_event);
                    return;
                }

                // Switch payload size to host byte order
                curr_hdr->payload_size = ntohs(curr_hdr->payload_size);

                node->io.recv_pkt_size = OSHPACKET_HDR_SIZE + curr_hdr->payload_size;
                if (node->io.recv_pkt_size > OSHPACKET_MAXSIZE) {
                    logger(LOG_ERR, "%s: Invalid packet size (recv, %zu bytes)",
                        node->addrw, node->io.recv_pkt_size);
                    aio_event_del(node->aio_event);
                    return;
                }

                // We decoded the public header so now we are ready to receive
                // the packet and process it after it was completely received
                node->io.recvd_hdr = true;
            } else {
                // No more data is ready to be processed, we break the loop
                break;
            }
        } else {
            // If we fully received the decoded packet we can process it
            if (remaining_size >= node->io.recv_pkt_size) {
                if (!oshd_process_packet(node, curr_packet)) {
                    // There was an error while processing the packet, we drop the
                    // connection
                    aio_event_del(node->aio_event);
                    return;
                }

                // Prepare to process the next packet
                node->io.recvd_hdr = false;

                // Shift the current packet pointer to the next
                remaining_size -= node->io.recv_pkt_size;
                curr_packet += node->io.recv_pkt_size;
                curr_hdr = OSHPACKET_HDR(curr_packet);
            } else {
                // We haven't fully received the packet and no more data is
                // ready to be processed, we break the loop
                break;
            }
        }
    }

    // Shift the unprocessed data for the next recv()
    if (remaining_size == 0) {
        // Everything in the buffer was processed
        node->io.recvbuf_size = 0;
    } else {
        // We have some unprocessed data left in the buffer, shift it to the
        // start of it
        memmove(node->io.recvbuf, curr_packet, remaining_size);
        node->io.recvbuf_size = remaining_size;
    }
}

// Write callback for nodes
// Sends queued data
static void node_aio_write(aio_event_t *event)
{
    node_t *node = (node_t *) event->userdata;
    ssize_t sent_size;

    sent_size = send(node->fd, netbuffer_data(node->io.sendq),
        netbuffer_data_size(node->io.sendq), MSG_NOSIGNAL);

    if (sent_size < 0) {
        // send() would block, this is a safe error
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return;

        // Other errors probably mean that the connection is broken
        logger(LOG_ERR, "%s: send: %s", node->addrw, strerror(errno));
        aio_event_del(node->aio_event);
        return;
    }

    logger_debug(DBG_SOCKETS, "%s: Sent %zi bytes", node->addrw, sent_size);
    if (!netbuffer_pop(node->io.sendq, sent_size)) {
        // The send queue is empty
        aio_disable_poll_events(node->aio_event, AIO_WRITE);

        // If we should disconnect, do it
        if (node->finish_and_disconnect) {
            logger(LOG_INFO, "Gracefully disconnecting %s", node->addrw);
            aio_event_del(node->aio_event);
            return;
        }
    }
}

// Non-blocking connect
static bool oshd_connect_async(node_t *node)
{
    // We try to connect the socket
    if (connect(node->fd, (struct sockaddr *) &node->sin, sizeof(node->sin)) < 0) {
        // If error is EISCONN the connection is already established, so we can
        // proceed without processing any error
        if (errno != EISCONN) {
            // If the error is EINPROGRESS or EALREADY we just need to wait longer
            // for the socket to finish connecting
            if (errno == EINPROGRESS || errno == EALREADY)
                return true;

            // Otherwise something is wrong with the socket
            logger(LOG_ERR, "connect: %s: %s", node->addrw, strerror(errno));
            aio_event_del(node->aio_event);
            return false;
        }
    }

    // We did not have an error, so the socket has finished connecting
    logger(LOG_INFO, "Established connection with %s", node->addrw);
    node->connected = true;
    node->aio_event->cb_write = node_aio_write;

    // We are the initiator, so we initiate the authentication
    return node_queue_initial_packet(node);
}

// Write callback for nodes
// Handles outgoing connections in progress
static void node_aio_write_connect(aio_event_t *event)
{
    node_t *node = (node_t *) event->userdata;

    if (!oshd_connect_async(node))
        aio_event_del(node->aio_event);
}

// Error callback for nodes
// Deletes the event on error
static void node_aio_error(aio_event_t *event, aio_poll_event_t revents)
{
    node_t *node = (node_t *) event->userdata;

    if (revents & AIO_HUP) {
        logger(LOG_ERR, "%s: socket closed", node->addrw);
    } else {
        logger(LOG_ERR, "%s: socket error", node->addrw);
    }
    aio_event_del(node->aio_event);
}

// Create an aio event for node and add it to the global aio
// Correctly sets poll_events and cb_write
// Sets node->aio_event
static void oshd_add_node(node_t *node)
{
    aio_event_t base_event;

    // Initialize the event's constants
    base_event.fd = node->fd;
    base_event.poll_events = AIO_READ;
    base_event.userdata = node;
    base_event.cb_add = node_aio_add;
    base_event.cb_delete = node_aio_delete;
    base_event.cb_read = node_aio_read;
    base_event.cb_error = node_aio_error;

    // Initialize the correct write callback and add AIO_WRITE if needed
    if (node->connected) {
        base_event.cb_write = node_aio_write;

        // There is no need to callback the write function if no data is queued
        if (netbuffer_data_size(node->io.sendq))
            base_event.poll_events |= AIO_WRITE;
    } else {
        // Outgoing connections trigger a write when ready
        base_event.cb_write = node_aio_write_connect;
        base_event.poll_events |= AIO_WRITE;
    }

    // The node needs to keep track of its aio event
    node->aio_event = aio_event_add(oshd.aio, &base_event);
}

// Queue node connection (non-blocking connect)
bool oshd_connect_queue(endpoint_group_t *endpoints, time_t delay)
{
    node_t *node;
    int client_fd;
    char d_addr[128];
    netaddr_t naddr;
    struct sockaddr_storage d_sin;
    endpoint_t *endpoint = endpoint_group_selected(endpoints);

    if (endpoints->has_owner) {
        node_id_t *id = node_id_find(endpoints->owner_name);

        if (id && id->node_socket) {
            logger(LOG_INFO,
                "Giving up trying to reconnect to %s (already connected)",
                id->name);
            endpoint_group_select_first(endpoints);
            endpoint_group_set_is_connecting(endpoints, false);
            return false;
        }
    }

    // Initialize and create a socket to connect to address:port
    memset(d_addr, 0, sizeof(d_addr));
    memset(&d_sin, 0, sizeof(d_sin));

    if (!endpoint) {
        // If this warning appears the code is glitched
        logger(LOG_WARN, "oshd_connect_queue called with no endpoint");
        return false;
    }

    client_fd = tcp_outgoing_socket(endpoint->hostname, endpoint->port, d_addr,
        sizeof(d_addr), (struct sockaddr *) &d_sin, sizeof(d_sin));

    if (client_fd < 0) {
        // Either the socket could not be created or there was a DNS lookup
        // error, try the next endpoint
        node_reconnect_endpoints_next(endpoints, delay);
        return false;
    }

    // The socket was created successfully, we can initialize some of the node's
    // socket information
    netaddr_pton(&naddr, d_addr);
    node = node_init(client_fd, true, &naddr, endpoint->port);
    node_reconnect_to(node, endpoints, delay);
    memcpy(&node->sin, &d_sin, sizeof(d_sin));

    // Set all the socket options
    oshd_setsockopts(client_fd);

    oshd_add_node(node);

    if (endpoints->has_owner) {
        logger(LOG_INFO, "Trying to connect to %s at %s...",
            endpoints->owner_name, node->addrw);
    } else {
        logger(LOG_INFO, "Trying to connect to %s...", node->addrw);
    }
    return oshd_connect_async(node);
}

// Error callback for TCP servers
// If a server fails, stop the daemon
static void server_aio_error(aio_event_t *event, aio_poll_event_t revents)
{
    logger(LOG_CRIT, "Server socket error (fd: %i, revents: " AIO_PE_FMT ")",
        event->fd, revents);
    aio_event_del(event);
    oshd_stop();
}

// Read callback for TCP servers
// Accept an incoming connection
static void server_aio_read(aio_event_t *event)
{
    // Only accept new connections if the daemon is running
    // This prevents accepting connections while the daemon is closing
    if (!oshd.run)
        return;

    node_t *node;
    netaddr_t addr;
    uint16_t port;
    struct sockaddr_in6 sin;
    socklen_t sin_len = sizeof(sin);
    int client_fd;

    // Accept the incoming socket
    if ((client_fd = accept(event->fd, (struct sockaddr *) &sin, &sin_len)) < 0) {
        logger(LOG_ERR, "accept: %i: %s", event->fd, strerror(errno));
        return;
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
    oshd_add_node(node);
}

// Add an aio event for a TCP server
void oshd_server_add(int server_fd)
{
    aio_event_add_inl(oshd.aio,
        server_fd,
        AIO_READ,
        NULL,
        NULL,
        aio_cb_delete_close_fd,
        server_aio_read,
        NULL,
        server_aio_error);
}