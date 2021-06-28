#include "oshd.h"
#include "oshd_process_packet.h"
#include "events.h"
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
        return node_queue_initial_packet(node);
    }
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

    if (client_fd < 0) {
        node_reconnect_exp(address, port, delay);
        return false;
    }

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
    return oshd_connect_async(node);
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
    if ((client_fd = tcp_connect(address, port, d_addr, sizeof(d_addr))) < 0) {
        node_reconnect_exp(address, port, delay);
        return false;
    }
    netaddr_pton(&naddr, d_addr);
    node = node_init(client_fd, true, &naddr, port);
    node_reconnect_to(node, address, port, delay);
    node->connected = true;
    oshd_setsockopts(client_fd);
    event_queue_node_add(node);
    return node_queue_initial_packet(node);
}

// Send queued data to node
// If netbuffer is complete free netbuffer and skip
// to next
bool node_send_queued(node_t *node)
{
    ssize_t sent_size;

    sent_size = send(node->fd, netbuffer_data(node->io.sendq),
        netbuffer_data_size(node->io.sendq), MSG_NOSIGNAL);

    if (sent_size > 0) {
        logger_debug(DBG_SOCKETS, "%s: Sent %zi bytes", node->addrw, sent_size);
        if (!netbuffer_pop(node->io.sendq, sent_size)) {
            // The send queue is empty
            node_pollout_unset(node);

            // If we should disconnect, do it
            if (node->finish_and_disconnect) {
                logger(LOG_INFO, "Gracefully disconnecting %s", node->addrw);
                event_queue_node_remove(node);
                return false;
            }
        }
    } else if (sent_size < 0) {
        // send() would block, this is a safe error
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return true;

        // Other errors need the connection to be dropped
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

    recvd_size = recv(node->fd, node->io.recvbuf + node->io.recvbuf_size,
        NODE_RECVBUF_SIZE - node->io.recvbuf_size, MSG_NOSIGNAL);

    if (recvd_size > 0) {
        logger_debug(DBG_SOCKETS, "%s: Received %zi bytes", node->addrw, recvd_size);
        node->io.recvbuf_size += recvd_size;
    } else if (recvd_size < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            logger(LOG_ERR, "%s: recv: %s", node->addrw, strerror(errno));
            event_queue_node_remove(node);
            return false;
        }
    }

    // There is no more data ready to be received on the socket, process the
    // received data

    uint8_t *curr_packet = node->io.recvbuf;
    oshpacket_hdr_t *curr_hdr = (oshpacket_hdr_t *) curr_packet;
    size_t remaining_size = node->io.recvbuf_size;

    while (1) {
        if (!node->io.recvd_hdr) {
            // If we have enough data to decode the next header, we decode it
            if (remaining_size >= OSHPACKET_PUBLIC_HDR_SIZE) {
                // If the magic number is invalid something is wrong
                if (curr_hdr->magic != OSHPACKET_MAGIC) {
                    logger(LOG_ERR, "%s: Received invalid magic number 0x%X",
                        node->addrw, curr_hdr->magic);
                    event_queue_node_remove(node);
                    return false;
                }

                // Switch payload size to host byte order
                curr_hdr->payload_size = ntohs(curr_hdr->payload_size);

                node->io.recv_pkt_size = OSHPACKET_HDR_SIZE + curr_hdr->payload_size;
                if (node->io.recv_pkt_size > OSHPACKET_MAXSIZE) {
                    logger(LOG_ERR, "%s: Invalid packet size (recv, %zu bytes)",
                        node->addrw, node->io.recv_pkt_size);
                    event_queue_node_remove(node);
                    return false;
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
                    event_queue_node_remove(node);
                    return false;
                }

                // Prepare to process the next packet
                node->io.recvd_hdr = false;

                // Shift the current packet pointer to the next
                remaining_size -= node->io.recv_pkt_size;
                curr_packet += node->io.recv_pkt_size;
                curr_hdr = (oshpacket_hdr_t *) curr_packet;
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
    return true;
}