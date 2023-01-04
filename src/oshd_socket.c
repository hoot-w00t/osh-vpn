#include "oshd_socket.h"
#include "oshd.h"
#include "oshd_process_packet.h"
#include "events.h"
#include "xalloc.h"
#include "tcp.h"
#include "logger.h"
#include "macros.h"
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

// Set network socket options
static bool oshd_setsockopts(sock_t sockfd)
{
    unsigned int optval;

#if defined(SOL_SOCKET) && defined(SO_KEEPALIVE)
    // Enable keep alive probing on the socket
    optval = 1;
    if (sock_setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval)) < 0) {
        logger(LOG_ERR, "Failed to set SO_KEEPALIVE option on socket " PRI_SOCK_T, sockfd);
        return false;
    }
#endif

#if defined(SOL_TCP) && defined(TCP_USER_TIMEOUT)
    // Set socket timeout to 30 seconds
    // The timeout value is in milliseconds
    optval = 30000;
    if (sock_setsockopt(sockfd, SOL_TCP, TCP_USER_TIMEOUT, &optval, sizeof(optval)) < 0) {
        logger(LOG_ERR, "Failed to set TCP_USER_TIMEOUT option on socket " PRI_SOCK_T, sockfd);
        return false;
    }
#endif

    // Set the socket to non-blocking
    if (sock_set_nonblocking(sockfd) < 0) {
        logger(LOG_ERR, "Failed to set socket " PRI_SOCK_T " to non-blocking: %s",
            sockfd, sock_strerror(sock_errno));
        return false;
    }
    return true;
}

// Add callback for clients
// Adds it to the clients list
// If the connections are limited and the limit is reached, deletes the event
// without adding it to the list
static void client_aio_add(aio_event_t *event)
{
    client_t *c = (client_t *) event->userdata;

    if (oshd_clients_limited()) {
        logger(LOG_WARN, "Simultaneous connections limited to %zu, disconnecting %s",
            oshd.clients_count_max, c->addrw);
        aio_event_del(c->aio_event);
    } else {
        oshd.clients = xreallocarray(oshd.clients, oshd.clients_count + 1, sizeof(client_t *));
        oshd.clients[oshd.clients_count] = c;
        oshd.clients_count += 1;
    }
}

// Delete callback for clients
// Frees the client and removes it from the clients list
static void client_aio_delete(aio_event_t *event)
{
    client_t *c = (client_t *) event->userdata;
    size_t i;

    // Free the client
    client_destroy(c);

    // Search the index of the client in the list
    for (i = 0; i < oshd.clients_count && oshd.clients[i] != c; ++i);

    // If the client is not in the list then we are done
    if (i >= oshd.clients_count)
        return;

    // Otherwise if the client is not last in the list we have to shift the
    // ones that come after before resizing the array
    if ((i + 1) < oshd.clients_count) {
        memmove(&oshd.clients[i], &oshd.clients[i + 1],
            sizeof(client_t *) * (oshd.clients_count - i - 1));
    }
    oshd.clients_count -= 1;
    oshd.clients = xreallocarray(oshd.clients, oshd.clients_count, sizeof(client_t *));
}

// Read callback for clients
// Reads available data from the socket and processes packets that are fully
// received
static void client_aio_read(aio_event_t *event)
{
    client_t *c = (client_t *) event->userdata;
    ssize_t recvd_size;

    // Receive available data
    recvd_size = sock_recv(c->sockfd, c->io.recvbuf + c->io.recvbuf_size,
        CLIENT_RECVBUF_SIZE - c->io.recvbuf_size, MSG_NOSIGNAL);

    if (recvd_size > 0) {
        logger_debug(DBG_SOCKETS, "%s: Received %zi bytes", c->addrw, recvd_size);
        c->io.recvbuf_size += recvd_size;
    } else if (recvd_size < 0) {
        const sock_errno_t err = sock_errno;

        if (!sock_ewouldblock(err)) {
            logger(LOG_ERR, "%s: %s: %s", c->addrw, "sock_recv", sock_strerror(err));
            aio_event_del(c->aio_event);
            return;
        }
    } else {
        logger(LOG_ERR, "%s: %s: socket closed", c->addrw, "sock_recv");
        aio_event_del(c->aio_event);
        return;
    }

    // Process packets in the buffer
    uint8_t *curr_packet = c->io.recvbuf;
    oshpacket_hdr_t *curr_hdr = OSHPACKET_HDR(curr_packet);
    size_t remaining_size = c->io.recvbuf_size;

    while (1) {
        if (!c->io.recvd_hdr) {
            // If we have enough data to decode the next header, we decode it
            if (remaining_size >= OSHPACKET_PUBLIC_HDR_SIZE) {
                // Switch payload size to host byte order
                curr_hdr->payload_size = ntohs(curr_hdr->payload_size);

                c->io.recv_pkt_size = OSHPACKET_CALC_SIZE(curr_hdr->payload_size);
                if (c->io.recv_pkt_size > OSHPACKET_MAXSIZE) {
                    logger(LOG_ERR, "%s: Invalid packet size (recv, %zu bytes)",
                        c->addrw, c->io.recv_pkt_size);
                    aio_event_del(c->aio_event);
                    return;
                }

                // We decoded the public header so now we are ready to receive
                // the packet and process it after it was completely received
                c->io.recvd_hdr = true;
            } else {
                // No more data is ready to be processed, we break the loop
                break;
            }
        } else {
            // If we fully received the decoded packet we can process it
            if (remaining_size >= c->io.recv_pkt_size) {
                oshpacket_t pkt;

                // Initialize the packet data for processing
                oshpacket_init(&pkt, curr_packet, c->io.recv_pkt_size, c->recv_seqno);

                // We have to pre-increment the receive seqno because the packet
                // handler can modify it after a successful handshake
                // In this case it must not be incremented as that would offset
                // it by 1 from the other node's send seqno (and decryptions
                // will fail)
                c->recv_seqno += 1;

                if (!oshd_process_packet(c, &pkt)) {
                    // There was an error while processing the packet, we drop the
                    // connection
                    aio_event_del(c->aio_event);
                    return;
                }

                // If finish_and_disconnect is true the client is gracefully
                // disconnecting, ignore any other packets
                if (c->finish_and_disconnect)
                    break;

                // Prepare to process the next packet
                c->io.recvd_hdr = false;

                // Shift the current packet pointer to the next
                remaining_size -= c->io.recv_pkt_size;
                curr_packet += c->io.recv_pkt_size;
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
        c->io.recvbuf_size = 0;
    } else {
        // We have some unprocessed data left in the buffer, shift it to the
        // start of it
        memmove(c->io.recvbuf, curr_packet, remaining_size);
        c->io.recvbuf_size = remaining_size;
    }
}

// Write callback for clients
// Sends queued data
static void client_aio_write(aio_event_t *event)
{
    client_t *c = (client_t *) event->userdata;
    ssize_t sent_size;

    sent_size = sock_send(c->sockfd, netbuffer_data(c->io.sendq),
        netbuffer_data_size(c->io.sendq), MSG_NOSIGNAL);

    if (sent_size < 0) {
        const sock_errno_t err = sock_errno;

        // send() would block, this is a safe error
        if (sock_ewouldblock(err))
            return;

        // Other errors probably mean that the connection is broken
        logger(LOG_ERR, "%s: %s: %s", c->addrw, "sock_send", sock_strerror(err));
        aio_event_del(c->aio_event);
        return;
    }

    logger_debug(DBG_SOCKETS, "%s: Sent %zi bytes", c->addrw, sent_size);
    if (!netbuffer_pop(c->io.sendq, sent_size)) {
        // The send queue is empty
        aio_disable_poll_events(c->aio_event, AIO_WRITE);

        // If we should disconnect, do it
        if (c->finish_and_disconnect) {
            logger(LOG_INFO, "Gracefully disconnecting %s", c->addrw);
            aio_event_del(c->aio_event);
            return;
        }
    }
}

// Non-blocking connect
static bool oshd_connect_async(client_t *c)
{
    // We try to connect the socket
    if (sock_connect(c->sockfd, (struct sockaddr *) &c->sa, sizeof(c->sa)) < 0) {
        const sock_errno_t err = sock_errno;

        // If error is EISCONN the connection is already established, so we can
        // proceed without processing any error
        if (!sock_eisconn(err)) {
            // If the error is EINPROGRESS, EALREADY or EWOULDBLOCK we just need
            // to wait longer for the socket to finish connecting
            if (sock_einprogress(err) || sock_ewouldblock(err))
                return true;

            // Otherwise something is wrong with the socket
            logger(LOG_ERR, "%s: %s: %s", "sock_connect", c->addrw, sock_strerror(err));
            aio_event_del(c->aio_event);
            return false;
        }
    }

    // We did not have an error, so the socket has finished connecting
    logger(LOG_INFO, "Established connection with %s", c->addrw);
    c->connected = true;
    c->aio_event->cb_write = client_aio_write;

    // We are the initiator, so we initiate the authentication
    return client_queue_initial_packet(c);
}

// Write callback for client
// Handles outgoing connections in progress
static void client_aio_write_connect(aio_event_t *event)
{
    client_t *c = (client_t *) event->userdata;

    if (!oshd_connect_async(c))
        aio_event_del(c->aio_event);
}

// Error callback for clients
// Deletes the event on error
static void client_aio_error(aio_event_t *event, aio_poll_event_t revents)
{
    client_t *c = (client_t *) event->userdata;

    if (revents & AIO_HUP) {
        logger(LOG_ERR, "%s: socket closed", c->addrw);
    } else {
        logger(LOG_ERR, "%s: socket error", c->addrw);
    }
    aio_event_del(c->aio_event);
}

// Create an aio event for the client and add it to the global aio
// Correctly sets poll_events and cb_write
// Sets c->aio_event
static void oshd_client_add(client_t *c)
{
    aio_event_t base_event;

    // Initialize the event's constants
    base_event.fd = c->sockfd;
    base_event.poll_events = AIO_READ;
    base_event.userdata = c;
    base_event.cb_add = client_aio_add;
    base_event.cb_delete = client_aio_delete;
    base_event.cb_read = client_aio_read;
    base_event.cb_error = client_aio_error;

    // Initialize the correct write callback and add AIO_WRITE if needed
    if (c->connected) {
        base_event.cb_write = client_aio_write;

        // There is no need to callback the write function if no data is queued
        if (netbuffer_data_size(c->io.sendq))
            base_event.poll_events |= AIO_WRITE;
    } else {
        // Outgoing connections trigger a write when ready
        base_event.cb_write = client_aio_write_connect;
        base_event.poll_events |= AIO_WRITE;
    }

    // The client needs to keep track of its aio event
    c->aio_event = aio_event_add(oshd.aio, &base_event);
}

// Queue client connection (non-blocking connect)
bool oshd_client_connect(node_id_t *nid, endpoint_t *endpoint)
{
    client_t *c;
    sock_t sockfd;
    struct sockaddr_storage sa;

    // If the endpoint is a hostname, lookup its IP addresses and insert them to
    // the connection group
    if (endpoint->type == ENDPOINT_TYPE_HOSTNAME) {
        endpoint_lookup(endpoint, nid->connect_endpoints);
        node_connect_continue(nid);
        return false;
    }

    // Initialize sockaddr
    if (!endpoint_to_sockaddr((struct sockaddr *) &sa, sizeof(sa), endpoint)) {
        logger(LOG_ERR, "Failed to initialize socket address for %s",
            endpoint->addrstr);
        node_connect_continue(nid);
        return false;
    }

    // Create TCP socket
    sockfd = tcp_outgoing_socket((const struct sockaddr *) &sa, sizeof(sa));
    if (sockfd == invalid_sock_t) {
        // The socket could not be created, try the next endpoint
        node_connect_continue(nid);
        return false;
    }

    // The socket was created successfully, initialize the client, configure it
    // and start trying to connect to it
    // client's socket information
    c = client_init(sockfd, true, endpoint, &sa);
    client_reconnect_to(c, nid);
    oshd_setsockopts(sockfd);
    oshd_client_add(c);
    logger(LOG_INFO, "Trying to connect to %s at %s...", nid->name, c->addrw);

    return oshd_connect_async(c);
}

// Error callback for TCP servers
// If a server fails, stop the daemon
static void server_aio_error(aio_event_t *event, aio_poll_event_t revents)
{
    logger(LOG_CRIT, "Server socket error (fd: " PRI_AIO_FD_T ", revents: " AIO_PE_FMT ")",
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

    client_t *c;
    struct sockaddr_storage sa;
    socklen_t sa_len = sizeof(sa);
    sock_t client_sockfd;
    endpoint_t *endpoint;

    // Accept the incoming socket
    client_sockfd = sock_accept(event->fd, (struct sockaddr *) &sa, &sa_len);
    if (client_sockfd == invalid_sock_t) {
        logger(LOG_ERR, "%s: " PRI_AIO_FD_T ": %s", "sock_accept", event->fd,
            sock_strerror(sock_errno));
        return;
    }

    endpoint = endpoint_from_sockaddr((const struct sockaddr *) &sa, sa_len,
        ENDPOINT_SOCKTYPE_TCP, true);
    if (!endpoint) {
        sock_close(client_sockfd);
        return;
    }

    // Set all the socket options
    oshd_setsockopts(client_sockfd);

    // Initialize the client with the newly created socket
    c = client_init(client_sockfd, false, endpoint, &sa);
    c->connected = true;
    oshd_client_add(c);
    logger(LOG_INFO, "Accepted connection from %s", c->addrw);

    // Free temporary endpoint
    endpoint_free(endpoint);
}

// Delete callback for TCP servers
static void server_aio_del(aio_event_t *event)
{
    if (event->fd != invalid_sock_t)
        sock_close(event->fd);
}

// Add an aio event for a TCP server
void oshd_server_add(sock_t server_sockfd)
{
    aio_event_add_inl(oshd.aio,
        server_sockfd,
        AIO_READ,
        NULL,
        NULL,
        server_aio_del,
        server_aio_read,
        NULL,
        server_aio_error);
}
