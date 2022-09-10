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
    recvd_size = recv(c->fd, c->io.recvbuf + c->io.recvbuf_size,
        CLIENT_RECVBUF_SIZE - c->io.recvbuf_size, MSG_NOSIGNAL);

    if (recvd_size > 0) {
        logger_debug(DBG_SOCKETS, "%s: Received %zi bytes", c->addrw, recvd_size);
        c->io.recvbuf_size += recvd_size;
    } else if (recvd_size < 0) {
        if (!IO_WOULDBLOCK(errno)) {
            logger(LOG_ERR, "%s: recv: %s", c->addrw, strerror(errno));
            aio_event_del(c->aio_event);
            return;
        }
    } else {
        logger(LOG_ERR, "%s: recv: socket closed", c->addrw);
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

                c->io.recv_pkt_size = OSHPACKET_HDR_SIZE + curr_hdr->payload_size;
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
                if (!oshd_process_packet(c, curr_packet)) {
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

    sent_size = send(c->fd, netbuffer_data(c->io.sendq),
        netbuffer_data_size(c->io.sendq), MSG_NOSIGNAL);

    if (sent_size < 0) {
        // send() would block, this is a safe error
        if (IO_WOULDBLOCK(errno))
            return;

        // Other errors probably mean that the connection is broken
        logger(LOG_ERR, "%s: send: %s", c->addrw, strerror(errno));
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
    if (connect(c->fd, (struct sockaddr *) &c->sin, sizeof(c->sin)) < 0) {
        // If error is EISCONN the connection is already established, so we can
        // proceed without processing any error
        if (errno != EISCONN) {
            // If the error is EINPROGRESS or EALREADY we just need to wait longer
            // for the socket to finish connecting
            if (errno == EINPROGRESS || errno == EALREADY)
                return true;

            // Otherwise something is wrong with the socket
            logger(LOG_ERR, "connect: %s: %s", c->addrw, strerror(errno));
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
static void oshd_add_client(client_t *c)
{
    aio_event_t base_event;

    // Initialize the event's constants
    base_event.fd = c->fd;
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
bool oshd_connect_queue(endpoint_group_t *endpoints, time_t delay)
{
    client_t *c;
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
        client_reconnect_endpoints_next(endpoints, delay);
        return false;
    }

    // The socket was created successfully, we can initialize some of the
    // client's socket information
    netaddr_pton(&naddr, d_addr);
    c = client_init(client_fd, true, &naddr, endpoint->port);
    client_reconnect_to(c, endpoints, delay);
    memcpy(&c->sin, &d_sin, sizeof(d_sin));

    // Set all the socket options
    oshd_setsockopts(client_fd);

    oshd_add_client(c);

    if (endpoints->has_owner) {
        logger(LOG_INFO, "Trying to connect to %s at %s...",
            endpoints->owner_name, c->addrw);
    } else {
        logger(LOG_INFO, "Trying to connect to %s...", c->addrw);
    }
    return oshd_connect_async(c);
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

    client_t *c;
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

    // Initialize the client we the newly created socket
    c = client_init(client_fd, false, &addr, port);
    c->connected = true;

    logger(LOG_INFO, "Accepted connection from %s", c->addrw);
    oshd_add_client(c);
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
