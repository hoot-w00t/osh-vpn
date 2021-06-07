#include "oshd.h"
#include "oshd_device.h"
#include "oshd_route.h"
#include "oshd_socket.h"
#include "events.h"
#include "netpacket.h"
#include "tcp.h"
#include "logger.h"
#include "crypto/sha3.h"
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

    if (client_fd < 0) {
        event_queue_connect(address, port, delay * 2, delay);
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
        event_queue_connect(address, port, delay * 2, delay);
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
    oshpacket_hdr_t *pkt = (oshpacket_hdr_t *) node->io.recvbuf;

recv_again:
    recvd_size = recv(node->fd, node->io.recvbuf + node->io.recv_bytes,
        node->io.recv_packet_size - node->io.recv_bytes, MSG_NOSIGNAL);

    if (recvd_size > 0) {
        logger_debug(DBG_SOCKETS, "%s: Received %zi bytes", node->addrw, recvd_size);
        node->io.recv_bytes += recvd_size;
        if (!node->io.recvd_hdr) {
            if (node->io.recv_bytes >= OSHPACKET_PUBLIC_HDR_SIZE) {
                // If the magic number is invalid something is wrong
                if (pkt->magic != OSHPACKET_MAGIC) {
                    logger(LOG_ERR, "%s: Received invalid magic number 0x%X",
                        node->addrw, pkt->magic);
                    event_queue_node_remove(node);
                    return false;
                }

                // Switch payload size to host byte order
                pkt->payload_size = ntohs(pkt->payload_size);

                node->io.recv_packet_size = OSHPACKET_HDR_SIZE + pkt->payload_size;
                if (node->io.recv_packet_size <= OSHPACKET_PUBLIC_HDR_SIZE || node->io.recv_packet_size > OSHPACKET_MAXSIZE) {
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
            node->io.recv_packet_size = OSHPACKET_PUBLIC_HDR_SIZE;
            node->io.recv_bytes = 0;
        }
    } else if (recvd_size < 0) {
        // There is no more data ready to be received on the socket, return
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return true;

        logger(LOG_ERR, "%s: recv: %s", node->addrw, strerror(errno));
        event_queue_node_remove(node);
        return false;
    }
    goto recv_again;
}

// Iterate through all edges in *payload and add/delete them
static bool oshd_process_edge(node_t *node, oshpacket_hdr_t *pkt,
    oshpacket_edge_t *payload, bool add)
{
    char *action_name = add ? "Add" : "Delete";
    void (*action)(node_id_t *, node_id_t *) = add ? &node_id_add_edge
                                                   : &node_id_del_edge;

    const size_t entries = pkt->payload_size / sizeof(oshpacket_edge_t);
    char src_name[NODE_NAME_SIZE + 1];
    char dest_name[NODE_NAME_SIZE + 1];
    node_id_t *src;
    node_id_t *dest;

    memset(src_name, 0, sizeof(src_name));
    memset(dest_name, 0, sizeof(dest_name));
    for (size_t i = 0; i < entries; ++i) {
        memcpy(src_name, payload[i].src_node, NODE_NAME_SIZE);
        memcpy(dest_name, payload[i].dest_node, NODE_NAME_SIZE);

        if (!node_valid_name(src_name) || !node_valid_name(dest_name)) {
            logger(LOG_ERR, "%s: %s: %s edge: Invalid edge names", node->addrw,
                node->id->name, action_name);
            return false;
        }
        src = node_id_add(src_name);
        dest = node_id_add(dest_name);

        logger_debug(DBG_NODETREE, "%s: %s: %s edge: %s <=> %s", node->addrw,
            node->id->name, action_name, src_name, dest_name);
        action(src, dest);
    }
    return true;
}

// Iterate through all routes in *payload and add them
static bool oshd_process_route(node_t *node, oshpacket_hdr_t *pkt,
    oshpacket_route_t *payload, node_id_t *src_node)
{
    const size_t entries = pkt->payload_size / sizeof(oshpacket_route_t);
    netaddr_t addr;

    for (size_t i = 0; i < entries; ++i) {
        addr.type = payload[i].addr_type;
        if (addr.type > IP6) {
            logger(LOG_ERR, "%s: %s: Invalid ROUTE_ADD address type",
                node->addrw, node->id->name);
            return false;
        }
        memcpy(addr.data, payload[i].addr_data, 16);
        oshd_route_add(&addr, src_node);
    }
    return true;
}

// Process HELLO packet to authenticate a node
static bool oshd_process_hello(node_t *node, oshpacket_hdr_t *pkt,
    oshpacket_hello_t *payload)
{
    if (pkt->payload_size != sizeof(oshpacket_hello_t)) {
        logger(LOG_ERR, "%s: Invalid HELLO size: %u bytes", node->addrw,
            pkt->payload_size);
        return false;
    }

    char name[NODE_NAME_SIZE + 1];
    memset(name, 0, sizeof(name));
    memcpy(name, payload->node_name, NODE_NAME_SIZE);

    if (!node_valid_name(name)) {
        logger(LOG_ERR, "%s: Authentication failed: Invalid name", node->addrw);
        return false;
    }

    node_id_t *id = node_id_add(name);

    if (id->local_node) {
        // Disconnect the current socket if node tries to authenticate
        // as our local node
        logger(LOG_ERR, "%s: Authentication failed: Tried to authenticate as myself",
            node->addrw);
        return node_queue_goodbye(node);
    }

    if (!id->pubkey) {
        // If we don't have a public key to verify the HELLO signature,
        // we can't authenticate the node
        logger(LOG_ERR, "%s: Authentication failed: No public key for %s",
            node->addrw, name);
        return node_queue_goodbye(node);
    }

    // If the public key is local we will always use it, but if it is a remote
    // key and remote authentication is not authorized then we can't
    // authenticate the node
    if (!id->pubkey_local && !oshd.remote_auth) {
        logger(LOG_ERR, "%s: Authentication failed: No local public key for %s",
            node->addrw, name);
        return node_queue_goodbye(node);
    }

    logger_debug(DBG_AUTHENTICATION, "%s: Authentication: %s has a %s public key",
        node->addrw, name, id->pubkey_local ? "local" : "remote");

    // If the signature verification succeeds then the node is authenticated
    logger_debug(DBG_AUTHENTICATION, "%s: Authentication: Verifying signature from %s",
        node->addrw, id->name);
    node->authenticated = pkey_verify(id->pubkey, (uint8_t *) payload,
        sizeof(oshpacket_hello_t) - sizeof(payload->sig), payload->sig,
        sizeof(payload->sig));

    // If the node is not authenticated, the signature verification failed
    // The remote node did not sign the data using the private key
    // associated with the public key we have
    if (!node->authenticated) {
        logger(LOG_ERR, "%s: Authentication failed: Failed to verify signature from %s",
            node->addrw, name);
        return node_queue_goodbye(node);
    }

    if (id->node_socket) {
        // Disconnect the current socket if node is already authenticated
        logger(LOG_WARN, "%s: Another socket is already authenticated as %s",
            node->addrw, name);

        // This node should not be used
        node->authenticated = false;

        // If the node has a reconnection we will disable it to prevent
        // duplicate connections (which will also be refused by the remote node)
        if (node->reconnect_addr) {
            // If the other authenticated socket does not have a reconnection
            // set, we can set it to this node's
            if (!id->node_socket->reconnect_addr) {
                logger(LOG_INFO, "%s: Moving reconnection to %s:%u to %s (%s)",
                    node->addrw, node->reconnect_addr, node->reconnect_port,
                    id->name, id->node_socket->addrw);
                node_reconnect_to(id->node_socket, node->reconnect_addr,
                    node->reconnect_port, node->reconnect_delay);
            } else {
                // TODO: Add a way to try reconnecting to multiple addresses
                logger(LOG_INFO, "%s: Disabling reconnection for %s:%u",
                    node->addrw, node->reconnect_addr, node->reconnect_port);
            }
            node_reconnect_disable(node);
        }
        return node_queue_goodbye(node);
    }

    node_id_t *me = node_id_find_local();

    // The remote node is now authenticated

    id->node_socket = node;
    node->id = id;

    node_id_add_edge(me, id);
    node_tree_update();

    logger(LOG_INFO, "%s: %s: Authenticated successfully", node->addrw,
        node->id->name);

    if (!node_queue_edge_exg(node))
        return false;
    if (!node_queue_edge_broadcast(node, EDGE_ADD, oshd.name, name))
        return false;
    return node_queue_ping(node);
}

static bool oshd_process_handshake(node_t *node, oshpacket_hdr_t *pkt,
    oshpacket_handshake_t *payload)
{
    if (pkt->payload_size != sizeof(oshpacket_handshake_t)) {
        logger(LOG_ERR, "%s: Invalid HANDSHAKE size: %u bytes", node->addrw,
            pkt->payload_size);
        return false;
    }

    // If we did not initiate this request then we have to reply with our own
    // handshake
    if (!node->handshake_initiator) {
        if (!node_queue_handshake(node, false))
            return false;
    }

    // Load the remote node's public keys
    logger_debug(DBG_HANDSHAKE, "%s: Handshake: Loading the remote node's public keys", node->addrw);
    EVP_PKEY *r_send_pubkey = pkey_load_x25519_pubkey(payload->send_pubkey,
        sizeof(payload->send_pubkey));
    EVP_PKEY *r_recv_pubkey = pkey_load_x25519_pubkey(payload->recv_pubkey,
        sizeof(payload->recv_pubkey));

    if (!r_send_pubkey || !r_recv_pubkey) {
        pkey_free(r_send_pubkey);
        pkey_free(r_recv_pubkey);
        logger(LOG_ERR, "%s: Handshake failed: Failed to load public keys", node->addrw);
        return false;
    }

    // Calculate the shared secret for both keys
    // Each node sends its own send_pubkey and recv_pubkey, so in order to link
    // them correctly we need to calculate our own send key with the other
    // node's recv key, the same applies for our recv key
    uint8_t *send_secret;
    uint8_t *recv_secret;
    size_t send_secret_size;
    size_t recv_secret_size;
    bool secret_success = true;

    logger_debug(DBG_HANDSHAKE, "%s: Handshake: Computing send_secret", node->addrw);
    if (pkey_derive(node->send_key, r_recv_pubkey, &send_secret, &send_secret_size)) {
        logger_debug(DBG_HANDSHAKE, "%s: Handshake: Computing recv_secret", node->addrw);
        if (!pkey_derive(node->recv_key, r_send_pubkey, &recv_secret, &recv_secret_size)) {
            secret_success = false;
            free(send_secret);
        }
    } else {
        secret_success = false;
    }

    // We don't need the remote node's public keys now
    pkey_free(r_send_pubkey);
    pkey_free(r_recv_pubkey);

    // All the above if statements are here to prevent memory leaks
    if (!secret_success) {
        logger(LOG_ERR, "%s: Handshake failed: Failed to compute secrets", node->addrw);
        return false;
    }

    // We now calculate the SHA3-512 hashes of the two secrets which we will use
    // to create the keys and IV of our ciphers
    uint8_t send_hash[EVP_MAX_MD_SIZE];
    uint8_t recv_hash[EVP_MAX_MD_SIZE];
    unsigned int send_hash_size;
    unsigned int recv_hash_size;

    logger_debug(DBG_HANDSHAKE, "%s: Handshake: Hashing shared secrets", node->addrw);
    if (   !sha3_512_hash(send_secret, send_secret_size, send_hash, &send_hash_size)
        || !sha3_512_hash(recv_secret, recv_secret_size, recv_hash, &recv_hash_size))
    {
        free(send_secret);
        free(recv_secret);
        logger(LOG_ERR, "%s: Handshake failed: Failed to hash secrets", node->addrw);
        return false;
    }
    free(send_secret);
    free(recv_secret);

    // We can now create our send/recv ciphers using the two hashes
    logger_debug(DBG_HANDSHAKE, "%s: Handshake: Creating send_cipher", node->addrw);
    node->send_cipher = cipher_create_aes_256_ctr(true, send_hash, 32, send_hash + 32, 16);
    logger_debug(DBG_HANDSHAKE, "%s: Handshake: Creating recv_cipher", node->addrw);
    node->recv_cipher = cipher_create_aes_256_ctr(false, recv_hash, 32, recv_hash + 32, 16);

    if (!node->send_cipher || !node->recv_cipher) {
        logger(LOG_ERR, "%s: Handshake failed: Failed to create ciphers", node->addrw);
        return false;
    }

    // Reset the handshake initiator now that the handshake process is done
    node->handshake_initiator = false;

    // We were able to create ciphers to encrypt traffic, so we can
    // proceed to the authentication part, if the node is not yet authenticated
    if (!node->authenticated)
        return node_queue_hello(node);
    return true;
}

// Process a packet from a node that is not authenticated yet
static bool oshd_process_unauthenticated(node_t *node, oshpacket_hdr_t *pkt,
    uint8_t *payload)
{
    switch (pkt->type) {
        case HELLO:
            return oshd_process_hello(node, pkt, (oshpacket_hello_t *) payload);

        case HANDSHAKE:
            return oshd_process_handshake(node, pkt, (oshpacket_handshake_t *) payload);

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

        case HANDSHAKE:
            logger(LOG_ERR, "%s: %s: Handshake after authentication is not supported",
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
            logger_debug(DBG_SOCKETS, "%s: %s: RTT %ims", node->addrw,
                node->id->name, node->rtt);

            return true;

        case EDGE_EXG:
        case EDGE_ADD:
        case EDGE_DEL: {
            if (    pkt->payload_size < sizeof(oshpacket_edge_t)
                || (pkt->payload_size % sizeof(oshpacket_edge_t)) != 0)
            {
                logger(LOG_ERR, "%s: %s: Invalid %s size: %u bytes",
                    node->addrw, node->id->name, oshpacket_type_name(pkt->type),
                    pkt->payload_size);
                return false;
            }

            bool success;

            if (pkt->type == EDGE_EXG) {
                // TODO: Only do it if our map doesn't share any edge with the
                //       remote node's map
                // Broadcast remote node's edges to our end of the network
                node_queue_packet_broadcast(node, EDGE_ADD, payload,
                    pkt->payload_size);

                success = oshd_process_edge(node, pkt,
                    (oshpacket_edge_t *) payload, true);
            } else if (pkt->type == EDGE_ADD) {
                success = oshd_process_edge(node, pkt,
                    (oshpacket_edge_t *) payload, true);
            } else {
                success = oshd_process_edge(node, pkt,
                    (oshpacket_edge_t *) payload, false);
            }
            node_tree_update();

            // Make sure that all nodes's routing tables are up to date with our
            // local routes
            node_queue_route_add_broadcast(NULL, oshd.local_routes,
                oshd.local_routes_count);
            return success;
        }

        case ROUTE_ADD: {
            if (    pkt->payload_size < sizeof(oshpacket_route_t)
                || (pkt->payload_size % sizeof(oshpacket_route_t)) != 0)
            {
                logger(LOG_ERR, "%s: %s: Invalid ROUTE_ADD size: %u bytes",
                    node->addrw, node->id->name, pkt->payload_size);
                return false;
            }
            return oshd_process_route(node, pkt, (oshpacket_route_t *) payload,
                    src_node);
        }

        case DATA: {
            if (!oshd.tuntap_used)
                return true;

            netpacket_t netpkt;
            char netpkt_src[INET6_ADDRSTRLEN];
            char netpkt_dest[INET6_ADDRSTRLEN];

            if (!netpacket_from_data(&netpkt, payload, oshd.is_tap)) {
                logger(LOG_ERR, "%s: %s: Failed to decode received tunnel packet",
                    node->addrw, node->id->name);
                return false;
            }

            netaddr_ntop(netpkt_src, sizeof(netpkt_src), &netpkt.src);
            netaddr_ntop(netpkt_dest, sizeof(netpkt_dest), &netpkt.dest);

            logger_debug(DBG_TUNTAP, "%s: %s: %s <- %s (%u bytes, from %s)",
                node->addrw, node->id->name, netpkt_dest, netpkt_src,
                pkt->payload_size, src_node->name);

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

    // If we have a recv_cipher, the private header and payload are encrypted,
    // so we need to decrypt it before we can process the data
    if (node->recv_cipher) {
        const size_t encrypted_size = OSHPACKET_PRIVATE_HDR_SIZE + pkt->payload_size;
        size_t decrypted_size;

        logger_debug(DBG_ENCRYPTION, "%s: Decrypting packet of %zu bytes",
            node->addrw, encrypted_size);

        // We decrypt packet at the same location because overlapping streams
        // are supported for AES-256-CTR
        // TODO: If the cipher does not support this, decrypt in a temporary
        //       buffer and then copy the decrypted data back in the recvbuf
        if (!cipher_decrypt(node->recv_cipher,
                ((uint8_t *) pkt) + OSHPACKET_PUBLIC_HDR_SIZE, &decrypted_size,
                ((uint8_t *) pkt) + OSHPACKET_PUBLIC_HDR_SIZE, encrypted_size))
        {
            logger(LOG_ERR, "%s: Failed to decrypt packet", node->addrw);
            return false;
        }

        // TODO: If the cipher pads data, this will create errors
        if (decrypted_size != encrypted_size) {
            logger(LOG_ERR, "%s: Decrypted packet has a different size (encrypted: %zu, decrypted: %zu)",
                node->addrw, encrypted_size, decrypted_size);
            return false;
        }
    }

    // Retrieve the packet's counter value
    pkt->counter = ntohl(pkt->counter);

    // Verify that the remote node's send_counter matches our recv_counter
    // This is to prevent replay attacks
    // If the counter is not correct then we drop the connection
    if (node->recv_counter != pkt->counter) {
        logger(LOG_CRIT, "%s: Invalid counter: Expected %u but got %u",
            node->addrw, node->recv_counter, pkt->counter);
        return false;
    }

    // The counter is correct, increment it for the next packet
    node->recv_counter += 1;

    // If the node is unauthenticated we only accept authentication packets,
    // nothing else will be accepted or forwarded, if the authentication encounters
    // an error the connection is terminated
    if (!node->authenticated)
        return oshd_process_unauthenticated(node, pkt, payload);

    // If the source or destination nodes don't exist in the tree the remote
    // node sent us invalid data, we drop the connection
    node_id_t *src = node_id_find(pkt->src_node);
    if (!src) {
        logger(LOG_ERR, "%s: %s: Unknown source node", node->addrw, node->id->name);
        return false;
    }

    node_id_t *dest = node_id_find(pkt->dest_node);
    if (!dest) {
        logger(LOG_ERR, "%s: %s: Unknown destination node", node->addrw, node->id->name);
        return false;
    }

    // If the destination node is not the local node we'll forward this packet
    if (!dest->local_node) {
        if (pkt->type <= PONG) {
            logger(LOG_WARN, "Dropping %s packet from %s to %s: This type of packet cannot be forwarded",
                oshpacket_type_name(pkt->type), src->name, dest->name);
            return true;
        }

        if (dest) {
            if (dest->next_hop) {
                logger_debug(DBG_ROUTING, "Forwarding %s packet from %s to %s through %s",
                    oshpacket_type_name(pkt->type), src->name, dest->name, dest->next_hop->id->name);
                node_queue_packet_forward(dest->next_hop, pkt);
            } else {
                logger(LOG_INFO, "Dropping %s packet from %s to %s: No route",
                    oshpacket_type_name(pkt->type), src->name, dest->name);
            }
        } else {
            logger(LOG_WARN, "Dropping %s packet from %s to %s: Unknown destination",
                oshpacket_type_name(pkt->type), src->name, dest->name);
        }
        return true;
    }

    // Otherwise the packet is for us
    return oshd_process_authenticated(node, pkt, payload, src);
}