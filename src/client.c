#include "client.h"
#include "oshd.h"
#include "logger.h"
#include "events.h"
#include "random.h"
#include "xalloc.h"
#include "macros_assert.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

// Gracefully disconnect a client, sets the finish_and_disconnect flag to
// disconnect the client automatically after the send queue is emptied
// Disables AIO_READ from the poll_events to ignore all incoming packets
void client_graceful_disconnect(client_t *c)
{
    c->finish_and_disconnect = true;
    aio_disable_poll_events(c->aio_event, AIO_READ);
}

// Find a matching endpoint in the group and delete it if it is ephemeral
// Does nothing if *endpoint is NULL
static void cleanup_ephemeral_endpoint(endpoint_group_t *group, const endpoint_t *endpoint)
{
    endpoint_t *result;

    if (!endpoint)
        return;

    result = endpoint_group_find(group, endpoint);
    if (result && (result->flags & ENDPOINT_FLAG_EPHEMERAL))
        endpoint_group_del(group, result);
}

// Cleanup ephemeral endpoint from the authenticated node's known endpoints
static void cleanup_ephemeral_remote_endpoint(client_t *c, const endpoint_t *endpoint)
{
    if (c->authenticated)
        cleanup_ephemeral_endpoint(c->id->endpoints, endpoint);
}

// Cleanup ephemeral endpoint from our own known endpoints
static void cleanup_ephemeral_local_endpoint(const endpoint_t *endpoint)
{
    node_id_t *me = node_id_find_local();

    cleanup_ephemeral_endpoint(me->endpoints, endpoint);
}

// Disconnect client and removes the node from the node tree
static void client_disconnect(client_t *c)
{
    // If the client is authenticated we have to remove our connection to it
    // from the node tree
    if (c->authenticated) {
        // Cleanup discovered ephemeral endpoints
        cleanup_ephemeral_remote_endpoint(c, c->remote_endpoint);
        cleanup_ephemeral_local_endpoint(c->local_endpoint);
        cleanup_ephemeral_local_endpoint(c->external_endpoint);
        cleanup_ephemeral_remote_endpoint(c, c->internal_endpoint);

        // Remove the direct connection from this node
        if (node_id_unlink_client(c->id, c)) {
            node_id_t *me = node_id_find_local();

            // Delete the edge between our two nodes if the client was unlinked
            //
            // If it was not unlinked this means that another connection was
            // established with the node, so the edge still exists
            node_id_del_edge(me, c->id);
            node_tree_update();

            // Broadcast this change to the rest of the network
            client_queue_edge_broadcast(c, OSHPKT_EDGE_DEL, me->name, c->id->name);
        }
    }

    // Close the network socket
    if (c->sockfd != invalid_sock_t) {
        logger(LOG_INFO, "Disconnecting %s", c->addrw);

        // Only close the socket if the AIO event is enabled
        // Otherwise the socket is shared with other events and must not be
        // released here
        if (aio_event_is_enabled(c->aio_event)) {
            logger_debug(DBG_SOCKETS, "%s: Closing socket " PRI_SOCK_T,
                c->addrw, c->sockfd);

            if (sock_shutdown(c->sockfd, sock_shut_rdwr) < 0) {
                logger_debug(DBG_SOCKETS, "%s: %s(" PRI_SOCK_T "): %s",
                    c->addrw, "sock_shutdown", c->sockfd, sock_strerror(sock_errno));
            }

            if (sock_close(c->sockfd) < 0) {
                logger(LOG_ERR, "%s: %s(" PRI_SOCK_T "): %s",
                    c->addrw, "sock_close", c->sockfd, sock_strerror(sock_errno));
            }
        }

        c->sockfd = invalid_sock_t;
    } else {
        logger(LOG_WARN, "%s: Already disconnected", c->addrw);
    }

    // If the client has a reconnection node, either try reconnecting or keep on
    // trying to connect
    if (c->reconnect_nid) {
        if (node_connect_in_progress(c->reconnect_nid)) {
            node_connect_continue(c->reconnect_nid);
        } else {
            node_connect(c->reconnect_nid, false);
        }
    }
}

// Free all ECDH keys and ciphers and reset their values to NULL
static void client_reset_ciphers(client_t *c)
{
    pkey_free(c->ecdh_key);
    cipher_free(c->send_cipher);
    cipher_free(c->recv_cipher);
    cipher_free(c->recv_cipher_next);
    c->ecdh_key = NULL;
    c->send_cipher = NULL;
    c->recv_cipher = NULL;
    c->recv_cipher_next = NULL;
}

// Generate a pseudo-random addrw
// The returned buffer is dynamically allocated and must be freed
static char *client_generate_unknown_addrw(void)
{
    char addrw[32];

    snprintf(addrw, sizeof(addrw), "[unknown-%" PRIX64 "]",
        random_xoshiro256() % 0x10000);
    return xstrdup(addrw);
}

// Update the client's local socket address
// c->remote_sa must be initialized and valid for connectionless sockets
static void client_update_local_sockaddr(client_t *c)
{
    socklen_t len = sizeof(c->local_sa);

    memset(&c->local_sa, 0, sizeof(c->local_sa));

    // If the client is not connected yet the local address is still unknown
    // We have to handle it here because sock_getsockname() can succeed but
    // return an invalid address
    if (!c->connected) {
        c->local_sa.ss_family = AF_UNSPEC;
        return;
    }

    if (sock_getsockname(c->sockfd, (struct sockaddr *) &c->local_sa, &len) != 0) {
        logger(LOG_ERR, "%s: %s: %s", __func__, "sock_getsockname", sock_strerror(sock_errno));
        c->local_sa.ss_family = AF_UNSPEC;
    }
}

// Set the client's remote socket address, endpoint and format addrw for logging
// Also sets the client's local socket address (if possible)
// If *sa is NULL the remote socket address stays the same (along with its
// endpoint and *addrw)
static void client_set_endpoint(client_t *c, const struct sockaddr_storage *sa,
    const endpoint_proto_t proto)
{
    const endpoint_flags_t common_flags = ENDPOINT_FLAG_CAN_EXPIRE | ENDPOINT_FLAG_EXPIRY_LOCAL;
    endpoint_flags_t remote_flags = common_flags | ENDPOINT_FLAG_EXTERNAL;
    endpoint_flags_t local_flags = common_flags | ENDPOINT_FLAG_INTERNAL;

    // We assume that the remote endpoint is ephemeral, the remote node will
    // rectify this if needed
    // Our local endpoint is ephemeral if the socket does not accept incoming
    // connections (if we are the initiator)
    remote_flags |= ENDPOINT_FLAG_EPHEMERAL;
    if (c->initiator)
        local_flags |= ENDPOINT_FLAG_EPHEMERAL;

    // Update remote and local socket addresses
    c->sa_proto = proto;
    if (sa != NULL && sa != &c->remote_sa) // Don't pass NULL or overlapping pointer to memcpy()
        memcpy(&c->remote_sa, sa, sizeof(c->remote_sa));
    client_update_local_sockaddr(c);

    // Try to create remote endpoint and create addrw (if it changed)
    if (sa != NULL) {
        cleanup_ephemeral_remote_endpoint(c, c->remote_endpoint);
        endpoint_free(c->remote_endpoint);
        free(c->addrw);

        c->remote_endpoint = endpoint_from_sockaddr((const struct sockaddr *) &c->remote_sa,
            sizeof(c->remote_sa), proto, remote_flags);
        if (c->remote_endpoint) {
            c->addrw = xstrdup(c->remote_endpoint->addrstr);
        } else {
            // This should never happen
            logger(LOG_CRIT, "%s: %s: %s", __func__, "endpoint_from_sockaddr",
                "Failed to create remote endpoint");
            c->addrw = client_generate_unknown_addrw();
        }
    }

    // Try to create local endpoint
    cleanup_ephemeral_local_endpoint(c->local_endpoint);
    endpoint_free(c->local_endpoint);

    if (c->local_sa.ss_family == AF_UNSPEC) {
        c->local_endpoint = NULL;
    } else {
        c->local_endpoint = endpoint_from_sockaddr((const struct sockaddr *) &c->local_sa,
            sizeof(c->local_sa), proto, local_flags);
        if (!c->local_endpoint) {
            logger(LOG_CRIT, "%s: %s: %s", __func__, "endpoint_from_sockaddr",
                "Failed to create local endpoint");
        }
    }

    // Announce the socket endpoints
    client_share_endpoints(c);
}

// Set the client endpoint to the same socket address to update the local socket
// address/endpoint (needed when a creating a client before the socket is connected)
void client_update_endpoint(client_t *c)
{
    client_set_endpoint(c, NULL, c->sa_proto);
}

// Change the client's existing remote socket address/endpoint and log it
void client_change_endpoint(client_t *c, const struct sockaddr_storage *sa,
    const endpoint_proto_t proto)
{
    char *previous_addrw = xstrdup(c->addrw);

    client_set_endpoint(c, sa, proto);
    logger(LOG_INFO, "%s: Endpoint changed to %s", previous_addrw, c->addrw);
    free(previous_addrw);
}

// Add discovered endpoint and announce it
static void client_share_endpoint(client_t *c, node_id_t *owner,
    const endpoint_t *endpoint)
{
    endpoint_t *inserted;

    if (!endpoint)
        return;

    endpoint_group_insert_sorted(owner->endpoints, endpoint, &inserted);
    if (c->authenticated)
        client_queue_endpoint_disc(c, endpoint, owner);

    // Ephemeral endpoints are not announced to all nodes because they are most
    // likely unreachable or irrelevant
    if (!(inserted->flags & ENDPOINT_FLAG_EPHEMERAL) && oshd.shareendpoints)
        client_queue_endpoint(NULL, inserted, owner, true);
}

// Add the client's socket endpoints to their owners' known endpoints
// This also announces the endpoints to other nodes if ShareEndpoints is enabled
void client_share_endpoints(client_t *c)
{
    node_id_t *me = node_id_find_local();

    client_share_endpoint(c, me, c->local_endpoint);
    if (c->authenticated)
        client_share_endpoint(c, c->id, c->remote_endpoint);
}

// Set the client's external endpoint
void client_set_external_endpoint(client_t *c, const endpoint_t *endpoint)
{
    if (!c->authenticated)
        return;

    cleanup_ephemeral_local_endpoint(c->external_endpoint);
    endpoint_free(c->external_endpoint);
    c->external_endpoint = endpoint_dup(endpoint);

    logger_debug(DBG_ENDPOINTS, "%s: %s: Set %s endpoint to %s",
        c->addrw, c->id->name, "external", c->external_endpoint->addrstr);

    if (c->local_endpoint) {
        // If our external endpoint is not the same type as the local endpoint
        // there is an address family translation
        // External/remote endpoints are probably not reachable for other nodes
        if (c->local_endpoint->type != c->external_endpoint->type) {
            logger_debug(DBG_ENDPOINTS, "%s: %s: AFT %s <-> %s",
                c->addrw, c->id->name,
                endpoint_type_name(c->local_endpoint->type),
                endpoint_type_name(c->external_endpoint->type));
            return;
        }

        // The external endpoint is tied to our local endpoint, so it should
        // have the same ephemeral flag
        // We rectify it if it's not the case
        const endpoint_flags_t correct_flags = (c->external_endpoint->flags & ~(ENDPOINT_FLAG_EPHEMERAL))
                                             | (c->local_endpoint->flags & ENDPOINT_FLAG_EPHEMERAL);

        if (c->external_endpoint->flags != correct_flags) {
            node_id_t *me = node_id_find_local();
            endpoint_t *inserted;

            logger_debug(DBG_ENDPOINTS,
                "%s: %s: Rectifying external endpoint %s (is %sephemeral)",
                c->addrw,
                c->id->name,
                c->external_endpoint->addrstr,
                (correct_flags & ENDPOINT_FLAG_EPHEMERAL) ? "" : "not ");

            endpoint_set_flags(NULL, c->external_endpoint, correct_flags);
            endpoint_group_insert_sorted(me->endpoints, c->external_endpoint, &inserted);
            if (oshd.shareendpoints)
                client_queue_endpoint(NULL, inserted, me, true);
        }
    }
}

// Set the client's internal endpoint
void client_set_internal_endpoint(client_t *c, const endpoint_t *endpoint)
{
    if (!c->authenticated)
        return;

    cleanup_ephemeral_remote_endpoint(c, c->internal_endpoint);
    endpoint_free(c->internal_endpoint);
    c->internal_endpoint = endpoint_dup(endpoint);

    logger_debug(DBG_ENDPOINTS, "%s: %s: Set %s endpoint to %s",
        c->addrw, c->id->name, "internal", c->internal_endpoint->addrstr);
}

// Disconnect and free a client
void client_destroy(client_t *c)
{
    // Cancel any events linked to this client
    event_cancel(c->handshake_renew_event);
    event_cancel(c->handshake_timeout_event);
    event_cancel(c->keepalive_event);

    client_disconnect(c);

    free(c->handshake_sig_data);
    free(c->io.recvbuf);

    netbuffer_free(c->io.sendq);
    client_reset_ciphers(c);

    endpoint_free(c->remote_endpoint);
    endpoint_free(c->local_endpoint);
    endpoint_free(c->external_endpoint);
    endpoint_free(c->internal_endpoint);
    free(c->addrw);
    free(c);
}

// Create and initialize a new client
client_t *client_init(sock_t sockfd, bool initiator,
    const struct sockaddr_storage *sa, const endpoint_proto_t proto)
{
    client_t *c = xzalloc(sizeof(client_t));

    c->sockfd = sockfd;
    c->initiator = initiator;

    // Set the client's socket address, endpoint and format addrw
    client_set_endpoint(c, sa, proto);

    // Initialize network buffers
    c->io.recvbuf = xalloc(CLIENT_RECVBUF_SIZE);
    c->io.sendq = netbuffer_create(CLIENT_SENDQ_MIN_SIZE, CLIENT_SENDQ_ALIGNMENT);

    // Queue the handshake timeout event
    // This event will terminate the connection if the authentication did not
    // succeed
    event_queue_handshake_timeout(c, HANDSHAKE_TIMEOUT);

    // Probe the other node to know if the connection is still alive
    client_set_keepalive(c, HANDSHAKE_TIMEOUT, HANDSHAKE_TIMEOUT);
    event_queue_keepalive(c, EVENT_QUEUE_NOW);

    return c;
}

// Set the client's connected state
void client_set_connected(client_t *c, bool connected)
{
    c->connected = connected;
    if (connected)
        client_update_endpoint(c);
}

// Set client connection timeout and keepalive interval
void client_set_keepalive(client_t *c, time_t interval, time_t timeout)
{
    c->keepalive_interval = interval;
    c->keepalive_timeout = timeout;
}

// Set the node to which this client should try to reconnect to
// If *nid is NULL reconnection will be disabled
void client_reconnect_to(client_t *c, node_id_t *nid)
{
    c->reconnect_nid = nid;
}

// Mark the client's handshake as finished, this resets all variables used
// during the handshake
void client_finish_handshake(client_t *c)
{
    if (c->handshake_in_progress)
        logger_debug(DBG_HANDSHAKE, "%s: Handshake finished", c->addrw);

    c->handshake_in_progress = false;
    c->handshake_id = NULL;
    c->handshake_valid_signature = false;
    free(c->handshake_sig_data);
    c->handshake_sig_data = NULL;
    c->handshake_sig_data_complete = false;
    if (c->recv_cipher_next) {
        logger(LOG_CRIT,
            "%s: Handshake finished but recv_cipher_next was not used",
            c->addrw);
    }
}

// Encrypt packet using the client's send cipher
bool client_encrypt_packet(client_t *c, oshpacket_t *pkt)
{
    size_t result;

    // If there is no cipher, the encryption operation is considered failed
    if (!c->send_cipher) {
        logger(LOG_ERR, "%s: Failed to encrypt packet seqno %" PRIu64 ": %s",
            c->addrw, pkt->seqno, "No send cipher");
        return false;
    }

    logger_debug(DBG_ENCRYPTION, "%s: Encrypting packet seqno %" PRIu64 " of %zu bytes",
        c->addrw, pkt->seqno, pkt->encrypted_size);

    // We encrypt the packet at the same location because we are using a
    // streaming cipher
    if (!cipher_encrypt(c->send_cipher,
            pkt->encrypted, &result,
            pkt->encrypted, pkt->encrypted_size,
            pkt->cipher_tag, pkt->seqno))
    {
        logger(LOG_ERR, "%s: Failed to encrypt packet seqno %" PRIu64, c->addrw, pkt->seqno);
        return false;
    }

    // Make sure that the packet size is the same
    if (result != pkt->encrypted_size) {
        logger(LOG_ERR,
            "%s: Encrypted packet seqno %" PRIu64 " has a different size (expected: %zu, actual: %zu)",
            c->addrw, pkt->seqno, pkt->encrypted_size, result);
        return false;
    }

    return true;
}

// Decrypt packet using the client's receive cipher
bool client_decrypt_packet(client_t *c, oshpacket_t *pkt)
{
    size_t result;

    // If there is no cipher, consider the decryption operation successful
    if (!c->recv_cipher)
        return true;

    logger_debug(DBG_ENCRYPTION, "%s: Decrypting packet seqno %" PRIu64 " of %zu bytes",
        c->addrw, pkt->seqno, pkt->encrypted_size);

    // We decrypt the packet at the same location because we are using a
    // streaming cipher
    if (!cipher_decrypt(c->recv_cipher,
            pkt->encrypted, &result,
            pkt->encrypted, pkt->encrypted_size,
            pkt->cipher_tag, pkt->seqno))
    {
        logger(LOG_ERR, "%s: Failed to decrypt packet seqno %" PRIu64, c->addrw, pkt->seqno);
        return false;
    }

    // Make sure that the packet size is the same
    if (result != pkt->encrypted_size) {
        logger(LOG_ERR,
            "%s: Decrypted packet seqno %" PRIu64 " has a different size (encrypted: %zu, decrypted: %zu)",
            c->addrw, pkt->seqno, pkt->encrypted_size, result);
        return false;
    }

    return true;
}

// Queue management
// Returns true if the packet should be dropped (when the send queue is too
// full or filling up too fast)
static bool qm_packet_should_drop(const client_t *c)
{
    if (netbuffer_data_size(c->io.sendq) >= CLIENT_SENDQ_DATA_SIZE_MIN) {
        const size_t random_drop_above = rand() % CLIENT_SENDQ_DATA_SIZE_MAX;

        // Randomly drop packets with an increasing chance as the queue size
        // gets closer to the maximum.
        // When the queue size is at or above the maximum we drop every packet
        if (netbuffer_data_size(c->io.sendq) >= random_drop_above) {
            logger_debug(DBG_TUNTAP_TRAFFIC,
                "%s: Data packet should drop: queue at %zu/%i bytes (%zu%%, drop above: %zu)",
                c->addrw,
                netbuffer_data_size(c->io.sendq),
                CLIENT_SENDQ_DATA_SIZE_MAX,
                (netbuffer_data_size(c->io.sendq) * 100 / CLIENT_SENDQ_DATA_SIZE_MAX),
                random_drop_above);
            return true;
        }
    }
    return false;
}

// Initialize packet's oshpacket_hdr_t
static void packet_init_hdr(oshpacket_t *pkt, const oshpacket_hdr_t *src_hdr)
{
    // Initialize the public part of the header
    pkt->hdr->payload_size = htons(((uint16_t) pkt->payload_size));

    // Copy the private part of the header which was initialized by the caller
    memcpy(OSHPACKET_PRIVATE_HDR(pkt->hdr), OSHPACKET_PRIVATE_HDR_CONST(src_hdr),
        OSHPACKET_PRIVATE_HDR_SIZE);
}

// Initialize packet's payload
static void packet_init_payload(oshpacket_t *pkt, const void *payload,
    const size_t payload_size)
{
    assert(pkt->payload_size == payload_size); // redundant check
    memcpy(pkt->payload, payload, payload_size);
}

// Encrypt the packet if we can
// This returns false if the encryption failed or the packet can not be sent
// unencrypted
static bool packet_encrypt(client_t *c, oshpacket_t *pkt, const oshpacket_def_t *def)
{
    if (c->send_cipher) {
        // The socket has a send_cipher, so the packet will be encrypted
        return client_encrypt_packet(c, pkt);

    } else if (def->can_be_sent_unencrypted) {
        // The socket does not have a send cipher yet but the packet is allowed
        // to be sent unencrypted

        // Zero the source and destination as they will not be taken into
        // account yet; this prevents leaking the nodes' names in plain text
        memset(pkt->hdr->src_node, 0,
            sizeof(pkt->hdr->src_node));
        memset(&pkt->hdr->dest, 0,
            sizeof(pkt->hdr->dest));

        // Zero the authentication tag as there is no encryption
        memset(pkt->cipher_tag, 0, pkt->cipher_tag_size);

        return true;

    } else {
        // The socket does not have a send cipher yet and it cannot be sent
        // unencrypted, we drop it
        // This should never happen, if it does there is a bug in the code
        logger(LOG_CRIT, "%s: Cannot queue unencrypted %s packet",
            c->addrw, def->name);

        return false;
    }
}

// Actually queue a packet
// The private part of the header must be initialized before calling this
// function, but not the public part as it will be initialized here
// This function also takes care of dropping DATA packets when needed
// Returns false if the packet was not queued (for any error/reason)
//
// Warning: If the payload is NULL but the payload size is different than 0
//          there will be uninitialized bytes sent as the payload
bool client_queue_packet(client_t *c, const oshpacket_hdr_t *hdr,
    const void *payload, const size_t payload_size)
{
    const oshpacket_def_t *def = oshpacket_lookup(hdr->type);
    const size_t packet_size = OSHPACKET_CALC_SIZE(payload_size);
    uint8_t *slot;
    oshpacket_t pkt;

    // This should never happen
    if (!def) {
        logger(LOG_CRIT, "%s: %s", __func__, "Invalid packet type");
        return false;
    }

    // Drop packet if its size exceeds the limit
    if (packet_size > OSHPACKET_MAXSIZE) {
        logger(LOG_ERR,
            "%s: Dropping %s packet of %zu bytes (%s)", c->addrw,
            oshpacket_type_name(hdr->type), packet_size, "exceeds size limit");
        return false;
    }

    // Drop packet if the client is planned to disconnect
    if (c->finish_and_disconnect) {
        logger_debug(DBG_SOCKETS,
            "%s: Dropping %s packet of %zu bytes (%s)", c->addrw,
            oshpacket_type_name(hdr->type), packet_size, "goodbye");
        return false;
    }

    // Apply queue management for unreliable packets to limit network congestion
    if (!(def->is_reliable) && qm_packet_should_drop(c))
    {
        logger_debug(DBG_TUNTAP_TRAFFIC, "%s: Dropping %s packet of %zu bytes (%s)",
            c->addrw, oshpacket_type_name(hdr->type), payload_size, "qm");
        return false;
    }

    slot = netbuffer_reserve(c->io.sendq, packet_size);
    oshpacket_init(&pkt, slot, packet_size, c->send_seqno);

    // Initialize the packet header
    packet_init_hdr(&pkt, hdr);

    // Copy the packet's payload to the buffer (if there is one)
    if (payload)
        packet_init_payload(&pkt, payload, payload_size);

    // Try to encrypt the packet
    // Cancel the buffer if this fails
    if (!packet_encrypt(c, &pkt, def)) {
        netbuffer_cancel(c->io.sendq, packet_size);
        return false;
    }

    // The packet was queued successfully

    // Increment the send seqno for future packets
    c->send_seqno += 1;

    // Make sure to enable writing on the socket
    aio_enable_poll_events(c->aio_event, AIO_WRITE);

    return true;
}

// Initialize the packet header for a unicast
// Source/destination nodes are not initialized here
static void hdr_init_unicast(oshpacket_hdr_t *hdr, oshpacket_type_t type)
{
    hdr->type = type;
    hdr->flags = 0;
}

// Initialize the packet header for a broadcast
// Nothing else has to be initialized after calling this function
static void hdr_init_broadcast(oshpacket_hdr_t *hdr, oshpacket_type_t type)
{
    hdr->type = type;
    hdr->flags = 0;
    BIT_SET(hdr->flags, OSHPACKET_HDR_FLAG_BROADCAST);
    memcpy(hdr->src_node, oshd.name, NODE_NAME_SIZE);
    memset(&hdr->dest.broadcast, 0, sizeof(hdr->dest.broadcast));
    hdr->dest.broadcast.id = random_xoshiro256();
}

// Queue a unicast packet for a client (direct connection only)
bool client_queue_packet_direct(client_t *c, oshpacket_type_t type,
    const void *payload, size_t payload_size)
{
    oshpacket_hdr_t hdr;

    hdr_init_unicast(&hdr, type);

    // If the client is authenticated, set the source and destination nodes
    // Otherwise unauthenticated packets have those fields cleared out to
    // prevent leaking the nodes' names
    if (c->authenticated) {
        memcpy(hdr.src_node, oshd.name, NODE_NAME_SIZE);
        memcpy(hdr.dest.unicast.dest_node, c->id->name, NODE_NAME_SIZE);
    } else {
        memset(hdr.src_node, 0, sizeof(hdr.src_node));
        memset(&hdr.dest.unicast, 0, sizeof(hdr.dest.unicast));
    }

    return client_queue_packet(c, &hdr, payload, payload_size);
}

// Queue a unicast packet for a node (indirectly, using its next hop)
// The packet is dropped if there is no route to the destination
bool client_queue_packet_indirect(node_id_t *dest, oshpacket_type_t type,
    const void *payload, size_t payload_size)
{
    client_t *next_hop = node_id_next_hop(dest);
    oshpacket_hdr_t hdr;

    if (!next_hop) {
        logger(LOG_WARN, "Dropping %s packet for %s: No route",
            oshpacket_type_name(type), dest->name);
        return false;
    }

    hdr_init_unicast(&hdr, type);
    memcpy(hdr.src_node, oshd.name, NODE_NAME_SIZE);
    memcpy(hdr.dest.unicast.dest_node, dest->name, NODE_NAME_SIZE);
    return client_queue_packet(next_hop, &hdr, payload, payload_size);
}

// Broadcast a packet to all authenticated direct connections
// If exclude is not NULL the packet will not be queued for the excluded client
bool client_queue_packet_broadcast(client_t *exclude, oshpacket_type_t type,
    const void *payload, size_t payload_size)
{
    oshpacket_hdr_t hdr;

    hdr_init_broadcast(&hdr, type);
    logger_debug(DBG_SOCKETS,
        "Broadcasting %s packet of %zu bytes (id: %" PRI_BRD_ID ")",
        oshpacket_type_name(type), payload_size, hdr.dest.broadcast.id);

    for (size_t i = 0; i < oshd.clients_count; ++i) {
        if (   !oshd.clients[i]->authenticated
            ||  oshd.clients[i] == exclude)
        {
            continue;
        }

        client_queue_packet(oshd.clients[i], &hdr, payload, payload_size);
    }

    return true;
}

// Forward an existing broadcast packet to all authenticated direct connections
// excluding the source socket
// exclude must not be NULL
bool client_queue_packet_broadcast_forward(client_t *exclude, const oshpacket_hdr_t *hdr,
    const void *payload, size_t payload_size)
{
    logger_debug(DBG_SOCKETS,
        "Broadcasting %s packet of %zu bytes (id: %" PRI_BRD_ID ", from %s)",
        oshpacket_type_name(hdr->type), payload_size, hdr->dest.broadcast.id,
        exclude->addrw);

    for (size_t i = 0; i < oshd.clients_count; ++i) {
        if (   !oshd.clients[i]->authenticated
            ||  oshd.clients[i] == exclude)
        {
            continue;
        }

        client_queue_packet(oshd.clients[i], hdr, payload, payload_size);
    }

    return true;
}

// Queue a unicast DATA packet for a node (indirectly)
bool client_queue_packet_data(node_id_t *dest, const void *payload,
    const size_t payload_size)
{
    return client_queue_packet_indirect(dest, OSHPKT_DATA, payload, payload_size);
}

// Broadcast a DATA packet for all nodes (indirectly)
// This function uses client_queue_packet_data to unicast the same payload to
// all nodes (except *exclude if it is not NULL)
bool client_queue_packet_data_broadcast(node_id_t *exclude, const void *payload,
    const size_t payload_size)
{
    node_id_t *nid;

    for (size_t i = 1; i < oshd.node_tree_count; ++i) {
        nid = oshd.node_tree[i];
        if (!nid->online || nid == exclude)
            continue;

        client_queue_packet_data(nid, payload, payload_size);
    }

    return true;
}

// Queue a broadcast packet for a single client
// This function should only be used to exchange mesh states after authenticating
bool client_queue_packet_exg(client_t *c, oshpacket_type_t type,
    const void *payload, const size_t payload_size)
{
    oshpacket_hdr_t hdr;

    hdr_init_broadcast(&hdr, type);
    logger_debug(DBG_SOCKETS,
        "%s: %s: Queuing state exchange %s packet of %zu bytes (id: %" PRI_BRD_ID ")",
        c->addrw, c->id->name, oshpacket_type_name(type), payload_size,
        hdr.dest.broadcast.id);

    return client_queue_packet(c, &hdr, payload, payload_size);
}

// Queue packet with a fragmented payload
// If the payload size is bigger than OSHPACKET_PAYLOAD_MAXSIZE it will be
// fragmented and sent with multiple packets (as many as needed)
// This can only be used for repeating payloads, like edges and routes which
// are processed as a flat array
// If broadcast is true, c is a client to exclude from the broadcast (can be
// NULL)
// Otherwise the fragmented packet will be sent to c (it is expected to be
// authenticated)
static bool client_queue_packet_fragmented(
    client_t *c,
    oshpacket_type_t type,
    const void *payload,
    const size_t payload_size,
    const size_t entry_size,
    bool broadcast)
{
    const size_t max_entries = OSHPACKET_PAYLOAD_MAXSIZE / entry_size;
    size_t remaining_entries = payload_size / entry_size;
    const uint8_t *curr_buf = payload;

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
            logger_debug(DBG_SOCKETS,
                "Broadcasting fragmented %s packet with %zu entries (%zu bytes)",
                oshpacket_type_name(type), entries, size);

            if (!client_queue_packet_broadcast(c, type, curr_buf, size))
                return false;
        } else {
            logger_debug(DBG_SOCKETS,
                "%s: %s: Queuing fragmented %s packet with %zu entries (%zu bytes)",
                c->addrw, c->id->name, oshpacket_type_name(type), entries, size);

            if (!client_queue_packet_direct(c, type, curr_buf, size))
                return false;
        }

        // Iterate to the next entries
        remaining_entries -= entries;
        curr_buf += size;
    }

    return true;
}

// Generate ECDH keypair into *key (*key must be NULL)
// Export the public key to *pubkey
static bool handshake_generate_ecdh_key(const client_t *c, EVP_PKEY **key,
    uint8_t *pubkey, size_t pubkey_size)
{
    uint8_t *tmp_pubkey;
    size_t tmp_pubkey_size;

    // Generate the Curve25519 keypair
    *key = pkey_generate_x25519();
    if (*key == NULL)
        return false;

    // Export the public key
    if (!pkey_save_pubkey(*key, &tmp_pubkey, &tmp_pubkey_size))
        return false;

    // Verify that the buffer sizes match
    if (tmp_pubkey_size != pubkey_size) {
        logger(LOG_CRIT,
            "%s: Invalid handshake ECDH public key size (%zu but expected %zu)",
            c->addrw, tmp_pubkey_size, pubkey_size);
        free(tmp_pubkey);
        return false;
    }

    // Copy the public key
    memcpy(pubkey, tmp_pubkey, pubkey_size);
    free(tmp_pubkey);
    return true;
}

// Generate handshake nonce
static bool handshake_generate_nonce(const client_t *c, oshpacket_handshake_t *pkt)
{
    logger_debug(DBG_HANDSHAKE, "%s: Generating nonce", c->addrw);
    if (!random_bytes(pkt->nonce, sizeof(pkt->nonce))) {
        logger(LOG_ERR, "%s: Failed to generate handshake nonce", c->addrw);
        return false;
    }
    return true;
}

// Generate handshake ID salt and hash
static bool handshake_generate_sender_id(const client_t *c, oshpacket_handshake_t *pkt)
{
    const node_id_t *me = node_id_find_local();
    uint8_t sender_id_hash[EVP_MAX_MD_SIZE];

    logger_debug(DBG_HANDSHAKE, "%s: Generating sender ID salt", c->addrw);
    if (!random_bytes(pkt->sender.id_salt, sizeof(pkt->sender.id_salt))) {
        logger(LOG_ERR, "%s: Failed to generate handshake sender ID salt", c->addrw);
        return false;
    }

    logger_debug(DBG_HANDSHAKE, "%s: Generating sender ID hash", c->addrw);
    if (!node_id_gen_hash(me, pkt->sender.id_salt, sizeof(pkt->sender.id_salt), sender_id_hash)) {
        logger(LOG_ERR, "%s: Failed to generate handshake sender ID hash", c->addrw);
        return false;
    }
    memcpy(pkt->sender.id_hash, sender_id_hash, NODE_ID_HASH_SIZE);

    return true;
}

// Queue HANDSHAKE request
bool client_queue_handshake(client_t *c)
{
    oshpacket_handshake_t packet;

    logger_debug(DBG_HANDSHAKE, "%s: Creating handshake packet", c->addrw);
    if (c->handshake_in_progress) {
        logger(LOG_ERR,
            "%s: Failed to create HANDSHAKE: Another one is in progress",
            c->addrw);
        return false;
    }

    // The handshake has now started
    c->handshake_in_progress = true;

    logger_debug(DBG_HANDSHAKE, "%s: Generating ECDH key", c->addrw);
    if (!handshake_generate_ecdh_key(c, &c->ecdh_key, packet.ecdh_pubkey, sizeof(packet.ecdh_pubkey)))
        return false;
    if (!handshake_generate_nonce(c, &packet))
        return false;
    if (!handshake_generate_sender_id(c, &packet))
        return false;

    // Timeout the connection if the handshake does not complete fast enough
    // When this is the initial handshake the timeout will already be queued by
    // client_init and this one will be ignored
    event_queue_handshake_timeout(c, HANDSHAKE_TIMEOUT);

    logger_debug(DBG_HANDSHAKE, "%s: Allocating handshake signature data", c->addrw);
    free(c->handshake_sig_data);
    c->handshake_sig_data = xzalloc(sizeof(oshpacket_handshake_sig_data_t));

    logger_debug(DBG_HANDSHAKE, "%s: Copying local handshake to signature data", c->addrw);
    memcpy(c->initiator ? &c->handshake_sig_data->initiator_handshake
                        : &c->handshake_sig_data->receiver_handshake,
           &packet, sizeof(packet));

    logger_debug(DBG_HANDSHAKE, "%s: Queuing local handshake packet", c->addrw);
    return client_queue_packet_direct(c, OSHPKT_HANDSHAKE, &packet, sizeof(packet));
}

// Queue a HANDSHAKE packet to renew the encryption keys
// If a handshake is already in progress, nothing is done
// If the packet cannot be queued the connection is terminated
void client_renew_handshake(client_t *c)
{
    if (!c->handshake_in_progress) {
        logger_debug(DBG_HANDSHAKE, "%s: Initiating handshake renewal", c->addrw);
        if (!client_queue_handshake(c)) {
            logger(LOG_ERR, "%s: Failed to renew handshake", c->addrw);
            aio_event_del(c->aio_event);
        }
    }
}

// Queue DEVMODE packet
bool client_queue_devmode(client_t *c)
{
    if (oshd.device_mode == MODE_DYNAMIC) {
        oshpacket_devmode_dynamic_t packet;
        netaddr_data_t prefix_data;

        packet.devmode_pkt.devmode = oshd.device_mode;
        memcpy(packet.network_name, oshd.network_name, NODE_NAME_SIZE);
        netaddr_cpy_data(&prefix_data, &oshd.dynamic_prefix6);
        packet.prefix6 = prefix_data;
        packet.prefixlen6 = oshd.dynamic_prefixlen6;
        netaddr_cpy_data(&prefix_data, &oshd.dynamic_prefix4);
        packet.prefix4 = prefix_data;
        packet.prefixlen4 = oshd.dynamic_prefixlen4;

        return client_queue_packet_direct(c, OSHPKT_DEVMODE, &packet, sizeof(packet));
    } else {
        oshpacket_devmode_t packet;

        packet.devmode = oshd.device_mode;
        return client_queue_packet_direct(c, OSHPKT_DEVMODE, &packet, sizeof(packet));
    }
}

// Queue GOODBYE request and gracefully disconnect the client
bool client_queue_goodbye(client_t *c)
{
    bool success = client_queue_packet_empty(c, OSHPKT_GOODBYE);

    client_graceful_disconnect(c);
    return success;
}

// Queue PING request
bool client_queue_ping(client_t *c)
{
    if (c->rtt_await) {
        logger_debug(DBG_SOCKETS, "%s: %s: Dropping PING request, another was not answered yet",
            c->addrw, c->id->name);
        return true;
    }

    oshd_gettime(&c->rtt_ping);
    c->rtt_await = true;
    return client_queue_packet_empty(c, OSHPKT_PING);
}

// Queue PONG request
bool client_queue_pong(client_t *c)
{
    return client_queue_packet_empty(c, OSHPKT_PONG);
}

// Broadcast a node's public key
bool client_queue_pubkey_broadcast(client_t *exclude, node_id_t *id)
{
    oshpacket_pubkey_t packet;

    if (   !id->pubkey
        || !id->pubkey_raw
        || id->pubkey_raw_size != NODE_PUBKEY_SIZE)
    {
        logger(LOG_ERR, "Failed to broadcast public key of %s: No public key",
            id->name);
        return false;
    }

    logger_debug(DBG_HANDSHAKE, "Broadcasting public key of %s", id->name);
    memcpy(packet.node_name, id->name, NODE_NAME_SIZE);
    memcpy(packet.node_pubkey, id->pubkey_raw, NODE_PUBKEY_SIZE);

    return client_queue_packet_broadcast(exclude, OSHPKT_PUBKEY, &packet, sizeof(packet));
}

// Queue an endpoint
// If broadcast is true, *dest is a client to exclude from the broadcast
static bool _client_queue_endpoint(client_t *dest, const endpoint_t *endpoint,
    const node_id_t *owner, const bool broadcast, const oshpacket_type_t pkt_type)
{
    uint8_t buf[sizeof(oshpacket_endpoint_t) + sizeof(endpoint_data_t)];
    oshpacket_endpoint_t *pkt = (oshpacket_endpoint_t *) buf;
    endpoint_data_t *data = (endpoint_data_t *) (pkt + 1);
    size_t data_size;
    size_t total_size;

    memset(buf, 0, sizeof(buf));
    if (!endpoint_to_packet(endpoint, pkt, data, &data_size)) {
        logger(LOG_ERR, "Failed to queue incompatible endpoint %s owned by %s",
            endpoint->addrstr, owner->name);
        return false;
    }

    memcpy(pkt->owner_name, owner->name, NODE_NAME_SIZE);
    total_size = sizeof(*pkt) + data_size;

    return broadcast ? client_queue_packet_broadcast(dest, pkt_type, buf, total_size)
                     : client_queue_packet_direct(dest, pkt_type, buf, total_size);
}

// Queue an endpoint
// If broadcast is true, *dest is a client to exclude from the broadcast
bool client_queue_endpoint(client_t *dest, const endpoint_t *endpoint,
    const node_id_t *owner, const bool broadcast)
{
    return _client_queue_endpoint(dest, endpoint, owner, broadcast, OSHPKT_ENDPOINT);
}

// Queue a discovered endpoint to share it
bool client_queue_endpoint_disc(client_t *dest, const endpoint_t *endpoint,
    const node_id_t *owner)
{
    return _client_queue_endpoint(dest, endpoint, owner, false, OSHPKT_ENDPOINT_DISC);
}

// Broadcast EDGE_ADD or EDGE_DEL request
bool client_queue_edge_broadcast(client_t *exclude, oshpacket_type_t type,
    const char *src, const char *dest)
{
    oshpacket_edge_t buf;

    switch (type) {
        case OSHPKT_EDGE_ADD:
        case OSHPKT_EDGE_DEL:
            memcpy(buf.src_node, src,  NODE_NAME_SIZE);
            memcpy(buf.dest_node, dest, NODE_NAME_SIZE);
            return client_queue_packet_broadcast(exclude, type,
                    &buf, sizeof(oshpacket_edge_t));

        default:
            logger(LOG_ERR, "client_queue_edge: Invalid type %s",
                oshpacket_type_name(type));
            return false;
    }
}

// Broadcast ROUTE_ADD request with one or more local routes
bool client_queue_route_add_local(client_t *exclude, const netaddr_t *addrs,
    size_t count, bool can_expire)
{
    if (count == 0)
        return true;

    size_t buf_size = sizeof(oshpacket_route_t) * count;
    oshpacket_route_t *buf = xalloc(buf_size);
    netaddr_data_t addr_data;

    // Format the addresses's type and data into buf
    for (size_t i = 0; i < count; ++i) {
        memcpy(buf[i].owner_name, oshd.name, NODE_NAME_SIZE);
        buf[i].type = addrs[i].type;
        buf[i].prefixlen = netaddr_max_prefixlen(addrs[i].type);
        netaddr_cpy_data(&addr_data, &addrs[i]);
        buf[i].addr = addr_data;
        buf[i].can_expire = can_expire;
    }

    bool success = client_queue_packet_fragmented(exclude, OSHPKT_ROUTE_ADD, buf, buf_size,
        sizeof(oshpacket_route_t), true);

    // We need to free the memory before returning
    free(buf);
    return success;
}
