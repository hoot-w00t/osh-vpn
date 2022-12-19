#include "client.h"
#include "oshd.h"
#include "logger.h"
#include "events.h"
#include "random.h"
#include "xalloc.h"
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

// Disconnect client and removes the node from the node tree
static void client_disconnect(client_t *c)
{
    // If the client is authenticated we have to remove our connection to it
    // from the node tree
    if (c->authenticated) {
        node_id_t *me = node_id_find_local();

        // Remove the direct connection from this node
        c->id->node_socket = NULL;

        // Delete the edge between our two nodes
        node_id_del_edge(me, c->id);
        node_tree_update();

        // Broadcast this change to the rest of the network
        client_queue_edge_broadcast(c, EDGE_DEL, me->name, c->id->name);
    }

    // CLose the network socket
    if (c->fd > 0) {
        logger(LOG_INFO, "Disconnecting %s", c->addrw);

        if (shutdown(c->fd, SHUT_RDWR) < 0)
            logger_debug(DBG_SOCKETS, "%s: shutdown(%i): %s", c->addrw, c->fd, strerror(errno));

        if (close(c->fd) < 0)
            logger(LOG_ERR, "%s: close(%i): %s", c->addrw, c->fd, strerror(errno));

        c->fd = -1;
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

// Set the client's endpoint, socket address and format addrw for logging
static void client_set_endpoint(client_t *c, const endpoint_t *endpoint,
    const struct sockaddr_storage *sa)
{
    endpoint_free(c->sa_endpoint);
    free(c->addrw);

    memcpy(&c->sa, sa, sizeof(c->sa));
    c->sa_endpoint = endpoint_dup(endpoint);
    c->addrw = xstrdup(c->sa_endpoint->addrstr);
}

// Change the client's existing endpoint and socket address and log it
void client_change_endpoint(client_t *c, const endpoint_t *endpoint,
    const struct sockaddr_storage *sa)
{
    logger(LOG_INFO, "%s: Endpoint changed to %s", c->sa_endpoint->addrstr,
        endpoint->addrstr);
    client_set_endpoint(c, endpoint, sa);
}

// Disconnect and free a client
void client_destroy(client_t *c)
{
    // Cancel any events linked to this client
    event_cancel(c->handshake_renew_event);
    event_cancel(c->handshake_timeout_event);

    client_disconnect(c);

    free(c->handshake_sig_data);
    free(c->io.recvbuf);

    netbuffer_free(c->io.sendq);
    client_reset_ciphers(c);

    endpoint_free(c->sa_endpoint);
    free(c->addrw);
    free(c);
}

// Create and initialize a new client
client_t *client_init(int fd, bool initiator, const endpoint_t *endpoint,
    const struct sockaddr_storage *sa)
{
    client_t *c = xzalloc(sizeof(client_t));

    c->fd = fd;
    c->initiator = initiator;

    // Set the client's socket address, endpoint and format addrw
    client_set_endpoint(c, endpoint, sa);

    // Initialize network buffers
    c->io.recvbuf = xalloc(CLIENT_RECVBUF_SIZE);
    c->io.sendq = netbuffer_create(CLIENT_SENDQ_MIN_SIZE, CLIENT_SENDQ_ALIGNMENT);

    // Queue the handshake timeout event
    // This event will terminate the connection if the authentication did not
    // succeed
    event_queue_handshake_timeout(c, HANDSHAKE_TIMEOUT);

    return c;
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

// Decrypt packet using the client's receive cipher
bool client_decrypt_packet(client_t *c, oshpacket_t *pkt)
{
    const size_t encrypted_size = OSHPACKET_PRIVATE_HDR_SIZE + pkt->payload_size;
    size_t decrypted_size;

    // If there is no cipher, consider the decryption operation successful
    if (!c->recv_cipher)
        return true;

    logger_debug(DBG_ENCRYPTION, "%s: Decrypting packet seqno %" PRIu64 " of %zu bytes",
        c->addrw, pkt->seqno, encrypted_size);

    // We decrypt the packet at the same location because we are using a
    // streaming cipher
    if (!cipher_decrypt(c->recv_cipher,
            OSHPACKET_PRIVATE_HDR(pkt->hdr), &decrypted_size,
            OSHPACKET_PRIVATE_HDR(pkt->hdr), encrypted_size,
            pkt->hdr->tag, pkt->seqno))
    {
        logger(LOG_ERR, "%s: Failed to decrypt packet seqno %" PRIu64, c->addrw, pkt->seqno);
        return false;
    }

    // Make sure that the packet size is the same
    if (decrypted_size != encrypted_size) {
        logger(LOG_ERR,
            "%s: Decrypted packet seqno %" PRIu64 " has a different size (encrypted: %zu, decrypted: %zu)",
            c->addrw, pkt->seqno, encrypted_size, decrypted_size);
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
            logger_debug(DBG_TUNTAP,
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
    const size_t packet_size = OSHPACKET_HDR_SIZE + payload_size;
    uint8_t *slot;

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
        logger_debug(DBG_TUNTAP, "%s: Dropping %s packet of %zu bytes (%s)",
            c->addrw, oshpacket_type_name(hdr->type), payload_size, "qm");
        return false;
    }

    slot = netbuffer_reserve(c->io.sendq, packet_size);

    // Initialize the public part of the header
    OSHPACKET_HDR(slot)->payload_size = htons(((uint16_t) payload_size));

    // Copy the private part of the header which was initialized by the caller
    memcpy(OSHPACKET_PRIVATE_HDR(slot), OSHPACKET_PRIVATE_HDR_CONST(hdr),
        OSHPACKET_PRIVATE_HDR_SIZE);

    // Copy the packet's payload to the buffer (if there is one)
    if (payload)
        memcpy(OSHPACKET_PAYLOAD(slot), payload, payload_size);

    if (c->send_cipher) {
        // The socket has a send_cipher, so the packet will be encrypted

        // We encrypt the private header and the payload but not the public
        // header as it is required to properly receive and decode the packet
        const size_t orig_size = OSHPACKET_PRIVATE_HDR_SIZE + payload_size;
        size_t encr_size;

        logger_debug(DBG_ENCRYPTION, "%s: Encrypting packet of %zu bytes",
            c->addrw, orig_size);

        if (!cipher_encrypt(c->send_cipher,
                OSHPACKET_PRIVATE_HDR(slot), &encr_size,
                OSHPACKET_PRIVATE_HDR(slot), orig_size,
                OSHPACKET_HDR(slot)->tag,
                c->send_seqno))
        {
            logger(LOG_ERR, "%s: Failed to encrypt packet", c->addrw);
            netbuffer_cancel(c->io.sendq, packet_size);
            return false;
        }

        // The encrypted data must have the same size as the original
        if (encr_size != orig_size) {
            logger(LOG_ERR,
                "%s: Encrypted packet has a different size (original: %zu, encrypted %zu)",
                c->addrw, orig_size, encr_size);
            netbuffer_cancel(c->io.sendq, packet_size);
            return false;
        }

    } else if (def->can_be_sent_unencrypted) {
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
            c->addrw, oshpacket_type_name(hdr->type));
        netbuffer_cancel(c->io.sendq, packet_size);

        return false;
    }

    // Increment the send seqno
    c->send_seqno += 1;

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
    return client_queue_packet_indirect(dest, DATA, payload, payload_size);
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
    return client_queue_packet_direct(c, HANDSHAKE, &packet, sizeof(packet));
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

        packet.devmode_pkt.devmode = oshd.device_mode;
        memcpy(packet.network_name, oshd.network_name, NODE_NAME_SIZE);
        netaddr_cpy_data(&packet.prefix6, &oshd.dynamic_prefix6);
        packet.prefixlen6 = oshd.dynamic_prefixlen6;
        netaddr_cpy_data(&packet.prefix4, &oshd.dynamic_prefix4);
        packet.prefixlen4 = oshd.dynamic_prefixlen4;

        return client_queue_packet_direct(c, DEVMODE, &packet, sizeof(packet));
    } else {
        oshpacket_devmode_t packet;

        packet.devmode = oshd.device_mode;
        return client_queue_packet_direct(c, DEVMODE, &packet, sizeof(packet));
    }
}

// Queue GOODBYE request and gracefully disconnect the client
bool client_queue_goodbye(client_t *c)
{
    bool success = client_queue_packet_empty(c, GOODBYE);

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
    return client_queue_packet_empty(c, PING);
}

// Queue PONG request
bool client_queue_pong(client_t *c)
{
    return client_queue_packet_empty(c, PONG);
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

    return client_queue_packet_broadcast(exclude, PUBKEY, &packet, sizeof(packet));
}

// Queue an endpoint
// If broadcast is true, *dest is a client to exclude from the broadcast
bool client_queue_endpoint(client_t *dest, const endpoint_t *endpoint,
    const node_id_t *owner, const bool broadcast)
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

    return broadcast ? client_queue_packet_broadcast(dest, ENDPOINT, buf, total_size)
                     : client_queue_packet_direct(dest, ENDPOINT, buf, total_size);
}



// Broadcast EDGE_ADD or EDGE_DEL request
bool client_queue_edge_broadcast(client_t *exclude, oshpacket_type_t type,
    const char *src, const char *dest)
{
    oshpacket_edge_t buf;

    switch (type) {
        case EDGE_ADD:
        case EDGE_DEL:
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

    // Format the addresses's type and data into buf
    for (size_t i = 0; i < count; ++i) {
        memcpy(buf[i].owner_name, oshd.name, NODE_NAME_SIZE);
        buf[i].type = addrs[i].type;
        buf[i].prefixlen = netaddr_max_prefixlen(addrs[i].type);
        netaddr_cpy_data(&buf[i].addr, &addrs[i]);
        buf[i].can_expire = can_expire;
    }

    bool success = client_queue_packet_fragmented(exclude, ROUTE_ADD, buf, buf_size,
        sizeof(oshpacket_route_t), true);

    // We need to free the memory before returning
    free(buf);
    return success;
}
