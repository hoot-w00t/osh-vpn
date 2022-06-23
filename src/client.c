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

    client_reconnect(c);
}

// Free all send/recv keys and ciphers and reset their values to NULL
static void client_reset_ciphers(client_t *c)
{
    pkey_free(c->send_key);
    cipher_free(c->send_cipher);
    pkey_free(c->recv_key);
    cipher_free(c->recv_cipher);
    cipher_free(c->recv_cipher_next);
    c->send_key = NULL;
    c->send_cipher = NULL;
    c->recv_key = NULL;
    c->recv_cipher = NULL;
    c->recv_cipher_next = NULL;
}

// Disconnect and free a client
void client_destroy(client_t *c)
{
    // Cancel any events linked to this client
    event_cancel(c->handshake_renew_event);
    event_cancel(c->handshake_timeout_event);
    event_cancel(c->auth_timeout_event);

    client_disconnect(c);

    free(c->unauth_handshake);
    free(c->hello_chall);
    free(c->io.recvbuf);

    netbuffer_free(c->io.sendq);
    client_reset_ciphers(c);

    free(c);
}

// Create and initialize a new client
client_t *client_init(int fd, bool initiator, const netaddr_t *addr, uint16_t port)
{
    client_t *c = xzalloc(sizeof(client_t));

    c->fd = fd;
    c->initiator = initiator;

    // Format the client's address and port for logging
    if (!netaddr_ntop2(c->addrw, sizeof(c->addrw), addr, port))
        snprintf(c->addrw, sizeof(c->addrw), "(format error)");

    // Initialize network buffers
    c->io.recvbuf = xalloc(CLIENT_RECVBUF_SIZE);
    c->io.sendq = netbuffer_create(CLIENT_SENDQ_MIN_SIZE, CLIENT_SENDQ_ALIGNMENT);

    // Queue the authentication timeout event
    // When it triggers if the client is not authenticated it will be
    // disconnected
    event_queue_node_auth_timeout(c, NODE_AUTH_TIMEOUT);

    return c;
}

// Returns a valid delay within the reconnection delay limits
static time_t client_reconnect_delay_limit(time_t delay)
{
    // If delay is too small, return the minimum delay
    if (delay < oshd.reconnect_delay_min)
        return oshd.reconnect_delay_min;

    // If it is too big, return the maximum
    if (delay > oshd.reconnect_delay_max)
        return oshd.reconnect_delay_max;

    // Otherwise the delay is already within the limits, return it
    return delay;
}

// Set the client's reconnection delay
void client_reconnect_delay(client_t *c, time_t delay)
{
    c->reconnect_delay = client_reconnect_delay_limit(delay);
}

// Set the client's reconnection endpoints
// Destroys the previous endpoints if there were some
void client_reconnect_to(client_t *c, endpoint_group_t *reconnect_endpoints,
    time_t delay)
{
    if (!reconnect_endpoints) {
        // If this warning appears something in the code should be using
        // client_reconnect_disable instead of this function, this situation
        // should not happen
        logger(LOG_WARN, "%s: client_reconnect_to called without any endpoints",
            c->addrw);
        c->reconnect_endpoints = NULL;
    } else {
        c->reconnect_endpoints = reconnect_endpoints;
    }
    client_reconnect_delay(c, delay);
}

// Disable the client's reconnection
void client_reconnect_disable(client_t *c)
{
    c->reconnect_endpoints = NULL;
    client_reconnect_delay(c, oshd.reconnect_delay_min);
}

// Queue a reconnection to one or multiple endpoints with delay seconds between
// each loop
// Doubles the delay for future reconnections
static void client_reconnect_endpoints(endpoint_group_t *reconnect_endpoints, time_t delay)
{
    time_t event_delay = client_reconnect_delay_limit(delay);

    if (endpoint_group_selected(reconnect_endpoints)) {
        // We still have an endpoint, queue a reconnection to it
        event_queue_connect(reconnect_endpoints, event_delay, event_delay);
    } else {
        // We don't have an endpoint, this means that we reached the end of the
        // list
        if (endpoint_group_select_first(reconnect_endpoints)) {
            // There are endpoints in the group, maybe try to reconnect
            if (reconnect_endpoints->always_retry) {
                // Increment the delay and go back to the start of the list
                event_delay = client_reconnect_delay_limit(delay * 2);
                event_queue_connect(reconnect_endpoints, event_delay, event_delay);
            } else {
                logger(LOG_INFO, "Giving up trying to reconnect to %s",
                    reconnect_endpoints->owner_name);
                endpoint_group_set_is_connecting(reconnect_endpoints, false);
            }
        } else {
            // The group is empty, there is nothing to do
            logger(LOG_INFO, "Giving up trying to reconnect to %s (no endpoints)",
                reconnect_endpoints->owner_name);
            endpoint_group_set_is_connecting(reconnect_endpoints, false);
        }
    }
}

// Selects the next endpoint in the list before calling client_reconnect_endpoints
void client_reconnect_endpoints_next(endpoint_group_t *reconnect_endpoints, time_t delay)
{
    endpoint_group_select_next(reconnect_endpoints);
    client_reconnect_endpoints(reconnect_endpoints, delay);
}

// If the client has a reconnect_endpoints, queue a reconnection
// If the previous reconnection was a success, start from the beginning of the
// list, otherwise choose the next endpoint in the list
void client_reconnect(client_t *c)
{
    if (c->reconnect_endpoints) {
        if (endpoint_group_is_connecting(c->reconnect_endpoints)) {
            client_reconnect_endpoints_next(c->reconnect_endpoints, c->reconnect_delay);
        } else {
            endpoint_group_select_first(c->reconnect_endpoints);
            client_reconnect_endpoints(c->reconnect_endpoints, c->reconnect_delay);
        }
    }
}

// Returns true if the DATA packet should be dropped (when the send queue is
// full or filling up too fast)
static bool data_packet_should_drop(client_t *c)
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
static bool client_queue_packet_internal(
    client_t *c,
    const oshpacket_hdr_t *hdr,
    const void *payload,
    const size_t payload_size)
{
    const size_t packet_size = OSHPACKET_HDR_SIZE + payload_size;
    uint8_t *slot;

    // Drop packet if its size exceeds the limit
    if (packet_size > OSHPACKET_MAXSIZE) {
        logger(LOG_ERR,
            "%s: Dropping %s packet of %zu bytes (exceeds size limit)",
            c->addrw, oshpacket_type_name(hdr->type), packet_size);
        return false;
    }

    // Drop DATA packets if the send queue exceeds a limit
    // This is a very basic way to handle network congestion, but without it the
    // send queue can accumulate an infinite amount of packets and this could
    // create a denial of service between two nodes until we can catch up and
    // the send queue flushes all of its data (this could take days in the worst
    // cases)
    if (   hdr->type == DATA
        && data_packet_should_drop(c))
    {
        logger_debug(DBG_TUNTAP, "%s: Dropping %s packet of %zu bytes",
            c->addrw, oshpacket_type_name(hdr->type), payload_size);
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
                OSHPACKET_HDR(slot)->tag))
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

    } else if (hdr->type == HANDSHAKE) {
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

        // GOODBYE packets should close the connection so if there's no data
        // queued after a failed GOODBYE we can remove the client
        if (hdr->type == GOODBYE) {
            if (netbuffer_data_size(c->io.sendq) == 0)
                aio_event_del(c->aio_event);
        }

        return false;
    }

    aio_enable_poll_events(c->aio_event, AIO_WRITE);
    return true;
}

// Queue a unicast packet for another node
bool client_queue_packet(client_t *c, node_id_t *dest, oshpacket_type_t type,
    const void *payload, size_t payload_size)
{
    oshpacket_hdr_t hdr;

    hdr.type = type;
    hdr.flags.u = 0;
    memcpy(hdr.src_node, oshd.name, sizeof(hdr.src_node));
    if (dest) {
        memcpy(hdr.dest.unicast.dest_node, dest->name, NODE_NAME_SIZE);
    } else {
        memset(&hdr.dest.unicast, 0, sizeof(hdr.dest.unicast));
    }
    return client_queue_packet_internal(c, &hdr, payload, payload_size);
}

// Forward an existing packet to another client
bool client_queue_packet_forward(client_t *c, const oshpacket_hdr_t *hdr,
    const void *payload, size_t payload_size)
{
    return client_queue_packet_internal(c, hdr, payload, payload_size);
}

// Broadcast a packet to all authenticated direct connections
// If exclude is not NULL the packet will not be queued for the excluded client
bool client_queue_packet_broadcast(client_t *exclude, oshpacket_type_t type,
    const void *payload, size_t payload_size)
{
    oshpacket_hdr_t hdr;

    hdr.type = type;
    hdr.flags.u = 0;
    hdr.flags.s.broadcast = 1;
    memcpy(hdr.src_node, oshd.name, sizeof(hdr.src_node));
    memset(&hdr.dest.broadcast, 0, sizeof(hdr.dest.broadcast));
    hdr.dest.broadcast.id = random_xoshiro256();

    logger_debug(DBG_SOCKETS,
        "Broadcasting %s packet of %zu bytes (id: %" PRI_BRD_ID ")",
        oshpacket_type_name(type), payload_size, hdr.dest.broadcast.id);

    for (size_t i = 0; i < oshd.clients_count; ++i) {
        if (   !oshd.clients[i]->authenticated
            ||  oshd.clients[i] == exclude)
        {
            continue;
        }

        client_queue_packet_internal(oshd.clients[i], &hdr, payload, payload_size);
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

        client_queue_packet_internal(oshd.clients[i], hdr, payload, payload_size);
    }

    return true;
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
    const void *curr_buf = payload;

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

            if (!client_queue_packet(c, c->id, type, curr_buf, size))
                return false;
        }

        // Iterate to the next entries
        remaining_entries -= entries;
        curr_buf += size;
    }

    return true;
}

// Queue HANDSHAKE request
bool client_queue_handshake(client_t *c)
{
    oshpacket_handshake_t packet;

    logger_debug(DBG_HANDSHAKE, "Creating HANDSHAKE packet for %s", c->addrw);
    if (c->handshake_in_progress) {
        logger(LOG_ERR,
            "%s: Failed to create HANDSHAKE: Another one is in progress",
            c->addrw);
        return false;
    }

    // We are now currently shaking hands
    // After completion c->send_key/recv_key will be freed and NULLed
    c->handshake_in_progress = true;

    // Generate random keys
    logger_debug(DBG_HANDSHAKE, "%s: Generating send_key", c->addrw);
    if (!(c->send_key = pkey_generate_x25519()))
        return false;
    logger_debug(DBG_HANDSHAKE, "%s: Generating recv_key", c->addrw);
    if (!(c->recv_key = pkey_generate_x25519()))
        return false;

    uint8_t *pubkey;
    size_t pubkey_size;

    // Export the keys to the packet
    logger_debug(DBG_HANDSHAKE, "%s: Exporting send_key", c->addrw);
    if (!pkey_save_pubkey(c->send_key, &pubkey, &pubkey_size))
        return false;
    if (pubkey_size != sizeof(packet.keys.k.send)) {
        free(pubkey);
        logger(LOG_ERR, "%s: send_key size is invalid (%zu, but expected %zu)",
            c->addrw, pubkey_size, sizeof(packet.keys.k.send));
        return false;
    }
    memcpy(packet.keys.k.send, pubkey, pubkey_size);
    free(pubkey);

    logger_debug(DBG_HANDSHAKE, "%s: Exporting recv_key", c->addrw);
    if (!pkey_save_pubkey(c->recv_key, &pubkey, &pubkey_size))
        return false;
    if (pubkey_size != sizeof(packet.keys.k.recv)) {
        free(pubkey);
        logger(LOG_ERR, "%s: recv_key size is invalid (%zu, but expected %zu)",
            c->addrw, pubkey_size, sizeof(packet.keys.k.recv));
        return false;
    }
    memcpy(packet.keys.k.recv, pubkey, pubkey_size);
    free(pubkey);

    // Sign the keys
    uint8_t *sig;
    size_t sig_size;

    if (!pkey_sign(oshd.privkey,
            packet.keys.both, sizeof(packet.keys.both),
            &sig, &sig_size))
    {
        logger(LOG_ERR, "%s: Failed to sign handshake keys", c->addrw);
        return false;
    }

    if (sig_size != sizeof(packet.sig)) {
        free(sig);
        logger(LOG_ERR, "%s: Invalid handshake signature size (%zu bytes)",
            c->addrw, sig_size);
        return false;
    }

    memcpy(packet.sig, sig, sizeof(packet.sig));
    free(sig);

    // If we are authenticateed we need to handle handshake timeouts
    // When unauthenticated the authentication timeout event takes care of this
    if (c->authenticated)
        event_queue_handshake_timeout(c, HANDSHAKE_TIMEOUT);

    return client_queue_packet(c, c->id, HANDSHAKE, &packet, sizeof(packet));
}

// Queue HANDSHAKE_END packet
bool client_queue_handshake_end(client_t *c)
{
    return client_queue_packet_empty(c, c->id, HANDSHAKE_END);
}

// Queue a HANDSHAKE packet to renew the encryption keys
// If a handshake is already in progress, nothing is done
// If packet cannot be queued the connection is terminated
void client_renew_handshake(client_t *c)
{
    if (!c->handshake_in_progress) {
        if (!client_queue_handshake(c))
            aio_event_del(c->aio_event);
    }
}

// Queue HELLO_CHALLENGE request
bool client_queue_hello_challenge(client_t *c)
{
    free(c->hello_chall);
    c->hello_chall = xalloc(sizeof(oshpacket_hello_challenge_t));

    if (!random_bytes(c->hello_chall->challenge, sizeof(c->hello_chall->challenge)))
        return false;

    return client_queue_packet(c, NULL, HELLO_CHALLENGE, c->hello_chall,
        sizeof(oshpacket_hello_challenge_t));
}

// Queue HELLO_END packet
bool client_queue_hello_end(client_t *c)
{
    oshpacket_hello_end_t packet;

    if (c->hello_auth) {
        logger_debug(DBG_AUTHENTICATION, "%s: Successful HELLO_END",
            c->addrw);
        packet.hello_success = 1;
    } else {
        logger_debug(DBG_AUTHENTICATION, "%s: Failed HELLO_END",
            c->addrw);
        packet.hello_success = 0;
        client_graceful_disconnect(c);
    }
    return client_queue_packet(c, NULL, HELLO_END, &packet, sizeof(packet));
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

        return client_queue_packet(c, c->id, DEVMODE, &packet, sizeof(packet));
    } else {
        oshpacket_devmode_t packet;

        packet.devmode = oshd.device_mode;
        return client_queue_packet(c, c->id, DEVMODE, &packet, sizeof(packet));
    }
}

// Queue STATEEXG_END packet
bool client_queue_stateexg_end(client_t *c)
{
    return client_queue_packet_empty(c, c->id, STATEEXG_END);
}

// Queue GOODBYE request
bool client_queue_goodbye(client_t *c)
{
    client_graceful_disconnect(c);
    return client_queue_packet_empty(c, c->id, GOODBYE);
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
    return client_queue_packet_empty(c, c->id, PING);
}

// Queue PONG request
bool client_queue_pong(client_t *c)
{
    return client_queue_packet_empty(c, c->id, PONG);
}

// Broadcast a node's public key
bool client_queue_pubkey_broadcast(client_t *exclude, node_id_t *id)
{
    oshpacket_pubkey_t packet;

    if (   !id->pubkey
        || !id->pubkey_raw
        || id->pubkey_raw_size != PUBLIC_KEY_SIZE)
    {
        logger(LOG_ERR, "Failed to broadcast public key of %s: No public key",
            id->name);
        return false;
    }

    logger_debug(DBG_AUTHENTICATION, "Public keys exchange: Broadcasting %s", id->name);
    memcpy(packet.node_name, id->name, NODE_NAME_SIZE);
    memcpy(packet.node_pubkey, id->pubkey_raw, PUBLIC_KEY_SIZE);

    return client_queue_packet_broadcast(exclude, PUBKEY, &packet, sizeof(packet));
}

// Queue PUBKEY exchange packet
bool client_queue_pubkey_exg(client_t *c)
{
    oshpacket_pubkey_t *pubkeys = NULL;
    size_t count = 0;
    bool success;

    for (size_t i = 0; i < oshd.node_tree_count; ++i) {
        // Only exchange public keys from online nodes
        if (   !oshd.node_tree[i]->online
            || !oshd.node_tree[i]->pubkey
            || !oshd.node_tree[i]->pubkey_raw
            ||  oshd.node_tree[i]->pubkey_raw_size != PUBLIC_KEY_SIZE)
        {
            continue;
        }

        logger_debug(DBG_AUTHENTICATION, "Public keys exchange: Adding %s", oshd.node_tree[i]->name);
        pubkeys = xreallocarray(pubkeys, count + 1, sizeof(oshpacket_pubkey_t));
        memcpy(pubkeys[count].node_name, oshd.node_tree[i]->name, NODE_NAME_SIZE);
        memcpy(pubkeys[count].node_pubkey, oshd.node_tree[i]->pubkey_raw, PUBLIC_KEY_SIZE);
        count += 1;
    }

    success = client_queue_packet_fragmented(c, PUBKEY, pubkeys,
        sizeof(oshpacket_pubkey_t) * count, sizeof(oshpacket_pubkey_t), false);
    free(pubkeys);
    return success;
}

// Broadcast an endpoint owned by group->owner_name
bool client_queue_endpoint_broadcast(client_t *exclude, const endpoint_t *endpoint,
    const endpoint_group_t *group)
{
    oshpacket_endpoint_t pkt;
    netaddr_t addr;

    if (!group->has_owner) {
        logger(LOG_ERR, "Failed to broadcast endpoint %s:%u: No owner (%s)",
            endpoint->hostname, endpoint->port, group->owner_name);
        return false;
    }
    if (!netaddr_lookup(&addr, endpoint->hostname)) {
        logger(LOG_WARN,
            "Failed to broadcast endpoint %s:%u owned by %s (lookup failed)",
            endpoint->hostname, endpoint->port, group->owner_name);
        return false;
    }

    memset(&pkt, 0, sizeof(pkt));
    for (size_t i = 0; (group->owner_name[i] != 0) && (i < NODE_NAME_SIZE); ++i)
        pkt.node_name[i] = group->owner_name[i];
    pkt.addr_type = addr.type;
    netaddr_cpy_data(&pkt.addr_data, &addr);
    pkt.port = htons(endpoint->port);

    logger_debug(DBG_ENDPOINTS, "Broadcasting endpoint %s:%u owned by %s",
        endpoint->hostname, endpoint->port, group->owner_name);
    return client_queue_packet_broadcast(exclude, ENDPOINT, &pkt, sizeof(pkt));
}

// Send an endpoint owned by group->owner_name to the client
static bool client_queue_endpoint(client_t *c, const endpoint_t *endpoint,
    const endpoint_group_t *group)
{
    oshpacket_endpoint_t pkt;
    netaddr_t addr;

    if (!group->has_owner) {
        logger(LOG_ERR, "%s: Failed to queue endpoint %s:%u: No owner (%s)",
            c->addrw, endpoint->hostname, endpoint->port, group->owner_name);
        return false;
    }
    if (!netaddr_lookup(&addr, endpoint->hostname)) {
        logger(LOG_WARN,
            "%s: Failed to queue endpoint %s:%u owned by %s (lookup failed)",
            c->addrw, endpoint->hostname, endpoint->port, group->owner_name);
        return false;
    }

    memset(&pkt, 0, sizeof(pkt));
    for (size_t i = 0; (group->owner_name[i] != 0) && (i < NODE_NAME_SIZE); ++i)
        pkt.node_name[i] = group->owner_name[i];
    pkt.addr_type = addr.type;
    netaddr_cpy_data(&pkt.addr_data, &addr);
    pkt.port = htons(endpoint->port);

    logger_debug(DBG_ENDPOINTS, "%s: Queuing endpoint %s:%u owned by %s",
        c->addrw, endpoint->hostname, endpoint->port, group->owner_name);
    return client_queue_packet(c, c->id, ENDPOINT, &pkt, sizeof(pkt));
}

// Queue ENDPOINT exchange packets
// Exchanges all endpoints with another node
// Endpoints from the configuration file will be skipped if ShareRemotes is
// not enabled
bool client_queue_endpoint_exg(client_t *c)
{
    for (size_t i = 0; i < oshd.node_tree_count; ++i) {
        endpoint_group_t *group = oshd.node_tree[i]->endpoints;

        foreach_endpoint(endpoint, group) {
            // If ShareRemotes was not set in the configuration file,
            // endpoints that don't expire will not be shared
            if (!endpoint->can_expire && !oshd.shareremotes)
                continue;

            if (!client_queue_endpoint(c, endpoint, group))
                return false;
        }
    }
    return true;
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

// Dynamically append edges to *buf
static void edge_exg_append(oshpacket_edge_t **buf, size_t *buf_count,
    const char *src_node, const char *dest_node, const char *edge_type,
    node_id_t *remote_node)
{
    const size_t alloc_count = 16;

    // Trim edges of the remote node with which we are exchanging states, it
    // will already know its edges
    if (   !strcmp(src_node, remote_node->name)
        || !strcmp(dest_node, remote_node->name))
    {
        // This edge is owned by the remote node, it already knows about it
        logger_debug(DBG_NODETREE, "    Skipped: %s: %s <=> %s (remote)",
            edge_type, src_node, dest_node);
        return;
    }

    // Trim repeating edges
    // Including src -> dest and dest -> src
    // The source and destination edges will be linked bidirectionally so we can
    // send one direction only
    for (size_t i = 0; i < (*buf_count); ++i) {
        if (   !strcmp((*buf)[i].src_node, dest_node)
            && !strcmp((*buf)[i].dest_node, src_node))
        {
            // This edge is already in the list in the other direction
            logger_debug(DBG_NODETREE, "    Skipped: %s: %s <=> %s (repeating)",
                edge_type, src_node, dest_node);
            return;
        }
    }

    // Add this edge to the buffer
    logger_debug(DBG_NODETREE, "    Adding : %s: %s <=> %s",
        edge_type, src_node, dest_node);

    // Reallocate more alloc_count items in the buffer when we need more memory
    if ((*buf_count) % alloc_count == 0)
        *buf = xreallocarray(*buf, (*buf_count) + alloc_count, sizeof(oshpacket_edge_t));

    memcpy((*buf)[(*buf_count)].src_node, src_node, NODE_NAME_SIZE);
    memcpy((*buf)[(*buf_count)].dest_node, dest_node, NODE_NAME_SIZE);
    *buf_count += 1;
}

// Queue EDGE_ADD packets for the client with the whole network map
bool client_queue_edge_exg(client_t *c)
{
    size_t buf_count = 0;
    oshpacket_edge_t *buf = NULL;

    logger_debug(DBG_NODETREE, "%s: %s: Creating EDGE_ADD packets (state exchange)",
        c->addrw, c->id->name);

    // We skip the local node because it is useless, by starting with the
    // second element, because the first one will always be our local node
    for (size_t i = 1; i < oshd.node_tree_count; ++i) {
        // Direct edge
        if (oshd.node_tree[i]->node_socket)
            edge_exg_append(&buf, &buf_count, oshd.name, oshd.node_tree[i]->name,
                "Direct", c->id);

        // Indirect edges
        for (ssize_t j = 0; j < oshd.node_tree[i]->edges_count; ++j) {
            edge_exg_append(&buf, &buf_count, oshd.node_tree[i]->name,
                oshd.node_tree[i]->edges[j]->name, "Indirect", c->id);
        }
    }

    size_t buf_size = buf_count * sizeof(oshpacket_edge_t);
    bool success = client_queue_packet_fragmented(c, EDGE_ADD, buf, buf_size,
        sizeof(oshpacket_edge_t), false);

    // We need to free the memory before returning
    free(buf);
    return success;
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

// Queue ROUTE_ADD request with all our known routes
bool client_queue_route_exg(client_t *c)
{
    const size_t total_count = oshd.route_table->total_owned_routes;

    if (total_count == 0)
        return true;

    size_t buf_size = sizeof(oshpacket_route_t) * total_count;
    oshpacket_route_t *buf = xalloc(buf_size);

    // Format all routes' addresses into buf
    size_t i = 0;

    foreach_netroute_const(route, oshd.route_table, route_iter) {
        if (route->owner) {
            memcpy(buf[i].owner_name, route->owner->name, NODE_NAME_SIZE);
            buf[i].type = route->addr.type;
            buf[i].prefixlen = route->prefixlen;
            netaddr_cpy_data(&buf[i].addr, &route->addr);
            buf[i].can_expire = route->can_expire;
            ++i;
        }
    }

    bool success = false;

    if (i == total_count) {
        success = client_queue_packet_fragmented(c, ROUTE_ADD, buf, buf_size,
            sizeof(oshpacket_route_t), false);
    } else {
        logger(LOG_CRIT,
            "%s: %s: Route exchange copied %zu routes but expected %zu (this should never happen)",
            c->addrw, c->id->name, i, total_count);
    }

    // We need to free the memory before returning
    free(buf);
    return success;
}
