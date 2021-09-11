#include "node.h"
#include "oshd_device.h"
#include "oshd.h"
#include "crypto/hash.h"
#include "netpacket.h"
#include "logger.h"
#include <stdlib.h>
#include <string.h>

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
    logger_debug(DBG_HANDSHAKE, "%s: Loading the remote node's public keys", node->addrw);
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

    logger_debug(DBG_HANDSHAKE, "%s: Computing send_secret", node->addrw);
    if (pkey_derive(node->send_key, r_recv_pubkey, &send_secret, &send_secret_size)) {
        logger_debug(DBG_HANDSHAKE, "%s: Computing recv_secret", node->addrw);
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

    logger_debug(DBG_HANDSHAKE, "%s: Hashing shared secrets", node->addrw);
    if (   !hash_sha3_512(send_secret, send_secret_size, send_hash, &send_hash_size)
        || !hash_sha3_512(recv_secret, recv_secret_size, recv_hash, &recv_hash_size))
    {
        free(send_secret);
        free(recv_secret);
        logger(LOG_ERR, "%s: Handshake failed: Failed to hash secrets", node->addrw);
        return false;
    }
    free(send_secret);
    free(recv_secret);

    // We can now create our send/recv ciphers using the two hashes
    logger_debug(DBG_HANDSHAKE, "%s: Creating send_cipher", node->addrw);
    node->send_cipher = cipher_create_aes_256_ctr(true, send_hash, 32, send_hash + 32, 16);
    logger_debug(DBG_HANDSHAKE, "%s: Creating recv_cipher", node->addrw);
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
        return node_queue_hello_challenge(node);
    return true;
}

// Process HELLO_CHALLENGE packet
static bool oshd_process_hello_challenge(node_t *node, oshpacket_hdr_t *pkt,
    oshpacket_hello_challenge_t *payload)
{
    if (pkt->payload_size != sizeof(oshpacket_hello_challenge_t)) {
        logger(LOG_ERR, "%s: Invalid HELLO_CHALLENGE size: %u bytes", node->addrw,
            pkt->payload_size);
        return false;
    }

    char name[NODE_NAME_SIZE + 1];
    memset(name, 0, sizeof(name));
    memcpy(name, payload->node_name, NODE_NAME_SIZE);

    if (!node_valid_name(name)) {
        logger(LOG_ERR, "%s: Authentication failed: Invalid name", node->addrw);
        return node_queue_hello_end(node);
    }

    node_id_t *id = node_id_add(name);

    if (id->local_node) {
        // Disconnect the current socket if node tries to authenticate
        // as our local node
        logger(LOG_ERR, "%s: Authentication failed: Tried to authenticate as myself",
            node->addrw);
        return node_queue_hello_end(node);
    }

    node->hello_id = id;

    uint8_t *sig;
    size_t sig_size;
    oshpacket_hello_response_t response;

    // Sign the challenge using our private key
    logger_debug(DBG_AUTHENTICATION, "%s: %s: Signing challenge",
        node->addrw, node->hello_id->name);
    if (!pkey_sign(oshd.privkey,
                   (uint8_t *) payload, sizeof(oshpacket_hello_challenge_t),
                   &sig, &sig_size))
    {
        logger(LOG_ERR, "%s: %s: Failed to sign the HELLO challenge",
            node->addrw, node->hello_id->name);
        return node_queue_hello_end(node);
    }

    // Make sure that the signature size is the same as the response packet expects
    if (sig_size != sizeof(response.sig)) {
        free(sig);
        logger(LOG_ERR, "%s: %s: Signature size is invalid (%zu bytes)",
            node->addrw, node->hello_id->name, sig_size);
        return node_queue_hello_end(node);
    }

    // Initialize and queue the response packet
    memcpy(response.sig, sig, sizeof(response.sig));
    free(sig);

    return node_queue_packet(node, NULL, HELLO_RESPONSE, (uint8_t *) &response,
        sizeof(oshpacket_hello_response_t));
}

// Process HELLO_RESPONSE packet
static bool oshd_process_hello_response(node_t *node, oshpacket_hdr_t *pkt,
    oshpacket_hello_response_t *payload)
{
    if (pkt->payload_size != sizeof(oshpacket_hello_response_t)) {
        logger(LOG_ERR, "%s: Invalid HELLO_RESPONSE size: %u bytes", node->addrw,
            pkt->payload_size);
        return false;
    }

    if (!node->hello_chall) {
        // If we don't have a hello_chall packet, authentication cannot proceed
        logger(LOG_ERR, "%s: Received HELLO_RESPONSE but no HELLO_CHALLENGE was sent",
            node->addrw);
        return node_queue_hello_end(node);
    }

    if (!node->hello_id->pubkey) {
        // If we don't have a public key to verify the HELLO signature,
        // we can't authenticate the node
        logger(LOG_ERR, "%s: Authentication failed: No public key for %s",
            node->addrw, node->hello_id->name);
        return node_queue_hello_end(node);
    }

    // If the public key is local we will always use it, but if it is a remote
    // key and remote authentication is not authorized then we can't
    // authenticate the node
    if (!node->hello_id->pubkey_local && !oshd.remote_auth) {
        logger(LOG_ERR, "%s: Authentication failed: No local public key for %s",
            node->addrw, node->hello_id->name);
        return node_queue_hello_end(node);
    }

    logger_debug(DBG_AUTHENTICATION, "%s: %s has a %s public key",
        node->addrw, node->hello_id->name,
        node->hello_id->pubkey_local ? "local" : "remote");

    // If the signature verification succeeds then the node is authenticated
    logger_debug(DBG_AUTHENTICATION, "%s: Verifying signature from %s",
        node->addrw, node->hello_id->name);
    node->hello_auth = pkey_verify(node->hello_id->pubkey,
        (uint8_t *) node->hello_chall, sizeof(oshpacket_hello_challenge_t),
        payload->sig, sizeof(payload->sig));

    // If the node is not authenticated, the signature verification failed
    // The remote node did not sign the data using the private key
    // associated with the public key we have
    if (!node->hello_auth) {
        logger(LOG_ERR, "%s: Authentication failed: Failed to verify signature from %s",
            node->addrw, node->hello_id->name);
        return node_queue_hello_end(node);
    }
    logger_debug(DBG_AUTHENTICATION, "%s: Valid signature from %s",
        node->addrw, node->hello_id->name);

    if (node->hello_id->node_socket) {
        // Disconnect the current socket if node is already authenticated
        logger(LOG_WARN, "%s: Another socket is already authenticated as %s",
            node->addrw, node->hello_id->name);

        // This node should not be used
        node->hello_auth = false;

        // If the node has some reconnection endpoints we will transfer those to
        // the existing connection to prevent duplicate connections (which would
        // be refused by the remote node while the other socket is connected)
        if (node->reconnect_endpoints) {
            // Add this node's reconnection endpoints to the other node's
            logger(LOG_INFO, "%s: Moving reconnection endpoints to %s (%s)",
                node->addrw,
                node->hello_id->name,
                node->hello_id->node_socket->addrw);
            endpoint_group_add_group(node->hello_id->endpoints,
                node->reconnect_endpoints);

            // Disable reconnection for this node
            node_reconnect_disable(node);
        }
        return node_queue_hello_end(node);
    }
    return node_queue_hello_end(node);
}

// Process HELLO_END packet
static bool oshd_process_hello_end(node_t *node, oshpacket_hdr_t *pkt,
    oshpacket_hello_end_t *payload)
{
    if (pkt->payload_size != sizeof(oshpacket_hello_end_t)) {
        logger(LOG_ERR, "%s: Invalid HELLO_END size: %u bytes", node->addrw,
            pkt->payload_size);
        return false;
    }
    if (!node->hello_auth || !payload->hello_success) {
        logger(LOG_ERR, "%s: Authentication did not succeed on both nodes",
            node->addrw);
        return node->finish_and_disconnect;
    }

    node_id_t *me = node_id_find_local();

    // The remote node is now authenticated

    node->authenticated = node->hello_auth;
    node->id = node->hello_id;
    node->id->node_socket = node;

    // After successful authentication we can consider that the reconnection
    // succeeded, reset the reconnection delay
    node_reconnect_delay(node, oshd.reconnect_delay_min);

    // Merge endpoints if the node's group is not the same as the node ID's
    if (   node->reconnect_endpoints
        && node->reconnect_endpoints != node->id->endpoints)
    {
        endpoint_group_add_group(node->id->endpoints, node->reconnect_endpoints);
    }

    // Always attach this socket's reconnection addresses to its node ID's
    // endpoints
    node_reconnect_to(node, node->id->endpoints, oshd.reconnect_delay_min);

    // We are no longer actively trying to connect to these endpoints
    endpoint_group_set_is_connecting(node->id->endpoints, false);

    if (node->hello_id->next_hop) {
        logger_debug(DBG_STATEEXG, "%s: %s: Previously accessible through %s (%s)",
            node->addrw, node->id->name,
            node->id->next_hop->id->name, node->id->next_hop->addrw);
    }

    // Cleanup the temporary hello variables
    node->hello_id = NULL;
    free(node->hello_chall);
    node->hello_chall = NULL;

    node_id_add_edge(me, node->id);
    node_tree_update();

    logger(LOG_INFO, "%s: %s: Authenticated successfully", node->addrw,
        node->id->name);

    logger_debug(DBG_STATEEXG, "%s: %s: Starting state exchange",
        node->addrw, node->id->name);
    node->state_exg = true;

    // Make sure that we are our device modes are compatible
    if (!node_queue_devmode(node))
        return false;

    logger_debug(DBG_STATEEXG, "%s: %s: Exchanging local state",
        node->addrw, node->id->name);

    // We exchange our network map
    if (!node_queue_edge_exg(node))
        return false;

    // We exchange all known network routes
    if (!node_queue_route_exg(node))
        return false;

    // We exchange all known public keys of the nodes that are online
    if (!node_queue_pubkey_exg(node))
        return false;

    // We exchange all known endpoints
    if (!node_queue_endpoint_exg(node))
        return false;

    // We finished queuing our state exchange packets
    if (!node_queue_stateexg_end(node))
        return false;

    // We broadcast the new connection to our end of the network
    if (!node_queue_edge_broadcast(node, EDGE_ADD, oshd.name, node->id->name))
        return false;

    // We broadcast the remote node's public key to our end of the network
    if (!node_queue_pubkey_broadcast(node, node->id))
        return false;

    // Update the node's latency
    return node_queue_ping(node);
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

        if (src->local_node || dest->local_node) {
            logger_debug(DBG_NODETREE, "%s: %s: %s edge: %s <=> %s (skipped, local)",
                node->addrw, node->id->name, action_name, src_name, dest_name);
            continue;
        }

        logger_debug(DBG_NODETREE, "%s: %s: %s edge: %s <=> %s", node->addrw,
            node->id->name, action_name, src_name, dest_name);
        action(src, dest);
    }
    return true;
}

// Iterate through all routes in *payload and add them
static bool oshd_process_route(node_t *node, oshpacket_hdr_t *pkt,
    oshpacket_route_t *payload)
{
    const size_t entries = pkt->payload_size / sizeof(oshpacket_route_t);
    char node_name[NODE_NAME_SIZE + 1];
    char addr_str[INET6_ADDRSTRLEN];
    netaddr_t addr;
    node_id_t *id;

    if (    pkt->payload_size < sizeof(oshpacket_route_t)
        || (pkt->payload_size % sizeof(oshpacket_route_t)) != 0)
    {
        logger(LOG_ERR, "%s: %s: Invalid %s size: %u bytes",
            node->addrw, node->id->name, oshpacket_type_name(pkt->type),
            pkt->payload_size);
        return false;
    }

    if (node->state_exg) {
        // Broadcast remote node's routes to our end of the network
        logger_debug(DBG_STATEEXG,
            "%s: %s: State exchange: Relaying ROUTE_ADD packet",
            node->addrw, node->id->name);
        node_queue_packet_broadcast(node, ROUTE_ADD, (uint8_t *) payload,
            pkt->payload_size);
    }

    memset(node_name, 0, sizeof(node_name));
    for (size_t i = 0; i < entries; ++i) {
        // Extract and verify the network address
        addr.type = payload[i].addr_type;
        if (addr.type > IP6) {
            logger(LOG_ERR, "%s: %s: Add route: Invalid address type",
                node->addrw, node->id->name);
            return false;
        }
        memcpy(addr.data, payload[i].addr_data, 16);

        // Extract and verify the node's name
        memcpy(node_name, payload[i].node_name, NODE_NAME_SIZE);
        if (!node_valid_name(node_name)) {
            logger(LOG_ERR, "%s: %s: Add route: Invalid name",
                node->addrw, node->id->name);
            return false;
        }

        // Make sure that the node exists
        if (!(id = node_id_find(node_name))) {
            logger(LOG_ERR, "%s: %s: Add route: Unknown node '%s'",
                node->addrw, node->id->name, node_name);
            return false;
        }

        // If we don't have a route to forward packets to the destination node,
        // continue processing the other routes skipping this one.
        if (!id->next_hop) {
            // We don't log route errors if they are local
            // In many scenarios we will get route broadcasts of our own routes,
            // we can ignore those silently
            netaddr_ntop(addr_str, sizeof(addr_str), &addr);
            if (id->local_node) {
                logger_debug(DBG_ROUTING, "%s: %s: Add route: Skipping local route %s",
                    node->addrw, node->id->name, addr_str);
            } else {
                logger(LOG_WARN, "%s: %s: Add route: %s -> %s: No route",
                    node->addrw, node->id->name, addr_str, node_name);
            }
            continue;
        }

        // Add a route to node_name for the network address
        if (logger_is_debugged(DBG_ROUTING)) {
            netaddr_ntop(addr_str, sizeof(addr_str), &addr);
            logger_debug(DBG_ROUTING, "%s: %s: Add route: %s -> %s", node->addrw,
                node->id->name, addr_str, id->name);
        }
        oshd_route_add(oshd.routes, &addr, id, true);
    }

    if (logger_is_debugged(DBG_ROUTING))
        oshd_route_dump(oshd.routes);
    return true;
}


// Process a packet from a node that is not authenticated yet
static bool oshd_process_unauthenticated(node_t *node, oshpacket_hdr_t *pkt,
    uint8_t *payload)
{
    switch (pkt->type) {
        case HANDSHAKE:
            return oshd_process_handshake(node, pkt,
                (oshpacket_handshake_t *) payload);

        case HELLO_CHALLENGE:
            return oshd_process_hello_challenge(node, pkt,
                (oshpacket_hello_challenge_t *) payload);

        case HELLO_RESPONSE:
            return oshd_process_hello_response(node, pkt,
                (oshpacket_hello_response_t *) payload);

        case HELLO_END:
            return oshd_process_hello_end(node, pkt,
                (oshpacket_hello_end_t *) payload);

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
        case HANDSHAKE:
            logger(LOG_ERR, "%s: %s: Handshake after authentication is not supported",
                node->addrw, node->id->name);
            return false;

        case HELLO_CHALLENGE:
        case HELLO_RESPONSE:
        case HELLO_END:
            logger(LOG_ERR, "%s: %s: Already authenticated but received %s",
                node->addrw, node->id->name, oshpacket_type_name(pkt->type));
            return false;

        case DEVMODE: {
            if (pkt->payload_size != sizeof(oshpacket_devmode_t)) {
                logger(LOG_ERR, "%s: %s: Invalid DEVMODE size: %u bytes",
                    node->addrw, node->id->name, pkt->payload_size);
                return false;
            }

            oshpacket_devmode_t *remote = (oshpacket_devmode_t *) payload;

            // If both nodes have a TUN/TAP device but don't use the same mode
            // they are incompatible
            if (   oshd.device_mode != MODE_NODEVICE
                && remote->devmode  != MODE_NODEVICE
                && remote->devmode  != oshd.device_mode)
            {
                logger(LOG_ERR, "%s: %s: Incompatible device modes (local: %s, remote: %s)",
                    node->addrw, node->id->name, device_mode_name(oshd.device_mode),
                    device_mode_name(remote->devmode));
                return node_queue_goodbye(node);
            }

            return true;
        }

        case STATEEXG_END:
            logger_debug(DBG_STATEEXG, "%s: %s: Finished state exchange",
                node->addrw, node->id->name);
            node->state_exg = false;
            return true;

        case GOODBYE:
            logger(LOG_INFO, "%s: %s: Gracefully disconnecting", node->addrw,
                node->id->name);
            return false;

        case PING: return node_queue_pong(node);
        case PONG: {
            if (!node->rtt_await) {
                logger(LOG_WARN, "%s: %s: Received unexpected PONG",
                    node->addrw, node->id->name);
                return true;
            }

            gettimeofday(&node->rtt_pong, NULL);
            timersub(&node->rtt_pong, &node->rtt_ping, &node->rtt_delta);
            node->rtt = (node->rtt_delta.tv_sec * 1000) + (node->rtt_delta.tv_usec / 1000);
            node->rtt_await = false;
            logger_debug(DBG_SOCKETS, "%s: %s: RTT %ims", node->addrw, node->id->name, node->rtt);

            return true;
        }

        case PUBKEY: {
            if (   pkt->payload_size == 0
                || pkt->payload_size % sizeof(oshpacket_pubkey_t) != 0)
            {
                logger(LOG_ERR, "%s: %s: Invalid PUBKEY size: %u bytes",
                    node->addrw, node->id->name, pkt->payload_size);
                return false;
            }

            if (node->state_exg) {
                // Broadcast the public keys to our end of the network
                logger_debug(DBG_STATEEXG,
                    "%s: %s: State exchange: Relaying PUBKEY packet",
                    node->addrw, node->id->name);
                node_queue_packet_broadcast(node, PUBKEY, payload,
                    pkt->payload_size);
            }

            size_t count = pkt->payload_size / sizeof(oshpacket_pubkey_t);
            oshpacket_pubkey_t *pubkeys = (oshpacket_pubkey_t *) payload;
            char node_name[NODE_NAME_SIZE + 1];
            memset(node_name, 0, sizeof(node_name));

            for (size_t i = 0; i < count; ++i) {
                memcpy(node_name, pubkeys[i].node_name, NODE_NAME_SIZE);
                if (!node_valid_name(node_name)) {
                    logger(LOG_ERR, "%s: %s: Public key: Invalid name", node->addrw,
                        node->id->name);
                    return false;
                }

                node_id_t *id = node_id_find(node_name);

                if (!id) {
                    logger(LOG_ERR, "%s: %s: Public key: Unknown node: %s",
                        node->addrw, node->id->name, node_name);
                    return false;
                }

                logger_debug(DBG_AUTHENTICATION, "%s: %s: Loading public key for %s",
                    node->addrw, node->id->name, node_name);
                if (!node_id_set_pubkey(id, pubkeys[i].node_pubkey,
                        sizeof(pubkeys[i].node_pubkey)))
                {
                    logger(LOG_ERR, "%s: %s: Failed to load public key for %s",
                        node->addrw, node->id->name, node_name);
                    return false;
                }
            }

            return true;
        }

        case ENDPOINT: {
            if (   pkt->payload_size == 0
                || pkt->payload_size % sizeof(oshpacket_endpoint_t) != 0)
            {
                logger(LOG_ERR, "%s: %s: Invalid ENDPOINT size: %u bytes",
                    node->addrw, node->id->name, pkt->payload_size);
                return false;
            }

            if (node->state_exg) {
                // Broadcast the endpoints to our end of the network
                logger_debug(DBG_STATEEXG,
                    "%s: %s: State exchange: Relaying ENDPOINT packet",
                    node->addrw, node->id->name);
                node_queue_packet_broadcast(node, ENDPOINT, payload,
                    pkt->payload_size);
            }

            size_t count = pkt->payload_size / sizeof(oshpacket_endpoint_t);
            oshpacket_endpoint_t *endpoints = (oshpacket_endpoint_t *) payload;
            char node_name[NODE_NAME_SIZE + 1];
            memset(node_name, 0, sizeof(node_name));

            for (size_t i = 0; i < count; ++i) {
                memcpy(node_name, endpoints[i].node_name, NODE_NAME_SIZE);
                if (!node_valid_name(node_name)) {
                    logger(LOG_ERR, "%s: %s: Endpoint: Invalid name",
                        node->addrw, node->id->name);
                    return false;
                }

                node_id_t *id = node_id_add(node_name);
                netaddr_t addr;
                netarea_t area;
                uint16_t hport;
                char hostname[INET6_ADDRSTRLEN];

                addr.type = endpoints[i].addr_type;
                memcpy(addr.data, endpoints[i].addr_data, 16);
                netaddr_ntop(hostname, sizeof(hostname), &addr);
                area = netaddr_area(&addr);
                hport = ntohs(endpoints[i].port);

                logger_debug(DBG_ENDPOINTS, "%s: %s: Adding %s endpoint %s:%u to %s",
                    node->addrw, node->id->name, netarea_name(area),
                    hostname, hport, id->name);
                endpoint_group_add(id->endpoints, hostname,
                    hport, area, true);
            }

            return true;
        }

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

            if (pkt->type == EDGE_ADD) {
                if (node->state_exg) {
                    // Broadcast remote node's edges to our end of the network
                    logger_debug(DBG_STATEEXG,
                        "%s: %s: State exchange: Relaying EDGE_ADD packet",
                        node->addrw, node->id->name);
                    node_queue_packet_broadcast(node, EDGE_ADD, payload,
                        pkt->payload_size);
                }

                success = oshd_process_edge(node, pkt,
                    (oshpacket_edge_t *) payload, true);
            } else {
                success = oshd_process_edge(node, pkt,
                    (oshpacket_edge_t *) payload, false);
            }
            node_tree_update();
            return success;
        }

        case ROUTE_ADD:
            return oshd_process_route(node, pkt, (oshpacket_route_t *) payload);

        case DATA: {
            if (!oshd.tuntap)
                return true;

            netpacket_t netpkt;

            if (!netpacket_from_data(&netpkt, payload, oshd.tuntap->is_tap)) {
                logger(LOG_ERR, "%s: %s: Failed to decode received tunnel packet",
                    node->addrw, node->id->name);
                return false;
            }

            if (logger_is_debugged(DBG_TUNTAP)) {
                char netpkt_src[INET6_ADDRSTRLEN];
                char netpkt_dest[INET6_ADDRSTRLEN];

                netaddr_ntop(netpkt_src, sizeof(netpkt_src), &netpkt.src);
                netaddr_ntop(netpkt_dest, sizeof(netpkt_dest), &netpkt.dest);
                logger_debug(DBG_TUNTAP, "%s: %s: %s <- %s (%u bytes, from %s)",
                    node->addrw, node->id->name, netpkt_dest, netpkt_src,
                    pkt->payload_size, src_node->name);
            }

            return tuntap_write(oshd.tuntap, payload, pkt->payload_size);
        }

        default:
            logger(LOG_ERR, "%s: %s: Received invalid packet type: 0x%X",
                node->addrw, node->id->name, pkt->type);
            return false;

    }
}

// Returns true if packet was processed without an error
// Returns false if node should be disconnected
bool oshd_process_packet(node_t *node, uint8_t *packet)
{
    oshpacket_hdr_t *hdr = (oshpacket_hdr_t *) packet;
    uint8_t *payload = packet + OSHPACKET_HDR_SIZE;

    // If we have a recv_cipher, the private header and payload are encrypted,
    // so we need to decrypt it before we can process the data
    if (node->recv_cipher) {
        const size_t encrypted_size = OSHPACKET_PRIVATE_HDR_SIZE + hdr->payload_size;
        size_t decrypted_size;

        logger_debug(DBG_ENCRYPTION, "%s: Decrypting packet of %zu bytes",
            node->addrw, encrypted_size);

        // We decrypt packet at the same location because overlapping streams
        // are supported for AES-256-CTR
        // TODO: If the cipher does not support this, decrypt in a temporary
        //       buffer and then copy the decrypted data back in the recvbuf
        if (!cipher_decrypt(node->recv_cipher,
                packet + OSHPACKET_PUBLIC_HDR_SIZE, &decrypted_size,
                packet + OSHPACKET_PUBLIC_HDR_SIZE, encrypted_size))
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
    hdr->counter = ntohl(hdr->counter);

    // Verify that the remote node's send_counter matches our recv_counter
    // This is to prevent replay attacks
    // If the counter is not correct then we drop the connection
    if (node->recv_counter != hdr->counter) {
        logger(LOG_CRIT, "%s: Invalid counter: Expected %u but got %u",
            node->addrw, node->recv_counter, hdr->counter);
        return false;
    }

    // The counter is correct, increment it for the next packet
    node->recv_counter += 1;

    // If the node is unauthenticated we only accept authentication packets,
    // nothing else will be accepted or forwarded, if the authentication encounters
    // an error the connection is terminated
    if (!node->authenticated)
        return oshd_process_unauthenticated(node, hdr, payload);

    // If the source or destination nodes don't exist in the tree the remote
    // node sent us invalid data, we drop the connection
    node_id_t *src = node_id_find(hdr->src_node);
    if (!src) {
        logger(LOG_ERR, "%s: %s: Unknown source node", node->addrw, node->id->name);
        return false;
    }

    node_id_t *dest = node_id_find(hdr->dest_node);
    if (!dest) {
        logger(LOG_ERR, "%s: %s: Unknown destination node", node->addrw, node->id->name);
        return false;
    }

    // If the destination node is not the local node we'll forward this packet
    if (!dest->local_node) {
        if (hdr->type <= PONG) {
            logger(LOG_WARN, "Dropping %s packet from %s to %s: This type of packet cannot be forwarded",
                oshpacket_type_name(hdr->type), src->name, dest->name);
            return true;
        }

        if (dest->next_hop) {
            logger_debug(DBG_ROUTING, "Forwarding %s packet from %s to %s through %s",
                oshpacket_type_name(hdr->type), src->name, dest->name, dest->next_hop->id->name);
            node_queue_packet_forward(dest->next_hop, hdr);
        } else {
            logger(LOG_INFO, "Dropping %s packet from %s to %s: No route",
                oshpacket_type_name(hdr->type), src->name, dest->name);
        }
        return true;
    }

    // Otherwise the packet is for us
    return oshd_process_authenticated(node, hdr, payload, src);
}