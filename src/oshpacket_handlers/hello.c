#include "oshd.h"
#include "logger.h"
#include <string.h>

bool oshpacket_handler_hello_challenge(client_t *c, oshpacket_hdr_t *hdr,
    void *payload)
{
    char name[NODE_NAME_SIZE + 1];

    memset(name, 0, sizeof(name));
    memcpy(name, hdr->src_node, NODE_NAME_SIZE);
    if (!node_valid_name(name)) {
        logger(LOG_ERR, "%s: Authentication failed: Invalid name", c->addrw);
        return client_queue_hello_end(c);
    }

    node_id_t *id = node_id_find(name);

    if (!id) {
        // We don't know this node so we can't authenticate it
        logger(LOG_ERR, "%s: Authentication failed: Unknown node %s",
            c->addrw, name);
        return client_queue_hello_end(c);
    }

    if (id->local_node) {
        // Disconnect the client if it tries to authenticate as our local node
        logger(LOG_ERR, "%s: Authentication failed: Tried to authenticate as myself",
            c->addrw);
        return client_queue_hello_end(c);
    }

    c->hello_id = id;

    uint8_t *sig;
    size_t sig_size;
    oshpacket_hello_response_t response;

    // Sign the challenge using our private key
    logger_debug(DBG_AUTHENTICATION, "%s: %s: Signing challenge",
        c->addrw, c->hello_id->name);
    if (!pkey_sign(oshd.privkey,
                   (uint8_t *) payload, sizeof(oshpacket_hello_challenge_t),
                   &sig, &sig_size))
    {
        logger(LOG_ERR, "%s: %s: Failed to sign the HELLO challenge",
            c->addrw, c->hello_id->name);
        return client_queue_hello_end(c);
    }

    // Make sure that the signature size is the same as the response packet expects
    if (sig_size != sizeof(response.sig)) {
        free(sig);
        logger(LOG_ERR, "%s: %s: Signature size is invalid (%zu bytes)",
            c->addrw, c->hello_id->name, sig_size);
        return client_queue_hello_end(c);
    }

    // Initialize and queue the response packet
    memcpy(response.sig, sig, sizeof(response.sig));
    free(sig);

    return client_queue_packet(c, NULL, HELLO_RESPONSE, &response,
        sizeof(oshpacket_hello_response_t));
}

bool oshpacket_handler_hello_response(client_t *c, __attribute__((unused)) oshpacket_hdr_t *hdr,
    void *payload)
{
    const oshpacket_hello_response_t *packet = (const oshpacket_hello_response_t *) payload;

    if (!c->hello_chall) {
        // If we don't have a hello_chall packet, authentication cannot proceed
        logger(LOG_ERR, "%s: Received HELLO_RESPONSE but no HELLO_CHALLENGE was sent",
            c->addrw);
        return client_queue_hello_end(c);
    }

    if (!c->hello_id) {
        // If there is no hello_id, authentication cannot proceed either
        logger(LOG_ERR, "%s: Received HELLO_RESPONSE but the node is unknown",
            c->addrw);
        return client_queue_hello_end(c);
    }

    if (!c->hello_id->pubkey) {
        // If we don't have a public key to verify the HELLO signature,
        // we can't authenticate the node
        logger(LOG_ERR, "%s: Authentication failed: No public key for %s",
            c->addrw, c->hello_id->name);
        return client_queue_hello_end(c);
    }

    // If the public key is local we will always use it, but if it is a remote
    // key and remote authentication is not authorized then we can't
    // authenticate the node
    if (!c->hello_id->pubkey_local && !oshd.remote_auth) {
        logger(LOG_ERR, "%s: Authentication failed: No local public key for %s",
            c->addrw, c->hello_id->name);
        return client_queue_hello_end(c);
    }

    logger_debug(DBG_AUTHENTICATION, "%s: %s has a %s public key",
        c->addrw, c->hello_id->name,
        c->hello_id->pubkey_local ? "local" : "remote");

    // If the signature verification succeeds then the node is authenticated
    logger_debug(DBG_AUTHENTICATION, "%s: Verifying signature from %s",
        c->addrw, c->hello_id->name);
    c->hello_auth = pkey_verify(c->hello_id->pubkey,
        (uint8_t *) c->hello_chall, sizeof(oshpacket_hello_challenge_t),
        packet->sig, sizeof(packet->sig));

    // If the node is not authenticated, the signature verification failed
    // The remote node did not sign the data using the private key
    // associated with the public key we have
    if (!c->hello_auth) {
        logger(LOG_ERR, "%s: Authentication failed: Failed to verify signature from %s",
            c->addrw, c->hello_id->name);
        return client_queue_hello_end(c);
    }
    logger_debug(DBG_AUTHENTICATION, "%s: Valid signature from %s",
        c->addrw, c->hello_id->name);

    // After authenticating we should always have the initial handshake packet
    // We must verify the signature to prevent MITM attacks
    if (c->unauth_handshake) {
        c->hello_auth = pkey_verify(c->hello_id->pubkey,
            c->unauth_handshake->keys.both, sizeof(c->unauth_handshake->keys.both),
            c->unauth_handshake->sig, sizeof(c->unauth_handshake->sig));
    } else {
        c->hello_auth = false;
    }

    free(c->unauth_handshake);
    c->unauth_handshake = NULL;

    if (!c->hello_auth) {
        logger(LOG_ERR,
            "%s: %s: Handshake signature verification failed",
            c->addrw, c->hello_id->name);
        return client_queue_hello_end(c);
    }
    logger_debug(DBG_HANDSHAKE, "%s: %s: Valid handshake signature",
        c->addrw, c->hello_id->name);

    if (c->hello_id->node_socket) {
        // Disconnect the client if the node is already authenticated
        logger(LOG_WARN, "%s: Another socket is already authenticated as %s",
            c->addrw, c->hello_id->name);

        // This client should not be used
        c->hello_auth = false;

        // If the node has some reconnection endpoints we will transfer those to
        // the existing connection to prevent duplicate connections (which would
        // be refused by the remote node while the other socket is connected)
        if (c->reconnect_endpoints) {
            // Add this client's reconnection endpoints to the other node's
            logger(LOG_INFO, "%s: Moving reconnection endpoints to %s (%s)",
                c->addrw,
                c->hello_id->name,
                c->hello_id->node_socket->addrw);
            endpoint_group_add_group(c->hello_id->endpoints,
                c->reconnect_endpoints);

            // Disable reconnection for this client
            client_reconnect_disable(c);
        }
        return client_queue_hello_end(c);
    }
    return client_queue_hello_end(c);
}

bool oshpacket_handler_hello_end(client_t *c, __attribute__((unused)) oshpacket_hdr_t *hdr,
    void *payload)
{
    const oshpacket_hello_end_t *packet = (const oshpacket_hello_end_t *) payload;

    if (!c->hello_auth || !packet->hello_success) {
        logger(LOG_ERR, "%s: Authentication did not succeed on both nodes",
            c->addrw);
        return c->finish_and_disconnect;
    }

    node_id_t *me = node_id_find_local();

    // The remote node is now authenticated

    c->authenticated = c->hello_auth;
    c->id = c->hello_id;
    c->id->node_socket = c;

    // After successful authentication we can consider that the reconnection
    // succeeded, reset the reconnection delay
    client_reconnect_delay(c, oshd.reconnect_delay_min);

    // Merge endpoints if the client's endpoints group is not the same as the node ID's
    if (   c->reconnect_endpoints
        && c->reconnect_endpoints != c->id->endpoints)
    {
        endpoint_group_add_group(c->id->endpoints, c->reconnect_endpoints);
    }

    // Always attach this socket's reconnection addresses to its node ID's
    // endpoints
    client_reconnect_to(c, c->id->endpoints, oshd.reconnect_delay_min);

    // We are no longer actively trying to connect to these endpoints
    endpoint_group_set_is_connecting(c->id->endpoints, false);

    if (c->id->next_hop) {
        logger_debug(DBG_STATEEXG, "%s: %s: Previously accessible through %s (%s)",
            c->addrw, c->id->name,
            c->id->next_hop->id->name, c->id->next_hop->addrw);
    }

    // Cleanup the temporary hello variables
    c->hello_id = NULL;
    free(c->hello_chall);
    c->hello_chall = NULL;

    node_id_add_edge(me, c->id);
    node_tree_update();

    logger(LOG_INFO, "%s: %s: Authenticated successfully", c->addrw,
        c->id->name);

    logger_debug(DBG_STATEEXG, "%s: %s: Starting state exchange",
        c->addrw, c->id->name);
    c->state_exg = true;

    // Make sure that we are our device modes are compatible
    if (!client_queue_devmode(c))
        return false;

    logger_debug(DBG_STATEEXG, "%s: %s: Exchanging local state",
        c->addrw, c->id->name);

    // We exchange our network map
    if (!client_queue_edge_exg(c))
        return false;

    // We exchange all known network routes
    if (!client_queue_route_exg(c))
        return false;

    // We exchange all known public keys of the nodes that are online
    if (!client_queue_pubkey_exg(c))
        return false;

    // We exchange all known endpoints
    if (!client_queue_endpoint_exg(c))
        return false;

    // We finished queuing our state exchange packets
    if (!client_queue_stateexg_end(c))
        return false;

    // We broadcast the new connection to our end of the network
    if (!client_queue_edge_broadcast(c, EDGE_ADD, oshd.name, c->id->name))
        return false;

    // We broadcast the remote node's public key to our end of the network
    if (!client_queue_pubkey_broadcast(c, c->id))
        return false;

    // Update the client's latency
    return client_queue_ping(c);
}
