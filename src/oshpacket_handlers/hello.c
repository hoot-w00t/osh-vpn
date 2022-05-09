#include "oshd.h"
#include "logger.h"
#include <string.h>

bool oshpacket_handler_hello_challenge(node_t *node, oshpacket_hdr_t *hdr,
    void *payload)
{
    char name[NODE_NAME_SIZE + 1];

    memset(name, 0, sizeof(name));
    memcpy(name, hdr->src_node, NODE_NAME_SIZE);
    if (!node_valid_name(name)) {
        logger(LOG_ERR, "%s: Authentication failed: Invalid name", node->addrw);
        return node_queue_hello_end(node);
    }

    node_id_t *id = node_id_find(name);

    if (!id) {
        // We don't know this node so we can't authenticate it
        logger(LOG_ERR, "%s: Authentication failed: Unknown node %s",
            node->addrw, name);
        return node_queue_hello_end(node);
    }

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

bool oshpacket_handler_hello_response(node_t *node, __attribute__((unused)) oshpacket_hdr_t *hdr,
    void *payload)
{
    const oshpacket_hello_response_t *packet = (const oshpacket_hello_response_t *) payload;

    if (!node->hello_chall) {
        // If we don't have a hello_chall packet, authentication cannot proceed
        logger(LOG_ERR, "%s: Received HELLO_RESPONSE but no HELLO_CHALLENGE was sent",
            node->addrw);
        return node_queue_hello_end(node);
    }

    if (!node->hello_id) {
        // If there is no hello_id, authentication cannot proceed either
        logger(LOG_ERR, "%s: Received HELLO_RESPONSE but the node is unknown",
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
        packet->sig, sizeof(packet->sig));

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

    // After authenticating we should always have the initial handshake packet
    // We must verify the signature to prevent MITM attacks
    if (node->unauth_handshake) {
        node->hello_auth = pkey_verify(node->hello_id->pubkey,
            node->unauth_handshake->keys.both, sizeof(node->unauth_handshake->keys.both),
            node->unauth_handshake->sig, sizeof(node->unauth_handshake->sig));
    } else {
        node->hello_auth = false;
    }

    free(node->unauth_handshake);
    node->unauth_handshake = NULL;

    if (!node->hello_auth) {
        logger(LOG_ERR,
            "%s: %s: Handshake signature verification failed",
            node->addrw, node->hello_id->name);
        return node_queue_hello_end(node);
    }
    logger_debug(DBG_HANDSHAKE, "%s: %s: Valid handshake signature",
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

bool oshpacket_handler_hello_end(node_t *node, __attribute__((unused)) oshpacket_hdr_t *hdr,
    void *payload)
{
    const oshpacket_hello_end_t *packet = (const oshpacket_hello_end_t *) payload;

    if (!node->hello_auth || !packet->hello_success) {
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