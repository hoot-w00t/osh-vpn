#include "oshd.h"
#include "logger.h"

// Returns true if the client's handshake_id is already authenticated on another
// direct connection
static bool already_has_another_connection(client_t *c)
{
    logger_debug(DBG_HANDSHAKE, "%s: Checking for other direct connections", c->addrw);

    // If we already have another direct connection with this node we will keep
    // it and disconnect this client
    if (c->handshake_id->node_socket && c->handshake_id->node_socket != c) {
        logger(LOG_WARN, "%s: Another socket is already authenticated as %s (%s)",
            c->addrw, c->handshake_id->name, c->handshake_id->node_socket->addrw);

        // If the node has some reconnection endpoints we will transfer those to
        // the existing connection to prevent duplicate connections (which would
        // be refused by the remote node while the other socket is connected)
        if (c->reconnect_endpoints) {
            // Add this client's reconnection endpoints to the other node's
            logger(LOG_INFO, "%s: Moving reconnection endpoints to %s (%s)",
                c->addrw,
                c->handshake_id->name,
                c->handshake_id->node_socket->addrw);
            endpoint_group_add_group(c->handshake_id->endpoints,
                c->reconnect_endpoints);

            // Disable reconnection for this client
            client_reconnect_disable(c);
        }
        return true;
    }
    return false;
}

// Finish the handshake and authenticate the client
static void finish_authentication(client_t *c)
{
    node_id_t *me = node_id_find_local();

    logger_debug(DBG_HANDSHAKE, "%s: Finishing authentication", c->addrw);

    // Mark the client as authenticated
    c->authenticated = c->handshake_valid_signature;
    c->id = c->handshake_id;
    c->id->node_socket = c;

    // Finish the handshake
    client_finish_handshake(c);

    // Add the new connection with the other node
    node_id_add_edge(me, c->id);
    node_tree_update();

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

    logger(LOG_INFO, "%s: %s: Authenticated successfully", c->addrw, c->id->name);
}

static bool queue_state_exchange(client_t *c)
{
    // Make sure that our device modes are compatible
    if (!client_queue_devmode(c))
        return false;

    // Advertise the new connection between us and the other node to our part of
    // the mesh (followed by its public key)
    if (!client_queue_edge_broadcast(c, EDGE_ADD, oshd.name, c->id->name))
        return false;
    if (!client_queue_pubkey_broadcast(c, c->id))
        return false;

    const size_t sendq_size_before_exg = netbuffer_data_size(c->io.sendq);

    // Broadcast all the information we know about the mesh to the other node
    // This syncs both nodes' maps of the mesh along with other relevant
    // information (routes, endpoints, etc)
    // TODO: If both nodes share a common edge this could be skipped as all the
    //       information should already be synced to other nodes
    if (!client_queue_edge_exg(c))
        return false;
    if (!client_queue_route_exg(c))
        return false;
    if (!client_queue_pubkey_exg(c))
        return false;
    if (!client_queue_endpoint_exg(c))
        return false;

    const size_t sendq_size_after_exg = netbuffer_data_size(c->io.sendq);

    logger_debug(DBG_STATEEXG, "%s: %s: Queued %zu bytes",
        c->addrw, c->id->name, sendq_size_after_exg - sendq_size_before_exg);

    // Update the client's latency
    return client_queue_ping(c);
}

// Swap all network byte order values in the payload to host byte order
static void hello_ntoh(oshpacket_hello_t *hello)
{
    hello->options = ntohl(hello->options);
}

bool oshpacket_handler_hello(client_t *c,
    __attribute__((unused)) oshpacket_hdr_t *hdr, void *payload)
{
    const oshpacket_hello_t *hello = (const oshpacket_hello_t *) payload;

    // Make sure that the handshake is in progress
    if (!c->handshake_in_progress || !c->handshake_id) {
        logger(LOG_ERR, "%s: Received HELLO but the handshake is not in progress", c->addrw);
        return false;
    }

    // If we were not able to verify the other node's signature, it either means
    // that we failed this step, or that the other node skipped sending us the
    // handshake signature
    // Either way we could not authenticate the remote node
    if (!c->handshake_valid_signature) {
        logger(LOG_ERR, "%s: Failed to authenticate the remote node", c->addrw);
        return false;
    }
    logger_debug(DBG_HANDSHAKE, "%s: Successfully authenticated the remote node", c->addrw);

    // Convert the payload values to host byte order
    hello_ntoh((oshpacket_hello_t *) payload);

    logger_debug(DBG_HANDSHAKE, "%s: Remote options 0x%08X", c->addrw, hello->options);

    // At this point both nodes have authenticated

    // Check if we already have another direct connection to this node, if we do
    // this connection will be closed
    if (already_has_another_connection(c))
        return false;

    finish_authentication(c);

    return queue_state_exchange(c);
}
