#include "oshd.h"
#include "events.h"
#include "logger.h"

// Regularly try to establish connections to nodes to which we don't have a
// direct connection
// If ConnectionsLimit is set, automatic connections will always leave enough
// slots for the endpoints in the configuration

// TODO: Work more on this

// Calculates the maximum connections to queue at most in one iteration
static size_t automatic_connections_remaining(size_t max_tries)
{
    const size_t target_connections = ((oshd.node_tree_count - 1) * oshd.automatic_connections_percent) / 100;

    // If we have more active connections than required, we don't need any more
    // automatic connections
    // TODO: Maybe only count authenticated sockets as active connections
    if (oshd.clients_count >= target_connections)
        return 0;

    // Otherwise we calculate how many connections we should establish to reach
    // the target percentage
    size_t remaining_tries = target_connections - oshd.clients_count;

    // If connections are limited, make sure to always leave enough slots for
    // the endpoints from the configuration file
    if (oshd.clients_count_max != 0) {
        if (oshd.conf_endpoints_count >= oshd.clients_count_max)
            return 0;
        else
            remaining_tries = oshd.clients_count_max - oshd.conf_endpoints_count;
    }

    // Make sure to not exceed the maximum amount of tries
    if (remaining_tries > max_tries)
        remaining_tries = max_tries;

    return remaining_tries;
}

// Calculates the total amount of time (in seconds) it can take to connect to
// every endpoint of every node on the network
static time_t automatic_connections_next_retry_delay(void)
{
    const size_t tree_count = oshd.node_tree_count - 1;
    const time_t max_ep_delay = oshd.reconnect_delay_max + HANDSHAKE_TIMEOUT;
    time_t delay = 0;

    // Sum the maximum delay for all endpoints in the tree
    for (size_t i = 0; i < tree_count; ++i)
        delay += max_ep_delay * oshd.node_tree[i]->endpoints->count;

    // Add an approximation of the automatic connections interval after trying
    // to connect to all nodes on the tree
    delay += oshd.automatic_connections_interval * (tree_count / 5);

    return delay;
}

// Automatic connections try to connect to more nodes on the tree at a given
// interval (1 hour by default) until enough connections are established
// (50% of the nodes in the tree by default)
// It will try to establish at most 5 connections in one iteration, this is to
// prevent queuing thousands of connections at once
// After trying to automatically connect to a node there will be a delay before
// the next try for this node, it should be long enough to let every node in the
// tree get an automatic connection (this also prevents queuing too many
// connections at once, but it should also prevent cases where some nodes would
// never be automatically connected because others don't have a long enough
// retry delay)
static time_t automatic_connections_handler(__attribute__((unused)) void *data)
{
    const time_t next_retry_delay = automatic_connections_next_retry_delay();
    size_t remaining_tries = automatic_connections_remaining(5);
    struct timespec now;
    struct timespec delta;

    logger_debug(DBG_ENDPOINTS, "Automatic connections (%zu at most, retry delay: %li seconds)",
        remaining_tries, next_retry_delay);
    oshd_gettime(&now);
    for (size_t i = 0; i < oshd.node_tree_count && remaining_tries > 0; ++i) {
        node_id_t *id = oshd.node_tree_ordered_hops[i];

        // Of course we won't try to connect to ourselves
        if (id->local_node)
            continue;

        // If the node has no direct connection but has at least one endpoint
        // and does not always retries to connect, then this is the only way to
        // try to initiate a direct connection to it
        // We set a delay before retrying to automatically initiate a connection
        // to it

        // The delta will be positive when enough time has elapsed
        timespecsub(&now, &id->endpoints_next_retry, &delta);

        if (   !id->node_socket
            && !node_connect_in_progress(id)
            && !endpoint_group_is_empty(id->endpoints)
            &&  node_has_trusted_pubkey(id)
            &&  delta.tv_sec >= 0)
        {
            logger(LOG_INFO, "Automatically connecting to %s", id->name);

            // Set the delay before trying to automatically connect to this node
            // again
            oshd_gettime(&id->endpoints_next_retry);
            id->endpoints_next_retry.tv_sec += next_retry_delay;
            node_connect(id, true);
            remaining_tries -= 1;
        }
    }

    return EVENT_QUEUE_IN_S(oshd.automatic_connections_interval);
}

// Queue a periodic event that will try to establish new connections
// automatically
void event_queue_automatic_connections(void)
{
    event_queue_in(
        event_create(
            "automatic_connections",
            automatic_connections_handler,
            NULL,
            NULL),
        oshd.automatic_connections_interval);
}
