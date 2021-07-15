#include "oshd.h"
#include "oshd_discovery.h"
#include "oshd_socket.h"
#include "events.h"
#include "logger.h"
#include "xalloc.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

static event_t *event_queue_head = NULL;

// Get the current time in *tv and add delay (in seconds) to it in *tv
static void tv_delay(struct timeval *tv, time_t delay)
{
    gettimeofday(tv, NULL);
    tv->tv_sec += delay;
}

// Return an allocated event_t
static event_t *event_create(event_handler_t handler, event_freedata_t freedata,
    void *data, const struct timeval *trigger, time_t periodic_delay)
{
    event_t *event = xzalloc(sizeof(event_t));

    event->handler = handler;
    event->data = data;
    event->freedata = freedata;
    memcpy(&event->trigger, trigger, sizeof(struct timeval));
    strftime(event->trigger_fmt, sizeof(event->trigger_fmt), "%Y-%m-%d %H:%M:%S",
        localtime(&event->trigger.tv_sec));
    event->periodic_delay = periodic_delay;
    return event;
}

// Free *event and its resources
static void event_free(event_t *event)
{
    if (event->freedata)
        event->freedata(event->data, event->handled);
    free(event);
}

// Queue *event
static void event_queue(event_t *event)
{
    event_t **i = &event_queue_head;

    if (event->handled) {
        logger_debug(DBG_EVENTS, "Re-queuing event %p at %s", event,
            event->trigger_fmt);
    } else {
        logger_debug(DBG_EVENTS, "Queuing event %p at %s", event,
            event->trigger_fmt);
    }

    // We will keep the event queue sorted by the trigger time of the events
    // The events must be sorted from the fastest to trigger to the longest
    while (*i) {
        // If our event triggers before the one we are checking, we insert it
        // here
        if (event->trigger.tv_sec < (*i)->trigger.tv_sec)
            break;

        // Otherwise we iterate until the end of the queue
        i = &(*i)->next;
    }

    // If *i is NULL we are either on the head or the tail of the queue, there
    // are no other events in the queue
    // Otherwise the our event's next will point to the next event in the queue
    // Otherwise we also have to set the the next event to the previous one
    event->next = *i;
    *i = event;
}

// Re-queue a handled event using its periodic delay
static void event_requeue(event_t *event)
{
    tv_delay(&event->trigger, event->periodic_delay);
    strftime(event->trigger_fmt, sizeof(event->trigger_fmt), "%Y-%m-%d %H:%M:%S",
        localtime(&event->trigger.tv_sec));
    event_queue(event);
}

// Process all events in the event queue that should trigger
void event_process_queued(void)
{
    event_t *event;
    struct timeval now;

    // Get the current time to compare with the triggers
    gettimeofday(&now, NULL);

    // We will process events while there are some in the queue
    while (event_queue_head) {
        // The event queue is sorted by trigger time, so whenever the next
        // event is not triggered yet, no other events will trigger
        // So we can stop now
        if (now.tv_sec < event_queue_head->trigger.tv_sec)
            break;

        event = event_queue_head;

        // Move the event queue to the next event
        event_queue_head = event->next;

        // Handle the current event
        logger_debug(DBG_EVENTS, "Processing event %p queued at %s",
            event, event->trigger_fmt);
        event->handler(event->data);
        event->handled = true;

        if (event->periodic_delay > 0) {
            event_requeue(event);
        } else {
            event_free(event);
        }
    }
}

// Cancel all events in the queue
void event_cancel_queue(void)
{
    event_t *i = event_queue_head;
    event_t *next;

    // Iterate over the entire event queue and free everything
    while (i) {
        next = i->next;
        event_free(i);
        i = next;
    }

    // The queue was entirely freed, now we can mark it as empty
    event_queue_head = NULL;
}

// Cancel a single event from the queue, if the event is not queued nothing is
// done
void event_cancel(event_t *event)
{
    event_t **i = &event_queue_head;

    // We will loop through all the queued events until we find the one we want
    // to cancel
    while (*i) {
        if ((*i) == event) {
            // We found the event to cancel
            logger_debug(DBG_EVENTS, "Canceling event %p at %s", event,
                event->trigger_fmt);

            // Replace the next event pointed to by i to the one that will come
            // after and then free the canceled event
            *i = (*i)->next;
            event_free(event);
            return;
        }

        // Otherwise we iterate until the end of the queue
        i = &(*i)->next;
    }

    // If we get here the event could not be found, this should not happen
    logger(LOG_ERR, "Failed to cancel event %p at %s: It was not found in the queue",
        event, event->trigger_fmt);
}

// Queue connect event
typedef struct connect_event_data {
    endpoint_group_t *endpoints;
    time_t delay;
} connect_event_data_t;

static void connect_event_freedata(void *data,
    __attribute__((unused)) bool handled)
{
    connect_event_data_t *e_data = (connect_event_data_t *) data;

    free(e_data);
}

static void connect_event_handler(void *data)
{
    connect_event_data_t *e_data = (connect_event_data_t *) data;

    oshd_connect_queue(e_data->endpoints, e_data->delay);
}

void event_queue_connect(endpoint_group_t *endpoints, time_t delay,
    time_t event_delay)
{
    struct timeval trigger;
    endpoint_t *endpoint;
    connect_event_data_t *data = xalloc(sizeof(connect_event_data_t));

    tv_delay(&trigger, event_delay);
    data->endpoints = endpoints;
    data->delay = delay;

    // If there is a delay for this connection then it is a reconnection
    endpoint = endpoint_group_selected_ep(data->endpoints);
    if (event_delay > 0 && endpoint) {
        logger(LOG_INFO, "Retrying to connect to %s:%u in %li seconds",
            endpoint->hostname, endpoint->port, delay);
    }

    event_queue(event_create(connect_event_handler, connect_event_freedata,
        data, &trigger, EVENT_TRIGGER_ONCE));
}


// Periodically ping direct nodes
static void periodic_ping_event_handler(__attribute__((unused)) void *data)
{
    for (size_t i = 0; i < oshd.nodes_count; ++i) {
        if (oshd.nodes[i]->authenticated)
            node_queue_ping(oshd.nodes[i]);
    }
}

// This function should only be called once outside of the event handler
void event_queue_periodic_ping(void)
{
    const time_t ping_delay = 30;
    struct timeval trigger;

    tv_delay(&trigger, ping_delay);
    event_queue(event_create(periodic_ping_event_handler, NULL,
        NULL, &trigger, ping_delay));
}


// Queue node add event
static void node_add_event_freedata(void *data, bool handled)
{
    if (!handled) {
        // If the node wasn't added to the list, we have to destroy it
        // Otherwise it will be lost in memory
        node_destroy((node_t *) data);
    }
}

static void node_add_event_handler(void *data)
{
    node_t *node = (node_t *) data;

    if (oshd_nodes_limited()) {
        logger(LOG_WARN, "Simultaneous connections limited to %zu, disconnecting %s",
            oshd.nodes_count_max, node->addrw);
        node_destroy(node);
    } else {
        oshd.nodes = xreallocarray(oshd.nodes, oshd.nodes_count + 1, sizeof(node_t *));
        oshd.nodes[oshd.nodes_count] = node;
        oshd.nodes_count += 1;
        oshd.nodes_updated = true;
    }
}

void event_queue_node_add(node_t *node)
{
    struct timeval trigger;

    // Always trigger when processing the event queue
    memset(&trigger, 0, sizeof(trigger));
    event_queue(event_create(node_add_event_handler, node_add_event_freedata,
        node, &trigger, EVENT_TRIGGER_ONCE));
}


// Queue node remove event
static void node_remove_event_handler(void *data)
{
    node_t *node = (node_t *) data;
    size_t i;

    for (i = 0; i < oshd.nodes_count && oshd.nodes[i] != node; ++i);

    // If the node doesn't exist in the list, stop here
    // It was probably already freed elsewhere
    if (i >= oshd.nodes_count)
        return;

    node_destroy(node);
    for (; i + 1 < oshd.nodes_count; ++i)
        oshd.nodes[i] = oshd.nodes[i + 1];
    oshd.nodes_count -= 1;
    oshd.nodes = xreallocarray(oshd.nodes, oshd.nodes_count, sizeof(node_t *));
    oshd.nodes_updated = true;
}

static void node_remove_event_freedata(void *data, bool handled)
{
    if (!handled) {
        node_add_event_handler(data);
    }
}

void event_queue_node_remove(node_t *node)
{
    struct timeval trigger;

    if (node->remove_queued) {
        logger(LOG_WARN, "node_remove event for %p is already queued", node);
        return;
    }
    node->remove_queued = true;

    // Always trigger when processing the event queue
    memset(&trigger, 0, sizeof(trigger));
    event_queue(event_create(node_remove_event_handler,
        node_remove_event_freedata, node, &trigger, EVENT_TRIGGER_ONCE));
}


// Queue node authentication timeout event
static void node_auth_timeout_event_handler(void *data)
{
    node_t *node = (node_t *) data;

    if (!node->authenticated) {
        if (node->connected) {
            logger(LOG_WARN, "%s: Authentication timed out", node->addrw);
        } else {
            logger(LOG_WARN, "%s: Timed out", node->addrw);
        }
        node->auth_timeout_event = NULL;
        event_queue_node_remove(node);
    }
}

static void node_auth_timeout_event_freedata(void *data,
    __attribute__((unused)) bool handled)
{
    ((node_t *) data)->auth_timeout_event = NULL;
}

void event_queue_node_auth_timeout(node_t *node, time_t timeout_delay)
{
    struct timeval trigger;
    event_t *event;

    tv_delay(&trigger, timeout_delay);
    event = event_create(node_auth_timeout_event_handler,
        node_auth_timeout_event_freedata, node, &trigger, EVENT_TRIGGER_ONCE);
    node->auth_timeout_event = event;
    event_queue(event);
}


// Periodically refresh endpoints from the node tree
// Clear endpoints that timed out and
static void endpoints_refresh_event_handler(__attribute__((unused)) void *data)
{
    const time_t expiry_delay = 3600; // 60 minutes
    struct timeval now;
    time_t delta;
    node_id_t *id;

    logger_debug(DBG_ENDPOINTS, "Refreshing expired endpoints");
    gettimeofday(&now, NULL);
    for (size_t i = 0; i < oshd.node_tree_count; ++i) {
        id = oshd.node_tree[i];

        delta = now.tv_sec - id->endpoints_last_update.tv_sec;
        if (delta < expiry_delay)
            continue;

        if (id->local_node) {
            if (oshd.shareendpoints) {
                logger_debug(DBG_ENDPOINTS, "Refreshing local endpoints");
                oshd_discover_local_endpoints();
                node_queue_local_endpoint_broadcast(NULL);
            }
        } else {
            node_id_expire_endpoints(id);
        }
    }
}

// This function should only be called once outside of the event handler
void event_queue_endpoints_refresh(void)
{
    const time_t endpoints_delay = 600; // 10 minutes
    struct timeval trigger;

    tv_delay(&trigger, endpoints_delay);
    event_queue(event_create(endpoints_refresh_event_handler, NULL,
        NULL, &trigger, endpoints_delay));
}

// Regularly try to establish connections to nodes to which we don't have a
// direct connection
// If ConnectionsLimit is set, automatic connections will always leave enough
// slots for the remotes in the configuration

// Calculates the maximum connections to queue at most in one iteration
static size_t automatic_connections_remaining(size_t max_tries)
{
    const size_t target_connections = ((oshd.node_tree_count - 1) * oshd.automatic_connections_percent) / 100;

    // If we have more active connections than required, we don't need any more
    // automatic connections
    // TODO: Maybe only count authenticated sockets as active connections
    if (oshd.nodes_count >= target_connections)
        return 0;

    // Otherwise we calculate how many connections we should establish to reach
    // the target percentage
    size_t remaining_tries = target_connections - oshd.nodes_count;

    // If connections are limited, make sure to always leave enough slots for
    // the remotes from the configuration file
    if (oshd.nodes_count_max != 0) {
        if (oshd.remote_count >= oshd.nodes_count_max)
            return 0;
        else
            remaining_tries = oshd.nodes_count_max - oshd.remote_count;
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
    const time_t max_ep_delay = oshd.reconnect_delay_max + NODE_AUTH_TIMEOUT;
    time_t delay = 0;

    // Sum the maximum delay for all endpoints in the tree
    for (size_t i = 0; i < tree_count; ++i)
        delay += max_ep_delay * oshd.node_tree[i]->endpoints->endpoints_count;

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
static void automatic_connections_handler(__attribute__((unused)) void *data)
{
    const time_t next_retry_delay = automatic_connections_next_retry_delay();
    size_t remaining_tries = automatic_connections_remaining(5);
    struct timeval now;

    logger_debug(DBG_ENDPOINTS, "Automatic connections (%zu at most)",
        remaining_tries);
    gettimeofday(&now, NULL);
    for (size_t i = 0; i < oshd.node_tree_count && remaining_tries > 0; ++i) {
        node_id_t *id = oshd.node_tree_ordered_hops[i];

        // Of course we won't try to connect to ourselves
        if (id->local_node)
            continue;

        // If the node has no direct connection but at least one endpoint and is
        // not a local endpoint group, then this is the only way to initiate a
        // connection

        if (   !id->endpoints_local
            && !id->node_socket
            &&  id->endpoints->endpoints_count > 0
            &&  now.tv_sec >= id->endpoints_next_retry.tv_sec)
        {
            logger_debug(DBG_ENDPOINTS, "Automatically connecting to %s", id->name);

            // Set the delay before trying to automatically connect to this node
            // again
            tv_delay(&id->endpoints_next_retry, next_retry_delay);
            event_queue_connect(id->endpoints, oshd.reconnect_delay_min, 0);
            remaining_tries -= 1;
        }
    }
}

// Queue a periodic event that will try to establish new connections
// automatically
void event_queue_automatic_connections(void)
{
    struct timeval trigger;

    tv_delay(&trigger, oshd.automatic_connections_interval);
    event_queue(event_create(automatic_connections_handler, NULL, NULL,
        &trigger, oshd.automatic_connections_interval));
}