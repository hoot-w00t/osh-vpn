#include "oshd.h"
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

    // If we *i is NULL we are either on the head or the tail of the queue
    // so we can just add the event
    // Otherwise we also have to set the the next event to the previous one
    if ((*i))
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
    char *addr;
    uint16_t port;
    time_t delay;
} connect_event_data_t;

static void connect_event_freedata(void *data,
    __attribute__((unused)) bool handled)
{
    connect_event_data_t *e_data = (connect_event_data_t *) data;

    free(e_data->addr);
    free(e_data);
}

static void connect_event_handler(void *data)
{
    connect_event_data_t *e_data = (connect_event_data_t *) data;

    oshd_connect_queue(e_data->addr, e_data->port, e_data->delay);
}

void event_queue_connect(const char *addr, uint16_t port, time_t delay,
    time_t event_delay)
{
    struct timeval trigger;
    connect_event_data_t *data = xalloc(sizeof(connect_event_data_t));

    tv_delay(&trigger, event_delay);
    data->addr = xstrdup(addr);
    data->port = port;
    data->delay = delay;
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

    oshd.nodes = xrealloc(oshd.nodes, sizeof(node_t *) * (oshd.nodes_count + 1));
    oshd.nodes[oshd.nodes_count] = node;
    oshd.nodes_count += 1;
    oshd.nodes_updated = true;
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
    oshd.nodes = xrealloc(oshd.nodes, sizeof(node_t *) * (oshd.nodes_count));
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

    if (node->auth_timeout_event)
        event_cancel(node->auth_timeout_event);

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
        logger(LOG_WARN, "%s: Authentication timed out", node->addrw);
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