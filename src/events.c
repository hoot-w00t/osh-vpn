#include "oshd.h"
#include "oshd_socket.h"
#include "events.h"
#include "xalloc.h"
#include <stdlib.h>
#include <string.h>

static event_t *event_queue_head = NULL;

// Return an allocated event_t
static event_t *event_create(event_handler_t handler, void *data,
    const struct timeval *trigger)
{
    event_t *event = xzalloc(sizeof(event_t));

    event->handler = handler;
    event->data = data;
    memcpy(&event->trigger, trigger, sizeof(struct timeval));
    return event;
}

// Queue *event
static void event_queue(event_t *event)
{
    event_t **i = &event_queue_head;

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

// Process all events in the event queue that should trigger
void event_process_queued(void)
{
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

        // Keep the current event here
        event_t *event = event_queue_head;

        // Move the event queue to the next event
        event_queue_head = event->next;

        // Handle the current event
        event->handler(event->data);

        // Free the event_t now that it was triggered
        free(event);
    }
}

// Get the current time and add delay_s seconds to it in *tv
static void tv_delay_s(struct timeval *tv, time_t delay_s)
{
    gettimeofday(tv, NULL);
    tv->tv_sec += delay_s;
}


// Queue connect event
typedef struct connect_event_data {
    char *addr;
    uint16_t port;
    time_t delay;
} connect_event_data_t;

static void connect_event_handler(void *data)
{
    connect_event_data_t *e_data = (connect_event_data_t *) data;

    oshd_connect_queue(e_data->addr, e_data->port, e_data->delay);
    free(e_data->addr);
    free(e_data);
}

void event_queue_connect(const char *addr, uint16_t port, time_t delay,
    time_t event_delay)
{
    struct timeval trigger;
    connect_event_data_t *data = xalloc(sizeof(connect_event_data_t));

    tv_delay_s(&trigger, event_delay);
    data->addr = xstrdup(addr);
    data->port = port;
    data->delay = delay;
    event_queue(event_create(connect_event_handler, data, &trigger));
}


// Periodic ping events
static void periodic_ping_event_handler(__attribute__((unused)) void *data)
{
    for (size_t i = 0; i < oshd.nodes_count; ++i) {
        if (oshd.nodes[i]->authenticated)
            node_queue_ping(oshd.nodes[i]);
    }
    event_queue_periodic_ping();
}

// This function should only be called once outside of the event handler
void event_queue_periodic_ping(void)
{
    struct timeval trigger;

    tv_delay_s(&trigger, 30);
    event_queue(event_create(periodic_ping_event_handler, NULL, &trigger));
}