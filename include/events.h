#ifndef _OSH_EVENTS_H
#define _OSH_EVENTS_H

#include "node.h"
#include <sys/time.h>

// Corresponds to the periodic delay of an event, 0 or negative values indicate
// that an event only triggers once
#define EVENT_TRIGGER_ONCE ((time_t) 0)

typedef void (*event_handler_t)(void *);
typedef void (*event_freedata_t)(void *, bool);
typedef struct event event_t;

struct event {
    // Function called when the event triggers, handled is set to true after
    event_handler_t handler;
    bool handled;

    // Function called after the handler is executed or when the event is
    // canceled, this is to free allocated resources in *data (including the
    // *data pointer itself)
    event_freedata_t freedata;

    // Pointer to some data passed to the handler
    // If this points to dynamically allocated memory it must be freed by the
    // handler
    void *data;

    // Timestamp at which the event should trigger
    struct timeval trigger;
    char trigger_fmt[32];

    // If this is higher than zero the event will be queued again using this
    // delay (in seconds) after it is processed
    // This is to create periodic events
    // No data or pointer are changed, it will only change the trigger timestamp
    // and place the event back in the queue
    // Periodic events cannot be stopped automatically, they must be canceled
    time_t periodic_delay;

    // Next event in the linked list
    event_t *next;
};

void event_process_queued(void);
void event_cancel_queue(void);
void event_cancel(event_t *event);

void event_queue_connect(endpoint_group_t *endpoints, time_t delay,
    time_t event_delay);
void event_queue_periodic_ping(void);
void event_queue_node_add(node_t *node);
void event_queue_node_remove(node_t *node);
void event_queue_node_auth_timeout(node_t *node, time_t timeout_delay);
void event_queue_endpoints_refresh(void);
void event_queue_automatic_connections(void);
void event_queue_expire_routes_refresh(void);

#endif
