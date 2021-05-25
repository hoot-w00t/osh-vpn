#ifndef _OSH_EVENTS_H
#define _OSH_EVENTS_H

#include "node.h"
#include <sys/time.h>

typedef void (*event_handler_t)(void *);
typedef struct event event_t;

struct event {
    // Function called when the event triggers
    event_handler_t handler;

    // Pointer to some data passed to the handler
    // If this points to dynamically allocated memory it must be freed by the
    // handler
    void *data;

    // Timestamp at which the event should trigger
    struct timeval trigger;

    // Next event in the linked list
    event_t *next;
};

void event_process_queued(void);

void event_queue_connect(const char *addr, uint16_t port, time_t delay_s);
void event_queue_periodic_ping(void);

#endif
