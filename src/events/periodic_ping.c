#include "oshd.h"
#include "events.h"

#define PERIODIC_PING_INTERVAL (30)

// Periodically ping direct nodes

static time_t periodic_ping_event_handler(__attribute__((unused)) void *data)
{
    for (size_t i = 0; i < oshd.clients_count; ++i) {
        if (oshd.clients[i]->authenticated)
            client_queue_ping(oshd.clients[i]);
    }
    return EVENT_QUEUE_IN_S(PERIODIC_PING_INTERVAL);
}

void event_queue_periodic_ping(void)
{
    event_queue_in(
        event_create(
            "periodic_ping",
            periodic_ping_event_handler,
            NULL,
            NULL),
        EVENT_QUEUE_IN_S(PERIODIC_PING_INTERVAL));
}
