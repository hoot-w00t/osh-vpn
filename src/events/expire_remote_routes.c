#include "oshd.h"
#include "events.h"

// Periodically expire remote routes that have not been advertised for a while

static time_t expire_remote_routes_event_handler(__attribute__((unused)) void *data)
{
    time_t next_expire;

    netroute_del_expired(oshd.remote_routes, ROUTE_REMOTE_EXPIRY, &next_expire);
    return EVENT_QUEUE_IN_S(next_expire);
}

void event_queue_expire_remote_routes(void)
{
    event_queue_in(
        event_create(
            "expire_remote_routes",
            expire_remote_routes_event_handler,
            NULL,
            NULL),
        ROUTE_REMOTE_EXPIRY);
}