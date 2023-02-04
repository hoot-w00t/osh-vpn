#include "oshd.h"
#include "events.h"

// Periodically expire stale routes from the routing table

static time_t expire_routes_event_handler(
    __attribute__((unused)) const event_t *event,
    __attribute__((unused)) const struct timespec *delay,
    __attribute__((unused)) void *data)
{
    time_t next_expire;

    netroute_del_expired(oshd.route_table, &next_expire, ROUTE_LOCAL_EXPIRY);
    return EVENT_QUEUE_IN_S(next_expire);
}

void event_queue_expire_routes(void)
{
    event_queue_in(
        event_create(
            "expire_routes",
            expire_routes_event_handler,
            NULL,
            NULL),
        EVENT_QUEUE_IN_S(ROUTE_LOCAL_EXPIRY));
}
