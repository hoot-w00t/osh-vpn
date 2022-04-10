#include "oshd.h"
#include "oshd_discovery.h"
#include "events.h"

// Periodically expire local routes that have not been advertised for a while

static time_t expire_local_routes_event_handler(__attribute__((unused)) void *data)
{
    time_t next_expire;

    if (netroute_del_expired(oshd.local_routes, ROUTE_LOCAL_EXPIRY, &next_expire))
        oshd_discover_local_routes();
    return EVENT_QUEUE_IN_S(next_expire);
}

void event_queue_expire_local_routes(void)
{
    event_queue_in(
        event_create(
            "expire_local_routes",
            expire_local_routes_event_handler,
            NULL,
            NULL),
        ROUTE_LOCAL_EXPIRY);
}