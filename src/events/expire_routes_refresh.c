#include "oshd.h"
#include "oshd_discovery.h"
#include "events.h"

// Periodically expire routes that have not been advertised for a while
// Also refreshes local routes

#define EXPIRE_ROUTES_INTERVAL (ROUTE_LOCAL_EXPIRY / 2)

static time_t expire_routes_event_handler(__attribute__((unused)) void *data)
{
    if (oshd_route_del_expired(oshd.routes))
        oshd_discover_local_routes();
    return EVENT_QUEUE_IN_S(EXPIRE_ROUTES_INTERVAL);
}

void event_queue_expire_routes_refresh(void)
{
    event_queue_in(
        event_create(
            "expire_routes",
            expire_routes_event_handler,
            NULL,
            NULL),
        EXPIRE_ROUTES_INTERVAL);
}