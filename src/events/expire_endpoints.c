#include "oshd.h"
#include "oshd_discovery.h"
#include "events.h"

// Periodically expire endpoints that have not been advertised for a while
// Also refreshes local endpoints

#define EXPIRE_ENDPOINTS_INTERVAL (ENDPOINT_EXPIRY / 4) // 15 minutes

static time_t expire_endpoints_event_handler(__attribute__((unused)) void *data)
{
    bool deleted = false;

    for (size_t i = 0; i < oshd.node_tree_count; ++i) {
        if (endpoint_group_del_expired(oshd.node_tree[i]->endpoints))
            deleted = true;
    }

    if (deleted && oshd.discoverendpoints)
        oshd_discover_local_endpoints();

    return EVENT_QUEUE_IN_S(EXPIRE_ENDPOINTS_INTERVAL);
}

void event_queue_expire_endpoints(void)
{
    event_queue_in(
        event_create(
            "expire_endpoints",
            expire_endpoints_event_handler,
            NULL,
            NULL),
        EXPIRE_ENDPOINTS_INTERVAL);
}