#include "oshd.h"
#include "events.h"
#include "logger.h"

// Periodically expire endpoints that have not been advertised for a while
// Also refreshes/re-announces local endpoints

static void announce_expired_endpoints(node_id_t *owner, endpoint_group_t *group,
    const endpoint_flags_t *expired_flags)
{
    // Re-announce endpoints that don't expire
    // These will expire but be refreshed instead of deleted, we announce them
    // again because they can expire on other nodes
    foreach_endpoint_const(endpoint, group) {
        if (endpoint->had_expired && !endpoint_can_expire(endpoint) && oshd.shareendpoints)
            client_queue_endpoint(NULL, endpoint, owner, true);
    }

    // Re-announce endpoints we discovered if any has expired
    if (   ((*expired_flags) & (ENDPOINT_FLAG_EXPIRY_LOCAL | ENDPOINT_FLAG_CAN_EXPIRE))
        && node_id_linked_client(owner))
    {
        client_share_endpoints(node_id_linked_client(owner));
    }
}

static time_t expire_endpoints_event_handler(
    __attribute__((unused)) const event_t *event,
    __attribute__((unused)) const struct timespec *delay,
    __attribute__((unused)) void *data)
{
    struct timespec now;
    time_t next_expire;

    logger_debug(DBG_ENDPOINTS, "Checking expired endpoints");
    oshd_gettime(&now);
    next_expire = ENDPOINT_EXPIRY_SHORTEST;

    for (size_t i = 0; i < oshd.node_tree_count; ++i) {
        node_id_t *owner = oshd.node_tree[i];
        endpoint_group_t *group = owner->endpoints;
        endpoint_flags_t expired_flags;

        if (endpoint_group_del_expired(group, &next_expire, &expired_flags, &now))
            announce_expired_endpoints(owner, group, &expired_flags);
    }

    logger_debug(DBG_ENDPOINTS, "Next expiration is in %" PRI_TIME_T "s",
        (pri_time_t) next_expire);
    return EVENT_QUEUE_IN_S(next_expire);
}

void event_queue_expire_endpoints(void)
{
    event_queue_in(
        event_create(
            "expire_endpoints",
            expire_endpoints_event_handler,
            NULL,
            NULL),
        EVENT_QUEUE_IN_S(ENDPOINT_EXPIRY_SHORTEST));
}
