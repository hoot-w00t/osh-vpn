#include "node.h"
#include "events.h"
#include "logger.h"

// Disconnect nodes that don't finish authentication in time

static time_t node_auth_timeout_event_handler(void *data)
{
    node_t *node = (node_t *) data;

    if (!node->authenticated) {
        if (node->connected) {
            logger(LOG_WARN, "%s: Authentication timed out", node->addrw);
        } else {
            logger(LOG_WARN, "%s: Timed out", node->addrw);
        }
        node->auth_timeout_event = NULL;
        aio_event_del(node->aio_event);
    }
    return EVENT_IS_DONE;
}

static void node_auth_timeout_event_freedata(void *data)
{
    ((node_t *) data)->auth_timeout_event = NULL;
}

void event_queue_node_auth_timeout(node_t *node, time_t timeout_delay)
{
    event_t *event = event_create(
        "node_auth_timeout",
        node_auth_timeout_event_handler,
        node_auth_timeout_event_freedata,
        node);

    node->auth_timeout_event = event;
    event_queue_in(event, timeout_delay);
}