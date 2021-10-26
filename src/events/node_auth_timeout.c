#include "node.h"
#include "events.h"
#include "logger.h"

// Disconnect nodes that don't finish authentication in time

static time_t node_auth_timeout_event_handler(void *data)
{
    node_t *node = (node_t *) data;

    node->auth_timeout_event = NULL;
    if (!node->authenticated) {
        if (node->connected) {
            logger(LOG_WARN, "%s: Authentication timed out", node->addrw);
        } else {
            logger(LOG_WARN, "%s: Timed out", node->addrw);
        }
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
    if (node->auth_timeout_event) {
        logger(LOG_WARN, "%s: node_auth_timeout event already exists", node->addrw);
    } else {
        node->auth_timeout_event = event_create(
            "node_auth_timeout",
            node_auth_timeout_event_handler,
            node_auth_timeout_event_freedata,
            node);
    }
    event_queue_in(node->auth_timeout_event, timeout_delay);
}