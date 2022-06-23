#include "client.h"
#include "events.h"
#include "logger.h"

// Disconnect clients that do not authenticate in time

static time_t node_auth_timeout_event_handler(void *data)
{
    client_t *c = (client_t *) data;

    c->auth_timeout_event = NULL;
    if (!c->authenticated) {
        if (c->connected) {
            logger(LOG_WARN, "%s: Authentication timed out", c->addrw);
        } else {
            logger(LOG_WARN, "%s: Timed out", c->addrw);
        }
        aio_event_del(c->aio_event);
    }
    return EVENT_IS_DONE;
}

static void node_auth_timeout_event_freedata(void *data)
{
    ((client_t *) data)->auth_timeout_event = NULL;
}

void event_queue_node_auth_timeout(client_t *c, time_t timeout_delay)
{
    if (c->auth_timeout_event) {
        logger(LOG_WARN, "%s: node_auth_timeout event already exists", c->addrw);
    } else {
        c->auth_timeout_event = event_create(
            "node_auth_timeout",
            node_auth_timeout_event_handler,
            node_auth_timeout_event_freedata,
            c);
    }
    event_queue_in(c->auth_timeout_event, timeout_delay);
}
