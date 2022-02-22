#include "node.h"
#include "events.h"
#include "logger.h"

// Regularly initiate a new handshake to renew encryption keys

static time_t handshake_renew_event_handler(void *data)
{
    node_t *node = (node_t *) data;

    node->handshake_renew_event = NULL;
    node_renew_handshake(node);
    return EVENT_IS_DONE;
}

static void handshake_renew_event_freedata(void *data)
{
    ((node_t *) data)->handshake_renew_event = NULL;
}

void event_queue_handshake_renew(node_t *node)
{
    if (!node->handshake_renew_event) {
        node->handshake_renew_event = event_create(
            "handshake_renew",
            handshake_renew_event_handler,
            handshake_renew_event_freedata,
            node);
    }
    event_queue_in(node->handshake_renew_event, HANDSHAKE_RENEW_INTERVAL);
}
