#include "events.h"
#include "node.h"
#include "logger.h"

// Disconnect nodes that don't finish handshakes in time

static time_t handshake_timeout_event_handler(void *data)
{
    node_t *node = (node_t *) data;

    node->handshake_timeout_event = NULL;
    if (node->handshake_in_progress || node->recv_cipher_next) {
        logger(LOG_WARN, "%s: Handshake timed out", node->addrw);
        aio_event_del(node->aio_event);
    }
    return EVENT_IS_DONE;
}

static void handshake_timeout_event_freedata(void *data)
{
    ((node_t *) data)->handshake_timeout_event = NULL;
}

void event_queue_handshake_timeout(node_t *node, time_t timeout_delay)
{
    if (!node->handshake_timeout_event) {
        node->handshake_timeout_event = event_create(
            "handshake_timeout",
            handshake_timeout_event_handler,
            handshake_timeout_event_freedata,
            node);
    }
    event_queue_in(node->handshake_timeout_event, timeout_delay);
}
