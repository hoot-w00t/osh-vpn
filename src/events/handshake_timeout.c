#include "events.h"
#include "client.h"
#include "logger.h"

// Disconnect nodes that don't finish handshakes in time

static time_t handshake_timeout_event_handler(void *data)
{
    client_t *c = (client_t *) data;

    c->handshake_timeout_event = NULL;
    if (c->handshake_in_progress || c->recv_cipher_next) {
        logger(LOG_WARN, "%s: Handshake timed out", c->addrw);
        aio_event_del(c->aio_event);
    }
    return EVENT_IS_DONE;
}

static void handshake_timeout_event_freedata(void *data)
{
    ((client_t *) data)->handshake_timeout_event = NULL;
}

void event_queue_handshake_timeout(client_t *c, time_t timeout_delay)
{
    if (!c->handshake_timeout_event) {
        c->handshake_timeout_event = event_create(
            "handshake_timeout",
            handshake_timeout_event_handler,
            handshake_timeout_event_freedata,
            c);
    }
    event_queue_in(c->handshake_timeout_event, timeout_delay);
}
