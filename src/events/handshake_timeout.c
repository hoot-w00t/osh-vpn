#include "events.h"
#include "client.h"
#include "logger.h"

// Disconnect nodes that don't finish handshakes in time (including the initial
// handshake which authenticates the node, this times out connections that don't
// authenticate in time)

static void timeout_client(client_t *c, const char *reason)
{
    logger(LOG_ERR, "%s: %s timed out", c->addrw, reason);
    aio_event_del(c->aio_event);
}

static time_t handshake_timeout_event_handler(void *data)
{
    client_t *c = (client_t *) data;

    c->handshake_timeout_event = NULL;
    if (!c->authenticated) {
        timeout_client(c, c->connected ? "Authentication" : "Connection");
    } else if (c->handshake_in_progress || c->recv_cipher_next || c->handshake_id) {
        timeout_client(c, "Handshake");
    }
    return EVENT_IS_DONE;
}

static void handshake_timeout_event_freedata(void *data)
{
    ((client_t *) data)->handshake_timeout_event = NULL;
}

void event_queue_handshake_timeout(client_t *c, time_t timeout_delay)
{
    // If another handshake_timeout event was already queued, ignore this one
    if (c->handshake_timeout_event)
        return;

    c->handshake_timeout_event = event_create(
        "handshake_timeout",
        handshake_timeout_event_handler,
        handshake_timeout_event_freedata,
        c);
    event_queue_in(c->handshake_timeout_event, EVENT_QUEUE_IN_S(timeout_delay));
}
