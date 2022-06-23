#include "client.h"
#include "events.h"
#include "logger.h"

// Regularly initiate a new handshake to renew encryption keys

static time_t handshake_renew_event_handler(void *data)
{
    client_t *c = (client_t *) data;

    c->handshake_renew_event = NULL;
    client_renew_handshake(c);
    return EVENT_IS_DONE;
}

static void handshake_renew_event_freedata(void *data)
{
    ((client_t *) data)->handshake_renew_event = NULL;
}

void event_queue_handshake_renew(client_t *c)
{
    if (!c->handshake_renew_event) {
        c->handshake_renew_event = event_create(
            "handshake_renew",
            handshake_renew_event_handler,
            handshake_renew_event_freedata,
            c);
    }
    event_queue_in(c->handshake_renew_event, HANDSHAKE_RENEW_INTERVAL);
}
