#include "events.h"
#include "client.h"
#include "logger.h"

// Send PING probes to measure latency and check if the connection is still
// alive, disconnect the client if there are no responses in time

static time_t timeout(client_t *c, const struct timespec *delay)
{
    logger(LOG_INFO, "%s: Timed out (after %" PRI_TIME_T " seconds)",
        c->addrw, (pri_time_t) delay->tv_sec);
    aio_event_del(c->aio_event);
    return EVENT_IS_DONE;
}

static time_t keepalive_event_handler(
    __attribute__((unused)) const event_t *event,
    const struct timespec *delay,
    void *data)
{
    client_t *c = (client_t *) data;

    if (delay->tv_sec >= c->keepalive_timeout)
        return timeout(c, delay);

    if (c->rtt_await) {
        struct timespec now;
        struct timespec delta;

        oshd_gettime(&now);
        timespecsub(&now, &c->rtt_ping, &delta);
        if (delta.tv_sec >= c->keepalive_timeout)
            return timeout(c, &delta);
    }

    if (c->authenticated)
        client_queue_ping(c);

    return EVENT_QUEUE_IN_S(c->keepalive_interval);
}

static void keepalive_event_freedata(
    __attribute__((unused)) const event_t *event,
    void *data)
{
    ((client_t *) data)->keepalive_event = NULL;
}

void event_queue_keepalive(client_t *c, time_t delay)
{
    // If another keepalive event was already queued, ignore this one
    if (c->keepalive_event)
        return;

    c->keepalive_event = event_create(
        "keepalive",
        keepalive_event_handler,
        keepalive_event_freedata,
        c);
    event_queue_in(c->keepalive_event, delay);
}
