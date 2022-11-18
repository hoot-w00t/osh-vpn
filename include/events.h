#ifndef _OSH_EVENTS_H
#define _OSH_EVENTS_H

#include "node.h"
#include "oshd_clock.h"
#include "netaddr.h"

#define EVENT_DELAY_UNIT "ms"
#define EVENT_DELAY_PRECISION (1000)
#define EVENT_NSEC_MAX (1000000000)
#define EVENT_DELAY_TO_SEC(x) \
    ((x) / EVENT_DELAY_PRECISION)
#define EVENT_DELAY_TO_NSEC(x) \
    (((x) % EVENT_DELAY_PRECISION) * (EVENT_NSEC_MAX / EVENT_DELAY_PRECISION))

// Corresponds to the delays an event can return
// < 0 : the event is finished (it is freed right after)
// >= 0: the event will be triggered again with this delay (in seconds) from now
#define EVENT_IS_DONE           (-1)
#define EVENT_QUEUE_NOW         (0)
#define EVENT_QUEUE_IN_MS(ms)   (ms)
#define EVENT_QUEUE_IN_S(s)     EVENT_QUEUE_IN_MS((s) * 1000)
#define EVENT_QUEUE_IN_M(m)     EVENT_QUEUE_IN_S((m) * 60)
#define EVENT_QUEUE_IN_H(h)     EVENT_QUEUE_IN_M((h) * 60)

typedef time_t (*event_handler_t)(void *);
typedef void (*event_freedata_t)(void *);
typedef struct event event_t;

struct event {
    // Name of the event for easier debugging
    char name[64];

    // Function called when the event triggers
    // The return value is used as a delay to re-queue the event
    // If the value is negative the event is freed
    // Otherwise the event is re-queued using that value (in seconds)
    event_handler_t handler;

    // Function called after the handler is executed or when the event is
    // canceled, this is to free allocated resources in *data (including the
    // *data pointer itself)
    event_freedata_t freedata;

    // Pointer to some data passed to the handler
    // If this points to dynamically allocated memory it must be freed by the
    // handler
    void *userdata;

    // Timestamp at which the event should trigger
    struct timespec trigger_at;

    // This is set to true when the event is in the event queue and back to
    // false when removed (either by cancelling the event or after it is
    // processed)
    bool in_queue;

    // Next event in the linked list
    event_t *next;
};

#ifndef EVENTS_USE_TIMERFD
void event_process_queued(void);
time_t event_get_timeout_ms(void);
#endif

bool event_init(void);

event_t *event_create(
    const char *name,
    event_handler_t handler,
    event_freedata_t freedata,
    void *userdata);
void event_free(event_t *event);

void event_queue_in(event_t *event, time_t delay);
#define event_queue_now(event) event_queue_in(event, EVENT_QUEUE_NOW)
void event_cancel(event_t *event);
void event_cancel_queue(void);

void event_queue_automatic_connections(void);
void event_queue_connect(node_id_t *nid, time_t delay);
void event_queue_dynamic_ip_conflict(node_id_t *s1, node_id_t *s2,
    const netaddr_t *addr);
void event_queue_expire_endpoints(void);
void event_queue_expire_routes(void);
void event_queue_expire_seen_brd_ids(void);
void event_queue_handshake_renew(client_t *c);
void event_queue_handshake_timeout(client_t *c, time_t timeout_delay);
void event_queue_keepalive(client_t *c, time_t delay);

#endif
