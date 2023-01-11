#include "oshd.h"
#include "oshd_socket.h"
#include "events.h"
#include "logger.h"
#include "xalloc.h"

// Try to connect to a node

// Set the node's connect_event to NULL only if it is the correct one
// It is possible that the connect event handler queues another connect event,
// we must not remove it since it's a different event
static void unlink_connect_event(const event_t *event, node_id_t *nid)
{
    if (nid->connect_event == event)
        nid->connect_event = NULL;
}

static void connect_event_freedata(const event_t *event, void *data)
{
    unlink_connect_event(event, (node_id_t *) data);
}

// Returns true if a connection can be attempted
static bool connection_attempt_is_valid(node_id_t *nid)
{
    // If a connection was made since the event was queued, stop here
    if (nid->node_socket) {
        node_connect_end(nid, false, "Already connected");
        return false;
    }

    // Make sure to have an endpoint to try to connect to
    if (!endpoint_group_selected(nid->connect_endpoints)) {
        // If this error appears the code is glitched
        logger(LOG_ERR, "Connect event called with no endpoint");
        node_connect_continue(nid);
        return false;
    }

    return true;
}

static time_t connect_event_handler(
    const event_t *event,
    __attribute__((unused)) const struct timespec *delay,
    void *data)
{
    node_id_t *nid = (node_id_t *) data;

    unlink_connect_event(event, nid);
    if (connection_attempt_is_valid(nid))
        oshd_client_connect(nid, endpoint_group_selected(nid->connect_endpoints));

    return EVENT_IS_DONE;
}

void event_queue_connect(node_id_t *nid, time_t delay)
{
    if (nid->connect_event) {
        // If this happens the connection logic has a bug
        logger(LOG_ERR, "Duplicate connect event for %s", nid->name);
        return;
    }

    // If there is a delay for this connection then it is a reconnection
    if (delay > 0) {
        logger(LOG_INFO, "Retrying to connect to %s in %" PRId64 " seconds",
            nid->name, delay);
    }

    nid->connect_event = event_create("connect", connect_event_handler,
        connect_event_freedata, nid);
    event_queue_in(nid->connect_event, EVENT_QUEUE_IN_S(delay));
}
