#include "oshd.h"
#include "oshd_socket.h"
#include "events.h"
#include "logger.h"
#include "xalloc.h"

// Try to connect to a node

static void connect_event_freedata(void *data)
{
    ((node_id_t *) data)->connect_event = NULL;
}

static time_t connect_event_handler(void *data)
{
    node_id_t *nid = (node_id_t *) data;

    nid->connect_event = NULL;
    oshd_connect_queue(nid);
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
        logger(LOG_INFO, "Retrying to connect to %s in %li seconds",
            nid->name, delay);
    }

    nid->connect_event = event_create("connect", connect_event_handler,
        connect_event_freedata, nid);
    event_queue_in(nid->connect_event, delay);
}
