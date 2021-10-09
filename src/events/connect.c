#include "oshd.h"
#include "oshd_socket.h"
#include "events.h"
#include "logger.h"
#include "xalloc.h"

// Try to connect to a node

typedef struct connect_event_data {
    endpoint_group_t *endpoints;
    time_t delay;
} connect_event_data_t;

static void connect_event_freedata(void *data)
{
    connect_event_data_t *e_data = (connect_event_data_t *) data;

    free(e_data);
}

static time_t connect_event_handler(void *data)
{
    connect_event_data_t *e_data = (connect_event_data_t *) data;

    oshd_connect_queue(e_data->endpoints, e_data->delay);
    return EVENT_IS_DONE;
}

void event_queue_connect(endpoint_group_t *endpoints, time_t delay,
    time_t event_delay)
{
    endpoint_t *endpoint;
    connect_event_data_t *data = xalloc(sizeof(connect_event_data_t));

    data->endpoints = endpoints;
    data->delay = delay;

    // If there is a delay for this connection then it is a reconnection
    endpoint = endpoint_group_selected(data->endpoints);
    if (event_delay > 0 && endpoint) {
        if (data->endpoints->has_owner) {
            logger(LOG_INFO,
                "Retrying to connect to %s at %s:%u in %li seconds",
                data->endpoints->owner_name, endpoint->hostname, endpoint->port,
                event_delay);
        } else {
            logger(LOG_INFO, "Retrying to connect to %s:%u in %li seconds",
                endpoint->hostname, endpoint->port, event_delay);
        }
    }

    // Prevent duplicate connections to the same endpoints
    endpoint_group_set_is_connecting(data->endpoints, true);

    event_queue_in(
        event_create(
            "connect",
            connect_event_handler,
            connect_event_freedata,
            data),
        event_delay);
}