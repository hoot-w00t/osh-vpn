#include "oshd.h"
#include "events.h"

// Periodically delete old broadcast IDs from the seen_brd_id array

static time_t expire_seen_brd_ids_event_handler(__attribute__((unused)) void *data)
{
    struct timespec now;
    struct timespec delta;
    time_t biggest_lifetime;
    size_t idx;
    node_id_t *nid;

    biggest_lifetime = 0;
    oshd_gettime(&now);

    for (size_t i = 0; i < oshd.node_tree_count; ++i) {
        nid = oshd.node_tree[i];

        // Broadcast IDs are ordered from oldest to most recent
        for (idx = 0; idx < nid->seen_brd_id_count; ++idx) {
            timespecsub(&now, &nid->seen_brd_id[idx].seen_at, &delta);

            // When we get to an entry that is not old enough, stop here as the
            // rest will be even more recent
            if (delta.tv_sec < NODE_BRD_ID_TIMEOUT) {
                // Remember the biggest lifetime of all broadcast IDs
                if (delta.tv_sec > biggest_lifetime)
                    biggest_lifetime = delta.tv_sec;
                break;
            }
        }

        // The index's value is the number of IDs to pop from the array
        if (idx > 0)
            node_brd_id_pop(nid, idx);
    }

    // This should never happen, but make sure that the biggest lifetime is
    // within bounds
    if (biggest_lifetime <= 0) {
        biggest_lifetime = 0;
    } else if (biggest_lifetime >= NODE_BRD_ID_TIMEOUT) {
        // Always wait at least a second before the next pass
        biggest_lifetime = NODE_BRD_ID_TIMEOUT - 1;
    }

    // Re-queue this event in time for the next timeout
    return EVENT_QUEUE_IN_S(NODE_BRD_ID_TIMEOUT - biggest_lifetime);
}

void event_queue_expire_seen_brd_ids(void)
{
    event_queue_in(
        event_create(
            "expire_seen_brd_ids",
            expire_seen_brd_ids_event_handler,
            NULL,
            NULL),
        EVENT_QUEUE_IN_S(NODE_BRD_ID_TIMEOUT));
}
