#define _OSH_AIO_C

#include "aio.h"
#include "xalloc.h"
#include "logger.h"
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

// Return a newly allocated copy of src
// aio, aio_idx, added_to_aio and pending_delete are initialized to zero
static aio_event_t *aio_event_dup(const aio_event_t *src)
{
    aio_event_t *dest = xzalloc(sizeof(aio_event_t));

    dest->fd = src->fd;
#if PLATFORM_IS_WINDOWS
    dest->read_handle = src->read_handle;
    dest->read_auto_reset = src->read_auto_reset;
    dest->write_handle = src->write_handle;
    dest->write_auto_reset = src->write_auto_reset;
#endif
    dest->poll_events = src->poll_events;
    dest->userdata = src->userdata;

    dest->cb_add = src->cb_add;
    dest->cb_delete = src->cb_delete;
    dest->cb_read = src->cb_read;
    dest->cb_write = src->cb_write;
    dest->cb_error = src->cb_error;
    return dest;
}

// Free event and its allocated resources
// Calls cb_delete (if set) before freeing the event
static void aio_event_free(aio_event_t *event)
{
    if (event) {
        _aio_event_free(event);

        if (event->cb_delete)
            event->cb_delete(event);
        free(event);
    }
}

// Add event to aio
static void aio_events_add(aio_t *aio, aio_event_t *event)
{
    const size_t idx = aio->events_count;
    const size_t new_count = aio->events_count + 1;

    // Allocate space for the new event and add it
    aio->events = xreallocarray(aio->events, new_count, sizeof(aio_event_t *));
    aio->events_count = new_count;
    aio->events[idx] = event;

    _aio_event_add(aio, event, idx, new_count);

    // Initialize the event's internal values
    event->aio_idx = idx;
    event->added_to_aio = true;

    // Call the add callback (if set)
    if (event->cb_add)
        event->cb_add(event);
}

// Delete event from its aio
static void aio_events_delete(aio_event_t *event)
{
    aio_t *aio = event->aio;
    const size_t idx = event->aio_idx;
    const size_t move_size = aio->events_count - idx - 1;

    if (move_size) {
        // Shift queues
        memmove(&aio->events[idx], &aio->events[idx + 1],
            sizeof(aio_event_t *) * move_size);

        // Update events' indexes
        for (size_t i = 0; i < move_size; ++i)
            aio->events[idx + i]->aio_idx = idx + i;
    }

    // Update dynamic arrays' sizes
    aio->events_count -= 1;
    aio->events = xreallocarray(aio->events, aio->events_count,
        sizeof(aio_event_t *));

    _aio_event_delete(aio, event, idx, move_size, aio->events_count);

    // Free the event
    aio_event_free(event);
}

// Queue addition/deletion of an event
// This only appends an element to the queue
static void aio_events_queue(aio_t *aio, aio_event_t *event, bool add)
{
    aio_pending_t **i = &aio->queue_head;
    aio_pending_t *pending = xalloc(sizeof(aio_pending_t));

    event->aio = aio;

    pending->event = event;
    pending->add = add;

    while (*i)
        i = &(*i)->next;
    pending->next = *i;
    *i = pending;
}

// Process queued additions/deletions
static void aio_process_queue(aio_t *aio)
{
    while (aio->queue_head) {
        aio_pending_t *pending = aio->queue_head;

        aio->queue_head = aio->queue_head->next;

        if (pending->add) {
            aio_events_add(aio, pending->event);
        } else {
            aio_events_delete(pending->event);
        }
        free(pending);
    }
}

// Create a new async IO object
// Returns NULL if the AIO cannot be initialized
aio_t *aio_create(void)
{
    aio_t *aio = xzalloc(sizeof(aio_t));

    if (!_aio_create(aio)) {
        free(aio);
        return NULL;
    }
    return aio;
}

// Free async IO object
void aio_free(aio_t *aio)
{
    if (aio) {
        // It is safer to use aio_event_del() instead of directly freeing the
        // events as it prevents an event's delete handler from re-queuing its
        // own deletion

        // Ensure that no events are left alone before deleting everything
        aio_process_queue(aio);

        // Queue all events for deletion
        for (size_t i = 0; i < aio->events_count; ++i)
            aio_event_del(aio->events[i]);

        // Actually delete all events
        aio_process_queue(aio);

        // If this happens then one of the delete handlers must have created and
        // added a new event to the AIO, this should not happen as the events'
        // resources will not be freed
        if (aio_has_queued_events(aio)) {
            logger(LOG_CRIT, "%s: %s", __func__,
                "queue_head is not NULL after deleting all events");
        }

        // Free and reset the list of events
        free(aio->events);
        aio->events = NULL;
        aio->events_count = 0;

        // Free internal resources
        _aio_free(aio);

        // Free the aio structure
        free(aio);
    }
}

// Poll for I/O events
// Block for timeout milliseconds at most
// If timeout is -1, blocks until an I/O event occurs
// If a polled I/O event does not have a callback it will keep being polled
// every time
// Returns -1 on error, or the number of events polled (this can exceed the
// number of events in the AIO)
ssize_t aio_poll(aio_t *aio, ssize_t timeout)
{
    ssize_t n;

    // Process all queued events to properly initialize/update events
    aio_process_queue(aio);

    // Call the actual polling function
    n = _aio_poll(aio, timeout);

    // Process any event queued by the callbacks
    aio_process_queue(aio);

    return n;
}

// Add a new async I/O event to aio
// Duplicates relevant definitions from event to create the event
// Returns the event's pointer which can be used to modify it
aio_event_t *aio_event_add(aio_t *aio, const aio_event_t *event)
{
    aio_event_t *e = aio_event_dup(event);

    _aio_event_init(e);
    aio_events_queue(aio, e, true);
    return e;
}

// Same as aio_event_add but initializes an aio_event_t structure from passed
// arguments
aio_event_t *aio_event_add_inl(aio_t *aio,
    aio_fd_t fd,
    aio_poll_event_t poll_events,
    void *userdata,
    aio_cb_add_t cb_add,
    aio_cb_delete_t cb_delete,
    aio_cb_read_t cb_read,
    aio_cb_write_t cb_write,
    aio_cb_error_t cb_error)
{
    aio_event_t event;

    event.fd = fd;
    event.poll_events = poll_events;
    event.userdata = userdata;
    event.cb_add = cb_add;
    event.cb_delete = cb_delete;
    event.cb_read = cb_read;
    event.cb_write = cb_write;
    event.cb_error = cb_error;
    return aio_event_add(aio, &event);
}

// Delete an event from its aio and free it
void aio_event_del(aio_event_t *event)
{
    // Queue this event's deletion if it was not already
    if (!event->pending_delete) {
        event->pending_delete = true;
        aio_events_queue(event->aio, event, false);
    }
}

// Delete all events with the given file descriptor
// If multiple events share the same file descriptor they will all be deleted
void aio_event_del_fd(aio_t *aio, aio_fd_t fd)
{
    for (size_t i = 0; i < aio->events_count; ++i) {
        if (aio->events[i]->fd == fd) {
            aio_event_del(aio->events[i]);
        }
    }
}

#if !(PLATFORM_IS_WINDOWS)
// Generic delete callback that closes the event's file descriptor if it is valid
void aio_cb_delete_close_fd(aio_event_t *event)
{
    if (event->fd >= 0)
        close(event->fd);
}
#endif
