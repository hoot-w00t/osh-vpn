#define _OSH_AIO_C

#include "aio.h"
#include "logger.h"
#include "xalloc.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>

static const short _poll_flags[4] = {
    0,                  // AIO_NOPOLL
    POLLIN,             // AIO_READ
    POLLOUT,            // AIO_WRITE
    POLLIN | POLLOUT    // AIO_POLLALL (or AIO_READ | AIO_WRITE)
};
#define poll_flags(x) _poll_flags[aio_poll_event_idx(x)]

#define aio_data(aio) ((struct pollfd *) aio->data.ptr)

void _aio_event_free(__attribute__((unused)) aio_event_t *event)
{
}

void _aio_event_init(__attribute__((unused)) aio_event_t *event)
{
}

void _aio_event_add(aio_t *aio, aio_event_t *event, size_t idx, size_t new_count)
{
    // Allocate space for the new event in the pollfd array and initialize it
    aio->data.ptr = xreallocarray(aio->data.ptr, new_count,
        sizeof(struct pollfd));
    aio_data(aio)[idx].fd = event->fd;
    aio_data(aio)[idx].events = poll_flags(event->poll_events);
}

void _aio_event_delete(aio_t *aio, __attribute__((unused)) aio_event_t *event,
    size_t idx, size_t move_size, __attribute__((unused)) size_t old_count)
{
    if (move_size) {
        memmove(&aio_data(aio)[idx], &aio_data(aio)[idx + 1],
            sizeof(struct pollfd) * move_size);
    }

    // Re-size the events_pfd array
    aio->data.ptr = xreallocarray(aio->data.ptr, aio->events_count,
        sizeof(struct pollfd));
}

aio_t *_aio_create(aio_t *aio)
{
    return aio;
}

void _aio_free(aio_t *aio)
{
    free(aio->data.ptr);
}

ssize_t _aio_poll(aio_t *aio, ssize_t timeout)
{
    // Poll all events
    ssize_t n = poll(aio_data(aio), aio->events_count, timeout);

    if (n < 0) {
        // Polling errors can occur when receiving signals, in this case the
        // error isn't actually from the polling so we can ignore it
        if (errno == EINTR)
            return 0;

        logger(LOG_CRIT, "aio_poll: poll: %s", strerror(errno));
        return -1;
    }

    // Process all events
    ssize_t remaining = n;

    for (size_t i = 0; n > 0 && i < aio->events_count; ++i) {
        // If there are no revents skip this event
        if (!aio_data(aio)[i].revents)
            continue;

        // Decrement the number of remaining events
        --remaining;

        // If there is an error call the error callback and ignore any other
        // events
        if (aio_data(aio)[i].revents & (POLLERR | POLLHUP)) {
            if (aio->events[i]->cb_error) {
                aio->events[i]->cb_error(
                    aio->events[i],
                    (aio_data(aio)[i].revents & POLLERR) ? AIO_ERR : AIO_HUP);
            }
            continue;
        }

        // If data is ready to be read, call the read callback
        if (aio_data(aio)[i].revents & (POLLIN)) {
            if (aio->events[i]->cb_read)
                aio->events[i]->cb_read(aio->events[i]);
        }

        // If data is ready to be written, call the write callback
        if (aio_data(aio)[i].revents & (POLLOUT)) {
            if (aio->events[i]->cb_write)
                aio->events[i]->cb_write(aio->events[i]);
        }
    }

    return n;
}

// Enables the given poll events
void aio_enable_poll_events(aio_event_t *event, aio_poll_event_t poll_events)
{
    if (event->added_to_aio) {
        aio_data(event->aio)[event->aio_idx].events |= poll_flags(poll_events);
    } else {
        event->poll_events |= poll_events;
    }
}

// Disables the given poll events
void aio_disable_poll_events(aio_event_t *event, aio_poll_event_t poll_events)
{
    if (event->added_to_aio) {
        aio_data(event->aio)[event->aio_idx].events &= ~(poll_flags(poll_events));
    } else {
        event->poll_events &= ~(poll_events);
    }
}