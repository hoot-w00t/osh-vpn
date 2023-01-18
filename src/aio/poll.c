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

typedef struct aio_data_poll {
    struct pollfd *pfd;
    size_t pfd_count;
} aio_data_poll_t;
#define aio_data(aio) ((aio_data_poll_t *) (aio)->data.ptr)

typedef struct event_data_poll {
    bool added_to_pfd;
    size_t pfd_idx;
} event_data_poll_t;
#define event_data(event) ((event_data_poll_t *) (event)->data.ptr)

void _aio_event_free(aio_event_t *event)
{
    free(event->data.ptr);
}

void _aio_event_init(aio_event_t *event)
{
    event->data.ptr = xalloc(sizeof(event_data_poll_t));
    event_data(event)->added_to_pfd = false;
}

// Re-size pfd array to hold count elements
static void resize_pfd(aio_t *aio, size_t count)
{
    aio_data(aio)->pfd_count = count;
    aio_data(aio)->pfd = xreallocarray(aio_data(aio)->pfd,
        count, sizeof(struct pollfd));
}

void _aio_event_enable(aio_t *aio, aio_event_t *event)
{
    const size_t idx = aio_data(aio)->pfd_count;

    // Allocate space for the new event in the pollfd array and initialize it
    resize_pfd(aio, aio_data(aio)->pfd_count + 1);
    aio_data(aio)->pfd[idx].fd = event->fd;
    aio_data(aio)->pfd[idx].events = poll_flags(event->poll_events);

    // Set the event's index in the pfd array
    event_data(event)->pfd_idx = idx;
    event_data(event)->added_to_pfd = true;
}

void _aio_event_disable(aio_t *aio, aio_event_t *event)
{
    // Don't try to delete events which are not in the pfd array
    if (!event_data(event)->added_to_pfd)
        return;

    const size_t idx = event_data(event)->pfd_idx;
    const size_t move_size = aio_data(aio)->pfd_count - idx - 1;

    // If the pollfd entry is not the last of the array, move everything that
    // comes after to prevent the last entry from being erased
    if (move_size) {
        memmove(&aio_data(aio)->pfd[idx], &aio_data(aio)->pfd[idx + 1],
            sizeof(struct pollfd) * move_size);

        // Update the moved events' pfd_idx
        for (size_t i = 0; i < aio->events_count; ++i) {
            aio_event_t *moved = aio->events[i];

            if (event_data(moved)->added_to_pfd && event_data(moved)->pfd_idx > idx)
                event_data(moved)->pfd_idx -= 1;
        }
    }

    resize_pfd(aio, aio_data(aio)->pfd_count - 1);
}

aio_t *_aio_create(aio_t *aio)
{
    aio->data.ptr = xzalloc(sizeof(aio_data_poll_t));
    return aio;
}

void _aio_free(aio_t *aio)
{
    free(aio_data(aio)->pfd);
    free(aio->data.ptr);
}

ssize_t _aio_poll(aio_t *aio, ssize_t timeout)
{
    // Poll all events
    ssize_t n = poll(aio_data(aio)->pfd, aio_data(aio)->pfd_count, timeout);

    if (n < 0) {
        // Polling errors can occur when receiving signals, in this case the
        // error isn't actually from the polling so we can ignore it
        if (errno == EINTR)
            return 0;

        logger(LOG_CRIT, "%s: %s: %s", __func__, "poll", strerror(errno));
        return -1;
    }

    // Process all events
    ssize_t remaining = n;

    for (size_t i = 0; n > 0 && i < aio->events_count; ++i) {
        aio_event_t *event = aio->events[i];

        // Skip events which are not polled
        if (!event_data(event)->added_to_pfd)
            continue;

        const struct pollfd *pfd = &aio_data(aio)->pfd[event_data(event)->pfd_idx];

        // Skip the event if no I/O events were polled
        if (pfd->revents == 0)
            continue;

        // Decrement the number of remaining events
        --remaining;

        // If there is an error call the error callback and ignore any other
        // events
        if (pfd->revents & (POLLERR | POLLHUP)) {
            if (event->cb_error) {
                event->cb_error(event,
                    (pfd->revents & POLLERR) ? AIO_ERR : AIO_HUP);
            }
            continue;
        }

        // If data is ready to be read, call the read callback
        if (pfd->revents & (POLLIN)) {
            if (event->cb_read)
                event->cb_read(event);
        }

        // If data is ready to be written, call the write callback
        if (pfd->revents & (POLLOUT)) {
            if (event->cb_write)
                event->cb_write(event);
        }
    }

    return n;
}

// Enables the given poll events
void aio_enable_poll_events(aio_event_t *event, aio_poll_event_t poll_events)
{
    if (event_data(event)->added_to_pfd) {
        aio_data(event->aio)->pfd[event_data(event)->pfd_idx].events |= poll_flags(poll_events);
    } else {
        event->poll_events |= poll_events;
    }
}

// Disables the given poll events
void aio_disable_poll_events(aio_event_t *event, aio_poll_event_t poll_events)
{
    if (event_data(event)->added_to_pfd) {
        aio_data(event->aio)->pfd[event_data(event)->pfd_idx].events &= ~(poll_flags(poll_events));
    } else {
        event->poll_events &= ~(poll_events);
    }
}
