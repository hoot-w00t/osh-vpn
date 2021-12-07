#define _OSH_AIO_C

#include "aio.h"
#include "logger.h"
#include "xalloc.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>

static const uint32_t _epoll_flags[4] = {
    0,                  // AIO_NOPOLL
    EPOLLIN,            // AIO_READ
    EPOLLOUT,           // AIO_WRITE
    EPOLLIN | EPOLLOUT  // AIO_POLLALL (or AIO_READ | AIO_WRITE)
};
#define epoll_flags(x) _epoll_flags[aio_poll_event_idx(x)]

#ifndef EPOLL_MAXEVENTS
#define EPOLL_MAXEVENTS (64)
#endif

#if (EPOLL_MAXEVENTS <= 0)
#error "EPOLL_MAXEVENTS must be a positive value"
#endif

typedef struct aio_data_epoll {
    // epoll file descriptor
    int epfd;

    // Dynamically allocated array for epoll_wait
    struct epoll_event ep_events[EPOLL_MAXEVENTS];
} aio_data_epoll_t;

typedef struct event_data_epoll {
    struct epoll_event ep_event;
} event_data_epoll_t;

#define aio_data(aio) ((aio_data_epoll_t *) (aio)->data.ptr)
#define event_data(e) ((event_data_epoll_t *) (e)->data.ptr)->ep_event

void _aio_event_free(aio_event_t *event)
{
    free(event->data.ptr);
    if (event->aio) {
        // Delete file descriptor from the interest list
        if (epoll_ctl(aio_data(event->aio)->epfd, EPOLL_CTL_DEL, event->fd,
                &event_data(event)) < 0)
        {
            logger(LOG_CRIT, "Failed to free AIO event: epoll_ctl: %s (fd=%i)",
                strerror(errno), event->fd);
            abort();
        }
    }
}

void _aio_event_init(aio_event_t *event)
{
    // Initialize epoll event data
    event->data.ptr = xzalloc(sizeof(struct epoll_event));
    event_data(event).events = epoll_flags(event->poll_events);
    event_data(event).data.ptr = event;
}

void _aio_event_add(aio_t *aio, aio_event_t *event,
    __attribute__((unused)) size_t idx,
    __attribute__((unused)) size_t new_count)
{
    // Add the file descriptor to the interest list
    if (epoll_ctl(aio_data(aio)->epfd, EPOLL_CTL_ADD, event->fd,
            &event_data(event)) < 0)
    {
        logger(LOG_CRIT, "Failed to add AIO event: epoll_ctl: %s (fd=%i)",
            strerror(errno), event->fd);
        abort();
    }
}

void _aio_event_delete(
    __attribute__((unused)) aio_t *aio,
    __attribute__((unused)) aio_event_t *event,
    __attribute__((unused)) size_t idx,
    __attribute__((unused)) size_t move_size,
    __attribute__((unused)) size_t old_count)
{
}

aio_t *_aio_create(aio_t *aio)
{
    aio->data.ptr = xzalloc(sizeof(aio_data_epoll_t));

    // Create the epoll file descriptor
    aio_data(aio)->epfd = epoll_create1(EPOLL_CLOEXEC);
    if (aio_data(aio)->epfd < 0) {
        logger(LOG_CRIT, "epoll_create1: %s", strerror(errno));
        free(aio->data.ptr);
        return NULL;
    }
    return aio;
}

void _aio_free(aio_t *aio)
{
    close(aio_data(aio)->epfd);
    free(aio->data.ptr);
}

ssize_t _aio_poll(aio_t *aio, ssize_t timeout)
{
    int n = epoll_wait(aio_data(aio)->epfd, aio_data(aio)->ep_events,
        EPOLL_MAXEVENTS, timeout);

    if (n < 0) {
        if (errno == EINTR)
            return 0;

        logger(LOG_CRIT, "aio_poll: epoll_wait: %s", strerror(errno));
        return -1;
    }

    for (int i = 0; i < n; ++i) {
        struct epoll_event *event = &aio_data(aio)->ep_events[i];
        aio_event_t *aio_event = (aio_event_t *) event->data.ptr;

        if (event->events & (EPOLLERR | EPOLLHUP)) {
            if (aio_event->cb_error) {
                aio_event->cb_error(
                    aio_event,
                    (event->events & EPOLLERR) ? AIO_ERR : AIO_HUP);
            }
            continue;
        }

        if (event->events & EPOLLIN) {
            if (aio_event->cb_read)
                aio_event->cb_read(aio_event);
        }

        if (event->events & EPOLLOUT) {
            if (aio_event->cb_write)
                aio_event->cb_write(aio_event);
        }
    }

    return n;
}

// Update epoll event with the new events
static void update_epoll_events(aio_event_t *event)
{
    if (event->added_to_aio) {
        if (epoll_ctl(aio_data(event->aio)->epfd, EPOLL_CTL_MOD, event->fd,
                &event_data(event)) < 0)
        {
            logger(LOG_CRIT,
                "update_epoll_events: epoll_ctl: %s (fd=%i, events=%u)",
                strerror(errno), event->fd, event_data(event).events);
            abort();
        }
    }
}

// Enables the given poll events
void aio_enable_poll_events(aio_event_t *event, aio_poll_event_t poll_events)
{
    event_data(event).events |= epoll_flags(poll_events);
    update_epoll_events(event);
}

// Disables the given poll events
void aio_disable_poll_events(aio_event_t *event, aio_poll_event_t poll_events)
{
    event_data(event).events &= ~(epoll_flags(poll_events));
    update_epoll_events(event);
}