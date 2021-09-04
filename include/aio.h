#ifndef _OSH_AIO_H
#define _OSH_AIO_H

#include <sys/types.h>
#include <stdbool.h>
#include <stddef.h>
#include <poll.h>

typedef struct aio aio_t;
typedef struct aio_event aio_event_t;
typedef struct aio_pending aio_pending_t;

typedef short aio_poll_event_t;
#define AIO_NOPOLL  (0)
#define AIO_READ    (POLLIN)
#define AIO_WRITE   (POLLOUT)
#define AIO_ERR     (POLLERR)
#define AIO_HUP     (POLLHUP)
#define AIO_POLLALL (AIO_READ | AIO_WRITE)

typedef void (*aio_cb_t)(aio_event_t *event);
typedef aio_cb_t aio_cb_add_t;
typedef aio_cb_t aio_cb_delete_t;
typedef aio_cb_t aio_cb_read_t;
typedef aio_cb_t aio_cb_write_t;
typedef void (*aio_cb_error_t)(aio_event_t *event, aio_poll_event_t revents);

struct aio_pending {
    aio_event_t *event;
    bool add;
    aio_pending_t *next;
};

struct aio {
    // Async I/O events
    aio_event_t **events;

    // pollfd array used and updated when necessary for polling I/O events
    struct pollfd *events_pfd;

    // Number of entries in events and events_pfd
    size_t events_count;

    // This holds a list of events to add/delete
    aio_pending_t *queue_head;
};

struct aio_event {
    // File descriptor to poll for I/O events
    int fd;

    // I/O events to poll for
    aio_poll_event_t poll_events;

    // Pointer to some data given by the user
    void *userdata;

    // Pointers to functions called respectively after the event was added to
    // the queue and before it is deleted
    aio_cb_add_t cb_add;
    aio_cb_delete_t cb_delete;

    // Pointers to functions which should be called when the associated I/O
    // event occurs
    aio_cb_read_t cb_read;
    aio_cb_write_t cb_write;
    aio_cb_error_t cb_error;

    // Pointer to the aio_t this event is a part of and its pollfd entry
    aio_t *aio;
    size_t aio_idx;

    // true when this event is queued for addition/deletion (used internally to
    // know the state of the event and prevent some errors, like deleting the
    // same event twice, or accessing unallocated memory)
    bool added_to_aio;
    bool pending_delete;
};

aio_t *aio_create(void);
void aio_free(aio_t *aio);
ssize_t aio_poll(aio_t *aio, ssize_t timeout);

#define aio_events_count(aio) ((aio)->events_count)

aio_event_t *aio_event_add(aio_t *aio, const aio_event_t *event);
aio_event_t *aio_event_add_inl(aio_t *aio,
    int fd,
    aio_poll_event_t poll_events,
    void *userdata,
    aio_cb_add_t cb_add,
    aio_cb_delete_t cb_delete,
    aio_cb_read_t cb_read,
    aio_cb_write_t cb_write,
    aio_cb_error_t cb_error);
void aio_event_del(aio_event_t *event);
void aio_event_del_fd(aio_t *aio, int fd);

void aio_enable_poll_events(aio_event_t *event, aio_poll_event_t poll_events);
void aio_disable_poll_events(aio_event_t *event, aio_poll_event_t poll_events);

void aio_cb_delete_close_fd(aio_event_t *event);

#endif