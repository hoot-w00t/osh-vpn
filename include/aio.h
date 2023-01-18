#ifndef _OSH_AIO_H
#define _OSH_AIO_H

#include "macros.h"
#include <sys/types.h>
#include <stdbool.h>
#include <stddef.h>

typedef struct aio aio_t;
typedef struct aio_event aio_event_t;
typedef struct aio_pending aio_pending_t;

#define AIO_PE_FMT "%u"
typedef enum aio_poll_event {
    AIO_NOPOLL = 0,
    AIO_READ  = (1 << 0),
    AIO_WRITE = (1 << 1),
    AIO_ERR   = (1 << 2),
    AIO_HUP   = (1 << 3)
} aio_poll_event_t;
#define AIO_POLLALL (AIO_READ | AIO_WRITE)

// Safely use an aio_poll_event_t as an index for these values only
// 0: AIO_NOPOLL
// 1: AIO_READ
// 2: AIO_WRITE
// 3: AIO_POLLALL (AIO_READ | AIO_WRITE)
#define aio_poll_event_idx(x) ((x) & 3)

// Safely use an aio_poll_event_t as an index for these error values only
// 0: No error
// 1: AIO_ERR
// 2: AIO_HUP
// 3: AIO_ERR | AIO_HUP
#define aio_poll_event_err_idx(x) (((x) >> 2) & 3)

typedef void (*aio_cb_t)(aio_event_t *event);
typedef aio_cb_t aio_cb_add_t;
typedef aio_cb_t aio_cb_delete_t;
typedef aio_cb_t aio_cb_read_t;
typedef aio_cb_t aio_cb_write_t;
typedef void (*aio_cb_error_t)(aio_event_t *event, aio_poll_event_t revents);

#if PLATFORM_IS_WINDOWS
    #include "sock.h"

    typedef sock_t aio_fd_t;
    #define PRI_AIO_FD_T PRI_SOCK_T

    typedef HANDLE aio_handle_t;
    #define PRI_AIO_HANDLE_T "%p"
#else
    typedef int aio_fd_t;
    #define PRI_AIO_FD_T "%d"
#endif

// Generic data types for the aio_t and aio_event_t structures
typedef union aio_data {
    void *ptr;
    aio_fd_t fd;
} aio_data_t;
typedef aio_data_t aio_event_data_t;

struct aio_pending {
    aio_event_t *event;
    bool add;
    aio_pending_t *next;
};

struct aio {
    // Async I/O events
    aio_event_t **events;

    // Number of AIO events
    size_t events_count;

    // This holds a list of events to add/delete
    aio_pending_t *queue_head;

    // Generic data
    aio_data_t data;
};

struct aio_event {
    // File descriptor to poll for I/O events
    aio_fd_t fd;

#if PLATFORM_IS_WINDOWS
    // Windows HANDLE/WSAEVENT to poll for I/O events
    // Socket events only need a file descriptor, the handles are automatically
    // set up
    // Non-socket events must use aio_event_set_handles() to configure the
    // handles correctly
    // Each handle is used to signal the corresponding callback (read/write)
    aio_handle_t read_handle;
    bool read_auto_reset;

    aio_handle_t write_handle;
    bool write_auto_reset;
#endif

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

    // Pointer to the aio_t this event is a part of
    aio_t *aio;

    // Index of this event_t in aio->events
    size_t aio_idx;

    // true when this event is queued for addition/deletion (used internally to
    // know the state of the event and prevent some errors, like deleting the
    // same event twice, or accessing unallocated memory)
    bool added_to_aio;
    bool pending_delete;

    // Generic data
    aio_event_data_t data;
};

aio_t *aio_create(void);
void aio_free(aio_t *aio);
ssize_t aio_poll(aio_t *aio, ssize_t timeout);

#define aio_events_count(aio) ((aio)->events_count)
#define aio_has_queued_events(aio) ((aio)->queue_head != NULL)

aio_event_t *aio_event_add(aio_t *aio, const aio_event_t *event);
aio_event_t *aio_event_add_inl(aio_t *aio,
    aio_fd_t fd,
    aio_poll_event_t poll_events,
    void *userdata,
    aio_cb_add_t cb_add,
    aio_cb_delete_t cb_delete,
    aio_cb_read_t cb_read,
    aio_cb_write_t cb_write,
    aio_cb_error_t cb_error);
void aio_event_del(aio_event_t *event);
void aio_event_del_fd(aio_t *aio, aio_fd_t fd);

#if !(PLATFORM_IS_WINDOWS)
void aio_cb_delete_close_fd(aio_event_t *event);
#endif

// These functions are implementation specific
void aio_enable_poll_events(aio_event_t *event, aio_poll_event_t poll_events);
void aio_disable_poll_events(aio_event_t *event, aio_poll_event_t poll_events);

#endif

#if PLATFORM_IS_WINDOWS
// Windows-specific functions

// Set the AIO event's read/write handles and mark it as a non-socket event
// The manual reset boolean should reflect the event handle's bManualReset value
// Unused handles must be set to NULL
void aio_event_set_handles(aio_event_t *event,
    aio_handle_t read_handle, bool read_manual_reset,
    aio_handle_t write_handle, bool write_manual_reset);
#endif

#ifdef _OSH_AIO_C
// Implementation specific function prototypes that should not be used outside
// of the AIO

// This function should free any generic data from the aio_event_t that was
// allocated by _aio_event_init()
void _aio_event_free(aio_event_t *event);

// This function is called after the aio_event_t is allocated but before
// it is inserted in an aio_t
void _aio_event_init(aio_event_t *event);

// This function is called when the aio_event_t is inserted in the aio_t
void _aio_event_add(aio_t *aio, aio_event_t *event);

// This function is called when an event is being deleted from an AIO
void _aio_event_delete(aio_t *aio, aio_event_t *event);

// This function is called after the aio_t is allocated
// On success it must return the aio pointer passed to it, on error it should
// return NULL and free any allocated data
aio_t *_aio_create(aio_t *aio);

// This function is called after clearing all events from the aio_t
// It should free any generic data from the aio_t
void _aio_free(aio_t *aio);

// This function polls for any I/O events on the events added to the AIO
// It calls the AIO event's callbacks when the requested events are ready
// timeout is the maximum amount of time (in milliseconds) to wait for I/O
//   events before returning
//   A value of 0 does not wait and processes events that are already ready
//   A negative value waits for I/O events forever
// It returns the number of events that were ready, or -1 for errors
ssize_t _aio_poll(aio_t *aio, ssize_t timeout);

#endif
