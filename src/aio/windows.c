#define _OSH_AIO_C

#include "aio.h"
#include "logger.h"
#include "xalloc.h"
#include <stdlib.h>

// Socket FD_* poll events
#define _fd_error_events    (FD_CLOSE)
#define _fd_read_events     (FD_READ | FD_ACCEPT)
#define _fd_write_events    (FD_WRITE | FD_CONNECT)

static const long _fd_events[4] = {
    // AIO_NOPOLL
    _fd_error_events,

    // AIO_READ
    _fd_read_events | _fd_error_events,

    // AIO_WRITE
    _fd_write_events | _fd_error_events,

    // AIO_POLLALL (or AIO_READ | AIO_WRITE)
    _fd_read_events | _fd_write_events | _fd_error_events
};
#define fd_events(x) _fd_events[aio_poll_event_idx(x)]

typedef struct aio_data_windows {
    // TODO: Handle more than MAXIMUM_WAIT_OBJECTS in total
    aio_handle_t handles[MAXIMUM_WAIT_OBJECTS];
    size_t handles_count;

    bool handles_need_update;
} aio_data_windows_t;
#define aio_data(aio) ((aio_data_windows_t *) (aio)->data.ptr)

typedef struct aio_event_data_windows {
    aio_poll_event_t shadow_poll_events;
} aio_event_data_windows_t;
#define event_data(event) ((aio_event_data_windows_t *) (event)->data.ptr)

// true if the AIO event is about a socket
#define event_is_socket(event) ((event)->fd != invalid_sock_t)

// Handle used for sockets in the event data
#define event_socket_handle(event) (event)->read_handle

// This function only initializes the handles for non-socket events without
// modifying the file descriptor
static void init_event_handles(aio_event_t *event,
    aio_handle_t read_handle, bool read_manual_reset,
    aio_handle_t write_handle, bool write_manual_reset)
{
    event->read_handle = read_handle;
    event->read_auto_reset = !read_manual_reset;

    event->write_handle = write_handle;
    event->write_auto_reset = !write_manual_reset;
}

void aio_event_set_handles(aio_event_t *event,
    aio_handle_t read_handle, bool read_manual_reset,
    aio_handle_t write_handle, bool write_manual_reset)
{
    event->fd = invalid_sock_t;
    init_event_handles(event, read_handle, read_manual_reset, write_handle, write_manual_reset);
}

// Add handle to the AIO if it is not NULL
// This must only be used by update_aio_handles()
static void add_aio_handle(aio_t *aio, aio_handle_t handle)
{
    if (handle) {
        if (aio_data(aio)->handles_count >= MAXIMUM_WAIT_OBJECTS) {
            logger(LOG_WARN, "%s: Not enough room for handle " PRI_AIO_HANDLE_T,
                __func__, handle);
            return;
        }

        aio_data(aio)->handles[aio_data(aio)->handles_count] = handle;
        aio_data(aio)->handles_count += 1;
    }
}

// Populate event handles array and count
// Only watch valid handles which should be polled
static void update_aio_handles(aio_t *aio)
{
    aio_data(aio)->handles_count = 0;

    for (size_t i = 0; i < aio->events_count; ++i) {
        aio_event_t *event = aio->events[i];

        if (event_is_socket(event)) {
            add_aio_handle(aio, event_socket_handle(event));
        } else {
            if (event->poll_events & AIO_READ)
                add_aio_handle(aio, event->read_handle);

            if (event->poll_events & AIO_WRITE)
                add_aio_handle(aio, event->write_handle);
        }
    }
}

// Link socket to the event's handle and set the network events to poll for
// This function must only be called on socket events which are added to the AIO
static void update_socket_poll_events(aio_event_t *event)
{
    if (WSAEventSelect(event->fd, event_socket_handle(event), fd_events(event->poll_events)) == SOCKET_ERROR) {
        logger(LOG_ERR, "%s: %s", __func__, sock_strerror(sock_errno));
        aio_event_del(event);
    }
}

// Lookup event handle
// This should always return, it calls abort() on error
// TODO: Optimize lookup
static aio_event_t *lookup_event_by_handle(aio_t *aio, aio_handle_t handle)
{
    for (size_t i = 0; i < aio->events_count; ++i) {
        if (   aio->events[i]->read_handle == handle
            || aio->events[i]->write_handle == handle)
        {
            return aio->events[i];
        }
    }

    // The handle could not be found, this should never happen
    logger(LOG_CRIT, "%s: %s: Handle " PRI_AIO_HANDLE_T " could not be found",
        __FILE__, __func__, handle);
    abort();
}

void _aio_event_free(__attribute__((unused)) aio_event_t *event)
{
    free(event->data.ptr);
}

void _aio_event_init(aio_event_t *event)
{
    event->data.ptr = xzalloc(sizeof(aio_event_data_windows_t));
}

void _aio_event_add(aio_t *aio, aio_event_t *event)
{
    event_data(event)->shadow_poll_events = event->poll_events;

    if (event_is_socket(event)) {
        // Sockets only have a file descriptor, we will create an event and link
        // the socket to it with the requested poll events

        init_event_handles(event, NULL, true, NULL, true);

        event_socket_handle(event) = WSACreateEvent();
        if (event_socket_handle(event) == WSA_INVALID_EVENT) {
            logger(LOG_ERR, "%s: %s", __func__, sock_strerror(sock_errno));
            aio_event_del(event);
            return;
        }

        update_socket_poll_events(event);
    } else {
        // Non-socket events must already have their handles configured
    }

    aio_data(aio)->handles_need_update = true;
}

void _aio_event_delete(aio_t *aio, aio_event_t *event)
{
    if (event_is_socket(event)) {
        // Deinitialize socket handle and close it

        if (WSAEventSelect(event->fd, event_socket_handle(event), 0) == SOCKET_ERROR)
            logger(LOG_WARN, "%s: %s", __func__, sock_strerror(sock_errno));

        if (!WSACloseEvent(event_socket_handle(event)))
            logger(LOG_WARN, "%s: %s: %s", __func__, "WSACloseEvent", sock_strerror(sock_errno));
    }

    aio_data(aio)->handles_need_update = true;
}

aio_t *_aio_create(aio_t *aio)
{
    aio->data.ptr = xzalloc(sizeof(aio_data_windows_t));
    return aio;
}

void _aio_free(aio_t *aio)
{
    free(aio->data.ptr);
}

// Handle AIO_WRITE for all sockets
// Returns the total number of write callbacks
static ssize_t handle_socket_writes(aio_t *aio)
{
    ssize_t count = 0;

    // The FD_WRITE event doesn't fire when the socket can be written to without
    // blocking, it triggers after connecting/accepting and when the socket
    // changes from blocking to non-blocking
    //
    // To make sure that write handlers are honored we have to manually call
    // them, until either the socket becomes blocking or AIO_WRITE is no longer
    // requested by the event
    //
    // This only applies to sockets, other handles are not affected by this
    for (size_t i = 0; i < aio->events_count; ++i) {
        aio_event_t *event = aio->events[i];

        // Skip non-socket events and those without a write callback
        if (!event_is_socket(event) || !event->cb_write)
            continue;

        while (   (event->poll_events & AIO_WRITE)
               && sock_send(event->fd, NULL, 0, 0) == 0)
        {
            event->cb_write(event);
            count += 1;
        }
    }

    return count;
}

static void handle_socket_event(aio_event_t *event)
{
    // The handle is signaled, but we don't know what network events are
    // active yet
    WSANETWORKEVENTS net_events;
    int err;

    // This function automatically resets the handle event
    err = WSAEnumNetworkEvents(event->fd, event_socket_handle(event), &net_events);
    if (err != 0) {
        logger(LOG_ERR, "%s: %s: %s", __func__, "WSAEnumNetworkEvents",
            win_strerror(WSAGetLastError()));
        aio_event_del(event);
        return;
    }

    if (net_events.lNetworkEvents & _fd_error_events) {
        // The connection was likely closed, pass AIO_HUP
        if (event->cb_error)
            event->cb_error(event, AIO_HUP);
        return;
    }

    if (   ((net_events.lNetworkEvents & FD_WRITE)   && net_events.iErrorCode[FD_WRITE_BIT]   != 0)
        || ((net_events.lNetworkEvents & FD_CONNECT) && net_events.iErrorCode[FD_CONNECT_BIT] != 0))
    {
        // Socket errors, pass AIO_ERR
        if (event->cb_error)
            event->cb_error(event, AIO_ERR);
        return;
    }

    if ((net_events.lNetworkEvents & _fd_read_events) && event->cb_read)
        event->cb_read(event);

    if ((net_events.lNetworkEvents & _fd_write_events) && event->cb_write)
        event->cb_write(event);
}

static bool handle_signaled_event(aio_event_t *event, aio_handle_t handle,
    bool auto_reset, aio_cb_t cb)
{
    // Check if the handle is valid and is signaled
    // We consider events that are reset automatically as signaled, otherwise
    // they will never be fired
    if (   handle
        && (auto_reset || WaitForSingleObject(handle, 0) == WAIT_OBJECT_0))
    {
        // The callback is responsible for resetting the handle, but we reset it
        // here if there is none to prevent it from firing non-stop
        if (cb)
            cb(event);
        else
            ResetEvent(handle);

        return true;
    }

    return false;
}

ssize_t _aio_poll(aio_t *aio, ssize_t timeout)
{
    DWORD wait_status;
    ssize_t polled_count;

    // Handle AIO_WRITE on all sockets
    polled_count = handle_socket_writes(aio);

    // If the AIO has pending events, one or more write callbacks have added or
    // deleted events in the AIO, return now to process them
    if (aio_has_queued_events(aio))
        return polled_count;

    // Update the handles array if needed
    if (aio_data(aio)->handles_need_update) {
        aio_data(aio)->handles_need_update = false;
        update_aio_handles(aio);
    }

    wait_status = WaitForMultipleObjectsEx(
        aio_data(aio)->handles_count,
        aio_data(aio)->handles,
        FALSE,
        (timeout < 0) ? WSA_INFINITE : (DWORD) timeout,
        FALSE);

    if (wait_status == WAIT_FAILED) {
        logger(LOG_ERR, "%s: %s: %s", __func__, "WaitForMultipleObjectsEx",
            win_strerror(WSAGetLastError()));
        return -1;
    }

    // WSAWaitForMultipleEvents was either interrupted or timed out, this is not
    // an error
    if (wait_status == WAIT_IO_COMPLETION || wait_status == WAIT_TIMEOUT)
        return 0;

    const size_t base_idx = wait_status - WAIT_OBJECT_0;

    for (size_t i = base_idx; i < aio_data(aio)->handles_count; ++i) {
        aio_handle_t handle = aio_data(aio)->handles[i];
        aio_event_t *event = lookup_event_by_handle(aio, handle);

        // Non-socket handles which don't have their respective poll events
        // enabled are not added to the watched handles, so we don't have to
        // check the poll events here

        if (event_is_socket(event)) {
            if (WaitForSingleObject(event_socket_handle(event), 0) == WAIT_OBJECT_0) {
                handle_socket_event(event);
                polled_count += 1;
            }

        } else if (handle == event->read_handle) {
            if (handle_signaled_event(event, handle, event->read_auto_reset, event->cb_read))
                polled_count += 1;

        } else if (handle == event->write_handle) {
            if (handle_signaled_event(event, handle, event->write_auto_reset, event->cb_write))
                polled_count += 1;
        }
    }

    // TODO: Return the actual number of signaled aio_event_t
    return polled_count;
}

// Update the poll events
static void update_poll_events(aio_event_t *event)
{
    if (event->poll_events == event_data(event)->shadow_poll_events)
        return;

    event_data(event)->shadow_poll_events = event->poll_events;

    if (event->added_to_aio) {
        if (event_is_socket(event)) {
            update_socket_poll_events(event);
        } else {
            aio_data(event->aio)->handles_need_update = true;
        }
    }
}

// Enables the given poll events
void aio_enable_poll_events(aio_event_t *event, aio_poll_event_t poll_events)
{
    event->poll_events |= poll_events;
    update_poll_events(event);
}

// Disables the given poll events
void aio_disable_poll_events(aio_event_t *event, aio_poll_event_t poll_events)
{
    event->poll_events &= ~(poll_events);
    update_poll_events(event);
}
