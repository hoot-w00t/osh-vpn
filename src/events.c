#include "oshd.h"
#include "events.h"
#include "logger.h"
#include "xalloc.h"
#include "macros.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#ifdef EVENTS_USE_TIMERFD
#include <sys/timerfd.h>

static aio_event_t *event_queue_aio = NULL;
#endif

static event_t *event_queue_head = NULL;

// When this is true update_timer_interval() does not update the timer interval
// This is to avoid useless/redundant updates while processing the event queue
static bool timer_update_lock = false;
static struct timespec timer_next_timeout;

// Update timerfd interval
// If there is at least one queued event, calculate the delay after which the
// first event should trigger and set the timerfd's interval to this delay
static bool update_timer_interval(void)
{
    struct timespec now;

    // Don't update the timerfd timeout if it was locked, or there are no
    // events queued
    if (timer_update_lock || !event_queue_head)
        return false;

    // Get the current time
    oshd_gettime(&now);

    // Calculate the remaining time before the next event should occur
    timespecsub(&event_queue_head->trigger_at, &now, &timer_next_timeout);

#ifdef EVENTS_USE_TIMERFD
    struct itimerspec aio_timer;

    // Make sure that an AIO event exists before trying to access it
    if (!event_queue_aio)
        return false;

    // We aren't using the timerfd's it_interval
    aio_timer.it_interval.tv_sec = 0;
    aio_timer.it_interval.tv_nsec = 0;

    if (timer_next_timeout.tv_sec < 0) {
        // If the remaining time is negative then the event should have already
        // been processed, set the timeout to the shortest delay
        aio_timer.it_value.tv_sec = 0;
        aio_timer.it_value.tv_nsec = 1;
    } else {
        // Otherwise set the timeout to the remaining time before the event
        // should trigger
        aio_timer.it_value.tv_sec = timer_next_timeout.tv_sec;
        aio_timer.it_value.tv_nsec = timer_next_timeout.tv_nsec;
    }

    // Arm the timer with the new timeout
    if (timerfd_settime(event_queue_aio->fd, 0, &aio_timer, NULL) < 0) {
        logger(LOG_CRIT,
            "Failed to set events timer: %s (fd=" PRI_AIO_FD_T ", %li.%09lis)",
            strerror(errno),
            event_queue_aio->fd,
            aio_timer.it_value.tv_sec,
            aio_timer.it_value.tv_nsec);
        return false;
    }
#endif

    logger_debug(DBG_EVENTS, "Updated timer timeout to %li.%09lis",
        timer_next_timeout.tv_sec, timer_next_timeout.tv_nsec);

    return true;
}

// Process all events in the event queue that should trigger
void event_process_queued(void)
{
    event_t *event;
    struct timespec now;
    struct timespec diff;
    struct timespec max_diff = {0};
    time_t new_delay;

    // Don't update the timer if events are queued/cancelled while we are
    // processing events as we will do it before returning
    timer_update_lock = true;

    // Get the current time to compare with the triggers
    oshd_gettime(&now);

    // We will process events while there are some in the queue
    while (event_queue_head) {
        // The event queue is sorted by trigger time, so whenever the next
        // event is not triggered yet, no other events will trigger
        timespecsub(&now, &event_queue_head->trigger_at, &diff);
        if (diff.tv_sec < 0)
            break;

        // Pop the event
        event = event_queue_head;

        // Move the event queue to the next event
        event_queue_head = event->next;
        event->in_queue = false;

        // If the event's trigger time is set to EVENT_QUEUE_NOW, set the delay
        // to 0 since it is invalid (not relative to the current time)
        if (event->trigger_at.tv_sec == 0 && event->trigger_at.tv_nsec == 0)
            diff = event->trigger_at;

        // Remember delays bigger than 10 seconds
        // We only remember the first delay since the event queue is sorted by
        // ascending trigger time, other events will have a smaller/equal delay
        if (max_diff.tv_sec <= 0 && diff.tv_sec >= 10)
            max_diff = diff;

        // Handle the current event
        logger_debug(DBG_EVENTS, "Processing %s event %p (delay %li.%09lis)",
            event->name, event, diff.tv_sec, diff.tv_nsec);

        new_delay = event->handler(event, &diff, event->userdata);

        // If the event handler returned a positive value, queue the event again
        // using this delay
        if (new_delay >= 0) {
            event_queue_in(event, new_delay);
        } else {
            event_free(event);
        }
    }

    // This should only happen after the system or process is suspended and
    // resumes, otherwise it indicates that the daemon is overwhelmed
    // FIXME: This is not a very accurate method as it relies on timed events
    if (max_diff.tv_sec != 0) {
        logger(LOG_WARN, "Event loop running %li.%09li seconds late",
            max_diff.tv_sec, max_diff.tv_nsec);
    }

    // Update the timer now that the event queue was processed
    timer_update_lock = false;
    update_timer_interval();
}

#ifdef EVENTS_USE_TIMERFD
// Handle timerfd expiring (processes the event queue)
static void event_aio_process(aio_event_t *event)
{
    uint64_t expirations = 0;

    // Disarm the timerfd
    if (read(event->fd, &expirations, sizeof(expirations)) < 0) {
        if (IO_WOULDBLOCK(errno)) {
            // This error indicates that the timer hasn't expired yet
            logger(LOG_WARN, "Events timerfd misfired");
        } else {
            logger(LOG_ERR, "Events timerfd: read: %s", strerror(errno));
        }
        return;
    }

    logger_debug(DBG_EVENTS,
        "Events timerfd expired %" PRIu64 " times (fd=" PRI_AIO_FD_T ")",
        expirations, event->fd);

    // Process queued events (at least one event should be processed every time
    // we call this function, otherwise there could be an issue with the timer)
    event_process_queued();
}

// Handle timerfd polling errors
static void event_aio_error(__attribute__((unused)) aio_event_t *event,
    __attribute__((unused)) aio_poll_event_t revents)
{
    logger(LOG_CRIT, "Events timerfd AIO error");

    // If the timed events' timer doesn't work we cannot call oshd_stop() to
    // gracefully exit, abort()
    abort();
}

// Initialize the event loop
// Adds an AIO event to oshd.aio
bool event_init(void)
{
    int timerfd = timerfd_create(oshd_gettime_clock, TFD_NONBLOCK | TFD_CLOEXEC);

    if (timerfd < 0) {
        logger(LOG_CRIT, "event_init: Failed to create timerfd: %s", strerror(errno));
        return false;
    }

    memset(&timer_next_timeout, 0, sizeof(timer_next_timeout));
    event_queue_aio = aio_event_add_inl(oshd.aio,
        timerfd,
        AIO_READ,
        NULL,
        NULL,
        aio_cb_delete_close_fd,
        event_aio_process,
        NULL,
        event_aio_error);
    return true;
}
#else
time_t event_get_timeout_ms(void)
{
    if (timer_next_timeout.tv_sec < 0)
        return 0;

    return    (timer_next_timeout.tv_sec  * 1000)
            + (timer_next_timeout.tv_nsec / 1000000)
            + 1;
}

bool event_init(void)
{
    memset(&timer_next_timeout, 0, sizeof(timer_next_timeout));
    return true;
}
#endif

// Return an allocated event_t
event_t *event_create(
    const char *name,
    event_handler_t handler,
    event_freedata_t freedata,
    void *userdata)
{
    event_t *event = xzalloc(sizeof(event_t));

    logger_debug(DBG_EVENTS, "Creating %s event %p", name, event);
    strncpy(event->name, name, sizeof(event->name) - 1);
    event->handler = handler;
    event->freedata = freedata;
    event->userdata = userdata;
    return event;
}

// Free *event and its resources
void event_free(event_t *event)
{
    logger_debug(DBG_EVENTS, "Freeing %s event %p", event->name, event);
    if (event->freedata)
        event->freedata(event, event->userdata);
    free(event);
}

// Removes a queued event
// Returns true if the event was removed from the queue, false if it wasn't queued
static bool event_unqueue(event_t *event)
{
    event_t **i = &event_queue_head;

    // We will loop through all the queued events until we find the one we want
    // to remove
    while (*i) {
        if ((*i) == event) {
            // We found the event to remove
            logger_debug(DBG_EVENTS, "Unqueuing %s event %p",
                event->name, event);

            // Replace the next event pointed to by i to the one that will come
            // after
            *i = (*i)->next;
            event->in_queue = false;
            return true;
        }

        // Otherwise we iterate until the end of the queue
        i = &(*i)->next;
    }

    // The event was not found in the queue, return false
    return false;
}

// Convert time_t delay into trigger_at timestamp
// If now is NULL, gets the current time using oshd_gettime()
static void event_trigger_at_from_delay(struct timespec *trigger_at,
    const time_t delay, const struct timespec *now)
{
    if (delay > 0) {
        if (now) {
            *trigger_at = *now;
        } else {
            oshd_gettime(trigger_at);
        }

        trigger_at->tv_sec  += EVENT_DELAY_TO_SEC(delay);
        trigger_at->tv_nsec += EVENT_DELAY_TO_NSEC(delay);
        while (trigger_at->tv_nsec >= EVENT_NSEC_MAX) {
            trigger_at->tv_nsec -= EVENT_NSEC_MAX;
            trigger_at->tv_sec  += 1;
        }
    } else {
        trigger_at->tv_sec  = 0;
        trigger_at->tv_nsec = 0;
    }
}

// Add an event to the queue which will trigger in delay milliseconds from now
// Automatically checks whether the event is already queued to prevent doubles
// Can be used to change the trigger of an already queued event
void event_queue_in(event_t *event, time_t delay)
{
    event_t **i = &event_queue_head;
    struct timespec trigger_at;
    struct timespec diff;

    // Calculate the event's trigger time
    event_trigger_at_from_delay(&trigger_at, delay, NULL);

    // Check if the event was already queued
    if (event->in_queue) {
        // Compare the new trigger time with the previous
        timespecsub(&trigger_at, &event->trigger_at, &diff);

        if (diff.tv_sec == 0 && diff.tv_nsec == 0) {
            // The new trigger time is the same as the previous one, we can
            // return now as no changes will be made
            logger_debug(DBG_EVENTS, "Queuing %s event %p in %li" EVENT_DELAY_UNIT " (no changes)",
                event->name, event, delay);
            return;
        }

        // The event's trigger time changed, we will update it by removing it
        // and adding it back with the new delay
        event_unqueue(event);
    }

    // Set the trigger time and queue the event
    event->trigger_at = trigger_at;
    logger_debug(DBG_EVENTS, "Queuing %s event %p in %li" EVENT_DELAY_UNIT,
        event->name, event, delay);

    // Sort the events by their trigger time (ascending)
    while (*i) {
        // Subtract the selected event's trigger time from our new event's trigger time
        // If the resulting seconds are negative our event's trigger time is smaller, so it should
        // trigger before the selected one, we will insert it before the selected one
        timespecsub(&event->trigger_at, &(*i)->trigger_at, &diff);
        if (diff.tv_sec < 0)
            break;

        // Iterate to the next event in the queue
        i = &(*i)->next;
    }

    // Insert our new event before the selected event
    event->next = *i;
    *i = event;
    event->in_queue = true;

    // Only update the event timer if this new event was inserted at the head of the queue
    if (i == &event_queue_head)
        update_timer_interval();
}

// Cancel a single event from the queue, if the event is not queued nothing is
// done
void event_cancel(event_t *event)
{
    if (!event) return;

    if (event_unqueue(event)) {
        // The event was successfully removed from the queue
        logger_debug(DBG_EVENTS, "Canceling %s event %p",
            event->name, event);
        event_free(event);
    } else {
        // This should not happen, if it does something went wrong
        logger(LOG_CRIT,
            "Failed to cancel %s event %p: It was not found in the queue",
            event->name, event);
    }
}

// Cancel all events in the queue
void event_cancel_queue(void)
{
    event_t *i = event_queue_head;
    event_t *next;

    // Iterate over the entire event queue and free everything
    while (i) {
        next = i->next;
        event_free(i);
        i = next;
    }

    // The queue was entirely freed, now we can mark it as empty
    event_queue_head = NULL;
}
