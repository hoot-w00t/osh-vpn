#include "oshd_clock.h"
#include "macros.h"
#include "macros_assert.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>

__attribute__((unused))
static void getepoch_nofail(struct timespec *ts)
{
#if defined(HAVE_GETTIMEOFDAY)
    struct timeval tv;

    gettimeofday(&tv, NULL);
    ts->tv_sec = tv.tv_sec;
    ts->tv_nsec = tv.tv_usec * 1000;
#else
    #error "getepoch_nofail() needs gettimeofday()"
#endif
}

// Get current time since epoch
void oshd_getepoch(struct timespec *ts)
{
#if defined(HAVE_CLOCK_GETTIME) && defined(CLOCK_REALTIME)
    if (clock_gettime(CLOCK_REALTIME, ts) != 0) {
        fprintf(stderr, "%s:%i:%s: %s\n", __FILE__, __LINE__, __func__, strerror(errno));
        getepoch_nofail(ts);
    }
#else
    getepoch_nofail(ts);
#endif
}

__attribute__((unused))
static void gettime_monotonic_from_epoch(struct timespec *ts)
{
    static pthread_mutex_t static_lock = PTHREAD_MUTEX_INITIALIZER;
    static bool initialized = false;
    static struct timespec last_epoch = {0};
    static struct timespec monotonic = {0};
    struct timespec now;
    struct timespec diff;

    pthread_mutex_lock(&static_lock);
    oshd_getepoch(&now);

    // Initialize last timestamp with the first one we get
    if (!initialized) {
        initialized = true;
        last_epoch = now;
    }

    // Calculate how much time has elapsed
    timespecsub(&now, &last_epoch, &diff);
    if (diff.tv_sec < 0) {
        // The epoch went back in time, leave the monotonic timestamp unchanged
        fprintf(stderr,
            "%s:%i:%s: epoch rolled back (%" PRI_TIME_T ".%09" PRI_TIME_T " seconds)\n",
            __FILE__, __LINE__, __func__, (pri_time_t) diff.tv_sec, (pri_time_t) diff.tv_nsec);
    } else {
        // Increase the monotonic timestamp by the elapsed time
        timespecadd(&monotonic, &diff, &monotonic);
    }

    // Always remember the current epoch to measure elapsed time since last call
    last_epoch = now;
    *ts = monotonic;

    pthread_mutex_unlock(&static_lock);
}

// Stores the current elapsed time in *ts
// Can abort on error
void oshd_gettime(struct timespec *ts)
{
    // Different monotonic sources return incompatible timestamps as they track
    // time differently (only one can be used, can't use a fallback if clock_gettime()
    // fails)

#if defined(HAVE_CLOCK_GETTIME) && defined(OSHD_CLOCK_MONOTONIC)
    if (clock_gettime(OSHD_CLOCK_MONOTONIC, ts) != 0) {
        fprintf(stderr, "%s:%i:%s: %s\n", __FILE__, __LINE__, __func__, strerror(errno));
        abort();
    }
#else
    gettime_monotonic_from_epoch(ts);
#endif

    assert(ts->tv_sec >= 0);
    assert(NSEC_VALID(ts->tv_nsec));
}

// Stores the current elapsed time + delay (in seconds) in *ts
// Can abort on error
void oshd_gettime_delay(struct timespec *ts, time_t delay_s)
{
    oshd_gettime(ts);
    ts->tv_sec += delay_s;
}

// Returns false if timespec value is invalid
// https://cr.yp.to/libtai/tai64.html
bool timespec_to_tai64n(struct tai64n *tai64n, const struct timespec *ts)
{
    if (!NSEC_VALID(ts->tv_nsec))
        return false;

    tai64n->tv_sec = TAI64_SEC_ZERO + ts->tv_sec;
    tai64n->tv_nsec = ts->tv_nsec;
    return true;
}
