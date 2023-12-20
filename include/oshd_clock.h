#ifndef _OSH_OSHD_CLOCK_H
#define _OSH_OSHD_CLOCK_H

#include <time.h>
#include <sys/time.h>
#include <inttypes.h>

// Used to cast time_t when printing it using printf()
typedef int64_t pri_time_t;
#define PRI_TIME_T PRId64

#if defined(CLOCK_BOOTTIME)
    #define OSHD_CLOCK_MONOTONIC CLOCK_BOOTTIME
#else
    #define OSHD_CLOCK_MONOTONIC CLOCK_MONOTONIC
#endif

void oshd_gettime(struct timespec *ts);
void oshd_gettime_delay(struct timespec *ts, time_t delay_s);

#ifndef timespecsub
// timersub for timespec structures
#define timespecsub(a, b, result)                           \
    do {                                                    \
        (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;       \
        (result)->tv_nsec = (a)->tv_nsec - (b)->tv_nsec;    \
        if ((result)->tv_nsec < 0) {                        \
            --(result)->tv_sec;                             \
            (result)->tv_nsec += 1000000000;                \
        }                                                   \
    } while (0)
#endif // timespecsub

#ifndef timespec_to_timeval
#define timespec_to_timeval(tv, ts)             \
    {                                           \
        (tv)->tv_sec = (ts)->tv_sec;            \
        (tv)->tv_usec = (ts)->tv_nsec / 1000;   \
    }
#endif // timespec_to_timeval

#endif
