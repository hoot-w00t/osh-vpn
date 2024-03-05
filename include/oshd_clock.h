#ifndef OSH_OSHD_CLOCK_H_
#define OSH_OSHD_CLOCK_H_

#include <time.h>
#include <sys/time.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>

// Used to cast time_t when printing it using printf()
typedef int64_t pri_time_t;
#define PRI_TIME_T PRId64

// https://cr.yp.to/libtai/tai64.html
#ifndef NSEC_MAX
    // Nanoseconds in a second
    #define NSEC_MAX (1000000000)
#endif

#define TAI64_SEC_ZERO          UINT64_C(0x4000000000000000)
#define NSEC_VALID(tv_nsec)     (tv_nsec >= 0 && tv_nsec < NSEC_MAX)

// Portable TAI64N 96-bit timestamp
struct __attribute__((packed)) tai64n {
    uint64_t tv_sec;
    uint32_t tv_nsec;
};

#if defined(CLOCK_BOOTTIME)
    #define OSHD_CLOCK_MONOTONIC CLOCK_BOOTTIME
#elif defined(CLOCK_MONOTONIC)
    #define OSHD_CLOCK_MONOTONIC CLOCK_MONOTONIC
#endif

void oshd_getepoch(struct timespec *ts);

void oshd_gettime(struct timespec *ts);
void oshd_gettime_delay(struct timespec *ts, time_t delay_s);

bool timespec_to_tai64n(struct tai64n *tai64n, const struct timespec *ts);

#ifndef timespecadd
// timeradd for timespec structures
#define timespecadd(a, b, result)                           \
    do {                                                    \
        (result)->tv_sec = (a)->tv_sec + (b)->tv_sec;       \
        (result)->tv_nsec = (a)->tv_nsec + (b)->tv_nsec;    \
        if ((result)->tv_nsec >= 1000000000) {              \
            ++(result)->tv_sec;                             \
            (result)->tv_nsec -= 1000000000;                \
        }                                                   \
    } while (0)
#endif // timespecadd

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
