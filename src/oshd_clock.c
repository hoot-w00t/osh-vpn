#include "oshd_clock.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

// Stores the current elapsed time in *ts
// Aborts on error
void oshd_gettime(struct timespec *ts)
{
    if (clock_gettime(OSHD_CLOCK_MONOTONIC, ts) != 0) {
        fprintf(stderr, "%s:%i:%s: %s\n", __FILE__, __LINE__, __func__, strerror(errno));
        abort();
    }
}

// Stores the current elapsed time + delay (in seconds) in *ts
// Aborts on error
void oshd_gettime_delay(struct timespec *ts, time_t delay_s)
{
    oshd_gettime(ts);
    ts->tv_sec += delay_s;
}
