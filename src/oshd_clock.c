#include "oshd_clock.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

// Stores the current elapsed time in *tp
// Aborts on error
void oshd_gettime(struct timespec *tp)
{
    if (clock_gettime(oshd_gettime_clock, tp)) {
        printf("%s:%i:%s: %s\n", __FILE__, __LINE__, __func__, strerror(errno));
        abort();
    }
}

// Stores the current elapsed time + delay (in seconds) in *tp
// Aborts on error
void oshd_gettime_delay(struct timespec *tp, time_t delay)
{
    oshd_gettime(tp);
    tp->tv_sec += delay;
}