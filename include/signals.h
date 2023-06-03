#ifndef _OSH_SIGNALS_H
#define _OSH_SIGNALS_H

#include "macros.h"
#include "aio.h"

#if PLATFORM_IS_WINDOWS
    #include <windows.h>
    #include <inttypes.h>

    typedef DWORD signal_t;
    #define PRI_SIGNAL_T "%lu"
#else
    #include <signal.h>

    typedef int signal_t;
    #define PRI_SIGNAL_T "%d"
#endif

void signal_init(aio_t *aio);
void signal_deinit(void);

const char *signal_name(signal_t sig);

#endif
