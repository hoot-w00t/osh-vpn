#ifndef _OSH_MACROS_H
#define _OSH_MACROS_H

#include "macros_bitfields.h"
#include <errno.h>

#define IO_WOULDBLOCK(err) ((err) == EAGAIN || (err) == EWOULDBLOCK)

// Platform detection
#if defined(__linux__)
    #define PLATFORM_IS_LINUX 1
#endif

#if defined(_WIN32) || defined(__CYGWIN__) || defined(__MSYS__)
    #define PLATFORM_IS_WINDOWS 1
#endif

// This macro should always equal to 1
#define PLATFORM_COUNT (PLATFORM_IS_LINUX + PLATFORM_IS_WINDOWS)

// We can only have one platform defined
#if PLATFORM_COUNT > 1
#error "Multiple platforms were recognized"
#endif

// We should always have a platform defined (even if having none does not
// prevent the code from compiling and working)
#if PLATFORM_COUNT <= 0
#warning "No platform was recognized"
#endif

#endif
