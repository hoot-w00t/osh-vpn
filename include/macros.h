#ifndef _OSH_MACROS_H
#define _OSH_MACROS_H

#include <errno.h>

#define IO_WOULDBLOCK(err) ((err) == EAGAIN || (err) == EWOULDBLOCK)

#define PLATFORM_IS_LINUX (__linux__)
#define PLATFORM_IS_WINDOWS (_WIN32 || __CYGWIN__ || __MSYS__)

// Only one of these macros should be true
#if PLATFORM_IS_LINUX && PLATFORM_IS_WINDOWS
#error "Platform detection is broken"
#endif

#endif