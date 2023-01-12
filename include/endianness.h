#ifndef _OSH_ENDIANNESS_H
#define _OSH_ENDIANNESS_H

// This header includes the definitions for byte order conversions

#include "macros.h"

// _OSH_ENDIANNESS is the host endianness
// If it is set to a valid endianness we will define the byte swapping functions
// using bswap.h
#ifdef _OSH_ENDIANNESS
#undef _OSH_ENDIANNESS
#endif

#define _OSH_ENDIANNESS_DISABLE 1   // Byte swapping and endianness are already
                                    // defined elsewhere

#define _OSH_ENDIANNESS_LITTLE  2   // Little endian
#define _OSH_ENDIANNESS_BIG     3   // Big endian

#if PLATFORM_IS_LINUX
    // endian.h has all the needed functions, don't re-define them
    #define _OSH_ENDIANNESS _OSH_ENDIANNESS_DISABLE
    #include <endian.h>

#elif PLATFORM_IS_WINDOWS
    #include <sys/param.h>

    #if !defined(BYTE_ORDER)
        #error "Unknown endianness: BYTE_ORDER undefined"
    #endif

    #if (BYTE_ORDER == LITTLE_ENDIAN)
        #define _OSH_ENDIANNESS _OSH_ENDIANNESS_LITTLE
    #elif (BYTE_ORDER == BIG_ENDIAN)
        #define _OSH_ENDIANNESS _OSH_ENDIANNESS_BIG
    #else
        #error "Unknown endianness"
    #endif

#else
    #warning "Unsupported platform"
#endif

// If _OSH_ENDIANNESS is defined and is not disabled, define the byte swapping
// macros using our own bswap functions
#if defined(_OSH_ENDIANNESS) && (_OSH_ENDIANNESS != _OSH_ENDIANNESS_DISABLE)
    #include "bswap.h"

    #if (_OSH_ENDIANNESS == _OSH_ENDIANNESS_LITTLE)
        // Little-endian

        #define htole16(x)  (x)
        #define letoh16(x)  (x)
        #define htobe16(x)  osh_bswap16(x)
        #define betoh16(x)  osh_bswap16(x)

        #define htole32(x)  (x)
        #define letoh32(x)  (x)
        #define htobe32(x)  osh_bswap32(x)
        #define betoh32(x)  osh_bswap32(x)

        #define htole64(x)  (x)
        #define letoh64(x)  (x)
        #define htobe64(x)  osh_bswap64(x)
        #define betoh64(x)  osh_bswap64(x)

    #elif (_OSH_ENDIANNESS == _OSH_ENDIANNESS_BIG)
        // Big-endian

        #define htole16(x)  osh_bswap16(x)
        #define letoh16(x)  osh_bswap16(x)
        #define htobe16(x)  (x)
        #define betoh16(x)  (x)

        #define htole32(x)  osh_bswap32(x)
        #define letoh32(x)  osh_bswap32(x)
        #define htobe32(x)  (x)
        #define betoh32(x)  (x)

        #define htole64(x)  osh_bswap64(x)
        #define letoh64(x)  osh_bswap64(x)
        #define htobe64(x)  (x)
        #define betoh64(x)  (x)
    #else
        #error "Unknown _OSH_ENDIANNESS value"
    #endif
#endif

#endif
