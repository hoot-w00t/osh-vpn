#ifndef _OSH_ENDIANNESS_H
#define _OSH_ENDIANNESS_H

// This header includes the definitions for byte order conversions
// If _OSH_ENDIANNESS_DEBUG is defined warnings will be emitted to debug the
// endianness detection

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

    #if defined(_OSH_ENDIANNESS_DEBUG)
        #warning "Endianness: Linux (endian.h)"
    #endif

#elif PLATFORM_IS_WINDOWS
    #if defined(_OSH_ENDIANNESS_DEBUG)
        #warning "Endianness: Windows (detect with sys/param.h)"
    #endif

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

#elif PLATFORM_IS_MACOS
    #if defined(_OSH_ENDIANNESS_DEBUG)
        #warning "Endianness: MacOS (libkern/OSByteOrder.h)"
    #endif

    #define _OSH_ENDIANNESS _OSH_ENDIANNESS_DISABLE
    #include <libkern/OSByteOrder.h>

    #define htole16(x)  OSSwapHostToLittleInt16(x)
    #define letoh16(x)  OSSwapLittleToHostInt16(x)
    #define htobe16(x)  OSSwapHostToBigInt16(x)
    #define betoh16(x)  OSSwapBigToHostInt16(x)

    #define htole32(x)  OSSwapHostToLittleInt32(x)
    #define letoh32(x)  OSSwapLittleToHostInt32(x)
    #define htobe32(x)  OSSwapHostToBigInt32(x)
    #define betoh32(x)  OSSwapBigToHostInt32(x)

    #define htole64(x)  OSSwapHostToLittleInt64(x)
    #define letoh64(x)  OSSwapLittleToHostInt64(x)
    #define htobe64(x)  OSSwapHostToBigInt64(x)
    #define betoh64(x)  OSSwapBigToHostInt64(x)

#else
    // Try to detect endianness using compiler definitions

    #if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && defined(__ORDER_BIG_ENDIAN__)
        #if defined(_OSH_ENDIANNESS_DEBUG)
            #warning "Endianness: Unknown (detect using __BYTE_ORDER__)"
        #endif

        #if (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
            #define _OSH_ENDIANNESS _OSH_ENDIANNESS_LITTLE
        #elif (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
            #define _OSH_ENDIANNESS _OSH_ENDIANNESS_BIG
        #else
            #error "Unknown __BYTE_ORDER__ value"
        #endif
    #else
        #if defined(_OSH_ENDIANNESS_DEBUG)
            #warning "Endianness: Unknown (detect using __LITTLE_ENDIAN__, __BIG_ENDIAN__)"
        #endif

        #if (__LITTLE_ENDIAN__)
            #define _OSH_ENDIANNESS _OSH_ENDIANNESS_LITTLE
        #elif (__BIG_ENDIAN__)
            #define _OSH_ENDIANNESS _OSH_ENDIANNESS_BIG
        #else
            #error "Failed to detect endianness"
        #endif
    #endif

#endif

// If _OSH_ENDIANNESS is defined and is not disabled, define the byte swapping
// macros using our own bswap functions
#if defined(_OSH_ENDIANNESS) && (_OSH_ENDIANNESS != _OSH_ENDIANNESS_DISABLE)
    #include "bswap.h"

    #if (_OSH_ENDIANNESS == _OSH_ENDIANNESS_LITTLE)
        // Little-endian

        #if defined(_OSH_ENDIANNESS_DEBUG)
            #warning "Endianness: Defining little-endian macros"
        #endif

        #define htole16(x)  (x)
        #define le16toh(x)  (x)
        #define htobe16(x)  osh_bswap16(x)
        #define be16toh(x)  osh_bswap16(x)

        #define htole32(x)  (x)
        #define le32toh(x)  (x)
        #define htobe32(x)  osh_bswap32(x)
        #define be32toh(x)  osh_bswap32(x)

        #define htole64(x)  (x)
        #define le64toh(x)  (x)
        #define htobe64(x)  osh_bswap64(x)
        #define be64toh(x)  osh_bswap64(x)

    #elif (_OSH_ENDIANNESS == _OSH_ENDIANNESS_BIG)
        // Big-endian

        #if defined(_OSH_ENDIANNESS_DEBUG)
            #warning "Endianness: Defining big-endian macros"
        #endif

        #define htole16(x)  osh_bswap16(x)
        #define le16toh(x)  osh_bswap16(x)
        #define htobe16(x)  (x)
        #define be16toh(x)  (x)

        #define htole32(x)  osh_bswap32(x)
        #define le32toh(x)  osh_bswap32(x)
        #define htobe32(x)  (x)
        #define be32toh(x)  (x)

        #define htole64(x)  osh_bswap64(x)
        #define le64toh(x)  osh_bswap64(x)
        #define htobe64(x)  (x)
        #define be64toh(x)  (x)
    #else
        #error "Unknown _OSH_ENDIANNESS value"
    #endif
#else
    #if defined(_OSH_ENDIANNESS_DEBUG)
        #warning "Endianness: Not defining macros"
    #endif
#endif

#endif
