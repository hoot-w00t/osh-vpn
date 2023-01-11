#ifndef _OSH_BSWAP_H
#define _OSH_BSWAP_H

// Byte swapping functions

#include <stdint.h>

static inline uint16_t osh_bswap16(uint16_t x)
{
    return   ((x & 0xFF00u) >> 8)
           | ((x & 0x00FFu) << 8);
}

static inline uint32_t osh_bswap32(uint32_t x)
{
    return   ((x & ((uint32_t) 0x000000FF)) << 24)
           | ((x & ((uint32_t) 0x0000FF00)) <<  8)
           | ((x & ((uint32_t) 0x00FF0000)) >>  8)
           | ((x & ((uint32_t) 0xFF000000)) >> 24);
}

static inline uint64_t osh_bswap64(uint64_t x)
{
    return   ((x & ((uint64_t) 0x00000000000000FF)) << 56)
           | ((x & ((uint64_t) 0x000000000000FF00)) << 40)
           | ((x & ((uint64_t) 0x0000000000FF0000)) << 24)
           | ((x & ((uint64_t) 0x00000000FF000000)) <<  8)
           | ((x & ((uint64_t) 0x000000FF00000000)) >>  8)
           | ((x & ((uint64_t) 0x0000FF0000000000)) >> 24)
           | ((x & ((uint64_t) 0x00FF000000000000)) >> 40)
           | ((x & ((uint64_t) 0xFF00000000000000)) >> 56);
}

#endif
