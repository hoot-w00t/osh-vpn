#ifndef _OSH_MURMURHASH_H
#define _OSH_MURMURHASH_H

#include <stddef.h>
#include <stdint.h>

uint32_t murmur3_32(const void *key, const uint32_t key_len,
    const uint32_t seed);

#endif