#include "murmurhash.h"
#include <string.h>

// References
// https://github.com/aappleby/smhasher
// https://en.wikipedia.org/wiki/MurmurHash

#define ROTL32(value, b) (((value) << (b)) | ((value) >> (32 - (b))))

static inline uint32_t murmur3_32_mix(uint32_t k)
{
    k *= 0xcc9e2d51;
    k = ROTL32(k, 15);
    k *= 0x1b873593;
    return k;
}

static inline uint32_t murmur3_32_final_mix(uint32_t hash)
{
    hash ^= (hash >> 16);
    hash *= 0x85ebca6b;
    hash ^= (hash >> 13);
    hash *= 0xc2b2ae35;
    hash ^= (hash >> 16);
    return hash;
}

uint32_t murmur3_32(const void *key, const uint32_t key_len,
    const uint32_t seed)
{
    uint32_t hash = seed;
    uint32_t k;

    // Read blocks of 32 bits
    for (uint32_t i = (key_len / 4); i != 0; --i) {
        memcpy(&k, key, sizeof(k));
        key = ((const uint8_t *) key) + sizeof(k);

        hash ^= murmur3_32_mix(k);
        hash = ROTL32(hash, 13);
        hash = (hash * 5) + 0xe6546b64;
    }

    // Read the remaining bytes (if any)
    if (key_len % 4) {
        k = 0;
        for (uint32_t i = (key_len % 4); i != 0; --i) {
            k <<= 8;
            k |= ((const uint8_t *) key)[i - 1];
        }
        hash ^= murmur3_32_mix(k);
    }

    // Finish the hash
    hash ^= key_len;
    hash = murmur3_32_final_mix(hash);

    return hash;
}
