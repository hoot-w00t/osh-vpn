#ifndef _OSH_RANDOM_H
#define _OSH_RANDOM_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// Write buf_size random bytes starting at buf
// This function can block
// Returns false on any error (including incomplete reads)
bool random_bytes(void *buf, size_t buf_size);

bool random_xoshiro256_seed(void);
uint64_t random_xoshiro256(void);

#endif
