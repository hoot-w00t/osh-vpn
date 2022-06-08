#ifndef _OSH_RANDOM_H
#define _OSH_RANDOM_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

bool random_bytes(void *buf, size_t buf_size);

bool random_xoshiro256_seed(void);
uint64_t random_xoshiro256(void);

#endif