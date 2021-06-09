#ifndef _OSH_RANDOM_H
#define _OSH_RANDOM_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

bool read_random_bytes(uint8_t *buf, size_t buf_size);

#endif