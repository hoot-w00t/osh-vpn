#ifndef _OSH_BASE64_H
#define _OSH_BASE64_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

// Align x on y
#define _base64_blkalign(x, y) ((x) + (((x) % (y)) ? ((y) - ((x) % (y))) : 0))

// Calculate the size of base64_encode's output (padded + NUL byte)
#define BASE64_ENCODE_OUTSIZE(size) ((((size) / 3) * 4) + 4 + 1)

// Calculate the exact size of base64_encode's output (padded + NUL byte)
#define BASE64_ENCODE_EXACTSIZE(size) (((_base64_blkalign(size, 3) / 3) * 4) + 1)

// Calculate the size of base64_decode's output (can exceed by two bytes)
#define BASE64_DECODE_OUTSIZE(size) ((_base64_blkalign(size, 4) / 4) * 3)

void base64_encode(char *output, const void *input, size_t input_size);
bool base64_decode(void *output, size_t *output_size, const char *input,
    size_t input_size);

#endif