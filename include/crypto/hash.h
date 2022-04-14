#ifndef _OSH_CRYPTO_HASH_H
#define _OSH_CRYPTO_HASH_H

#include <stdbool.h>
#include <stdint.h>

bool hash_sha3_512(const void *in, unsigned int in_size, uint8_t *hash,
    unsigned int *hash_size);
void hash_hexdump(const uint8_t *hash, unsigned int hash_size,
    char *hexdump, bool upper_case);

#endif