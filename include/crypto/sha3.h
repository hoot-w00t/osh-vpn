#ifndef _OSH_CRYPTO_SHA3_H
#define _OSH_CRYPTO_SHA3_H

#include <stdbool.h>
#include <stdint.h>

bool sha3_512_hash(const uint8_t *in, unsigned int in_size, uint8_t *hash,
    unsigned int *hash_size);
void hash_hexdump(const uint8_t *hash, unsigned int hash_size,
    char *hexdump, bool upper_case);

#endif