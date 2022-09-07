#ifndef _OSH_CRYPTO_HKDF_H
#define _OSH_CRYPTO_HKDF_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool hkdf_derive(
    const void *key, size_t key_size,
    const void *salt, size_t salt_size,
    const void *label, size_t label_size,
    void *out, size_t out_size);

#endif
