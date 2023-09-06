#ifndef _OSH_CRYPTO_HASH_H
#define _OSH_CRYPTO_HASH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum hash_type {
    HASH_SHA2_256 = 0,
    HASH_SHA2_512,
    HASH_SHA3_512,
    HASH_BLAKE2S,
    HASH_BLAKE2B,

    _HASH_TYPE_LAST
} hash_type_t;
#define HASH_TYPE_COUNT _HASH_TYPE_LAST

#define HASH_SHA2_256_LEN       32
#define HASH_SHA2_512_LEN       64
#define HASH_SHA3_512_LEN       64
#define HASH_BLAKE2S_LEN        32
#define HASH_BLAKE2B_LEN        64

// TODO: Remove *_SIZE macros
#define HASH_SHA2_256_SIZE      HASH_SHA2_256_LEN
#define HASH_SHA2_512_SIZE      HASH_SHA2_512_LEN
#define HASH_SHA3_512_SIZE      HASH_SHA3_512_LEN
#define HASH_BLAKE2B_SIZE       HASH_BLAKE2B_LEN

typedef struct hash_ctx hash_ctx_t;

const char *hash_type_name(hash_type_t type);
size_t hash_type_length(hash_type_t type);

hash_ctx_t *hash_ctx_create(hash_type_t type);
bool hash_ctx_reset(hash_ctx_t *ctx);
bool hash_ctx_update(hash_ctx_t *ctx, const void *in, size_t in_size);
bool hash_ctx_final(hash_ctx_t *ctx, void *out, size_t out_size);
void hash_ctx_free(hash_ctx_t *ctx);

bool hash_oneshot(hash_type_t type, void *out, size_t out_size,
    const void *in, size_t in_size);

bool hash_hkdf(hash_type_t hash_type,
    const void *key, size_t key_size,
    const void *salt, size_t salt_size,
    const void *label, size_t label_size,
    void *out, size_t out_size);

#endif
