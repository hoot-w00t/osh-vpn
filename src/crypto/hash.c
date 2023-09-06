#include "logger.h"
#include "xalloc.h"
#include "crypto/hash.h"
#include "crypto/common.h"
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

struct hash_type_def {
    const hash_type_t type;
    const char *name;
    const size_t hash_length;

    const char *openssl_name;
};

static const struct hash_type_def hash_type_table[HASH_TYPE_COUNT] = {
    {
        .type = HASH_SHA2_256,
        .name = "sha2-256",
        .hash_length = HASH_SHA2_256_LEN,

        .openssl_name = "sha256"
    },
    {
        .type = HASH_SHA2_512,
        .name = "sha2-512",
        .hash_length = HASH_SHA2_512_LEN,

        .openssl_name = "sha512"
    },
    {
        .type = HASH_SHA3_512,
        .name = "sha3-512",
        .hash_length = HASH_SHA3_512_LEN,

        .openssl_name = "sha3-512"
    },
    {
        .type = HASH_BLAKE2S,
        .name = "blake2s",
        .hash_length = HASH_BLAKE2S_LEN,

        .openssl_name = "blake2s256"
    },
    {
        .type = HASH_BLAKE2B,
        .name = "blake2b",
        .hash_length = HASH_BLAKE2B_LEN,

        .openssl_name = "blake2b512"
    }
};

static const struct hash_type_def *hash_type_lookup(hash_type_t type)
{
    if ((unsigned) type <= HASH_TYPE_COUNT)
        return &hash_type_table[type];
    return NULL;
}

const char *hash_type_name(hash_type_t type)
{
    const struct hash_type_def *def = hash_type_lookup(type);

    return def ? def->name : NULL;
}

size_t hash_type_length(hash_type_t type)
{
    const struct hash_type_def *def = hash_type_lookup(type);

    return def ? def->hash_length : 0;
}

#define HASH_CTX_MAX_HASH_SIZE EVP_MAX_MD_SIZE
struct hash_ctx {
    hash_type_t type;

    uint8_t hash[HASH_CTX_MAX_HASH_SIZE];
    unsigned int hash_size;

    EVP_MD_CTX *evp_ctx;
};

// Create message digest context
hash_ctx_t *hash_ctx_create(hash_type_t type)
{
    const struct hash_type_def *def = hash_type_lookup(type);
    EVP_MD_CTX *evp_ctx = NULL;
    const EVP_MD *evp_md = NULL;
    hash_ctx_t *ctx;

    if (!def) {
        logger(LOG_ERR, "%s: Invalid hash type %u", __func__, (unsigned) type);
        goto err;
    }

    evp_md = EVP_get_digestbyname(def->openssl_name);
    if (!evp_md) {
        osh_openssl_log_error("EVP_get_digestbyname");
        goto err;
    }

    evp_ctx = EVP_MD_CTX_new();
    if (!evp_ctx) {
        osh_openssl_log_error("EVP_MD_CTX_new");
        goto err;
    }

    if (!EVP_DigestInit_ex(evp_ctx, evp_md, NULL)) {
        osh_openssl_log_error("EVP_DigestInit_ex");
        goto err;
    }

    ctx = xzalloc(sizeof(*ctx));
    ctx->type = type;
    ctx->evp_ctx = evp_ctx;
    return ctx;

err:
    EVP_MD_CTX_free(evp_ctx);
    return NULL;
}

// Update message digest with in_size bytes from in
bool hash_ctx_update(hash_ctx_t *ctx, const void *in, size_t in_size)
{
    if (!EVP_DigestUpdate(ctx->evp_ctx, in, in_size)) {
        osh_openssl_log_error("EVP_DigestUpdate");
        return false;
    }
    return true;
}

// Finalize message digest and write output to *out
// out_size is the size of the buffer pointed by *out and must exactly match
// the digest size
bool hash_ctx_final(hash_ctx_t *ctx, void *out, size_t out_size)
{
    if (!EVP_DigestFinal_ex(ctx->evp_ctx, ctx->hash, &ctx->hash_size)) {
        osh_openssl_log_error("EVP_DigestFinal_ex");
        return false;
    }

    if (ctx->hash_size != out_size) {
        logger(LOG_ERR, "%s: Expected out_size of %u bytes but got %zu",
            __func__, ctx->hash_size, out_size);
        return false;
    }

    memcpy(out, ctx->hash, ctx->hash_size);
    memzero(ctx->hash, sizeof(ctx->hash));
    return true;
}

// Free message digest context
void hash_ctx_free(hash_ctx_t *ctx)
{
    if (ctx) {
        memzero(ctx->hash, sizeof(ctx->hash));
        EVP_MD_CTX_free(ctx->evp_ctx);
        free(ctx);
    }
}

// Hash in_size bytes from in and write hash to out in a single function call
bool hash_oneshot(hash_type_t type, void *out, size_t out_size,
    const void *in, size_t in_size)
{
    hash_ctx_t *ctx = hash_ctx_create(type);
    bool success = false;

    if (!ctx)
        goto end;
    if (!hash_ctx_update(ctx, in, in_size))
        goto end;
    success = hash_ctx_final(ctx, out, out_size);

end:
    hash_ctx_free(ctx);
    return success;
}

// Derive out_size bytes to *out using HKDF
// Returns false on error
bool hash_hkdf(hash_type_t hash_type,
    const void *key, size_t key_size,
    const void *salt, size_t salt_size,
    const void *label, size_t label_size,
    void *out, size_t out_size)
{
    const struct hash_type_def *def = hash_type_lookup(hash_type);
    EVP_PKEY_CTX *pctx = NULL;
    const EVP_MD *evp_md = NULL;
    bool success = false;

    if (!def) {
        logger(LOG_ERR, "%s: Invalid hash type %u", __func__, (unsigned) hash_type);
        goto end;
    }

    evp_md = EVP_get_digestbyname(def->openssl_name);
    if (!evp_md) {
        osh_openssl_log_error("EVP_get_digestbyname");
        goto end;
    }

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) {
        osh_openssl_log_error("EVP_PKEY_CTX_new_id");
        goto end;
    }

    if (EVP_PKEY_derive_init(pctx) <= 0) {
        osh_openssl_log_error("EVP_PKEY_derive_init");
        goto end;
    }
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, evp_md) <= 0) {
        osh_openssl_log_error("EVP_PKEY_CTX_set_hkdf_md");
        goto end;
    }

    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, salt_size) <= 0) {
        osh_openssl_log_error("EVP_PKEY_CTX_set1_hkdf_salt");
        goto end;
    }
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, key, key_size) <= 0) {
        osh_openssl_log_error("EVP_PKEY_CTX_set1_hkdf_key");
        goto end;
    }
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, label, label_size) <= 0) {
        osh_openssl_log_error("EVP_PKEY_CTX_add1_hkdf_info");
        goto end;
    }

    // Derive out_size bytes to *out
    if (EVP_PKEY_derive(pctx, out, &out_size) <= 0) {
        osh_openssl_log_error("EVP_PKEY_derive");
        goto end;
    }

    success = true;

end:
    if (pctx)
        EVP_PKEY_CTX_free(pctx);
    return success;
}
