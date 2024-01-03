#include "noise/symmetricstate.h"
#include "crypto/hash.h"
#include "macros_assert.h"
#include "xalloc.h"
#include "memzero.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct noise_symmetricstate {
    cipher_type_t cipher_type;
    noise_cipherstate_t *cipher;

    size_t keylen;

    hash_type_t hash_type;
    size_t hash_len;
    hash_ctx_t *hash_ctx;

    uint8_t chaining_key[NOISE_HASH_MAXLEN];
    uint8_t hash[NOISE_HASH_MAXLEN];

    uint8_t hkdf_output_buf[NOISE_HASH_MAXLEN * 3];
    void *hkdf_output1;
    void *hkdf_output2;
    void *hkdf_output3;
};

// Reset HKDF result buffer
static void reset_hkdf_output(noise_symmetricstate_t *ctx)
{
    memzero(ctx->hkdf_output_buf, sizeof(ctx->hkdf_output_buf));
}

__attribute__((warn_unused_result))
static bool noise_hkdf(noise_symmetricstate_t *ctx,
    const void *ikm, size_t ikm_len, size_t num_outputs)
{
    const char label = 0;
    size_t hkdf_output_len;

    if (num_outputs != 2 && num_outputs != 3)
        return false;

    hkdf_output_len = ctx->hash_len * num_outputs;
    if (hkdf_output_len > sizeof(ctx->hkdf_output_buf))
        return false;

    reset_hkdf_output(ctx);
    return hash_hkdf(ctx->hash_type,
        ikm, ikm_len,
        ctx->chaining_key, ctx->hash_len,
        &label, 0,
        ctx->hkdf_output_buf, hkdf_output_len);
}

noise_symmetricstate_t *noise_symmetricstate_create(const char *protocol_name,
    cipher_type_t cipher_type, hash_type_t hash_type)
{
    noise_symmetricstate_t *ctx = xzalloc(sizeof(*ctx));
    const size_t name_len = strlen(protocol_name);

    ctx->cipher_type = cipher_type;
    ctx->cipher = noise_cipherstate_create(ctx->cipher_type,
        NOISE_CIPHERSTATE_CAN_ENCRYPT | NOISE_CIPHERSTATE_CAN_DECRYPT);
    if (ctx->cipher == NULL)
        goto fail;

    ctx->keylen = cipher_get_key_size_from_type(ctx->cipher_type);
    ctx->hash_type = hash_type;
    ctx->hash_len = hash_type_length(ctx->hash_type);
    ctx->hash_ctx = hash_ctx_create(ctx->hash_type);
    if (ctx->hash_ctx == NULL)
        goto fail;

    assert(ctx->keylen > 0);
    assert(ctx->keylen <= NOISE_CIPHER_KEY_MAXLEN);
    assert(ctx->hash_len > 0);
    assert(ctx->hash_len <= NOISE_HASH_MAXLEN);
    assert(ctx->hash_len >= ctx->keylen); // we get keys from hashes (truncated if KEYLEN is smaller than HASHLEN)
                                          // so HASHLEN must not be smaller than KEYLEN

    assert(sizeof(ctx->hkdf_output_buf) >= (ctx->hash_len * 3));
    ctx->hkdf_output1 = ctx->hkdf_output_buf + (ctx->hash_len * 0);
    ctx->hkdf_output2 = ctx->hkdf_output_buf + (ctx->hash_len * 1);
    ctx->hkdf_output3 = ctx->hkdf_output_buf + (ctx->hash_len * 2);

    if (name_len <= ctx->hash_len) {
        memcpy(ctx->hash, protocol_name, name_len);
    } else {
        if (!(   hash_ctx_reset(ctx->hash_ctx)
              && hash_ctx_update(ctx->hash_ctx, protocol_name, name_len)
              && hash_ctx_final(ctx->hash_ctx, ctx->hash, ctx->hash_len)))
        {
            goto fail;
        }
    }
    memcpy(ctx->chaining_key, ctx->hash, ctx->hash_len);

    // We expect this to return false since we reset the key
    if (noise_cipherstate_initialize_key(ctx->cipher, NULL, 0))
        goto fail;

    return ctx;

fail:
    noise_symmetricstate_destroy(ctx);
    return NULL;
}

void noise_symmetricstate_destroy(noise_symmetricstate_t *ctx)
{
    if (ctx) {
        memzero(ctx->chaining_key, NOISE_HASH_MAXLEN);
        memzero(ctx->hash, NOISE_HASH_MAXLEN);
        reset_hkdf_output(ctx);

        hash_ctx_free(ctx->hash_ctx);
        noise_cipherstate_destroy(ctx->cipher);
        free(ctx);
    }
}

bool noise_symmetricstate_has_key(noise_symmetricstate_t *ctx)
{
    return noise_cipherstate_has_key(ctx->cipher);
}

bool noise_symmetricstate_mix_key(noise_symmetricstate_t *ctx, const void *ikm, size_t ikm_len)
{
    bool success;

    if (!noise_hkdf(ctx, ikm, ikm_len, 2))
        return false;

    memcpy(ctx->chaining_key, ctx->hkdf_output1, ctx->hash_len);
    success = noise_cipherstate_initialize_key(ctx->cipher, ctx->hkdf_output2, ctx->keylen);

    reset_hkdf_output(ctx);
    return success;
}

bool noise_symmetricstate_mix_hash(noise_symmetricstate_t *ctx, const void *data, size_t data_len)
{
    return hash_ctx_reset(ctx->hash_ctx)
        && hash_ctx_update(ctx->hash_ctx, ctx->hash, ctx->hash_len)
        && hash_ctx_update(ctx->hash_ctx, data, data_len)
        && hash_ctx_final(ctx->hash_ctx, ctx->hash, ctx->hash_len);
}

// same as mix_hash but hashes data1 then data2 (avoids byte array concats)
bool noise_symmetricstate_mix_hash_2(noise_symmetricstate_t *ctx,
    const void *data1, size_t data1_len,
    const void *data2, size_t data2_len)
{
    return hash_ctx_reset(ctx->hash_ctx)
        && hash_ctx_update(ctx->hash_ctx, ctx->hash, ctx->hash_len)
        && hash_ctx_update(ctx->hash_ctx, data1, data1_len)
        && hash_ctx_update(ctx->hash_ctx, data2, data2_len)
        && hash_ctx_final(ctx->hash_ctx, ctx->hash, ctx->hash_len);
}

bool noise_symmetricstate_mix_key_and_hash(noise_symmetricstate_t *ctx, const void *ikm, size_t ikm_len)
{
    bool success;

    if (!noise_hkdf(ctx, ikm, ikm_len, 3))
        return false;

    memcpy(ctx->chaining_key, ctx->hkdf_output1, ctx->hash_len);
    success = noise_symmetricstate_mix_hash(ctx, ctx->hkdf_output2, ctx->hash_len)
           && noise_cipherstate_initialize_key(ctx->cipher, ctx->hkdf_output3, ctx->keylen);

    reset_hkdf_output(ctx);
    return success;
}

const uint8_t *noise_symmetricstate_get_handshake_hash(const noise_symmetricstate_t *ctx)
{
    return ctx->hash;
}

bool noise_symmetricstate_encrypt_and_hash(noise_symmetricstate_t *ctx,
    const void *plaintext, size_t plaintext_len,
    void *output, size_t *output_len,
    void *mac, size_t mac_len)
{
    if (noise_cipherstate_has_key(ctx->cipher)) {
        if (!noise_cipherstate_encrypt_with_ad_postinc(ctx->cipher,
                ctx->hash, ctx->hash_len,
                plaintext, plaintext_len,
                output, output_len,
                mac, mac_len))
        {
            return false;
        }

        return noise_symmetricstate_mix_hash_2(ctx, output, *output_len, mac, mac_len);
    } else {
        memcpy(output, plaintext, plaintext_len);
        *output_len = plaintext_len;
        memzero(mac, mac_len);

        return noise_symmetricstate_mix_hash(ctx, output, *output_len);
    }
}

bool noise_symmetricstate_decrypt_and_hash(noise_symmetricstate_t *ctx,
    const void *ciphertext, size_t ciphertext_len,
    void *output, size_t *output_len,
    void *mac, size_t mac_len)
// FIXME: Make *mac const once noise_cipherstate_decrypt_with_ad_postinc() *mac becomes const
{
    if (noise_cipherstate_has_key(ctx->cipher)) {
        if (!noise_cipherstate_decrypt_with_ad_postinc(ctx->cipher,
                ctx->hash, ctx->hash_len,
                ciphertext, ciphertext_len,
                output, output_len,
                mac, mac_len))
        {
            return false;
        }

        return noise_symmetricstate_mix_hash_2(ctx, ciphertext, ciphertext_len, mac, mac_len);
    } else {
        memcpy(output, ciphertext, ciphertext_len);
        *output_len = ciphertext_len;

        return noise_symmetricstate_mix_hash(ctx, ciphertext, ciphertext_len);
    }
}

bool noise_symmetricstate_split(noise_symmetricstate_t *ctx, bool initiator,
    noise_cipherstate_t **send_cipher, noise_cipherstate_t **recv_cipher)
{
    const uint8_t empty = 0;
    noise_cipherstate_t *c1 = NULL; // for *send_cipher
    noise_cipherstate_t *c2 = NULL; // for *recv_cipher
    bool success = false;

    assert(send_cipher != NULL);
    assert(recv_cipher != NULL);
    assert(send_cipher != recv_cipher);

    if (!noise_hkdf(ctx, &empty, 0, 2))
        goto end;

    c1 = noise_cipherstate_create(ctx->cipher_type, NOISE_CIPHERSTATE_CAN_ENCRYPT);
    if (c1 == NULL)
        goto end;

    c2 = noise_cipherstate_create(ctx->cipher_type, NOISE_CIPHERSTATE_CAN_DECRYPT);
    if (c2 == NULL)
        goto end;

    // output 1 is the encryption key for the initiator
    // output 2 is the encryption key for the responder
    if (initiator) {
        if (!noise_cipherstate_initialize_key(c1, ctx->hkdf_output1, ctx->keylen))
            goto end;
        if (!noise_cipherstate_initialize_key(c2, ctx->hkdf_output2, ctx->keylen))
            goto end;
    } else {
        if (!noise_cipherstate_initialize_key(c1, ctx->hkdf_output2, ctx->keylen))
            goto end;
        if (!noise_cipherstate_initialize_key(c2, ctx->hkdf_output1, ctx->keylen))
            goto end;
    }

    *send_cipher = c1;
    *recv_cipher = c2;
    success = true;

end:
    reset_hkdf_output(ctx);
    if (!success) {
        noise_cipherstate_destroy(c1);
        noise_cipherstate_destroy(c2);
    }
    return success;
}
