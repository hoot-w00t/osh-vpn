#include "noise/cipherstate.h"
#include "endianness.h"
#include "macros_assert.h"
#include "xalloc.h"
#include "memzero.h"
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

struct __attribute__((packed)) noise_cipher_iv {
    uint32_t zero;
    uint64_t nonce;
};
typedef void (*cipherstate_make_iv_from_nonce_t)(struct noise_cipher_iv *iv, uint64_t nonce);
STATIC_ASSERT_NOMSG(sizeof(struct noise_cipher_iv) == NOISE_CIPHER_IV_MAXLEN);

struct noise_cipherstate {
    enum noise_cipherstate_flags flags;

    bool has_key;
    uint8_t key[NOISE_CIPHER_KEY_MAXLEN];
    size_t keylen;

    size_t ivlen;
    size_t maclen;

    uint64_t nonce;

    cipher_type_t cipher_type;
    cipher_t *cipher;
    cipherstate_make_iv_from_nonce_t make_iv_from_nonce;
    bool encrypts;
};

// Little-endian encoding of nonce (ChaChaPoly)
static void make_iv_from_nonce_little(struct noise_cipher_iv *iv, uint64_t nonce)
{
    iv->zero = 0;
    iv->nonce = htole64(nonce);
}

// Big-endian encoding of nonce (AESGCM)
static void make_iv_from_nonce_big(struct noise_cipher_iv *iv, uint64_t nonce)
{
    iv->zero = 0;
    iv->nonce = htobe64(nonce);
}

// Increment nonce (if its current value is valid)
static void inc_nonce(noise_cipherstate_t *ctx)
{
    if (noise_nonce_is_valid(ctx->nonce))
        ctx->nonce += 1;
}

// Free ctx->cipher and reset cipher related variables
static void delete_cipher(noise_cipherstate_t *ctx)
{
    cipher_free(ctx->cipher);
    ctx->cipher = NULL;
    ctx->encrypts = false;
}

// Update ctx->cipher
// Returns true if the cipher was created and can be used
// Returns false if there is no cipher
__attribute__((warn_unused_result))
static bool update_cipher(noise_cipherstate_t *ctx, bool encrypts)
{
    // If we already have a cipher for encryption/decryption don't re-create it
    if (ctx->cipher && ctx->encrypts == encrypts)
        return true;

    // If there is no key we can't create a cipher
    if (!noise_cipherstate_has_key(ctx)) {
        delete_cipher(ctx);
        return false;
    }

    // Create a new cipher
    cipher_free(ctx->cipher);
    ctx->cipher = cipher_create(ctx->cipher_type, encrypts, ctx->key, ctx->keylen, NULL, 0);
    ctx->encrypts = encrypts;

    if (ctx->cipher == NULL) {
        delete_cipher(ctx);
        return false;
    }
    return true;
}

noise_cipherstate_t *noise_cipherstate_create(cipher_type_t cipher_type, enum noise_cipherstate_flags flags)
{
    noise_cipherstate_t *ctx = xzalloc(sizeof(*ctx));

    ctx->flags = flags;

    ctx->cipher_type = cipher_type;
    ctx->keylen = cipher_get_key_size_from_type(ctx->cipher_type);
    assert(ctx->keylen > 0);
    assert(ctx->keylen <= NOISE_CIPHER_KEY_MAXLEN);
    ctx->has_key = false;

    ctx->ivlen = cipher_get_iv_size_from_type(ctx->cipher_type);
    assert(ctx->ivlen == sizeof(struct noise_cipher_iv));
    ctx->maclen = cipher_get_mac_size_from_type(ctx->cipher_type);
    assert(ctx->maclen > 0);
    assert(ctx->maclen <= NOISE_CIPHER_MAC_MAXLEN);

    // Nonce is encoded in big-endian with AESGCM and little-endian with ChaChaPoly
    // Default to little-endian if cipher type is unknown
    ctx->make_iv_from_nonce = (ctx->cipher_type == CIPHER_TYPE_AES_256_GCM)
                            ? make_iv_from_nonce_big
                            : make_iv_from_nonce_little;

    return ctx;

/* Commented out because unused currently
fail:
    noise_cipherstate_destroy(ctx);
    return NULL;
*/
}

void noise_cipherstate_destroy(noise_cipherstate_t *ctx)
{
    if (ctx) {
        memzero(ctx->key, NOISE_CIPHER_KEY_MAXLEN);
        cipher_free(ctx->cipher);
        free(ctx);
    }
}

cipher_type_t noise_cipherstate_get_cipher_type(const noise_cipherstate_t *ctx)
{
    return ctx->cipher_type;
}

size_t noise_cipherstate_get_key_length(const noise_cipherstate_t *ctx)
{
    return ctx->keylen;
}

size_t noise_cipherstate_get_iv_length(const noise_cipherstate_t *ctx)
{
    return ctx->ivlen;
}

size_t noise_cipherstate_get_mac_length(const noise_cipherstate_t *ctx)
{
    return ctx->maclen;
}

// Returns true if a key was set, false otherwise
bool noise_cipherstate_initialize_key(noise_cipherstate_t *ctx, const void *k, size_t len)
{
    // The current key bytes are always reset
    memzero(ctx->key, NOISE_CIPHER_KEY_MAXLEN);

    if (k == NULL || len != ctx->keylen) {
        ctx->has_key = false;
    } else {
        memcpy(ctx->key, k, ctx->keylen);
        ctx->has_key = true;
    }

    ctx->nonce = 0;
    delete_cipher(ctx);
    return ctx->has_key;
}

bool noise_cipherstate_has_key(const noise_cipherstate_t *ctx)
{
    return ctx->has_key;
}

void noise_cipherstate_set_nonce(noise_cipherstate_t *ctx, uint64_t n)
{
    // External nonces must be handled securely to prevent reuse
    ctx->nonce = n;
}

bool noise_cipherstate_encrypt_with_ad(noise_cipherstate_t *ctx,
    const void *ad, size_t ad_len,
    const void *plaintext, size_t plaintext_len,
    void *output, size_t *output_len,
    void *mac, size_t mac_len)
{
    struct noise_cipher_iv iv;

    if (plaintext_len > NOISE_MESSAGE_MAXLEN)
        return false;

    if (!noise_cipherstate_has_key(ctx)) {
        if (ctx->flags & NOISE_CIPHERSTATE_FAIL_WITHOUT_KEY)
            return false;

        memcpy(output, plaintext, plaintext_len);
        *output_len = plaintext_len;
        memzero(mac, mac_len);
        return true;
    }

    if (!noise_nonce_is_valid(ctx->nonce))
        return false;

    if (!update_cipher(ctx, true))
        return false;

    ctx->make_iv_from_nonce(&iv, ctx->nonce);
    return cipher_set_iv(ctx->cipher, &iv, sizeof(iv))
        && cipher_encrypt(ctx->cipher, output, output_len, plaintext, plaintext_len, ad, ad_len, mac, mac_len);
}

bool noise_cipherstate_encrypt_with_ad_postinc(noise_cipherstate_t *ctx,
    const void *ad, size_t ad_len,
    const void *plaintext, size_t plaintext_len,
    void *output, size_t *output_len,
    void *mac, size_t mac_len)
{
    bool success = noise_cipherstate_encrypt_with_ad(ctx,
        ad, ad_len, plaintext, plaintext_len, output, output_len, mac, mac_len);

    inc_nonce(ctx);
    return success;
}

bool noise_cipherstate_decrypt_with_ad(noise_cipherstate_t *ctx,
    const void *ad, size_t ad_len,
    const void *ciphertext, size_t ciphertext_len,
    void *output, size_t *output_len,
    void *mac, size_t mac_len)
// FIXME: Make *mac const once cipher_decrypt() *mac becomes const
{
    struct noise_cipher_iv iv;

    if (ciphertext_len > NOISE_MESSAGE_MAXLEN)
        return false;

    if (!noise_cipherstate_has_key(ctx)) {
        if (ctx->flags & NOISE_CIPHERSTATE_FAIL_WITHOUT_KEY)
            return false;

        memcpy(output, ciphertext, ciphertext_len);
        *output_len = ciphertext_len;
        return true;
    }

    if (!noise_nonce_is_valid(ctx->nonce))
        return false;

    if (!update_cipher(ctx, false))
        return false;

    ctx->make_iv_from_nonce(&iv, ctx->nonce);
    return cipher_set_iv(ctx->cipher, &iv, sizeof(iv))
        && cipher_decrypt(ctx->cipher, output, output_len, ciphertext, ciphertext_len, ad, ad_len, mac, mac_len);
}

bool noise_cipherstate_decrypt_with_ad_postinc(noise_cipherstate_t *ctx,
    const void *ad, size_t ad_len,
    const void *ciphertext, size_t ciphertext_len,
    void *output, size_t *output_len,
    void *mac, size_t mac_len)
// FIXME: Make *mac const once cipher_decrypt() *mac becomes const
{
    bool success = noise_cipherstate_decrypt_with_ad(ctx,
        ad, ad_len, ciphertext, ciphertext_len, output, output_len, mac, mac_len);

    inc_nonce(ctx);
    return success;
}
