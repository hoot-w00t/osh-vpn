#ifndef OSH_NOISE_CIPHERSTATE_H_
#define OSH_NOISE_CIPHERSTATE_H_

#include "noise/constants.h"
#include "crypto/cipher.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum noise_cipherstate_flags {
    NOISE_CIPHERSTATE_NO_FLAGS          = 0,

    NOISE_CIPHERSTATE_FAIL_WITHOUT_KEY  = (1 << 0),
    NOISE_CIPHERSTATE_CAN_ENCRYPT       = (1 << 1),
    NOISE_CIPHERSTATE_CAN_DECRYPT       = (1 << 2)
};

typedef struct noise_cipherstate noise_cipherstate_t;

__attribute__((warn_unused_result))
noise_cipherstate_t *noise_cipherstate_create(cipher_type_t cipher_type, enum noise_cipherstate_flags flags);
void noise_cipherstate_destroy(noise_cipherstate_t *ctx);

enum noise_cipherstate_flags noise_cipherstate_get_flags(const noise_cipherstate_t *ctx);
cipher_type_t noise_cipherstate_get_cipher_type(const noise_cipherstate_t *ctx);
size_t noise_cipherstate_get_key_length(const noise_cipherstate_t *ctx);
size_t noise_cipherstate_get_iv_length(const noise_cipherstate_t *ctx);
size_t noise_cipherstate_get_mac_length(const noise_cipherstate_t *ctx);

__attribute__((warn_unused_result))
bool noise_cipherstate_initialize_key(noise_cipherstate_t *ctx, const void *k, size_t len);
bool noise_cipherstate_has_key(const noise_cipherstate_t *ctx);
void noise_cipherstate_set_nonce(noise_cipherstate_t *ctx, uint64_t n);

__attribute__((warn_unused_result))
bool noise_cipherstate_encrypt_with_ad(noise_cipherstate_t *ctx,
    const void *ad, size_t ad_len,
    const void *plaintext, size_t plaintext_len,
    void *output, size_t *output_len,
    void *mac, size_t mac_len);
__attribute__((warn_unused_result))
bool noise_cipherstate_encrypt_with_ad_postinc(noise_cipherstate_t *ctx,
    const void *ad, size_t ad_len,
    const void *plaintext, size_t plaintext_len,
    void *output, size_t *output_len,
    void *mac, size_t mac_len);

__attribute__((warn_unused_result))
bool noise_cipherstate_decrypt_with_ad(noise_cipherstate_t *ctx,
    const void *ad, size_t ad_len,
    const void *ciphertext, size_t ciphertext_len,
    void *output, size_t *output_len,
    void *mac, size_t mac_len);
__attribute__((warn_unused_result))
bool noise_cipherstate_decrypt_with_ad_postinc(noise_cipherstate_t *ctx,
    const void *ad, size_t ad_len,
    const void *ciphertext, size_t ciphertext_len,
    void *output, size_t *output_len,
    void *mac, size_t mac_len);

#endif
