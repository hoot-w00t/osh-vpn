#ifndef OSH_NOISE_SYMMETRICSTATE_H_
#define OSH_NOISE_SYMMETRICSTATE_H_

#include "noise/cipherstate.h"
#include "crypto/hash.h"

typedef struct noise_symmetricstate noise_symmetricstate_t;

__attribute__((warn_unused_result))
noise_symmetricstate_t *noise_symmetricstate_create(const char *protocol_name,
    cipher_type_t cipher_type, hash_type_t hash_type);
void noise_symmetricstate_destroy(noise_symmetricstate_t *ctx);

bool noise_symmetricstate_has_key(noise_symmetricstate_t *ctx);

__attribute__((warn_unused_result))
bool noise_symmetricstate_mix_key(noise_symmetricstate_t *ctx, const void *ikm, size_t ikm_len);
__attribute__((warn_unused_result))
bool noise_symmetricstate_mix_hash(noise_symmetricstate_t *ctx, const void *data, size_t data_len);
__attribute__((warn_unused_result))
bool noise_symmetricstate_mix_hash_2(noise_symmetricstate_t *ctx,
    const void *data1, size_t data1_len,
    const void *data2, size_t data2_len);
__attribute__((warn_unused_result))
bool noise_symmetricstate_mix_key_and_hash(noise_symmetricstate_t *ctx, const void *ikm, size_t ikm_len);

__attribute__((warn_unused_result))
const uint8_t *noise_symmetricstate_get_handshake_hash(const noise_symmetricstate_t *ctx);

__attribute__((warn_unused_result))
bool noise_symmetricstate_encrypt_and_hash(noise_symmetricstate_t *ctx,
    const void *plaintext, size_t plaintext_len,
    void *output, size_t *output_len,
    void *mac, size_t mac_len);
__attribute__((warn_unused_result))
bool noise_symmetricstate_decrypt_and_hash(noise_symmetricstate_t *ctx,
    const void *ciphertext, size_t ciphertext_len,
    void *output, size_t *output_len,
    void *mac, size_t mac_len);

__attribute__((warn_unused_result))
bool noise_symmetricstate_split(noise_symmetricstate_t *ctx,
    noise_cipherstate_t **c1, noise_cipherstate_t **c2);

#endif
