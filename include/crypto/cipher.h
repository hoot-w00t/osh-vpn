#ifndef _OSH_CRYPTO_CIPHER_H
#define _OSH_CRYPTO_CIPHER_H

#include <stdbool.h>
#include <stdint.h>
#include <openssl/evp.h>

typedef struct cipher {
    // Cipher context for encryption/decryption
    EVP_CIPHER_CTX *ctx;

    // true if the cipher context is initialized for encryption, false for
    // decryption
    bool encrypts;
} cipher_t;

cipher_t *cipher_create_aes_256_ctr(bool encrypts, const uint8_t *key,
    size_t key_size, const uint8_t *iv, size_t iv_size);
void cipher_free(cipher_t *cipher);

bool cipher_encrypt(cipher_t *cipher, uint8_t *out, size_t *out_size,
    const uint8_t *in, size_t in_size);
bool cipher_decrypt(cipher_t *cipher, uint8_t *out, size_t *out_size,
    const uint8_t *in, size_t in_size);

#endif