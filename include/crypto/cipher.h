#ifndef _OSH_CRYPTO_CIPHER_H
#define _OSH_CRYPTO_CIPHER_H

#include <stdbool.h>
#include <stdint.h>
#include <openssl/evp.h>

#define CIPHER_KEY_SIZE (32)
#define CIPHER_IV_SIZE  (12)
#define CIPHER_TAG_SIZE (16)

typedef uint64_t cipher_seqno_t;

typedef union cipher_iv {
    uint8_t b[CIPHER_IV_SIZE];
    struct __attribute__((packed)) {
        uint8_t _pad[CIPHER_IV_SIZE - sizeof(cipher_seqno_t)];
        cipher_seqno_t seqno_be;
    } s;
} cipher_iv_t;

typedef struct cipher {
    // Cipher context for encryption/decryption
    EVP_CIPHER_CTX *ctx;

    // true if the cipher context is initialized for encryption, false for
    // decryption
    bool encrypts;

    // Base IV (nonce)
    cipher_iv_t base_iv;

    // Actual IV that will be used
    cipher_iv_t iv;

    // Sequence number, incremented after every cipher operation
    cipher_seqno_t seqno;
} cipher_t;

cipher_t *cipher_create_aes_256_gcm(bool encrypts,
    const uint8_t *key, size_t key_size,
    const uint8_t *iv, size_t iv_size);

void cipher_free(cipher_t *cipher);

bool cipher_encrypt(cipher_t *cipher, uint8_t *out, size_t *out_size,
    const uint8_t *in, size_t in_size, void *tag);
bool cipher_decrypt(cipher_t *cipher, uint8_t *out, size_t *out_size,
    const uint8_t *in, size_t in_size, void *tag);

#endif