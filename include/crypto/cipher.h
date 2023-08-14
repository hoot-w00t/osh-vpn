#ifndef _OSH_CRYPTO_CIPHER_H
#define _OSH_CRYPTO_CIPHER_H

#include "macros_assert.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef uint64_t cipher_seqno_t;
typedef struct cipher cipher_t;

typedef enum cipher_type {
    CIPHER_TYPE_AES_256_GCM = 0,
    CIPHER_TYPE_CHACHA20_POLY1305,

    _LAST_CIPHER_TYPE
} cipher_type_t;
#define CIPHER_TYPE_COUNT _LAST_CIPHER_TYPE

#define CIPHER_AES_256_GCM_KEY_SIZE             32
#define CIPHER_AES_256_GCM_IV_SIZE              12
#define CIPHER_AES_256_GCM_MAC_SIZE             16
#define CIPHER_CHACHA20_POLY1305_KEY_SIZE       32
#define CIPHER_CHACHA20_POLY1305_IV_SIZE        12
#define CIPHER_CHACHA20_POLY1305_MAC_SIZE       16

#define _cipher_attr __attribute__((warn_unused_result))

// Returns the cipher type name
// Returns NULL if the cipher type is invalid or CIPHER_TYPE_NONE
const char *cipher_type_name(cipher_type_t cipher_type);

// Create a new cipher
// It is set up for encryption if encrypts is true and for decryption otherwise
// Key/IV are optional and can be set later
// Returns NULL on error
_cipher_attr
cipher_t *cipher_create(cipher_type_t cipher_type, bool encrypts,
    const void *key, size_t key_size,
    const void *iv, size_t iv_size);

// Free cipher_t and allocated resources
void cipher_free(cipher_t *cipher);

// Return cipher type
cipher_type_t cipher_get_type(const cipher_t *cipher);

// Return cipher key size
size_t cipher_get_key_size(const cipher_t *cipher);

// Return cipher IV size
size_t cipher_get_iv_size(const cipher_t *cipher);

// Return cipher MAC size
size_t cipher_get_mac_size(const cipher_t *cipher);

// Set cipher key
_cipher_attr
bool cipher_set_key(cipher_t *cipher, const void *key, size_t key_size);

// Set cipher IV
_cipher_attr
bool cipher_set_iv(cipher_t *cipher, const void *iv, size_t iv_size);

// Get original cipher IV passed to cipher_create()
_cipher_attr
bool cipher_get_original_iv(cipher_t *cipher, void *iv, size_t iv_size);

// Encrypt in_size bytes from *in and write the result to *out
// *out_size is set to the number of bytes written to *out
// *ad is additional data ciphers that support it (can be set to NULL to ignore)
// Returns false on any error
_cipher_attr
bool cipher_encrypt(cipher_t *cipher,
    void *out, size_t *out_size,
    const void *in, size_t in_size,
    const void *ad, size_t ad_size,
    void *mac, size_t mac_size);

// Decrypt in_size bytes from *in and write the result to *out
// *out_size is set to the number of bytes written to *out
// *ad is additional data ciphers that support it (can be set to NULL to ignore)
// Returns false on any error
// Warning: The decrypted output must only be used if this function returns true
_cipher_attr
bool cipher_decrypt(cipher_t *cipher,
    void *out, size_t *out_size,
    const void *in, size_t in_size,
    const void *ad, size_t ad_size,
    void *mac, size_t mac_size);

#endif
