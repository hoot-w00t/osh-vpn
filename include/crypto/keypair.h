#ifndef OSH_CRYPTO_KEYPAIR_H_
#define OSH_CRYPTO_KEYPAIR_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum keypair_type {
    KEYPAIR_ED25519 = 0,
    KEYPAIR_X25519,

    _KEYPAIR_LAST
} keypair_type_t;
#define KEYPAIR_COUNT _KEYPAIR_LAST

typedef struct keypair keypair_t;

#define KEYPAIR_ED25519_KEYLEN          32
#define KEYPAIR_ED25519_SIGLEN          64

#define KEYPAIR_X25519_KEYLEN           32
#define KEYPAIR_X25519_SECRETLEN        32

// Create keypair
// Returns NULL on error
keypair_t *keypair_create(keypair_type_t type);

// Create keypair
// Never returns NULL, it calls abort() on error
keypair_t *keypair_create_nofail(keypair_type_t type);

// Free keypair
void keypair_destroy(keypair_t *kp);

// Clear keys stored in the keypair
void keypair_clear(keypair_t *kp);

// kp must not be NULL
// Returns keypair type
keypair_type_t keypair_get_type(const keypair_t *kp);

// kp must not be NULL
// Returns private key length
size_t keypair_get_private_key_length(const keypair_t *kp);

// Returns private key length or 0 if type is invalid
size_t keypair_get_private_key_length_from_type(keypair_type_t type);

// kp must not be NULL
// Returns public key length
size_t keypair_get_public_key_length(const keypair_t *kp);

// Returns public key length or 0 if type is invalid
size_t keypair_get_public_key_length_from_type(keypair_type_t type);

// kp must not be NULL
// Returns signature length or 0 if the key type is not for signing
size_t keypair_get_signature_length(const keypair_t *kp);

// kp must not be NULL
// Returns DH shared secret length or 0 if the key type is not for key exchange
size_t keypair_get_secret_length(const keypair_t *kp);

// Set the private key
// The public is automatically computed
bool keypair_set_private_key(keypair_t *kp, const void *key, size_t key_len);

// Set the public key
// There will not be any private key
bool keypair_set_public_key(keypair_t *kp, const void *key, size_t key_len);

// Decode Base64 encoded private key and set it with keypair_set_private_key()
bool keypair_set_private_key_base64(keypair_t *kp, const char *key_b64);

// Decode Base64 encoded public key and set it with keypair_set_public_key()
bool keypair_set_public_key_base64(keypair_t *kp, const char *key_b64);

// Read private key from PEM file
bool keypair_set_private_key_pem(keypair_t *kp, const char *filename);

// Generate a random key
bool keypair_generate_random(keypair_t *kp);

// Returns pointer to the private key or NULL if there is no private key
// The pointer must not be used after changing/clearing/destroying the keypair
const void *keypair_get_private_key(const keypair_t *kp);

// Returns pointer to the public key or NULL if there is no public key
// The pointer must not be used after changing/clearing/destroying the keypair
const void *keypair_get_public_key(const keypair_t *kp);

// Returns the private key in Base64 or NULL if there is no private key
// The pointer must be freed (and should be zeroed with memzero() before)
char *keypair_get_private_key_b64(const keypair_t *kp);

// Returns the public key in Base64 or NULL if there is no public key
// The pointer must be freed
char *keypair_get_public_key_b64(const keypair_t *kp);

// Write private key to PEM file
bool keypair_get_private_key_pem(const keypair_t *kp, const char *filename);

// true if keypair has a private key
#define keypair_has_private_key(kp) (keypair_get_private_key(kp) != NULL)

// true if keypair has a public key
#define keypair_has_public_key(kp) (keypair_get_public_key(kp) != NULL)

// Set destination private key to that of the source
bool keypair_copy_private_key(keypair_t *dest, const keypair_t *src);

// Set destination public key to that of the source
bool keypair_copy_public_key(keypair_t *dest, const keypair_t *src);

// Dump private key to a buffer
// The buffer should be zeroed with memzero() before it is discarded
bool keypair_dump_private_key(const keypair_t *kp, void *buf, size_t buf_len);

// Dump public key to a buffer
bool keypair_dump_public_key(const keypair_t *kp, void *buf, size_t buf_len);

// Returns true if the keypair was set to be trusted with keypair_set_trusted()
// This is an attribute that is not used internally but can be used to keep
// track of keys that should be trusted or not
// This always returns false when there is no key
// Whevener the keys are modified they default to not being trusted
bool keypair_is_trusted(const keypair_t *kp);

// Set a keypair's trust
// If there is no key it will default to not being trusted
void keypair_set_trusted(keypair_t *kp, bool is_trusted);

// Compute a shared secret for key exchange
bool keypair_kex_dh(keypair_t *private, keypair_t *public,
    void *shared_secret, size_t shared_secret_len);

// Sign data with a private key
bool keypair_sig_sign(keypair_t *key, const void *data, size_t data_len,
    void *sig, size_t sig_len);

// Verify signature with a public key
bool keypair_sig_verify(keypair_t *key, const void *data, size_t data_len,
    const void *sig, size_t sig_len);

#endif
