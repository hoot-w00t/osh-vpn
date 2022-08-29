#ifndef _OSH_CRYPTO_PKEY_H
#define _OSH_CRYPTO_PKEY_H

#include <stdbool.h>
#include <stdint.h>
#include <openssl/evp.h>

EVP_PKEY *pkey_generate_ed25519(void);
EVP_PKEY *pkey_generate_x25519(void);
#define pkey_free(pkey) EVP_PKEY_free(pkey)

bool pkey_derive(EVP_PKEY *privkey, EVP_PKEY *pubkey, uint8_t **shared_secret,
    size_t *shared_secret_size);
bool pkey_sign(EVP_PKEY *privkey, const void *data, size_t data_size,
    uint8_t **sig, size_t *sig_size);
bool pkey_verify(EVP_PKEY *pubkey, const void *data, size_t data_size,
    const void *sig, size_t sig_size);

bool pkey_save_privkey_pem(EVP_PKEY *pkey, const char *filename);
bool pkey_save_privkey(const EVP_PKEY *privkey, uint8_t **dest, size_t *dest_size);

bool pkey_save_pubkey(const EVP_PKEY *pubkey, uint8_t **dest, size_t *dest_size);

EVP_PKEY *pkey_load_privkey_pem(const char *filename);
EVP_PKEY *pkey_load_ed25519_privkey(const uint8_t *privkey, size_t privkey_size);

EVP_PKEY *pkey_load_x25519_pubkey(const uint8_t *pubkey, size_t pubkey_size);
EVP_PKEY *pkey_load_ed25519_pubkey(const uint8_t *pubkey, size_t pubkey_size);

#endif
