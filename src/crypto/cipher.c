#include "logger.h"
#include "xalloc.h"
#include "crypto/common.h"
#include "crypto/cipher.h"
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <openssl/aes.h>

// Generic cipher_create function for any *evp_cipher
static cipher_t *cipher_create(const EVP_CIPHER *evp_cipher, bool encrypts,
    const uint8_t *key, size_t key_size, const uint8_t *iv, size_t iv_size)
{
    // Make sure that the key and IV are of a valid size for *evp_cipher
    if (key_size != (size_t) EVP_CIPHER_key_length(evp_cipher)) {
        logger(LOG_ERR, "cipher_create: Invalid key size %zu for %s",
            key_size, EVP_CIPHER_name(evp_cipher));
        return NULL;
    }
    if (iv_size > (size_t) EVP_CIPHER_iv_length(evp_cipher)) {
        logger(LOG_ERR, "cipher_create: Invalid IV size %zu for %s",
            iv_size, EVP_CIPHER_name(evp_cipher));
        return NULL;
    }

    // Allocate the cipher
    cipher_t *cipher = xzalloc(sizeof(cipher_t));

    cipher->encrypts = encrypts;

    // Allocate the cipher context
    if (!(cipher->ctx = EVP_CIPHER_CTX_new())) {
        logger(LOG_ERR, "cipher_create: EVP_CIPHER_CTX_new: %s",
            osh_openssl_strerror);
        goto error;
    }
    if (encrypts) {
        if (!EVP_EncryptInit_ex(cipher->ctx, evp_cipher, NULL, key, iv)) {
            logger(LOG_ERR, "cipher_create: EVP_EncryptInit_ex: %s",
                osh_openssl_strerror);
            goto error;
        }
    } else {
        if (!EVP_DecryptInit_ex(cipher->ctx, evp_cipher, NULL, key, iv)) {
            logger(LOG_ERR, "cipher_create: EVP_DecryptInit_ex: %s",
                osh_openssl_strerror);
            goto error;
        }
    }
    return cipher;

error:
    cipher_free(cipher);
    return NULL;
}

// Create an AES-256-CTR cipher
// Returns NULL on error
// If encrypts is true the cipher will be initialized for encryption, otherwise
// it will be initialized for decryption
cipher_t *cipher_create_aes_256_ctr(bool encrypts, const uint8_t *key,
    size_t key_size, const uint8_t *iv, size_t iv_size)
{
    return cipher_create(EVP_aes_256_ctr(), encrypts, key, key_size, iv, iv_size);
}

// Free cipher_t
void cipher_free(cipher_t *cipher)
{
    if (cipher) {
        EVP_CIPHER_CTX_free(cipher->ctx);
        free(cipher);
    }
}

// Encrypt in_size bytes of in to out and write the size of the encrypted data
// in *out_size using cipher
bool cipher_encrypt(cipher_t *cipher, uint8_t *out, size_t *out_size,
    const uint8_t *in, size_t in_size)
{
    int out_len, final_len;

    if (!EVP_EncryptInit_ex(cipher->ctx, NULL, NULL, NULL, NULL)) {
        logger(LOG_ERR, "cipher_encrypt: EVP_EncryptInit_ex: %s",
            osh_openssl_strerror);
        return false;
    }
    if (!EVP_EncryptUpdate(cipher->ctx, out, &out_len, in, in_size)) {
        logger(LOG_ERR, "cipher_encrypt: EVP_EncryptUpdate: %s",
            osh_openssl_strerror);
        return false;
    }
    if (!EVP_EncryptFinal_ex(cipher->ctx, out + out_len, &final_len)) {
        logger(LOG_ERR, "cipher_encrypt: EVP_EncryptFinal_ex: %s",
            osh_openssl_strerror);
        return false;
    }
    *out_size = out_len + final_len;
    return true;
}

// Decrypt in_size bytes of in to out and write the size of the decrypted data
// in *out_size using cipher
bool cipher_decrypt(cipher_t *cipher, uint8_t *out, size_t *out_size,
    const uint8_t *in, size_t in_size)
{
    int out_len, final_len;

    if (!EVP_DecryptInit_ex(cipher->ctx, NULL, NULL, NULL, NULL)) {
        logger(LOG_ERR, "cipher_decrypt: EVP_DecryptInit_ex: %s",
            osh_openssl_strerror);
        return false;
    }
    if (!EVP_DecryptUpdate(cipher->ctx, out, &out_len, in, in_size)) {
        logger(LOG_ERR, "cipher_decrypt: EVP_DecryptUpdate: %s",
            osh_openssl_strerror);
        return false;
    }
    if (!EVP_DecryptFinal_ex(cipher->ctx, out + out_len, &final_len)) {
        logger(LOG_ERR, "cipher_decrypt: EVP_DecryptFinal_ex: %s",
            osh_openssl_strerror);
        return false;
    }
    *out_size = out_len + final_len;
    return true;
}