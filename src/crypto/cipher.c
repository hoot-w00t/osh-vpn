#include "logger.h"
#include "xalloc.h"
#include "crypto/common.h"
#include "crypto/cipher.h"
#include <stdlib.h>
#include <stddef.h>
#include <string.h>

// Compute iv from the base_iv and sequence number
static void cipher_compute_iv(cipher_t *cipher)
{
    cipher->iv.s.seqno_be = cipher->base_iv.s.seqno_be ^ htobe64(cipher->seqno);
}

// Increment sequence number and compute the new IV
static void cipher_increment_iv(cipher_t *cipher)
{
    cipher->seqno += 1;
    cipher_compute_iv(cipher);
}

// Generic cipher_create function for any *evp_cipher
static cipher_t *cipher_create(const EVP_CIPHER *evp_cipher, bool encrypts,
    const uint8_t *key, size_t key_size, const uint8_t *iv, size_t iv_size)
{
    cipher_t *cipher = NULL;

    // Make sure that the key and IV are of a valid size
    if (EVP_CIPHER_key_length(evp_cipher) != CIPHER_KEY_SIZE) {
        logger(LOG_CRIT, "cipher_create: Invalid cipher key size %i for %s",
            CIPHER_KEY_SIZE, EVP_CIPHER_name(evp_cipher));
        goto error;
    }
    if (EVP_CIPHER_iv_length(evp_cipher) != CIPHER_IV_SIZE) {
        logger(LOG_CRIT, "cipher_create: Invalid cipher IV size %i for %s",
            CIPHER_IV_SIZE, EVP_CIPHER_name(evp_cipher));
        goto error;
    }
    if (key_size != CIPHER_KEY_SIZE) {
        logger(LOG_ERR, "cipher_create: Invalid key size %zu for %s",
            key_size, EVP_CIPHER_name(evp_cipher));
        goto error;
    }
    if (iv_size != CIPHER_IV_SIZE) {
        logger(LOG_ERR, "cipher_create: Invalid IV size %zu for %s",
            iv_size, EVP_CIPHER_name(evp_cipher));
        goto error;
    }

    // Make sure that the cipher_iv_t structure is of the right size
    OPENSSL_assert(sizeof(cipher_iv_t)  == CIPHER_IV_SIZE);
    OPENSSL_assert(sizeof(cipher->iv.b) == CIPHER_IV_SIZE);
    OPENSSL_assert(sizeof(cipher->iv.s) == CIPHER_IV_SIZE);

    // Allocate and initialize the cipher
    cipher = xalloc(sizeof(cipher_t));
    cipher->encrypts = encrypts;
    memcpy(cipher->base_iv.b, iv, CIPHER_IV_SIZE);
    memcpy(cipher->iv.b, cipher->base_iv.b, CIPHER_IV_SIZE);
    cipher->seqno = 0;
    cipher_compute_iv(cipher);

    // Allocate the cipher context
    if (!(cipher->ctx = EVP_CIPHER_CTX_new())) {
        logger(LOG_ERR, "cipher_create: EVP_CIPHER_CTX_new: %s",
            osh_openssl_strerror);
        goto error;
    }

    // Initialize the cipher context for encryption or decryption
    // The IV is not initialized here, it will be set before encrypting or
    // decrypting data
    if (encrypts) {
        if (!EVP_EncryptInit_ex(cipher->ctx, evp_cipher, NULL, key, NULL)) {
            logger(LOG_ERR, "cipher_create: EVP_EncryptInit_ex: %s",
                osh_openssl_strerror);
            goto error;
        }
    } else {
        if (!EVP_DecryptInit_ex(cipher->ctx, evp_cipher, NULL, key, NULL)) {
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

// Create an AES-256-GCM cipher
// If encrypts is true the cipher will be initialized for encryption
// Otherwise it will be initialized for decryption
// Returns NULL on error
cipher_t *cipher_create_aes_256_gcm(bool encrypts,
    const uint8_t *key, size_t key_size,
    const uint8_t *iv,  size_t iv_size)
{
    return cipher_create(EVP_aes_256_gcm(), encrypts,
        key, key_size, iv, iv_size);
}

// Free cipher_t
void cipher_free(cipher_t *cipher)
{
    if (cipher) {
        EVP_CIPHER_CTX_free(cipher->ctx);
        free(cipher);
    }
}

// Encrypt in_size bytes from in to out and write the size of the encrypted data
// in *out_size
// Write authentication tag to tag
_cipher_attr
bool cipher_encrypt(cipher_t *cipher, uint8_t *out, size_t *out_size,
    const uint8_t *in, size_t in_size, void *tag)
{
    int out_len, final_len;

    if (EVP_EncryptInit_ex(cipher->ctx, NULL, NULL, NULL, cipher->iv.b) != 1) {
        logger(LOG_ERR, "cipher_encrypt: EVP_EncryptInit_ex: %s",
            osh_openssl_strerror);
        return false;
    }
    if (EVP_EncryptUpdate(cipher->ctx, out, &out_len, in, in_size) != 1) {
        logger(LOG_ERR, "cipher_encrypt: EVP_EncryptUpdate: %s",
            osh_openssl_strerror);
        return false;
    }
    if (EVP_EncryptFinal_ex(cipher->ctx, out + out_len, &final_len) != 1) {
        logger(LOG_ERR, "cipher_encrypt: EVP_EncryptFinal_ex: %s",
            osh_openssl_strerror);
        return false;
    }
    if (EVP_CIPHER_CTX_ctrl(cipher->ctx,
            EVP_CTRL_AEAD_GET_TAG, CIPHER_TAG_SIZE, tag) != 1)
    {
        logger(LOG_ERR, "cipher_encrypt: EVP_CIPHER_CTX_ctrl: %s",
            osh_openssl_strerror);
        return false;
    }
    *out_size = out_len + final_len;
    cipher_increment_iv(cipher);
    return true;
}

// Decrypt in_size bytes from in to out and write the size of the decrypted data
// in *out_size
// Verifies the authenticity of the cipher text using tag
_cipher_attr
bool cipher_decrypt(cipher_t *cipher, uint8_t *out, size_t *out_size,
    const uint8_t *in, size_t in_size, void *tag)
{
    int out_len, final_len;

    if (EVP_DecryptInit_ex(cipher->ctx, NULL, NULL, NULL, cipher->iv.b) != 1) {
        logger(LOG_ERR, "cipher_decrypt: EVP_DecryptInit_ex: %s",
            osh_openssl_strerror);
        return false;
    }
    if (EVP_DecryptUpdate(cipher->ctx, out, &out_len, in, in_size)  != 1) {
        logger(LOG_ERR, "cipher_decrypt: EVP_DecryptUpdate: %s",
            osh_openssl_strerror);
        return false;
    }
    if (EVP_CIPHER_CTX_ctrl(cipher->ctx,
            EVP_CTRL_AEAD_SET_TAG, CIPHER_TAG_SIZE, tag) != 1)
    {
        logger(LOG_ERR, "cipher_decrypt: EVP_CIPHER_CTX_ctrl: %s",
            osh_openssl_strerror);
        return false;
    }
    if (EVP_DecryptFinal_ex(cipher->ctx, out + out_len, &final_len)  != 1) {
        logger(LOG_ERR, "cipher_decrypt: EVP_DecryptFinal_ex: %s",
            osh_openssl_strerror);
        return false;
    }
    *out_size = out_len + final_len;
    cipher_increment_iv(cipher);
    return true;
}