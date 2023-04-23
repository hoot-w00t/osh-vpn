#include "logger.h"
#include "xalloc.h"
#include "crypto/common.h"
#include "crypto/cipher.h"
#include "endianness.h"
#include <stdlib.h>
#include <stddef.h>
#include <string.h>

// Compute iv from the base_iv and sequence number
static void cipher_compute_iv(cipher_t *cipher, cipher_seqno_t seqno)
{
    STATIC_ASSERT_NOMSG(sizeof(cipher->base_iv.s) == CIPHER_IV_SIZE);
    cipher->iv.s.seqno_be = cipher->base_iv.s.seqno_be ^ htobe64(seqno);
}

// Create a cipher
// If encrypts is true the cipher will be initialized for encryption
// Otherwise it will be initialized for decryption
// Returns NULL on error
cipher_t *cipher_create(const char *cipher_name, bool encrypts,
    const uint8_t *key, size_t key_size,
    const uint8_t *iv, size_t iv_size)
{
    const EVP_CIPHER *evp_cipher = NULL;
    cipher_t *cipher = NULL;

    // Fetch the requested cipher
    evp_cipher = EVP_get_cipherbyname(cipher_name);
    if (!evp_cipher) {
        logger(LOG_ERR, "%s: %s: Could not fetch cipher %s: %s",
            __func__, "EVP_get_cipherbyname", cipher_name, osh_openssl_strerror);
        goto error;
    }

    // Make sure that the key and IV are of a valid size
    if (EVP_CIPHER_key_length(evp_cipher) != CIPHER_KEY_SIZE) {
        logger(LOG_CRIT, "%s: Invalid cipher %s size %i for %s",
            __func__, "key", CIPHER_KEY_SIZE, EVP_CIPHER_name(evp_cipher));
        goto error;
    }
    if (EVP_CIPHER_iv_length(evp_cipher) != CIPHER_IV_SIZE) {
        logger(LOG_CRIT, "%s: Invalid cipher %s size %i for %s",
            __func__, "IV", CIPHER_IV_SIZE, EVP_CIPHER_name(evp_cipher));
        goto error;
    }
    if (key_size != CIPHER_KEY_SIZE) {
        logger(LOG_ERR, "%s: Invalid %s size %zu for %s",
            __func__, "key", key_size, EVP_CIPHER_name(evp_cipher));
        goto error;
    }
    if (iv_size != CIPHER_IV_SIZE) {
        logger(LOG_ERR, "%s: Invalid %s size %zu for %s",
            __func__, "IV", iv_size, EVP_CIPHER_name(evp_cipher));
        goto error;
    }

    // Allocate and initialize the cipher
    cipher = xalloc(sizeof(cipher_t));
    cipher->encrypts = encrypts;

    STATIC_ASSERT_NOMSG(sizeof(cipher->iv.b) == CIPHER_IV_SIZE);
    memcpy(cipher->base_iv.b, iv, CIPHER_IV_SIZE);
    memcpy(cipher->iv.b, cipher->base_iv.b, CIPHER_IV_SIZE);

    // Allocate the cipher context
    if (!(cipher->ctx = EVP_CIPHER_CTX_new())) {
        logger(LOG_ERR, "%s: %s: %s", __func__, "EVP_CIPHER_CTX_new",
            osh_openssl_strerror);
        goto error;
    }

    // Initialize the cipher context for encryption or decryption
    // The IV is not initialized here, it will be set before encrypting or
    // decrypting data
    if (encrypts) {
        if (!EVP_EncryptInit_ex(cipher->ctx, evp_cipher, NULL, key, NULL)) {
            logger(LOG_ERR, "%s: %s: %s", __func__, "EVP_EncryptInit_ex",
                osh_openssl_strerror);
            goto error;
        }
    } else {
        if (!EVP_DecryptInit_ex(cipher->ctx, evp_cipher, NULL, key, NULL)) {
            logger(LOG_ERR, "%s: %s: %s", __func__, "EVP_DecryptInit_ex",
                osh_openssl_strerror);
            goto error;
        }
    }

    return cipher;

error:
    cipher_free(cipher);
    return NULL;
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
    const uint8_t *in, size_t in_size, void *tag, cipher_seqno_t seqno)
{
    int out_len, final_len;

    cipher_compute_iv(cipher, seqno);
    if (EVP_EncryptInit_ex(cipher->ctx, NULL, NULL, NULL, cipher->iv.b) != 1) {
        logger(LOG_ERR, "%s: %s: %s", __func__, "EVP_EncryptInit_ex",
            osh_openssl_strerror);
        return false;
    }
    if (EVP_EncryptUpdate(cipher->ctx, out, &out_len, in, in_size) != 1) {
        logger(LOG_ERR, "%s: %s: %s", __func__, "EVP_EncryptUpdate",
            osh_openssl_strerror);
        return false;
    }
    if (EVP_EncryptFinal_ex(cipher->ctx, out + out_len, &final_len) != 1) {
        logger(LOG_ERR, "%s: %s: %s", __func__, "EVP_EncryptFinal_ex",
            osh_openssl_strerror);
        return false;
    }
    if (EVP_CIPHER_CTX_ctrl(cipher->ctx,
            EVP_CTRL_AEAD_GET_TAG, CIPHER_TAG_SIZE, tag) != 1)
    {
        logger(LOG_ERR, "%s: %s: %s", __func__, "EVP_CIPHER_CTX_ctrl",
            osh_openssl_strerror);
        return false;
    }
    *out_size = out_len + final_len;
    return true;
}

// Decrypt in_size bytes from in to out and write the size of the decrypted data
// in *out_size
// Verifies the authenticity of the cipher text using tag
_cipher_attr
bool cipher_decrypt(cipher_t *cipher, uint8_t *out, size_t *out_size,
    const uint8_t *in, size_t in_size, void *tag, cipher_seqno_t seqno)
{
    int out_len, final_len;

    cipher_compute_iv(cipher, seqno);
    if (EVP_DecryptInit_ex(cipher->ctx, NULL, NULL, NULL, cipher->iv.b) != 1) {
        logger(LOG_ERR, "%s: %s: %s", __func__, "EVP_DecryptInit_ex",
            osh_openssl_strerror);
        return false;
    }
    if (EVP_DecryptUpdate(cipher->ctx, out, &out_len, in, in_size)  != 1) {
        logger(LOG_ERR, "%s: %s: %s", __func__, "EVP_DecryptUpdate",
            osh_openssl_strerror);
        return false;
    }
    if (EVP_CIPHER_CTX_ctrl(cipher->ctx,
            EVP_CTRL_AEAD_SET_TAG, CIPHER_TAG_SIZE, tag) != 1)
    {
        logger(LOG_ERR, "%s: %s: %s", __func__, "EVP_CIPHER_CTX_ctrl",
            osh_openssl_strerror);
        return false;
    }
    if (EVP_DecryptFinal_ex(cipher->ctx, out + out_len, &final_len)  != 1) {
        logger(LOG_ERR, "%s: %s: %s", __func__, "EVP_DecryptFinal_ex",
            osh_openssl_strerror);
        return false;
    }
    *out_size = out_len + final_len;
    return true;
}
