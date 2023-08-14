#include "logger.h"
#include "xalloc.h"
#include "crypto/common.h"
#include "crypto/cipher.h"
#include "endianness.h"
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <openssl/evp.h>

typedef struct cipher_def {
    cipher_type_t type;
    const char *name;
    const size_t key_size;
    const size_t iv_size;
    const size_t mac_size;

    const char *ossl_name;
} cipher_def_t;

struct cipher {
    // Cipher definition
    const cipher_def_t *def;

    // true if the cipher context is initialized for encryption, false for
    // decryption
    bool encrypts;

    // Original IV passed to cipher_create()
    // Can be NULL
    void *original_iv;
    size_t original_iv_len;

    // OpenSSL EVP
    const EVP_CIPHER *evp_cipher;
    EVP_CIPHER_CTX *evp_ctx;
};

static const cipher_def_t cipher_def_table[CIPHER_TYPE_COUNT] = {
    {
        .type       = CIPHER_TYPE_AES_256_GCM,
        .name       = "AES-256-GCM",
        .key_size   = CIPHER_AES_256_GCM_KEY_SIZE,
        .iv_size    = CIPHER_AES_256_GCM_IV_SIZE,
        .mac_size   = CIPHER_AES_256_GCM_MAC_SIZE,

        .ossl_name  = "AES-256-GCM"
    },
    {
        .type       = CIPHER_TYPE_CHACHA20_POLY1305,
        .name       = "ChaCha20-Poly1305",
        .key_size   = CIPHER_CHACHA20_POLY1305_KEY_SIZE,
        .iv_size    = CIPHER_CHACHA20_POLY1305_IV_SIZE,
        .mac_size   = CIPHER_CHACHA20_POLY1305_MAC_SIZE,

        .ossl_name  = "ChaCha20-Poly1305",
    }
};

static const cipher_def_t *cipher_def(cipher_type_t cipher_type)
{
    if (cipher_type < CIPHER_TYPE_COUNT)
        return &cipher_def_table[cipher_type];
    return NULL;
}

const char *cipher_type_name(cipher_type_t cipher_type)
{
    const cipher_def_t *def = cipher_def(cipher_type);

    return (def != NULL) ? def->name : NULL;
}

cipher_t *cipher_create(cipher_type_t cipher_type, bool encrypts,
    const void *key, size_t key_size,
    const void *iv, size_t iv_size)
{
    const cipher_def_t *def = cipher_def(cipher_type);
    const EVP_CIPHER *evp_cipher = NULL;
    int cipher_key_len;
    int cipher_iv_len;
    cipher_t *cipher = NULL;

    if (!def) {
        logger(LOG_ERR, "%s: Unknown cipher type %X", __func__, cipher_type);
        goto error;
    }

    evp_cipher = EVP_get_cipherbyname(def->ossl_name);
    if (!evp_cipher) {
        logger(LOG_ERR, "%s: %s: Could not fetch cipher %s: %s",
            __func__, "EVP_get_cipherbyname", def->ossl_name, osh_openssl_strerror);
        goto error;
    }

    // Allocate and initialize the cipher
    cipher = xzalloc(sizeof(cipher_t));
    cipher->def = def;
    cipher->encrypts = encrypts;
    cipher->evp_cipher = evp_cipher;
    if (!(cipher->evp_ctx = EVP_CIPHER_CTX_new())) {
        logger(LOG_ERR, "%s: %s: %s", __func__, "EVP_CIPHER_CTX_new",
            osh_openssl_strerror);
        goto error;
    }

    if (iv && iv_size > 0) {
        cipher->original_iv_len = iv_size;
        cipher->original_iv = xmemdup(iv, cipher->original_iv_len);
    }

    // Check key/IV lengths if they are defined
    cipher_key_len = EVP_CIPHER_key_length(cipher->evp_cipher);
    assert((unsigned) cipher_key_len == cipher->def->key_size);
    if (key != NULL && (unsigned) cipher_key_len != key_size) {
        logger(LOG_CRIT, "%s: Invalid cipher %s size %zu for %s (expected %d)",
            __func__, "key", key_size, cipher->def->name, cipher_key_len);
        return false;
    }

    cipher_iv_len = EVP_CIPHER_iv_length(cipher->evp_cipher);
    assert((unsigned) cipher_iv_len == cipher->def->iv_size);
    if (iv != NULL && (unsigned) cipher_iv_len != iv_size) {
        logger(LOG_CRIT, "%s: Invalid cipher %s size %zu for %s (expected %d)",
            __func__, "IV", iv_size, cipher->def->name, cipher_iv_len);
        return false;
    }

    // Initialize the cipher context for encryption or decryption
    if (encrypts) {
        if (!EVP_EncryptInit_ex(cipher->evp_ctx, evp_cipher, NULL, key, iv)) {
            logger(LOG_ERR, "%s: %s: %s", __func__, "EVP_EncryptInit_ex",
                osh_openssl_strerror);
            goto error;
        }
    } else {
        if (!EVP_DecryptInit_ex(cipher->evp_ctx, evp_cipher, NULL, key, iv)) {
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

void cipher_free(cipher_t *cipher)
{
    if (cipher) {
        EVP_CIPHER_CTX_free(cipher->evp_ctx);
        free(cipher->original_iv);
        free(cipher);
    }
}

cipher_type_t cipher_get_type(const cipher_t *cipher)
{
    assert(cipher != NULL);
    return cipher->def->type;
}

size_t cipher_get_key_size(const cipher_t *cipher)
{
    assert(cipher != NULL);
    return cipher->def->key_size;
}

size_t cipher_get_iv_size(const cipher_t *cipher)
{
    assert(cipher != NULL);
    return cipher->def->iv_size;
}

size_t cipher_get_mac_size(const cipher_t *cipher)
{
    assert(cipher != NULL);
    return cipher->def->mac_size;
}

bool cipher_set_key(cipher_t *cipher, const void *key, size_t key_size)
{
    int ctx_key_len;

    assert(cipher != NULL);
    ctx_key_len = EVP_CIPHER_CTX_key_length(cipher->evp_ctx);

    if ((unsigned) ctx_key_len != key_size) {
        logger(LOG_CRIT, "%s: Invalid cipher %s size %zu for %s (expected %d)",
            __func__, "key", key_size, cipher->def->name, ctx_key_len);
        return false;
    }

    if (cipher->encrypts) {
        if (!EVP_EncryptInit_ex(cipher->evp_ctx, NULL, NULL, key, NULL)) {
            logger(LOG_ERR, "%s: %s: %s", __func__, "EVP_EncryptInit_ex",
                osh_openssl_strerror);
            return false;
        }
    } else {
        if (!EVP_DecryptInit_ex(cipher->evp_ctx, NULL, NULL, key, NULL)) {
            logger(LOG_ERR, "%s: %s: %s", __func__, "EVP_DecryptInit_ex",
                osh_openssl_strerror);
            return false;
        }
    }

    return true;
}

bool cipher_set_iv(cipher_t *cipher, const void *iv, size_t iv_size)
{
    int ctx_iv_len;

    assert(cipher != NULL);
    ctx_iv_len = EVP_CIPHER_CTX_iv_length(cipher->evp_ctx);

    if ((unsigned) ctx_iv_len != iv_size) {
        logger(LOG_CRIT, "%s: Invalid cipher %s size %zu for %s (expected %d)",
            __func__, "IV", iv_size, cipher->def->name, ctx_iv_len);
        return false;
    }

    if (cipher->encrypts) {
        if (!EVP_EncryptInit_ex(cipher->evp_ctx, NULL, NULL, NULL, iv)) {
            logger(LOG_ERR, "%s: %s: %s", __func__, "EVP_EncryptInit_ex",
                osh_openssl_strerror);
            return false;
        }
    } else {
        if (!EVP_DecryptInit_ex(cipher->evp_ctx, NULL, NULL, NULL, iv)) {
            logger(LOG_ERR, "%s: %s: %s", __func__, "EVP_DecryptInit_ex",
                osh_openssl_strerror);
            return false;
        }
    }

    return true;
}

bool cipher_get_original_iv(cipher_t *cipher, void *iv, size_t iv_size)
{
    assert(cipher != NULL);

    if (cipher->original_iv == NULL || cipher->original_iv_len != iv_size) {
        logger(LOG_ERR, "%s: %s", __func__, "No original IV or invalid buffer size");
        return false;
    }

    memcpy(iv, cipher->original_iv, iv_size);
    return true;
}

bool cipher_encrypt(cipher_t *cipher,
    void *out, size_t *out_size,
    const void *in, size_t in_size,
    const void *ad, size_t ad_size,
    void *mac, size_t mac_size)
{
    int out_len, final_len, ad_len;

    assert(cipher != NULL);
    if (EVP_EncryptUpdate(cipher->evp_ctx, NULL, &ad_len, ad, ad_size) != 1) {
        logger(LOG_ERR, "%s: %s: %s", __func__, "EVP_EncryptUpdate(ad)",
            osh_openssl_strerror);
        return false;
    }
    if (EVP_EncryptUpdate(cipher->evp_ctx, out, &out_len, in, in_size) != 1) {
        logger(LOG_ERR, "%s: %s: %s", __func__, "EVP_EncryptUpdate",
            osh_openssl_strerror);
        return false;
    }
    if (EVP_EncryptFinal_ex(cipher->evp_ctx, ((uint8_t *) out) + out_len, &final_len) != 1) {
        logger(LOG_ERR, "%s: %s: %s", __func__, "EVP_EncryptFinal_ex",
            osh_openssl_strerror);
        return false;
    }
    if (EVP_CIPHER_CTX_ctrl(cipher->evp_ctx,
            EVP_CTRL_AEAD_GET_TAG, mac_size, mac) != 1)
    {
        logger(LOG_ERR, "%s: %s: %s", __func__, "EVP_CIPHER_CTX_ctrl",
            osh_openssl_strerror);
        return false;
    }
    *out_size = out_len + final_len;
    return true;
}

bool cipher_decrypt(cipher_t *cipher,
    void *out, size_t *out_size,
    const void *in, size_t in_size,
    const void *ad, size_t ad_size,
    void *mac, size_t mac_size)
// FIXME: *mac should be const but OpenSSL API takes a non-const pointer
{
    int out_len, final_len, ad_len;

    assert(cipher != NULL);
    if (EVP_DecryptUpdate(cipher->evp_ctx, NULL, &ad_len, ad, ad_size) != 1) {
        logger(LOG_ERR, "%s: %s: %s", __func__, "EVP_DecryptUpdate(ad)",
            osh_openssl_strerror);
        return false;
    }
    if (EVP_DecryptUpdate(cipher->evp_ctx, out, &out_len, in, in_size)  != 1) {
        logger(LOG_ERR, "%s: %s: %s", __func__, "EVP_DecryptUpdate",
            osh_openssl_strerror);
        return false;
    }
    if (EVP_CIPHER_CTX_ctrl(cipher->evp_ctx,
            EVP_CTRL_AEAD_SET_TAG, mac_size, mac) != 1)
    {
        logger(LOG_ERR, "%s: %s: %s", __func__, "EVP_CIPHER_CTX_ctrl",
            osh_openssl_strerror);
        return false;
    }
    if (EVP_DecryptFinal_ex(cipher->evp_ctx, ((uint8_t *) out) + out_len, &final_len)  != 1) {
        logger(LOG_ERR, "%s: %s: %s", __func__, "EVP_DecryptFinal_ex",
            osh_openssl_strerror);
        return false;
    }
    *out_size = out_len + final_len;
    return true;
}
