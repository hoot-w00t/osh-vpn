#include "logger.h"
#include "crypto/common.h"
#include "crypto/hkdf.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>

// Derive out_size bytes to *out using HKDF (SHA2-512 as the message digest)
// Returns false on error
bool hkdf_derive(
    const void *key, size_t key_size,
    const void *salt, size_t salt_size,
    const void *label, size_t label_size,
    void *out, size_t out_size)
{
    bool success = false;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

    // Initialize EVP context
    if (!pctx) {
        logger(LOG_CRIT, "hkdf_derive: %s: %s", "EVP_PKEY_CTX_new_id",
            osh_openssl_strerror);
        goto end;
    }
    if (EVP_PKEY_derive_init(pctx) <= 0) {
        logger(LOG_CRIT, "hkdf_derive: %s: %s", "EVP_PKEY_derive_init",
            osh_openssl_strerror);
        goto end;
    }

    // Set the message digest
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha512()) <= 0) {
        logger(LOG_CRIT, "hkdf_derive: %s: %s", "EVP_PKEY_CTX_set_hkdf_md",
            osh_openssl_strerror);
        goto end;
    }

    // Set the salt, key and label
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, salt_size) <= 0) {
        logger(LOG_CRIT, "hkdf_derive: %s: %s", "EVP_PKEY_CTX_set1_hkdf_salt",
            osh_openssl_strerror);
        goto end;
    }
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, key, key_size) <= 0) {
        logger(LOG_CRIT, "hkdf_derive: %s: %s", "EVP_PKEY_CTX_set1_hkdf_key",
            osh_openssl_strerror);
        goto end;
    }
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, label, label_size) <= 0) {
        logger(LOG_CRIT, "hkdf_derive: %s: %s", "EVP_PKEY_CTX_add1_hkdf_info",
            osh_openssl_strerror);
        goto end;
    }

    // Derive out_size bytes to *out
    if (EVP_PKEY_derive(pctx, out, &out_size) <= 0) {
        logger(LOG_CRIT, "hkdf_derive: %s: %s", "EVP_PKEY_derive",
            osh_openssl_strerror);
        goto end;
    }

    success = true;

end:
    EVP_PKEY_CTX_free(pctx);
    return success;
}
