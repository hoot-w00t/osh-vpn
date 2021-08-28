#include "logger.h"
#include "xalloc.h"
#include "crypto/pkey.h"
#include "crypto/common.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <openssl/ecdh.h>
#include <openssl/pem.h>

// Generate private/public keys
static EVP_PKEY *pkey_generate(int id, const char *id_name)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(id, NULL);

    if (!pctx) {
        logger(LOG_ERR, "pkey_generate: %s: EVP_PKEY_CTX_new_id: %s",
            id_name, osh_openssl_strerror);
        goto error;
    }
    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        logger(LOG_ERR, "pkey_generate: %s: EVP_PKEY_keygen_init: %s",
            id_name, osh_openssl_strerror);
        goto error;
    }
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        logger(LOG_ERR, "pkey_generate: %s: EVP_PKEY_keygen: %s",
            id_name, osh_openssl_strerror);
        goto error;
    }
    EVP_PKEY_CTX_free(pctx);
    return pkey;

error:
    EVP_PKEY_CTX_free(pctx);
    return NULL;
}

// Generate an Ed25519 keypair
// Returns NULL on error
EVP_PKEY *pkey_generate_ed25519(void)
{
    return pkey_generate(EVP_PKEY_ED25519, "ED25519");
}

// Generate an X25519 keypair
// Returns NULL on error
EVP_PKEY *pkey_generate_x25519(void)
{
    return pkey_generate(EVP_PKEY_X25519, "X25519");
}

// Create a shared secret between the privkey and pubkey, dynamically allocates
// the shared secret buffer
// Returns false on error, when an error occurs all allocations in this function
// are freed, including *shared_secret
bool pkey_derive(EVP_PKEY *privkey, EVP_PKEY *pubkey, uint8_t **shared_secret,
    size_t *shared_secret_size)
{
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(privkey, NULL);

    if (!pctx) {
        logger(LOG_ERR, "pkey_derive: EVP_PKEY_CTX_new: %s", osh_openssl_strerror);
        goto error;
    }
    if (EVP_PKEY_derive_init(pctx) <= 0) {
        logger(LOG_ERR, "pkey_derive: EVP_PKEY_derive_init: %s", osh_openssl_strerror);
        goto error;
    }
    if (EVP_PKEY_derive_set_peer(pctx, pubkey) <= 0) {
        logger(LOG_ERR, "pkey_derive: EVP_PKEY_derive_set_peer: %s", osh_openssl_strerror);
        goto error;
    }

    // Retrieve the max size of the shared secret
    if (EVP_PKEY_derive(pctx, NULL, shared_secret_size) <= 0) {
        logger(LOG_ERR, "pkey_derive: EVP_PKEY_derive (size): %s", osh_openssl_strerror);
        goto error;
    }

    // Allocate the shared secret buffer with its max size
    *shared_secret = xzalloc(*shared_secret_size);

    if (EVP_PKEY_derive(pctx, *shared_secret, shared_secret_size) <= 0) {
        free(*shared_secret);
        logger(LOG_ERR, "pkey_derive: EVP_PKEY_derive: %s", osh_openssl_strerror);
        goto error;
    }
    EVP_PKEY_CTX_free(pctx);
    return true;

error:
    EVP_PKEY_CTX_free(pctx);
    return false;
}

// Sign data using privkey, dynamically allocates the signature buffer
// This function signs as a one-shot, it only calculates the signature, nothing
// is hashed
bool pkey_sign(EVP_PKEY *privkey, const uint8_t *data, size_t data_size,
    uint8_t **sig, size_t *sig_size)
{
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;

    if (!mctx) {
        logger(LOG_ERR, "pkey_sign: EVP_MD_CTX_new: %s", osh_openssl_strerror);
        goto error;
    }
    if (EVP_DigestSignInit(mctx, &pctx, NULL, NULL, privkey) <= 0) {
        logger(LOG_ERR, "pkey_sign: EVP_DigestSignInit: %s", osh_openssl_strerror);
        goto error;
    }

    // Retrieve the max size of the signature
    if (EVP_DigestSign(mctx, NULL, sig_size, data, data_size) <= 0) {
        logger(LOG_ERR, "pkey_sign: EVP_DigestSign (size): %s", osh_openssl_strerror);
        goto error;
    }

    // Allocate the signature buffer
    *sig = xzalloc(*sig_size);

    if (EVP_DigestSign(mctx, *sig, sig_size, data, data_size) <= 0) {
        free(*sig);
        logger(LOG_ERR, "pkey_sign: EVP_DigestSign: %s", osh_openssl_strerror);
        goto error;
    }

    EVP_MD_CTX_free(mctx);
    return true;

error:
    EVP_MD_CTX_free(mctx);
    return false;
}

// Verify signed data using pubkey
// Returns true if the signature is valid, false if it is invalid or if an error
// occurs
bool pkey_verify(EVP_PKEY *pubkey, const uint8_t *data, size_t data_size,
    const uint8_t *sig, size_t sig_size)
{
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;
    int err = 0;

    if (!mctx) {
        logger(LOG_ERR, "pkey_verify: EVP_MD_CTX_new: %s", osh_openssl_strerror);
        goto error;
    }
    if (EVP_DigestVerifyInit(mctx, &pctx, NULL, NULL, pubkey) != 1) {
        logger(LOG_ERR, "pkey_verify: EVP_DigestVerifyInit: %s", osh_openssl_strerror);
        goto error;
    }
    if ((err = EVP_DigestVerify(mctx, sig, sig_size, data, data_size)) != 1) {
        if (err != 0) {
            logger(LOG_ERR, "pkey_verify: EVP_DigestVerify: %s",
                osh_openssl_strerror);
        }
        goto error;
    }
    EVP_MD_CTX_free(mctx);
    return true;

error:
    EVP_MD_CTX_free(mctx);
    return false;
}

// Save a private key to file
// Returns false on error
bool pkey_save_privkey_pem(EVP_PKEY *pkey, const char *filename)
{
    FILE *fp = fopen(filename, "w");

    if (!fp) {
        logger(LOG_ERR, "Failed to open %s: %s", filename, strerror(errno));
        goto error;
    }
    if (!PEM_write_PKCS8PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL)) {
        logger(LOG_ERR, "Failed to write private key to %s: %s", filename,
            osh_openssl_strerror);
        goto error;
    }
    fclose(fp);
    return true;

error:
    if (fp) fclose(fp);
    return false;
}

// Save a public key to a file
// Returns false on error
bool pkey_save_pubkey_pem(EVP_PKEY *pkey, const char *filename)
{
    FILE *fp = fopen(filename, "w");

    if (!fp) {
        logger(LOG_ERR, "Failed to open %s: %s", filename, strerror(errno));
        goto error;
    }
    if (!PEM_write_PUBKEY(fp, pkey)) {
        logger(LOG_ERR, "Failed to write public key to %s: %s", filename,
            osh_openssl_strerror);
        goto error;
    }
    fclose(fp);
    return true;

error:
    if (fp) fclose(fp);
    return false;
}

// Load a private key from a file
// Returns NULL on error
EVP_PKEY *pkey_load_privkey_pem(const char *filename)
{
    FILE *fp = fopen(filename, "r");
    EVP_PKEY *pkey = NULL;

    if (!fp) {
        logger(LOG_ERR, "Failed to open %s: %s", filename, strerror(errno));
        goto error;
    }
    pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    if (!pkey) {
        logger(LOG_ERR, "Failed to read private key from %s: %s", filename,
            osh_openssl_strerror);
        goto error;
    }
    fclose(fp);
    return pkey;

error:
    if (fp) fclose(fp);
    EVP_PKEY_free(pkey);
    return NULL;
}

// Load a public key from a file
// Returns NULL on error
EVP_PKEY *pkey_load_pubkey_pem(const char *filename)
{
    FILE *fp = fopen(filename, "r");
    EVP_PKEY *pkey = NULL;

    if (!fp) {
        logger(LOG_ERR, "Failed to open %s: %s", filename, strerror(errno));
        goto error;
    }
    pkey = PEM_read_PUBKEY(fp, &pkey, NULL, NULL);
    if (!pkey) {
        logger(LOG_ERR, "Failed to read public key from %s: %s", filename,
            osh_openssl_strerror);
        goto error;
    }
    fclose(fp);
    return pkey;

error:
    if (fp) fclose(fp);
    EVP_PKEY_free(pkey);
    return NULL;
}

// Save a public key to memory
static bool pkey_save_pubkey(const char *id_name, const EVP_PKEY *pubkey,
    uint8_t **dest, size_t *dest_size)
{
    if (!EVP_PKEY_get_raw_public_key(pubkey, NULL, dest_size)) {
        logger(LOG_ERR, "pkey_save_pubkey: %s: %s", id_name, osh_openssl_strerror);
        return false;
    }
    *dest = xzalloc(*dest_size);
    if (!EVP_PKEY_get_raw_public_key(pubkey, *dest, dest_size)) {
        free(*dest);
        logger(LOG_ERR, "pkey_save_pubkey: %s: %s", id_name, osh_openssl_strerror);
        return false;
    }
    return true;
}

// Save a public X25519 key to memory
// Dynamically allocates *dest to hold the key
// Returns false on error
bool pkey_save_x25519_pubkey(const EVP_PKEY *pubkey, uint8_t **dest,
    size_t *dest_size)
{
    return pkey_save_pubkey("X25519", pubkey, dest, dest_size);
}

// Save a public Ed25519 key to memory
// Dynamically allocates *dest to hold the key
// Returns false on error
bool pkey_save_ed25519_pubkey(const EVP_PKEY *pubkey, uint8_t **dest,
    size_t *dest_size)
{
    return pkey_save_pubkey("Ed25519", pubkey, dest, dest_size);
}

// Load a public key from memory
static EVP_PKEY *pkey_load_pubkey(int id, const char *id_name,
    const uint8_t *pubkey, size_t pubkey_size)
{
    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(id, NULL, pubkey, pubkey_size);

    if (!pkey)
        logger(LOG_ERR, "pkey_load_pubkey: %s: %s", id_name, osh_openssl_strerror);
    return pkey;
}

// Load a public X25519 key from memory
// Returns NULL on error
EVP_PKEY *pkey_load_x25519_pubkey(const uint8_t *pubkey, size_t pubkey_size)
{
    return pkey_load_pubkey(EVP_PKEY_X25519, "X25519", pubkey, pubkey_size);
}

// Load a public Ed25519 key from memory
// Returns NULL on error
EVP_PKEY *pkey_load_ed25519_pubkey(const uint8_t *pubkey, size_t pubkey_size)
{
    return pkey_load_pubkey(EVP_PKEY_ED25519, "Ed25519", pubkey, pubkey_size);
}