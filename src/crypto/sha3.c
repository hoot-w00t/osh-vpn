#include "logger.h"
#include "crypto/common.h"
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

// Calculate the SHA3-512 hash of *in and put in into *hash
// *hash must have a size of EVP_MAX_MD_SIZE bytes at least, the actual size of
// the written hash will be stored in *hash_size
bool sha3_512_hash(const uint8_t *in, unsigned int in_size, uint8_t *hash,
    unsigned int *hash_size)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    if (!ctx) {
        logger(LOG_ERR, "sha3_512_hash: EVP_MD_CTX_new: %s",
            osh_openssl_strerror);
        goto error;
    }
    if (!EVP_DigestInit_ex(ctx, EVP_sha3_512(), NULL)) {
        logger(LOG_ERR, "sha3_512_hash: EVP_DigestInit_ex: %s",
            osh_openssl_strerror);
        goto error;
    }
    if (!EVP_DigestUpdate(ctx, in, in_size)) {
        logger(LOG_ERR, "sha3_512_hash: EVP_DigestUpdate: %s",
            osh_openssl_strerror);
        goto error;
    }
    if (!EVP_DigestFinal_ex(ctx, hash, hash_size)) {
        logger(LOG_ERR, "sha3_512_hash: EVP_DigestFinal_ex: %s",
            osh_openssl_strerror);
        goto error;
    }
    EVP_MD_CTX_free(ctx);
    return true;

error:
    EVP_MD_CTX_free(ctx);
    return false;
}

// Dump hash to hexdump
// hexdump must have a size of ((EVP_MAX_MD_SIZE * 2) + 1)
// If upper_case is true the hexadecimal letters will be in upper case
void hash_hexdump(const uint8_t *hash, unsigned int hash_size,
    char *hexdump, bool upper_case)
{
    const char *fmt = upper_case ? "%02X" : "%02x";
    const size_t hexdump_size = (hash_size * 2) + 1;
    char h[3];

    memset(hexdump, 0, hexdump_size);
    for (unsigned int i = 0; i < hash_size; ++i) {
        snprintf(h, sizeof(h), fmt, hash[i]);
        strcat(hexdump, h);
    }
}