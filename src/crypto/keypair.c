#include "crypto/common.h"
#include "crypto/keypair.h"
#include "macros_assert.h"
#include "base64.h"
#include "xalloc.h"
#include "memzero.h"
#include "logger.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <openssl/ecdh.h>
#include <openssl/pem.h>

typedef struct keypair_def {
    const keypair_type_t type;
    const char *name;

    const size_t private_key_len;
    const size_t public_key_len;
    const bool is_signing_key;
    const size_t signature_length;
    const bool is_dh_key;
    const size_t secret_length;

    const int ossl_id;
} keypair_def_t;

struct keypair {
    const keypair_def_t *def;

    EVP_PKEY *evp_pkey;
    void *private_key;
    void *public_key;

    bool key_is_trusted;
};

static const keypair_def_t keypair_def_table[KEYPAIR_COUNT] = {
    {
        .type = KEYPAIR_ED25519,
        .name = "Ed25519",
        .private_key_len = KEYPAIR_ED25519_KEYLEN,
        .public_key_len = KEYPAIR_ED25519_KEYLEN,
        .is_signing_key = true,
        .signature_length = KEYPAIR_ED25519_SIGLEN,
        .is_dh_key = false,
        .secret_length = 0,

        .ossl_id = EVP_PKEY_ED25519
    },
    {
        .type = KEYPAIR_X25519,
        .name = "X25519",
        .private_key_len = KEYPAIR_X25519_KEYLEN,
        .public_key_len = KEYPAIR_X25519_KEYLEN,
        .is_signing_key = false,
        .signature_length = 0,
        .is_dh_key = true,
        .secret_length = KEYPAIR_X25519_SECRETLEN,

        .ossl_id = EVP_PKEY_X25519
    }
};

static const keypair_def_t *keypair_def(keypair_type_t type)
{
    if ((unsigned) type < KEYPAIR_COUNT)
        return &keypair_def_table[(unsigned) type];
    return NULL;
}

keypair_t *keypair_create(keypair_type_t type)
{
    const keypair_def_t *def = keypair_def(type);
    keypair_t *kp;

    if (!def) {
        logger(LOG_ERR, "%s: Invalid keypair type %u", __func__, (unsigned) type);
        return NULL;
    }

    kp = xzalloc(sizeof(*kp));
    kp->def = def;
    return kp;
}

keypair_t *keypair_create_nofail(keypair_type_t type)
{
    keypair_t *kp = keypair_create(type);

    assert(kp != NULL);
    return kp;
}

void keypair_destroy(keypair_t *kp)
{
    if (kp) {
        keypair_clear(kp);
        free(kp);
    }
}

void keypair_clear(keypair_t *kp)
{
    assert(kp != NULL);

    keypair_set_trusted(kp, false);
    EVP_PKEY_free(kp->evp_pkey);
    kp->evp_pkey = NULL;

    if (kp->private_key) {
        memzero_free(kp->private_key, kp->def->private_key_len);
        kp->private_key = NULL;
    }

    if (kp->public_key) {
        memzero_free(kp->public_key, kp->def->public_key_len);
        kp->public_key = NULL;
    }
}

keypair_type_t keypair_get_type(const keypair_t *kp)
{
    assert(kp != NULL);
    return kp->def->type;
}

size_t keypair_get_private_key_length(const keypair_t *kp)
{
    assert(kp != NULL);
    return kp->def->private_key_len;
}

size_t keypair_get_private_key_length_from_type(keypair_type_t type)
{
    const keypair_def_t *def = keypair_def(type);

    return def ? def->private_key_len : 0;
}

size_t keypair_get_public_key_length(const keypair_t *kp)
{
    assert(kp != NULL);
    return kp->def->public_key_len;
}

size_t keypair_get_public_key_length_from_type(keypair_type_t type)
{
    const keypair_def_t *def = keypair_def(type);

    return def ? def->public_key_len : 0;
}

size_t keypair_get_signature_length(const keypair_t *kp)
{
    assert(kp != NULL);
    return kp->def->signature_length;
}

size_t keypair_get_secret_length(const keypair_t *kp)
{
    assert(kp != NULL);
    return kp->def->secret_length;
}

// kp->private_key must have been cleared before calling this function
static bool _dump_evp_private_key(keypair_t *kp)
{
    size_t evp_keylen;

    assert(kp != NULL);
    assert(kp->evp_pkey != NULL);
    if (EVP_PKEY_get_raw_private_key(kp->evp_pkey, NULL, &evp_keylen) != 1) {
        osh_openssl_log_error("EVP_PKEY_get_raw_private_key (length)");
        return false;
    }
    assert(evp_keylen == kp->def->private_key_len);
    assert(kp->private_key == NULL);
    kp->private_key = xzalloc(kp->def->private_key_len);
    if (EVP_PKEY_get_raw_private_key(kp->evp_pkey, kp->private_key, &evp_keylen) != 1) {
        osh_openssl_log_error("EVP_PKEY_get_raw_private_key (key)");
        memzero_free(kp->private_key, kp->def->private_key_len);
        return false;
    }
    assert(evp_keylen == kp->def->private_key_len);
    return true;
}

// kp->public_key must have been cleared before calling this function
static bool _dump_evp_public_key(keypair_t *kp)
{
    size_t evp_keylen;

    assert(kp != NULL);
    assert(kp->evp_pkey != NULL);
    if (EVP_PKEY_get_raw_public_key(kp->evp_pkey, NULL, &evp_keylen) != 1) {
        osh_openssl_log_error("EVP_PKEY_get_raw_public_key (length)");
        return false;
    }
    assert(evp_keylen == kp->def->public_key_len);
    assert(kp->public_key == NULL);
    kp->public_key = xzalloc(kp->def->public_key_len);
    if (EVP_PKEY_get_raw_public_key(kp->evp_pkey, kp->public_key, &evp_keylen) != 1) {
        osh_openssl_log_error("EVP_PKEY_get_raw_public_key (key)");
        memzero_free(kp->public_key, kp->def->public_key_len);
        return false;
    }
    assert(evp_keylen == kp->def->public_key_len);
    return true;
}

// Dump raw keys from kp->evp_pkey to kp->private_key/public_key
// kp->private_key is ignored if is_private_key is false
// kp->private_key/public_key must have been cleared before calling this function
// This calls keypair_clear() on failure
static bool dump_evp_keys(keypair_t *kp, bool is_private_key)
{
    if (is_private_key) {
        if (!_dump_evp_private_key(kp))
            goto fail;
    }

    if (!_dump_evp_public_key(kp))
        goto fail;

    return true;

fail:
    keypair_clear(kp);
    return false;
}

bool keypair_set_private_key(keypair_t *kp, const void *key, size_t key_len)
{
    keypair_clear(kp);

    if (key == NULL || key_len == 0) {
        logger(LOG_ERR, "%s: %s", __func__, "No key");
        return false;
    }

    kp->evp_pkey = EVP_PKEY_new_raw_private_key(kp->def->ossl_id, NULL, key, key_len);
    if (!kp->evp_pkey) {
        osh_openssl_log_error("EVP_PKEY_new_raw_private_key");
        return false;
    }

    return dump_evp_keys(kp, true);
}

bool keypair_set_public_key(keypair_t *kp, const void *key, size_t key_len)
{
    keypair_clear(kp);

    if (key == NULL || key_len == 0) {
        logger(LOG_ERR, "%s: %s", __func__, "No key");
        return false;
    }

    kp->evp_pkey = EVP_PKEY_new_raw_public_key(kp->def->ossl_id, NULL, key, key_len);
    if (!kp->evp_pkey) {
        osh_openssl_log_error("EVP_PKEY_new_raw_public_key");
        return false;
    }

    return dump_evp_keys(kp, false);
}

bool keypair_set_private_key_base64(keypair_t *kp, const char *key_b64)
{
    bool success = false;
    const size_t key_b64_len = strlen(key_b64);
    const size_t key_maxlen = BASE64_DECODE_OUTSIZE(key_b64_len);
    uint8_t *key = xalloc(key_maxlen);
    size_t key_len;

    if (base64_decode(key, &key_len, key_b64, key_b64_len))
        success = keypair_set_private_key(kp, key, key_len);
    else
        logger(LOG_ERR, "%s: %s", __func__, "Failed to decode Base64 key");

    memzero_free(key, key_maxlen);
    return success;
}

bool keypair_set_public_key_base64(keypair_t *kp, const char *key_b64)
{
    bool success = false;
    const size_t key_b64_len = strlen(key_b64);
    const size_t key_maxlen = BASE64_DECODE_OUTSIZE(key_b64_len);
    uint8_t *key = xalloc(key_maxlen);
    size_t key_len;

    if (base64_decode(key, &key_len, key_b64, key_b64_len))
        success = keypair_set_public_key(kp, key, key_len);
    else
        logger(LOG_ERR, "%s: %s", __func__, "Failed to decode Base64 key");

    memzero_free(key, key_maxlen);
    return success;
}

bool keypair_set_private_key_pem(keypair_t *kp, const char *filename)
{
    FILE *f;

    keypair_clear(kp);

    if (filename == NULL) {
        logger(LOG_ERR, "%s: No filename", __func__);
        return false;
    }

    f = fopen(filename, "r");
    if (!f) {
        logger(LOG_ERR, "%s: Failed to open %s: %s", __func__, filename, strerror(errno));
        return false;
    }
    kp->evp_pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    if (!kp->evp_pkey)
        return false;

    return dump_evp_keys(kp, true);
}

bool keypair_generate_random(keypair_t *kp)
{
    EVP_PKEY_CTX *evp_ctx;

    keypair_clear(kp);

    evp_ctx = EVP_PKEY_CTX_new_id(kp->def->ossl_id, NULL);
    if (!evp_ctx) {
        osh_openssl_log_error("EVP_PKEY_CTX_new_id");
        goto end;
    }
    if (EVP_PKEY_keygen_init(evp_ctx) <= 0) {
        osh_openssl_log_error("EVP_PKEY_keygen_init");
        goto end;
    }
    if (EVP_PKEY_keygen(evp_ctx, &kp->evp_pkey) <= 0) {
        osh_openssl_log_error("EVP_PKEY_keygen");
        goto end;
    }

end:
    EVP_PKEY_CTX_free(evp_ctx);
    if (!kp->evp_pkey)
        return false;
    return dump_evp_keys(kp, true);
}

const void *keypair_get_private_key(const keypair_t *kp)
{
    return (kp == NULL) ? NULL : kp->private_key;
}

const void *keypair_get_public_key(const keypair_t *kp)
{
    return (kp == NULL) ? NULL : kp->public_key;
}

// Dump key in Base64
// The returned pointer is dynamically allocated and must be freed
static char *dump_key_b64(const void *key, size_t len)
{
    size_t b64_maxlen;
    char *b64;

    if (key == NULL || len == 0)
        return NULL;

    b64_maxlen = BASE64_ENCODE_EXACTSIZE(len);
    b64 = xzalloc(b64_maxlen);
    base64_encode(b64, key, len);
    return b64;
}

char *keypair_get_private_key_b64(const keypair_t *kp)
{
    return dump_key_b64(keypair_get_private_key(kp), keypair_get_private_key_length(kp));
}

char *keypair_get_public_key_b64(const keypair_t *kp)
{
    return dump_key_b64(keypair_get_public_key(kp), keypair_get_public_key_length(kp));
}

bool keypair_get_private_key_pem(const keypair_t *kp, const char *filename)
{
    const int flags = O_WRONLY | O_CREAT | O_EXCL;
    const int mode = S_IRUSR | S_IWUSR;
    int fd = -1;
    FILE *fp = NULL;
    bool success = false;

    if (kp == NULL || !keypair_has_private_key(kp)) {
        logger(LOG_ERR, "%s: %s", __func__, "No private key");
        goto end;
    }
    fd = open(filename, flags, mode);
    if (fd < 0) {
        logger(LOG_ERR, "%s: Failed to open %s: %s", __func__, filename, strerror(errno));
        goto end;
    }
    fp = fdopen(fd, "w");
    if (fp == NULL) {
        logger(LOG_ERR, "%s: %s: fdopen(%i): %s", __func__, filename, fd, strerror(errno));
        goto end;
    }
    fd = -1;
    if (!PEM_write_PKCS8PrivateKey(fp, kp->evp_pkey, NULL, NULL, 0, NULL, NULL)) {
        logger(LOG_ERR, "%s: Failed to write private key to %s: %s",
            __func__, filename, osh_openssl_strerror);
        goto end;
    }
    success = true;

end:
    if (fp) {
        fclose(fp);
    } else if (fd >= 0) {
        close(fd);
    }
    return success;
}

bool keypair_copy_private_key(keypair_t *dest, const keypair_t *src)
{
    return dest != NULL
        && src  != NULL
        && keypair_set_private_key(dest, keypair_get_private_key(src), keypair_get_private_key_length(src));
}

bool keypair_copy_public_key(keypair_t *dest, const keypair_t *src)
{
    return dest != NULL
        && src  != NULL
        && keypair_set_public_key(dest, keypair_get_public_key(src), keypair_get_public_key_length(src));
}

// Dump key if the buffer has the correct length
static bool dump_key(void *buf, size_t buf_len, const void *key, size_t key_len)
{
    if (buf == NULL || key == NULL || buf_len != key_len || key_len == 0)
        return false;

    memcpy(buf, key, key_len);
    return true;
}

bool keypair_dump_private_key(const keypair_t *kp, void *buf, size_t buf_len)
{
    return dump_key(buf, buf_len,
        keypair_get_private_key(kp), keypair_get_private_key_length(kp));
}

bool keypair_dump_public_key(const keypair_t *kp, void *buf, size_t buf_len)
{
    return dump_key(buf, buf_len,
        keypair_get_public_key(kp), keypair_get_public_key_length(kp));
}

bool keypair_is_trusted(const keypair_t *kp)
{
    assert(kp != NULL);
    return kp->key_is_trusted;
}

void keypair_set_trusted(keypair_t *kp, bool is_trusted)
{
    assert(kp != NULL);

    // Only trust key if there is one loaded
    if (is_trusted && keypair_has_public_key(kp))
        kp->key_is_trusted = true;
    else
        kp->key_is_trusted = false;
}

bool keypair_kex_dh(keypair_t *private, keypair_t *public,
    void *shared_secret, size_t shared_secret_len)
{
    bool success = false;
    EVP_PKEY_CTX *evp_ctx;
    size_t evp_secret_len;

    if (private == NULL || public == NULL) {
        logger(LOG_ERR, "%s: %s", __func__, "Missing private and/or public keypair_t");
        return false;
    }

    if (private->evp_pkey == NULL || public->evp_pkey == NULL) {
        logger(LOG_ERR, "%s: %s", __func__, "Missing private and/or public key");
        return false;
    }

    evp_ctx = EVP_PKEY_CTX_new(private->evp_pkey, NULL);
    if (!evp_ctx) {
        osh_openssl_log_error("EVP_PKEY_CTX_new");
        goto fail;
    }
    if (EVP_PKEY_derive_init(evp_ctx) <= 0) {
        osh_openssl_log_error("EVP_PKEY_derive_init");
        goto fail;
    }
    if (EVP_PKEY_derive_set_peer(evp_ctx, public->evp_pkey) <= 0) {
        osh_openssl_log_error("EVP_PKEY_derive_set_peer");
        goto fail;
    }
    if (EVP_PKEY_derive(evp_ctx, NULL, &evp_secret_len) <= 0) {
        osh_openssl_log_error("EVP_PKEY_derive (length)");
        goto fail;
    }
    if (shared_secret == NULL) {
        logger(LOG_ERR, "%s: %s", __func__, "Shared secret buffer is NULL");
        goto fail;
    }
    if (evp_secret_len != shared_secret_len) {
        logger(LOG_ERR, "%s: Incorrect shared secret buffer length %zu for %s",
            __func__, shared_secret_len, private->def->name);
        goto fail;
    }
    if (EVP_PKEY_derive(evp_ctx, shared_secret, &evp_secret_len) <= 0) {
        memzero(shared_secret, shared_secret_len);
        osh_openssl_log_error("EVP_PKEY_derive (derive)");
        goto fail;
    }
    assert(evp_secret_len == shared_secret_len);
    success = true;

fail:
    EVP_PKEY_CTX_free(evp_ctx);
    return success;
}

bool keypair_sig_sign(keypair_t *key, const void *data, size_t data_len,
    void *sig, size_t sig_len)
{
    EVP_MD_CTX *evp_md_ctx = NULL;
    EVP_PKEY_CTX *evp_pkey_ctx = NULL;
    size_t evp_sig_len = 0;
    bool success = false;

    if (key == NULL || !keypair_has_private_key(key)) {
        logger(LOG_ERR, "%s: %s", __func__, "Missing private key");
        goto end;
    }

    evp_md_ctx = EVP_MD_CTX_new();
    if (!evp_md_ctx) {
        osh_openssl_log_error("EVP_MD_CTX_new");
        goto end;
    }
    assert(key->evp_pkey != NULL);
    if (EVP_DigestSignInit(evp_md_ctx, &evp_pkey_ctx, NULL, NULL, key->evp_pkey) <= 0) {
        osh_openssl_log_error("EVP_DigestSignInit");
        goto end;
    }
    if (EVP_DigestSign(evp_md_ctx, NULL, &evp_sig_len, data, data_len) <= 0) {
        osh_openssl_log_error("EVP_DigestSign (length)");
        goto end;
    }
    assert(sig != NULL);
    if (evp_sig_len != sig_len) {
        logger(LOG_ERR, "%s: Incorrect signature length for %s", __func__, key->def->name);
        goto end;
    }
    if (EVP_DigestSign(evp_md_ctx, sig, &evp_sig_len, data, data_len) <= 0) {
        memzero(sig, sig_len);
        osh_openssl_log_error("EVP_DigestSign (sign)");
        goto end;
    }
    assert(evp_sig_len == sig_len);
    success = true;

end:
    // evp_pkey_ctx is freed with evp_md_ctx automatically because it wasn't
    // initialized prior to calling EVP_DigestSignInit()
    EVP_MD_CTX_free(evp_md_ctx);
    return success;
}

bool keypair_sig_verify(keypair_t *key, const void *data, size_t data_len,
    const void *sig, size_t sig_len)
{
    EVP_MD_CTX *evp_md_ctx = NULL;
    EVP_PKEY_CTX *evp_pkey_ctx = NULL;
    bool success = false;
    int err;

    if (key == NULL || !keypair_has_public_key(key)) {
        logger(LOG_ERR, "%s: %s", __func__, "Missing public key");
        goto end;
    }

    evp_md_ctx = EVP_MD_CTX_new();
    if (!evp_md_ctx) {
        osh_openssl_log_error("EVP_MD_CTX_new");
        goto end;
    }
    assert(key->evp_pkey != NULL);
    if (EVP_DigestVerifyInit(evp_md_ctx, &evp_pkey_ctx, NULL, NULL, key->evp_pkey) != 1) {
        osh_openssl_log_error("EVP_DigestVerifyInit");
        goto end;
    }
    err = EVP_DigestVerify(evp_md_ctx, sig, sig_len, data, data_len);
    if (err != 1) {
        // 0 is verification failure, let caller log that error
        if (err != 0) {
            osh_openssl_log_error("EVP_DigestVerify");
        }
        goto end;
    }
    success = true;

end:
    // evp_pkey_ctx is freed with evp_md_ctx automatically because it wasn't
    // initialized prior to calling EVP_DigestVerifyInit()
    EVP_MD_CTX_free(evp_md_ctx);
    return success;
}
