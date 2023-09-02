#include "crypto/keypair.h"
#include "xalloc.h"
#include "memzero.h"
#include <stdlib.h>
#include <criterion/criterion.h>

Test(keypair_t, keypair_type_ed25519)
{
    keypair_t *kp = keypair_create(KEYPAIR_ED25519);

    cr_assert_not_null(kp);
    cr_assert_eq(keypair_get_type(kp), KEYPAIR_ED25519);
    cr_assert_eq(keypair_get_private_key_length(kp), KEYPAIR_ED25519_KEYLEN);
    cr_assert_eq(keypair_get_public_key_length(kp), KEYPAIR_ED25519_KEYLEN);
    cr_assert_eq(keypair_get_private_key_length_from_type(KEYPAIR_ED25519), KEYPAIR_ED25519_KEYLEN);
    cr_assert_eq(keypair_get_public_key_length_from_type(KEYPAIR_ED25519), KEYPAIR_ED25519_KEYLEN);
    cr_assert_eq(keypair_get_signature_length(kp), KEYPAIR_ED25519_SIGLEN);
    cr_assert_eq(keypair_get_secret_length(kp), 0);
    keypair_destroy(kp);
}

Test(keypair_t, keypair_type_x25519)
{
    keypair_t *kp = keypair_create(KEYPAIR_X25519);

    cr_assert_not_null(kp);
    cr_assert_eq(keypair_get_type(kp), KEYPAIR_X25519);
    cr_assert_eq(keypair_get_private_key_length(kp), KEYPAIR_X25519_KEYLEN);
    cr_assert_eq(keypair_get_public_key_length(kp), KEYPAIR_X25519_KEYLEN);
    cr_assert_eq(keypair_get_private_key_length_from_type(KEYPAIR_X25519), KEYPAIR_X25519_KEYLEN);
    cr_assert_eq(keypair_get_public_key_length_from_type(KEYPAIR_X25519), KEYPAIR_X25519_KEYLEN);
    cr_assert_eq(keypair_get_signature_length(kp), 0);
    cr_assert_eq(keypair_get_secret_length(kp), KEYPAIR_X25519_SECRETLEN);
    keypair_destroy(kp);
}

Test(keypair_t, keypair_type_x448)
{
    keypair_t *kp = keypair_create(KEYPAIR_X448);

    cr_assert_not_null(kp);
    cr_assert_eq(keypair_get_type(kp), KEYPAIR_X448);
    cr_assert_eq(keypair_get_private_key_length(kp), KEYPAIR_X448_KEYLEN);
    cr_assert_eq(keypair_get_public_key_length(kp), KEYPAIR_X448_KEYLEN);
    cr_assert_eq(keypair_get_private_key_length_from_type(KEYPAIR_X448), KEYPAIR_X448_KEYLEN);
    cr_assert_eq(keypair_get_public_key_length_from_type(KEYPAIR_X448), KEYPAIR_X448_KEYLEN);
    cr_assert_eq(keypair_get_signature_length(kp), 0);
    cr_assert_eq(keypair_get_secret_length(kp), KEYPAIR_X448_SECRETLEN);
    keypair_destroy(kp);
}

static void test_keypair_trust(keypair_type_t type)
{
    keypair_t *orig = keypair_create(type);
    keypair_t *kp = keypair_create(type);
    const void *privkey;
    size_t privkey_len;
    char *privkey_b64;
    const void *pubkey;
    size_t pubkey_len;
    char *pubkey_b64;

    cr_assert_not_null(orig);
    cr_assert_not_null(kp);
    cr_assert_eq(keypair_generate_random(orig), true);
    privkey = keypair_get_private_key(orig);
    privkey_len = keypair_get_private_key_length(orig);
    privkey_b64 = keypair_get_private_key_b64(orig);
    pubkey = keypair_get_public_key(orig);
    pubkey_len = keypair_get_public_key_length(orig);
    pubkey_b64 = keypair_get_public_key_b64(orig);
    cr_assert_not_null(privkey);
    cr_assert_gt(privkey_len, 0);
    cr_assert_not_null(privkey_b64);
    cr_assert_not_null(pubkey);
    cr_assert_gt(pubkey_len, 0);
    cr_assert_not_null(pubkey_b64);

    cr_assert_eq(keypair_is_trusted(kp), false, "keypair_t should not be trusted after creation");
    keypair_set_trusted(kp, true);
    cr_assert_eq(keypair_is_trusted(kp), false, "keypair_t should not be trusted without a key");

    cr_assert_eq(keypair_set_private_key(kp, privkey, privkey_len), true);
    cr_assert_eq(keypair_is_trusted(kp), false, "keypair_t should not be trusted after setting a new key");
    keypair_set_trusted(kp, true);
    cr_assert_eq(keypair_is_trusted(kp), true, "keypair_t has a key and should have been trusted");

    cr_assert_eq(keypair_set_private_key_base64(kp, privkey_b64), true);
    cr_assert_eq(keypair_is_trusted(kp), false, "keypair_t should not be trusted after setting a new key");
    keypair_set_trusted(kp, true);
    cr_assert_eq(keypair_is_trusted(kp), true, "keypair_t has a key and should have been trusted");

    cr_assert_eq(keypair_set_public_key(kp, pubkey, pubkey_len), true);
    cr_assert_eq(keypair_is_trusted(kp), false, "keypair_t should not be trusted after setting a new key");
    keypair_set_trusted(kp, true);
    cr_assert_eq(keypair_is_trusted(kp), true, "keypair_t has a key and should have been trusted");

    cr_assert_eq(keypair_set_public_key_base64(kp, pubkey_b64), true);
    cr_assert_eq(keypair_is_trusted(kp), false, "keypair_t should not be trusted after setting a new key");
    keypair_set_trusted(kp, true);
    cr_assert_eq(keypair_is_trusted(kp), true, "keypair_t has a key and should have been trusted");

    cr_assert_eq(keypair_generate_random(kp), true);
    cr_assert_eq(keypair_is_trusted(kp), false, "keypair_t should not be trusted after setting a new key");
    keypair_set_trusted(kp, true);
    cr_assert_eq(keypair_is_trusted(kp), true, "keypair_t has a key and should have been trusted");

    keypair_clear(kp);
    cr_assert_eq(keypair_is_trusted(kp), false, "keypair_t should not be trusted after being cleared");
    keypair_set_trusted(kp, true);
    cr_assert_eq(keypair_is_trusted(kp), false, "keypair_t should not be trusted without a key");

    free(privkey_b64);
    free(pubkey_b64);
    keypair_destroy(orig);
    keypair_destroy(kp);
}

Test(keypair_t, keypair_trust_ed25519)
{
    test_keypair_trust(KEYPAIR_ED25519);
}

Test(keypair_t, keypair_trust_x25519)
{
    test_keypair_trust(KEYPAIR_X25519);
}

Test(keypair_t, keypair_trust_x448)
{
    test_keypair_trust(KEYPAIR_X448);
}

static void test_keypair_kex_dh(keypair_type_t type)
{
    keypair_t *k1 = keypair_create(type);
    keypair_t *k2 = keypair_create(type);
    const size_t s1_len = keypair_get_secret_length(k1);
    uint8_t *s1 = xalloc(s1_len);
    const size_t s2_len = keypair_get_secret_length(k2);
    uint8_t *s2 = xalloc(s2_len);

    cr_assert_not_null(k1);
    cr_assert_not_null(k2);
    cr_assert_not_null(s1);
    cr_assert_not_null(s2);
    cr_assert_eq(s1_len, s2_len);
    cr_assert_eq(keypair_generate_random(k1), true);
    cr_assert_eq(keypair_generate_random(k2), true);
    cr_assert_eq(keypair_kex_dh(k1, k2, s1, s1_len), true);
    cr_assert_eq(keypair_kex_dh(k2, k1, s2, s2_len), true);
    cr_assert_arr_eq(s1, s2, s1_len);
    memzero_free(s1, s1_len);
    memzero_free(s2, s2_len);
    keypair_destroy(k1);
    keypair_destroy(k2);
}

static void test_keypair_kex_dh_missing_one_key(keypair_type_t type)
{
    keypair_t *k1 = keypair_create(type);
    keypair_t *k2 = keypair_create(type);
    const size_t s1_len = keypair_get_secret_length(k1);
    uint8_t *s1 = xalloc(s1_len);
    const size_t s2_len = keypair_get_secret_length(k2);
    uint8_t *s2 = xalloc(s2_len);

    cr_assert_not_null(k1);
    cr_assert_not_null(k2);
    cr_assert_not_null(s1);
    cr_assert_not_null(s2);
    cr_assert_eq(s1_len, s2_len);
    cr_assert_eq(keypair_generate_random(k1), true);
    cr_assert_eq(keypair_kex_dh(k1, k2, s1, s1_len), false);
    cr_assert_eq(keypair_kex_dh(k2, k1, s2, s2_len), false);
    memzero_free(s1, s1_len);
    memzero_free(s2, s2_len);
    keypair_destroy(k1);
    keypair_destroy(k2);
}

static void test_keypair_kex_dh_missing_both_keys(keypair_type_t type)
{
    keypair_t *k1 = keypair_create(type);
    keypair_t *k2 = keypair_create(type);
    const size_t s1_len = keypair_get_secret_length(k1);
    uint8_t *s1 = xalloc(s1_len);
    const size_t s2_len = keypair_get_secret_length(k2);
    uint8_t *s2 = xalloc(s2_len);

    cr_assert_not_null(k1);
    cr_assert_not_null(k2);
    cr_assert_not_null(s1);
    cr_assert_not_null(s2);
    cr_assert_eq(s1_len, s2_len);
    cr_assert_eq(keypair_kex_dh(k1, k2, s1, s1_len), false);
    cr_assert_eq(keypair_kex_dh(k2, k1, s2, s2_len), false);
    memzero_free(s1, s1_len);
    memzero_free(s2, s2_len);
    keypair_destroy(k1);
    keypair_destroy(k2);
}

Test(keypair_t, keypair_kex_dh_x25519)
{
    test_keypair_kex_dh(KEYPAIR_X25519);
}

Test(keypair_t, keypair_kex_dh_x25519_missing_one_key)
{
    test_keypair_kex_dh_missing_one_key(KEYPAIR_X25519);
}

Test(keypair_t, keypair_kex_dh_x25519_missing_both_keys)
{
    test_keypair_kex_dh_missing_both_keys(KEYPAIR_X25519);
}

Test(keypair_t, keypair_kex_dh_x448)
{
    test_keypair_kex_dh(KEYPAIR_X448);
}

Test(keypair_t, keypair_kex_dh_x448_missing_one_key)
{
    test_keypair_kex_dh_missing_one_key(KEYPAIR_X448);
}

Test(keypair_t, keypair_kex_dh_x448_missing_both_keys)
{
    test_keypair_kex_dh_missing_both_keys(KEYPAIR_X448);
}

static void test_keypair_sig(keypair_type_t type)
{
    keypair_t *priv = keypair_create(type);
    keypair_t *pub = keypair_create(type);
    const void *pubkey;
    size_t pubkey_len;
    uint8_t *sig;
    size_t sig_len;

    cr_assert_not_null(priv);
    cr_assert_not_null(pub);
    cr_assert_eq(keypair_generate_random(priv), true);
    pubkey = keypair_get_public_key(priv);
    pubkey_len = keypair_get_public_key_length(priv);
    cr_assert_not_null(pubkey);
    cr_assert_gt(pubkey_len, 0);
    cr_assert_eq(keypair_set_public_key(pub, pubkey, pubkey_len), true);

    sig_len = keypair_get_signature_length(priv);
    cr_assert_gt(sig_len, 0);
    sig = xalloc(sig_len);

    cr_assert_eq(keypair_sig_sign(priv, pubkey, pubkey_len, sig, sig_len), true);
    cr_assert_eq(keypair_sig_verify(pub, pubkey, pubkey_len, sig, sig_len), true);
    cr_assert_eq(keypair_generate_random(pub), true);
    cr_assert_eq(keypair_sig_verify(pub, pubkey, pubkey_len, sig, sig_len), false);

    free(sig);
    keypair_destroy(priv);
    keypair_destroy(pub);
}

Test(keypair_t, keypair_sig_ed25519)
{
    test_keypair_sig(KEYPAIR_ED25519);
}
