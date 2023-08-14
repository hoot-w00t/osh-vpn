#include "macros_assert.h"
#include "crypto/cipher.h"
#include <stdlib.h>
#include <criterion/criterion.h>

struct __attribute__((packed)) test_cipher_iv {
    uint32_t n;
    uint8_t random[8];
};
STATIC_ASSERT_NOMSG(sizeof(struct test_cipher_iv) == 12);

static void pseudorandom_buf(void *buf, size_t len)
{
    for (size_t i = 0; i < len; ++i)
        ((uint8_t *) buf)[i] = rand() % 0xFF;
}

static void test_cipher_type(cipher_type_t cipher_type, unsigned int srand_seed)
{
    uint8_t key[32];
    uint8_t fake_key[32];
    struct test_cipher_iv iv;
    struct test_cipher_iv fake_iv;
    uint8_t ad[16];
    uint8_t fake_ad[16];
    uint8_t mac[16];
    uint8_t fake_mac[16];
    cipher_t *enc;
    cipher_t *dec;

    srand(srand_seed);
    pseudorandom_buf(key, sizeof(key));
    iv.n = 0;
    pseudorandom_buf(iv.random, sizeof(iv.random));
    pseudorandom_buf(ad, sizeof(ad));
    enc = cipher_create(cipher_type, true, key, sizeof(key), NULL, 0);
    dec = cipher_create(cipher_type, false, NULL, 0, NULL, 0);

    for (size_t i = 0; i < 16; ++i) {
        const size_t orig_plaintext = i;
        const size_t orig_plaintext_size = sizeof(orig_plaintext);
        size_t ciphertext;
        size_t ciphertext_size;
        size_t plaintext;
        size_t plaintext_size;

        // Encrypt orig_plaintext
        cr_assert_eq(cipher_set_iv(enc, &iv, sizeof(iv)), true);
        cr_assert_eq(cipher_encrypt(enc,
            &ciphertext, &ciphertext_size,
            &orig_plaintext, orig_plaintext_size,
            ad, sizeof(ad),
            mac, sizeof(mac)), true);
        cr_assert_eq(ciphertext_size, orig_plaintext_size);

        // Test working decryption
        cr_assert_eq(cipher_set_key(dec, key, sizeof(key)), true);
        cr_assert_eq(cipher_set_iv(dec, &iv, sizeof(iv)), true);
        cr_assert_eq(cipher_decrypt(dec,
            &plaintext, &plaintext_size,
            &ciphertext, ciphertext_size,
            ad, sizeof(ad),
            mac, sizeof(mac)), true);
        cr_assert_eq(plaintext_size, ciphertext_size);
        cr_assert_eq(plaintext, orig_plaintext);

        // Test incorrect key
        pseudorandom_buf(fake_key, sizeof(fake_key));
        cr_assert_eq(cipher_set_key(dec, fake_key, sizeof(fake_key)), true);
        cr_assert_eq(cipher_set_iv(dec, &iv, sizeof(iv)), true);
        cr_assert_eq(cipher_decrypt(dec,
            &plaintext, &plaintext_size,
            &ciphertext, ciphertext_size,
            ad, sizeof(ad),
            mac, sizeof(mac)), false);

        // Test incorrect IV
        pseudorandom_buf(&fake_iv, sizeof(fake_iv));
        cr_assert_eq(cipher_set_key(dec, key, sizeof(key)), true);
        cr_assert_eq(cipher_set_iv(dec, &fake_iv, sizeof(fake_iv)), true);
        cr_assert_eq(cipher_decrypt(dec,
            &plaintext, &plaintext_size,
            &ciphertext, ciphertext_size,
            ad, sizeof(ad),
            mac, sizeof(mac)), false);

        // Test incorrect AD
        pseudorandom_buf(fake_ad, sizeof(fake_ad));
        cr_assert_eq(cipher_set_key(dec, key, sizeof(key)), true);
        cr_assert_eq(cipher_set_iv(dec, &iv, sizeof(iv)), true);
        cr_assert_eq(cipher_decrypt(dec,
            &plaintext, &plaintext_size,
            &ciphertext, ciphertext_size,
            fake_ad, sizeof(fake_ad),
            mac, sizeof(mac)), false);

        // Test incorrect MAC
        pseudorandom_buf(fake_mac, sizeof(fake_mac));
        cr_assert_eq(cipher_set_key(dec, key, sizeof(key)), true);
        cr_assert_eq(cipher_set_iv(dec, &iv, sizeof(iv)), true);
        cr_assert_eq(cipher_decrypt(dec,
            &plaintext, &plaintext_size,
            &ciphertext, ciphertext_size,
            ad, sizeof(ad),
            fake_mac, sizeof(fake_mac)), false);

        // Increment IV for next operation
        iv.n += 1;
    }

    cipher_free(enc);
    cipher_free(dec);
}

Test(cipher_t, test_aes_256_gcm)
{
    test_cipher_type(CIPHER_TYPE_AES_256_GCM, 0);
}

Test(cipher_t, test_chacha20_poly1305)
{
    test_cipher_type(CIPHER_TYPE_CHACHA20_POLY1305, 0);
}
