#include "base64.h"
#include "xalloc.h"
#include <criterion/criterion.h>
#include <stdlib.h>

static const char *test_1_dec = "Hello world!";
static const char *test_1_enc = "SGVsbG8gd29ybGQh";

static const char *test_2_dec = "base64";
static const char *test_2_enc = "YmFzZTY0";

static const char *test_3_dec_1 = "a";
static const char *test_3_enc_1 = "YQ==";
static const char *test_3_dec_2 = "ab";
static const char *test_3_enc_2 = "YWI=";
static const char *test_3_dec_3 = "abc";
static const char *test_3_enc_3 = "YWJj";
static const char *test_3_dec_4 = "abcd";
static const char *test_3_enc_4 = "YWJjZA==";

static const char *test_4_dec = "Many hands make light work.";
static const char *test_4_enc = "TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu";

static void test_encode(const char *input, const char *expected)
{
    const size_t input_size = strlen(input);
    const size_t result_size = BASE64_ENCODE_OUTSIZE(input_size);
    char *result = xalloc(result_size);

    memset(result, 0xFF, result_size);
    base64_encode(result, input, input_size);
    cr_assert_str_eq(result, expected);
    cr_assert_geq(result_size, strlen(result) + 1);
    cr_assert_eq(BASE64_ENCODE_EXACTSIZE(input_size), strlen(result) + 1);
    free(result);
}

static void test_decode(const char *input, const char *expected)
{
    const size_t input_size = strlen(input);
    const size_t result_size = BASE64_DECODE_OUTSIZE(input_size);
    char *result = xalloc(result_size);
    size_t real_size = (size_t) - 1;

    memset(result, 0xFF, result_size);
    cr_assert_eq(base64_decode(result, &real_size, input, input_size), true);
    cr_assert_eq(real_size, strlen(expected));
    cr_assert_arr_eq(result, expected, strlen(expected));
    cr_assert_geq(result_size, real_size);
    cr_assert_leq(result_size - real_size, 2);
    free(result);
}

Test(base64_encode, encode_test_1)
{
    test_encode(test_1_dec, test_1_enc);
}

Test(base64_encode, encode_test_2)
{
    test_encode(test_2_dec, test_2_enc);
}

Test(base64_encode, encode_test_3)
{
    test_encode(test_3_dec_1, test_3_enc_1);
    test_encode(test_3_dec_2, test_3_enc_2);
    test_encode(test_3_dec_3, test_3_enc_3);
    test_encode(test_3_dec_4, test_3_enc_4);
}

Test(base64_encode, encode_test_4)
{
    test_encode(test_4_dec, test_4_enc);
}

Test(base64_decode, decode_test_1)
{
    test_decode(test_1_enc, test_1_dec);
}

Test(base64_decode, decode_test_2)
{
    test_decode(test_2_enc, test_2_dec);
}

Test(base64_decode, decode_test_3)
{
    test_decode(test_3_enc_1, test_3_dec_1);
    test_decode(test_3_enc_2, test_3_dec_2);
    test_decode(test_3_enc_3, test_3_dec_3);
    test_decode(test_3_enc_4, test_3_dec_4);
}

Test(base64_decode, decode_test_4)
{
    test_decode(test_4_enc, test_4_dec);
}

static void test_encode_decode(const uint8_t *input, size_t input_size)
{
    const size_t encoded_size = BASE64_ENCODE_OUTSIZE(input_size);
    char *encoded = xalloc(encoded_size);
    size_t encoded_strlen;
    uint8_t *decoded = xalloc(input_size);
    size_t decoded_size = (size_t) -1;

    memset(encoded, 0xFF, encoded_size);
    memset(decoded, 0xFF, input_size);

    base64_encode(encoded, input, input_size);
    encoded_strlen = strlen(encoded);
    cr_assert_geq(encoded_size, encoded_strlen + 1);
    cr_assert_eq(BASE64_ENCODE_EXACTSIZE(input_size), encoded_strlen + 1);
    cr_assert_eq(base64_decode(decoded, &decoded_size, encoded, encoded_strlen), true);
    cr_assert_eq(decoded_size, input_size);
    cr_assert_geq(BASE64_DECODE_OUTSIZE(encoded_strlen), decoded_size);
    cr_assert_leq(BASE64_DECODE_OUTSIZE(encoded_strlen) - decoded_size, 2);
    cr_assert_arr_eq(decoded, input, input_size);
    free(encoded);
    free(decoded);
}

static inline void rseed(uint32_t *x)
{
    uint32_t bit_out = *x & 1;

    for (uint32_t i = 0; i < 5; ++i)
        bit_out ^= (*x >> (i + 1)) & 1;

    *x >>= 1;
    *x |= bit_out << 31;
}

static uint8_t *generate_input(size_t size, uint32_t seed)
{
    uint8_t *in = xalloc(size);

    for (size_t i = 0; i < size; ++i) {
        in[i] = seed % 256;
        rseed(&seed);
    }
    return in;
}

Test(base64_encode_decode, encode_and_decode_bytes)
{
    const size_t input_size = 8192;
    uint8_t *input = generate_input(input_size, input_size);

    for (size_t i = 1; i <= input_size; ++i)
        test_encode_decode(input, i);
    free(input);
}

Test(base64_encode_decode, encode_and_decode_pseudorandom_bytes)
{
    for (size_t size = 1; size <= 8192; ++size) {
        uint8_t *input = generate_input(size, size);

        test_encode_decode(input, size);
        free(input);
    }
}

Test(base64_encode_decode, encode_and_decode_nothing)
{
    char output[20];
    size_t output_size = (size_t) -1;

    memset(output, 0xFF, sizeof(output));
    base64_encode(output, NULL, 0);
    cr_assert_str_eq(output, "");
    cr_assert_eq(base64_decode(NULL, &output_size, NULL, 0), true);
    cr_assert_eq(output_size, 0);
}

Test(base64_decode, invalid_padding)
{
    cr_assert_eq(base64_decode(NULL, NULL, "====", 4), false);
    cr_assert_eq(base64_decode(NULL, NULL, "a===", 4), false);
    cr_assert_eq(base64_decode(NULL, NULL, "=a==", 4), false);
}

Test(base64_decode, invalid_size)
{
    cr_assert_eq(base64_decode(NULL, NULL, "aaaa", 1), false);
    cr_assert_eq(base64_decode(NULL, NULL, "aaaa", 2), false);
    cr_assert_eq(base64_decode(NULL, NULL, "aaaa", 3), false);
}

Test(base64_decode, invalid_chars)
{
    cr_assert_eq(base64_decode(NULL, NULL, "@aaa",  4), false);
    cr_assert_eq(base64_decode(NULL, NULL, "\naaa", 4), false);
    cr_assert_eq(base64_decode(NULL, NULL, "\\aaa", 4), false);
}