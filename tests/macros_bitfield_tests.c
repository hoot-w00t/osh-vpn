#include "macros_bitfields.h"
#include <stdint.h>
#include <criterion/criterion.h>

Test(BIT_SET, test_bit_set_macro)
{
    uint32_t u   = 0;
    uint32_t ref = 0;

    for (int i = 0; i < 32; ++i) {
        BIT_SET(u, i);
        ref |= ((unsigned) 1 << i);
        cr_assert_eq(u, ref);
    }
    cr_assert_eq(u, 0xFFFFFFFFu);
    cr_assert_eq(ref, 0xFFFFFFFFu);
}

Test(BIT_CLEAR, test_bit_clear_macro)
{
    uint32_t u   = 0xFFFFFFFFu;
    uint32_t ref = 0xFFFFFFFFu;

    for (int i = 0; i < 32; ++i) {
        BIT_CLEAR(u, i);
        ref &= ~((unsigned) 1 << i);
        cr_assert_eq(u, ref);
    }
    cr_assert_eq(u, 0);
    cr_assert_eq(ref, 0);
}

Test(BIT_TEST, test_bit_test_macro)
{
    const uint32_t u = 0xF0F0F0F0;

    cr_assert_eq(BIT_TEST(u, 30), 0x40000000u);
    cr_assert_eq(BIT_TEST(u, 26), 0);
}

Test(BIT_GET, test_bit_get_macro)
{
    const uint32_t u = 0xF0F0F0F0;

    cr_assert_eq(BIT_GET(u, 22), 1u);
    cr_assert_eq(BIT_GET(u, 16), 0);
}
