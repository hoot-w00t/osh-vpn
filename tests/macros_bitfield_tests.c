#include "macros_bitfields.h"
#include <stdint.h>
#include <criterion/criterion.h>

typedef uint64_t                    test_type_t;
#define test_type_width             64
#define test_type_c                 UINT64_C
#define test_type_max               UINT64_MAX
#define test_type_f0                test_type_c(0xF0F0F0F0F0F0F0F0)

Test(BIT_SET, test_bit_set_macro)
{
    test_type_t u   = 0;
    test_type_t ref = 0;

    for (int i = 0; i < test_type_width; ++i) {
        BIT_SET(u, i);
        ref |= (test_type_c(1) << i);
        cr_assert_eq(u, ref);
    }
    cr_assert_eq(u, test_type_max);
    cr_assert_eq(ref, test_type_max);
}

Test(BIT_CLEAR, test_bit_clear_macro)
{
    test_type_t u   = test_type_max;
    test_type_t ref = test_type_max;

    for (int i = 0; i < test_type_width; ++i) {
        BIT_CLEAR(u, i);
        ref &= ~(test_type_c(1) << i);
        cr_assert_eq(u, ref);
    }
    cr_assert_eq(u, 0);
    cr_assert_eq(ref, 0);
}

Test(BIT_TEST, test_bit_test_macro)
{
    const test_type_t u = test_type_f0;

    for (int bit = 0; bit < test_type_width; ++bit) {
        test_type_t value;

        if ((bit % 8) < 4)
            value = 0;
        else
            value = test_type_c(1) << bit;

        cr_assert_eq(BIT_TEST(u, bit), value);
    }
}

Test(BIT_GET, test_bit_get_macro)
{
    const test_type_t u = test_type_f0;

    for (int bit = 0; bit < test_type_width; ++bit) {
        test_type_t value;

        if ((bit % 8) < 4)
            value = 0;
        else
            value = 1;

        cr_assert_eq(BIT_GET(u, bit), value);
    }
}
