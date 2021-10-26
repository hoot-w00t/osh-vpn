#include "random.h"
#include "xalloc.h"
#include <criterion/criterion.h>
#include <stdlib.h>
#include <string.h>

Test(random_bytes, test_nonzero)
{
    uint8_t buf[1024];
    uint8_t zero[sizeof(buf)];

    memset(buf, 0, sizeof(buf));
    memset(zero, 0, sizeof(zero));
    cr_assert_eq(random_bytes(buf, sizeof(buf)), true);
    cr_assert_neq(memcmp(buf, zero, sizeof(buf)), 0);
}

Test(random_bytes, test_randomness)
{
    const size_t buf_size = 1024;
    const size_t buf_count = 64;
    uint8_t **buf = xalloc(sizeof(uint8_t *) * buf_count);

    for (size_t i = 0; i < buf_count; ++i) {
        buf[i] = xzalloc(buf_size);
        cr_assert_eq(random_bytes(buf[i], buf_size), true);
    }

    for (size_t i = 0; i < buf_count; ++i) {
        for (size_t j = 0; j < buf_count; ++j) {
            if (i == j)
                continue;

            cr_assert_neq(memcmp(buf[i], buf[j], buf_size), 0);
        }
    }

    for (size_t i = 0; i < buf_count; ++i)
        free(buf[i]);
    free(buf);
}
