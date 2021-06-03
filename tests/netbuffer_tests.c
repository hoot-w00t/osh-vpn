#include "netbuffer.h"
#include "xalloc.h"
#include <string.h>
#include <criterion/criterion.h>

static void netbuffer_test(size_t min_size, size_t alignment, size_t test_size,
    size_t push_size)
{
    netbuffer_t *nbuf = netbuffer_create(min_size, alignment);
    uint8_t *push = xalloc(push_size);

    cr_assert_not_null(nbuf);
    cr_assert_not_null(push);
    for (size_t i = 0; i < push_size; ++i)
        push[i] = i & 0xFF;

    size_t actual_size = 0;
    for (; actual_size <= test_size; actual_size += push_size)
        netbuffer_push(nbuf, push, push_size);

    cr_assert_eq(netbuffer_data_size(nbuf), actual_size);
    if (actual_size > nbuf->min_size) {
        cr_assert(nbuf->current_size > nbuf->min_size);
    } else {
        cr_assert(nbuf->current_size == nbuf->min_size);
    }

    for (size_t i = 0; i < actual_size; i += push_size) {
        uint8_t *data = netbuffer_data(nbuf);
        size_t data_size = netbuffer_data_size(nbuf);

        cr_assert_not_null(data);
        cr_assert_eq(data_size, actual_size - i);
        cr_assert(data_size >= push_size);
        cr_assert(!memcmp(data, push, push_size));

        size_t new_size;
        if (push_size > data_size) {
            new_size = 0;
        } else {
            new_size = data_size - push_size;
        }
        cr_assert_eq(netbuffer_pop(nbuf, 0), data_size);
        cr_assert_eq(netbuffer_pop(nbuf, push_size), new_size);
    }
    free(push);

    cr_assert_eq(netbuffer_data_size(nbuf), 0);
    cr_assert_eq(netbuffer_pop(nbuf, push_size), 0);
    cr_assert_eq(nbuf->current_size, nbuf->min_size);
    cr_assert_eq(nbuf->alignment, alignment);
    netbuffer_free(nbuf);
}

Test(netbuffer, test_small)
{
    netbuffer_test(1024, 1024, 8192, 256);
}

Test(netbuffer, test_medium)
{
    netbuffer_test(4096, 4096, 16384, 512);
}

Test(netbuffer, test_big)
{
    netbuffer_test(8192, 16384, 65565, 1024);
}

Test(netbuffer, test_small_pushes)
{
    netbuffer_test(512, 256, 1024, 1);
}

Test(netbuffer, test_one_push)
{
    netbuffer_test(1024, 1024, 1024, 1024);
}

Test(netbuffer, test_small_size_and_alignment_push_1)
{
    netbuffer_test(1, 1, 1024, 1);
}

Test(netbuffer, test_small_size_and_alignment_push_quarter)
{
    netbuffer_test(1, 1, 1024, 256);
}

Test(netbuffer, test_small_size_and_alignment_push_max)
{
    netbuffer_test(1, 1, 1024, 1024);
}

Test(netbuffer, test_range)
{
    const size_t range_min = 1;
    const size_t range_max = 4096;
    const size_t test_size_max = 16384;

    for (size_t min_size = range_min; min_size <= range_max; min_size *= 2)
    for (size_t alignment = range_min; alignment <= range_max; alignment *= 2)
    for (size_t test_size = range_min; test_size <= test_size_max; test_size *= 2)
    for (size_t push_size = range_min; push_size <= range_max; push_size *= 2)
        netbuffer_test(min_size, alignment, test_size, push_size);
}

Test(netbuffer, test_cancel)
{
    netbuffer_t *nbuf = netbuffer_create(32, 64);
    uint8_t push[256];

    cr_assert((sizeof(push) % 2) == 0);
    cr_assert_not_null(nbuf);

    for (size_t i = 0; i < sizeof(push); ++i)
        push[i] = i & 0xFF;

    netbuffer_push(nbuf, push, sizeof(push));
    cr_assert_eq(netbuffer_data_size(nbuf), sizeof(push));
    netbuffer_cancel(nbuf, sizeof(push) / 2);
    cr_assert_eq(netbuffer_data_size(nbuf), sizeof(push) / 2);
    memset(push + (sizeof(push) / 2), 0, sizeof(push) / 2);
    cr_assert(!memcmp(netbuffer_data(nbuf), push, netbuffer_data_size(nbuf)));
    netbuffer_cancel(nbuf, sizeof(push) / 2);
    cr_assert_eq(netbuffer_data_size(nbuf), 0);
    cr_assert_eq(nbuf->current_size, nbuf->min_size);
    netbuffer_free(nbuf);
}

Test(netbuffer, test_clear)
{
    netbuffer_t *nbuf = netbuffer_create(32, 64);
    uint8_t push[256];

    cr_assert_not_null(nbuf);
    netbuffer_push(nbuf, push, sizeof(push));
    cr_assert_eq(netbuffer_data_size(nbuf), sizeof(push));
    netbuffer_clear(nbuf);
    cr_assert_eq(netbuffer_data_size(nbuf), 0);
    cr_assert_eq(nbuf->current_size, nbuf->min_size);
    netbuffer_free(nbuf);
}

Test(netbuffer, test_error_cases)
{
    cr_assert_null(netbuffer_create(0, 1));
    cr_assert_null(netbuffer_create(1, 0));
    cr_assert_null(netbuffer_create(0, 0));
}