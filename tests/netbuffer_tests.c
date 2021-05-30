#include "netbuffer.h"
#include <criterion/criterion.h>

static void netbuffer_test_full(netbuffer_t *nbuf, const size_t slot_count, const size_t size)
{
    uint8_t *slots[slot_count];
    uint8_t *slot = NULL;

    memset(slots, 0, sizeof(slots));

    // No slots are reserved, so we should get a NULL pointer
    cr_assert_null(netbuffer_next(nbuf));

    for (size_t i = 0; i < slot_count; ++i) {
        slots[i] = netbuffer_reserve(nbuf);

        // All the slots should return a pointer
        cr_assert_not_null(slots[i]);

        if (i == 0)
            slot = slots[i];

        for (size_t j = 0; j < size; ++j) {
            slots[i][j] = (i & 0xFF);
        }
    }

    // No more slots should be available, this should return NULL
    cr_assert_null(netbuffer_reserve(nbuf));

    for (size_t i = 0; i < slot_count; ++i) {
        for (size_t j = 0; j < slot_count; ++j) {
            if (j == i) continue;

            // We shouldn't have duplicate pointers
            cr_assert_neq(slots[i], slots[j]);
        }
    }

    for (size_t i = 0; i < slot_count; ++i, slot = netbuffer_next(nbuf)) {
        // All the slots should return a pointer
        cr_assert_not_null(slot);

        for (size_t j = 0; j < size; ++j) {
            // Test if we're getting the same values as before
            cr_assert_eq(slot[j], (i & 0xFF));
        }
    }

    // We should have processed every slot, this should return NULL
    size_t slot_count_mul = slot_count * 2;
    for (size_t i = 0; i < slot_count_mul; ++i)
        cr_assert_null(netbuffer_next(nbuf));
}

static void netbuffer_test_chain(netbuffer_t *nbuf, const size_t loop_amount, const size_t size)
{
    uint8_t *prev = NULL;
    uint8_t *slot = NULL;

    // No slots are reserved, so we should get a NULL pointer
    cr_assert_null(netbuffer_next(nbuf));

    for (size_t i = 0; i < loop_amount; ++i, prev = slot) {
        slot = netbuffer_reserve(nbuf);
        cr_assert_not_null(slot);
        cr_assert_null(netbuffer_next(nbuf));

        for (size_t j = 0; j < size; ++j) {
            slot[j] = (i & 0xFF);
        }
        if (prev) {
            for (size_t j = 0; j < size; ++j) {
                cr_assert_eq(prev[j], ((i - 1) & 0xFF));
            }
        }
    }
    if (prev) {
        for (size_t j = 0; j < size; ++j) {
            cr_assert_eq(prev[j], ((loop_amount - 1) & 0xFF));
        }
    }

    // We should have processed every slot, this should return NULL
    for (size_t i = 0; i < loop_amount; ++i)
        cr_assert_null(netbuffer_next(nbuf));
}

Test(netbuffer, test_very_big)
{
    const size_t slot_count = 4096, size = 4096;
    netbuffer_t *nbuf = netbuffer_alloc(slot_count, size);

    for (size_t i = 0; i < 32; ++i)
        netbuffer_test_full(nbuf, slot_count, size);
    netbuffer_test_chain(nbuf, slot_count * 2, size);
    netbuffer_test_chain(nbuf, slot_count - 1, size);
    netbuffer_test_full(nbuf, slot_count, size);
    netbuffer_free(nbuf);
}

Test(netbuffer, test_big)
{
    const size_t slot_count = 1024, size = 1024;
    netbuffer_t *nbuf = netbuffer_alloc(slot_count, size);

    for (size_t i = 0; i < 32; ++i)
        netbuffer_test_full(nbuf, slot_count, size);
    netbuffer_test_chain(nbuf, slot_count * 2, size);
    netbuffer_test_chain(nbuf, slot_count - 1, size);
    netbuffer_test_full(nbuf, slot_count, size);
    netbuffer_free(nbuf);
}

Test(netbuffer, test_small)
{
    const size_t slot_count = 32, size = 128;
    netbuffer_t *nbuf = netbuffer_alloc(slot_count, size);

    for (size_t i = 0; i < 32; ++i)
        netbuffer_test_full(nbuf, slot_count, size);
    netbuffer_test_chain(nbuf, slot_count * 2, size);
    netbuffer_test_chain(nbuf, slot_count - 1, size);
    netbuffer_test_full(nbuf, slot_count, size);
    netbuffer_free(nbuf);
}

Test(netbuffer, test_unaligned)
{
    const size_t slot_count = 7, size = 9;
    netbuffer_t *nbuf = netbuffer_alloc(slot_count, size);

    for (size_t i = 0; i < 32; ++i)
        netbuffer_test_full(nbuf, slot_count, size);
    netbuffer_test_chain(nbuf, slot_count * 2, size);
    netbuffer_test_chain(nbuf, slot_count - 1, size);
    netbuffer_test_full(nbuf, slot_count, size);
    netbuffer_free(nbuf);
}

Test(netbuffer, test_one_slot_one_byte)
{
    const size_t slot_count = 1, size = 1;
    netbuffer_t *nbuf = netbuffer_alloc(slot_count, size);

    for (size_t i = 0; i < 32; ++i)
        netbuffer_test_full(nbuf, slot_count, size);
    netbuffer_free(nbuf);
}

Test(netbuffer, error_cases)
{
    cr_assert_null(netbuffer_alloc(0, 1024));
    cr_assert_null(netbuffer_alloc(1, 0));
}

Test(netbuffer, range_test_slot_counts_and_sizes)
{
    const size_t max_slots = 64, max_size = 256;

    for (size_t slot_count = 1; slot_count <= max_slots; ++slot_count) {
        for (size_t size = 1; size <= max_size; ++size) {
            netbuffer_t *nbuf = netbuffer_alloc(slot_count, size);
            netbuffer_test_full(nbuf, slot_count, size);
            if (slot_count > 1 && size > 1) {
                netbuffer_test_chain(nbuf, slot_count * 2, size);
                netbuffer_test_chain(nbuf, slot_count - 1, size);
            }
            netbuffer_test_full(nbuf, slot_count, size);
            netbuffer_free(nbuf);
        }
    }
}