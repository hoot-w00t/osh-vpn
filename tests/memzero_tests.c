#include "memzero.h"
#include "xalloc.h"
#include <stdint.h>
#include <stdlib.h>
#include <criterion/criterion.h>

// Note: These tests verify that memzero() does zero memory, but they can't
//       verify that the compiler won't optimize them away

#define arr_len 64
static const uint8_t arr_zero[arr_len] = {0};
static const char hello_world[] = "Hello world";

static void assert_arr_zero(void)
{
    for (size_t i = 0; i < arr_len; ++i)
        cr_assert_eq(arr_zero[i], 0);
}

static void pseudorandom_buf(void *buf, size_t len)
{
    srand(0);
    for (size_t i = 0; i < len; ++i)
        ((uint8_t *) buf)[i] = rand() % 256;
}

static void assert_hello_world(void)
{
    cr_assert_str_not_empty(hello_world);
    cr_assert(arr_len >= sizeof(hello_world));
}

Test(memzero, memzero_stack)
{
    uint8_t arr[arr_len];

    assert_arr_zero();
    pseudorandom_buf(arr, arr_len);
    cr_assert_arr_neq(arr, arr_zero, arr_len);
    memzero(arr, arr_len);
    cr_assert_arr_eq(arr, arr_zero, arr_len);
}

Test(memzero, memzero_heap)
{
    uint8_t *arr = xalloc(arr_len);

    assert_arr_zero();
    pseudorandom_buf(arr, arr_len);
    cr_assert_arr_neq(arr, arr_zero, arr_len);
    memzero(arr, arr_len);
    cr_assert_arr_eq(arr, arr_zero, arr_len);
    free(arr);
}

Test(memzero, memzero_str_stack)
{
    char s[sizeof(hello_world)];

    assert_hello_world();
    strcpy(s, hello_world);
    cr_assert_str_eq(s, hello_world);
    memzero_str(s);
    cr_assert_arr_eq(s, arr_zero, sizeof(hello_world));
}

Test(memzero, memzero_str_heap)
{
    char *s = xalloc(sizeof(hello_world));

    assert_hello_world();
    strcpy(s, hello_world);
    cr_assert_str_eq(s, hello_world);
    memzero_str(s);
    cr_assert_arr_eq(s, arr_zero, sizeof(hello_world));
    free(s);
}
