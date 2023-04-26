#include "hashtable.h"
#include <criterion/criterion.h>

static void assert_item(hashtable_item_t *item, size_t i)
{
    cr_assert_not_null(item);
    cr_assert_eq(item->keylen, sizeof(i));
    cr_assert_eq(*((size_t *) item->key), i);
    cr_assert_eq(item->valuelen, sizeof(i));
    cr_assert_eq(item->value_is_alloc, true);
    cr_assert_eq(*((size_t *) item->value), i);
}

static void remove_cb_assert(hashtable_item_t *item, void *data)
{
    assert_item(item, *((size_t *) data));
}

static bool value_cmp_eq(const void *s1, size_t s1_len, void *vctx)
{
    const size_t *value = (const size_t *) s1;
    size_t *ctx = (size_t *) vctx;

    cr_assert_eq(s1_len, sizeof(*value));
    *ctx = *value;
    return (*value % 2) == 0;
}

static void test_hashtable(hashtable_t *ht)
{
    const size_t n = 1024;
    size_t i;

    hashtable_set_remove_cb(ht, remove_cb_assert, &i);
    for (i = 0; i < n; ++i) {
        assert_item(hashtable_insert(ht, &i, sizeof(i), &i, sizeof(i)), i);
    }
    cr_assert_eq(ht->item_count, n);
    for (i = 0; i < n; ++i) {
        assert_item(hashtable_lookup(ht, &i, sizeof(i)), i);
    }
    cr_assert_eq(ht->item_count, n);

    i = 0;
    cr_assert_eq(hashtable_remove_key(ht, &i, sizeof(i)), true);
    i = n - 1;
    cr_assert_eq(hashtable_remove_key(ht, &i, sizeof(i)), true);
    cr_assert_eq(ht->item_count, n - 2);

    cr_assert_eq(hashtable_remove_value_ctx(ht, value_cmp_eq, &i), (n / 2) - 1);
    cr_assert_eq(ht->item_count, (n / 2) - 1);
}

Test(hashtable, test_hashtable_insertion)
{
    hashtable_t *ht = hashtable_create(0, NULL);

    hashtable_autoresize(ht, 8, 4, 256);
    test_hashtable(ht);
    hashtable_use_murmur3_32(ht, 0);
    test_hashtable(ht);
    hashtable_free(ht);
}
