#include "hashtable.h"
#include "xalloc.h"
#include "macros_assert.h"
#include <stdlib.h>
#include <string.h>

#define hashtable_min(x, y) (((x) < (y)) ? (x) : (y))
#define hashtable_max(x, y) (((x) < (y)) ? (y) : (x))

#define hashtable_minsize(size) (((size) < 1) ? 1 : (size))
#define hashtable_setfunc(dest, func) \
    dest = (func == NULL) ? hashtable_default_##func : func

// Return index of the key in the table (always within bounds)
static size_t hashtable_index(hashtable_t *ht, const void *key, size_t keylen)
{
    hashtable_hash_t hash;

    ht->hashfunc(hashtable_hashfunc_ctx(ht), key, keylen, &hash);
    return hash % ht->table_size;
}

// Return pointer to head item at the key index (can point to a NULL item)
static hashtable_item_t **hashtable_head(hashtable_t *ht, const void *key, size_t keylen)
{
    return &ht->table[hashtable_index(ht, key, keylen)];
}

// Compare item key using hash table key comparator
static bool hashtable_item_key_eq(const hashtable_t *ht,
    const hashtable_item_t *item, const void *key, size_t keylen)
{
    return ht->key_cmp_eq(item->key, item->keylen, key, keylen);
}

// Create item without value (same as hashtable_item_reset_value())
static hashtable_item_t *hashtable_item_create(const void *key, size_t keylen)
{
    hashtable_item_t *item = xzalloc(sizeof(*item));

    assert(key != NULL);
    assert(keylen != 0);
    item->key = xmemdup(key, keylen);
    item->keylen = keylen;
    return item;
}

// Remove item value
// Frees pointer (if needed), resets value to NULL of length 0 (not allocated)
static void hashtable_item_reset_value(hashtable_item_t *item)
{
    if (item->value_is_alloc)
        free(item->value);

    item->value = NULL;
    item->valuelen = 0;
    item->value_is_alloc = false;
}

// Set item value to a dynamically allocated copy of the passed pointer data
static void hashtable_item_set_value_copy(hashtable_item_t *item, const void *value, size_t valuelen)
{
    // Make sure the item value pointer can be passed to realloc() if it wasn't
    // already a dynamically allocated pointer
    if (!item->value_is_alloc)
        hashtable_item_reset_value(item);

    // Dynamically allocate item value pointer (if needed)
    item->value_is_alloc = true;
    if (item->valuelen != valuelen) {
        item->valuelen = valuelen;
        item->value = xrealloc(item->value, item->valuelen);
    }

    // Initialize value pointer data (to all zeros if there is no source value)
    if (item->value && item->valuelen > 0) {
        if (value)
            memcpy(item->value, value, item->valuelen);
        else
            memset(item->value, 0, item->valuelen);
    }
}

// Set item value pointer directly (without allocating/copying data it points to)
static void hashtable_item_set_value_ptr(hashtable_item_t *item, void *value)
{
    // Free the item value pointer if it was dynamically allocated before we
    // overwrite it
    if (item->value_is_alloc)
        hashtable_item_reset_value(item);

    // Store the pointer directly without copying its content
    item->value = value;
    item->valuelen = 0;
    item->value_is_alloc = false;
}

// Free item
static void hashtable_item_free(hashtable_item_t *item)
{
    if (item) {
        hashtable_item_reset_value(item);
        free(item->key);
        free(item);
    }
}

// Insert an existing item to the tail of its key index
static void hashtable_insert_item(hashtable_t *ht, hashtable_item_t *item)
{
    hashtable_item_t **it = hashtable_head(ht, item->key, item->keylen);

    while (*it)
        it = &(*it)->next;

    item->next = NULL;
    *it = item;
    ht->item_count += 1;
}

// Allocate a new table of new_table_size
// Inserts previous items to the new table
// This can be used to change the hash table size or re-generate it after a
// breaking change (like the hash function)
static void hashtable_reallocate(hashtable_t *ht, size_t new_table_size)
{
    hashtable_item_t **old_table;
    size_t old_table_size;

    old_table = ht->table;
    old_table_size = ht->table_size;
    ht->table_size = hashtable_minsize(new_table_size);
    ht->table = xzalloc(sizeof(hashtable_item_t *) * ht->table_size);
    ht->item_count = 0;

    for (size_t i = 0; i < old_table_size; ++i) {
        hashtable_item_t *item = old_table[i];
        hashtable_item_t *next;

        while (item) {
            next = item->next;
            hashtable_insert_item(ht, item);
            item = next;
        }
    }

    free(old_table);
}

// Free the current hash function, reset pointers and context
static void _hashtable_free_hashfunc(hashtable_t *ht)
{
    hashtable_userctx_t *ctx = hashtable_hashfunc_ctx(ht);

    if (ht->hashfunc_free)
        ht->hashfunc_free(ctx);
    ht->hashfunc_free = NULL;
    ht->hashfunc = NULL;
    memset(ctx, 0, sizeof(*ctx));
}

// Free current hash function and setup a new one
// If this returns false, there is no hash function set up and this function
// must be called again to set up another hash function (otherwise hash table
// lookups will crash)
static bool _hashtable_setup_hashfunc(
    hashtable_t *ht,
    hashtable_hashfunc_init_t hashfunc_init,
    hashtable_hashfunc_free_t hashfunc_free,
    hashtable_hashfunc_t hashfunc,
    void *data)
{
    _hashtable_free_hashfunc(ht);

    // There must be a hash function
    if (hashfunc == NULL)
        return false;

    ht->hashfunc_free = hashfunc_free;
    ht->hashfunc = hashfunc;

    if (hashfunc_init) {
        if (!hashfunc_init(hashtable_hashfunc_ctx(ht), data)) {
            _hashtable_free_hashfunc(ht);
            return false;
        }
    }

    // Update table indices (only needed if there are items in the table)
    if (ht->item_count != 0)
        hashtable_reallocate(ht, ht->table_size);

    return true;
}

// Default empty hash function
static void _hashfunc_default(
    __attribute__((unused)) hashtable_userctx_t *ctx,
    __attribute__((unused)) const void *in,
    __attribute__((unused)) size_t inlen,
    hashtable_hash_t *out)
{
    *out = 0;
}

// Setup default hash function
// This function must never fail and calls abort() if it does
static void _hashtable_setup_default_hashfunc(hashtable_t *ht)
{
    assert(_hashtable_setup_hashfunc(ht, NULL, NULL, _hashfunc_default, NULL) == true);
}

hashtable_t *hashtable_create(size_t table_size, hashtable_key_cmp_eq_t key_cmp_eq)
{
    hashtable_t *ht = xzalloc(sizeof(*ht));

    hashtable_setfunc(ht->key_cmp_eq, key_cmp_eq);
    ht->table_size = hashtable_minsize(table_size);
    ht->table = xzalloc(sizeof(hashtable_item_t *) * ht->table_size);
    _hashtable_setup_default_hashfunc(ht);
    hashtable_disable_remove_cb(ht);
    return ht;
}

hashtable_t *hashtable_create_autoresize(size_t max_depth,
    size_t min_size, size_t max_size, hashtable_key_cmp_eq_t key_cmp_eq)
{
    hashtable_t *ht = hashtable_create(min_size, key_cmp_eq);

    hashtable_autoresize(ht, max_depth, min_size, max_size);
    return ht;
}

void hashtable_free(hashtable_t *ht)
{
    if (ht) {
        hashtable_disable_remove_cb(ht);
        hashtable_clear(ht);
        _hashtable_free_hashfunc(ht);
        free(ht->table);
        free(ht);
    }
}

bool hashtable_set_hashfunc(
    hashtable_t *ht,
    hashtable_hashfunc_init_t hashfunc_init,
    hashtable_hashfunc_free_t hashfunc_free,
    hashtable_hashfunc_t hashfunc,
    void *data)
{
    if (_hashtable_setup_hashfunc(ht, hashfunc_init, hashfunc_free, hashfunc, data))
        return true;

    _hashtable_setup_default_hashfunc(ht);
    return false;
}

void hashtable_remove_hashfunc(hashtable_t *ht)
{
    _hashtable_setup_default_hashfunc(ht);
}

void hashtable_resize(hashtable_t *ht, size_t new_table_size)
{
    new_table_size = hashtable_minsize(new_table_size);

    // Don't do anything if the size stays the same
    if (ht->table_size != new_table_size)
        hashtable_reallocate(ht, new_table_size);
}

// Expand hash table if enabled and necessary
static void _hashtable_autoexpand(hashtable_t *ht, size_t depth)
{
    if (ht->auto_expand && depth >= ht->expand_max_depth) {
        const size_t new_size = ht->table_size * 2;

        hashtable_resize(ht, hashtable_min(new_size, ht->expand_max_size));
    }
}

// Shrink hash table if enabled and necessary
static void _hashtable_autoshrink(hashtable_t *ht)
{
    if (ht->auto_shrink && ((ht->item_count / ht->shrink_max_depth) * 2) < ht->table_size) {
        const size_t new_size = ht->table_size / 2;

        hashtable_resize(ht, hashtable_max(new_size, ht->shrink_min_size));
    }
}

// Resize hash table to stay between shrink_min_size and expand_max_size
// (if enabled)
static void _hashtable_resize_limits(hashtable_t *ht)
{
    const size_t min_size = ht->auto_shrink ? ht->shrink_min_size : 0;
    const size_t max_size = ht->auto_expand ? ht->expand_max_size : SIZE_MAX;

    if (min_size > max_size)
        return;
    else if (ht->table_size < min_size)
        hashtable_resize(ht, min_size);
    else if (ht->table_size > max_size)
        hashtable_resize(ht, max_size);
}

void hashtable_autoexpand(hashtable_t *ht, size_t max_depth, size_t max_size)
{
    ht->expand_max_depth = max_depth;
    ht->expand_max_size = (max_size == 0) ? SIZE_MAX : max_size;
    ht->auto_expand = ht->expand_max_depth == 0 ? false : true;
    _hashtable_resize_limits(ht);
}

void hashtable_autoshrink(hashtable_t *ht, size_t max_depth, size_t min_size)
{
    ht->shrink_max_depth = max_depth;
    ht->shrink_min_size = min_size;
    ht->auto_shrink = ht->shrink_max_depth == 0 ? false : true;
    _hashtable_resize_limits(ht);
}

void hashtable_autoresize(hashtable_t *ht, size_t max_depth,
    size_t min_size, size_t max_size)
{
    hashtable_autoexpand(ht, max_depth, max_size);
    hashtable_autoshrink(ht, max_depth, min_size);
}

void hashtable_set_remove_cb(hashtable_t *ht, hashtable_remove_cb_t remove_cb,
    void *remove_cb_data)
{
    ht->remove_cb = remove_cb;
    ht->remove_cb_data = remove_cb_data;
}

// Lookup item by key and return the iterator
// This function always returns a valid iterator but the item it points to will
// be NULL if the key wasn't found
// If *depth is not NULL write the depth of the linked list to the item
static hashtable_item_t **hashtable_lookup_iter(hashtable_t *ht,
    const void *key, size_t keylen, size_t *depth)
{
    hashtable_item_t **it = hashtable_head(ht, key, keylen);
    size_t it_depth = 0;

    while (*it) {
        if (hashtable_item_key_eq(ht, *it, key, keylen))
            break;
        it = &(*it)->next;
        it_depth += 1;
    }

    if (depth)
        *depth = it_depth;
    return it;
}

hashtable_item_t *hashtable_lookup(hashtable_t *ht, const void *key, size_t keylen)
{
    return *hashtable_lookup_iter(ht, key, keylen, NULL);
}

// Insert item with key to the hash table and return it
static hashtable_item_t *_hashtable_insert(hashtable_t *ht, const void *key, size_t keylen)
{
    hashtable_item_t **it;
    hashtable_item_t *item;
    size_t depth;

    it = hashtable_lookup_iter(ht, key, keylen, &depth);
    if (*it == NULL) {
        *it = hashtable_item_create(key, keylen);
        ht->item_count += 1;
    }
    item = *it;
    _hashtable_autoexpand(ht, depth);

    // We cannot access **it since _hashtable_autoexpand() and hashtable_resize()
    // can free it, but the item pointer is kept intact
    return item;
}

hashtable_item_t *hashtable_insert(hashtable_t *ht, const void *key, size_t keylen,
    const void *value, size_t valuelen)
{
    hashtable_item_t *item = _hashtable_insert(ht, key, keylen);

    hashtable_item_set_value_copy(item, value, valuelen);
    return item;
}

hashtable_item_t *hashtable_insert_ptr(hashtable_t *ht, const void *key, size_t keylen, void *ptr)
{
    hashtable_item_t *item = _hashtable_insert(ht, key, keylen);

    hashtable_item_set_value_ptr(item, ptr);
    return item;
}

// Remove item pointed to by *it and replace *it with the next item in the
// linked list
static void _hashtable_remove(hashtable_t *ht, hashtable_item_t **it)
{
    hashtable_item_t *item;

    assert(it != NULL);
    assert(*it != NULL);
    item = *it;
    *it = (*it)->next;
    ht->item_count -= 1;
    if (ht->remove_cb)
        ht->remove_cb(item, ht->remove_cb_data);
    hashtable_item_free(item);
}

bool hashtable_remove_key(hashtable_t *ht, const void *key, size_t keylen)
{
    hashtable_item_t **it = hashtable_lookup_iter(ht, key, keylen, NULL);

    if (*it) {
        _hashtable_remove(ht, it);
        _hashtable_autoshrink(ht);
        return true;
    }
    return false;
}

size_t hashtable_remove_value_ctx(hashtable_t *ht,
    hashtable_value_ctx_cmp_eq_t value_cmp_eq, void *ctx)
{
    size_t removed_count = ht->item_count;
    hashtable_item_t **it;

    // Comparator is required because we don't know what the context data is
    if (value_cmp_eq == NULL)
        return 0;

    for (size_t i = 0; i < ht->table_size; ++i) {
        it = &ht->table[i];

        while (*it) {
            if (value_cmp_eq((*it)->value, (*it)->valuelen, ctx))
                _hashtable_remove(ht, it);
            else
                it = &(*it)->next;
        }
    }

    removed_count -= ht->item_count;
    if (removed_count != 0)
        _hashtable_autoshrink(ht);

    return removed_count;
}

struct _ht_remove_value_ctx {
    hashtable_value_cmp_eq_t cmp_eq;
    const void *s2;
    size_t s2_len;
};

static bool _ht_remove_value_ctx_cmp_eq(const void *s1, size_t s1_len, void *vctx)
{
    struct _ht_remove_value_ctx *ctx = (struct _ht_remove_value_ctx *) vctx;

    return ctx->cmp_eq(s1, s1_len, ctx->s2, ctx->s2_len);
}

size_t hashtable_remove_value(hashtable_t *ht, const void *value, size_t valuelen,
    hashtable_value_cmp_eq_t value_cmp_eq)
{
    struct _ht_remove_value_ctx ctx;

    hashtable_setfunc(ctx.cmp_eq, value_cmp_eq);
    ctx.s2 = value;
    ctx.s2_len = valuelen;
    return hashtable_remove_value_ctx(ht, _ht_remove_value_ctx_cmp_eq, &ctx);
}

void hashtable_clear(hashtable_t *ht)
{
    for (size_t i = 0; i < ht->table_size; ++i) {
        hashtable_item_t **it = &ht->table[i];

        while (*it)
            _hashtable_remove(ht, it);
    }
    _hashtable_autoshrink(ht);
}

// Compare pointers data
// Pointers are assumed to be non-NULL
static inline bool ptr_data_eq(const void *s1, const size_t s1_len,
    const void *s2, const size_t s2_len)
{
    return (s1_len == s2_len) && !memcmp(s1, s2, s1_len);
}

// If any pointer is NULL or its length is 0 this compares pointer values,
// otherwise it compares pointers data
static inline bool ptr_eq(const void *s1, const size_t s1_len,
    const void *s2, size_t s2_len)
{
    return (s1 == NULL || s2 == NULL || s1_len == 0 || s2_len == 0)
         ? s1 == s2
         : ptr_data_eq(s1, s1_len, s2, s2_len);
}

bool hashtable_default_key_cmp_eq(const void *s1, size_t s1_len,
    const void *s2, size_t s2_len)
{
    return ptr_data_eq(s1, s1_len, s2, s2_len);
}

bool hashtable_default_value_cmp_eq(const void *s1, size_t s1_len,
    const void *s2, size_t s2_len)
{
    return ptr_eq(s1, s1_len, s2, s2_len);
}
