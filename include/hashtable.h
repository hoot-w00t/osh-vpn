#ifndef _OSH_HASHTABLE_H
#define _OSH_HASHTABLE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef uint64_t                    hashtable_hash_t;

#ifdef UINT64_MAX
    #define HASHTABLE_HASH_MAX      UINT64_MAX
#endif

#ifdef UINT64_C
    #define HASHTABLE_HASH_C        UINT64_C
#endif

// Added in C23
#ifdef UINT64_WIDTH
    #define HASHTABLE_HASH_WIDTH    UINT64_WIDTH
#endif

typedef union hashtable_userctx hashtable_userctx_t;
typedef struct hashtable_item hashtable_item_t;
typedef struct hashtable hashtable_t;

typedef bool (*hashtable_hashfunc_init_t)(hashtable_userctx_t *ctx, void *data);
typedef void (*hashtable_hashfunc_free_t)(hashtable_userctx_t *ctx);
typedef void (*hashtable_hashfunc_t)(hashtable_userctx_t *ctx, const void *in, size_t inlen, hashtable_hash_t *out);
typedef bool (*hashtable_key_cmp_eq_t)(const void *s1, size_t s1_len, const void *s2, size_t s2_len);
typedef bool (*hashtable_value_ctx_cmp_eq_t)(const void *s1, size_t s1_len, void *ctx);
typedef bool (*hashtable_value_cmp_eq_t)(const void *s1, size_t s1_len, const void *s2, size_t s2_len);
typedef void (*hashtable_remove_cb_t)(hashtable_item_t *item, void *data);

union hashtable_userctx {
    uint32_t u32;
    uint64_t u64;
    void *ptr;
};

struct hashtable_item {
    void *key;
    size_t keylen;

    void *value;
    size_t valuelen;
    bool value_is_alloc;

    hashtable_item_t *next;
};

struct hashtable {
    hashtable_item_t **table;
    size_t table_size;
    size_t item_count;

    bool auto_expand;
    size_t expand_max_depth;
    size_t expand_max_size;

    bool auto_shrink;
    size_t shrink_max_depth;
    size_t shrink_min_size;

    hashtable_hashfunc_free_t hashfunc_free;
    hashtable_hashfunc_t hashfunc;
    hashtable_userctx_t hashfunc_ctx;

    hashtable_key_cmp_eq_t key_cmp_eq;

    hashtable_remove_cb_t remove_cb;
    void *remove_cb_data;
};

// Pointer the the hash function context data
#define hashtable_hashfunc_ctx(ht) (&(ht)->hashfunc_ctx)

// Create a hash table
// If key_cmp_eq is NULL the default key comparator will be used
// By default there is no hash function, it must be initialized after creating
//   the hash table using hashtable_set_hashfunc() or hashtable_use_*() wrappers
hashtable_t *hashtable_create(size_t table_size, hashtable_key_cmp_eq_t key_cmp_eq);

// Wrapper for hashtable_create() that enables automatic resizing using
// hashtable_autoresize()
hashtable_t *hashtable_create_autoresize(size_t max_depth,
    size_t min_size, size_t max_size, hashtable_key_cmp_eq_t key_cmp_eq);

// Free hash table
void hashtable_free(hashtable_t *ht);

// Change the hash function used
// If hashfunc_init is not NULL it is called to initialize the hashfunc context
// If hashfunc_free is not NULL it is called before removing the hashfunc or
//   after hashfunc_init() returns false
// hashfunc is the function that generates hashes from keys, it cannot be NULL
// *data is passed to hashfunc_init()
//
// Returns true if the hash function was set up successfully, otherwise returns
// false and the default hash function is set up instead
bool hashtable_set_hashfunc(
    hashtable_t *ht,
    hashtable_hashfunc_init_t hashfunc_init,
    hashtable_hashfunc_free_t hashfunc_free,
    hashtable_hashfunc_t hashfunc,
    void *data);

// Remove the current hash function and set up the default one
void hashtable_remove_hashfunc(hashtable_t *ht);

// Re-size the hash table
void hashtable_resize(hashtable_t *ht, size_t new_table_size);

// Automatically expand the hash table size after inserting an item if max_depth
//   or more items are at the same index (limited to max_size)
//
// If max_depth is 0 automatic expansion is disabled (the hash table retains its
//   current size)
// If max_size is 0 the hash table size has no upper limit
// max_size shouldn't exceed the maximum value that can be returned by the hash
//   function, as indices beyond that value will never be used
// Note: This is a best-effort and it heavily depends on the efficiency of the
//       hash function to spread items evenly, item depths may still exceed the
//       max_depth value
void hashtable_autoexpand(hashtable_t *ht, size_t max_depth, size_t max_size);
#define hashtable_autoexpand_disable(ht) hashtable_autoexpand(ht, 0, 0)

// Automatically shrink the hash table size after removing an item if more than
//   50% of the allocated space is unused
//
// If max_depth is 0 automatic shrinking is disabled
// The hash table size will not be shrunk below min_size (can be set to 0)
void hashtable_autoshrink(hashtable_t *ht, size_t max_depth, size_t min_size);
#define hashtable_autoshrink_disable(ht) hashtable_autoshrink(ht, 0, 0)

// Call both automatic expand/shrink functions
void hashtable_autoresize(hashtable_t *ht, size_t max_depth,
    size_t min_size, size_t max_size);
#define hashtable_autoresize_disable(ht) hashtable_autoresize(ht, 0, 0, 0)

// Set remove callback function and data pointer passed to it
// It will be called every time an item is removed from the hash table (right
//   before freeing it)
// The function pointer can be set to NULL to disable it
// Note: The callback function must not modify the hash table as it could make
//       the caller function crash (by messing up pointers/iterators)
void hashtable_set_remove_cb(hashtable_t *ht, hashtable_remove_cb_t remove_cb,
    void *remove_cb_data);
#define hashtable_disable_remove_cb(ht) hashtable_set_remove_cb(ht, NULL, NULL)

// Lookup an item in the hash table
// Returns NULL if the item is not found
hashtable_item_t *hashtable_lookup(hashtable_t *ht, const void *key, size_t keylen);

// Insert an item in the hash table
// If the item already exists it overwrites the previous value (no duplicate keys)
//
// keylen bytes are copied from *key to a dynamically allocated buffer (freed automatically)
//   *key must not be NULL and keylen must not be 0
//
// hashtable_insert() dynamically allocates the item value buffer and copies valuelen bytes from value to it (if it is not NULL and valuelen is not 0)
//   (the item value pointer is freed automatically)
// hashtable_insert_ptr() sets the item value pointer to ptr without copying its data, the value length is set to 0
//   (the pointer is never freed)
hashtable_item_t *hashtable_insert(hashtable_t *ht, const void *key, size_t keylen,
    const void *value, size_t valuelen);
hashtable_item_t *hashtable_insert_ptr(hashtable_t *ht, const void *key, size_t keylen, void *ptr);

// Remove item with matching key from the hash table
// Returns false if the item was not found
bool hashtable_remove_key(hashtable_t *ht, const void *key, size_t keylen);

// Compare all items' values with value_cmp_eq and remove all those that match
//
// value_cmp_eq must be a valid function pointer, if NULL nothing is done
//   (*ctx is passed to it as argument)
//
// Returns the number of items that were removed
size_t hashtable_remove_value_ctx(hashtable_t *ht,
    hashtable_value_ctx_cmp_eq_t value_cmp_eq, void *ctx);

// Wrapper for hashtable_remove_value_ctx() that compares all items' values with
//   value/valuelen using value_cmp_eq
// If value_cmp_eq is NULL the default comparator is used
size_t hashtable_remove_value(hashtable_t *ht, const void *value, size_t valuelen,
    hashtable_value_cmp_eq_t value_cmp_eq);

// Remove all items from the hash table
void hashtable_clear(hashtable_t *ht);

// Default key comparator function (compare pointers data)
bool hashtable_default_key_cmp_eq(const void *s1, size_t s1_len,
    const void *s2, size_t s2_len);

// Default value comparator function (compare pointers or data they point to)
bool hashtable_default_value_cmp_eq(const void *s1, size_t s1_len,
    const void *s2, size_t s2_len);

// Iterate over all items in the hash table
#define hashtable_foreach(item, ht, iter)                                                       \
    for (size_t iter = 0; iter < ht->table_size; iter += 1)                                     \
        for (hashtable_item_t *item = ht->table[iter]; item != NULL; item = item->next)
#define hashtable_foreach_const(item, ht, iter)                                                 \
    for (size_t iter = 0; iter < ht->table_size; iter += 1)                                     \
        for (const hashtable_item_t *item = ht->table[iter]; item != NULL; item = item->next)

// Wrappers to set hash functions to use
bool hashtable_use_murmur3_32(hashtable_t *ht, uint32_t seed);

#endif
