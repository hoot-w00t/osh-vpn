#include "hashtable.h"
#include "netaddr.h"
#include "murmurhash.h"
#include "macros_assert.h"
#include "logger.h"

#ifdef HASHTABLE_HASH_WIDTH
    #if HASHTABLE_HASH_WIDTH < 32
        #warning "Netaddr hash will be truncated"
    #endif
#endif

static bool _init(hashtable_userctx_t *ctx, void *data)
{
    ctx->u32 = *((uint32_t *) data);
    return true;
}

static void _hashfunc(hashtable_userctx_t *ctx, const void *in, size_t inlen, hashtable_hash_t *out)
{
    const netaddr_t *addr = (const netaddr_t *) in;

    assert(inlen == sizeof(*addr));
    switch (addr->type) {
    case MAC: *out = murmur3_32(&addr->data.mac, sizeof(addr->data.mac), ctx->u32); break;
    case IP4: *out = murmur3_32(&addr->data.ip4, sizeof(addr->data.ip4), ctx->u32); break;
    case IP6: *out = murmur3_32(&addr->data.ip6, sizeof(addr->data.ip6), ctx->u32); break;
    default:  *out = 0;
    }
}

bool hashtable_use_netaddr(hashtable_t *ht, uint32_t seed)
{
    bool success = hashtable_set_hashfunc(ht, _init, NULL, _hashfunc, &seed);

    if (!success)
        logger(LOG_CRIT, "%s: %s", __FILE__, "Failed to set up netaddr hash function");
    return success;
}

static bool _netaddr_key_cmp_eq(const void *s1, size_t s1_len,
    const void *s2, size_t s2_len)
{
    assert(s1_len == sizeof(netaddr_t) && s2_len == sizeof(netaddr_t));

    return netaddr_eq((const netaddr_t *) s1, (const netaddr_t *) s2);
}

hashtable_t *hashtable_create_netaddr(size_t table_size, uint32_t hash_seed)
{
    hashtable_t *ht = hashtable_create(table_size, _netaddr_key_cmp_eq);

    hashtable_use_netaddr(ht, hash_seed);
    return ht;
}

hashtable_t *hashtable_create_netaddr_autoresize(size_t max_depth,
    size_t min_size, size_t max_size, uint32_t hash_seed)
{
    hashtable_t *ht = hashtable_create_autoresize(max_depth, min_size, max_size,
        _netaddr_key_cmp_eq);

    hashtable_use_netaddr(ht, hash_seed);
    return ht;
}
