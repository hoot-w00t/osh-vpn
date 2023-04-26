#include "hashtable.h"
#include "murmurhash.h"
#include "logger.h"

#ifdef HASHTABLE_HASH_WIDTH
    #if HASHTABLE_HASH_WIDTH < 32
        #warning "Murmur3_32 hash will be truncated"
    #endif
#endif

static bool _init(hashtable_userctx_t *ctx, void *data)
{
    ctx->u32 = *((uint32_t *) data);
    return true;
}

static void _hashfunc(hashtable_userctx_t *ctx, const void *in, size_t inlen, hashtable_hash_t *out)
{
    *out = murmur3_32(in, inlen, ctx->u32);
}

bool hashtable_use_murmur3_32(hashtable_t *ht, uint32_t seed)
{
    bool success = hashtable_set_hashfunc(ht, _init, NULL, _hashfunc, &seed);

    if (!success)
        logger(LOG_CRIT, "%s: %s", __FILE__, "Failed to set up Murmur3_32 hash function");
    return success;
}
