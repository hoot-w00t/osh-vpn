#include "netutil.h"

struct icmp_checksum_ctx {
    uint32_t checksum;
};

// Initialize context for a new ICMP checksum
static void icmp_checksum_begin(struct icmp_checksum_ctx *ctx)
{
    ctx->checksum = 0;
}

// Checksum data_len bytes of data
// FIXME: This function does not handle odd intermediate data, an odd data
//        length must be the last data to compute before finalizing
//        Here we only use this for ICMP6 with the pseudo header, which has an
//        even size so it will work fine
static void icmp_checksum_bytes(struct icmp_checksum_ctx *ctx, const void *data,
    size_t data_len)
{
    const uint8_t *dataptr = (const uint8_t *) data;
    size_t i = 0;

    // Sum all bytes grouped by 2
    for (; (i + 1) < data_len; i += 2)
        ctx->checksum += *((const uint16_t *) (dataptr + i));

    // Add the last byte if length is odd
    if (i < data_len)
        ctx->checksum += (uint16_t) dataptr[i];
}

// Finalize checksum and return the result
static uint16_t icmp_checksum_finish(struct icmp_checksum_ctx *ctx)
{
    // Carry
    while ((ctx->checksum & 0xFFFF0000) != 0)
        ctx->checksum = (ctx->checksum & 0xFFFF) + (ctx->checksum >> 16);

    return ~((uint16_t) ctx->checksum);
}

// Compute ICMP4 checksum
// RFC 1071 (https://www.rfc-editor.org/rfc/rfc1071)
uint16_t icmp4_checksum(const void *data, size_t data_len)
{
    struct icmp_checksum_ctx ctx;

    icmp_checksum_begin(&ctx);
    icmp_checksum_bytes(&ctx, data, data_len);
    return icmp_checksum_finish(&ctx);
}

// Compute ICMP6 checksum
// RFC 2463 (https://www.rfc-editor.org/rfc/rfc2463#section-2.3)
uint16_t icmp6_checksum(const struct ipv6_pseudo *pseudo, const void *data,
    size_t data_len)
{
    struct icmp_checksum_ctx ctx;

    icmp_checksum_begin(&ctx);
    icmp_checksum_bytes(&ctx, pseudo, sizeof(*pseudo));
    icmp_checksum_bytes(&ctx, data, data_len);
    return icmp_checksum_finish(&ctx);
}
