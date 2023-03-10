#include "netutil/icmp_nd.h"
#include "logger.h"

// Initialize *opt to iterate over ND options in IPv6 packet
// ip_pkt must be an IPv6 packet starting with the header
// size_without_options is the fixed size of the IPv6 packet without ND options
void icmp6_nd_opt_init(icmp6_nd_opt_t *opt, const void *ip_pkt, size_t ip_pkt_size,
    size_t size_without_options)
{
    opt->ip_pkt = ip_pkt;
    opt->ip_pkt_size = ip_pkt_size;
    opt->opt_offset = size_without_options;

    opt->opt = NULL;
    opt->opt_size = 0;
    opt->opt_hdr = NULL;
}

// Get to and decode the next ND option
// If a valid option with a correct size was found and the function returns true
// If there are no more options or the packet is malformed, function returns false
// On success members opt, opt_size and opt_hdr are initialized and safe to use,
// on error they are in an undefined state
// loglevel is the debug log level the function will use
bool icmp6_nd_opt_next(icmp6_nd_opt_t *opt)
{
    if (!opt->ip_pkt || opt->ip_pkt_size == 0 || opt->opt_offset == 0)
        return false;

    // We either reached the end of the packet or it is malformed
    if (opt->opt_offset + sizeof(struct nd_opt_hdr) > opt->ip_pkt_size)
        return false;

    opt->opt = ((const uint8_t *) opt->ip_pkt) + opt->opt_offset;
    opt->opt_hdr = (const struct nd_opt_hdr *) opt->opt;

    // An option length of 0 is invalid
    if (opt->opt_hdr->length == 0)
        return false;
    opt->opt_size = ND_OPT_LENGTH_TO_BYTES(opt->opt_hdr->length);

    // The packet is malformed
    if (opt->opt_offset + opt->opt_size > opt->ip_pkt_size)
        return false;

    // Check that the option type matches its length
    size_t expected_size;

    switch (opt->opt_hdr->type) {
        case ND_OPT_SOURCE_LINKADDR: expected_size = sizeof(struct nd_opt_source_linkaddr); break;
        case ND_OPT_TARGET_LINKADDR: expected_size = sizeof(struct nd_opt_target_linkaddr); break;
        case ND_OPT_TIMESTAMP:       expected_size = sizeof(struct nd_opt_timestamp);       break;
        case ND_OPT_NONCE:           expected_size = opt->opt_size;                         break;
        default:
            logger(LOG_WARN, "%s: Unsupported option type %u",
                __func__, opt->opt_hdr->type);
            return false;
    }

    if (opt->opt_size != expected_size)
        return false;

    // Setup offset for the next option
    opt->opt_offset += opt->opt_size;

    return true;
}
