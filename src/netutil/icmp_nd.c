#include "netutil/icmp_nd.h"
#include "netutil/icmp.h"
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

// Initialize IPv6 header
static void ipv6_init_hdr(
    struct ipv6_hdr *hdr,
    const uint32_t traffic_class,
    const uint32_t flow_label,
    const uint16_t payload_length,
    const uint8_t next_header,
    const uint8_t hop_limit,
    const struct in6_addr *src_addr,
    const struct in6_addr *dst_addr)
{
    const uint32_t h_version = 6u << 28;
    const uint32_t h_traffic_class = (traffic_class & 0xFF) << 24;
    const uint32_t h_flow_label = (flow_label & 0xFFFFFF);

    hdr->flow_label = htonl(h_version | h_traffic_class | h_flow_label);
    hdr->payload_length = htons(payload_length);
    hdr->next_header = next_header;
    hdr->hop_limit = hop_limit;
    hdr->src_addr = *src_addr;
    hdr->dst_addr = *dst_addr;
}

// Initialize IPv6 pseudo-header from IPv6 header
static void ipv6_init_pseudo(struct ipv6_pseudo *pseudo, const struct ipv6_hdr *hdr)
{
    pseudo->dst = hdr->dst_addr;
    pseudo->src = hdr->src_addr;
    pseudo->length = hdr->payload_length;
    memset(pseudo->zero, 0, sizeof(pseudo->zero));
    pseudo->next_header = hdr->next_header;
}

// Make ICMPv6 NA from NS (solicited)
void icmp6_make_nd_na_tla(struct icmp6_nd_na_tla *reply,
    const struct icmp6_nd_ns *req, const struct eth_addr *reply_linkaddr)
{
    const uint32_t fl = ntohl(req->iphdr.flow_label);
    struct ipv6_pseudo pseudo_hdr;
    struct in6_addr src_addr;
    struct in6_addr dst_addr;

    // IPv6 header
    src_addr = req->ns.target_address;
    dst_addr = req->iphdr.src_addr;
    ipv6_init_hdr(&reply->iphdr,
        ipv6_hdr_traffic_class(fl),
        ipv6_hdr_flow_label(fl),
        sizeof(*reply) - sizeof(struct ipv6_hdr),
        IPPROTO_ICMPV6,
        255,
        &src_addr,
        &dst_addr);

    // ICMPv6 header
    reply->na.hdr.type = ND_NEIGHBOR_ADVERT;
    reply->na.hdr.code = 0;
    reply->na.hdr.checksum = 0;
    reply->na.hdr.reserved = htonl(0x40000000u); // Solicited

    // ICMPv6 NA
    reply->na.target_address = req->ns.target_address;

    // Target link-layer address
    reply->opt_tla.hdr.type = ND_OPT_TARGET_LINKADDR;
    reply->opt_tla.hdr.length = ND_OPT_LENGTH(sizeof(reply->opt_tla));
    reply->opt_tla.addr = *reply_linkaddr;

    // Compute the checksum
    ipv6_init_pseudo(&pseudo_hdr, &reply->iphdr);
    reply->na.hdr.checksum = icmp6_checksum(&pseudo_hdr,
        ((const uint8_t *) reply) + sizeof(struct ipv6_hdr),
        sizeof(*reply) - sizeof(struct ipv6_hdr));
}
