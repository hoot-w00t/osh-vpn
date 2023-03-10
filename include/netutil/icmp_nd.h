#ifndef _OSH_NETUTIL_ICMP_ND_H
#define _OSH_NETUTIL_ICMP_ND_H

#include "netdefs/icmp.h"
#include <stdbool.h>

typedef struct icmp6_nd_opt icmp6_nd_opt_t;
struct icmp6_nd_opt {
    // IPv6 packet being processed
    const void *ip_pkt;
    size_t ip_pkt_size;

    // Offset to the start of the next ND option (from *ip_pkt)
    size_t opt_offset;

    // Current IPv6 option
    const void *opt;
    size_t opt_size;

    // Option header (same pointer as *buf)
    const struct nd_opt_hdr *opt_hdr;
};

void icmp6_nd_opt_init(icmp6_nd_opt_t *opt, const void *ip_pkt, size_t ip_pkt_size,
    size_t size_without_options);
bool icmp6_nd_opt_next(icmp6_nd_opt_t *opt);

#endif
