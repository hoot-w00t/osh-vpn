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

// ICMPv6 Neighbor Discovery packet structures
#define _icmp6_common_ns                    \
    struct ipv6_hdr iphdr;                  \
    struct nd_neighbor_solicit ns;

#define _icmp6_common_na                    \
    struct ipv6_hdr iphdr;                  \
    struct nd_neighbor_advert na;

// ICMPv6 NS without options
struct __attribute__((packed)) icmp6_nd_ns {
    _icmp6_common_ns
};

// ICMPv6 NA without options
struct __attribute__((packed)) icmp6_nd_na {
    _icmp6_common_na
};

// ICMPv6 NA with target link-layer address option
struct __attribute__((packed)) icmp6_nd_na_tla {
    _icmp6_common_na
    struct nd_opt_target_linkaddr opt_tla;
};

void icmp6_make_nd_na_tla(struct icmp6_nd_na_tla *reply,
    const struct icmp6_nd_ns *req, const struct eth_addr *reply_linkaddr);

#endif
