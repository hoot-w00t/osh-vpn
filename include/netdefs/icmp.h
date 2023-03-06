#ifndef _OSH_NETDEFS_ICMP_H
#define _OSH_NETDEFS_ICMP_H

#include "netdefs/ip.h"
#include "netdefs/ether.h"

// Neighbor Discovery: https://www.rfc-editor.org/rfc/rfc4861.html

// ICMPv6 types
#define ICMP6_DST_UNREACH           1
#define ICMP6_PACKET_TOO_BIG        2
#define ICMP6_TIME_EXCEEDED         3
#define ICMP6_PARAM_PROB            4
#define ICMP6_ECHO_REQUEST          128
#define ICMP6_ECHO_REPLY            129

#define ND_ROUTER_SOLICIT           133
#define ND_ROUTER_ADVERT            134
#define ND_NEIGHBOR_SOLICIT         135
#define ND_NEIGHBOR_ADVERT          136
#define ND_REDIRECT                 137

// ICMPv6 codes
#define ICMP6_DST_UNREACH_NOROUTE       0 // no route to destination
#define ICMP6_DST_UNREACH_ADMIN         1 // communication with destination administratively prohibited
#define ICMP6_DST_UNREACH_BEYONDSCOPE   2 // beyond scope of source address
#define ICMP6_DST_UNREACH_ADDR          3 // address unreachable
#define ICMP6_DST_UNREACH_PORT          4 // port unreachable
#define ICMP6_DST_UNREACH_SAPOLICY      5 // source address failed ingress/egress policy
#define ICMP6_DST_UNREACH_REJECT        6 // reject route to destination
#define ICMP6_DST_UNREACH_SRCHEADER     7 // error in source routing header

#define ICMP6_TIME_EXCEEDED_TRANSIT     0 // hop limit exceeded in transit
#define ICMP6_TIME_EXCEEDED_REASSEMBLY  1 // fragment reassembly time exceeded

#define ICMP6_PARAM_PROB_HEADER         0 // erroneous header field encountered
#define ICMP6_PARAM_PROB_NEXTHEADER     1 // unrecognized next header type encountered
#define ICMP6_PARAM_PROB_OPTION         2 // unrecognized ipv6 option encountered

// ICMPv6 option types
#define ICMP6_OPT_SOURCE_LINKADDR       1
#define ICMP6_OPT_TARGET_LINKADDR       2

// ICMPv6 header
struct __attribute__((packed)) icmp6_hdr {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;

    uint32_t reserved;
};

// Neighbor Discovery option header
struct __attribute__((packed)) nd_opt_hdr {
    uint8_t type;
    uint8_t length; // total option length (in units of 8 octets)
    // option data
};

// Get nd_opt_hdr->length value from length in bytes
// (must be a multiple of 8)
#define ND_OPT_LENGTH(raw_length) ((raw_length) / 8)

// ND option source link-layer address
struct __attribute__((packed)) nd_opt_source_linkaddr {
    struct nd_opt_hdr hdr;
    struct eth_addr addr;
};

// ND option target link-layer address
struct __attribute__((packed)) nd_opt_target_linkaddr {
    struct nd_opt_hdr hdr;
    struct eth_addr addr;
};

// ND Neighbor Solicitation
struct __attribute__((packed)) nd_neighbor_solicit {
    struct icmp6_hdr hdr;
    struct in6_addr target_address;
    // can be followed by options
};

// ND Neighbor Advertisement
struct __attribute__((packed)) nd_neighbor_advert {
    struct icmp6_hdr hdr;
    struct in6_addr target_address;
    // can be followed by options
};

#endif
