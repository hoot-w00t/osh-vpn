#ifndef _OSH_NETADDR_H
#define _OSH_NETADDR_H

#include "sock.h"
#include "netarea.h"
#include "netdefs/ether.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum netaddr_type {
    MAC = 0,
    IP4,
    IP6,
    _netaddr_type_last
} netaddr_type_t;

typedef union netaddr_data {
    uint8_t b[16];
    struct in_addr ip4;
    struct in6_addr ip6;
    struct eth_addr mac;
} netaddr_data_t;

typedef struct netaddr {
    netaddr_type_t type; // Address type
    netaddr_data_t data; // Address data
} netaddr_t;

typedef uint8_t netaddr_prefixlen_t;

// Returns the maximum prefix length for this address type
static inline netaddr_prefixlen_t netaddr_max_prefixlen(const netaddr_type_t type)
{
    switch (type) {
        case MAC: return  48;
        case IP4: return  32;
        case IP6: return 128;
         default: return   0;
    }
}

// Returns true if type is valid
static inline bool netaddr_type_is_valid(const netaddr_type_t type)
{
    return type >= MAC && type < _netaddr_type_last;
}

// Mask IPv4 netaddr_t with mask and compare it with net
// The mask and network must be in host byte order
#define NETADDR_IP4_NET(addr, mask, net) \
    (((addr)->data.ip4.s_addr & htonl(mask)) == htonl(net))

bool netaddr_lookup(netaddr_t *addr, const char *hostname);
bool netaddr_ntop(char *dest, size_t maxlen, const netaddr_t *addr);
bool netaddr_ntop2(char *dest, size_t maxlen, const netaddr_t *addr,
    const uint16_t port);
bool netaddr_pton(netaddr_t *dest, const char *data);
bool netaddr_dton(netaddr_t *dest, netaddr_type_t type, const netaddr_data_t *data);
void netaddr_cpy(netaddr_t *dest, const netaddr_t *src);
void netaddr_cpy_data(netaddr_data_t *dest, const netaddr_t *src);
netaddr_t *netaddr_dup(const netaddr_t *src);
bool netaddr_eq(const netaddr_t *s1, const netaddr_t *s2);

bool netaddr_is_zero(const netaddr_t *addr);
bool netaddr_is_loopback(const netaddr_t *addr);
netarea_t netaddr_area(const netaddr_t *addr);

void netaddr_mask(netaddr_t *dest, const netaddr_t *addr, const netaddr_t *mask);
bool netaddr_mask_from_prefix(netaddr_t *mask, netaddr_type_t type,
    netaddr_prefixlen_t prefixlen);

// Generic inline initializer of netaddr_t
#define _NETADDR_DTON_INLINE(DEST, ADDR, TYPE, DATA)        \
    do {                                                    \
        (DEST)->type = TYPE;                                \
        (DEST)->DATA = ADDR;                                \
    } while (0)

// Set MAC address from struct eth_addr
#define netaddr_dton_mac(dest, addr)        _NETADDR_DTON_INLINE(dest, addr, MAC, data.mac)

// Set IPv4 address from struct in_addr
#define netaddr_dton_ip4(dest, addr)        _NETADDR_DTON_INLINE(dest, addr, IP4, data.ip4)

// Set IPv4 address from uint32_t
#define netaddr_dton_ip4_u32(dest, addr)    _NETADDR_DTON_INLINE(dest, addr, IP4, data.ip4.s_addr)

// Set IPv6 address from struct in6_addr
#define netaddr_dton_ip6(dest, addr)        _NETADDR_DTON_INLINE(dest, addr, IP6, data.ip6)

#endif
