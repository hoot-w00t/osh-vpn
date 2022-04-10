#ifndef _OSH_NETADDR_H
#define _OSH_NETADDR_H

#include "netarea.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>

typedef enum netaddr_type {
    MAC = 0,
    IP4,
    IP6
} netaddr_type_t;

struct __attribute__((packed)) netaddr_data_mac {
    uint8_t addr[6];
};

typedef union netaddr_data {
    uint8_t b[16];
    struct in_addr ip4;
    struct in6_addr ip6;
    struct netaddr_data_mac mac;
} netaddr_data_t;

typedef struct netaddr {
    netaddr_type_t type; // Address type
    netaddr_data_t data; // Address data
} netaddr_t;

typedef uint8_t netaddr_prefixlen_t;

// Mask IPv4 netaddr_t with mask and compare it with net
// The mask and network must be in host byte order
#define NETADDR_IP4_NET(addr, mask, net) \
    (((addr)->data.ip4.s_addr & htonl(mask)) == htonl(net))

bool netaddr_lookup(netaddr_t *addr, const char *hostname);
bool netaddr_ntop(char *dest, size_t maxlen, const netaddr_t *addr);
bool netaddr_ntop2(char *dest, size_t maxlen, const netaddr_t *addr,
    const uint16_t port);
bool netaddr_pton(netaddr_t *dest, const char *data);
bool netaddr_dton(netaddr_t *dest, netaddr_type_t type, const void *data);
void netaddr_cpy(netaddr_t *dest, const netaddr_t *src);
void netaddr_cpy_data(void *dest, const netaddr_t *src);
netaddr_t *netaddr_dup(netaddr_t *src);
bool netaddr_eq(const netaddr_t *s1, const netaddr_t *s2);

bool netaddr_is_zero(const netaddr_t *addr);
bool netaddr_is_loopback(const netaddr_t *addr);
netarea_t netaddr_area(const netaddr_t *addr);

void netaddr_mask(netaddr_t *dest, const netaddr_t *addr, const netaddr_t *mask);
bool netaddr_mask_from_prefix(netaddr_t *mask, netaddr_type_t type,
    netaddr_prefixlen_t prefixlen);

#endif