#ifndef _OSH_NETADDR_H
#define _OSH_NETADDR_H

#include "netarea.h"
#include <stdint.h>
#include <stdbool.h>

typedef enum netaddr_type {
    MAC = 0,
    IP4,
    IP6
} netaddr_type_t;

typedef struct netaddr {
    netaddr_type_t type;   // Address type
    uint8_t data[16];      // Address data
} netaddr_t;

typedef uint8_t cidr_t;

bool netaddr_lookup(netaddr_t *addr, const char *hostname);
bool netaddr_ntop(char *dest, uint32_t maxlen, const netaddr_t *addr);
bool netaddr_pton(netaddr_t *dest, const char *data);
bool netaddr_dton(netaddr_t *dest, netaddr_type_t type, const void *data);
void netaddr_cpy(netaddr_t *dest, const netaddr_t *src);
netaddr_t *netaddr_dup(netaddr_t *src);
bool netaddr_eq(const netaddr_t *s1, const netaddr_t *s2);

void netaddr_mask_from_cidr(netaddr_t *mask, cidr_t cidr);
cidr_t netaddr_cidr_from_mask(const netaddr_t *mask);
void netaddr_mask(netaddr_t *masked_addr, const netaddr_t *addr,
    const netaddr_t *mask);
void netaddr_mask_cidr(netaddr_t *masked_addr, const netaddr_t *addr,
    cidr_t cidr);

bool netaddr_is_zero(const netaddr_t *addr);
bool netaddr_is_loopback(const netaddr_t *addr);
netarea_t netaddr_area(const netaddr_t *addr);

#endif