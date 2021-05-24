#ifndef _OSH_NETADDR_H
#define _OSH_NETADDR_H

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

bool netaddr_ntop(char *dest, uint32_t maxlen, netaddr_t *addr);
bool netaddr_pton(netaddr_t *dest, const char *data);
bool netaddr_dton(netaddr_t *dest, netaddr_type_t type, const void *data);
void netaddr_cpy(netaddr_t *dest, const netaddr_t *src);
netaddr_t *netaddr_dup(netaddr_t *src);
bool netaddr_eq(const netaddr_t *s1, const netaddr_t *s2);

#endif