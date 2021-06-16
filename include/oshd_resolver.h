#ifndef _OSH_OSHD_RESOLVER_H
#define _OSH_OSHD_RESOLVER_H

#include <stdbool.h>

typedef enum resolver_type {
    RESOLVER_NONE = 0,
    RESOLVER_HOSTSDUMP
} resolver_type_t;

const char *oshd_resolver_name(resolver_type_t resolver);
bool oshd_resolver_check(void);
void oshd_resolver_append(const netaddr_t *addr, const char *name);
void oshd_resolver_update(void);

#endif