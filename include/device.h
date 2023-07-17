#ifndef _OSH_DEVICE_H
#define _OSH_DEVICE_H

#include "tuntap.h"
#include <stddef.h>

typedef struct dynamic_addr dynamic_addr_t;

void device_add(tuntap_t *tuntap);

// Dynamic device mode functions
void device_dynamic_gen_prefix6(void);
void device_dynamic_gen_prefix4(void);

void device_dynamic_gen_addr6_stable(dynamic_addr_t *daddr, size_t seed);
void device_dynamic_gen_addr6_random(dynamic_addr_t *daddr);

void device_dynamic_gen_addr4_stable(dynamic_addr_t *daddr, size_t seed);
void device_dynamic_gen_addr4_random(dynamic_addr_t *daddr);

bool device_dynamic_add(tuntap_t *tuntap, const dynamic_addr_t *daddr);
bool device_dynamic_del(tuntap_t *tuntap, const dynamic_addr_t *daddr);

#endif
