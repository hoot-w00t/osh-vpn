#ifndef _OSH_NETUTIL_ICMP_H
#define _OSH_NETUTIL_ICMP_H

#include "netdefs/ip.h"
#include <stddef.h>
#include <stdint.h>

uint16_t icmp4_checksum(const void *data, size_t data_len);
uint16_t icmp6_checksum(const struct ipv6_pseudo *pseudo, const void *data,
    size_t data_len);

#endif
