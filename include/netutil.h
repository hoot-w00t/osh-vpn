#ifndef _OSH_NETUTIL_H
#define _OSH_NETUTIL_H

#include "netdefs/ether.h"
#include "netdefs/ip.h"
#include "netdefs/icmp.h"
#include "netdefs/arp.h"
#include <stddef.h>
#include <stdint.h>

// Defined in netutil/icmp.c
uint16_t icmp4_checksum(const void *data, size_t data_len);
uint16_t icmp6_checksum(const struct ipv6_pseudo *pseudo, const void *data,
    size_t data_len);

#endif
