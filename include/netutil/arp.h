#ifndef _OSH_NETUTIL_ARP_H
#define _OSH_NETUTIL_ARP_H

#include "netdefs/arp.h"
#include <stdbool.h>

void arp_ether_ip_make_request(struct arp_ether_ip *req,
    const struct eth_addr *s_hwaddr, const struct in_addr *s_ipaddr,
    const struct eth_addr *t_hwaddr, const struct in_addr *t_ipaddr);

void arp_ether_ip_make_reply(struct arp_ether_ip *reply,
    const struct arp_ether_ip *req, const struct eth_addr *reply_hwaddr);

#endif
