#include "netutil/arp.h"

static void arp_init_hdr(
    struct arp_hdr *hdr, const uint16_t op,
    const uint16_t hw, const uint8_t hw_len,
    const uint16_t proto, const uint8_t proto_len)
{
    hdr->op = htons(op);
    hdr->hw = htons(hw);
    hdr->hw_len = hw_len;
    hdr->proto = htons(proto);
    hdr->proto_len = proto_len;
}

#define arp_ether_ip_init_hdr(hdr, op) \
    arp_init_hdr(hdr, op, ARP_HW_ETHER, ARP_HW_ETHER_LEN, ARP_PROTO_IP, ARP_PROTO_IP_LEN)

// Make ARP probe
// Address pointers can be NULL, if they are their respective fields in the ARP
// packet will be set 0
void arp_ether_ip_make_request(struct arp_ether_ip *req,
    const struct eth_addr *s_hwaddr, const struct in_addr *s_ipaddr,
    const struct eth_addr *t_hwaddr, const struct in_addr *t_ipaddr)
{
    memset(req, 0, sizeof(*req));
    arp_ether_ip_init_hdr(&req->hdr, ARP_OP_REQUEST);
    if (s_hwaddr) req->s_hwaddr    = *s_hwaddr;
    if (s_ipaddr) req->s_protoaddr = *s_ipaddr;
    if (t_hwaddr) req->t_hwaddr    = *t_hwaddr;
    if (t_ipaddr) req->t_protoaddr = *t_ipaddr;
}

// Make ARP reply from a request
// Swaps sender and target addresses and set the reply's sender hardware address
// to *reply_hwaddr
void arp_ether_ip_make_reply(struct arp_ether_ip *reply,
    const struct arp_ether_ip *req, const struct eth_addr *reply_hwaddr)
{
    arp_ether_ip_init_hdr(&reply->hdr, ARP_OP_REPLY);
    reply->s_hwaddr    = *reply_hwaddr;
    reply->s_protoaddr =  req->t_protoaddr;
    reply->t_hwaddr    =  req->s_hwaddr;
    reply->t_protoaddr =  req->s_protoaddr;
}
