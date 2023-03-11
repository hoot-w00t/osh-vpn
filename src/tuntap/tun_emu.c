#include "tuntap.h"
#include "logger.h"
#include "xalloc.h"
#include "netutil/arp.h"
#include "netutil/icmp_nd.h"
#include "random.h"
#include <stdlib.h>

#ifdef TUNTAP_DISABLE_EMULATION
#warning "TUN emulation is compiled but should be disabled"
#endif

struct emu_data {
    uint8_t readbuf[TUNTAP_BUFSIZE];  // Read packet buffer
    uint8_t writebuf[TUNTAP_BUFSIZE]; // Write packet buffer

    struct eth_addr int_addr; // Internal MAC address (virtual interface)
    struct eth_addr ext_addr; // External MAC address
};

#define emu_data(tuntap) ((struct emu_data *) (tuntap)->emu.data.ptr)

// Generate external MAC address from *addr
// If addr is NULL the address is randomly generated
static void gen_external_mac(tuntap_t *tuntap, const struct eth_addr *addr)
{
    char addrstr[NETADDR_ADDRSTRLEN];

    if (addr) {
        emu_data(tuntap)->ext_addr = *addr;
        for (int i = 3; i < ETH_ALEN; ++i)
            emu_data(tuntap)->ext_addr.addr[i] ^= 0xFF;
    } else {
        for (int i = 0; i < ETH_ALEN; ++i)
            emu_data(tuntap)->ext_addr.addr[i] = random_xoshiro256() % 256;
    }

    emu_data(tuntap)->ext_addr.addr[0] &= ~(1);

    netaddr_ntop_mac(addrstr, sizeof(addrstr), &emu_data(tuntap)->ext_addr);
    logger_debug(DBG_TUNTAP_EMU, "Generated external MAC address: %s", addrstr);
}

// Set the internal MAC address
// If addr is NULL the MAC address is set to ff:ff:ff:ff:ff:ff
static void set_internal_mac(tuntap_t *tuntap, const struct eth_addr *addr)
{
    char addrstr[NETADDR_ADDRSTRLEN];

    if (addr)
        emu_data(tuntap)->int_addr = *addr;
    else
        memset(&emu_data(tuntap)->int_addr, 0xff, sizeof(emu_data(tuntap)->int_addr));

    netaddr_ntop_mac(addrstr, sizeof(addrstr), &emu_data(tuntap)->int_addr);
    logger_debug(DBG_TUNTAP_EMU, "Set internal MAC address: %s", addrstr);
}

// Update internal/external MAC addresses if the internal address has changed
static void update_internal_mac(tuntap_t *tuntap, const struct eth_addr *addr)
{
    if (!addr || memcmp(addr, &emu_data(tuntap)->int_addr, sizeof(*addr))) {
        set_internal_mac(tuntap, addr);
        gen_external_mac(tuntap, addr);
    }
}

// Write a raw packet to the driver
static bool write_raw_packet(tuntap_t *tuntap, const void *raw, size_t raw_size,
    const uint16_t ethertype)
{
    const size_t packet_size = sizeof(struct eth_hdr) + raw_size;
    struct emu_data *data = emu_data(tuntap);
    struct eth_hdr *hdr = (struct eth_hdr *) data->writebuf;

    if (packet_size > TUNTAP_BUFSIZE) {
        logger(LOG_WARN, "%s: Dropping packet bigger than the buffer size (%zu/%d)",
            __func__, packet_size, TUNTAP_BUFSIZE);
        return true;
    }

    // Copy the raw packet
    memcpy(data->writebuf + sizeof(*hdr), raw, raw_size);

    // Initialize Ethernet header
    hdr->dest = emu_data(tuntap)->int_addr;
    hdr->src = emu_data(tuntap)->ext_addr;
    hdr->ethertype = htons(ethertype);

    // Write the packet
    return tuntap_driver_write(tuntap, data->writebuf, packet_size);
}

// Handle ICMPv6 Neighbor Solicitations
// Returns true if the packet can be passed to tuntap_read()
static bool handle_icmpv6_ns(tuntap_t *tuntap, const void *packet, size_t packet_size)
{
    const struct icmp6_nd_ns *ns = (const struct icmp6_nd_ns *) packet;

    if (   packet_size < sizeof(*ns)
        || ns->iphdr.next_header != IPPROTO_ICMPV6
        || ns->ns.hdr.type != ND_NEIGHBOR_SOLICIT)
    {
        return true;
    }

    struct in6_addr src_addr;
    struct in6_addr dst_addr;
    struct in6_addr target_addr;
    char src_addr_str[NETADDR_ADDRSTRLEN];
    char dst_addr_str[NETADDR_ADDRSTRLEN];
    char target_addr_str[NETADDR_ADDRSTRLEN];
    struct icmp6_nd_na_tla na;

    src_addr = ns->iphdr.src_addr;
    dst_addr = ns->iphdr.dst_addr;
    target_addr = ns->ns.target_address;
    netaddr_ntop_ip6(src_addr_str, sizeof(src_addr_str), &src_addr);
    netaddr_ntop_ip6(dst_addr_str, sizeof(dst_addr_str), &dst_addr);
    netaddr_ntop_ip6(target_addr_str, sizeof(target_addr_str), &target_addr);

    if (IN6_ARE_ADDR_EQUAL(&src_addr, &in6addr_any)) {
        logger_debug(DBG_TUNTAP_EMU,
            "Ignoring ICMPv6 NS with null sender (dest %s, target %s)",
            dst_addr_str, target_addr_str);
        return true;
    }

    if (IN6_ARE_ADDR_EQUAL(&src_addr, &target_addr)) {
        logger_debug(DBG_TUNTAP_EMU,
            "Ignoring ICMPv6 NS with identical sender and target %s (dest %s)",
            target_addr_str, dst_addr_str);
        return true;
    }

    logger_debug(DBG_TUNTAP_EMU,
        "Replying to ICMPv6 NS from %s (dest %s, target %s)",
        src_addr_str, dst_addr_str, target_addr_str);
    icmp6_make_nd_na_tla(&na, ns, &emu_data(tuntap)->ext_addr);
    write_raw_packet(tuntap, &na, sizeof(na), ETH_P_IPV6);
    return false;
}

// Handle ARP requests
static void handle_arp(tuntap_t *tuntap, const void *packet, size_t packet_size)
{
    const struct arp_ether_ip *arp = (const struct arp_ether_ip *) packet;

    // If the ARP packet is not Ethernet/IPv4, ignore it
    if (!arp_is_ether_ip(arp, packet_size)) {
        logger_debug(DBG_TUNTAP_EMU,
            "Ignoring unsupported ARP packet of %zu bytes", packet_size);
        return;
    }

    netaddr_t sender_hw, sender_ip;
    struct in_addr target_ip;
    char sender_hw_str[NETADDR_ADDRSTRLEN];
    char sender_ip_str[NETADDR_ADDRSTRLEN];
    char target_ip_str[NETADDR_ADDRSTRLEN];

    netaddr_dton_mac(&sender_hw, *((const struct eth_addr *) arp->s_hwaddr));
    netaddr_dton_ip4(&sender_ip, *((const struct in_addr *)  arp->s_protoaddr));
    target_ip = *((const struct in_addr *)  arp->t_protoaddr);
    netaddr_ntop(sender_hw_str, sizeof(sender_hw_str), &sender_hw);
    netaddr_ntop(sender_ip_str, sizeof(sender_ip_str), &sender_ip);
    netaddr_ntop_ip4(target_ip_str, sizeof(target_ip_str), &target_ip);

    // Ignore the request if the sender protocol address is zeroed-out
    // (this is likely a probe to check if the target protocol address is
    //  already in use or not)
    if (netaddr_is_zero(&sender_hw) || netaddr_is_zero(&sender_ip)) {
        logger_debug(DBG_TUNTAP_EMU,
            "Ignoring ARP packet with null sender (target %s)", target_ip_str);
        return;
    }

    // Ignore the request if the sender and target protocol addresses are identical
    if (sender_ip.data.ip4.s_addr == target_ip.s_addr) {
        logger_debug(DBG_TUNTAP_EMU,
            "Ignoring ARP packet with identical sender and target %s (from %s)",
                target_ip_str, sender_hw_str);
        return;
    }

    if (arp->hdr.op == htons(ARP_OP_REQUEST)) {
        struct arp_ether_ip reply;

        logger_debug(DBG_TUNTAP_EMU,
            "Replying to ARP request from %s, %s (target %s)",
            sender_hw_str, sender_ip_str, target_ip_str);
        arp_ether_ip_make_reply(&reply, arp, &emu_data(tuntap)->ext_addr);
        write_raw_packet(tuntap, &reply, sizeof(reply), ETH_P_ARP);
    } else {
        logger_debug(DBG_TUNTAP_EMU,
            "Ignoring ARP packet with unknown operation %u from %s, %s (target %s)",
             ntohs(arp->hdr.op), sender_hw_str, sender_ip_str, target_ip_str);
    }
}

// Returns true if the protocol is compatible with layer 3 and can be read by tuntap_read()
// This function also processes ARP/NDP requests/replies
static bool tun_compatible(tuntap_t *tuntap, const uint16_t ethertype,
    const void *packet, size_t packet_size)
{
    switch (ethertype) {
        case ETH_P_IP:
            return true;

        case ETH_P_IPV6:
            return handle_icmpv6_ns(tuntap, packet, packet_size);

        case ETH_P_ARP:
            handle_arp(tuntap, packet, packet_size);
            return false;

        default: // Drop all other protocols
            logger_debug(DBG_TUNTAP_EMU,
                "Dropped packet of %zu bytes (type: 0x%04X)",
                packet_size, ethertype);
            return false;
    }
}

static bool _tun_read(tuntap_t *tuntap, void *buf, size_t buf_size, size_t *pkt_size)
{
    size_t driver_pkt_size;
    const bool success = tuntap_driver_read(tuntap, emu_data(tuntap)->readbuf,
        TUNTAP_BUFSIZE, &driver_pkt_size);

    if (!success)
        return false;

    if (driver_pkt_size <= sizeof(struct eth_hdr)) {
        *pkt_size = 0;
        return true;
    }

    const struct eth_hdr *hdr = (const struct eth_hdr *) emu_data(tuntap)->readbuf;
    const uint8_t *raw_packet = emu_data(tuntap)->readbuf + sizeof(struct eth_hdr);
    const size_t raw_packet_size = driver_pkt_size - sizeof(struct eth_hdr);

    // Keep the internal MAC address up to date if it changes
    update_internal_mac(tuntap, &hdr->src);

    if (!tun_compatible(tuntap, ntohs(hdr->ethertype), raw_packet, raw_packet_size)) {
        *pkt_size = 0;
        return true;
    }

    if (raw_packet_size > buf_size) {
        logger(LOG_CRIT, "%s: Buffer size is too small (%zu/%zu bytes)",
            __func__, raw_packet_size, buf_size);
        errno = EINVAL;
        return false;
    }

    memcpy(buf, raw_packet, raw_packet_size);
    *pkt_size = raw_packet_size;
    return true;
}

static bool _tun_write(tuntap_t *tuntap, const void *packet, size_t packet_size)
{
    // Silently ignore empty packets
    if (packet_size == 0)
        return true;

    switch (IP_HDR_VERSION(packet)) {
        case 4: return write_raw_packet(tuntap, packet, packet_size, ETH_P_IP);
        case 6: return write_raw_packet(tuntap, packet, packet_size, ETH_P_IPV6);
        default:
            logger(LOG_ERR, "%s: Invalid IP packet", __func__);
            return false;
    }
}

void tuntap_emu_tun_init(tuntap_t *tuntap)
{
    tuntap->emu.data.ptr = xzalloc(sizeof(struct emu_data));
    update_internal_mac(tuntap, NULL);

    tuntap->read = _tun_read;
    tuntap->write = _tun_write;
}

void tuntap_emu_tun_deinit(tuntap_t *tuntap)
{
    free(tuntap->emu.data.ptr);
}
