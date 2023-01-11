#include "netaddr.h"
#include <criterion/criterion.h>

Test(netaddr_data_t, netaddr_data_sizes)
{
    netaddr_data_t d;

    cr_assert_eq(sizeof(d), 16);
    cr_assert_eq(sizeof(d.b), sizeof(d));
    cr_assert_eq(sizeof(d.mac), 6);
    cr_assert_eq(sizeof(d.ip4), 4);
    cr_assert_eq(sizeof(d.ip6), 16);
}

Test(netaddr_data_t, netaddr_data_union_pointers)
{
    netaddr_data_t d;

    cr_assert_eq(&d, d.b);
    cr_assert_eq(&d, &d.ip4);
    cr_assert_eq(&d, &d.ip6);
    cr_assert_eq(&d, &d.mac);
}

Test(netaddr_dton, test_netaddr_dton)
{
    const uint8_t macaddr[6] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6};
    const struct in_addr sin = {htonl(INADDR_LOOPBACK)};
    const struct in6_addr sin6 = in6addr_loopback;
    netaddr_t nmac, nip4, nip6;

    cr_assert_neq(netaddr_dton(&nmac, MAC, macaddr), false);
    cr_assert_neq(netaddr_dton(&nip4, IP4, &sin), false);
    cr_assert_neq(netaddr_dton(&nip6, IP6, &sin6), false);
}

Test(netaddr_pton, test_netaddr_pton)
{
    netaddr_t addr;

    cr_assert_neq(netaddr_pton(&addr, "01:02:03:04:05:06"), false);
    cr_assert_eq(addr.type, MAC);
    cr_assert_neq(netaddr_pton(&addr, "127.0.0.1"), false);
    cr_assert_eq(addr.type, IP4);
    cr_assert_neq(netaddr_pton(&addr, "::1"), false);
    cr_assert_eq(addr.type, IP6);
    cr_assert_eq(netaddr_pton(&addr, "invalid address"), false);
}

Test(netaddr_ntop, test_netaddr_ntop)
{
    netaddr_t addr;
    char addrw[INET6_ADDRSTRLEN];
    static const char *addresses[] = {
        "01:02:03:04:05:06",
        "192.168.1.1",
        "ffff::",
        NULL
    };

    for (int i = 0; addresses[i]; ++i) {
        netaddr_pton(&addr, addresses[i]);
        netaddr_ntop(addrw, sizeof(addrw), &addr);
        cr_assert_str_eq(addrw, addresses[i]);
    }
}

Test(netaddr_cpy, test_netaddr_cpy)
{
    netaddr_t src, dest;

    cr_assert_neq(netaddr_pton(&src, "01:02:03:04:05:06"), false);
    netaddr_cpy(&dest, &src);
    cr_assert_eq(src.type, dest.type);
    for (uint8_t i = 0; i < sizeof(src.data.mac); ++i)
        cr_assert_eq(src.data.b[i], dest.data.b[i]);
}

Test(netaddr_dup, test_netaddr_dup)
{
    netaddr_t src;
    netaddr_t *dup;

    cr_assert_neq(netaddr_pton(&src, "01:02:03:04:05:06"), false);
    dup = netaddr_dup(&src);
    cr_assert_eq(src.type, dup->type);
    for (uint8_t i = 0; i < sizeof(src.data.mac); ++i)
        cr_assert_eq(src.data.b[i], dup->data.b[i]);
    free(dup);
}

Test(netaddr_eq, test_netaddr_eq)
{
    netaddr_t mac_0, mac_1, mac_2;
    netaddr_t ip4_0, ip4_1;
    netaddr_t ip6_0, ip6_1;

    cr_assert_neq(netaddr_pton(&mac_0, "01:02:03:04:05:06"), false);
    cr_assert_neq(netaddr_pton(&mac_1, "ff:ff:ff:ff:ff:ff"), false);
    cr_assert_neq(netaddr_pton(&mac_2, "01:02:03:04:05:07"), false);

    cr_assert_neq(netaddr_pton(&ip4_0, "192.168.1.1"), false);
    cr_assert_neq(netaddr_pton(&ip4_1, "255.255.255.255"), false);

    cr_assert_neq(netaddr_pton(&ip6_0, "::1"), false);
    cr_assert_neq(netaddr_pton(&ip6_1, "feff:80ef::1"), false);

    cr_assert_neq(netaddr_eq(&mac_0, &mac_0), false);
    cr_assert_neq(netaddr_eq(&mac_1, &mac_1), false);
    cr_assert_eq(netaddr_eq(&mac_0, &mac_1), false);
    cr_assert_eq(netaddr_eq(&mac_0, &mac_2), false);

    cr_assert_neq(netaddr_eq(&ip4_0, &ip4_0), false);
    cr_assert_neq(netaddr_eq(&ip4_1, &ip4_1), false);
    cr_assert_eq(netaddr_eq(&ip4_0, &ip4_1), false);
    cr_assert_neq(netaddr_eq(&ip6_0, &ip6_0), false);
    cr_assert_neq(netaddr_eq(&ip6_1, &ip6_1), false);
    cr_assert_eq(netaddr_eq(&ip6_0, &ip6_1), false);

    cr_assert_eq(netaddr_eq(&mac_0, &ip4_0), false);
    cr_assert_eq(netaddr_eq(&mac_0, &ip6_0), false);
    cr_assert_eq(netaddr_eq(&ip4_0, &ip6_0), false);

    netaddr_cpy(&mac_1, &mac_0);
    cr_assert_eq(netaddr_eq(&mac_0, &mac_1), true);
    mac_1.type = IP4;
    cr_assert_eq(netaddr_eq(&mac_0, &mac_1), false);
}

Test(netaddr_is_loopback, netaddr_is_loopback_invalid)
{
    netaddr_t addr;

    memset(&addr, 0, sizeof(addr));
    addr.type = MAC;
    cr_assert_eq(netaddr_is_loopback(&addr), false);
}

Test(netaddr_is_loopback, netaddr_is_loopback_ipv4)
{
    netaddr_t addr;

    addr.type = IP4;
    for (size_t i = 0; i < 256; ++i) {
        if (i == 127)
            continue;

        addr.data.ip4.s_addr = htonl((i << 24) & 0xff000000);
        cr_assert_eq(netaddr_is_loopback(&addr), false);
    }

    for (uint32_t i = 0x7f000000; i <= 0x7fffffff; ++i) {
        addr.data.ip4.s_addr = htonl(i);
        cr_assert_eq(netaddr_is_loopback(&addr), true);
    }
}

Test(netaddr_is_loopback, netaddr_is_loopback_ipv6)
{
    netaddr_t addr;

    cr_assert_eq(netaddr_pton(&addr, "::"), true);
    cr_assert_eq(netaddr_is_loopback(&addr), false);
    cr_assert_eq(netaddr_pton(&addr, "::1"), true);
    cr_assert_eq(netaddr_is_loopback(&addr), true);
    cr_assert_eq(netaddr_pton(&addr, "::2"), true);
    cr_assert_eq(netaddr_is_loopback(&addr), false);
}

Test(netaddr_area, test_netaddr_area_10_0_0_0)
{
    netaddr_t addr;

    addr.type = IP4;
    for (uint32_t i = 0; i <= 0x00ffffff; ++i) {
        addr.data.ip4.s_addr = htonl(0x0A000000 | i);
        cr_assert_eq(netaddr_area(&addr), NETAREA_LAN);
    }
}

Test(netaddr_area, test_netaddr_area_172_16_0_0)
{
    netaddr_t addr;

    addr.type = IP4;
    for (uint32_t i = 0; i <= 0x000fffff; ++i) {
        addr.data.ip4.s_addr = htonl(0xac100000 | i);
        cr_assert_eq(netaddr_area(&addr), NETAREA_LAN);
    }
}

Test(netaddr_area, test_netaddr_area_192_168_0_0)
{
    netaddr_t addr;

    addr.type = IP4;
    for (uint32_t i = 0; i <= 0x0000ffff; ++i) {
        addr.data.ip4.s_addr = htonl(0xc0a80000 | i);
        cr_assert_eq(netaddr_area(&addr), NETAREA_LAN);
    }
}

Test(netaddr_area, test_netaddr_area_ipv4_loopback)
{
    netaddr_t addr;

    addr.type = IP4;
    for (uint32_t i = 0; i <= 0x00ffffff; ++i) {
        addr.data.ip4.s_addr = htonl(0x7f000000 | i);
        cr_assert_eq(netaddr_area(&addr), NETAREA_LAN);
    }
}

Test(netaddr_area, test_netaddr_area_link_local)
{
    netaddr_t addr;

    addr.type = IP6;
    memset(&addr.data.ip6, 0, sizeof(addr.data.ip6));
    for (uint16_t i = 0; i <= 0x3ff; ++i) {
        ((uint16_t *) &addr.data.ip6)[0] = htons(i);
        if (i == 0xfe8) {
            cr_assert_eq(netaddr_area(&addr), NETAREA_LAN);
        } else {
            cr_assert_eq(netaddr_area(&addr), NETAREA_WAN);
        }
    }
}

Test(netaddr_area, test_netaddr_area_ipv6_loopback)
{
    netaddr_t addr;

    cr_assert_eq(netaddr_pton(&addr, "::1"), true);
    cr_assert_eq(netaddr_area(&addr), NETAREA_LAN);
}

Test(netaddr_mask_from_prefix, prefixlen_zero)
{
    const uint8_t zero[16] = {0};
    netaddr_t masks[3];

    cr_assert_eq(netaddr_mask_from_prefix(&masks[0], MAC, 0), true);
    cr_assert_eq(netaddr_mask_from_prefix(&masks[1], IP4, 0), true);
    cr_assert_eq(netaddr_mask_from_prefix(&masks[2], IP6, 0), true);
    cr_assert_eq(masks[0].type, MAC);
    cr_assert_eq(masks[1].type, IP4);
    cr_assert_eq(masks[2].type, IP6);
    cr_assert_eq(memcmp(&masks[0].data.mac, zero, sizeof(masks[0].data.mac)), 0);
    cr_assert_eq(memcmp(&masks[1].data.ip4, zero, sizeof(masks[1].data.ip4)), 0);
    cr_assert_eq(memcmp(&masks[2].data.ip6, zero, sizeof(masks[2].data.ip6)), 0);
}

Test(netaddr_mask_from_prefix, ipv4_masks_from_prefix)
{
    netaddr_t ref[32];
    netaddr_t from;

    netaddr_pton(&ref[0],  "128.0.0.0");
    netaddr_pton(&ref[1],  "192.0.0.0");
    netaddr_pton(&ref[2],  "224.0.0.0");
    netaddr_pton(&ref[3],  "240.0.0.0");
    netaddr_pton(&ref[4],  "248.0.0.0");
    netaddr_pton(&ref[5],  "252.0.0.0");
    netaddr_pton(&ref[6],  "254.0.0.0");
    netaddr_pton(&ref[7],  "255.0.0.0");
    netaddr_pton(&ref[8],  "255.128.0.0");
    netaddr_pton(&ref[9],  "255.192.0.0");
    netaddr_pton(&ref[10], "255.224.0.0");
    netaddr_pton(&ref[11], "255.240.0.0");
    netaddr_pton(&ref[12], "255.248.0.0");
    netaddr_pton(&ref[13], "255.252.0.0");
    netaddr_pton(&ref[14], "255.254.0.0");
    netaddr_pton(&ref[15], "255.255.0.0");
    netaddr_pton(&ref[16], "255.255.128.0");
    netaddr_pton(&ref[17], "255.255.192.0");
    netaddr_pton(&ref[18], "255.255.224.0");
    netaddr_pton(&ref[19], "255.255.240.0");
    netaddr_pton(&ref[20], "255.255.248.0");
    netaddr_pton(&ref[21], "255.255.252.0");
    netaddr_pton(&ref[22], "255.255.254.0");
    netaddr_pton(&ref[23], "255.255.255.0");
    netaddr_pton(&ref[24], "255.255.255.128");
    netaddr_pton(&ref[25], "255.255.255.192");
    netaddr_pton(&ref[26], "255.255.255.224");
    netaddr_pton(&ref[27], "255.255.255.240");
    netaddr_pton(&ref[28], "255.255.255.248");
    netaddr_pton(&ref[29], "255.255.255.252");
    netaddr_pton(&ref[30], "255.255.255.254");
    netaddr_pton(&ref[31], "255.255.255.255");
    for (netaddr_prefixlen_t i = 0; i < 32; ++i) {
        netaddr_mask_from_prefix(&from, IP4, i + 1);
        cr_assert_eq(netaddr_eq(&from, &ref[i]), true);
    }
}

Test(netaddr_mask, mask_mac)
{
    netaddr_t mac, mask1, mask2, tmp;

    netaddr_pton(&mac,   "ff:ff:ff:ff:ff:ff");
    netaddr_pton(&mask1, "aa:aa:aa:aa:aa:aa");
    netaddr_pton(&mask2, "55:55:55:55:55:55");

    netaddr_mask(&tmp, &mac, &mask1);
    cr_assert_eq(netaddr_eq(&tmp, &mask1), true);
    netaddr_mask(&tmp, &mac, &mask2);
    cr_assert_eq(netaddr_eq(&tmp, &mask2), true);
}

Test(netaddr_mask, mask_ipv4)
{
    netaddr_t ip4, mask1, mask2, tmp;

    netaddr_pton(&ip4,   "255.255.255.255");
    netaddr_pton(&mask1, "170.170.170.170");
    netaddr_pton(&mask2, "85.85.85.85");

    netaddr_mask(&tmp, &ip4, &mask1);
    cr_assert_eq(netaddr_eq(&tmp, &mask1), true);
    netaddr_mask(&tmp, &ip4, &mask2);
    cr_assert_eq(netaddr_eq(&tmp, &mask2), true);
}

Test(netaddr_mask, mask_ipv6)
{
    netaddr_t ip6, mask1, mask2, tmp;

    netaddr_pton(&ip6,   "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
    netaddr_pton(&mask1, "aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa");
    netaddr_pton(&mask2, "5555:5555:5555:5555:5555:5555:5555:5555");

    netaddr_mask(&tmp, &ip6, &mask1);
    cr_assert_eq(netaddr_eq(&tmp, &mask1), true);
    netaddr_mask(&tmp, &ip6, &mask2);
    cr_assert_eq(netaddr_eq(&tmp, &mask2), true);
}
