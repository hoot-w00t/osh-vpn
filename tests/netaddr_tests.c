#include "netaddr.h"
#include <criterion/criterion.h>
#include <netinet/in.h>

Test(netaddr_dton, test_netaddr_dton)
{
    uint8_t macaddr[6] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6};
    struct in_addr sin;
    struct in6_addr sin6 = in6addr_loopback;
    netaddr_t nmac, nip4, nip6;

    sin.s_addr = htonl(INADDR_LOOPBACK);
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
    for (uint8_t i = 0; i < sizeof(src.data); ++i)
        cr_assert_eq(src.data[i], dest.data[i]);
}

Test(netaddr_dup, test_netaddr_dup)
{
    netaddr_t src;
    netaddr_t *dup;

    cr_assert_neq(netaddr_pton(&src, "01:02:03:04:05:06"), false);
    dup = netaddr_dup(&src);
    cr_assert_eq(src.type, dup->type);
    for (uint8_t i = 0; i < sizeof(src.data); ++i)
        cr_assert_eq(src.data[i], dup->data[i]);
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