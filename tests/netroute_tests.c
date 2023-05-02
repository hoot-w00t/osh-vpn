#include "netroute.h"
#include "xalloc.h"
#include <criterion/criterion.h>

#define fuzz_seed (0)

static void rand_bytes(void *ptr, size_t size)
{
    for (size_t i = 0; i < size; ++i)
        *(((uint8_t *) ptr) + i) = rand() % 256;
}

static void rand_addr(netaddr_t *addr)
{
    const netaddr_type_t type[3] = { MAC, IP4, IP6 };

    addr->type = type[rand() % 3];
    switch (addr->type) {
        case MAC:
            rand_bytes(&addr->data.mac, sizeof(addr->data.mac));
            break;
        case IP4:
            rand_bytes(&addr->data.ip4, sizeof(addr->data.ip4));
            break;
        case IP6:
            rand_bytes(&addr->data.ip6, sizeof(addr->data.ip6));
            break;
        default: abort();
    }
}

static void fuzz_netroute_table(const size_t addr_count, const uint32_t seed)
{
    netroute_table_t *table;
    const netroute_t *route;
    netaddr_t addr;
    struct timespec zero_ts;

    zero_ts.tv_sec = 0;
    zero_ts.tv_nsec = 0;
    srand(seed);
    table = netroute_table_create();

    cr_assert_not_null(table);
    cr_assert_not_null(table->ht);

    cr_assert_eq(table->total_routes, 0);
    cr_assert_eq(table->total_owned_routes, 0);

    for (size_t i = 0; i < addr_count; ++i) {
        const bool can_expire = (rand() % 2) == 0;

        rand_addr(&addr);
        route = netroute_add(table, &addr, netaddr_max_prefixlen(addr.type),
            NULL, can_expire ? ROUTE_REMOTE_EXPIRY : ROUTE_NEVER_EXPIRE);

        cr_assert_not_null(route);
        cr_assert_eq(netaddr_eq(&route->addr, &addr), true);
        if (can_expire) {
            cr_assert_neq(route->expire_after.tv_sec, zero_ts.tv_sec);
            cr_assert_neq(route->expire_after.tv_nsec, zero_ts.tv_nsec);
        } else {
            cr_assert_eq(route->expire_after.tv_sec, zero_ts.tv_sec);
            cr_assert_eq(route->expire_after.tv_nsec, zero_ts.tv_nsec);
        }
        cr_assert_eq(route->can_expire, can_expire);
        cr_assert_null(route->owner);

        cr_assert_eq(table->total_routes, i + 1);
        cr_assert_eq(table->total_owned_routes, 0);
    }

    cr_assert_eq(table->total_routes, addr_count);
    cr_assert_eq(table->total_owned_routes, 0);

    netroute_table_clear(table);

    cr_assert_eq(table->total_routes, 0);
    cr_assert_eq(table->total_owned_routes, 0);

    netroute_table_free(table);
}

Test(netroute_table_t, fuzz_table_100_addr)
{
    fuzz_netroute_table(100, fuzz_seed);
}

Test(netroute_table_t, fuzz_table_1000_addr)
{
    fuzz_netroute_table(1000, fuzz_seed);
}

Test(netroute_table_t, fuzz_table_16384_addr)
{
    fuzz_netroute_table(16384, fuzz_seed);
}

Test(netroute_table_t, route_masks_order)
{
    netroute_table_t *table = netroute_table_create();
    netaddr_t nets[32];
    netaddr_t addr;

    cr_assert_not_null(table);
    netroute_add_broadcasts(table);

    for (netaddr_prefixlen_t i = 0; i < 32; ++i) {
        addr.type = IP4;
        addr.data.ip4.s_addr = htonl(0xC0A85500 | i);
        netaddr_mask_from_prefix(&nets[i], addr.type, i + 1);
        cr_assert_not_null(netroute_add(table, &addr, i + 1, NULL,
            ROUTE_NEVER_EXPIRE));
    }

    netaddr_prefixlen_t i = 32;

    foreach_netroute_mask_head(rmask, table->masks_ip4) {
        cr_assert_gt(i, 0);
        cr_assert_eq(rmask->prefixlen, i);
        cr_assert_eq(netaddr_eq(&rmask->mask, &nets[i - 1]), true);
        i -= 1;
    }
    netroute_table_free(table);
}

Test(netroute_table_t, lookup_ipv4_networks)
{
    netroute_table_t *table = netroute_table_create();
    node_id_t *owners[3];
    netaddr_t nets[3];
    netaddr_t addr;
    const netroute_t *route;

    cr_assert_not_null(table);
    netroute_add_broadcasts(table);

    owners[0] = xzalloc(sizeof(node_id_t));
    cr_assert_eq(netaddr_pton(&nets[0], "192.168.0.0"), true);
    cr_assert_not_null(netroute_add(table, &nets[0], 16, owners[0],
        ROUTE_NEVER_EXPIRE));

    owners[1] = xzalloc(sizeof(node_id_t));
    cr_assert_eq(netaddr_pton(&nets[1], "172.16.0.0"), true);
    cr_assert_not_null(netroute_add(table, &nets[1], 12, owners[1],
        ROUTE_NEVER_EXPIRE));

    owners[2] = xzalloc(sizeof(node_id_t));
    cr_assert_eq(netaddr_pton(&nets[2], "10.0.0.0"), true);
    cr_assert_not_null(netroute_add(table, &nets[2],  8, owners[2],
        ROUTE_NEVER_EXPIRE));

    addr.type = IP4;

    // 192.168.0.0/16
    for (uint32_t i = 0; i <= 0x0000ffff; ++i) {
        addr.data.ip4.s_addr = htonl(0xC0A80000 | i);
        route = netroute_lookup(table, &addr);
        cr_assert_not_null(route);
        cr_assert_eq(route->owner, owners[0]);
    }

    // 172.16.0.0/12
    for (uint32_t i = 0; i <= 0x000fffff; ++i) {
        addr.data.ip4.s_addr = htonl(0xAC100000 | i);
        route = netroute_lookup(table, &addr);
        cr_assert_not_null(route);
        cr_assert_eq(route->owner, owners[1]);
    }

    // 10.0.0.0/8
    for (uint32_t i = 0; i <= 0x00ffffff; ++i) {
        addr.data.ip4.s_addr = htonl(0x0A000000 | i);
        route = netroute_lookup(table, &addr);
        cr_assert_not_null(route);
        cr_assert_eq(route->owner, owners[2]);
    }

    netroute_table_free(table);
}
