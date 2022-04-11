#include "netroute.h"
#include <criterion/criterion.h>

#define fuzz_seed (0)

Test(netroute_table_t, invalid_table_size)
{
    netroute_table_t *table = netroute_table_create(0);

    cr_assert_not_null(table);
    cr_assert_eq(table->heads_count, 1);
    netroute_table_free(table);
}

static void rand_bytes(const void *ptr, size_t size)
{
    for (size_t i = 0; i < size; ++i)
        *((uint8_t *) (ptr + i)) = rand() % 256;
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

static void fuzz_netroute_table(const size_t size, const size_t addr_count,
    const uint32_t seed)
{
    netroute_table_t *table;
    netroute_t *route;
    netaddr_t addr;
    struct timespec zero_ts;

    zero_ts.tv_sec = 0;
    zero_ts.tv_nsec = 0;
    srand(seed);
    table = netroute_table_create(size);

    cr_assert_not_null(table);
    cr_assert_not_null(table->heads);
    cr_assert_eq(table->heads_count, size);
    for (size_t i = 0; i < table->heads_count; ++i)
        cr_assert_null(table->heads[i]);

    cr_assert_eq(table->total_routes, 0);
    cr_assert_eq(table->total_owned_routes, 0);

    for (size_t i = 0; i < addr_count; ++i) {
        const bool can_expire = (rand() % 2) == 0;

        rand_addr(&addr);
        route = netroute_add(table, &addr, netaddr_max_prefixlen(addr.type),
            NULL, can_expire);

        cr_assert_not_null(route);
        cr_assert_eq(netaddr_eq(&route->addr, &addr), true);
        cr_assert_eq(route->addr_hash, netroute_hash(table, &addr));
        if (can_expire) {
            cr_assert_neq(route->last_refresh.tv_sec, zero_ts.tv_sec);
            cr_assert_neq(route->last_refresh.tv_nsec, zero_ts.tv_nsec);
        } else {
            cr_assert_eq(route->last_refresh.tv_sec, zero_ts.tv_sec);
            cr_assert_eq(route->last_refresh.tv_nsec, zero_ts.tv_nsec);
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

Test(netroute_table_t, fuzz_table_size_1_with_16384_addr)
{
    fuzz_netroute_table(1, 16384, fuzz_seed);
}

Test(netroute_table_t, fuzz_table_size_128_with_16384_addr)
{
    fuzz_netroute_table(128, 16384, fuzz_seed);
}

Test(netroute_table_t, fuzz_table_size_512_with_16384_addr)
{
    fuzz_netroute_table(512, 16384, fuzz_seed);
}

Test(netroute_table_t, fuzz_table_size_1024_with_16384_addr)
{
    fuzz_netroute_table(1024, 16384, fuzz_seed);
}

Test(netroute_table_t, fuzz_table_size_4096_with_16384_addr)
{
    fuzz_netroute_table(4096, 16384, fuzz_seed);
}