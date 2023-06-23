#include "netroute.h"
#include "events.h"
#include "macros_assert.h"
#include "xalloc.h"
#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Hash table value comparator, s1 must point to a netroute_t and vctx must point
// to a node_id_t
// Returns true if the route owner is the same as the one passed in vctx
static bool netroute_owner_cmp_eq(const void *s1, size_t s1_len, void *vctx)
{
    const netroute_t *route = (const netroute_t *) s1;
    const node_id_t *owner = (const node_id_t *) vctx;

    assert(s1_len == sizeof(*route));
    return route->owner == owner;
}

// Hash table value comparator, s1 must point to a netroute_t
// Returns true if the route is orphan (owned by an offline node)
static bool _netroute_orphan_cmp_eq(const void *s1, size_t s1_len,
    __attribute__((unused)) void *vctx)
{
    const netroute_t *route = (const netroute_t *) s1;

    assert(s1_len == sizeof(*route));
    return  route->owner
        && !route->owner->online
        && !route->owner->local_node;
}

struct netroute_expired_cmp_eq_ctx {
    struct timespec now;
    time_t *next_expire;
};

// Hash table value comparator, s1 must point to a netroute_t and vctx must point
// to a struct netroute_expired_cmp_eq_ctx
// Returns true if the route has expired
static bool netroute_expired_cmp_eq(const void *s1, size_t s1_len, void *vctx)
{
    const netroute_t *route = (const netroute_t *) s1;
    struct netroute_expired_cmp_eq_ctx *ctx = (struct netroute_expired_cmp_eq_ctx *) vctx;
    struct timespec delta;

    assert(s1_len == sizeof(*route));
    timespecsub(&route->expire_after, &ctx->now, &delta);

    if (delta.tv_sec < 0) {
        // Route has expired
        return route->can_expire;
    } else {
        // Route has not expired
        if ((delta.tv_sec + 1) < *(ctx->next_expire))
            *(ctx->next_expire) = (delta.tv_sec + 1);
        return false;
    }
}

// Initialize a netroute_t
static void netroute_init(netroute_t *route, const netaddr_t *addr,
    netaddr_prefixlen_t prefixlen, node_id_t *owner)
{
    netaddr_cpy(&route->addr, addr);
    if (prefixlen > netaddr_max_prefixlen(addr->type)) {
        route->prefixlen = netaddr_max_prefixlen(addr->type);
    } else {
        route->prefixlen = prefixlen;
    }
    netaddr_mask_from_prefix(&route->mask, addr->type, route->prefixlen);
    route->owner = owner;
}

// Create a new netroute_mask_t
static netroute_mask_t *netroute_mask_create(const netaddr_t *mask,
    netaddr_prefixlen_t prefixlen)
{
    netroute_mask_t *rmask = xzalloc(sizeof(netroute_mask_t));

    netaddr_cpy(&rmask->mask, mask);
    rmask->prefixlen = prefixlen;
    return rmask;
}

// Free netroute_mask_t
static void netroute_mask_free(netroute_mask_t *rmask)
{
    free(rmask);
}

// Free all the linked netroute_mask_t
static void netroute_mask_free_all(netroute_mask_t *head)
{
    netroute_mask_t *rmask = head;
    netroute_mask_t *next;

    while (rmask) {
        next = rmask->next;
        netroute_mask_free(rmask);
        rmask = next;
    }
}

// Return the matching netroute_mask_t, or NULL if it is not found
static netroute_mask_t *netroute_mask_find(netroute_table_t *table,
    const netaddr_t *mask, netaddr_prefixlen_t prefixlen)
{
    netroute_mask_t *head;

    switch (mask->type) {
        case MAC: head = table->masks_mac; break;
        case IP4: head = table->masks_ip4; break;
        case IP6: head = table->masks_ip6; break;
         default: return NULL;
    }

    foreach_netroute_mask_head(rmask, head) {
        if (rmask->prefixlen == prefixlen && netaddr_eq(&rmask->mask, mask))
            return rmask;
    }
    return NULL;
}

// Add a network mask to the table
static netroute_mask_t *netroute_add_mask(netroute_table_t *table,
    const netaddr_t *mask, netaddr_prefixlen_t prefixlen)
{
    netroute_mask_t *rmask = netroute_mask_find(table, mask, prefixlen);
    netroute_mask_t **it;

    // Stop here if the mask is already in the list
    if (rmask)
        return rmask;

    // Select the correct mask list
    switch (mask->type) {
        case MAC: it = &table->masks_mac; break;
        case IP4: it = &table->masks_ip4; break;
        case IP6: it = &table->masks_ip6; break;
         default: return NULL;
    }

    // Validate the prefix length
    if (prefixlen > netaddr_max_prefixlen(mask->type))
        prefixlen = netaddr_max_prefixlen(mask->type);

    // Sort the masks from highest prefix length to smallest
    while (*it) {
        // If the prefix length is bigger, insert it here
        if (prefixlen > (*it)->prefixlen)
            break;

        it = &(*it)->next;
    }

    // Create and insert this new mask in the list
    rmask = netroute_mask_create(mask, prefixlen);
    rmask->next = *it;
    *it = rmask;

    if (logger_is_debugged(DBG_NETROUTE)) {
        char addrw[NETADDR_ADDRSTRLEN];

        netaddr_ntop(addrw, sizeof(addrw), &rmask->mask);
        logger_debug(DBG_NETROUTE, "Added mask %s/%u to %p",
            addrw, rmask->prefixlen, (void *) table);
    }

    return *it;
}

// Delete a network mask from the table
static bool netroute_del_mask(netroute_table_t *table, netroute_mask_t *rmask)
{
    netroute_mask_t **it;

    // Select the correct mask list
    switch (rmask->mask.type) {
        case MAC: it = &table->masks_mac; break;
        case IP4: it = &table->masks_ip4; break;
        case IP6: it = &table->masks_ip6; break;
         default: return false;
    }

    // Look for rmask
    while (*it) {
        if (*it == rmask) {
            // Delete rmask from the list
            *it = (*it)->next;

            if (logger_is_debugged(DBG_NETROUTE)) {
                char addrw[NETADDR_ADDRSTRLEN];

                netaddr_ntop(addrw, sizeof(addrw), &rmask->mask);
                logger_debug(DBG_NETROUTE, "Deleted mask %s/%u from %p",
                    addrw, rmask->prefixlen, (void *) table);
            }

            netroute_mask_free(rmask);
            return true;
        }
        it = &(*it)->next;
    }

    return false;
}

// Hash table remove callback
// data must point to the netroute_table_t that owns the route
// Updates route counts and masks after a route is deleted
static void netroute_ht_remove_cb(hashtable_item_t *item, void *data)
{
    netroute_t *route = (netroute_t *) item->value;
    netroute_table_t *table = (netroute_table_t *) data;
    netroute_mask_t *rmask;

    // Update the route counts
    table->total_routes -= 1;
    if (route->owner)
        table->total_owned_routes -= 1;

    // Decrement the mask's use count and delete it if it reaches zero
    rmask = netroute_mask_find(table, &route->mask, route->prefixlen);
    if (rmask) {
        if (rmask->use_count > 0)
            rmask->use_count -= 1;
        if (rmask->use_count == 0)
            netroute_del_mask(table, rmask);
    }

    if (logger_is_debugged(DBG_NETROUTE)) {
        char addrw[NETADDR_ADDRSTRLEN];

        netaddr_ntop(addrw, sizeof(addrw), &route->addr);
        logger_debug(DBG_NETROUTE, "Deleted %s/%u owned by %s from %p",
            addrw, route->prefixlen, netroute_owner_name(route), (void *) table);
    }
}

// Allocate an empty route table
netroute_table_t *netroute_table_create(void)
{
    netroute_table_t *table = xzalloc(sizeof(netroute_table_t));

    table->ht = hashtable_create_netaddr_autoresize(32, 32768, 4, 0);
    hashtable_set_remove_cb(table->ht, netroute_ht_remove_cb, table);
    logger_debug(DBG_NETROUTE, "Created table %p", (void *) table);
    return table;
}

// Free route table
void netroute_table_free(netroute_table_t *table)
{
    if (table) {
        logger_debug(DBG_NETROUTE, "Freeing table %p", (void *) table);
        netroute_table_clear(table);
        hashtable_free(table->ht);
        netroute_mask_free_all(table->masks_mac);
        netroute_mask_free_all(table->masks_ip4);
        netroute_mask_free_all(table->masks_ip6);
        free(table);
    }
}

// Delete all routes from the table
void netroute_table_clear(netroute_table_t *table)
{
    logger_debug(DBG_NETROUTE, "Clearing table %p", (void *) table);
    hashtable_clear(table->ht);
}

// Looks up addr in the table, returns a netroute_t pointer if it is found
// Returns NULL otherwise
const netroute_t *netroute_lookup(netroute_table_t *table, const netaddr_t *addr)
{
    netroute_mask_t *head;
    netaddr_t result;
    hashtable_item_t *item;

    switch (addr->type) {
        case MAC: head = table->masks_mac; break;
        case IP4: head = table->masks_ip4; break;
        case IP6: head = table->masks_ip6; break;
         default: return NULL;
    }

    foreach_netroute_mask_head(rmask, head) {
        netaddr_mask(&result, addr, &rmask->mask);
        item = hashtable_lookup(table->ht, &result, sizeof(result));
        if (item)
            return (const netroute_t *) item->value;
    }
    return NULL;
}

// Add a new route to the table
// The prefix length is used to create and add the corresponding network mask to
// the table
//
// If the network address already exists:
// - owner will be updated if both are not NULL
// - can_expire will keep its initial value
//
// The route will expire after expire_in seconds if this value is positive
// If expire_in if <= 0 the route never expires
// Returns a pointer to the netroute_t from the table
const netroute_t *netroute_add(netroute_table_t *table,
    const netaddr_t *addr, netaddr_prefixlen_t prefixlen,
    node_id_t *owner, time_t expire_in)
{
    hashtable_item_t *item = hashtable_lookup(table->ht, addr, sizeof(*addr));
    netroute_t *route;

    if (item) {
        route = (netroute_t *) item->value;
    } else {
        netroute_mask_t *rmask;

        // The route doesn't exist, create it and append it to the list
        item = hashtable_insert(table->ht, addr, sizeof(*addr), NULL, sizeof(netroute_t));
        route = (netroute_t *) item->value;

        // Initialize the new route
        netroute_init(route, addr, prefixlen, owner);
        table->total_routes += 1;
        if (owner)
            table->total_owned_routes += 1;

        // Add the route's mask to the table
        rmask = netroute_add_mask(table, &route->mask, route->prefixlen);
        if (rmask)
            rmask->use_count += 1;

        route->can_expire = expire_in > 0;
    }

    // Update the owner if none of the two are NULL
    if (route->owner && owner) {
        // If the route's owner changes two nodes may be using the same
        // address/route, log a warning just in case (only for our own routes)
        if (   route->owner != owner
            && (route->owner->local_node || owner->local_node))
        {
            char addrw[NETADDR_ADDRSTRLEN];

            netaddr_ntop(addrw, sizeof(addrw), &route->addr);
            logger(LOG_WARN,
                "Conflicting local route %s/%u previously owned by %s, now %s",
                addrw, route->prefixlen, route->owner->name, owner->name);

            // When the device mode is dynamic Osh will try to fix conflicts
            event_queue_dynamic_ip_conflict(route->owner, owner, &route->addr);
        }

        route->owner = owner;
    }

    // Update the expire_after timestamp if this route can expire
    if (route->can_expire) {
        oshd_gettime(&route->expire_after);
        if (expire_in > 0)
            route->expire_after.tv_sec += expire_in;
    }

    if (logger_is_debugged(DBG_NETROUTE)) {
        char addrw[NETADDR_ADDRSTRLEN];

        netaddr_ntop(addrw, sizeof(addrw), &route->addr);
        logger_debug(DBG_NETROUTE, "Added %s/%u owned by %s (%s expire) to %p",
            addrw, route->prefixlen, netroute_owner_name(route),
            route->can_expire ? "can" : "cannot", (void *) table);
    }

    return route;
}

// Add standard broadcast routes to the table (MAC, IPv4 and IPv6)
// These routes do not expire
void netroute_add_broadcasts(netroute_table_t *table)
{
    netaddr_t mac_broadcast;
    netaddr_t ip4_broadcast;
    netaddr_t ip6_broadcast;

    // This address must also be explicitly added as a mask to the table,
    // because the generated /48 mask will not match this address
    // x1:xx:xx:xx:xx:xx
    mac_broadcast.type = MAC;
    memset(&mac_broadcast.data.mac, 0, sizeof(mac_broadcast.data.mac));
    mac_broadcast.data.mac.addr[0] = 0x01;
    netroute_add(table, &mac_broadcast, 48, NULL, ROUTE_NEVER_EXPIRE);
    netroute_add_mask(table, &mac_broadcast, 48);

    // 224.0.0.0/4
    ip4_broadcast.type = IP4;
    ip4_broadcast.data.ip4.s_addr = htonl(0xe0000000);
    netroute_add(table, &ip4_broadcast, 4, NULL, ROUTE_NEVER_EXPIRE);

    // 255.255.255.255/32
    ip4_broadcast.data.ip4.s_addr = htonl(0xffffffff);
    netroute_add(table, &ip4_broadcast, 32, NULL, ROUTE_NEVER_EXPIRE);

    // ff00::/8
    ip6_broadcast.type = IP6;
    memset(&ip6_broadcast.data.ip6, 0, sizeof(ip6_broadcast.data.ip6));
    ((uint8_t *) &ip6_broadcast.data.ip6)[0] = 0xff;
    netroute_add(table, &ip6_broadcast, 8, NULL, ROUTE_NEVER_EXPIRE);
}

// Delete route that matches addr from the table
void netroute_del_addr(netroute_table_t *table, const netaddr_t *addr)
{
    hashtable_remove_key(table->ht, addr, sizeof(*addr));
}

// Delete all routes owned by owner from the table
// This function does not delete NULL owners
void netroute_del_owner(netroute_table_t *table, node_id_t *owner)
{
    // Don't remove routes without owners
    if (owner) {
        hashtable_remove_value_ctx(table->ht, netroute_owner_cmp_eq, owner);
    }
}

// Delete all orphan routes from the table
bool netroute_del_orphan_owners(netroute_table_t *table)
{
    return hashtable_remove_value_ctx(table->ht, _netroute_orphan_cmp_eq, NULL) != 0;
}

// Delete all expired routes from the table
// next_expire will contain the delay in seconds of the next route expiry
// next_expire will be limited to next_expire_max seconds
// Returns true if routes were deleted, false otherwise
bool netroute_del_expired(netroute_table_t *table, time_t *next_expire,
    time_t next_expire_max)
{
    struct netroute_expired_cmp_eq_ctx ctx;
    size_t removed_count;

    oshd_gettime(&ctx.now);
    ctx.next_expire = next_expire;

    *next_expire = next_expire_max;
    removed_count = hashtable_remove_value_ctx(table->ht, netroute_expired_cmp_eq, &ctx);

    if (*next_expire <= 0 || *next_expire > next_expire_max)
        *next_expire = next_expire_max;

    return removed_count != 0;
}

// Dump all routes to outfile
void netroute_dump_to(netroute_table_t *table, FILE *outfile)
{
    char addrw[NETADDR_ADDRSTRLEN];

    hashtable_foreach_const(item, table->ht, it) {
        const netroute_t *route = (const netroute_t *) item->value;

        netaddr_ntop(addrw, sizeof(addrw), &route->addr);
        fprintf(outfile, "\t%s owned by %s\n",
            addrw, netroute_owner_name(route));
    }
    fflush(outfile);
}

// Dump all routes to stdout
void netroute_dump(netroute_table_t *table)
{
    netroute_dump_to(table, stdout);
}
