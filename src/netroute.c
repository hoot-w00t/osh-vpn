#include "netroute.h"
#include "xalloc.h"
#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Create a new netroute_t
static netroute_t *netroute_create(const netaddr_t *addr,
    const netroute_hash_t addr_hash, node_id_t *owner)
{
    netroute_t *route = xzalloc(sizeof(netroute_t));

    netaddr_cpy(&route->addr, addr);
    route->addr_hash = addr_hash;
    route->owner = owner;
    return route;
}

// Free netroute_t
static void netroute_free(netroute_t *route)
{
    free(route);
}

// Free all the linked netroute_t
static void netroute_free_all(netroute_t *head)
{
    netroute_t *route = head;
    netroute_t *next;

    while (route) {
        next = route->next;
        netroute_free(route);
        route = next;
    }
}

// Allocate an empty route table
netroute_table_t *netroute_table_create(size_t hash_table_size)
{
    netroute_table_t *table = xzalloc(sizeof(netroute_table_t));

    table->heads_count = hash_table_size;
    if (table->heads_count == 0)
        table->heads_count = 1;

    table->heads = xzalloc(sizeof(netroute_t *) * table->heads_count);
    return table;
}

// Free route table
void netroute_table_free(netroute_table_t *table)
{
    if (table) {
        netroute_table_clear(table);
        free(table->heads);
        free(table);
    }
}

// Delete all routes from the table
void netroute_table_clear(netroute_table_t *table)
{
    for (size_t i = 0; i < table->heads_count; ++i) {
        netroute_free_all(table->heads[i]);
        table->heads[i] = NULL;
    }
    table->total_routes = 0;
    table->total_owned_routes = 0;
}

// Search through all routes in the linked list for a matching address
static inline netroute_t *netroute_find_head(
    netroute_t *head, const netaddr_t *addr)
{
    foreach_netroute_head(route, head) {
        if (netaddr_eq(&route->addr, addr))
            return route;
    }
    return NULL;
}

// Returns a pointer to the netroute_t with the given network address
// Returns NULL if no routes match
netroute_t *netroute_find(netroute_table_t *table, const netaddr_t *addr)
{
    const netroute_hash_t hash = netroute_hash(table, addr);

    return netroute_find_head(table->heads[hash], addr);
}

static netroute_t *netroute_insert(netroute_table_t *table,
    const netaddr_t *addr, const netroute_hash_t addr_hash, node_id_t *owner)
{
    netroute_t **it = &table->heads[addr_hash];

    while (*it)
        it = &(*it)->next;
    *it = netroute_create(addr, addr_hash, owner);
    table->total_routes += 1;
    if (owner)
        table->total_owned_routes += 1;
    return *it;
}

// Add a new route to the table
//
// If refresh is true the route's last_refresh timestamp will be updated to the
// current time
// If the network address already exists its owner will be updated to this one
// (only if there was an owner and there is still one, owner cannot be updated
//  to NULL or from NULL)
//
// Returns a pointer to the netroute_t from the table
netroute_t *netroute_add(netroute_table_t *table, const netaddr_t *addr,
    node_id_t *owner, bool refresh)
{
    const netroute_hash_t hash = netroute_hash(table, addr);
    netroute_t *route = netroute_find_head(table->heads[hash], addr);

    if (!route) {
        // The route doesn't exist, create it and append it to the list
        route = netroute_insert(table, addr, hash, owner);
    }

    // Update the owner if none of the two are NULL
    if (route->owner && owner)
        route->owner = owner;

    if (refresh) {
        // Update the last_refresh timestamp
        oshd_gettime(&route->last_refresh);
    }

    if (logger_is_debugged(DBG_NETROUTE)) {
        char addrw[INET6_ADDRSTRLEN];

        netaddr_ntop(addrw, sizeof(addrw), addr);
        logger_debug(DBG_NETROUTE, "Added %s owned by %s (refreshed: %i) to %p",
            addrw, netroute_owner_name(route), refresh, table);
    }

    return route;
}

// Delete route from the table
static bool netroute_del(netroute_table_t *table, netroute_t *route)
{
    netroute_t **it = &table->heads[route->addr_hash];

    while (*it) {
        if (*it == route) {
            // Remove the route from the linked list
            *it = (*it)->next;
            table->total_routes -= 1;
            if (route->owner)
                table->total_owned_routes -= 1;

            if (logger_is_debugged(DBG_NETROUTE)) {
                char addrw[INET6_ADDRSTRLEN];

                netaddr_ntop(addrw, sizeof(addrw), &route->addr);
                logger_debug(DBG_NETROUTE, "Deleted %s owned by %s from %p",
                    addrw, netroute_owner_name(route), table);
            }

            netroute_free(route);
            return true;
        }
        it = &(*it)->next;
    }
    return false;
}

// Delete route that matches addr from the table
// TODO: Optimize this function by doing the comparison and removal here
//       instead of calling netroute_del
void netroute_del_addr(netroute_table_t *table, const netaddr_t *addr)
{
    netroute_t *route = netroute_find(table, addr);

    if (route)
        netroute_del(table, route);
}

// Delete all routes owned by owner from the table
// This function does not delete NULL owners
void netroute_del_owner(netroute_table_t *table, node_id_t *owner)
{
    netroute_t *route;
    netroute_t *next;

    // Don't remove routes without owners
    if (!owner)
        return;

    for (size_t i = 0; i < table->heads_count; ++i) {
        route = table->heads[i];

        while (route) {
            next = route->next;
            if (route->owner == owner)
                netroute_del(table, route);
            route = next;
        }
    }
}

// Delete all expired routes from the table
// Routes expire if expire_secs seconds or more have elapsed since last_refresh
// Routes without an owner do not expire
// next_expire will contain the delay in seconds of the next route expiry
// Returns true if routes were deleted, false otherwise
bool netroute_del_expired(netroute_table_t *table, const time_t expire_secs,
    time_t *next_expire)
{
    struct timespec now;
    struct timespec delta;
    netroute_t *route;
    netroute_t *next;
    bool deleted = false;

    oshd_gettime(&now);
    *next_expire = expire_secs;
    for (size_t i = 0; i < table->heads_count; ++i) {
        route = table->heads[i];

        while (route) {
            next = route->next;

            timespecsub(&now, &route->last_refresh, &delta);
            if (delta.tv_sec >= expire_secs) {
                if (route->owner) {
                    netroute_del(table, route);
                    deleted = true;
                }
            } else {
                if ((expire_secs - delta.tv_sec) < *next_expire)
                    *next_expire = (expire_secs - delta.tv_sec) + 1;
            }

            route = next;
        }
    }

    if (*next_expire <= 0 || *next_expire > expire_secs)
        *next_expire = expire_secs;

    return deleted;
}

// Dump all routes to outfile
void netroute_dump_to(netroute_table_t *table, FILE *outfile)
{
    char addrw[INET6_ADDRSTRLEN];

    foreach_netroute(route, table, i) {
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