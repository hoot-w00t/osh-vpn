#include "oshd.h"
#include "xalloc.h"
#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Dump the remote routes
void oshd_route_dump(void)
{
    char addr[INET6_ADDRSTRLEN];

    printf("Dumping routes:\n");
    for (size_t i = 0; i < oshd.routes_count; ++i) {
        netaddr_ntop(addr, sizeof(addr), &oshd.routes[i]->addr);
        printf("    %s -> %s\n", addr, oshd.routes[i]->dest_node->name);
    }
}

// Dump the local routes
void oshd_route_dump_local(void)
{
    char addr[INET6_ADDRSTRLEN];

    printf("Dumping local routes:\n");
    for (size_t i = 0; i < oshd.local_routes_count; ++i) {
        netaddr_ntop(addr, sizeof(addr), oshd.local_routes + i);
        printf("    %s\n", addr);
    }
}

// Find *addr in the routing table
// Returns NULL if the route doesn't exist
oshd_route_t *oshd_route_find(const netaddr_t *addr)
{
    for (size_t i = 0; i < oshd.routes_count; ++i) {
        if (netaddr_eq(addr, &oshd.routes[i]->addr))
            return oshd.routes[i];
    }
    return NULL;
}

// Add a new route to the routing table
// If it already exists, overwrites the previous destination node with the one
// given as argument
oshd_route_t *oshd_route_add(const netaddr_t *addr, node_id_t *dest_node)
{
    oshd_route_t *route = oshd_route_find(addr);

    if (!route) {
        // Allocate the new route
        route = xalloc(sizeof(oshd_route_t));
        oshd.routes = xrealloc(oshd.routes,
            sizeof(oshd_route_t *) * (oshd.routes_count + 1));
        oshd.routes[oshd.routes_count] = route;
        oshd.routes_count += 1;

        netaddr_cpy(&route->addr, addr);
    }
    route->dest_node = dest_node;
    return route;
}

// Free *route and its allocated resources
void oshd_route_free(oshd_route_t *route)
{
    // A function for just one free is useless but if one day there are more
    // resources to free in the structure it'll be easy to add here
    free(route);
}

// Delete all routes that don't have a dest_node->next_hop
void oshd_route_del_orphan_routes(void)
{
    bool changed = false;
    size_t i = 0;

    logger_debug(DBG_ROUTING, "Deleting orphan routes");
    while (i < oshd.routes_count) {
        if (!oshd.routes[i]->dest_node->next_hop) {
            changed = true;

            oshd_route_free(oshd.routes[i]);

            if (i + 1 < oshd.routes_count) {
                // Shift the remaining route pointers, overwriting the orphan
                // route, if there are more routes after this one
                memmove(&oshd.routes[i], &oshd.routes[i + 1],
                    sizeof(oshd_route_t *) * (oshd.routes_count - i - 1));
            }
            oshd.routes_count -= 1;
            oshd.routes = xrealloc(oshd.routes,
                sizeof(oshd_route_t *) * oshd.routes_count);
        } else {
            // We only increment our iterator if the route wasn't removed,
            // because if we removed one the next will be shifted at the same
            // position
            ++i;
        }
    }
    if (changed) {
        if (logger_is_debugged(DBG_ROUTING))
            oshd_route_dump();
        oshd_resolver_update();
    }
}

// Add a new local route
// Returns true if the route was added to the local routes
// Returns false if it already exists
bool oshd_route_add_local(const netaddr_t *addr)
{
    for (size_t i = 0; i < oshd.local_routes_count; ++i) {
        if (netaddr_eq(&oshd.local_routes[i], addr))
            return false;
    }

    oshd.local_routes = xrealloc(oshd.local_routes,
        sizeof(netaddr_t) * (oshd.local_routes_count + 1));
    netaddr_cpy(&oshd.local_routes[oshd.local_routes_count], addr);
    oshd.local_routes_count += 1;
    oshd_resolver_update();

    if (logger_is_debugged(DBG_ROUTING))
        oshd_route_dump_local();
    return true;
}