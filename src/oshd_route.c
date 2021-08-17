#include "oshd.h"
#include "xalloc.h"
#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Allocate an empty oshd_route_group
oshd_route_group_t *oshd_route_group_create(void)
{
    oshd_route_group_t *group = xzalloc(sizeof(oshd_route_group_t));

    return group;
}

// Free route group and all allocated resources
void oshd_route_group_free(oshd_route_group_t *group)
{
    oshd_route_clear(group);
    free(group);
}

// Returns a pointer to the oshd_route_t which has the same addr
// Returns NULL if no route matches addr
// Searches through all routes
oshd_route_t *oshd_route_find(oshd_route_group_t *group, const netaddr_t *addr)
{
    foreach_oshd_route(route, group) {
        if (netaddr_eq(&route->addr, addr))
            return route;
    }
    return NULL;
}

// Same as oshd_route_find but searches through a given list for faster results
oshd_route_t *oshd_route_find_in(oshd_route_t **list, size_t list_size,
    const netaddr_t *addr)
{
    for (size_t i = 0; i < list_size; ++i) {
        if (netaddr_eq(&list[i]->addr, addr))
            return list[i];
    }
    return NULL;
}

// Returns true if the address type is compatible with the device type
// TAP devices work with MAC addresses only
// TUN devices work with IPv4/6 addresses only
// If there is no device all routes are compatible
static bool oshd_route_compatible(const netaddr_t *addr)
{
    if (!oshd.tuntap) {
        return true;
    } else if (oshd.tuntap->is_tap) {
        return addr->type == MAC;
    } else {
        return addr->type != MAC;
    }
}

// Append route to *list and update *list_count
static void oshd_route_add_to(oshd_route_t ***list, size_t *list_count,
    oshd_route_t *route)
{
    *list = xreallocarray(*list, *list_count + 1, sizeof(oshd_route_t *));
    (*list)[*list_count] = route;
    *list_count += 1;
}

// Adds a new route to the group, if refresh is true the route's last_refresh
// timestamp will be updated to the current time
// If the address already exists nothing will be changed, the timestamp will
// only be refreshed if dest_node is also the same as the route's dest_node
// Returns a pointer to the oshd_route_t from the group
// Adds the address in the relevant lists for faster searches
oshd_route_t *oshd_route_add(oshd_route_group_t *group, const netaddr_t *addr,
    node_id_t *dest_node, bool refresh)
{
    oshd_route_t *route = oshd_route_find(group, addr);

    // If the route doesn't exist already, allocate it
    if (!route) {
        // Allocate the new route
        oshd_route_t **i = &group->head;

        while (*i) i = &(*i)->next;
        *i = xzalloc(sizeof(oshd_route_t));
        route = *i;
        group->total_count += 1;

        // Initialize it
        netaddr_cpy(&route->addr, addr);
        route->dest_node = dest_node;

        // If the route is compatible with the TUN/TAP device, add it to the
        // routing table
        if (oshd_route_compatible(addr)) {
            // If the destination is our local node it belongs in the local
            // routes, otherwise it should be added to the remote routes
            if (dest_node->local_node) {
                oshd_route_add_to(&group->local, &group->local_count, route);
            } else {
                oshd_route_add_to(&group->remote, &group->remote_count, route);
            }
        }

        // If the route is an IPv4 or IPv6 it belongs in the resolver list
        if (addr->type == IP4 || addr->type == IP6)
            oshd_route_add_to(&group->resolver, &group->resolver_count, route);

        if (logger_is_debugged(DBG_ROUTING)) {
            char addrw[INET6_ADDRSTRLEN];

            netaddr_ntop(addrw, sizeof(addrw), addr);
            logger_debug(DBG_ROUTING, "Added route %s owned by %s",
                addrw, dest_node->name);
        }
        oshd_resolver_update();
    }

    if (refresh && route->dest_node == dest_node) {
        gettimeofday(&route->last_refresh, NULL);

        if (logger_is_debugged(DBG_ROUTING)) {
            char addrw[INET6_ADDRSTRLEN];

            netaddr_ntop(addrw, sizeof(addrw), addr);
            logger_debug(DBG_ROUTING, "Refreshed route %s owned by %s",
                addrw, dest_node->name);
        }
    }

    return route;
}

// Delete route from *list and update *list_count
static void oshd_route_del_from(oshd_route_t ***list, size_t *list_count,
    oshd_route_t *route)
{
    for (size_t i = 0; i < *list_count; ++i) {
        if ((*list)[i] == route) {
            if ((i + 1) < *list_count) {
                memmove(&(*list)[i], &(*list)[i + 1],
                    sizeof(oshd_route_t *) * (*list_count - i - 1));
            }
            *list_count -= 1;
            *list = xreallocarray(*list, *list_count, sizeof(oshd_route_t *));
            break;
        }
    }
}

// Delete route from group and all lists
static bool oshd_route_del(oshd_route_group_t *group, oshd_route_t *route)
{
    oshd_route_t **i = &group->head;

    while (*i) {
        if (*i == route) {
            *i = (*i)->next;
            oshd_route_del_from(&group->remote, &group->remote_count, route);
            oshd_route_del_from(&group->local, &group->local_count, route);
            oshd_route_del_from(&group->resolver, &group->resolver_count, route);
            group->total_count -= 1;

            if (logger_is_debugged(DBG_ROUTING)) {
                char addrw[INET6_ADDRSTRLEN];

                netaddr_ntop(addrw, sizeof(addrw), &route->addr);
                logger_debug(DBG_ROUTING, "Deleted route %s owned by %s",
                    addrw, route->dest_node->name);
            }

            free(route);
            return true;
        }
        i = &(*i)->next;
    }
    return false;
}

// TODO: Optimize these loops, we could perform the removal here instead of
//       calling oshd_route_del which re-iterates through the linked list at
//       every deletion

// Delete route that matches addr from the group
void oshd_route_del_addr(oshd_route_group_t *group, const netaddr_t *addr)
{
    oshd_route_t *route = oshd_route_find(group, addr);

    if (route) {
        oshd_route_del(group, route);
        oshd_resolver_update();
    }
}

// Delete route that matche dest_node from the group
void oshd_route_del_dest(oshd_route_group_t *group, node_id_t *dest_node)
{
    oshd_route_t *route = group->head;
    oshd_route_t *next;
    bool deleted = false;

    while (route) {
        next = route->next;
        if (route->dest_node == dest_node) {
            if (oshd_route_del(group, route))
                deleted = true;
        }
        route = next;
    }
    if (deleted)
        oshd_resolver_update();
}

// Delete expired routes
bool oshd_route_del_expired(oshd_route_group_t *group)
{
    struct timeval now;
    struct timeval delta;
    oshd_route_t *route = group->head;
    oshd_route_t *next;
    bool deleted = false;

    gettimeofday(&now, NULL);
    while (route) {
        bool expired = false;

        next = route->next;

        timersub(&now, &route->last_refresh, &delta);
        if (route->dest_node->local_node) {
            expired = delta.tv_sec >= ROUTE_LOCAL_EXPIRY;
        } else {
            expired = delta.tv_sec >= ROUTE_REMOTE_EXPIRY;
        }
        if (expired) {
            if (oshd_route_del(group, route))
                deleted = true;
        }

        route = next;
    }
    if (deleted)
        oshd_resolver_update();
    return deleted;
}

// Deletes all routes owned by orphan nodes
// This excludes our local node
bool oshd_route_del_orphan(oshd_route_group_t *group)
{
    bool deleted = false;

    for (size_t i = 0; i < oshd.node_tree_count; ++i) {
        if (   !oshd.node_tree[i]->next_hop
            && !oshd.node_tree[i]->local_node)
        {
            oshd_route_del_dest(group, oshd.node_tree[i]);
            deleted = true;
        }
    }
    return deleted;
}

// Deletes all routes
void oshd_route_clear(oshd_route_group_t *group)
{
    oshd_route_t *next;

    while (group->head) {
        next = group->head->next;
        free(group->head);
        group->head = next;
    }
    group->total_count = 0;

    free(group->remote);
    group->remote = NULL;
    group->remote_count = 0;

    free(group->local);
    group->local = NULL;
    group->local_count = 0;

    free(group->resolver);
    group->resolver = NULL;
    group->resolver_count = 0;

    logger_debug(DBG_ROUTING, "Cleared all routes");
    oshd_resolver_update();
}

// Dump list to outfile
static void oshd_route_dump_list_to(oshd_route_t **list, size_t list_count,
    FILE *outfile)
{
    char addrw[INET6_ADDRSTRLEN];

    for (size_t i = 0; i < list_count; ++i) {
        netaddr_ntop(addrw, sizeof(addrw), &list[i]->addr);
        fprintf(outfile, "    %s owned by %s\n", addrw, list[i]->dest_node->name);
    }
}

// Dump all routes to outfile
void oshd_route_dump_to(oshd_route_group_t *group, FILE *outfile)
{
    char addrw[INET6_ADDRSTRLEN];

    fprintf(outfile, "Routes dump (%zu):\n", group->total_count);
    foreach_oshd_route(route, group) {
        netaddr_ntop(addrw, sizeof(addrw), &route->addr);
        fprintf(outfile, "    %s owned by %s\n", addrw, route->dest_node->name);
    }

    fprintf(outfile, "\nLocal routes (%zu):\n", group->local_count);
    oshd_route_dump_list_to(group->local, group->local_count, outfile);

    fprintf(outfile, "\nRemote routes (%zu):\n", group->remote_count);
    oshd_route_dump_list_to(group->remote, group->remote_count, outfile);

    fprintf(outfile, "\nResolver routes (%zu):\n", group->resolver_count);
    oshd_route_dump_list_to(group->resolver, group->resolver_count, outfile);

    fflush(outfile);
}

// Dump all routes to stdout
void oshd_route_dump(oshd_route_group_t *group)
{
    oshd_route_dump_to(group, stdout);
}