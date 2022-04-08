#ifndef _OSH_OSHD_ROUTE_H
#define _OSH_OSHD_ROUTE_H

#include "oshd_clock.h"
#include "node.h"

// Local routes expire sooner than remote routes so that Osh can advertise them
// to other nodes before they expire there
// Local routes expire after 30 minutes
// Remote routes expire after 60 minutes
#define ROUTE_LOCAL_EXPIRY (1800)
#define ROUTE_REMOTE_EXPIRY (ROUTE_LOCAL_EXPIRY * 2)

typedef struct oshd_route oshd_route_t;
typedef struct oshd_route_group oshd_route_group_t;

struct oshd_route {
    // Network address
    netaddr_t addr;

    // Which node to send packets which have addr as their destination
    node_id_t *dest_node;

    // Timestamp of the last time this route was advertised
    struct timespec last_refresh;

    oshd_route_t *next;
};

struct oshd_route_group {
    oshd_route_t *head;
    size_t total_count;

    oshd_route_t **remote;
    size_t remote_count;

    oshd_route_t **local;
    size_t local_count;
};

oshd_route_group_t *oshd_route_group_create(void);
void oshd_route_group_free(oshd_route_group_t *group);

oshd_route_t *oshd_route_find(oshd_route_group_t *group, const netaddr_t *addr);
oshd_route_t *oshd_route_find_in(oshd_route_t **list, size_t list_size,
    const netaddr_t *addr);

// Find addr in the routing table (MAC addresses in TAP mode, IPv4/6 in TUN)
#define oshd_route_find_remote(group, addr) \
    oshd_route_find_in((group)->remote, (group)->remote_count, addr)

// Find addr in the local routes (MAC addresses in TAP mode, IPv4/6 in TUN)
#define oshd_route_find_local(group, addr) \
    oshd_route_find_in((group)->local, (group)->local_count, addr)

oshd_route_t *oshd_route_add(oshd_route_group_t *group, const netaddr_t *addr,
    node_id_t *dest_node, bool refresh);

void oshd_route_del_addr(oshd_route_group_t *group, const netaddr_t *addr);
void oshd_route_del_dest(oshd_route_group_t *group, node_id_t *dest_node);
bool oshd_route_del_expired(oshd_route_group_t *group);
bool oshd_route_del_orphan(oshd_route_group_t *group);
void oshd_route_clear(oshd_route_group_t *group);

void oshd_route_dump_to(oshd_route_group_t *group, FILE *outfile);
void oshd_route_dump(oshd_route_group_t *group);

// Iterate through all routes from head to tail
#define foreach_oshd_route(route, group) \
    for (oshd_route_t *route = group->head; route; route = route->next)

#endif