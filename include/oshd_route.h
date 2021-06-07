#ifndef _OSH_OSHD_ROUTE_H
#define _OSH_OSHD_ROUTE_H

#include "node.h"

typedef struct oshd_route oshd_route_t;

struct oshd_route {
    // Network address
    netaddr_t addr;

    // Which node to send packets which have addr as their destination
    node_id_t *dest_node;
};

void oshd_route_dump(void);
void oshd_route_dump_local(void);

oshd_route_t *oshd_route_find(const netaddr_t *addr);
oshd_route_t *oshd_route_add(const netaddr_t *addr, node_id_t *dest_node);
void oshd_route_free(oshd_route_t *route);
void oshd_route_del_orphan_routes(void);

bool oshd_route_add_local(const netaddr_t *addr);

#endif