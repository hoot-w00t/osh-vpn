#ifndef _OSH_OSHD_ROUTE_H
#define _OSH_OSHD_ROUTE_H

#include "node.h"

typedef struct netroute netroute_t;

struct netroute {
    // Network address
    netaddr_t addr;

    // Which node to send packets which have addr as their destination
    node_id_t *dest_node;
};

void netroute_dump(void);
void netroute_dump_local(void);

netroute_t *netroute_find(const netaddr_t *addr);
netroute_t *netroute_add(const netaddr_t *addr, node_id_t *dest_node);
void netroute_free(netroute_t *route);
void netroute_del_orphan_routes(void);

bool netroute_add_local(const netaddr_t *addr);

#endif