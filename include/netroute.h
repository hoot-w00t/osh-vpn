#ifndef _OSH_NETROUTE_H
#define _OSH_NETROUTE_H

#include "oshd_clock.h"
#include "node.h"
#include "hashtable.h"
#include <stdio.h>
#include <stddef.h>

// Local routes expire sooner than remote routes so that Osh can advertise them
// to other nodes before they expire there
// Remote routes expire after 5 minutes
// Local routes expire after 4 minutes
#define ROUTE_REMOTE_EXPIRY (300)
#define ROUTE_LOCAL_EXPIRY (240)
#define ROUTE_NEVER_EXPIRE (0)

typedef struct netroute netroute_t;
typedef struct netroute_mask netroute_mask_t;
typedef struct netroute_table netroute_table_t;
typedef uint32_t netroute_hash_t;

struct netroute {
    // Network address
    netaddr_t addr;
    netaddr_t mask;
    netaddr_prefixlen_t prefixlen;

    // The node owning this network address
    node_id_t *owner;

    // Time after which this route will expire (if it should)
    bool can_expire;
    struct timespec expire_after;
};

struct netroute_mask {
    // Network mask
    netaddr_t mask;
    netaddr_prefixlen_t prefixlen;

    // Number of routes using this mask
    size_t use_count;

    // Next item in the linked list
    netroute_mask_t *next;
};

struct netroute_table {
    // Hash table of all routes
    hashtable_t *ht;

    // Total number of routes in the table
    size_t total_routes;

    // Total number of routes with an owner in the table
    size_t total_owned_routes;

    // Masks used in the table
    netroute_mask_t *masks_mac;
    netroute_mask_t *masks_ip4;
    netroute_mask_t *masks_ip6;
};

netroute_table_t *netroute_table_create(void);
void netroute_table_free(netroute_table_t *table);
void netroute_table_clear(netroute_table_t *table);

const netroute_t *netroute_lookup(netroute_table_t *table, const netaddr_t *addr);

const netroute_t *netroute_add(netroute_table_t *table,
    const netaddr_t *addr, netaddr_prefixlen_t prefixlen,
    node_id_t *owner, time_t expire_in);

void netroute_add_broadcasts(netroute_table_t *table);

void netroute_del_addr(netroute_table_t *table, const netaddr_t *addr);
void netroute_del_owner(netroute_table_t *table, node_id_t *owner);
bool netroute_del_orphan_owners(netroute_table_t *table);
bool netroute_del_expired(netroute_table_t *table, time_t *next_expire,
    time_t next_expire_max);

void netroute_dump_to(netroute_table_t *table, FILE *outfile);
void netroute_dump(netroute_table_t *table);

// Iterate through all netroute masks in a linked list
#define foreach_netroute_mask_head(rmask, head) \
    for (netroute_mask_t *rmask = (head); rmask; rmask = rmask->next)

static inline const char *netroute_owner_name(const netroute_t *route)
{
    return route->owner ? route->owner->name : "(broadcast)";
}

#endif
