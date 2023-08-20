#include "oshd.h"
#include "device.h"
#include "netroute.h"
#include "events.h"
#include "logger.h"
#include "xalloc.h"
#include <stdlib.h>
#include <string.h>

// Solve dynamic IP address conflicts when using the dynamic device mode

// FIXME: This conflict solving works if two nodes use the same address, if more
//        than two nodes use the same address at the same time it will likely
//        break or not work (some nodes may advertise a static route with an
//        incorrect owner)

struct conflict_routes {
    node_id_t *chg;        // The node that changes its address
    node_id_t *keeps;      // The node that keeps it
    dynamic_addr_t *daddr; // The conflicting dynamic address
};

// Delete the current dynamic address and add a new random one
static bool change_addr(struct conflict_routes *cr)
{
    // Make sure that there is a TUN/TAP device
    if (!oshd.tuntap)
        return false;

    // First delete the conflicting address from the TUN/TAP device
    if (!device_dynamic_del(oshd.tuntap, cr->daddr))
        return false;

    // Delete and add the conflicting address to the routing table with the
    // correct owner
    netroute_del_addr(oshd.route_table, &cr->daddr->addr);
    netroute_add(oshd.route_table, &cr->daddr->addr, cr->daddr->route_prefixlen,
        cr->keeps, ROUTE_NEVER_EXPIRE);

    // Generate a new random dynamic address of the correct type
    switch (cr->daddr->addr.type) {
        case IP6: device_dynamic_gen_addr6_random(cr->daddr); break;
        case IP4: device_dynamic_gen_addr4_random(cr->daddr); break;
        default: return false;
    }

    logger(LOG_INFO, "New dynamic address: %s/%s", cr->daddr->addr_str,
        cr->daddr->prefixlen_str);

    // Add the new address to the TUN/TAP device ..
    if (!device_dynamic_add(oshd.tuntap, cr->daddr))
        return false;

    // .. to the routing table ..
    netroute_add(oshd.route_table, &cr->daddr->addr, cr->daddr->route_prefixlen,
        cr->chg, ROUTE_NEVER_EXPIRE);

    // .. and advertise it to the mesh
    client_queue_route_add_local(NULL, &cr->daddr->addr, 1, false);

    return true;
}

// Keep the current dynamic address
static void keep_addr(struct conflict_routes *cr)
{
    // Delete and add the conflicting address to the routing table with the
    // correct owner
    netroute_del_addr(oshd.route_table, &cr->daddr->addr);
    netroute_add(oshd.route_table, &cr->daddr->addr, cr->daddr->route_prefixlen,
        cr->keeps, ROUTE_NEVER_EXPIRE);

    // Advertise it to the mesh
    client_queue_route_add_local(NULL, &cr->daddr->addr, 1, false);
}

static time_t dynamic_ip_conflict_handler(
    __attribute__((unused)) const event_t *event,
    __attribute__((unused)) const struct timespec *delay,
    void *data)
{
    struct conflict_routes *cr = (struct conflict_routes *) data;

    logger(LOG_INFO,
        "Solving dynamic address conflict: %s keeps the address, %s changes",
        cr->keeps->name, cr->chg->name);

    if (cr->chg->local_node) {
        if (!change_addr(cr))
            logger(LOG_ERR, "Failed to change dynamic address");
    } else {
        keep_addr(cr);
    }

    return EVENT_IS_DONE;
}

static void dynamic_ip_conflict_freedata(
    __attribute__((unused)) const event_t *event,
    void *data)
{
    struct conflict_routes *cr = (struct conflict_routes *) data;

    cr->daddr->handling_conflict = false;
    free(data);
}

// TODO: After handling a conflict add a delay before trying to solve another
//       conflict on the same dynamic_addr_t
void event_queue_dynamic_ip_conflict(node_id_t *s1, node_id_t *s2,
    const netaddr_t *addr)
{
    struct conflict_routes *data;
    dynamic_addr_t *daddr;

    // If the device mode is not dynamic Osh doesn't solve conflicts itself
    if (oshd.device_mode != MODE_DYNAMIC || !oshd.tuntap)
        return;

    // Make sure that both pointers are valid and that they are different
    if (!s1 || !s2 || s1 == s2)
        return;

    // Make sure that one of the conflicting nodes is us
    if (!s1->local_node && !s2->local_node)
        return;

    // Find the conflicting dynamic address
    daddr = NULL;
    for (size_t i = 0; i < dynamic_addr_count; ++i) {
        if (netaddr_eq(&oshd.dynamic_addrs[i].addr, addr)) {
            daddr = &oshd.dynamic_addrs[i];
            break;
        }
    }

    // If the dynamic address was not found the conflict is about an address
    // which we don't control
    if (!daddr)
        return;

    // If the dynamic address is already solving a conflict, stop here
    if (daddr->handling_conflict)
        return;

    daddr->handling_conflict = true;

    data = xzalloc(sizeof(struct conflict_routes));
    data->chg = s1;
    data->keeps = s2;
    data->daddr = daddr;

    // Sort the nodes with their names (as they are unique) to decide which gets
    // to keep the address and which will change
    if (strcmp(data->chg->name, data->keeps->name) > 0) {
        node_id_t *tmp = data->chg;

        data->chg = data->keeps;
        data->keeps = tmp;
    }

    event_queue_now(event_create(
            "dynamic_ip_conflict",
            dynamic_ip_conflict_handler,
            dynamic_ip_conflict_freedata,
            data));
}
