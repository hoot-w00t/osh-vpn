#include "oshd.h"
#include "logger.h"
#include "xalloc.h"
#include <stdlib.h>
#include <string.h>

// Iterate through all routes in *payload and add them
bool oshpacket_handler_route(client_t *c, __attribute__((unused)) node_id_t *src,
    oshpacket_hdr_t *hdr, void *payload)
{
    const oshpacket_route_t *packet = (const oshpacket_route_t *) payload;
    const size_t entries = hdr->payload_size / sizeof(oshpacket_route_t);
    char node_name[NODE_NAME_SIZE + 1];
    char addr_str[INET6_ADDRSTRLEN];
    netaddr_t addr;
    node_id_t *id;
    const netroute_t *route;

    if (c->state_exg) {
        // Broadcast remote node's routes to our end of the network
        logger_debug(DBG_STATEEXG,
            "%s: %s: State exchange: Relaying ROUTE_ADD packet",
            c->addrw, c->id->name);
        client_queue_packet_broadcast(c, ROUTE_ADD, payload, hdr->payload_size);
    }

    memset(node_name, 0, sizeof(node_name));
    for (size_t i = 0; i < entries; ++i) {
        // Extract and verify the network address
        if (!netaddr_dton(&addr,
                           packet[i].type,
                          &packet[i].addr))
        {
            logger(LOG_ERR, "%s: %s: Add route: Invalid address type",
                c->addrw, c->id->name);
            return false;
        }

        // Verify that the prefix length is valid
        if (packet[i].prefixlen > netaddr_max_prefixlen(addr.type)) {
            logger(LOG_ERR, "%s: %s: Add route: Invalid prefix length",
                c->addrw, c->id->name);
            return false;
        }

        // Extract and verify the node's name
        memcpy(node_name, packet[i].owner_name, NODE_NAME_SIZE);
        if (!node_valid_name(node_name)) {
            logger(LOG_ERR, "%s: %s: Add route: Invalid name",
                c->addrw, c->id->name);
            return false;
        }

        // Make sure that the node exists
        if (!(id = node_id_find(node_name))) {
            logger(LOG_ERR, "%s: %s: Add route: Unknown node '%s'",
                c->addrw, c->id->name, node_name);
            return false;
        }

        // If we don't have a route to forward packets to the destination node,
        // continue processing the other routes skipping this one.
        if (!id->online) {
            // We don't log route errors if they are local
            // In many scenarios we will get route broadcasts of our own routes,
            // we can ignore those silently
            netaddr_ntop(addr_str, sizeof(addr_str), &addr);
            if (id->local_node) {
                logger_debug(DBG_ROUTING, "%s: %s: Add route: Skipping local route %s/%u",
                    c->addrw, c->id->name, addr_str, packet[i].prefixlen);
            } else {
                logger(LOG_WARN, "%s: %s: Add route: %s/%u -> %s: No route",
                    c->addrw, c->id->name, addr_str, packet[i].prefixlen, node_name);
            }
            continue;
        }

        // Prevent adding broadcast routes
        route = netroute_lookup(oshd.route_table, &addr);
        if (route && !route->owner) {
            netaddr_ntop(addr_str, sizeof(addr_str), &addr);
            logger(LOG_WARN, "%s: %s: Ignoring broadcast route: %s/%u -> %s",
                c->addrw, c->id->name, addr_str, packet[i].prefixlen, id->name);
            continue;
        }

        // Add a route to node_name for the network address
        if (logger_is_debugged(DBG_ROUTING)) {
            netaddr_ntop(addr_str, sizeof(addr_str), &addr);
            logger_debug(DBG_ROUTING, "%s: %s: Add route: %s/%u -> %s", c->addrw,
                c->id->name, addr_str, packet[i].prefixlen, id->name);
        }

        netroute_add(oshd.route_table, &addr, packet[i].prefixlen, id,
            packet[i].can_expire ? ROUTE_REMOTE_EXPIRY : ROUTE_NEVER_EXPIRE);
    }

    if (logger_is_debugged(DBG_ROUTING)) {
        printf("Routing table (%zu routes):\n", oshd.route_table->total_routes);
        netroute_dump(oshd.route_table);
    }
    return true;
}
