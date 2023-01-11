#include "oshd.h"
#include "logger.h"
#include "macros.h"
#include "sock.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#if PLATFORM_IS_LINUX
    #include <ifaddrs.h>

    // Contains the definitions for the interface flags
    #include <linux/if.h>
#endif

// Discover all addresses on the TUN/TAP device and add them to our local routes
void oshd_discover_local_routes(void)
{
    struct ifaddrs *ifaces;
    char addrw[INET6_ADDRSTRLEN];
    netaddr_t addr;

    if (getifaddrs(&ifaces) < 0) {
        logger(LOG_ERR, "getifaddrs: %s", strerror(errno));
        return;
    }

    for (struct ifaddrs *ifa = ifaces; ifa; ifa = ifa->ifa_next) {
        if (   !ifa->ifa_name
            || !ifa->ifa_addr
            || !(   ifa->ifa_addr->sa_family == AF_INET
                 || ifa->ifa_addr->sa_family == AF_INET6))
        {
            // Skip this entry if it has no name, no address or an address
            // family that is not IPv4/6
            continue;
        }

        size_t af_size = ifa->ifa_addr->sa_family == AF_INET
            ? sizeof(struct sockaddr_in)
            : sizeof(struct sockaddr_in6);

        int err = getnameinfo(ifa->ifa_addr, af_size, addrw, sizeof(addrw),
            NULL, 0, NI_NUMERICHOST);

        if (err) {
            logger(LOG_ERR, "getnameinfo: %s", gai_strerror(err));
            continue;
        }

        memset(&addr, 0, sizeof(addr));
        if (!netaddr_pton(&addr, addrw))
            continue;

        // If this interface is our TUN/TAP device add the address to our
        // local routes
        // If this is a TAP device these addresses will be used for the
        // resolver, the MAC addresses are discovered automatically
        if (   oshd.tuntap
            && (   (oshd.tuntap->dev_name && !strcmp(ifa->ifa_name, oshd.tuntap->dev_name))
                || (oshd.tuntap->dev_id   && !strcmp(ifa->ifa_name, oshd.tuntap->dev_id))))
        {
            if (!netroute_lookup(oshd.route_table, &addr)) {
                const netroute_t *route;

                logger_debug(DBG_ROUTING, "Discovered local route %s (%s)",
                    addrw, oshd.tuntap->dev_name);
                route = netroute_add(oshd.route_table, &addr,
                    netaddr_max_prefixlen(addr.type), node_id_find_local(),
                        ROUTE_LOCAL_EXPIRY);
                client_queue_route_add_local(NULL, &route->addr, 1, true);
            }
        }
    }

    freeifaddrs(ifaces);
}

// Discover endpoints from the network devices (excluding the TUN/TAP device and
// the devices explicitly excluded)
// Clear the previous endpoints of the local node and add those new endpoints
void oshd_discover_local_endpoints(void)
{
    struct ifaddrs *ifaces;
    char addrw[INET6_ADDRSTRLEN];
    netaddr_t addr;
    netarea_t area;
    node_id_t *local_id = node_id_find_local();

    if (getifaddrs(&ifaces) < 0) {
        logger(LOG_ERR, "getifaddrs: %s", strerror(errno));
        return;
    }

    for (struct ifaddrs *ifa = ifaces; ifa; ifa = ifa->ifa_next) {
        if (   !ifa->ifa_name
            || !ifa->ifa_addr
            || !(   ifa->ifa_addr->sa_family == AF_INET
                 || ifa->ifa_addr->sa_family == AF_INET6))
        {
            // Skip this entry if it has no name, no address or an address
            // family that is not IPv4/6
            if (ifa->ifa_name) {
                logger_debug(DBG_ENDPOINTS, "Ignoring incompatible device: %s",
                    ifa->ifa_name);
            }
            continue;
        }

        if (ifa->ifa_flags & IFF_LOOPBACK) {
            logger_debug(DBG_ENDPOINTS, "Ignoring loopback device: %s", ifa->ifa_name);
            continue;
        }

        if (!(ifa->ifa_flags & IFF_UP)) {
            logger_debug(DBG_ENDPOINTS, "Ignoring disabled device: %s", ifa->ifa_name);
            continue;
        }

        // If this interface is our TUN/TAP device, skip it
        if (   oshd.tuntap
            && (   (oshd.tuntap->dev_name && !strcmp(ifa->ifa_name, oshd.tuntap->dev_name))
                || (oshd.tuntap->dev_id   && !strcmp(ifa->ifa_name, oshd.tuntap->dev_id))))
        {
            logger_debug(DBG_ENDPOINTS, "Ignoring TUN/TAP device: %s", ifa->ifa_name);
            continue;
        }

        size_t af_size = ifa->ifa_addr->sa_family == AF_INET
            ? sizeof(struct sockaddr_in)
            : sizeof(struct sockaddr_in6);

        int err = getnameinfo(ifa->ifa_addr, af_size, addrw, sizeof(addrw),
            NULL, 0, NI_NUMERICHOST);

        if (err) {
            logger(LOG_ERR, "getnameinfo: %s", gai_strerror(err));
            continue;
        }

        memset(&addr, 0, sizeof(addr));
        if (!netaddr_pton(&addr, addrw))
            continue;
        area = netaddr_area(&addr);

        // TODO: Add a parameter to allow which interfaces can be discovered
        //       instead of excluding those that shouldn't be

        // Check if this device is excluded
        bool excluded = false;

        for (size_t i = 0; i < oshd.excluded_devices_count; ++i) {
            if (!strcmp(ifa->ifa_name, oshd.excluded_devices[i])) {
                excluded = true;
                break;
            }
        }
        if (excluded) {
            logger_debug(DBG_ENDPOINTS, "Excluded device: %s (%s)", addrw, ifa->ifa_name);
            continue;
        }

        // Zeroed out addresses are obviously not valid
        if (netaddr_is_zero(&addr)) {
            logger_debug(DBG_ENDPOINTS, "Ignoring zeroed: %s (%s)", addrw, ifa->ifa_name);
            continue;
        }

        // Finally discover the local endpoint
        logger_debug(DBG_ENDPOINTS, "Discovered %s endpoint: %s (%s)",
            netarea_name(area), addrw, ifa->ifa_name);

        endpoint_t *endpoint = endpoint_create(addrw, oshd.server_port,
            ENDPOINT_SOCKTYPE_TCP, true);
        endpoint_t *inserted = endpoint_group_insert_sorted(local_id->endpoints, endpoint);

        if (inserted)
            client_queue_endpoint(NULL, inserted, local_id, true);

        endpoint_free(endpoint);

    }
    freeifaddrs(ifaces);
}
