#include "oshd_cmd.h"
#include "oshd.h"
#include "logger.h"
#include "xalloc.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>

// Returns the name of the resolver
const char *oshd_resolver_name(resolver_type_t resolver)
{
    switch (resolver) {
        case RESOLVER_NONE     : return "None";
        case RESOLVER_HOSTSDUMP: return "HostsDump";
             default           : return "Unknown";
    }
}

// Returns true if the resolver is configured correctly for the selected
// resolver type
bool oshd_resolver_check(void)
{
    if (oshd.resolver == RESOLVER_NONE)
        return true;

    if (!oshd.resolver_file) {
        logger(LOG_ERR, "%s resolver requires a ResolverFile",
                oshd_resolver_name(oshd.resolver));
        return false;
    }
    if (!oshd.resolver_tld && oshd.device_mode == MODE_NODEVICE) {
        logger(LOG_ERR, "%s resolver requires a ResolverTLD when no TUN/TAP device is used",
                oshd_resolver_name(oshd.resolver));
        return false;
    }
    return true;
}

// Dump network routes formatted for a hosts file
static bool oshd_resolver_hostsdump(const char *tld)
{
    char addr[INET6_ADDRSTRLEN];
    FILE *file;

    logger_debug(DBG_RESOLVER, "HostsDump: Opening %s", oshd.resolver_file);
    file = fopen(oshd.resolver_file, "w");
    if (!file) {
        logger(LOG_ERR, "Failed to open %s: %s", oshd.resolver_file, strerror(errno));
        return false;
    }

    logger_debug(DBG_RESOLVER, "HostsDump: Dumping to %s", oshd.resolver_file);
    for (size_t i = 0; i < oshd.local_routes_count; ++i) {
        netaddr_ntop(addr, sizeof(addr), oshd.local_routes + i);
        fprintf(file, "%s %s.%s\n", addr, oshd.name, tld);
    }
    for (size_t i = 0; i < oshd.routes_count; ++i) {
        netaddr_ntop(addr, sizeof(addr), &oshd.routes[i]->addr);
        fprintf(file, "%s %s.%s\n", addr, oshd.routes[i]->dest_node->name, tld);
    }
    fflush(file);
    fclose(file);
    return true;
}

// Called after the routing table was updated, updates the resolver
void oshd_resolver_update(void)
{
    // If no TLD was configured the TUN/TAP device's name will be used
    const char *tld = oshd.resolver_tld ? oshd.resolver_tld : oshd.tuntap_dev;
    bool success = false;

    switch (oshd.resolver) {
        case RESOLVER_HOSTSDUMP:
            success = oshd_resolver_hostsdump(tld);
            break;

        default: return;
    }
    if (success)
        oshd_cmd_execute("OnResolverUpdate");
}