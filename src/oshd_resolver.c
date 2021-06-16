#include "oshd_cmd.h"
#include "oshd.h"
#include "logger.h"
#include "xalloc.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>

// If no TLD was configured the TUN/TAP device's name will be used
#define get_tld() (oshd.resolver_tld ? oshd.resolver_tld : oshd.tuntap_dev)

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

// Append one network route formatted to a hosts file
static bool oshd_resolver_hostsdump_append(const netaddr_t *addr,
    const char *name, const char *tld)
{
    char addrp[INET6_ADDRSTRLEN];
    FILE *file;

    logger_debug(DBG_RESOLVER, "HostsDump: Appending to %s", oshd.resolver_file);
    if (!(file = fopen(oshd.resolver_file, "a"))) {
        logger(LOG_ERR, "Failed to open %s: %s", oshd.resolver_file, strerror(errno));
        return false;
    }

    netaddr_ntop(addrp, sizeof(addrp), addr);
    fprintf(file, "%s %s.%s\n", addrp, name, tld);
    fflush(file);
    fclose(file);
    return true;
}

// Dump network routes formatted for a hosts file
static bool oshd_resolver_hostsdump_update(const char *tld)
{
    char addr[INET6_ADDRSTRLEN];
    FILE *file;

    logger_debug(DBG_RESOLVER, "HostsDump: Dumping to %s", oshd.resolver_file);
    if (!(file = fopen(oshd.resolver_file, "w"))) {
        logger(LOG_ERR, "Failed to open %s: %s", oshd.resolver_file, strerror(errno));
        return false;
    }

    for (size_t i = 0; i < oshd.node_tree_count; ++i) {
        for (size_t j = 0; j < oshd.node_tree[i]->resolver_routes_count; ++j) {
            netaddr_ntop(addr, sizeof(addr), &oshd.node_tree[i]->resolver_routes[j]);
            fprintf(file, "%s %s.%s\n", addr, oshd.node_tree[i]->name, tld);
        }
    }
    fflush(file);
    fclose(file);
    return true;
}

// Called after the routing table was updated, appends one host
void oshd_resolver_append(const netaddr_t *addr, const char *name)
{
    bool success = false;

    switch (oshd.resolver) {
        case RESOLVER_HOSTSDUMP:
            success = oshd_resolver_hostsdump_append(addr, name, get_tld());
            break;

        default: return;
    }
    if (success)
        oshd_cmd_execute("OnResolverUpdate");
}

// Called after the routing table was updated, updates all hosts
void oshd_resolver_update(void)
{
    bool success = false;

    switch (oshd.resolver) {
        case RESOLVER_HOSTSDUMP:
            success = oshd_resolver_hostsdump_update(get_tld());
            break;

        default: return;
    }
    if (success)
        oshd_cmd_execute("OnResolverUpdate");
}