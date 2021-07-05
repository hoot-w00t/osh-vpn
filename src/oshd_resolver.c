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
#define get_tld() (oshd.resolver_tld ? oshd.resolver_tld : oshd.tuntap->dev_name)

#ifndef RESOLVER_GETLINE_SIZE
#define RESOLVER_GETLINE_SIZE (256)
#endif

// Simple getline implementation
static char *resolver_getline(FILE *stream)
{
    int c;
    char *line;
    char *new_ptr;
    size_t line_len;
    size_t ptr_size;

    if (!stream || ((c = fgetc(stream)) == EOF))
        return NULL;

    ptr_size = sizeof(char) * RESOLVER_GETLINE_SIZE;
    line = xalloc(ptr_size);
    line_len = 0;
    memset(line, 0, ptr_size);

    while (c != EOF) {
        ++line_len;
        if (ptr_size <= line_len) {
            ptr_size += sizeof(char) * RESOLVER_GETLINE_SIZE;
            new_ptr = xrealloc(line, ptr_size);
            line = new_ptr;
            memset(line + line_len, 0, ptr_size - line_len);
        }
        line[line_len - 1] = (char) c;

        if (c == '\n') break;
        c = fgetc(stream);
    }
    line[line_len] = '\0';
    return line;
}

// Returns the name of the resolver
const char *oshd_resolver_name(resolver_type_t resolver)
{
    switch (resolver) {
        case RESOLVER_NONE        : return "None";
        case RESOLVER_HOSTSDUMP   : return "HostsDump";
        case RESOLVER_HOSTSDYNAMIC: return "HostsDynamic";
             default              : return "Unknown";
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

    switch (oshd.resolver) {
        case RESOLVER_HOSTSDUMP:
            if (!oshd.resolver_tld && oshd.device_mode == MODE_NODEVICE) {
                logger(LOG_ERR, "HostsDump resolver requires a ResolverTLD when no TUN/TAP device is used");
                return false;
            }
            return true;

        case RESOLVER_HOSTSDYNAMIC:
            if (oshd.device_mode == MODE_NODEVICE) {
                logger(LOG_ERR, "HostsDynamic resolver requires a TUN/TAP device");
                return false;
            }
            return true;

        default:
            return true;
    }
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

// Write the HostsDynamic suffix to buf which is of buf_size bytes
static inline void hostsdynamic_suffix(char *buf, size_t buf_size)
{
    snprintf(buf, buf_size, "# osh-%s", oshd.tuntap->dev_name);
}

// Append one network route formatted to a hosts file
static bool oshd_resolver_hostsdynamic_append(const netaddr_t *addr,
    const char *name, const char *tld)
{
    char addrp[INET6_ADDRSTRLEN];
    FILE *file;
    char suffix[oshd.tuntap->dev_name_size + 8];

    logger_debug(DBG_RESOLVER, "HostsDynamic: Appending to %s", oshd.resolver_file);
    if (!(file = fopen(oshd.resolver_file, "a"))) {
        logger(LOG_ERR, "Failed to open %s: %s", oshd.resolver_file, strerror(errno));
        return false;
    }

    netaddr_ntop(addrp, sizeof(addrp), addr);
    hostsdynamic_suffix(suffix, sizeof(suffix));
    fprintf(file, "%s %s.%s %s\n", addrp, name, tld, suffix);
    fflush(file);
    fclose(file);
    return true;
}

// Open and rewrite hosts file preserving the original contents
static bool oshd_resolver_hostsdynamic_update(const char *tld)
{
    char **hosts = NULL;
    size_t hosts_size = 0;
    char *line = NULL;
    FILE *file;
    bool success = false;
    char addr[INET6_ADDRSTRLEN];
    char suffix[oshd.tuntap->dev_name_size + 8];
    size_t suffix_len;

    logger_debug(DBG_RESOLVER, "HostsDynamic: Loading %s", oshd.resolver_file);
    if (!(file = fopen(oshd.resolver_file, "r+"))) {
        logger(LOG_ERR, "Failed to open %s: %s", oshd.resolver_file, strerror(errno));
        goto end;
    }

    // Read the whole file line by line into a buffer
    while ((line = resolver_getline(file))) {
        hosts = xreallocarray(hosts, hosts_size + 1, sizeof(char *));
        hosts[hosts_size] = line;
        hosts_size += 1;

        size_t line_len = strlen(line);
        if (line_len && line[line_len - 1] == '\n')
            line[line_len - 1] = '\0';
    }

    logger_debug(DBG_RESOLVER, "HostsDynamic: Re-opening %s to overwrite it", oshd.resolver_file);
    fclose(file);
    if (!(file = fopen(oshd.resolver_file, "w"))) {
        logger(LOG_ERR, "Failed to open %s: %s", oshd.resolver_file, strerror(errno));
        goto end;
    }

    hostsdynamic_suffix(suffix, sizeof(suffix));
    suffix_len = strlen(suffix);

    // Rewrite all lines from the original file that are not managed by the daemon
    logger_debug(DBG_RESOLVER, "HostsDynamic: Rewriting unmanaged lines");
    for (size_t i = 0; i < hosts_size; ++i) {
        char *line_suffix = strrchr(hosts[i], '#');

        // Skip lines managed by Osh, we will write those at the end of the file
        if (line_suffix && !strncmp(line_suffix, suffix, suffix_len)) {
            logger_debug(DBG_RESOLVER, "HostsDynamic: Skipping managed line %zu '%s'",
                i + 1, hosts[i]);
            continue;
        }
        fprintf(file, "%s\n", hosts[i]);
    }

    // Rewrite all the routes managed by the daemon
    logger_debug(DBG_RESOLVER, "HostsDynamic: Rewriting managed lines");
    fprintf(file, "%s\n", suffix);
    for (size_t i = 0; i < oshd.node_tree_count; ++i) {
        for (size_t j = 0; j < oshd.node_tree[i]->resolver_routes_count; ++j) {
            netaddr_ntop(addr, sizeof(addr), &oshd.node_tree[i]->resolver_routes[j]);
            fprintf(file, "%s %s.%s %s\n", addr, oshd.node_tree[i]->name, tld, suffix);
        }
    }
    fflush(file);
    fclose(file);
    success = true;

end:
    for (size_t i = 0; i < hosts_size; ++i)
        free(hosts[i]);
    free(hosts);
    free(line);
    return success;
}

// Called after the routing table was updated, appends one host
void oshd_resolver_append(const netaddr_t *addr, const char *name)
{
    bool success = false;

    switch (oshd.resolver) {
        case RESOLVER_HOSTSDUMP:
            success = oshd_resolver_hostsdump_append(addr, name, get_tld());
            break;

        case RESOLVER_HOSTSDYNAMIC:
            success = oshd_resolver_hostsdynamic_append(addr, name, get_tld());
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

        case RESOLVER_HOSTSDYNAMIC:
            success = oshd_resolver_hostsdynamic_update(get_tld());
            break;

        default: return;
    }
    if (success)
        oshd_cmd_execute("OnResolverUpdate");
}