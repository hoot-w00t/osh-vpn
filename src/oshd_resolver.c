#include "oshd_cmd.h"
#include "oshd.h"
#include "logger.h"
#include "xalloc.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>

// TODO: Work on the resolver to make it better

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
    return true;
}

// Ensure that there is a TLD for the resolver
void oshd_resolver_check_tld(void)
{
    if (!oshd.resolver_tld) {
        if (oshd.tuntap) {
            // If there is a TUN/TAP device, use its name as a TLD
            oshd.resolver_tld = xstrdup(oshd.tuntap->dev_name);
        } else {
            // Otherwise fallback to a default TLD
            oshd.resolver_tld = xstrdup("osh");
        }
    }
}

// Dump network routes formatted for a hosts file
static bool oshd_resolver_hostsdump_update(void)
{
    char addrw[INET6_ADDRSTRLEN];
    FILE *file;

    logger_debug(DBG_RESOLVER, "HostsDump: Dumping to %s", oshd.resolver_file);
    if (!(file = fopen(oshd.resolver_file, "w"))) {
        logger(LOG_ERR, "Failed to open %s: %s", oshd.resolver_file, strerror(errno));
        return false;
    }

    for (size_t i = 0; i < oshd.routes->resolver_count; ++i) {
        netaddr_ntop(addrw, sizeof(addrw), &oshd.routes->resolver[i]->addr);
        fprintf(file, "%s %s.%s\n", addrw, oshd.routes->resolver[i]->dest_node->name, oshd.resolver_tld);
    }
    fflush(file);
    fclose(file);
    return true;
}

// Open and rewrite hosts file preserving the original contents
// TODO: Optimize this
static bool oshd_resolver_hostsdynamic_update(void)
{
    char **hosts = NULL;
    size_t hosts_size = 0;
    char *line = NULL;
    FILE *file;
    bool success = false;
    char addrw[INET6_ADDRSTRLEN];
    char *suffix = NULL;
    size_t suffix_size;
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

    suffix_size = strlen(oshd.resolver_tld) + 7;
    suffix = xzalloc(suffix_size);
    snprintf(suffix, suffix_size, "# osh-%s", oshd.resolver_tld);
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
    for (size_t i = 0; i < oshd.routes->resolver_count; ++i) {
        netaddr_ntop(addrw, sizeof(addrw), &oshd.routes->resolver[i]->addr);
        fprintf(file, "%s %s.%s %s\n",
            addrw,
            oshd.routes->resolver[i]->dest_node->name,
            oshd.resolver_tld,
            suffix);
    }
    fflush(file);
    fclose(file);
    success = true;

end:
    for (size_t i = 0; i < hosts_size; ++i)
        free(hosts[i]);
    free(hosts);
    free(line);
    free(suffix);
    return success;
}

// Called after the routing table was updated, updates all hosts
void oshd_resolver_update(void)
{
    bool success = false;

    switch (oshd.resolver) {
    case RESOLVER_HOSTSDUMP:
        success = oshd_resolver_hostsdump_update();
        break;

    case RESOLVER_HOSTSDYNAMIC:
        success = oshd_resolver_hostsdynamic_update();
        break;

    default: return;
    }
    if (success)
        oshd_cmd_execute("OnResolverUpdate");
}