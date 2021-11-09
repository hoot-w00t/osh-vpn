#include "oshd.h"
#include "oshd_cmd.h"
#include "xalloc.h"
#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <easyconf.h>

typedef bool (*oshd_conf_handler_t)(ecp_t *);

typedef enum oshd_conf_param_type {
    VALUE_OPTIONAL = 0,
    VALUE_NONE,
    VALUE_REQUIRED
} oshd_conf_param_type_t;

typedef struct oshd_conf_param {
    char *name;
    oshd_conf_param_type_t type;
    oshd_conf_handler_t handler;
} oshd_conf_param_t;

// Buffer to store configuration error messages from handlers
static char oshd_conf_error[256];

// NoServer
static bool oshd_param_noserver(__attribute__((unused)) ecp_t *ecp)
{
    oshd.server_enabled = false;
    logger_debug(DBG_CONF, "Disabled server");
    return true;
}

// Name
static bool oshd_param_name(ecp_t *ecp)
{
    if (!node_valid_name(ecp_value(ecp))) {
        // TODO: Print the invalid character in the error
        snprintf(oshd_conf_error, sizeof(oshd_conf_error),
            "Invalid node name");
        return false;
    }
    memset(oshd.name, 0, sizeof(oshd.name));
    strncpy(oshd.name, ecp_value(ecp), NODE_NAME_SIZE);
    logger_debug(DBG_CONF, "Set daemon name to '%s'", oshd.name);
    return true;
}

// KeysDir
static bool oshd_param_keysdir(ecp_t *ecp)
{
    free(oshd.keys_dir);
    oshd.keys_dir = xstrdup(ecp_value(ecp));

    // If the path does not end with a /, add one
    size_t len = strlen(oshd.keys_dir);
    if (len == 0 || oshd.keys_dir[len - 1] != '/') {
        oshd.keys_dir = xrealloc(oshd.keys_dir, len + 2);
        oshd.keys_dir[len] = '/';
        oshd.keys_dir[len + 1] = '\0';
    }
    logger_debug(DBG_CONF, "Set keys dir to '%s'", oshd.keys_dir);
    return true;
}

// KeysTrust
static bool oshd_param_keystrust(ecp_t *ecp)
{
    if (!strcasecmp(ecp_value(ecp), "local")) {
        oshd.remote_auth = false;
    } else if (!strcasecmp(ecp_value(ecp), "remote")) {
        oshd.remote_auth = true;
    } else {
        snprintf(oshd_conf_error, sizeof(oshd_conf_error),
            "Invalid KeysTrust: '%s'", ecp_value(ecp));
        return false;
    }
    logger_debug(DBG_CONF, "%s authentication using remote keys",
        oshd.remote_auth ? "Enabled" : "Disabled");
    return true;
}

// ShareRemotes
static bool oshd_param_shareremotes(__attribute__((unused)) ecp_t *ecp)
{
    oshd.shareremotes = true;
    logger_debug(DBG_CONF, "Enabled ShareRemotes");
    return true;
}

// DiscoverEndpoints
static bool oshd_param_discoverendpoints(__attribute__((unused)) ecp_t *ecp)
{
    oshd.discoverendpoints = true;
    logger_debug(DBG_CONF, "Enabled DiscoverEndpoints");
    return true;
}

// AutomaticConnections
static bool oshd_param_automaticconnections(__attribute__((unused)) ecp_t *ecp)
{
    oshd.automatic_connections = true;
    logger_debug(DBG_CONF, "%s automatic connections",
        oshd.automatic_connections ? "Enabled" : "Disabled");
    return true;
}

// AutomaticConnectionsInterval
static bool oshd_param_automaticconnectionsinterval(ecp_t *ecp)
{
    oshd.automatic_connections_interval = (time_t) atoi(ecp_value(ecp));
    logger_debug(DBG_CONF,
        "Set AutomaticConnectionsInterval to %" PRIi64 " seconds",
        oshd.automatic_connections_interval);
    return true;
}

// AutomaticConnectionsPercent
static bool oshd_param_automaticconnectionspercent(ecp_t *ecp)
{
    const size_t percent = (size_t) atoi(ecp_value(ecp));

    if (percent == 0 || percent > 100) {
        snprintf(oshd_conf_error, sizeof(oshd_conf_error),
            "Invalid AutomaticConnectionsPercent: %s", ecp_value(ecp));
        return false;
    }
    oshd.automatic_connections_percent = percent;
    logger_debug(DBG_CONF, "Set AutomaticConnectionsPercent to %zu%%",
        oshd.automatic_connections_percent);
    return true;
}

// Port
static bool oshd_param_port(ecp_t *ecp)
{
    oshd.server_port = (uint16_t) atoi(ecp_value(ecp));
    if (oshd.server_port == 0) {
        snprintf(oshd_conf_error, sizeof(oshd_conf_error),
            "Invalid port: %s", ecp_value(ecp));
        return false;
    }
    logger_debug(DBG_CONF, "Set server port to %u", oshd.server_port);
    return true;
}

// Mode
static bool oshd_param_mode(ecp_t *ecp)
{
    if (!strcasecmp(ecp_value(ecp), "NoDevice")) {
        oshd.device_mode = MODE_NODEVICE;
    } else if (!strcasecmp(ecp_value(ecp), "TAP")) {
        oshd.device_mode = MODE_TAP;
    } else if (!strcasecmp(ecp_value(ecp), "TUN")) {
        oshd.device_mode = MODE_TUN;
    } else {
        snprintf(oshd_conf_error, sizeof(oshd_conf_error), "Unknown mode");
        return false;
    }

    logger_debug(DBG_CONF, "Set device mode to %s (%s, %s)",
        device_mode_name(oshd.device_mode),
        (oshd.device_mode != MODE_NODEVICE)  ? "used" : "unused",
        device_mode_is_tap(oshd.device_mode) ? "TAP"  : "TUN");
    return true;
}

// Device
static bool oshd_param_device(ecp_t *ecp)
{
    free(oshd.tuntap_devname);
    oshd.tuntap_devname = xstrdup(ecp_value(ecp));
    logger_debug(DBG_CONF, "Set device name to %s", oshd.tuntap_devname);
    return true;
}

// ExcludeDevice
static bool oshd_param_excludedevice(ecp_t *ecp)
{
    oshd.excluded_devices = xreallocarray(oshd.excluded_devices,
        oshd.excluded_devices_count + 1, sizeof(char *));
    oshd.excluded_devices[oshd.excluded_devices_count] = xstrdup(ecp_value(ecp));
    oshd.excluded_devices_count += 1;
    logger_debug(DBG_CONF, "Excluding device '%s'", ecp_value(ecp));
    return true;
}

// Remote
static bool oshd_param_remote(ecp_t *ecp)
{
    const char remote_separator[] = ",";

    // Duplicate the value to use it with strtok
    char *tokens = xstrdup(ecp_value(ecp));
    char *token = strtok(tokens, remote_separator);

    // Add the new empty endpoint group
    oshd.remote_endpoints = xreallocarray(oshd.remote_endpoints,
        oshd.remote_count + 1, sizeof(endpoint_group_t *));
    oshd.remote_endpoints[oshd.remote_count] = endpoint_group_create(NULL);

    logger_debug(DBG_CONF, "Remote: Processing tokens from '%s'", ecp_value(ecp));

    // Iterate through all tokens to add multiple endpoints to this group
    for (; token; token = strtok(NULL, remote_separator)) {
        // Skip whitespaces before the endpoint address
        size_t addr_off = 0;
        for (; token[addr_off] == ' ' || token[addr_off] == '\t'; ++addr_off);
        if (!token[addr_off]) {
            logger_debug(DBG_CONF, "Remote: Skipping empty token '%s'", token);
            continue;
        }

        // Duplicate the address
        char *addr = xstrdup(token + addr_off);
        char *port = addr;

        logger_debug(DBG_CONF, "Remote: Processing token '%s'", addr);

        // Skip the address to get to the next value (separated with whitespaces)
        for (; *port && *port != ' ' && *port != '\t'; ++port);

        // If there are still characters after the address, separate the address and
        // port values
        if (*port) *port++ = '\0';

        // Go to the start of the second parameter, skipping whitespaces
        for (; *port == ' ' || *port == '\t'; ++port);

        // Convert the port value to a number
        uint16_t port_nb = (*port) ? ((uint16_t) atoi(port)) : OSHD_DEFAULT_PORT;

        // Add the endpoint to the group
        netaddr_t naddr;
        netarea_t area;

        if (!netaddr_lookup(&naddr, addr)) {
            area = NETAREA_UNK;
        } else {
            area = netaddr_area(&naddr);
        }
        if (endpoint_group_add(oshd.remote_endpoints[oshd.remote_count],
                addr, port_nb, area, false))
        {
            logger_debug(DBG_CONF, "Remote: %s:%u (%s) added",
                addr, port_nb, netarea_name(area));
        } else {
            logger_debug(DBG_CONF, "Remote: %s:%u (%s) ignored",
                addr, port_nb, netarea_name(area));
        }

        // Free the temporary address
        free(addr);
    }

    oshd.remote_count += 1;
    free(tokens);
    return true;
}

// ReconnectDelayMin
static bool oshd_param_reconnectdelaymin(ecp_t *ecp)
{
    oshd.reconnect_delay_min = (time_t) atoi(ecp_value(ecp));
    if (oshd.reconnect_delay_min <= 0) {
        snprintf(oshd_conf_error, sizeof(oshd_conf_error),
            "ReconnectDelayMin cannot be of 0 seconds or less");
        return false;
    }
    logger_debug(DBG_CONF, "Set ReconnectDelayMin to %" PRIi64,
        oshd.reconnect_delay_min);
    return true;
}

// ReconnectDelayMax
static bool oshd_param_reconnectdelaymax(ecp_t *ecp)
{
    oshd.reconnect_delay_max = (time_t) atoi(ecp_value(ecp));
    if (oshd.reconnect_delay_max <= 0) {
        snprintf(oshd_conf_error, sizeof(oshd_conf_error),
            "ReconnectDelayMax cannot be of 0 seconds or less");
        return false;
    }
    logger_debug(DBG_CONF, "Set ReconnectDelayMax to %" PRIi64,
        oshd.reconnect_delay_max);
    return true;
}

// ConnectionsLimit
static bool oshd_param_connectionslimit(ecp_t *ecp)
{
    oshd.nodes_count_max = (size_t) atoi(ecp_value(ecp));
    logger_debug(DBG_CONF, "Set ConnectionsLimit to %zu%s", oshd.nodes_count_max,
        (oshd.nodes_count_max == 0) ? " (unlimited)" : "");
    return true;
}

// DigraphFile
static bool oshd_param_digraphfile(ecp_t *ecp)
{
    free(oshd.digraph_file);
    oshd.digraph_file = xstrdup(ecp_value(ecp));
    logger_debug(DBG_CONF, "Set DigraphFile to '%s'", oshd.digraph_file);
    return true;
}

// Resolver
static bool oshd_param_resolver(ecp_t *ecp)
{
    if (!strcasecmp(ecp_value(ecp), "None")) {
        oshd.resolver = RESOLVER_NONE;
    } else if (!strcasecmp(ecp_value(ecp), "HostsDump")) {
        oshd.resolver = RESOLVER_HOSTSDUMP;
    } else if (!strcasecmp(ecp_value(ecp), "HostsDynamic")) {
        oshd.resolver = RESOLVER_HOSTSDYNAMIC;
    } else {
        snprintf(oshd_conf_error, sizeof(oshd_conf_error),
            "Invalid resolver: %s", ecp_value(ecp));
        return false;
    }

    logger_debug(DBG_CONF, "Set Resolver to %s",
        oshd_resolver_name(oshd.resolver));
    return true;
}

// ResolverTLD
static bool oshd_param_resolvertld(ecp_t *ecp)
{
    free(oshd.resolver_tld);
    oshd.resolver_tld = xstrdup(ecp_value(ecp));
    logger_debug(DBG_CONF, "Set ResolverTLD to '%s'", oshd.resolver_tld);
    return true;
}

// ResolverFile
static bool oshd_param_resolverfile(ecp_t *ecp)
{
    free(oshd.resolver_file);
    oshd.resolver_file = xstrdup(ecp_value(ecp));
    logger_debug(DBG_CONF, "Set ResolverFile to '%s'", oshd.resolver_file);
    return true;
}

// LogLevel
static bool oshd_param_loglevel(ecp_t *ecp)
{
    if (!logger_set_level_name(ecp_value(ecp))) {
        snprintf(oshd_conf_error, sizeof(oshd_conf_error),
            "Invalid LogLevel: %s", ecp_value(ecp));
        return false;
    }
    logger_debug(DBG_CONF, "Set LogLevel to %s",
        logger_get_level_name(logger_get_level()));
    return true;
}

// Parameters that set commands (the command name is the same as the parameter)
static bool oshd_param_command(ecp_t *ecp)
{
    oshd_cmd_set(ecp_name(ecp), ecp_value(ecp));
    logger_debug(DBG_CONF, "Set %s to '%s'", ecp_name(ecp), ecp_value(ecp));
    return true;
}

// Array of all configuration parameters and their handlers
static const oshd_conf_param_t oshd_conf_params[] = {
    { .name = "NoServer", .type = VALUE_NONE, &oshd_param_noserver },
    { .name = "Name", .type = VALUE_REQUIRED, &oshd_param_name },
    { .name = "KeysDir", .type = VALUE_REQUIRED, &oshd_param_keysdir },
    { .name = "KeysTrust", .type = VALUE_REQUIRED, &oshd_param_keystrust },
    { .name = "ShareRemotes", .type = VALUE_NONE, &oshd_param_shareremotes },
    { .name = "DiscoverEndpoints", .type = VALUE_NONE, &oshd_param_discoverendpoints },
    { .name = "AutomaticConnections", .type = VALUE_NONE, &oshd_param_automaticconnections },
    { .name = "AutomaticConnectionsInterval", .type = VALUE_REQUIRED, &oshd_param_automaticconnectionsinterval },
    { .name = "AutomaticConnectionsPercent", .type = VALUE_REQUIRED, &oshd_param_automaticconnectionspercent },
    { .name = "Port", .type = VALUE_REQUIRED, &oshd_param_port },
    { .name = "Mode", .type = VALUE_REQUIRED, &oshd_param_mode },
    { .name = "Device", .type = VALUE_REQUIRED, &oshd_param_device },
    { .name = "ExcludeDevice", .type = VALUE_REQUIRED, &oshd_param_excludedevice },
    { .name = "DevUp", .type = VALUE_REQUIRED, &oshd_param_command },
    { .name = "DevDown", .type = VALUE_REQUIRED, &oshd_param_command },
    { .name = "Remote", .type = VALUE_REQUIRED, &oshd_param_remote },
    { .name = "ReconnectDelayMin", .type = VALUE_REQUIRED, &oshd_param_reconnectdelaymin },
    { .name = "ReconnectDelayMax", .type = VALUE_REQUIRED, &oshd_param_reconnectdelaymax },
    { .name = "ConnectionsLimit", .type = VALUE_REQUIRED, &oshd_param_connectionslimit },
    { .name = "DigraphFile", .type = VALUE_REQUIRED, &oshd_param_digraphfile },
    { .name = "Resolver", .type = VALUE_REQUIRED, &oshd_param_resolver },
    { .name = "ResolverTLD", .type = VALUE_REQUIRED, &oshd_param_resolvertld },
    { .name = "ResolverFile", .type = VALUE_REQUIRED, &oshd_param_resolverfile },
    { .name = "OnResolverUpdate", .type = VALUE_REQUIRED, &oshd_param_command },
    { .name = "LogLevel", .type = VALUE_REQUIRED, &oshd_param_loglevel },
    { NULL, 0, NULL }
};

// Initialize oshd_t global
void oshd_init_conf(void)
{
    // Everything should be at zero, including pointers and counts
    memset(&oshd, 0, sizeof(oshd_t));

    // Everything that should not be zero by default is set
    oshd.keys_dir = xstrdup("./");

    oshd.server_fd = -1;
    oshd.server_fd6 = -1;
    oshd.server_port = OSHD_DEFAULT_PORT;
    oshd.server_enabled = true;

    oshd.reconnect_delay_min = 10;
    oshd.reconnect_delay_max = 60;

    oshd.automatic_connections_interval = 3600; // 1 hour (60m, 3600s)
    oshd.automatic_connections_percent = 50;

    oshd.routes = oshd_route_group_create();

    oshd.run = true;
}

// Load configuration file
bool oshd_load_conf(const char *filename)
{
    ec_t *conf;

    // Reset the oshd_conf_error buffer
    memset(oshd_conf_error, 0, sizeof(oshd_conf_error));

    // Load the configuration file
    if (!(conf = ec_load_from_file(filename))) {
        logger(LOG_ERR, "%s: %s", filename, strerror(errno));
        return false;
    }

    // Iterate through each configuration parameter
    ec_foreach(ecp, conf) {
        bool found = false;

        logger_debug(DBG_CONF, "Processing parameter '%s'", ecp_name(ecp));

        // Find the corresponding handler for the parameter
        for (size_t i = 0; oshd_conf_params[i].name; ++i) {
            if (!strcmp(ecp_name(ecp), oshd_conf_params[i].name)) {
                found = true;
                if (oshd_conf_params[i].type == VALUE_NONE && ecp_value(ecp)) {
                    snprintf(oshd_conf_error, sizeof(oshd_conf_error),
                        "%s does not take a value", oshd_conf_params[i].name);
                    goto on_error;
                } else if (oshd_conf_params[i].type == VALUE_REQUIRED && !ecp_value(ecp)) {
                    snprintf(oshd_conf_error, sizeof(oshd_conf_error),
                        "%s requires a value", oshd_conf_params[i].name);
                    goto on_error;
                }

                if (!(oshd_conf_params[i].handler(ecp)))
                    goto on_error;
                break;
            }
        }

        if (!found) {
            snprintf(oshd_conf_error, sizeof(oshd_conf_error),
                "Invalid parameter: %s", ecp_name(ecp));
            goto on_error;
        }
    }
    ec_destroy(conf);

    if (strlen(oshd.name) == 0) {
        logger(LOG_ERR, "The daemon must have a name");
        return false;
    }
    if (oshd.reconnect_delay_max < oshd.reconnect_delay_min) {
        logger(LOG_ERR,
            "ReconnectDelayMax (%" PRIi64 "s) cannot be smaller than ReconnectDelayMin (%" PRIi64 "s)",
            oshd.reconnect_delay_max, oshd.reconnect_delay_min);
        return false;
    }
    if (!oshd_resolver_check())
        return false;

    return true;

on_error:
    logger(LOG_ERR, "%s: %s", filename, oshd_conf_error);
    ec_destroy(conf);
    return false;
}