#include "oshd.h"
#include "oshd_cmd.h"
#include "oshd_conf.h"
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

typedef struct oshd_conf {
    ec_t *ec;
    ecp_t *iter;
    char *filename;
} oshd_conf_t;

// Buffer to store configuration error messages from handlers
static char oshd_conf_error[256];

// Configuration stack
static oshd_conf_t *oshd_conf = NULL;
static size_t oshd_conf_count = 0;
#define conf_curr oshd_conf[oshd_conf_count - 1]

// Push configuration file on the stack
static void oshd_conf_push(ec_t *ec, ecp_t *iter, const char *filename)
{
    logger_debug(DBG_CONF, "Pushing '%s' (new count: %zu)",
        filename, oshd_conf_count + 1);
    oshd_conf = xreallocarray(oshd_conf, oshd_conf_count + 1,
        sizeof(oshd_conf_t));
    oshd_conf[oshd_conf_count].ec = ec;
    oshd_conf[oshd_conf_count].iter = iter;
    oshd_conf[oshd_conf_count].filename = xstrdup(filename);
    oshd_conf_count += 1;
}

// Pop configuration file from the stack
static void oshd_conf_pop(void)
{
    if (oshd_conf_count > 0) {
        oshd_conf_count -= 1;
        logger_debug(DBG_CONF, "Popping '%s' (new count: %zu)",
            oshd_conf[oshd_conf_count].filename, oshd_conf_count);
        ec_destroy(oshd_conf[oshd_conf_count].ec);
        free(oshd_conf[oshd_conf_count].filename);
        oshd_conf = xreallocarray(oshd_conf, oshd_conf_count,
            sizeof(oshd_conf_t));
    }
}

// Load a configuration file and push it to the stack
static bool oshd_conf_load(const char *filename)
{
    ec_t *ec;

    logger_debug(DBG_CONF, "Loading '%s'", filename);

    // Prevent infinite include loops
    for (size_t i = 0; i < oshd_conf_count; ++i) {
        if (!strcmp(filename, oshd_conf[i].filename)) {
            snprintf(oshd_conf_error, sizeof(oshd_conf_error), "include loop");
            return false;
        }
    }

    // Load the file
    if (!(ec = ec_load_from_file(filename))) {
        snprintf(oshd_conf_error, sizeof(oshd_conf_error),
            "%s", strerror(errno));
        return false;
    }

    oshd_conf_push(ec, ec->head, filename);
    return true;
}

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
    oshd_conf_set_keysdir(ecp_value(ecp));
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
    logger_debug(DBG_CONF, "Set AutomaticConnectionsInterval to %li seconds",
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
    logger_debug(DBG_CONF, "Set ReconnectDelayMin to %li", oshd.reconnect_delay_min);
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
    logger_debug(DBG_CONF, "Set ReconnectDelayMax to %li", oshd.reconnect_delay_max);
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

// Include
static bool oshd_param_include(ecp_t *ecp)
{
    char *tmp;

    if (!oshd_conf_load(ecp_value(ecp))) {
        tmp = xstrdup(oshd_conf_error);
        snprintf(oshd_conf_error, sizeof(oshd_conf_error),
            "Failed to include '%s': %s", ecp_value(ecp), tmp);
        free(tmp);
        return false;
    }
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
    { .name = "Include", .type = VALUE_REQUIRED, &oshd_param_include },
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
    bool load_error = false;

    // Reset global variables
    oshd_conf = NULL;
    oshd_conf_count = 0;
    memset(oshd_conf_error, 0, sizeof(oshd_conf_error));

    // Load the primary configuration file
    if (!oshd_conf_load(filename)) {
        logger(LOG_ERR, "%s: %s", filename, oshd_conf_error);
        return false;
    }

    // Iterate through all parameters from the current configuration file
    while (oshd_conf_count > 0) {
        ecp_t *ecp = conf_curr.iter;
        bool found = false;

        if (!ecp) {
            // If the current configuration's iterator is NULL we processed all
            // the parameters so we can pop it
            oshd_conf_pop();
            continue;
        }

        // Iterate the iterator now because the current configuration can change
        // if another file is included and we would iterate a different one
        conf_curr.iter = conf_curr.iter->next;

        logger_debug(DBG_CONF, "Processing parameter '%s'", ecp_name(ecp));

        // Find the corresponding handler for the parameter
        for (size_t i = 0; oshd_conf_params[i].name; ++i) {
            if (!strcmp(ecp_name(ecp), oshd_conf_params[i].name)) {
                found = true;

                if (   oshd_conf_params[i].type == VALUE_NONE
                    && ecp_value(ecp))
                {
                    snprintf(oshd_conf_error, sizeof(oshd_conf_error),
                        "%s does not take a value", oshd_conf_params[i].name);
                    load_error = true;
                    break;
                } else if (   oshd_conf_params[i].type == VALUE_REQUIRED
                           && !ecp_value(ecp))
                {
                    snprintf(oshd_conf_error, sizeof(oshd_conf_error),
                        "%s requires a value", oshd_conf_params[i].name);
                    load_error = true;
                    break;
                }

                if (!(oshd_conf_params[i].handler(ecp)))
                    load_error = true;
                break;
            }
        }

        if (!found) {
            snprintf(oshd_conf_error, sizeof(oshd_conf_error),
                "Invalid parameter: %s", ecp_name(ecp));
            load_error = true;
        }

        // On any error we stop loading the configuration right away
        if (load_error)
            break;
    }

    // Display error if there was one
    if (load_error)
        logger(LOG_ERR, "%s: %s", conf_curr.filename, oshd_conf_error);

    // Pop any remaining configuration files
    while (oshd_conf_count > 0)
        oshd_conf_pop();

    // If there was an error we stop here
    if (load_error)
        return false;

    // One-shot verifications

    if (strlen(oshd.name) == 0) {
        logger(LOG_ERR, "The daemon must have a name");
        return false;
    }
    if (oshd.reconnect_delay_max < oshd.reconnect_delay_min) {
        logger(LOG_ERR, "ReconnectDelayMax (%lis) cannot be smaller than ReconnectDelayMin (%lis)",
            oshd.reconnect_delay_max, oshd.reconnect_delay_min);
        return false;
    }
    if (!oshd_resolver_check())
        return false;

    // The configuration was loaded successfully
    return true;
}

// Set oshd.keys_dir to dir
// Adds a / if necessary
void oshd_conf_set_keysdir(const char *dir)
{
    free(oshd.keys_dir);
    oshd.keys_dir = xstrdup(dir);

    // If the path does not end with a /, add one
    size_t len = strlen(oshd.keys_dir);
    if (len == 0 || oshd.keys_dir[len - 1] != '/') {
        oshd.keys_dir = xrealloc(oshd.keys_dir, len + 2);
        oshd.keys_dir[len] = '/';
        oshd.keys_dir[len + 1] = '\0';
    }
    logger_debug(DBG_CONF, "Set keys directory to '%s'", oshd.keys_dir);
}