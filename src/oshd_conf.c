#include "oshd.h"
#include "oshd_cmd.h"
#include "oshd_conf.h"
#include "base64.h"
#include "random.h"
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
    const char *name;
    oshd_conf_param_type_t type;
    oshd_conf_handler_t handler;
} oshd_conf_param_t;

typedef struct oshd_conf {
    ec_t *ec;
    ecp_t *iter;
    char *filename;
    char selected_node[NODE_NAME_SIZE + 1];
} oshd_conf_t;

// Buffer to store configuration error messages from handlers
static char oshd_conf_error[256];

// Macro to snprintf to oshd_conf_error
#define set_error(fmt, ...) \
    snprintf(oshd_conf_error, sizeof(oshd_conf_error), fmt, ## __VA_ARGS__)

// Line number of the last error message
static size_t oshd_conf_error_line_no = 0;

// Configuration stack
static oshd_conf_t *oshd_conf = NULL;
static size_t oshd_conf_count = 0;
#define conf_curr oshd_conf[oshd_conf_count - 1]

// Push configuration file on the stack
static void oshd_conf_push(ec_t *ec, ecp_t *iter, const char *filename)
{
    oshd_conf_count += 1;
    logger_debug(DBG_CONF, "Pushing '%s' (new count: %zu)",
        filename, oshd_conf_count);
    oshd_conf = xreallocarray(oshd_conf, oshd_conf_count, sizeof(oshd_conf_t));

    conf_curr.ec = ec;
    conf_curr.iter = iter;
    conf_curr.filename = xstrdup(filename);
    memset(conf_curr.selected_node, 0, sizeof(conf_curr.selected_node));
}

// Pop configuration file from the stack
static void oshd_conf_pop(void)
{
    if (oshd_conf_count > 0) {
        logger_debug(DBG_CONF, "Popping '%s' (old count: %zu)",
            conf_curr.filename, oshd_conf_count);
        ec_destroy(conf_curr.ec);
        free(conf_curr.filename);

        oshd_conf_count -= 1;
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
            set_error("include loop");
            return false;
        }
    }

    // Load the file
    if (!(ec = ec_load_from_file(filename))) {
        set_error("%s", strerror(errno));
        return false;
    }

    oshd_conf_push(ec, ec->head, filename);
    return true;
}

// Returns true if a valid Node is selected
static bool oshd_conf_has_selected_node(void)
{
    return strlen(conf_curr.selected_node) != 0;
}

// Returns true if a valid Node is selected
// If not the error message is set here
static bool oshd_conf_require_selected_node(const ecp_t *ecp)
{
    if (oshd_conf_has_selected_node())
        return true;
    set_error("Missing '%s' parameter for '%s'", "Node", ecp_name(ecp));
    return false;
}

// Returns the selected node
static const char *oshd_conf_selected_node(void)
{
    return conf_curr.selected_node;
}

// Set the selected node
static bool oshd_conf_select_node(const char *name)
{
    if (!node_valid_name(name)) {
        // TODO: Print the invalid character in the error
        set_error("Invalid node name");
        return false;
    }
    memset(conf_curr.selected_node, 0, sizeof(conf_curr.selected_node));
    strncpy(conf_curr.selected_node, name, NODE_NAME_SIZE);
    logger_debug(DBG_CONF, "Selected node '%s'", oshd_conf_selected_node());
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
        set_error("Invalid node name");
        return false;
    }
    memset(oshd.name, 0, sizeof(oshd.name));
    strncpy(oshd.name, ecp_value(ecp), NODE_NAME_SIZE);
    logger_debug(DBG_CONF, "Set daemon name to '%s'", oshd.name);
    return true;
}

// NetworkName
static bool oshd_param_networkname(ecp_t *ecp)
{
    if (!node_valid_name(ecp_value(ecp))) {
        // TODO: Print the invalid character in the error
        set_error("Invalid network name");
        return false;
    }
    memset(oshd.network_name, 0, sizeof(oshd.network_name));
    strncpy(oshd.network_name, ecp_value(ecp), NODE_NAME_SIZE);
    logger_debug(DBG_CONF, "Set network name to '%s'", oshd.network_name);
    return true;
}

// DynamicAddr
static bool oshd_param_dynamicaddr(ecp_t *ecp)
{
    if (!strcasecmp(ecp_value(ecp), "stable")) {
        oshd.dynamic_addr_stable = true;
    } else if (!strcasecmp(ecp_value(ecp), "random")) {
        oshd.dynamic_addr_stable = false;
    } else {
        set_error("Invalid DynamicAddr option");
        return false;
    }

    logger_debug(DBG_CONF, "Set DynamicAddr to %s",
        oshd.dynamic_addr_stable ? "stable" : "random");
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
        set_error("Invalid KeysTrust: '%s'", ecp_value(ecp));
        return false;
    }
    logger_debug(DBG_CONF, "%s authentication using remote keys",
        oshd.remote_auth ? "Enabled" : "Disabled");
    return true;
}

// ShareEndpoints
static bool oshd_param_shareendpoints(__attribute__((unused)) ecp_t *ecp)
{
    oshd.shareendpoints = true;
    logger_debug(DBG_CONF, "Enabled ShareEndpoints");
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
    int interval;

    if (sscanf(ecp_value(ecp), "%i", &interval) != 1) {
        set_error("Invalid %s value", ecp_name(ecp));
        return false;
    }
    if (interval <= 0) {
        set_error("%s must be a positive value", ecp_name(ecp));
        return false;
    }
    oshd.automatic_connections_interval = interval;
    logger_debug(DBG_CONF, "Set %s to %" PRI_TIME_T " seconds", ecp_name(ecp),
        (pri_time_t) oshd.automatic_connections_interval);
    return true;
}

// AutomaticConnectionsPercent
static bool oshd_param_automaticconnectionspercent(ecp_t *ecp)
{
    int percent;

    if (sscanf(ecp_value(ecp), "%i", &percent) != 1) {
        set_error("Invalid %s value", ecp_name(ecp));
        return false;
    }
    if (percent <= 0 || percent > 100) {
        set_error("%s must be a value between 0 and 100 (excluded)", ecp_name(ecp));
        return false;
    }
    oshd.automatic_connections_percent = percent;
    logger_debug(DBG_CONF, "Set %s to %zu%%", ecp_name(ecp),
        oshd.automatic_connections_percent);
    return true;
}

// Port
static bool oshd_param_port(ecp_t *ecp)
{
    int port;

    if (sscanf(ecp_value(ecp), "%i", &port) != 1) {
        set_error("Invalid port value");
        return false;
    }
    if (port <= 0 || port > 65535) {
        set_error("Invalid port: %i", port);
        return false;
    }
    oshd.server_port = port;
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
    } else if (!strcasecmp(ecp_value(ecp), "Dynamic")) {
        oshd.device_mode = MODE_DYNAMIC;
    } else {
        set_error("Unknown mode");
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

// Return the endpoint group of a node
// Creates an empty one if it doesn't exist yet
static endpoint_group_t *get_endpoint_group(const char *node_name)
{
    for (size_t i = 0; i < oshd.conf_endpoints_count; ++i) {
        if (!strcmp(oshd.conf_endpoints[i]->owner_name, node_name)) {
            // The node already has an endpoint group
            return oshd.conf_endpoints[i];
        }
    }

    // The node does not have an endpoint group, create it
    oshd.conf_endpoints_count += 1;
    oshd.conf_endpoints = xreallocarray(oshd.conf_endpoints,
        oshd.conf_endpoints_count, sizeof(endpoint_group_t *));
    oshd.conf_endpoints[oshd.conf_endpoints_count - 1] = endpoint_group_create(node_name, "conf");
    return oshd.conf_endpoints[oshd.conf_endpoints_count - 1];
}

// Endpoint
static bool oshd_param_endpoint(ecp_t *ecp)
{
    char *addr;
    char *port;
    uint16_t port_no;
    endpoint_group_t *group;
    endpoint_t *endpoint;
    const endpoint_t *inserted;

    if (!oshd_conf_require_selected_node(ecp))
        return false;

    // Copy the address to parse it
    addr = xstrdup(ecp_value(ecp));
    port = addr;

    // Get to the end of the address
    for (; *port && *port != ' ' && *port != '\t'; ++port);

    // End the address
    if (*port) *port++ = 0;

    // Skip the whitespaces to get to the start of the port (if there is one)
    for (; *port == ' ' || *port == '\t'; ++port);

    // Get the selected node's endpoints
    group = get_endpoint_group(oshd_conf_selected_node());

    // Convert the port value to a number
    port_no = (*port) ? ((uint16_t) atoi(port)) : OSHD_DEFAULT_PORT;

    // Add the endpoint to the group
    endpoint = endpoint_create(addr, port_no, ENDPOINT_PROTO_TCP, false);
    inserted = endpoint_group_insert_sorted(group, endpoint);

    logger_debug(DBG_CONF, "%s endpoint %s for %s",
        inserted ? "Added" : "Ignored",
        endpoint->addrstr,
        oshd_conf_selected_node());

    // Free the temporary address
    endpoint_free(endpoint);
    free(addr);
    return true;
}

// AlwaysConnect
static bool oshd_param_alwaysconnect(__attribute__((unused)) ecp_t *ecp)
{
    endpoint_group_t *group;

    if (!oshd_conf_require_selected_node(ecp))
        return false;

    group = get_endpoint_group(oshd_conf_selected_node());
    group->always_retry = true;
    return true;
}

// ReconnectDelayMin
static bool oshd_param_reconnectdelaymin(ecp_t *ecp)
{
    int delay;

    if (sscanf(ecp_value(ecp), "%i", &delay) != 1) {
        set_error("Invalid %s value", ecp_name(ecp));
        return false;
    }
    if (oshd.reconnect_delay_min <= 0) {
        set_error("%s cannot be of 0 seconds or less", ecp_name(ecp));
        return false;
    }
    oshd.reconnect_delay_min = delay;
    logger_debug(DBG_CONF, "Set %s to %" PRI_TIME_T, ecp_name(ecp),
        (pri_time_t) oshd.reconnect_delay_min);
    return true;
}

// ReconnectDelayMax
static bool oshd_param_reconnectdelaymax(ecp_t *ecp)
{
    int delay;

    if (sscanf(ecp_value(ecp), "%i", &delay) != 1) {
        set_error("Invalid %s value", ecp_name(ecp));
        return false;
    }
    if (oshd.reconnect_delay_max <= 0) {
        set_error("%s cannot be of 0 seconds or less", ecp_name(ecp));
        return false;
    }
    oshd.reconnect_delay_max = delay;
    logger_debug(DBG_CONF, "Set %s to %" PRI_TIME_T, ecp_name(ecp),
        (pri_time_t) oshd.reconnect_delay_max);
    return true;
}

// ConnectionsLimit
static bool oshd_param_connectionslimit(ecp_t *ecp)
{
    unsigned int limit;

    if (sscanf(ecp_value(ecp), "%u", &limit) != 1) {
        set_error("Invalid %s value", ecp_name(ecp));
        return false;
    }
    oshd.clients_count_max = limit;
    logger_debug(DBG_CONF, "Set %s to %zu%s", ecp_name(ecp), oshd.clients_count_max,
        (oshd.clients_count_max == 0) ? " (unlimited)" : "");
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

// LogLevel
static bool oshd_param_loglevel(ecp_t *ecp)
{
    if (!logger_set_level_name(ecp_value(ecp))) {
        set_error("Invalid LogLevel: %s", ecp_value(ecp));
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
        set_error("Failed to include '%s': %s", ecp_value(ecp), tmp);
        free(tmp);
        return false;
    }
    return true;
}

// PrivateKey
static bool oshd_param_privatekey(ecp_t *ecp)
{
    const char *b64 = ecp_value(ecp);
    const size_t b64_size = strlen(b64);
    uint8_t *privkey = NULL;
    size_t privkey_size;
    bool success = false;

    if (oshd.privkey) {
        set_error("A private key was already loaded");
        goto end;
    }

    privkey_size = BASE64_DECODE_OUTSIZE(b64_size);
    privkey = xzalloc(privkey_size);

    if (!base64_decode(privkey, &privkey_size, b64, b64_size)) {
        set_error("Failed to decode private key");
        goto end;
    }

    if (!(oshd.privkey = pkey_load_ed25519_privkey(privkey, privkey_size))) {
        set_error("Failed to load private key");
        goto end;
    }

    success = true;
    logger_debug(DBG_CONF, "Loaded private key from configuration file");

end:
    free(privkey);
    return success;
}

// PrivateKeyFile
static bool oshd_param_privatekeyfile(ecp_t *ecp)
{
    const char *filename = ecp_value(ecp);

    if (oshd.privkey) {
        set_error("A private key was already loaded");
        return false;
    }

    if (!(oshd.privkey = pkey_load_privkey_pem(filename))) {
        set_error("Failed to load private key from '%s'", filename);
        return false;
    }

    logger_debug(DBG_CONF, "Loaded private key from '%s'", filename);
    return true;
}

// Load a Base64 encoded public key for a node and add it to oshd.conf_pubkeys
// Returns false on error
static bool conf_pubkey_add(const char *node_name, const char *pubkey64)
{
    size_t pubkey64_size;
    uint8_t *pubkey = NULL;
    size_t pubkey_size;
    EVP_PKEY *pkey = NULL;
    bool success = false;

    // Verify that the node's name is valid
    if (!node_valid_name(node_name)) {
        set_error("Invalid node name: '%s'", node_name);
        goto end;
    }

    // Verify that there is a public key
    pubkey64_size = pubkey64 ? strlen(pubkey64) : 0;
    if (pubkey64_size == 0) {
        set_error("%s does not have a public key", node_name);
        goto end;
    }

    // Decode the Base64 public key
    pubkey = xzalloc(BASE64_DECODE_OUTSIZE(pubkey64_size));
    if (!base64_decode(pubkey, &pubkey_size, pubkey64, pubkey64_size)) {
        set_error("Failed to decode public key for %s", node_name);
        goto end;
    }

    // Load it
    if (!(pkey = pkey_load_ed25519_pubkey(pubkey, pubkey_size))) {
        set_error("Failed to load public key for %s", node_name);
        goto end;
    }

    // Check if this node is already in the conf_pubkeys list to prevent
    // duplicates
    for (size_t i = 0; i < oshd.conf_pubkeys_size; ++i) {
        if (!strcmp(oshd.conf_pubkeys[i].node_name, node_name)) {
            set_error("A public key was already loaded for %s", node_name);
            goto end;
        }
    }

    // Add the public key
    oshd.conf_pubkeys = xreallocarray(oshd.conf_pubkeys,
        oshd.conf_pubkeys_size + 1, sizeof(conf_pubkey_t));
    memset(&oshd.conf_pubkeys[oshd.conf_pubkeys_size], 0, sizeof(conf_pubkey_t));
    strncpy(oshd.conf_pubkeys[oshd.conf_pubkeys_size].node_name, node_name, NODE_NAME_SIZE);
    oshd.conf_pubkeys[oshd.conf_pubkeys_size].pkey = pkey;
    oshd.conf_pubkeys_size += 1;

    pkey = NULL; // The key shouldn't be freed
    success = true;
    logger_debug(DBG_CONF, "Loaded public key for %s", node_name);

end:
    free(pubkey);
    pkey_free(pkey);
    return success;
}

// PublicKey
static bool oshd_param_publickey(ecp_t *ecp)
{
    if (!oshd_conf_require_selected_node(ecp))
        return false;

    return conf_pubkey_add(oshd_conf_selected_node(), ecp_value(ecp));
}

// PublicKeysFile
static bool oshd_param_publickeysfile(ecp_t *ecp)
{
    bool success = false;
    const char *filename = ecp_value(ecp);
    ec_t *conf = ec_load_from_file(filename);

    ec_foreach(i, conf) {
        if (!conf_pubkey_add(ecp_name(i), ecp_value(i)))
            goto end;
    }
    success = true;

end:
    ec_destroy(conf);
    return success;
}

// Add a route to oshd.conf_routes
static bool conf_route_add(const netaddr_t *addr, netaddr_prefixlen_t prefixlen)
{
    // Prevent adding the same route twice
    for (size_t i = 0; i < oshd.conf_routes_size; ++i) {
        if (   oshd.conf_routes[i].prefixlen == prefixlen
            && netaddr_eq(&oshd.conf_routes[i].addr, addr))
        {
            return false;
        }
    }

    oshd.conf_routes = xreallocarray(oshd.conf_routes, oshd.conf_routes_size + 1,
        sizeof(conf_route_t));
    netaddr_cpy(&oshd.conf_routes[oshd.conf_routes_size].addr, addr);
    oshd.conf_routes[oshd.conf_routes_size].prefixlen = prefixlen;
    oshd.conf_routes_size += 1;
    return true;
}

// Route
static bool oshd_param_route(ecp_t *ecp)
{
    char *addrp = NULL;
    unsigned int prefixlen;
    netaddr_t addr;

    // Separate the address and prefix length
    if (sscanf(ecp_value(ecp), "%m[^/]/%u", &addrp, &prefixlen) != 2) {
        set_error("Invalid route format");
        free(addrp);
        return false;
    }

    // Parse the address
    if (!addrp || !netaddr_pton(&addr, addrp)) {
        set_error("Invalid route address");
        free(addrp);
        return false;
    }

    // Verify the prefix length
    if (prefixlen > netaddr_max_prefixlen(addr.type)) {
        set_error("Invalid route prefix length %u", prefixlen);
        free(addrp);
        return false;
    }

    // Add the local route
    if (conf_route_add(&addr, prefixlen)) {
        logger_debug(DBG_CONF, "Added local route %s/%u", addrp, prefixlen);
    } else {
        logger(LOG_WARN, "Ignoring duplicate local route %s/%u", addrp, prefixlen);
    }
    free(addrp);
    return true;
}

// Node
static bool oshd_param_node(ecp_t *ecp)
{
    return oshd_conf_select_node(ecp_value(ecp));
}

// Parameters that set commands (the command name is the same as the parameter)
static bool oshd_param_command(ecp_t *ecp)
{
    oshd_cmd_set(ecp_name(ecp), ecp_value(ecp));
    logger_debug(DBG_CONF, "Set %s to '%s'", ecp_name(ecp), ecp_value(ecp));
    return true;
}

// Old removed parameters
static bool oshd_param_removed(ecp_t *ecp)
{
    logger(LOG_WARN, "Ignoring '%s': this parameter was removed", ecp_name(ecp));
    return true;
}

// Array of all configuration parameters and their handlers
static const oshd_conf_param_t oshd_conf_params[] = {
    { .name = "NoServer", .type = VALUE_NONE, &oshd_param_noserver },
    { .name = "Name", .type = VALUE_REQUIRED, &oshd_param_name },
    { .name = "NetworkName", .type = VALUE_REQUIRED, &oshd_param_networkname },
    { .name = "DynamicAddr", .type = VALUE_REQUIRED, &oshd_param_dynamicaddr },
    { .name = "KeysTrust", .type = VALUE_REQUIRED, &oshd_param_keystrust },
    { .name = "ShareEndpoints", .type = VALUE_NONE, &oshd_param_shareendpoints },
    { .name = "DiscoverEndpoints", .type = VALUE_OPTIONAL, &oshd_param_removed },
    { .name = "AutomaticConnections", .type = VALUE_NONE, &oshd_param_automaticconnections },
    { .name = "AutomaticConnectionsInterval", .type = VALUE_REQUIRED, &oshd_param_automaticconnectionsinterval },
    { .name = "AutomaticConnectionsPercent", .type = VALUE_REQUIRED, &oshd_param_automaticconnectionspercent },
    { .name = "Port", .type = VALUE_REQUIRED, &oshd_param_port },
    { .name = "Mode", .type = VALUE_REQUIRED, &oshd_param_mode },
    { .name = "Device", .type = VALUE_REQUIRED, &oshd_param_device },
    { .name = "ExcludeDevice", .type = VALUE_OPTIONAL, &oshd_param_removed },
    { .name = "DevUp", .type = VALUE_REQUIRED, &oshd_param_command },
    { .name = "DevDown", .type = VALUE_REQUIRED, &oshd_param_command },
    { .name = "Endpoint", .type = VALUE_REQUIRED, &oshd_param_endpoint },
    { .name = "AlwaysConnect", .type = VALUE_NONE, &oshd_param_alwaysconnect },
    { .name = "ReconnectDelayMin", .type = VALUE_REQUIRED, &oshd_param_reconnectdelaymin },
    { .name = "ReconnectDelayMax", .type = VALUE_REQUIRED, &oshd_param_reconnectdelaymax },
    { .name = "ConnectionsLimit", .type = VALUE_REQUIRED, &oshd_param_connectionslimit },
    { .name = "DigraphFile", .type = VALUE_REQUIRED, &oshd_param_digraphfile },
    { .name = "Resolver", .type = VALUE_OPTIONAL, &oshd_param_removed },
    { .name = "ResolverTLD", .type = VALUE_OPTIONAL, &oshd_param_removed },
    { .name = "ResolverFile", .type = VALUE_OPTIONAL, &oshd_param_removed },
    { .name = "OnResolverUpdate", .type = VALUE_OPTIONAL, &oshd_param_removed },
    { .name = "LogLevel", .type = VALUE_REQUIRED, &oshd_param_loglevel },
    { .name = "Include", .type = VALUE_REQUIRED, &oshd_param_include },
    { .name = "PrivateKey", .type = VALUE_REQUIRED, &oshd_param_privatekey },
    { .name = "PrivateKeyFile", .type = VALUE_REQUIRED, &oshd_param_privatekeyfile },
    { .name = "PublicKey", .type = VALUE_REQUIRED, &oshd_param_publickey },
    { .name = "PublicKeysFile", .type = VALUE_REQUIRED, &oshd_param_publickeysfile },
    { .name = "Route", .type = VALUE_REQUIRED, &oshd_param_route },
    { .name = "Node", .type = VALUE_REQUIRED, &oshd_param_node },
    { NULL, 0, NULL }
};

// Initialize oshd_t global
void oshd_init_conf(void)
{
    // Seed the PRNG
    srand(time(NULL));
    if (!random_xoshiro256_seed())
        abort();

    // Initialize sockets
    if (sock_init() != 0)
        abort();

    // Everything should be at zero, including pointers and counts
    memset(&oshd, 0, sizeof(oshd_t));

    // Everything that should not be zero by default is set
    oshd.server_port = OSHD_DEFAULT_PORT;
    oshd.server_enabled = true;

    oshd.reconnect_delay_min = 10;
    oshd.reconnect_delay_max = 60;

    oshd.automatic_connections_interval = 3600; // 1 hour (60m, 3600s)
    oshd.automatic_connections_percent = 50;

    oshd.route_table = netroute_table_create(4096);
    netroute_add_broadcasts(oshd.route_table);

    oshd.dynamic_addr_stable = true;
    for (size_t i = 0; i < dynamic_addr_count; ++i)
        memset(&oshd.dynamic_addrs[i], 0, sizeof(dynamic_addr_t));

    oshd.run = true;
}

// One-time configuration checks
static bool validate_configuration(void)
{
    if (strlen(oshd.name) == 0) {
        logger(LOG_ERR, "The daemon must have a name");
        return false;
    }

    if (!oshd.privkey) {
        logger(LOG_ERR, "The daemon must have a private key");
        return false;
    }

    if (oshd.reconnect_delay_max < oshd.reconnect_delay_min) {
        logger(LOG_ERR,
            "ReconnectDelayMax (%" PRI_TIME_T "s) cannot be smaller than ReconnectDelayMin (%" PRI_TIME_T "s)",
            (pri_time_t) oshd.reconnect_delay_max, (pri_time_t) oshd.reconnect_delay_min);
        return false;
    }

    if (   oshd.device_mode == MODE_DYNAMIC
        && strlen(oshd.network_name) == 0)
    {
        logger(LOG_ERR, "NetworkName must be set when using the dynamic device mode");
        return false;
    }

    return true;
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

        // Remember the current parameter's line number to display on error
        oshd_conf_error_line_no = ecp_line_no(ecp);

        // Iterate the iterator now because the current configuration can change
        // if another file is included and we would iterate a different one
        conf_curr.iter = conf_curr.iter->next;

        logger_debug(DBG_CONF, "Processing parameter '%s' line %zu",
            ecp_name(ecp), ecp_line_no(ecp));

        // Find the corresponding handler for the parameter
        for (size_t i = 0; oshd_conf_params[i].name; ++i) {
            if (!strcmp(ecp_name(ecp), oshd_conf_params[i].name)) {
                found = true;

                if (   oshd_conf_params[i].type == VALUE_NONE
                    && ecp_value(ecp))
                {
                    set_error("%s does not take a value", oshd_conf_params[i].name);
                    load_error = true;
                    break;
                } else if (   oshd_conf_params[i].type == VALUE_REQUIRED
                           && !ecp_value(ecp))
                {
                    set_error("%s requires a value", oshd_conf_params[i].name);
                    load_error = true;
                    break;
                }

                if (!(oshd_conf_params[i].handler(ecp)))
                    load_error = true;
                break;
            }
        }

        if (!found) {
            set_error("Invalid parameter: %s", ecp_name(ecp));
            load_error = true;
        }

        // On any error we stop loading the configuration right away
        if (load_error)
            break;
    }

    // Display error if there was one
    if (load_error) {
        logger(LOG_ERR, "%s: line %zu: %s", conf_curr.filename,
            oshd_conf_error_line_no, oshd_conf_error);
    }

    // Pop any remaining configuration files
    while (oshd_conf_count > 0)
        oshd_conf_pop();

    // If there was an error we stop here
    if (load_error)
        return false;

    // One-shot checks
    if (!validate_configuration())
        return false;

    // The configuration was loaded successfully
    return true;
}
