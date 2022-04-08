#include "oshd.h"
#include "oshd_cmd.h"
#include "oshd_conf.h"
#include "base64.h"
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

// Line number of the last error message
static size_t oshd_conf_error_line_no = 0;

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

// Old resolver parameters
static bool oshd_param_resolver_removed(__attribute__((unused)) ecp_t *ecp)
{
    logger(LOG_WARN, "Ignoring '%s': this parameter was removed", ecp_name(ecp));
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

// PrivateKey
static bool oshd_param_privatekey(ecp_t *ecp)
{
    const char *b64 = ecp_value(ecp);
    const size_t b64_size = strlen(b64);
    uint8_t *privkey = NULL;
    size_t privkey_size;
    bool success = false;

    if (oshd.privkey) {
        snprintf(oshd_conf_error, sizeof(oshd_conf_error),
            "A private key was already loaded");
        goto end;
    }

    privkey_size = BASE64_DECODE_OUTSIZE(b64_size);
    privkey = xzalloc(privkey_size);

    if (!base64_decode(privkey, &privkey_size, b64, b64_size)) {
        snprintf(oshd_conf_error, sizeof(oshd_conf_error),
            "Failed to decode private key");
        goto end;
    }

    if (!(oshd.privkey = pkey_load_ed25519_privkey(privkey, privkey_size))) {
        snprintf(oshd_conf_error, sizeof(oshd_conf_error),
            "Failed to load private key");
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
        snprintf(oshd_conf_error, sizeof(oshd_conf_error),
            "A private key was already loaded");
        return false;
    }

    if (!(oshd.privkey = pkey_load_privkey_pem(filename))) {
        snprintf(oshd_conf_error, sizeof(oshd_conf_error),
            "Failed to load private key from '%s'", filename);
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
        snprintf(oshd_conf_error, sizeof(oshd_conf_error),
            "Invalid node name: '%s'", node_name);
        goto end;
    }

    // Verify that there is a public key
    pubkey64_size = pubkey64 ? strlen(pubkey64) : 0;
    if (pubkey64_size == 0) {
        snprintf(oshd_conf_error, sizeof(oshd_conf_error),
            "%s does not have a public key", node_name);
        goto end;
    }

    // Decode the Base64 public key
    pubkey = xzalloc(BASE64_DECODE_OUTSIZE(pubkey64_size));
    if (!base64_decode(pubkey, &pubkey_size, pubkey64, pubkey64_size)) {
        snprintf(oshd_conf_error, sizeof(oshd_conf_error),
            "Failed to decode public key for %s", node_name);
        goto end;
    }

    // Load it
    if (!(pkey = pkey_load_ed25519_pubkey(pubkey, pubkey_size))) {
        snprintf(oshd_conf_error, sizeof(oshd_conf_error),
            "Failed to load public key for %s", node_name);
        goto end;
    }

    // Check if this node is already in the conf_pubkeys list to prevent
    // duplicates
    for (size_t i = 0; i < oshd.conf_pubkeys_size; ++i) {
        if (!strcmp(oshd.conf_pubkeys[i].node_name, node_name)) {
            snprintf(oshd_conf_error, sizeof(oshd_conf_error),
                "A public key was already loaded for %s", node_name);
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
    char *node_name = xstrdup(ecp_value(ecp));
    char *pubkey64 = node_name;
    bool success;

    // Get to the end of the node name
    for (; *pubkey64 && *pubkey64 != ' ' && *pubkey64 != '\t'; ++pubkey64);

    // End the node name
    if (*pubkey64) *pubkey64++ = 0;

    // Skip the whitespaces to get to the start of the public key
    for (; *pubkey64 == ' ' || *pubkey64 == '\t'; ++pubkey64);

    success = conf_pubkey_add(node_name, pubkey64);
    free(node_name);
    return success;
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
    { .name = "Resolver", .type = VALUE_OPTIONAL, &oshd_param_resolver_removed },
    { .name = "ResolverTLD", .type = VALUE_OPTIONAL, &oshd_param_resolver_removed },
    { .name = "ResolverFile", .type = VALUE_OPTIONAL, &oshd_param_resolver_removed },
    { .name = "OnResolverUpdate", .type = VALUE_OPTIONAL, &oshd_param_resolver_removed },
    { .name = "LogLevel", .type = VALUE_REQUIRED, &oshd_param_loglevel },
    { .name = "Include", .type = VALUE_REQUIRED, &oshd_param_include },
    { .name = "PrivateKey", .type = VALUE_REQUIRED, &oshd_param_privatekey },
    { .name = "PrivateKeyFile", .type = VALUE_REQUIRED, &oshd_param_privatekeyfile },
    { .name = "PublicKey", .type = VALUE_REQUIRED, &oshd_param_publickey },
    { .name = "PublicKeysFile", .type = VALUE_REQUIRED, &oshd_param_publickeysfile },
    { NULL, 0, NULL }
};

// Initialize oshd_t global
void oshd_init_conf(void)
{
    // Seed the PRNG
    srand(time(NULL));

    // Everything should be at zero, including pointers and counts
    memset(&oshd, 0, sizeof(oshd_t));

    // Everything that should not be zero by default is set
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

    // One-shot verifications

    if (strlen(oshd.name) == 0) {
        logger(LOG_ERR, "The daemon must have a name");
        return false;
    }

    if (!oshd.privkey) {
        logger(LOG_ERR, "The daemon must have a private key");
        return false;
    }

    if (oshd.reconnect_delay_max < oshd.reconnect_delay_min) {
        logger(LOG_ERR, "ReconnectDelayMax (%lis) cannot be smaller than ReconnectDelayMin (%lis)",
            oshd.reconnect_delay_max, oshd.reconnect_delay_min);
        return false;
    }

    // The configuration was loaded successfully
    return true;
}