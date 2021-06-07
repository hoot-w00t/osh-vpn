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

// NoDevice
static bool oshd_param_nodevice(__attribute__((unused)) ecp_t *ecp)
{
    oshd.tuntap_used = false;
    logger_debug(DBG_CONF, "Disabled TUN/TAP device");
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

// RemoteAuth
static bool oshd_param_remoteauth(__attribute__((unused)) ecp_t *ecp)
{
    oshd.remote_auth = true;
    logger_debug(DBG_CONF, "Enabled RemoteAuth");
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
    if (!strcmp(ecp_value(ecp), "tap")) {
        oshd.is_tap = true;
    } else if (!strcmp(ecp_value(ecp), "tun")) {
        oshd.is_tap = false;
    } else {
        snprintf(oshd_conf_error, sizeof(oshd_conf_error), "Unknown mode");
        return false;
    }
    logger_debug(DBG_CONF, "Set device mode to %s", oshd.is_tap ? "TAP" : "TUN");
    return true;
}

// Device
static bool oshd_param_device(ecp_t *ecp)
{
    memset(oshd.tuntap_dev, 0, sizeof(oshd.tuntap_dev));
    strncpy(oshd.tuntap_dev, ecp_value(ecp), sizeof(oshd.tuntap_dev) - 1);
    logger_debug(DBG_CONF, "Set device name to %s", ecp_value(ecp));
    return true;
}

// DevUp
static bool oshd_param_devup(ecp_t *ecp)
{
    oshd_cmd_set("DevUp", ecp_value(ecp));
    logger_debug(DBG_CONF, "Set DevUp to %s", ecp_value(ecp));
    return true;
}

// DevDown
static bool oshd_param_devdown(ecp_t *ecp)
{
    oshd_cmd_set("DevDown", ecp_value(ecp));
    logger_debug(DBG_CONF, "Set DevDown to %s", ecp_value(ecp));
    return true;
}

// Remote
static bool oshd_param_remote(ecp_t *ecp)
{
    char *addr = xstrdup(ecp_value(ecp));
    char *port = addr;

    // Skip the address to get to the next value (separated with whitespaces)
    for (; *port && *port != ' ' && *port != '\t'; ++port);

    // If there are still characters after the address, separate the address and
    // port values
    if (*port) *port++ = '\0';

    // Go to the start of the second parameter, skipping whitespaces
    for (; *port == ' ' || *port == '\t'; ++port);

    // Append a new address and port to the remote lists
    oshd.remote_addrs = xrealloc(oshd.remote_addrs,
        sizeof(char *) * (oshd.remote_count + 1));
    oshd.remote_ports = xrealloc(oshd.remote_ports,
        sizeof(uint16_t) * (oshd.remote_count + 1));

    // Set the address
    oshd.remote_addrs[oshd.remote_count] = addr;

    // Set the port
    if ((*port)) {
        oshd.remote_ports[oshd.remote_count] = (uint16_t) atoi(port);
    } else {
        oshd.remote_ports[oshd.remote_count] = OSHD_DEFAULT_PORT;
    }

    logger_debug(DBG_CONF, "Remote: %s:%u added",
        oshd.remote_addrs[oshd.remote_count],
        oshd.remote_ports[oshd.remote_count]);

    oshd.remote_count += 1;
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

// DigraphFile
static bool oshd_param_digraphfile(ecp_t *ecp)
{
    free(oshd.digraph_file);
    oshd.digraph_file = xstrdup(ecp_value(ecp));
    logger_debug(DBG_CONF, "Set DigraphFile to '%s'", oshd.digraph_file);
    return true;
}

// Array of all configuration parameters and their handlers
static const oshd_conf_param_t oshd_conf_params[] = {
    { .name = "NoServer", .type = VALUE_NONE, &oshd_param_noserver },
    { .name = "NoDevice", .type = VALUE_NONE, &oshd_param_nodevice },
    { .name = "Name", .type = VALUE_REQUIRED, &oshd_param_name },
    { .name = "KeysDir", .type = VALUE_REQUIRED, &oshd_param_keysdir },
    { .name = "RemoteAuth", .type = VALUE_NONE, &oshd_param_remoteauth },
    { .name = "Port", .type = VALUE_REQUIRED, &oshd_param_port },
    { .name = "Mode", .type = VALUE_REQUIRED, &oshd_param_mode },
    { .name = "Device", .type = VALUE_REQUIRED, &oshd_param_device },
    { .name = "DevUp", .type = VALUE_REQUIRED, &oshd_param_devup },
    { .name = "DevDown", .type = VALUE_REQUIRED, &oshd_param_devdown },
    { .name = "Remote", .type = VALUE_REQUIRED, &oshd_param_remote },
    { .name = "ReconnectDelayMin", .type = VALUE_REQUIRED, &oshd_param_reconnectdelaymin },
    { .name = "ReconnectDelayMax", .type = VALUE_REQUIRED, &oshd_param_reconnectdelaymax },
    { .name = "DigraphFile", .type = VALUE_REQUIRED, &oshd_param_digraphfile },
    { NULL, 0, NULL }
};

// Initialize oshd_t global
void oshd_init_conf(void)
{
    // Everything should be at zero, including pointers and counts
    memset(&oshd, 0, sizeof(oshd_t));

    // Everything that should not be zero by default is set
    oshd.keys_dir = xstrdup("./");

    oshd.tuntap_used = true;
    oshd.tuntap_fd = -1;

    oshd.server_fd = -1;
    oshd.server_port = OSHD_DEFAULT_PORT;
    oshd.server_enabled = true;

    oshd.reconnect_delay_min = 10;
    oshd.reconnect_delay_max = 60;

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
        logger(LOG_ERR, "ReconnectDelayMax (%lus) cannot be smaller than ReconnectDelayMin (%lus)",
            oshd.reconnect_delay_max, oshd.reconnect_delay_min);
        return false;
    }

    return true;

on_error:
    logger(LOG_ERR, "%s: %s", filename, oshd_conf_error);
    ec_destroy(conf);
    return false;
}