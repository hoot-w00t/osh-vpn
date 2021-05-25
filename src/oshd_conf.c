#include "oshd.h"
#include "oshd_cmd.h"
#include "xalloc.h"
#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <easyconf.h>

// Initialize oshd_t global
void oshd_init_conf(void)
{
    // Everything should be at zero, including pointers and counts
    memset(&oshd, 0, sizeof(oshd_t));

    // Everything that should not be zero by default is set
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
    ecp_t *p;
    char err[256];

    if (!(conf = ec_load_from_file(filename))) {
        logger(LOG_ERR, "%s: %s", filename, strerror(errno));
        return false;
    }

    // Load single parameters

    if (ec_find(conf, "NoServer"))
        oshd.server_enabled = false;

    if (ec_find(conf, "NoDevice"))
        oshd.tuntap_used = false;

    if ((p = ec_find(conf, "Name")) && ecp_value(p)) {
        if (!node_valid_name(ecp_value(p))) {
            // TODO: Print the invalid character in the error
            snprintf(err, sizeof(err), "Invalid node name");
            goto on_error;
        }
        strncpy(oshd.name, ecp_value(p), NODE_NAME_SIZE);
    } else {
        snprintf(err, sizeof(err), "The node requires a name");
        goto on_error;
    }

    if ((p = ec_find(conf, "Port")))
        oshd.server_port = (uint16_t) atoi(ecp_value(p));

    if ((p = ec_find(conf, "Mode"))) {
        if (!ecp_value(p)) {
            snprintf(err, sizeof(err), "Mode requires a value");
            goto on_error;
        }
        if (!strcmp(ecp_value(p), "tap")) {
            oshd.is_tap = true;
        } else if (!strcmp(ecp_value(p), "tun")) {
            oshd.is_tap = false;
        } else {
            snprintf(err, sizeof(err), "Unknown mode");
            goto on_error;
        }
    }

    if ((p = ec_find(conf, "Device"))) {
        memset(oshd.tuntap_dev, 0, sizeof(oshd.tuntap_dev));
        if (ecp_value(p))
            strncpy(oshd.tuntap_dev, ecp_value(p), sizeof(oshd.tuntap_dev) - 1);
    }

    if ((p = ec_find(conf, "DevUp"))) {
        if (!ecp_value(p)) {
            snprintf(err, sizeof(err), "DevUp requires a value");
            goto on_error;
        }
        oshd_cmd_set("DevUp", ecp_value(p));
    }

    if ((p = ec_find(conf, "DevDown"))) {
        if (!ecp_value(p)) {
            snprintf(err, sizeof(err), "DevDown requires a value");
            goto on_error;
        }
        oshd_cmd_set("DevDown", ecp_value(p));
    }

    // Load all remotes

    ec_foreach(pr, conf) {
        if (strcmp(ecp_name(pr), "Remote")) continue;
        if (!ecp_value(pr)) {
            snprintf(err, sizeof(err), "Remote requires a value");
            goto on_error;
        }

        char *addr = xstrdup(ecp_value(pr));
        char *port = addr;

        for (; *port && *port != ' ' && *port != '\t'; ++port);
        if (*port) *port++ = '\0';
        for (; *port == ' ' || *port == '\t'; ++port);

        oshd.remote_addrs = xrealloc(oshd.remote_addrs,
            sizeof(char *) * (oshd.remote_count + 1));
        oshd.remote_ports = xrealloc(oshd.remote_ports,
            sizeof(uint16_t) * (oshd.remote_count + 1));

        oshd.remote_addrs[oshd.remote_count] = addr;
        if ((*port)) {
            oshd.remote_ports[oshd.remote_count] = (uint16_t) atoi(port);
        } else {
            oshd.remote_ports[oshd.remote_count] = OSHD_DEFAULT_PORT;
        }

        logger(LOG_INFO, "Remote: %s:%u added",
            oshd.remote_addrs[oshd.remote_count],
            oshd.remote_ports[oshd.remote_count]);

        oshd.remote_count += 1;
    }

    ec_destroy(conf);
    return true;

on_error:
    logger(LOG_ERR, "%s: %s", filename, err);
    ec_destroy(conf);
    return false;
}