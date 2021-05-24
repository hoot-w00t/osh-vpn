#ifndef _OSH_OSHD_H
#define _OSH_OSHD_H

#include "node.h"
#include "oshd_route.h"
#include <stdbool.h>
#include <stdint.h>

#define OSHD_DEFAULT_PORT (9270)

typedef struct oshd {
    // Name of the local node
    char name[NODE_NAME_SIZE + 1];

    // TUN/TAP device information
    bool tuntap_used;    // true if the device will be opened and used
    int tuntap_fd;       // File descriptor of the device
    char tuntap_dev[17]; // Name of the device interface
    bool is_tap;         // true if the device is running in Layer 2 (TAP)
                         // Otherwise the device is in Layer 3 (TUN)

    int server_fd;        // TCP server socket
    uint16_t server_port; // TCP server port
    bool server_enabled;  // true if the TCP server will be opened and used

    char **remote_addrs;    // List of remote addresses to connect to
                            // Loaded from the configuration file
    uint16_t *remote_ports; // List of remote ports corresponding to the remote
                            // addresses
    size_t remote_count;    // Amount of entries in those arrays

    char *cmd_devup;   // Command that will be executed after the TUN/TAP
                       // device is opened
    char *cmd_devdown; // Same as above but will be executed right before the
                       // device is closed

    // Array of the node's sockets, all direct connections
    node_t **nodes;
    size_t nodes_count;

    // Array of all nodes on the network (ID)
    node_id_t **node_tree;
    size_t node_tree_count;

    // Array of the network routes of the local node
    netaddr_t *local_routes;
    size_t local_routes_count;

    // Array of the network routes of remote nodes on the network
    // This is our routing table
    netroute_t **routes;
    size_t routes_count;

    // When set to false the daemon will stop
    bool run;
} oshd_t;

int set_nonblocking(int fd);

void pfd_resize(void);
void pfd_update(void);
void node_add(node_t *node);
void node_remove(node_t *node);

bool oshd_init(void);
void oshd_free(void);
bool oshd_process_packet(node_t *node);
void oshd_loop(void);

#endif

#ifndef _OSH_OSHD_C
#define _OSH_OSHD_C

// The global is defined in oshd.c
extern oshd_t oshd;

#endif