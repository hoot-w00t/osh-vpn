#ifndef _OSH_OSHD_H
#define _OSH_OSHD_H

#include "node.h"
#include "oshd_route.h"
#include "crypto/pkey.h"
#include <stdbool.h>
#include <stdint.h>

#define OSHD_DEFAULT_PORT (9270)

typedef struct oshd {
    // Name of the local node
    char name[NODE_NAME_SIZE + 1];

    // Keys directory to fetch all private and public keys from
    char *keys_dir;

    // true of authentication using remote keys is allowed
    bool remote_auth;

    // The local node's private and public keys
    EVP_PKEY *privkey;

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

    // Array of the node's sockets, all direct connections
    node_t **nodes;
    size_t nodes_count;
    bool nodes_updated;

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

    // Minimum and maximum reconnection delays (in seconds)
    time_t reconnect_delay_min;
    time_t reconnect_delay_max;

    // Path to a file to dump the digraph to
    char *digraph_file;

    // When set to false the daemon will stop
    bool run;
} oshd_t;

EVP_PKEY *oshd_open_key(const char *name, bool private);
bool oshd_open_keys(const char *dirname);

int set_nonblocking(int fd);

void oshd_stop(void);
bool oshd_init(void);
void oshd_free(void);
void oshd_loop(void);

#endif

#ifndef _OSH_OSHD_C
#define _OSH_OSHD_C

// The global is defined in oshd.c
extern oshd_t oshd;

#endif