#ifndef _OSH_OSHD_H
#define _OSH_OSHD_H

#include "node.h"
#include "tuntap.h"
#include "oshd_route.h"
#include "oshd_resolver.h"
#include "oshd_device_mode.h"
#include "crypto/pkey.h"
#include <stdbool.h>
#include <stdint.h>

#define OSHD_DEFAULT_PORT (9270)

typedef struct oshd {
    // Name of the local node
    char name[NODE_NAME_SIZE + 1];

    // Keys directory to fetch all private and public keys from
    char *keys_dir;

    // true if authenticating nodes using remote keys is allowed, otherwise only
    // local keys will be used
    bool remote_auth;

    // true if local endpoints should be shared with the network
    bool shareendpoints;

    // Automatic connections
    bool automatic_connections;
    time_t automatic_connections_interval;
    size_t automatic_connections_percent;

    // The local node's private and public keys
    EVP_PKEY *privkey;

    // TUN/TAP device information
    device_mode_t device_mode; // The mode of the TUN/TAP device
    tuntap_t *tuntap;          // The TUN/TAP device
    char *tuntap_devname;       // The requested TUN/TAP device name

    int server_fd;        // TCP server socket
    int server_fd6;       // TCP6 server socket
    uint16_t server_port; // TCP server port
    bool server_enabled;  // true if the TCP server will be opened and used

    // List of remote endpoints to connect to
    endpoint_group_t **remote_endpoints;
    size_t remote_count;

    // Array of the node's sockets, all direct connections
    node_t **nodes;
    size_t nodes_count;
    size_t nodes_count_max;
    bool nodes_updated;

    // Array of all nodes on the network (ID)
    node_id_t **node_tree;
    size_t node_tree_count;

    // Contains the same allocated pointers as node_tree, only the array pointer
    // should be freed
    // Node ID tree sorted by hops_count (highest to lowest)
    node_id_t **node_tree_ordered_hops;

    // Array of the network routes of the local node
    netaddr_t *local_routes;
    size_t local_routes_count;

    // Array of the network routes of remote nodes on the network
    // This is our routing table
    oshd_route_t **routes;
    size_t routes_count;

    // Array of network device names/IDs which should be excluded from the
    // endpoint discovery
    char **excluded_devices;
    size_t excluded_devices_count;

    // Minimum and maximum reconnection delays (in seconds)
    time_t reconnect_delay_min;
    time_t reconnect_delay_max;

    // Resolver parameters
    resolver_type_t resolver;
    char *resolver_tld;
    char *resolver_file;

    // Path to a file to dump the digraph to
    char *digraph_file;

    // When set to false the daemon will stop
    bool run;
} oshd_t;

// true if the maximum number of nodes is reached
#define oshd_nodes_limited() (oshd.nodes_count_max != 0 && oshd.nodes_count >= oshd.nodes_count_max)

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