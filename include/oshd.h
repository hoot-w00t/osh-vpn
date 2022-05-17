#ifndef _OSH_OSHD_H
#define _OSH_OSHD_H

#include "aio.h"
#include "node.h"
#include "tuntap.h"
#include "netroute.h"
#include "device_mode.h"
#include "crypto/pkey.h"
#include <stdbool.h>
#include <stdint.h>

#define OSHD_DEFAULT_PORT (9270)

#ifndef OSHD_TCP_SERVER_BACKLOG
#define OSHD_TCP_SERVER_BACKLOG (5)
#endif

typedef struct conf_pubkey {
    char node_name[NODE_NAME_SIZE + 1];
    EVP_PKEY *pkey;
} conf_pubkey_t;

typedef struct conf_route {
    netaddr_t addr;
    netaddr_prefixlen_t prefixlen;
} conf_route_t;

typedef struct dynamic_addr {
    netaddr_t addr;                      // Dynamic IP address
    netaddr_prefixlen_t prefixlen;       // Prefix length of its network
    netaddr_prefixlen_t route_prefixlen; // Prefix length of the single address
                                         // used for the routing table
    char addr_str[INET6_ADDRSTRLEN];     // Formatted string of the IP address
    char prefixlen_str[8];               // Formatted string of the prefix length

    bool handling_conflict; // set to true while a conflict is in the process
                            // of being solved to prevent queuing more than one
                            // dynamic_ip_conflict event
} dynamic_addr_t;
#define dynamic_addr_count (2)

typedef struct oshd {
    // Name of the local node
    char name[NODE_NAME_SIZE + 1];

    // Name of the mesh (shares the same properties as node names)
    char network_name[NODE_NAME_SIZE + 1];

    // Dynamic addresses of the mesh when using dynamic device mode
    // The IPv6 prefix is a pseudo-random ULA generated using the network name
    // The IPv4 prefix is always 169.254.0.0/16
    bool dynamic_addr_stable;

    netaddr_t dynamic_prefix6;
    netaddr_prefixlen_t dynamic_prefixlen6;
    char dynamic_prefix6_str[INET6_ADDRSTRLEN];

    netaddr_t dynamic_prefix4;
    netaddr_prefixlen_t dynamic_prefixlen4;
    char dynamic_prefix4_str[INET6_ADDRSTRLEN];

    dynamic_addr_t dynamic_addrs[dynamic_addr_count];

    // true if authenticating nodes using remote keys is allowed, otherwise only
    // local keys will be used
    bool remote_auth;

    // true if the remotes loaded from the configuration file should be shared
    // with other nodes on the network
    bool shareremotes;

    // true if local endpoints should be discovered
    bool discoverendpoints;

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

    uint16_t server_port; // TCP server port
    bool server_enabled;  // true if the TCP server will be opened and used

    // List of remote endpoints to connect to
    endpoint_group_t **remote_endpoints;
    size_t remote_count;

    // Array of the node's sockets, all direct connections
    node_t **nodes;
    size_t nodes_count;
    size_t nodes_count_max;

    // Array of all nodes on the network (ID)
    node_id_t **node_tree;
    size_t node_tree_count;

    // Contains the same allocated pointers as node_tree, only the array pointer
    // should be freed
    // Node ID tree sorted by hops_count (highest to lowest)
    node_id_t **node_tree_ordered_hops;

    // Routing table
    netroute_table_t *route_table;

    // Manually configured local routes
    conf_route_t *conf_routes;
    size_t conf_routes_size;

    // Array of network device names/IDs which should be excluded from the
    // endpoint discovery
    char **excluded_devices;
    size_t excluded_devices_count;

    // Minimum and maximum reconnection delays (in seconds)
    time_t reconnect_delay_min;
    time_t reconnect_delay_max;

    // Path to a file to dump the digraph to
    char *digraph_file;

    // Nodes' public keys loaded from the configuration
    conf_pubkey_t *conf_pubkeys;
    size_t conf_pubkeys_size;

    // When set to false the daemon will stop
    bool run;

    // Async I/O events
    aio_t *aio;
} oshd_t;

// true if the maximum number of nodes is reached
#define oshd_nodes_limited() (oshd.nodes_count_max != 0 && oshd.nodes_count >= oshd.nodes_count_max)

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