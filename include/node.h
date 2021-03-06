#ifndef _OSH_NODE_H
#define _OSH_NODE_H

#include "endpoints.h"
#include "netaddr.h"
#include "netbuffer.h"
#include "oshpacket.h"
#include "crypto/cipher.h"
#include "crypto/pkey.h"
#include <sys/time.h>
#include <netinet/in.h>
#include <poll.h>

#ifndef NODE_SENDQ_MIN_SIZE
// Allocate 2 MiB of buffer to the send queue at minimum
#define NODE_SENDQ_MIN_SIZE (1024 * 1024 * 2)
#endif

#ifndef NODE_SENDQ_ALIGNMENT
// Align the send queue allocations on the minimum size
#define NODE_SENDQ_ALIGNMENT NODE_SENDQ_MIN_SIZE
#endif

#ifndef NODE_RECVBUF_SIZE
// Size of the receive buffer, 1 MiB
#define NODE_RECVBUF_SIZE (1024 * 1024 * 1)
#endif

#if (NODE_RECVBUF_SIZE < OSHPACKET_MAXSIZE)
#error "NODE_RECVBUF_SIZE must be OSHPACKET_MAXSIZE or higher"
#endif

#ifndef NODE_AUTH_TIMEOUT
// Time in seconds to authenticate a node, if it is not authenticated after this
// delay, drop the connection
#define NODE_AUTH_TIMEOUT (30)
#endif

typedef struct node_id node_id_t;
typedef struct node node_t;

// We need to manually define the event_t type for the node_t structure to
// prevent mutually including events.h and node.h (events.h includes node.h)
typedef struct event event_t;

// Network data buffers
struct node_io {
    uint8_t *recvbuf;     // Buffer for received packets
    size_t recvbuf_size;  // Size of the data in recvbuf
    bool recvd_hdr;       // true when the packet header was processed
    size_t recv_pkt_size; // Size of the next packet to receive

    netbuffer_t *sendq;   // Network buffer for queuing packets
};

struct node_id {
    // Node name (which serves as its unique ID)
    char name[NODE_NAME_SIZE + 1];

    // Node's public key for authentication
    EVP_PKEY *pubkey;

    // Public key data for public key exchanges
    uint8_t *pubkey_raw;
    size_t pubkey_raw_size;

    // true if *pubkey is a local key loaded from the keys directory
    // false otherwise
    bool pubkey_local;

    // The node socket associated to this ID (if we have a direct connection)
    node_t *node_socket;

    // The node socket to which we should queue packets for this destination
    node_t *next_hop;

    // The number of hops to reach this node, how many others nodes will relay
    // packets for this destination
    size_t hops_count;

    // The node's "edges", a list of the node's direct neighbors
    node_id_t **edges;
    ssize_t edges_count;

    // A hash of the node's edges, ordered the same as on other nodes
    // If the local node's edges_hash differs with another node's edges_hash of
    // the local node, it means that the remote node went out of sync
    // The remote node must then clear those edges and the local node will send
    // its valid edges to re-sync
    uint8_t edges_hash[EVP_MAX_MD_SIZE];
    char edges_hash_hex[(EVP_MAX_MD_SIZE * 2) + 1];
    unsigned int edges_hash_size;

    // The node's routes, these are the VPN addresses
    netaddr_t *resolver_routes;
    size_t resolver_routes_count;

    // The node's endpoints, these are real endpoints to which Osh can try to
    // connect to
    // endpoints_local is set to true when this node ID authenticates on a
    // connection from a local endpoint group (in the configuration)
    // last_update is a timestamp of the last addition to the group, endpoints
    // received from the network will regularly timeout and get cleared. It is
    // then up to the nodes to broadcast their endpoints to the network again
    endpoint_group_t *endpoints;
    endpoint_group_t *endpoints_local;
    struct timeval endpoints_last_update;
    struct timeval endpoints_next_retry;

    // true if the node ID is our ID (name == oshd.name)
    bool local_node;

    // Used for the Breadth-first Search (node_id_find_next_hop function)
    bool visited;
};

struct node {
    int fd;                  // Network socket handle
    struct sockaddr_in6 sin; // Socket data (pointed to by *sin)
    struct node_io io;       // send/recv data buffers
    struct pollfd *pfd;      // Node's pollfd structure
                             // Used to update the POLLOUT event

    bool remove_queued; // true if the node_remove is queued
    bool initiator;     // true if it is an outgoing connection
    bool connected;     // true if the socket is connected (used for the async
                        // connect() calls)
    bool authenticated; // true when the node is authenticated
    node_id_t *id;      // The node's ID, when the node is authenticated this
                        // pointer will never be NULL
                        // But it will be NULL before the node has successfully
                        // authenticated

    // node_auth_timeout event queued in node_init
    event_t *auth_timeout_event;

    // This is the node ID the remote socket pretends to be, used only during
    // authentication in HELLO packets
    node_id_t *hello_id;

    // This is the local node's challenge packet sent to the other node during
    // authentication, it is kept in memory to verify the signed challenge data
    // by the remote node
    oshpacket_hello_challenge_t *hello_chall;

    // This is the result of the authentication process, if this is true and the
    // the other node also succeeds we will then finish the authentication and
    // start the state exchange
    bool hello_auth;

    // X25519 keys, ciphers and counters to encrypt/decrypt traffic
    // The send cipher will be used to encrypt outgoing packets
    // The recv cipher will be used to decrypt incoming packets
    // The send/recv counters are used to prevent replay attacks
    // The send counter increments every time we send a packet to the node
    // The recv counter increments every time we receive a packet from the node
    EVP_PKEY *send_key;
    cipher_t *send_cipher;
    uint32_t send_counter;
    EVP_PKEY *recv_key;
    cipher_t *recv_cipher;
    uint32_t recv_counter;

    // This is set to true when initiating the handshake
    // This is to know when to reply to a handshake request
    bool handshake_initiator;

    // This is set to true after authentication to indicate that all the
    // informations about the other node's network map should also be relayed to
    // our end of the network
    // This is to merge two nodes' current states when they connect and relay
    // all of the information to both ends of the network
    bool state_exg;

    // If this is true disconnect and remove the node after the send queue is
    // empty. Used for GOODBYE packets
    bool finish_and_disconnect;

    // Remote "address:port" string
    char addrw[128];

    // If *reconnect_endpoints is not NULL, contains one or multiple endpoints
    // to try to reconnect to when this socket disconnects
    // Reconnections will loop through all endpoints, if none works after a full
    // loop the delay will increase
    // reconnect_success is used internally to know when a connection succeeded
    // to reset the delay and select the first endpoint in the group
    endpoint_group_t *reconnect_endpoints;
    time_t reconnect_delay;
    bool reconnect_success;

    int32_t rtt;             // RTT latency in milliseconds
    struct timeval rtt_ping; // Timestamp of the last sent PING request
    struct timeval rtt_pong; // Timestamp of the last received PONG request
};

node_id_t *node_id_find(const char *name);
node_id_t *node_id_find_local(void);
node_id_t *node_id_add(const char *name);
void node_id_free(node_id_t *nid);
void node_id_add_edge(node_id_t *src, node_id_t *dest);
void node_id_del_edge(node_id_t *src, node_id_t *dest);
bool node_id_set_pubkey(node_id_t *nid, const uint8_t *pubkey,
    size_t pubkey_size);
void node_id_add_resolver_route(node_id_t *nid, const netaddr_t *addr);
void node_id_clear_resolver_routes(node_id_t *nid);
void node_id_expire_endpoints(node_id_t *nid);

void node_tree_dump_digraph(void);
void node_tree_dump(void);
void node_tree_update(void);

void node_graceful_disconnect(node_t *node);
void node_disconnect(node_t *node);
void node_destroy(node_t *node);
node_t *node_init(int fd, bool initiator, netaddr_t *addr, uint16_t port);

time_t node_reconnect_delay_limit(time_t delay);
void node_reconnect_delay(node_t *node, time_t delay);
void node_reconnect_to(node_t *node, endpoint_group_t *reconnect_endpoints,
    time_t delay);
void node_reconnect_disable(node_t *node);
void node_reconnect_endpoints(endpoint_group_t *reconnect_endpoints, time_t delay);
void node_reconnect_endpoints_next(endpoint_group_t *reconnect_endpoints, time_t delay);
void node_reconnect(node_t *node);

bool node_valid_name(const char *name);

bool node_queue_packet(node_t *node, const char *dest, oshpacket_type_t type,
    uint8_t *payload, uint16_t payload_size);
bool node_queue_packet_forward(node_t *node, oshpacket_hdr_t *pkt);
bool node_queue_packet_broadcast(node_t *exclude, oshpacket_type_t type,
    uint8_t *payload, uint16_t payload_size);

bool node_queue_handshake(node_t *node, bool initiator);
bool node_queue_hello_challenge(node_t *node);
bool node_queue_hello_end(node_t *node);
bool node_queue_devmode(node_t *node);
bool node_queue_stateexg_end(node_t *node);
bool node_queue_goodbye(node_t *node);
bool node_queue_ping(node_t *node);
bool node_queue_pong(node_t *node);
bool node_queue_pubkey_broadcast(node_t *exclude, node_id_t *id);
bool node_queue_pubkey_exg(node_t *node);
bool node_queue_local_endpoint_broadcast(node_t *exclude);
bool node_queue_endpoint_exg(node_t *node);
bool node_queue_edge(node_t *node, oshpacket_type_t type,
    const char *src, const char *dest);
bool node_queue_edge_broadcast(node_t *exclude, oshpacket_type_t type,
    const char *src, const char *dest);
bool node_queue_edge_exg(node_t *node);
bool node_queue_route_add_local(node_t *exclude, const netaddr_t *addrs,
    size_t count);
bool node_queue_route_exg(node_t *node);

// This is the function called to send the initial packet when an initiator
// established a connection
#define node_queue_initial_packet(node) node_queue_handshake(node, true)

static inline void node_pollin_set(node_t *node)
{
    if (node->pfd)
        node->pfd->events |= POLLIN;
}

static inline void node_pollin_unset(node_t *node)
{
    if (node->pfd)
        node->pfd->events &= ~(POLLIN);
}

static inline void node_pollout_set(node_t *node)
{
    if (node->pfd)
        node->pfd->events |= POLLOUT;
}

static inline void node_pollout_unset(node_t *node)
{
    if (node->pfd)
        node->pfd->events &= ~(POLLOUT);
}

#endif