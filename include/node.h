#ifndef _OSH_NODE_H
#define _OSH_NODE_H

#include "aio.h"
#include "endpoints.h"
#include "netaddr.h"
#include "netbuffer.h"
#include "oshpacket.h"
#include "oshd_clock.h"
#include "crypto/cipher.h"
#include "crypto/pkey.h"
#include <netinet/in.h>

#ifndef NODE_SENDQ_MIN_SIZE
// Minimum size of the send queue
#define NODE_SENDQ_MIN_SIZE (OSHPACKET_MAXSIZE * 128)
#endif

#ifndef NODE_SENDQ_ALIGNMENT
// Align the send queue allocations on the minimum size
#define NODE_SENDQ_ALIGNMENT NODE_SENDQ_MIN_SIZE
#endif

#ifndef NODE_RECVBUF_SIZE
// Size of the receive buffer
#define NODE_RECVBUF_SIZE (OSHPACKET_MAXSIZE * 128)
#endif

#if (NODE_RECVBUF_SIZE < OSHPACKET_MAXSIZE)
#error "NODE_RECVBUF_SIZE must be OSHPACKET_MAXSIZE or higher"
#endif

#ifndef NODE_SENDQ_DATA_SIZE_MAX
// Send queue size limit for queuing DATA packets
#define NODE_SENDQ_DATA_SIZE_MAX (OSHPACKET_MAXSIZE * 64)
#endif

#ifndef NODE_SENDQ_DATA_SIZE_MIN
// Minimum size of the send queue to start dropping packets
#define NODE_SENDQ_DATA_SIZE_MIN (NODE_SENDQ_DATA_SIZE_MAX / 2)
#endif

// Size of the queue's "packet drop" range
#define NODE_SENDQ_DATA_SIZE (NODE_SENDQ_DATA_SIZE_MAX - NODE_SENDQ_DATA_SIZE_MIN)

#if (NODE_SENDQ_DATA_SIZE <= 0)
#error "NODE_SENDQ_DATA_SIZE cannot be less than or equal to zero"
#endif

#ifndef NODE_AUTH_TIMEOUT
// Time in seconds to authenticate a node, if it is not authenticated after this
// delay, drop the connection
#define NODE_AUTH_TIMEOUT (30)
#endif

#ifndef HANDSHAKE_TIMEOUT
// Time in seconds to complete a handshake, if the handshake does not end after
// this delay the connection is dropped
#define HANDSHAKE_TIMEOUT (30)
#endif

#ifndef HANDSHAKE_RENEW_INTERVAL
// Interval in seconds for renewing encryption keys
// Renew every hour
#define HANDSHAKE_RENEW_INTERVAL (3600)
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

#ifndef seen_brd_id_maxsize
#define seen_brd_id_maxsize (256)
#endif

#if (seen_brd_id_maxsize < 1)
#error "seen_brd_id_maxsize must be a positive value"
#endif

struct node_id {
    // Node name (which serves as its unique ID)
    char name[NODE_NAME_SIZE + 1];

    // Node's public key for authentication
    EVP_PKEY *pubkey;

    // Public key data for public key exchanges
    uint8_t *pubkey_raw;
    size_t pubkey_raw_size;

    // true if *pubkey is a local key loaded from the configuration
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

    // The node's endpoints, these are real endpoints to which Osh can try to
    // connect to
    endpoint_group_t *endpoints;
    struct timespec endpoints_next_retry;

    // Array of the most recently received broadcast IDs
    // This is used to ignore broadcast packets which we already processed
    oshpacket_brd_id_t seen_brd_id[seen_brd_id_maxsize];
    size_t seen_brd_id_count;

    // true if the node ID is our ID (name == oshd.name)
    bool local_node;

    // Used for the Breadth-first Search (node_id_find_next_hop function)
    bool visited;
};

struct node {
    int fd;                      // Network socket handle
    struct sockaddr_storage sin; // Socket data
    struct node_io io;           // send/recv data buffers
    aio_event_t *aio_event;      // Node's async I/O event

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

    // handshake_renew event queued after the initial handshake
    event_t *handshake_renew_event;

    // handshake_timeout event queued in node_queue_handshake
    event_t *handshake_timeout_event;

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

    // X25519 keys and ciphers to encrypt/decrypt traffic
    // The send cipher will be used to encrypt outgoing packets
    // The recv cipher will be used to decrypt incoming packets
    EVP_PKEY *send_key;
    cipher_t *send_cipher;
    EVP_PKEY *recv_key;
    cipher_t *recv_cipher;
    cipher_t *recv_cipher_next;

    // This is set to true when sending a handshake to the node, it is set to
    // false after the handshake is done to prevent overlaps
    bool handshake_in_progress;

    // This pointer holds a copy of the first unauthenticated handshake packet
    oshpacket_handshake_t *unauth_handshake;

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
    endpoint_group_t *reconnect_endpoints;
    time_t reconnect_delay;

    int32_t rtt;               // RTT latency in milliseconds
    bool rtt_await;            // true while a PONG is expected to be received
    struct timespec rtt_ping;  // Timestamp of the last sent PING request
    struct timespec rtt_pong;  // Timestamp of the last received PONG request
    struct timespec rtt_delta; // Difference between rtt_ping and rtt_pong
};

node_id_t *node_id_find(const char *name);
node_id_t *node_id_find_local(void);
node_id_t *node_id_add(const char *name);
void node_id_free(node_id_t *nid);
void node_id_add_edge(node_id_t *src, node_id_t *dest);
void node_id_del_edge(node_id_t *src, node_id_t *dest);
bool node_id_set_pubkey(node_id_t *nid, const uint8_t *pubkey,
    size_t pubkey_size);

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
void node_reconnect_endpoints_next(endpoint_group_t *reconnect_endpoints, time_t delay);
void node_reconnect(node_t *node);

bool node_valid_name(const char *name);
bool node_has_seen_brd_id(node_id_t *nid, const oshpacket_brd_id_t brd_id);

// TODO: Rename node_queue_* functions
bool node_queue_packet(node_t *node, node_id_t *dest, oshpacket_type_t type,
    const void *payload, size_t payload_size);
bool node_queue_packet_forward(node_t *node, const oshpacket_hdr_t *hdr,
    const void *payload, size_t payload_size);
bool node_queue_packet_broadcast(node_t *exclude, oshpacket_type_t type,
    const void *payload, size_t payload_size);
bool node_queue_packet_broadcast_forward(node_t *exclude, const oshpacket_hdr_t *hdr,
    const void *payload, size_t payload_size);

#define node_queue_packet_empty(node, dest, type) node_queue_packet(node, dest, type, NULL, 0)

bool node_queue_handshake(node_t *node);
bool node_queue_handshake_end(node_t *node);
void node_renew_handshake(node_t *node);
bool node_queue_hello_challenge(node_t *node);
bool node_queue_hello_end(node_t *node);
bool node_queue_devmode(node_t *node);
bool node_queue_stateexg_end(node_t *node);
bool node_queue_goodbye(node_t *node);
bool node_queue_ping(node_t *node);
bool node_queue_pong(node_t *node);
bool node_queue_pubkey_broadcast(node_t *exclude, node_id_t *id);
bool node_queue_pubkey_exg(node_t *node);
bool node_queue_endpoint_broadcast(node_t *exclude, const endpoint_t *endpoint,
    const endpoint_group_t *group);
bool node_queue_endpoint_exg(node_t *node);
bool node_queue_edge(node_t *node, oshpacket_type_t type,
    const char *src, const char *dest);
bool node_queue_edge_broadcast(node_t *exclude, oshpacket_type_t type,
    const char *src, const char *dest);
bool node_queue_edge_exg(node_t *node);
bool node_queue_route_add_local(node_t *exclude, const netaddr_t *addrs,
    size_t count, bool can_expire);
bool node_queue_route_exg(node_t *node);

// This is the function called to send the initial packet when an initiator
// established a connection
#define node_queue_initial_packet(node) node_queue_handshake(node)

#endif
