#ifndef _OSH_NODE_H
#define _OSH_NODE_H

#include "netaddr.h"
#include "netbuffer.h"
#include "oshpacket.h"
#include <sys/time.h>
#include <netinet/in.h>

#ifndef NODE_SENDQ_SIZE
// Allocate 2 MiB of buffer to the send queue at most
#define NODE_SENDQ_SIZE (1024 * 1024 * 2)
#endif

#ifndef NODE_SENDQ_SLOTS
#define NODE_SENDQ_SLOTS (NODE_SENDQ_SIZE / OSHPACKET_MAXSIZE)
#endif

#if (NODE_SENDQ_SLOTS <= 0)
#error "NODE_SENDQ_SLOTS must have at least one slot"
#endif

typedef struct node_id node_id_t;
typedef struct node node_t;

// Network data buffers
struct node_io {
    uint8_t *recvbuf;          // Buffer to receive packets to
    uint16_t recv_bytes;       // Amount of received bytes in *recvbuf
    uint16_t recv_packet_size; // Amount of bytes to receive in total
    bool recvd_hdr;            // true when the packet header was processed

    netbuffer_t *sendq;         // Network buffer for queuing packets
    uint8_t *sendq_ptr;         // Buffer from which we are currently sending
    uint16_t sendq_packet_size; // Amount of remaining bytes to send from the buffer
};

struct node_id {
    // Node name (which serves as its unique ID)
    char name[NODE_NAME_SIZE + 1];

    // The node socket associated to this ID (if we have a direct connection)
    node_t *node_socket;

    // The node socket to which we should queue packets for this destination
    node_t *next_hop;

    // The node's "edges", a list of the node's direct neighbors
    node_id_t **edges;
    ssize_t edges_count;

    // true if the node ID is our ID (name == oshd.name)
    bool local_node;

    // Used for the Breadth-first Search (node_id_find_next_hop function)
    bool visited;
};

struct node {
    int fd;                  // Network socket handle
    struct sockaddr_in6 sin; // Socket data (pointed to by *sin)
    struct node_io io;       // send/recv data buffers

    bool initiator;     // true if it is an outgoing connection
    bool connected;     // true if the socket is connected (used for the async
                        // connect() calls)
    bool authenticated; // true when the node is authenticated
    node_id_t *id;      // The node's ID, when the node is authenticated this
                        // pointer will never be NULL
                        // But it will be NULL before the node has successfully
                        // authenticated

    netaddr_t addr;      // Remote peer address
    uint16_t port;       // Remote peer port
    char addrw[128];     // "address:port" string

    int32_t rtt;             // RTT latency in milliseconds
    struct timeval rtt_ping; // Timestamp of the last sent PING request
    struct timeval rtt_pong; // Timestamp of the last received PONG request
};

node_id_t *node_id_find(const char *name);
node_id_t *node_id_add(const char *name);
void node_id_free(node_id_t *nid);
void node_id_add_edge(node_id_t *src, node_id_t *dest);
void node_id_del_edge(node_id_t *src, node_id_t *dest);

void node_tree_dump_digraph(void);
void node_tree_dump(void);
void node_tree_update(void);

void node_disconnect(node_t *node);
void node_destroy(node_t *node);
node_t *node_init(int fd, bool initiator, netaddr_t *addr, uint16_t port);
bool node_valid_name(const char *name);

bool node_queue_packet(node_t *node, const char *dest, oshpacket_type_t type,
    uint8_t *payload, uint16_t payload_size);
bool node_queue_packet_forward(node_t *node, oshpacket_hdr_t *pkt);
bool node_queue_packet_broadcast(node_t *exclude, oshpacket_type_t type,
    uint8_t *payload, uint16_t payload_size);

bool node_queue_hello(node_t *node);
bool node_queue_ping(node_t *node);
bool node_queue_pong(node_t *node);
bool node_queue_edge(node_t *node, oshpacket_type_t type,
    const char *src, const char *dest);
bool node_queue_edge_broadcast(node_t *exclude, oshpacket_type_t type,
    const char *src, const char *dest);
bool node_queue_edge_exg(node_t *node);
bool node_queue_add_route_broadcast(node_t *exclude, const netaddr_t *addrs,
    size_t count);

#endif