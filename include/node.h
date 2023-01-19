#ifndef _OSH_NODE_H
#define _OSH_NODE_H

#include "client.h"

// Structure holding the recently seen broadcast IDs
struct node_brd_id {
    oshpacket_brd_id_t brd_id;
    struct timespec seen_at;
};

typedef struct node_id node_id_t;

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

    // The client associated to this ID (if we have a direct connection)
    client_t *node_socket;

    // The client to which we should queue packets for to reach this destination
    client_t *next_hop;
    bool next_hop_searched;

    // The number of hops to reach this node, how many others nodes will relay
    // packets for this destination
    size_t hops_count;

    // The node's "edges", a list of the node's direct neighbors
    node_id_t **edges;
    ssize_t edges_count;

    // The node's endpoints, these are real endpoints to which Osh can try to
    // connect to
    endpoint_group_t *endpoints;
    struct timespec endpoints_next_retry;

    // The connect event and endpoints used when trying to connect to the node
    event_t *connect_event;
    endpoint_group_t *connect_endpoints;
    time_t connect_delay;

    // Array of the most recently received broadcast IDs
    // This is used to ignore broadcast packets which we already processed
    struct node_brd_id *seen_brd_id;
    size_t seen_brd_id_count;

    // true if the node ID is our ID (name == oshd.name)
    bool local_node;

    // true if the node is online
    bool online;

    // Used for the Breadth-First Search
    bool visited;
};

bool node_id_gen_hash(const node_id_t *nid, const uint8_t *salt,
    size_t salt_size, uint8_t *hash);

node_id_t *node_id_find_by_hash(const uint8_t *hash,
    const uint8_t *salt, size_t salt_size);
node_id_t *node_id_find(const char *name);
node_id_t *node_id_find_local(void);
node_id_t *node_id_add(const char *name);
void node_id_free(node_id_t *nid);
void node_id_add_edge(node_id_t *src, node_id_t *dest);
void node_id_del_edge(node_id_t *src, node_id_t *dest);
bool node_id_set_pubkey(node_id_t *nid, const uint8_t *pubkey,
    size_t pubkey_size);

#define node_id_linked_client(nid) ((nid)->node_socket)
client_t *node_id_link_client(node_id_t *nid, client_t *c);
bool node_id_unlink_client(node_id_t *nid, const client_t *c);

client_t *node_id_next_hop(node_id_t *id);

void node_tree_dump_digraph(void);
void node_tree_dump(void);
void node_tree_update(void);

bool node_valid_name(const char *name);
bool node_has_trusted_pubkey(const node_id_t *nid);

void node_brd_id_push(node_id_t *nid, const oshpacket_brd_id_t brd_id);
void node_brd_id_pop(node_id_t *nid, size_t amount);
bool node_brd_id_was_seen(node_id_t *nid, const oshpacket_brd_id_t brd_id);

bool node_connect_in_progress(const node_id_t *nid);
bool node_connect(node_id_t *nid, const bool now);
void node_connect_continue(node_id_t *nid);
void node_connect_end(node_id_t *nid, const bool success, const char *reason);

#endif
