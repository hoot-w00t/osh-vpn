#ifndef _OSH_CLIENT_H
#define _OSH_CLIENT_H

#include "aio.h"
#include "endpoints.h"
#include "netaddr.h"
#include "netbuffer.h"
#include "oshpacket.h"
#include "oshd_clock.h"
#include "crypto/cipher.h"
#include "crypto/pkey.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>

#ifndef CLIENT_SENDQ_MIN_SIZE
// Minimum size of the send queue
#define CLIENT_SENDQ_MIN_SIZE (OSHPACKET_MAXSIZE * 128)
#endif

#ifndef CLIENT_SENDQ_ALIGNMENT
// Align the send queue allocations on the minimum size
#define CLIENT_SENDQ_ALIGNMENT CLIENT_SENDQ_MIN_SIZE
#endif

#ifndef CLIENT_RECVBUF_SIZE
// Size of the receive buffer
#define CLIENT_RECVBUF_SIZE (OSHPACKET_MAXSIZE * 128)
#endif

#if (CLIENT_RECVBUF_SIZE < OSHPACKET_MAXSIZE)
#error "CLIENT_RECVBUF_SIZE must be OSHPACKET_MAXSIZE or higher"
#endif

#ifndef CLIENT_SENDQ_DATA_SIZE_MAX
// Send queue size limit for queuing DATA packets
#define CLIENT_SENDQ_DATA_SIZE_MAX (OSHPACKET_MAXSIZE * 64)
#endif

#ifndef CLIENT_SENDQ_DATA_SIZE_MIN
// Minimum size of the send queue to start dropping packets
#define CLIENT_SENDQ_DATA_SIZE_MIN (CLIENT_SENDQ_DATA_SIZE_MAX / 2)
#endif

// Size of the queue's "packet drop" range
#define CLIENT_SENDQ_DATA_SIZE (CLIENT_SENDQ_DATA_SIZE_MAX - CLIENT_SENDQ_DATA_SIZE_MIN)

#if (CLIENT_SENDQ_DATA_SIZE <= 0)
#error "CLIENT_SENDQ_DATA_SIZE cannot be less than or equal to zero"
#endif

#ifndef HANDSHAKE_TIMEOUT
// Time in seconds to complete a handshake, if the handshake does not end after
// this delay the connection is dropped (also serves as the authentication
// timeout)
#define HANDSHAKE_TIMEOUT (30)
#endif

#ifndef HANDSHAKE_RENEW_INTERVAL
// Interval in seconds for renewing encryption keys
// Renew every hour
#define HANDSHAKE_RENEW_INTERVAL (3600)
#endif

#ifndef NODE_BRD_ID_TIMEOUT
// Time in seconds after which a broadcast ID can be forgotten
#define NODE_BRD_ID_TIMEOUT (30)
#endif

typedef struct client client_t;

// We need to manually define the event_t type for the client_t structure to
// prevent include loops (events.h includes node.h/client.h)
typedef struct event event_t;

// Network data buffers
struct client_io {
    uint8_t *recvbuf;     // Buffer for received packets
    size_t recvbuf_size;  // Size of the data in recvbuf
    bool recvd_hdr;       // true when the packet header was processed
    size_t recv_pkt_size; // Size of the next packet to receive

    netbuffer_t *sendq;   // Network buffer for queuing packets
};

struct client {
    int fd;                      // Network socket
    struct sockaddr_storage sa;  // Socket address
    endpoint_t *sa_endpoint;     // Socket endpoint
    char *addrw;                 // Endpoint "address:port" string

    struct client_io io;         // send/recv data buffers
    aio_event_t *aio_event;      // Client's async I/O event

    bool initiator;     // true if it is an outgoing connection
    bool connected;     // true if the socket is connected (used for the async
                        // connect() calls)
    bool authenticated; // true when the client is authenticated
    node_id_t *id;      // The node's ID, when the client is authenticated this
                        // pointer will never be NULL
                        // But it will be NULL before the client has successfully
                        // authenticated

    // Timed events linked to clients
    event_t *handshake_renew_event;
    event_t *handshake_timeout_event;

    // This variable is true after a local handshake is created and sent to the
    // other node
    // It is set back to false once the handshake is over to prevent overlaps
    bool handshake_in_progress;

    // This is the node ID the remote socket pretends to be
    // This is used only for and during the handshake
    node_id_t *handshake_id;

    // This is the node's handshake signature data, it is filled in and used
    // during the handshake
    // This data will be signed with the local node's private key, and will also
    // be used to verify the signature of the remote node to authenticate it
    oshpacket_handshake_sig_data_t *handshake_sig_data;

    // Set to true after all fields of the signature data are filled in
    bool handshake_sig_data_complete;

    // This will be true if the handshake signature verification succeeds
    // (meaning we were able to authenticate the remote node)
    bool handshake_valid_signature;

    // ECDH key and ciphers to encrypt/decrypt traffic
    // The send cipher will be used to encrypt outgoing packets
    // The recv cipher will be used to decrypt incoming packets
    EVP_PKEY *ecdh_key;
    cipher_t *send_cipher;
    cipher_t *recv_cipher;
    cipher_t *recv_cipher_next;

    // When this is set to true, disconnect and remove the client after the
    // send queue is emptied (graceful disconnection)
    // No more packets will be received or queued
    bool finish_and_disconnect;

    // If *reconnect_nid is not NULL, it points to the node to which we should
    // try to connect to after the client is disconnected
    node_id_t *reconnect_nid;

    int32_t rtt;               // RTT latency in milliseconds
    bool rtt_await;            // true while a PONG is expected to be received
    struct timespec rtt_ping;  // Timestamp of the last sent PING request
    struct timespec rtt_pong;  // Timestamp of the last received PONG request
    struct timespec rtt_delta; // Difference between rtt_ping and rtt_pong
};

void client_graceful_disconnect(client_t *c);

void client_change_endpoint(client_t *c, const endpoint_t *endpoint,
    const struct sockaddr_storage *sa);

void client_destroy(client_t *c);
client_t *client_init(int fd, bool initiator, const endpoint_t *endpoint,
    const struct sockaddr_storage *sa);

void client_reconnect_to(client_t *c, node_id_t *nid);
#define client_reconnect_disable(c) client_reconnect_to(c, NULL)

void client_finish_handshake(client_t *c);

bool client_queue_packet(client_t *c, const oshpacket_hdr_t *hdr,
    const void *payload, const size_t payload_size);
bool client_queue_packet_direct(client_t *c, oshpacket_type_t type,
    const void *payload, size_t payload_size);
bool client_queue_packet_indirect(node_id_t *dest, oshpacket_type_t type,
    const void *payload, size_t payload_size);
#define client_queue_packet_forward(client, hdr, payload, payload_size) \
    client_queue_packet(client, hdr, payload, payload_size)

bool client_queue_packet_broadcast(client_t *exclude, oshpacket_type_t type,
    const void *payload, size_t payload_size);
bool client_queue_packet_broadcast_forward(client_t *exclude, const oshpacket_hdr_t *hdr,
    const void *payload, size_t payload_size);
bool client_queue_packet_data(node_id_t *dest, const void *payload,
    const size_t payload_size);
bool client_queue_packet_data_broadcast(node_id_t *exclude, const void *payload,
    const size_t payload_size);
bool client_queue_packet_exg(client_t *c, oshpacket_type_t type,
    const void *payload, const size_t payload_size);

#define client_queue_packet_empty(client, type) \
    client_queue_packet_direct(client, type, NULL, 0)

bool client_queue_handshake(client_t *c);
void client_renew_handshake(client_t *c);
bool client_queue_devmode(client_t *c);
bool client_queue_goodbye(client_t *c);
bool client_queue_ping(client_t *c);
bool client_queue_pong(client_t *c);
bool client_queue_pubkey_broadcast(client_t *exclude, node_id_t *id);
bool client_queue_endpoint(client_t *dest, const endpoint_t *endpoint,
    const node_id_t *owner, const bool broadcast);
bool client_queue_edge_broadcast(client_t *exclude, oshpacket_type_t type,
    const char *src, const char *dest);
bool client_queue_route_add_local(client_t *exclude, const netaddr_t *addrs,
    size_t count, bool can_expire);

// This is the function called to send the initial packet when an initiator
// established a connection
#define client_queue_initial_packet(client) client_queue_handshake(client)

// Defined in client_state_exchange.c
bool client_queue_pubkey_exg(client_t *c);
bool client_queue_endpoint_exg(client_t *c);
bool client_queue_edge_exg(client_t *c);
bool client_queue_route_exg(client_t *c);

#endif
