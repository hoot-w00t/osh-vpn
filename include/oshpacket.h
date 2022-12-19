#ifndef _OSH_OSHPACKET_H
#define _OSH_OSHPACKET_H

#include "macros_bitfields.h"
#include "crypto/cipher.h"
#include "netaddr.h"
#include "device_mode.h"
#include <stdint.h>
#include <stddef.h>

#ifndef NODE_NAME_SIZE
#define NODE_NAME_SIZE (16)
#endif

#ifndef ED25519_SIG_SIZE
// Ed25519 signatures are 64 bytes in length
#define ED25519_SIG_SIZE (64)
#endif

#ifndef ED25519_KEY_SIZE
// Ed25519 keys are 32 bytes in length
#define ED25519_KEY_SIZE (32)
#endif

#ifndef X25519_KEY_SIZE
// X25519 keys are the same size as Ed25519 keys
#define X25519_KEY_SIZE ED25519_KEY_SIZE
#endif

#ifndef NODE_PUBKEY_SIZE
#define NODE_PUBKEY_SIZE ED25519_KEY_SIZE
#endif

#ifndef HANDSHAKE_PUBKEY_SIZE
#define HANDSHAKE_PUBKEY_SIZE NODE_PUBKEY_SIZE
#endif

#ifndef HANDSHAKE_SIG_SIZE
#define HANDSHAKE_SIG_SIZE ED25519_SIG_SIZE
#endif

#ifndef HANDSHAKE_ECDH_KEY_SIZE
#define HANDSHAKE_ECDH_KEY_SIZE X25519_KEY_SIZE
#endif

#ifndef HANDSHAKE_NONCE_SIZE
#define HANDSHAKE_NONCE_SIZE (64)
#endif

// The node ID hash is a SHA3-512
#define NODE_ID_HASH_SIZE (64)
#if (NODE_ID_HASH_SIZE > EVP_MAX_MD_SIZE)
#error "NODE_ID_HASH_SIZE is bigger than the maximum message digest size"
#endif

#define OSHPACKET_PAYLOAD_MAXSIZE (2048)

typedef enum oshpacket_type {
    HANDSHAKE = 0,
    HANDSHAKE_SIG,
    HANDSHAKE_END,
    HELLO,
    DEVMODE,
    GOODBYE,
    PING,
    PONG,
    DATA,
    PUBKEY,
    ENDPOINT,
    EDGE_ADD,
    EDGE_DEL,
    ROUTE_ADD,
    _LAST_OSHPACKET_TYPE_ENTRY // must always be the last entry
} oshpacket_type_t;
#define OSHPACKET_TYPE_COUNT (_LAST_OSHPACKET_TYPE_ENTRY)

typedef enum oshpacket_payload_size {
    OSHPACKET_PAYLOAD_SIZE_VARIABLE = 0, // Let the handler check the size
    OSHPACKET_PAYLOAD_SIZE_FIXED, // Only accept one payload size
    OSHPACKET_PAYLOAD_SIZE_FRAGMENTED // Accept the payload size or a multiple
} oshpacket_payload_size_t;

typedef uint64_t oshpacket_brd_id_t;
#define PRI_BRD_ID "016" PRIx64

// For a total of 36 bytes
typedef struct __attribute__((__packed__)) oshpacket_hdr {
    // Public part of the header (never encrypted)
    // If it changes OSHPACKET_PUBLIC_HDR_SIZE needs to be updated
    uint16_t         payload_size;
    uint8_t          tag[CIPHER_TAG_SIZE];

    // Private header (always encrypted except for HANDSHAKE packets)
    // If it changes OSHPACKET_PRIVATE_HDR_SIZE needs to be updated
    oshpacket_type_t type : 8;
    uint8_t          flags;

    char             src_node[NODE_NAME_SIZE];

    // This field contains information about the destination of the packet
    // Both structures are of the same size, but the one used will depend on
    // the broadcast flag of the packet
    union {
        // This structure is used when the broadcast flag is 1
        // It contains a random ID used to prevent duplicated packets
        struct __attribute__((__packed__)) {
            oshpacket_brd_id_t id;      // The endianness of this ID should not
                                        // matter as we only compare and store
                                        // the value
            uint64_t           _unused;
        } broadcast;

        // This structure is used when the broadcast flag is 0
        // It only contains the destination node's name
        struct __attribute__((__packed__)) {
            char dest_node[NODE_NAME_SIZE];
        } unicast;
    } dest;
} oshpacket_hdr_t;

// Bitfield of oshpacket_hdr_t->flags
#define OSHPACKET_HDR_FLAG_BROADCAST (7)

typedef struct client client_t;
typedef struct node_id node_id_t;

// Packet data structure used for packet handling
typedef struct oshpacket {
    cipher_seqno_t seqno;       // Packet sequence number

    void *packet;               // Raw packet data
    size_t packet_size;         // Raw packet data size

    oshpacket_hdr_t *hdr;       // Packet header

    void *payload;              // Packet payload
                                // NULL if there is no payload
    size_t payload_size;        // Packet payload size
} oshpacket_t;

// Unauthenticated handler is called with the client_t socket which received the
// packet and the packet data
// Closes the socket if the return value is false
typedef bool (*oshpacket_unauth_handler_t)(client_t *, oshpacket_t *);

// Authenticated handler is called with the client_t socket which received the
// packet, the node that sent it and the packet data
// Closes the socket if the return value is false
typedef bool (*oshpacket_handler_t)(client_t *, node_id_t *, oshpacket_t *);

// Packet type definitions
typedef struct oshpacket_def {
    oshpacket_type_t type;                      // Packet type
    const char *name;                           // Type name

    oshpacket_unauth_handler_t handler_unauth;  // Packet handler (on unauthenticated clients)
    oshpacket_handler_t handler;                // Packet handler (on authenticated clients)

    bool can_be_forwarded;                      // true if the packet can be forwarded
    bool can_be_sent_unencrypted;               // true if the packet can be sent unencrypted
    bool is_reliable;                           // true if the packet must not be lost or re-ordered
                                                // false if the packet can be lost or re-ordered

    oshpacket_payload_size_t payload_size_type; // Type of payload size
    size_t payload_size;                        // Expected payload size
} oshpacket_def_t;

typedef struct __attribute__((__packed__)) oshpacket_devmode {
    device_mode_t devmode : 8;
} oshpacket_devmode_t;

typedef struct __attribute__((__packed__)) oshpacket_devmode_dynamic {
    oshpacket_devmode_t devmode_pkt;
    char network_name[NODE_NAME_SIZE];
    netaddr_data_t prefix6;
    netaddr_prefixlen_t prefixlen6;
    netaddr_data_t prefix4;
    netaddr_prefixlen_t prefixlen4;
} oshpacket_devmode_dynamic_t;

typedef struct __attribute__((__packed__)) oshpacket_handshake {
    // The sender node's name and public key (hashed with the random salt)
    struct __attribute__((__packed__)) {
        uint8_t id_hash[NODE_ID_HASH_SIZE];
        uint8_t id_salt[64];
    } sender;

    // Public X25519 key to compute a shared secret
    uint8_t ecdh_pubkey[HANDSHAKE_ECDH_KEY_SIZE];

    // Additional unique random data
    uint8_t nonce[HANDSHAKE_NONCE_SIZE];
} oshpacket_handshake_t;

// This structure is constructed locally and used as the output of the HKDF
typedef struct __attribute__((packed)) handshake_hkdf_keys {
    uint8_t initiator_cipher_key[CIPHER_KEY_SIZE];
    uint8_t initiator_cipher_iv[CIPHER_IV_SIZE];

    uint8_t receiver_cipher_key[CIPHER_KEY_SIZE];
    uint8_t receiver_cipher_iv[CIPHER_IV_SIZE];
} handshake_hkdf_keys_t;

// This structure is constructed locally and never sent over the network
typedef struct __attribute__((__packed__)) oshpacket_handshake_sig_data {
    // Note: initiator/receiver refers to the value of client_t->initiator

    // Raw handshake packets from both nodes
    oshpacket_handshake_t initiator_handshake;
    oshpacket_handshake_t receiver_handshake;

    // The initiator node's name and public key
    char initiator_name[NODE_NAME_SIZE];
    uint8_t initiator_pubkey[HANDSHAKE_PUBKEY_SIZE];

    // The receiver node's name and public key
    char receiver_name[NODE_NAME_SIZE];
    uint8_t receiver_pubkey[HANDSHAKE_PUBKEY_SIZE];
} oshpacket_handshake_sig_data_t;

typedef struct __attribute__((__packed__)) oshpacket_handshake_sig {
    // Signature of oshpacket_handshake_sig_data_t
    uint8_t sig[HANDSHAKE_SIG_SIZE];
} oshpacket_handshake_sig_t;

typedef struct __attribute__((__packed__)) oshpacket_hello {
    // Bitfield of options for this connection
    uint32_t options;
} oshpacket_hello_t;

typedef struct __attribute__((__packed__)) oshpacket_pubkey {
    char node_name[NODE_NAME_SIZE];
    uint8_t node_pubkey[NODE_PUBKEY_SIZE];
} oshpacket_pubkey_t;

typedef struct __attribute__((__packed__)) oshpacket_endpoint {
    uint8_t type;                       // endpoint_type_t
    uint8_t socktype;                   // endpoint_socktype_t
    char owner_name[NODE_NAME_SIZE];
} oshpacket_endpoint_t;

typedef struct __attribute__((__packed__)) oshpacket_edge {
    char src_node[NODE_NAME_SIZE];
    char dest_node[NODE_NAME_SIZE];
} oshpacket_edge_t;

typedef struct __attribute__((__packed__)) oshpacket_route {
    char owner_name[NODE_NAME_SIZE];
    netaddr_type_t type : 8;
    netaddr_prefixlen_t prefixlen;
    netaddr_data_t addr;
    uint8_t can_expire;
} oshpacket_route_t;

// Size of the public part of the header
#define OSHPACKET_PUBLIC_HDR_SIZE  (2 + CIPHER_TAG_SIZE)

// Size of the private part of the header
#define OSHPACKET_PRIVATE_HDR_SIZE (1 + 1 + (NODE_NAME_SIZE * 2))

// Total size of the header
#define OSHPACKET_HDR_SIZE (OSHPACKET_PUBLIC_HDR_SIZE + OSHPACKET_PRIVATE_HDR_SIZE)

// Maximum size of a packet (including the header)
#define OSHPACKET_MAXSIZE  (OSHPACKET_HDR_SIZE + OSHPACKET_PAYLOAD_MAXSIZE)

#define _OSHPACKET_OFFSET(pkt, offset)       ((void *) (((uint8_t *) (pkt)) + (offset)))
#define _OSHPACKET_OFFSET_CONST(pkt, offset) ((const void *) (((const uint8_t *) (pkt)) + (offset)))

#define OSHPACKET_HDR(pkt)         ((oshpacket_hdr_t *) (pkt))
#define OSHPACKET_PRIVATE_HDR(pkt) _OSHPACKET_OFFSET(pkt, OSHPACKET_PUBLIC_HDR_SIZE)
#define OSHPACKET_PAYLOAD(pkt)     _OSHPACKET_OFFSET(pkt, OSHPACKET_HDR_SIZE)

#define OSHPACKET_HDR_CONST(pkt)         ((const oshpacket_hdr_t *) (pkt))
#define OSHPACKET_PRIVATE_HDR_CONST(pkt) _OSHPACKET_OFFSET_CONST(pkt, OSHPACKET_PUBLIC_HDR_SIZE)
#define OSHPACKET_PAYLOAD_CONST(pkt)     _OSHPACKET_OFFSET_CONST(pkt, OSHPACKET_HDR_SIZE)

static inline bool oshpacket_type_valid(oshpacket_type_t type)
{
    return (type >= 0) && (type < _LAST_OSHPACKET_TYPE_ENTRY);
}

const char *oshpacket_type_name(oshpacket_type_t type);
const oshpacket_def_t *oshpacket_lookup(oshpacket_type_t type);
bool oshpacket_payload_size_valid(const oshpacket_def_t *def,
    const size_t payload_size);

void oshpacket_init(oshpacket_t *pkt, void *packet, size_t packet_size,
    cipher_seqno_t seqno);

#endif
