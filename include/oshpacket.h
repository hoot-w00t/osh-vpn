#ifndef _OSH_OSHPACKET_H
#define _OSH_OSHPACKET_H

#include "crypto/cipher.h"
#include "netaddr.h"
#include "oshd_device_mode.h"
#include <stdint.h>

#ifndef OSHPACKET_MAGIC
#define OSHPACKET_MAGIC (0x1)
#endif

#if (OSHPACKET_MAGIC > 0xFF)
#error "OSHPACKET_MAGIC is a 1 byte value"
#endif

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

#ifndef HELLO_SIG_SIZE
#define HELLO_SIG_SIZE ED25519_SIG_SIZE
#endif

#ifndef HANDSHAKE_KEY_SIZE
#define HANDSHAKE_KEY_SIZE X25519_KEY_SIZE
#endif

#ifndef PUBLIC_KEY_SIZE
#define PUBLIC_KEY_SIZE ED25519_KEY_SIZE
#endif

#define OSHPACKET_PAYLOAD_MAXSIZE (2048)

typedef enum oshpacket_type {
    HANDSHAKE = 0,
    HANDSHAKE_END,
    HELLO_CHALLENGE,
    HELLO_RESPONSE,
    HELLO_END,
    DEVMODE,
    STATEEXG_END,
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

// For a total of 36 bytes
typedef struct __attribute__((__packed__)) oshpacket_hdr {
    // Public header (never encrypted)
    // 3 bytes, if it changes OSHPACKET_PUBLIC_HDR_SIZE needs to be updated
    uint8_t          magic;
    uint16_t         payload_size;
    uint8_t          tag[CIPHER_TAG_SIZE];

    // Private header (after the handshake is done, this is always encrypted)
    // 33 bytes, if it changes OSHPACKET_HDR_SIZE needs to be updated
    oshpacket_type_t type : 8;
    char             src_node[NODE_NAME_SIZE];
    char             dest_node[NODE_NAME_SIZE];
} oshpacket_hdr_t;

typedef struct __attribute__((__packed__)) oshpacket_hello_challenge {
    uint8_t challenge[OSHPACKET_PAYLOAD_MAXSIZE];
} oshpacket_hello_challenge_t;

typedef struct __attribute__((__packed__)) oshpacket_hello_response {
    uint8_t sig[HELLO_SIG_SIZE];
} oshpacket_hello_response_t;

typedef struct __attribute__((__packed__)) oshpacket_hello_end {
    uint8_t hello_success;
} oshpacket_hello_end_t;

typedef struct __attribute__((__packed__)) oshpacket_devmode {
    device_mode_t devmode : 8;
} oshpacket_devmode_t;

typedef struct __attribute__((__packed__)) oshpacket_handshake {
    // Public X25519 keys to compute a shared secret
    union {
        struct __attribute__((__packed__)) {
            uint8_t send[HANDSHAKE_KEY_SIZE];
            uint8_t recv[HANDSHAKE_KEY_SIZE];
        } k;
        uint8_t both[HANDSHAKE_KEY_SIZE * 2];
    } keys;

    // Signature of both public keys
    uint8_t sig[HELLO_SIG_SIZE];
} oshpacket_handshake_t;

typedef struct __attribute__((__packed__)) oshpacket_pubkey {
    char node_name[NODE_NAME_SIZE];
    uint8_t node_pubkey[PUBLIC_KEY_SIZE];
} oshpacket_pubkey_t;

typedef struct __attribute__((__packed__)) oshpacket_endpoint {
    char node_name[NODE_NAME_SIZE];
    netaddr_type_t addr_type : 8;
    netaddr_data_t addr_data;
    uint16_t port;
} oshpacket_endpoint_t;

typedef struct __attribute__((__packed__)) oshpacket_edge {
    char src_node[NODE_NAME_SIZE];
    char dest_node[NODE_NAME_SIZE];
} oshpacket_edge_t;

typedef struct __attribute__((__packed__)) oshpacket_route {
    char owner_name[NODE_NAME_SIZE];
    netaddr_type_t type : 8;
    netaddr_prefixlen_t prefixlen : 8;
    netaddr_data_t addr;
    uint8_t can_expire : 8;
} oshpacket_route_t;

// Size of the public part of the header
#define OSHPACKET_PUBLIC_HDR_SIZE (3 + CIPHER_TAG_SIZE)

// Size of the private part of the header
#define OSHPACKET_PRIVATE_HDR_SIZE (1 + (NODE_NAME_SIZE * 2))

// Total size of the header
#define OSHPACKET_HDR_SIZE (OSHPACKET_PUBLIC_HDR_SIZE + OSHPACKET_PRIVATE_HDR_SIZE)

#define OSHPACKET_MAXSIZE (OSHPACKET_HDR_SIZE + OSHPACKET_PAYLOAD_MAXSIZE)

#define _OSHPACKET_OFFSET(pkt, offset) (((uint8_t *) (pkt)) + (offset))
#define OSHPACKET_HDR(pkt) ((oshpacket_hdr_t *) (pkt))
#define OSHPACKET_PRIVATE_HDR(pkt) _OSHPACKET_OFFSET(pkt, OSHPACKET_PUBLIC_HDR_SIZE)
#define OSHPACKET_PAYLOAD(pkt) _OSHPACKET_OFFSET(pkt, OSHPACKET_HDR_SIZE)

const char *oshpacket_type_name(oshpacket_type_t type);

static inline bool oshpacket_type_valid(oshpacket_type_t type)
{
    return type >= 0 && type < _LAST_OSHPACKET_TYPE_ENTRY;
}

#endif