#ifndef _OSH_OSHPACKET_H
#define _OSH_OSHPACKET_H

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
    ROUTE_ADD
} oshpacket_type_t;

// For a total of 40 bytes
typedef struct __attribute__((__packed__)) oshpacket_hdr {
    // Public header (never encrypted)
    // 3 bytes, if it changes OSHPACKET_PUBLIC_HDR_SIZE needs to be updated
    uint8_t          magic;
    uint16_t         payload_size;

    // Private header (after the handshake is done, this is always encrypted)
    // 37 bytes, if it changes OSHPACKET_HDR_SIZE needs to be updated
    oshpacket_type_t type : 8;
    uint32_t         counter;
    char             src_node[NODE_NAME_SIZE];
    char             dest_node[NODE_NAME_SIZE];
} oshpacket_hdr_t;

typedef struct __attribute__((__packed__)) oshpacket_hello_challenge {
    char node_name[NODE_NAME_SIZE];
    uint8_t challenge[OSHPACKET_PAYLOAD_MAXSIZE - NODE_NAME_SIZE];
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
    uint8_t addr_data[16];
    uint16_t port;
} oshpacket_endpoint_t;

typedef struct __attribute__((__packed__)) oshpacket_edge {
    char src_node[NODE_NAME_SIZE];
    char dest_node[NODE_NAME_SIZE];
} oshpacket_edge_t;

typedef struct __attribute__((__packed__)) oshpacket_route {
    char node_name[NODE_NAME_SIZE];
    netaddr_type_t addr_type : 8;
    uint8_t addr_data[16];
} oshpacket_route_t;

// Size of the public part of the header
#define OSHPACKET_PUBLIC_HDR_SIZE (3)

// Size of the private part of the header
#define OSHPACKET_PRIVATE_HDR_SIZE (1 + 4 + (NODE_NAME_SIZE * 2))

// Total size of the header
#define OSHPACKET_HDR_SIZE (OSHPACKET_PUBLIC_HDR_SIZE + OSHPACKET_PRIVATE_HDR_SIZE)

#define OSHPACKET_MAXSIZE (OSHPACKET_HDR_SIZE + OSHPACKET_PAYLOAD_MAXSIZE)

const char *oshpacket_type_name(oshpacket_type_t type);
bool oshpacket_type_valid(oshpacket_type_t type);

#endif