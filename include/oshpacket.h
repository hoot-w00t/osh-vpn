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

#ifndef HELLO_SIG_SIZE
// The Ed25519 keys' signature is 64 bytes in length
#define HELLO_SIG_SIZE (64)
#endif

#ifndef HANDSHAKE_KEY_SIZE
// The X25519 public keys' length is 32 bytes
#define HANDSHAKE_KEY_SIZE (32)
#endif

#ifndef PUBLIC_KEY_SIZE
// The Ed25519 public keys' length is 32 bytes
#define PUBLIC_KEY_SIZE (32)
#endif

#define OSHPACKET_PAYLOAD_MAXSIZE (2048)

typedef enum oshpacket_type {
    HANDSHAKE = 0,
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
    ENDPOINT_EXPIRE,
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
    // Public X25519 key to derive for sending packets to the other node
    uint8_t send_pubkey[HANDSHAKE_KEY_SIZE];

    // Public X25519 key to derive for receiving packets from the other node
    uint8_t recv_pubkey[HANDSHAKE_KEY_SIZE];
} oshpacket_handshake_t;

typedef struct __attribute__((__packed__)) oshpacket_pubkey {
    char node_name[NODE_NAME_SIZE];
    uint8_t node_pubkey[PUBLIC_KEY_SIZE];
} oshpacket_pubkey_t;

typedef struct __attribute__((__packed__)) oshpacket_endpoint_expire {
    char node_name[NODE_NAME_SIZE];
} oshpacket_endpoint_expire_t;

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