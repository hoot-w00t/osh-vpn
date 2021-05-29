#ifndef _OSH_OSHPACKET_H
#define _OSH_OSHPACKET_H

#include <stdint.h>

#ifndef OSHPACKET_MAGIC
#define OSHPACKET_MAGIC (0x1)
#endif

#if (OSHPACKET_MAGIC > 0xF)
#error "OSHPACKET_MAGIC is a 4-bit value"
#endif

#ifndef NODE_NAME_SIZE
#define NODE_NAME_SIZE (16)
#endif

#ifndef HELLO_SIG_SIZE
// The Ed25519 keys' signature is 64 bytes in length
#define HELLO_SIG_SIZE (64)
#endif

typedef enum oshpacket_type {
    HELLO = 0,
    GOODBYE,
    PING,
    PONG,
    DATA,
    EDGE_EXG,
    ADD_EDGE,
    DEL_EDGE,
    ADD_ROUTE
} oshpacket_type_t;

typedef struct __attribute__((__packed__)) oshpacket_hdr {
    uint8_t          magic;
    oshpacket_type_t type : 8;
    uint16_t         payload_size;
    char             src_node[NODE_NAME_SIZE];
    char             dest_node[NODE_NAME_SIZE];
} oshpacket_hdr_t;

typedef struct __attribute__((__packed__)) oshpacket_hello {
    char node_name[NODE_NAME_SIZE];
    uint8_t sig[HELLO_SIG_SIZE];
} oshpacket_hello_t;

typedef struct __attribute__((__packed__)) oshpacket_edge {
    char src_node[NODE_NAME_SIZE];
    char dest_node[NODE_NAME_SIZE];
} oshpacket_edge_t;

typedef struct __attribute__((__packed__)) oshpacket_route {
    netaddr_type_t addr_type : 8;
    uint8_t addr_data[16];
} oshpacket_route_t;

#define OSHPACKET_HDR_SIZE (4 + (NODE_NAME_SIZE * 2))
// TODO: Define a proper payload size
#define OSHPACKET_PAYLOAD_MAXSIZE (2048)
#define OSHPACKET_MAXSIZE (OSHPACKET_HDR_SIZE + OSHPACKET_PAYLOAD_MAXSIZE)

const char *oshpacket_type_name(oshpacket_type_t type);

#endif