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


typedef enum oshpacket_type {
    HELLO = 0,
    PING,
    PONG,
    DATA,
    EDGE_EXG,
    ADD_EDGE,
    DEL_EDGE,
    ADD_ROUTE
} oshpacket_type_t;

typedef struct __attribute__((__packed__)) oshpacket_hdr {
    uint8_t          magic            ;
    oshpacket_type_t type          : 8;
    uint16_t         payload_size     ;
    char             src_node[16]     ;
    char             dest_node[16]    ;
} oshpacket_hdr_t;

#define OSHPACKET_HDR_SIZE (4 + (NODE_NAME_SIZE * 2))
// TODO: Define a proper payload size
#define OSHPACKET_PAYLOAD_MAXSIZE (2048)
#define OSHPACKET_MAXSIZE (OSHPACKET_HDR_SIZE + OSHPACKET_PAYLOAD_MAXSIZE)

const char *oshpacket_type_name(oshpacket_type_t type);

#endif