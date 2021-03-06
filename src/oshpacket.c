#include "oshpacket.h"

const char *oshpacket_type_name(oshpacket_type_t type)
{
    switch (type) {
        case HANDSHAKE      : return "HANDSHAKE";
        case HELLO_CHALLENGE: return "HELLO_CHALLENGE";
        case HELLO_RESPONSE : return "HELLO_RESPONSE";
        case HELLO_END      : return "HELLO_END";
        case DEVMODE        : return "DEVMODE";
        case STATEEXG_END   : return "STATEEXG_END";
        case GOODBYE        : return "GOODBYE";
        case PING           : return "PING";
        case PONG           : return "PONG";
        case DATA           : return "DATA";
        case PUBKEY         : return "PUBKEY";
        case ENDPOINT_EXPIRE: return "ENDPOINT_EXPIRE";
        case ENDPOINT       : return "ENDPOINT";
        case EDGE_ADD       : return "EDGE_ADD";
        case EDGE_DEL       : return "EDGE_DEL";
        case ROUTE_ADD      : return "ROUTE_ADD";
             default        : return "UNKNOWN";
    }
}

bool oshpacket_type_valid(oshpacket_type_t type)
{
    return type >= HANDSHAKE && type <= ROUTE_ADD;
}