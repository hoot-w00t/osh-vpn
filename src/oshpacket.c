#include "oshpacket.h"

const char *oshpacket_type_name(oshpacket_type_t type)
{
    switch (type) {
        case HELLO_CHALLENGE: return "HELLO_CHALLENGE";
        case HELLO_RESPONSE : return "HELLO_RESPONSE";
        case HANDSHAKE      : return "HANDSHAKE";
        case GOODBYE        : return "GOODBYE";
        case PING           : return "PING";
        case PONG           : return "PONG";
        case DATA           : return "DATA";
        case EDGE_EXG       : return "EDGE_EXG";
        case EDGE_ADD       : return "EDGE_ADD";
        case EDGE_DEL       : return "EDGE_DEL";
        case ROUTE_ADD      : return "ROUTE_ADD";
             default        : return "UNKNOWN";
    }
}

bool oshpacket_type_valid(oshpacket_type_t type)
{
    return type >= HELLO_CHALLENGE && type <= ROUTE_ADD;
}