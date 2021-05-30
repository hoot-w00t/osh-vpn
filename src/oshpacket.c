#include "oshpacket.h"

const char *oshpacket_type_name(oshpacket_type_t type)
{
    switch (type) {
        case HELLO    : return "HELLO";
        case GOODBYE  : return "GOODBYE";
        case PING     : return "PING";
        case PONG     : return "PONG";
        case DATA     : return "DATA";
        case EDGE_EXG : return "EDGE_EXG";
        case ADD_EDGE : return "ADD_EDGE";
        case DEL_EDGE : return "DEL_EDGE";
        case ADD_ROUTE: return "ADD_ROUTE";
             default  : return "UNKNOWN";
    }
}