#ifndef _OSH_NETAREA_H
#define _OSH_NETAREA_H

typedef enum netarea {
    NETAREA_UNK = 0, // Unknown area
    NETAREA_LAN,     // Local area network
    NETAREA_WAN,     // Wide area network
    _netarea_last
} netarea_t;

// Returns the name of the area
static inline const char *netarea_name(netarea_t area)
{
    switch (area) {
        case NETAREA_UNK: return "UNK";
        case NETAREA_LAN: return "LAN";
        case NETAREA_WAN: return "WAN";
        default: return "Unknown";
    }
}

#endif
