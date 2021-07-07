#ifndef _OSH_NETAREA_H
#define _OSH_NETAREA_H

typedef enum netarea {
    NETAREA_UNK = 0, // Unknown area
    NETAREA_LAN,     // Local area network
    NETAREA_WAN      // Wide area network
} netarea_t;

#endif