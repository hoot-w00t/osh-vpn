#ifndef _OSH_NETBUFFER_H
#define _OSH_NETBUFFER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

typedef struct netbuffer {
    size_t slot_size;    // Size in bytes of each slot
    uint8_t *data_start; // Pointer the current slot in queue
    uint8_t *data_end;   // Pointer to the last slot in queue
    uint8_t *phys_start; // Pointer to the buffer data
    uint8_t *phys_end;   // Pointer to the end of the buffer data (out of bounds)
    bool empty;          // Is the netbuffer empty
} netbuffer_t;

netbuffer_t *netbuffer_alloc(size_t slots, size_t slot_size);
void netbuffer_free(netbuffer_t *nbuf);
uint8_t *netbuffer_reserve(netbuffer_t *nbuf);
uint8_t *netbuffer_next(netbuffer_t *nbuf);

#endif