#ifndef _OSH_NETBUFFER_H
#define _OSH_NETBUFFER_H

#include <stdint.h>
#include <stddef.h>

typedef struct netbuffer {
    size_t slot_size;      // Size in bytes of each slot
    size_t slot_count;     // Number of allocated slots
    size_t next_available; // Index of the next available slot (netbuffer_reserve)
    size_t next_taken;     // Index of the next taken slot (netbuffer_next)
    uint8_t *data;         // Slots data
    size_t data_size;      // Size of *data
    uint8_t **slots;       // Pointers to the slots allocated in *data
    uint8_t *slots_taken;  // Array of slot_count being non-zero or zero to
                           // indicate which slots are reserved and which are
                           // available. Non-zero means that the slot is taken,
                           // zero means that the slot is available
} netbuffer_t;

netbuffer_t *netbuffer_alloc(size_t slot_count, size_t slot_size);
void netbuffer_free(netbuffer_t *nbuf);
uint8_t *netbuffer_reserve(netbuffer_t *nbuf);
uint8_t *netbuffer_next(netbuffer_t *nbuf);

#endif