#ifndef _OSH_NETBUFFER_H
#define _OSH_NETBUFFER_H

#include <stdint.h>
#include <stddef.h>

typedef struct netbuffer {
    uint8_t *data;       // Data buffer
    size_t data_size;    // Size of the reserved data in the buffer

    size_t min_size;     // Minimum allocated size of the data buffer
    size_t current_size; // Currently allocated size of the data buffer
    size_t alignment;    // Size to align reallocations to
} netbuffer_t;

#define _netbuffer_ptr_attr __attribute__((returns_nonnull, warn_unused_result))

// Data pointer of the netbuffer
#define netbuffer_data(nbuf) ((nbuf)->data)

// Returns the amount of bytes queued in nbuf->data
#define netbuffer_data_size(nbuf) ((nbuf)->data_size)

netbuffer_t *netbuffer_create(size_t min_size, size_t alignment);
void netbuffer_free(netbuffer_t *nbuf);

void netbuffer_expand(netbuffer_t *nbuf, size_t size);
void netbuffer_shrink(netbuffer_t *nbuf);

_netbuffer_ptr_attr
uint8_t *netbuffer_reserve(netbuffer_t *nbuf, size_t data_size);
void netbuffer_cancel(netbuffer_t *nbuf, size_t data_size);
#define netbuffer_clear(nbuf) netbuffer_cancel(nbuf, netbuffer_data_size(nbuf))
void netbuffer_push(netbuffer_t *nbuf, const uint8_t *data, size_t data_size);
size_t netbuffer_pop(netbuffer_t *nbuf, size_t size);

#endif