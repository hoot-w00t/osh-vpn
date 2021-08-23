#include "netbuffer.h"
#include "xalloc.h"
#include "logger.h"
#include <stdlib.h>
#include <string.h>

#define align(size, alignment) (((((size) - 1) / (alignment)) + 1) * (alignment))

// Create an empty netbuffer
// Memory allocations will be aligned to alignment
// min_size will also be aligned
// Returns NULL if min_size or alignment is 0
netbuffer_t *netbuffer_create(size_t min_size, size_t alignment)
{
    netbuffer_t *nbuf;

    if (!min_size || !alignment) {
        logger(LOG_CRIT, "netbuffer_create: min_size and alignment cannot be 0");
        return NULL;
    }

    nbuf = xzalloc(sizeof(netbuffer_t));
    nbuf->alignment = alignment;
    nbuf->min_size = align(min_size, alignment);
    nbuf->current_size = nbuf->min_size;
    nbuf->data = xalloc(nbuf->current_size);
    logger_debug(DBG_NETBUFFER, "Created netbuffer %p of %zu bytes, aligned to %zu bytes",
        nbuf, nbuf->current_size, nbuf->alignment);
    return nbuf;
}

// Free netbuffer
void netbuffer_free(netbuffer_t *nbuf)
{
    logger_debug(DBG_NETBUFFER, "Netbuffer %p: Freeing %zu bytes", nbuf,
        nbuf->current_size);
    free(nbuf->data);
    free(nbuf);
}

// Reallocate at least size bytes in the netbuffer
void netbuffer_expand(netbuffer_t *nbuf, size_t size)
{
    const size_t aligned_size = align(size, nbuf->alignment);

    logger_debug(DBG_NETBUFFER, "Netbuffer %p: Expanding %zu bytes (unaligned %zu)",
        nbuf, aligned_size, size);
    nbuf->current_size += aligned_size;
    nbuf->data = xrealloc(nbuf->data, nbuf->current_size);
}

// Reallocate netbuffer to its minimum size
void netbuffer_shrink(netbuffer_t *nbuf)
{
    logger_debug(DBG_NETBUFFER, "Netbuffer %p: Shrinking to %zu bytes (from %zu bytes)",
        nbuf, nbuf->min_size, nbuf->current_size);
    nbuf->current_size = nbuf->min_size;
    nbuf->data = xrealloc(nbuf->data, nbuf->current_size);
}

// Reserve data_size bytes at the end of the netbuffer
// Dynamically allocates memory if needed
_netbuffer_ptr_attr
uint8_t *netbuffer_reserve(netbuffer_t *nbuf, size_t data_size)
{
    uint8_t *dataptr;

    // If the new data size is bigger than the allocated buffer, expand it
    if ((nbuf->data_size + data_size) > nbuf->current_size)
        netbuffer_expand(nbuf, data_size);

    // The data pointer can change during reallocation so we need to calculate
    // it after it was done
    dataptr = nbuf->data + nbuf->data_size;
    nbuf->data_size += data_size;

    logger_debug(DBG_NETBUFFER, "Netbuffer %p: Reserved %zu bytes (%p)",
        nbuf, data_size, dataptr);
    return dataptr;
}

// Cancel the last data_size bytes from the netbuffer
// Can be used to cancel reserved bytes
void netbuffer_cancel(netbuffer_t *nbuf, size_t data_size)
{
    if (data_size >= nbuf->data_size) {
        logger_debug(DBG_NETBUFFER, "Netbuffer %p: Cancelled the last %zu bytes",
            nbuf, nbuf->data_size);

        nbuf->data_size = 0;

        // Shrink the netbuffer to reduce memory usage
        if (nbuf->current_size > nbuf->min_size)
            netbuffer_shrink(nbuf);
    } else {
        logger_debug(DBG_NETBUFFER, "Netbuffer %p: Cancelled %zu bytes",
            nbuf, data_size);
        nbuf->data_size -= data_size;
    }
}

// Reserve data_size bytes and copy data to the reserved space
void netbuffer_push(netbuffer_t *nbuf, const uint8_t *data, size_t data_size)
{
    uint8_t *dataptr = netbuffer_reserve(nbuf, data_size);

    memcpy(dataptr, data, data_size);
    logger_debug(DBG_NETBUFFER, "Netbuffer %p: Pushed %zu bytes (%p)",
        nbuf, data_size, dataptr);
}

// Remove size bytes from the start of the data pointer
// Returns the new data_size of the netbuffer
size_t netbuffer_pop(netbuffer_t *nbuf, size_t size)
{
    // If we pop the last bytes of the buffer we will reset the data_size and
    // shrink the netbuffer if necessary
    if (size >= nbuf->data_size) {
        logger_debug(DBG_NETBUFFER, "Netbuffer %p: Popped the last %zu bytes",
            nbuf, nbuf->data_size);

        nbuf->data_size = 0;

        // Shrink the netbuffer to reduce memory usage
        if (nbuf->current_size > nbuf->min_size)
            netbuffer_shrink(nbuf);
    } else {
        // Otherwise we shift the data by size bytes and decrement the data_size
        logger_debug(DBG_NETBUFFER, "Netbuffer %p: Popped %zu/%zu bytes",
            nbuf, size, nbuf->data_size);

        nbuf->data_size -= size;
        memmove(nbuf->data, nbuf->data + size, nbuf->data_size);
    }
    return nbuf->data_size;
}