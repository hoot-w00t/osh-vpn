#include "netbuffer.h"
#include "xalloc.h"
#include "logger.h"
#include <stdlib.h>
#include <string.h>

// Allocate network buffer
netbuffer_t *netbuffer_alloc(size_t slots, size_t slot_size)
{
    netbuffer_t *nbuf;

    if (!slots || !slot_size)
        return NULL;

    nbuf = xalloc(sizeof(netbuffer_t));
    nbuf->slot_size = slot_size;
    nbuf->empty = true;
    nbuf->phys_start = xalloc(sizeof(uint8_t) * (slots * slot_size));
    nbuf->phys_end = nbuf->phys_start + (slots * slot_size);
    nbuf->data_start = nbuf->phys_start;
    nbuf->data_end = nbuf->phys_start;

    logger_debug(DBG_NETBUFFER,
        "Allocated netbuffer %p starting at %p (%zu slots of %zu bytes)",
        nbuf, nbuf->phys_start, slots, slot_size);
    return nbuf;
}

// Free network buffer
void netbuffer_free(netbuffer_t *nbuf)
{
    logger_debug(DBG_NETBUFFER, "Freeing netbuffer %p", nbuf);
    free(nbuf->phys_start);
    free(nbuf);
}

// Returns pointer to the next available slot
// If netbuffer is full, returns NULL
uint8_t *netbuffer_reserve(netbuffer_t *nbuf)
{
    uint8_t *slot;

    if (nbuf->data_end >= nbuf->phys_end)
        nbuf->data_end = nbuf->phys_start;
    if (nbuf->data_end == nbuf->data_start && !nbuf->empty)
        return NULL;

    nbuf->empty = false;
    slot = nbuf->data_end;
    nbuf->data_end += nbuf->slot_size;
    logger_debug(DBG_NETBUFFER, "Netbuffer %p reserved slot %p", nbuf, slot);
    return slot;
}

// Returns pointer to the next slot in queue
// If netbuffer is empty, returns NULL
uint8_t *netbuffer_next(netbuffer_t *nbuf)
{
    if (nbuf->empty)
        return NULL;

    nbuf->data_start += nbuf->slot_size;
    if (nbuf->data_start >= nbuf->phys_end)
        nbuf->data_start = nbuf->phys_start;

    if (   nbuf->data_start == nbuf->data_end
        || nbuf->data_end >= nbuf->phys_end)
    {
        nbuf->empty = true;
        return NULL;
    }
    return nbuf->data_start;
}