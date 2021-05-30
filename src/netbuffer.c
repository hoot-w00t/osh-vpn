#include "netbuffer.h"
#include "xalloc.h"
#include "logger.h"
#include <stdlib.h>
#include <string.h>

// Allocate network buffer
netbuffer_t *netbuffer_alloc(size_t slot_count, size_t slot_size)
{
    netbuffer_t *nbuf;

    if (!slot_count || !slot_size)
        return NULL;

    nbuf = xzalloc(sizeof(netbuffer_t));
    logger_debug(DBG_NETBUFFER, "Netbuffer: Allocated %p for %zu slots of %zu bytes",
        slot_count, slot_size);

    nbuf->slot_size = slot_size;
    nbuf->slot_count = slot_count;

    nbuf->data_size = slot_count * slot_size;
    nbuf->data = xzalloc(nbuf->data_size);
    nbuf->slots = xalloc(slot_count * sizeof(uint8_t *));
    nbuf->slots_taken = xzalloc(slot_count * sizeof(bool));
    for (size_t i = 0; i < slot_count; ++i)
        nbuf->slots[i] = nbuf->data + (i * slot_size);

    logger_debug(DBG_NETBUFFER, "Netbuffer: %p: Allocated data %p (%zu bytes)",
        nbuf->data, nbuf->data_size);
    return nbuf;
}

// Free network buffer
void netbuffer_free(netbuffer_t *nbuf)
{
    logger_debug(DBG_NETBUFFER, "Freeing netbuffer %p (%zu slots of %zu bytes)",
        nbuf, nbuf->slot_count, nbuf->slot_size);
    free(nbuf->data);
    free(nbuf->slots);
    free(nbuf->slots_taken);
    free(nbuf);
}

// Returns pointer to the next available slot
// If netbuffer is full, returns NULL
uint8_t *netbuffer_reserve(netbuffer_t *nbuf)
{
    uint8_t *slot;

    // If the next available index is at the end of the slots, go back to the
    // beginning
    if (nbuf->next_available >= nbuf->slot_count)
        nbuf->next_available = 0;

    // If the next available slot is taken already the netbuffer is full and
    // cannot reserve any more data
    if (nbuf->slots_taken[nbuf->next_available])
        return NULL;

    // The next available slot is not taken, so take it
    nbuf->slots_taken[nbuf->next_available] = 1;
    slot = nbuf->slots[nbuf->next_available];

    // Move to the next slot for future calls
    nbuf->next_available += 1;

    logger_debug(DBG_NETBUFFER, "Netbuffer %p reserved slot %p", nbuf, slot);
    return slot;
}

// Returns pointer to the next slot in queue
// If netbuffer is empty, returns NULL
uint8_t *netbuffer_next(netbuffer_t *nbuf)
{
    // If the current slot is not taken then there are no other slots taken,
    // the netbuffer is empty
    if (!nbuf->slots_taken[nbuf->next_taken])
        return NULL;

    // The current slot is taken, we move to the next one and make this one
    // available again
    nbuf->slots_taken[nbuf->next_taken] = 0;
    nbuf->next_taken += 1;

    // If the next taken index is at the end of the slots, go back to the
    // beginning
    if (nbuf->next_taken >= nbuf->slot_count)
        nbuf->next_taken = 0;

    // If the next queued slot is taken, we can return it
    // Otherwise it means that the netbuffer is now empty
    if (nbuf->slots_taken[nbuf->next_taken]) {
        return nbuf->slots[nbuf->next_taken];
    } else {
        return NULL;
    }
}