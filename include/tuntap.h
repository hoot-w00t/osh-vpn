#ifndef _OSH_TUNTAP_H
#define _OSH_TUNTAP_H

#include "macros.h"
#include "aio.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifndef TUNTAP_BUFSIZE
// Maximum size of a single TUN/TAP packet (maximum supported MTU)
#define TUNTAP_BUFSIZE 1518
#endif

#if (TUNTAP_BUFSIZE <= 0)
#error "TUNTAP_BUFSIZE must be a positive value"
#endif

typedef union tuntap_data {
    void *ptr;
    int fd;
    uint32_t u32;
    uint64_t u64;
} tuntap_data_t;

typedef struct tuntap {
    // true if the device is running in layer 2
    bool is_tap;

    // Device name
    char *dev_name;
    size_t dev_name_size;

    // Device ID (depends on the platform)
    char *dev_id;
    size_t dev_id_size;

    // Any data needed by the TUN/TAP interface we are compiling
    tuntap_data_t data;
} tuntap_t;

// Open TUN/TAP device
// If devname is NULL or empty the device name will be determined automatically
// (if possible)
// If tap is true the device will use layer 2 (TAP), otherwise it will use
// layer 3 (TUN)
// Returns NULL on error
tuntap_t *tuntap_open(const char *devname, bool tap);

// Close TUN/TAP device and free all resources
// The pointer will also be freed, it should not be used after calling this
// function
void tuntap_close(tuntap_t *tuntap);

// Read a packet from the TUN/TAP device to buf which should be of buf_size
// Sets *pkt_size to the actual size of the packet (<= buf_size)
// If *pkt_size is 0 there are no packets ready to be read
// Returns false on error
bool tuntap_read(tuntap_t *tuntap, void *buf, size_t buf_size, size_t *pkt_size);

// Write a packet to the TUN/TAP device
// Returns false on error
bool tuntap_write(tuntap_t *tuntap, const void *packet, size_t packet_size);

// Initialize an AIO event for the TUN/TAP device
// This function should only modify the file descriptor/handle, other members
// (poll events, userdata and callbacks) must not be modified as they can be
// overwritten
void tuntap_init_aio_event(tuntap_t *tuntap, aio_event_t *event);

// Close TUN/TAP device pointed by tuntap, sets it to NULL after
static inline void tuntap_close_at(tuntap_t **tuntap)
{
    tuntap_close(*tuntap);
    *tuntap = NULL;
}

// Common functions for all interfaces
// Defined in src/tuntap/common.c
bool tuntap_nonblock(int fd);
tuntap_t *tuntap_empty(bool is_tap);
void tuntap_free_common(tuntap_t *tuntap);

#endif
