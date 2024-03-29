#ifndef _OSH_TUNTAP_H
#define _OSH_TUNTAP_H

#include "macros.h"
#include "aio.h"
#include "netaddr.h"
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

#define TUNTAP_IS_TAP_STR(is_tap) ((is_tap) ? "TAP" : "TUN")

typedef struct tuntap_packethdr tuntap_packethdr_t;
typedef union tuntap_data tuntap_data_t;
typedef struct tuntap tuntap_t;

typedef void (*tuntap_emu_func_init_t)(tuntap_t *tuntap);
typedef void (*tuntap_emu_func_deinit_t)(tuntap_t *tuntap);

typedef void (*tuntap_func_close_t)(tuntap_t *tuntap);
typedef bool (*tuntap_func_read_t)(tuntap_t *tuntap, void *buf, size_t buf_size, size_t *pkt_size);
typedef bool (*tuntap_func_write_t)(tuntap_t *tuntap, const void *packet, size_t packet_size);
typedef void (*tuntap_func_init_aio_event_t)(tuntap_t *tuntap, aio_event_t *event);

typedef bool (*tuntap_func_parse_packethdr_t)(tuntap_packethdr_t *hdr, const void *packet, size_t packet_size);

// TUN/TAP packet header information
struct tuntap_packethdr {
    netaddr_t src;      // Source address
    netaddr_t dest;     // Destination address
};

union tuntap_data {
    void *ptr;
    int fd;
    uint32_t u32;
    uint64_t u64;
};

struct tuntap_drv {
    // true if the virtual network interface is running in layer 2
    bool is_tap;

    // API function pointers of the TUN/TAP driver
    tuntap_func_close_t close;
    tuntap_func_read_t read;
    tuntap_func_write_t write;
    tuntap_func_init_aio_event_t init_aio_event;
};

struct tuntap_emu {
    // true if emulation is enabled
    bool enabled;

    // Emulation-specific function pointers
    tuntap_emu_func_init_t init;
    tuntap_emu_func_deinit_t deinit;

    // Any data needed by the emulation layer
    tuntap_data_t data;
};

struct tuntap {
    // TUN/TAP driver information and API function pointers
    struct tuntap_drv drv;

    // Any data needed by the TUN/TAP driver
    tuntap_data_t data;

    // TUN/TAP emulation information
    struct tuntap_emu emu;

    // API function pointers used by tuntap_read()/tuntap_write(), set up by
    // tuntap_open()
    tuntap_func_read_t read;
    tuntap_func_write_t write;

    // Function to parse network packets of tuntap_read()/tuntap_write()
    tuntap_func_parse_packethdr_t parse_packethdr;

    // Device name
    char *dev_name;

    // Device ID (can be NULL, depends on the platform)
    char *dev_id;

    // true if the TUN/TAP device is running in layer 2
    // This reflects the layer of tuntap_read()/tuntap_write() packets
    bool is_tap;
};

// Open TUN/TAP device
// If devname is NULL or empty the device name will be determined automatically
// (if possible)
// If tap is true the device will use layer 2 (TAP), otherwise it will use
// layer 3 (TUN)
// Returns NULL on error
tuntap_t *tuntap_open(const char *devname, bool tap);

// Platform-specific function called by tuntap_open() to actually open a TUN/TAP
// device
// If multiple drivers are available this function chooses which one to open
// Returns NULL on any error
tuntap_t *_tuntap_open(const char *devname, bool tap);

// Close TUN/TAP device and free all resources
// The pointer will also be freed, it should not be used after calling this
// function
void tuntap_close(tuntap_t *tuntap);

// Read a packet from the TUN/TAP device to buf which should be of buf_size
// Sets *pkt_size to the actual size of the packet (<= buf_size)
// If *pkt_size is 0 there are no packets ready to be read
// Returns false on error
#define tuntap_read(tuntap, buf, buf_size, pkt_size) \
    (tuntap)->read(tuntap, buf, buf_size, pkt_size)

// Write a packet to the TUN/TAP device
// Returns false on error
#define tuntap_write(tuntap, packet, packet_size) \
    (tuntap)->write(tuntap, packet, packet_size)

// Initialize an AIO event for the TUN/TAP device
// This function should only modify the file descriptor/handle, other members
// (poll events, userdata and callbacks) must not be modified as they can be
// overwritten
#define tuntap_init_aio_event(tuntap, event) \
    (tuntap)->drv.init_aio_event(tuntap, event)

// Parse TUN/TAP packet header
// (parses Ethernet header in TAP mode, IPv4/IPv6 header in TUN mode)
#define tuntap_parse_packethdr(tuntap, hdr, packet, packet_size) \
    (tuntap)->parse_packethdr(hdr, packet, packet_size)

// Close TUN/TAP device pointed by tuntap, sets it to NULL after
static inline void tuntap_close_at(tuntap_t **tuntap)
{
    tuntap_close(*tuntap);
    *tuntap = NULL;
}

// Common functions for all interfaces
// Defined in src/tuntap/common.c
bool tuntap_nonblock(int fd);

tuntap_t *tuntap_empty(const struct tuntap_drv *drv, const bool is_tap);

void tuntap_generate_devname(char *dest, size_t dest_maxsize, const char *name_prefix);
void tuntap_set_devname(tuntap_t *tuntap, const char *devname);
void tuntap_set_devid(tuntap_t *tuntap, const char *devid);

#define tuntap_driver_is_tap(tuntap)    ((tuntap)->drv.is_tap)
#define tuntap_driver_is_tun(tuntap)    (!tuntap_driver_is_tap(tuntap))
#define tuntap_is_tap(tuntap)           ((tuntap)->is_tap)
#define tuntap_is_tun(tuntap)           (!tuntap_is_tap(tuntap))

#ifndef TUNTAP_DISABLE_EMULATION
    // Emulation layers
    // API functions which must only be used by emulation layers
    #define tuntap_driver_read(tuntap, buf, buf_size, pkt_size) \
        (tuntap)->drv.read(tuntap, buf, buf_size, pkt_size)
    #define tuntap_driver_write(tuntap, packet, packet_size) \
        (tuntap)->drv.write(tuntap, packet, packet_size)

    // Defined in src/tuntap/tun_emu.c
    void tuntap_emu_tun_init(tuntap_t *tuntap);
    void tuntap_emu_tun_deinit(tuntap_t *tuntap);
#endif

#endif
