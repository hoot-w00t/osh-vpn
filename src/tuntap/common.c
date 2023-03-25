#include "macros.h"
#include "logger.h"
#include "xalloc.h"
#include "tuntap.h"
#include "netdefs/ether.h"
#include "netdefs/ip.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>

// Parse TAP packet header to *hdr
static bool tap_to_packethdr(tuntap_packethdr_t *hdr, const void *packet, size_t packet_size)
{
    const struct eth_hdr *eth_hdr = (const struct eth_hdr *) packet;

    if (packet_size < sizeof(*eth_hdr))
        return false;

    netaddr_dton_mac(&hdr->dest, eth_hdr->dest);
    netaddr_dton_mac(&hdr->src,  eth_hdr->src);
    return true;
}

// Parse TUN packet header to *hdr
static bool tun_to_packethdr(tuntap_packethdr_t *hdr, const void *packet, size_t packet_size)
{
    if (packet_size == 0)
        return false;

    switch (IP_HDR_VERSION(packet)) {
        case 4: { // IPv4 packet
            const struct ipv4_hdr *ipv4_hdr = (const struct ipv4_hdr *) packet;

            if (packet_size < sizeof(*ipv4_hdr))
                return false;

            netaddr_dton_ip4_u32(&hdr->src,  ipv4_hdr->saddr);
            netaddr_dton_ip4_u32(&hdr->dest, ipv4_hdr->daddr);
            return true;
        }

        case 6: { // IPv6 packet
            const struct ipv6_hdr *ipv6_hdr = (const struct ipv6_hdr *) packet;

            if (packet_size < sizeof(*ipv6_hdr))
                return false;

            netaddr_dton_ip6(&hdr->src,  ipv6_hdr->src_addr);
            netaddr_dton_ip6(&hdr->dest, ipv6_hdr->dst_addr);
            return true;
        }

        default: // Invalid or unknown packet
            return false;
    }
}

#if !(PLATFORM_IS_WINDOWS)
#include <fcntl.h>

// Set O_NONBLOCK for fd
bool tuntap_nonblock(int fd)
{
    int flags;

    if ((flags = fcntl(fd, F_GETFL, 0)) < 0) {
        logger(LOG_ERR, "fcntl(%i, F_GETFL): %s", fd, strerror(errno));
        return false;
    }

    flags |= O_NONBLOCK;
    if (fcntl(fd, F_SETFL, flags) < 0) {
        logger(LOG_ERR, "fcntl(%i, F_SETFL, %i): %s", fd, flags, strerror(errno));
        return false;
    }
    return true;
}
#endif

#ifndef TUNTAP_DISABLE_EMULATION
// Initialize tuntap_t->emu and function pointers
static void tuntap_emu_setup(
    tuntap_t *tuntap,
    tuntap_emu_func_init_t init,
    tuntap_emu_func_deinit_t deinit)
{
    tuntap->emu.enabled = true;
    tuntap->emu.init = init;
    tuntap->emu.deinit = deinit;
}
#endif

// Allocate an empty tuntap_t
// Initializes the driver information from *drv (all of the function pointers
// must be valid)
// is_tap is the requested/emulated layer used by tuntap_read()/tuntap_write()
tuntap_t *tuntap_empty(const struct tuntap_drv *drv, const bool is_tap)
{
    tuntap_t *tuntap = xzalloc(sizeof(tuntap_t));

    tuntap->drv = *drv;
    tuntap->is_tap = is_tap;

#ifndef TUNTAP_DISABLE_EMULATION
    // If the opened driver doesn't work on the requested layer, emulate it
    if (tuntap_is_tun(tuntap) && tuntap_driver_is_tap(tuntap)) {
        // TUN emulation
        tuntap_emu_setup(tuntap, tuntap_emu_tun_init, tuntap_emu_tun_deinit);
    }
#endif

    return tuntap;
}

// Set TUN/TAP device name
void tuntap_set_devname(tuntap_t *tuntap, const char *devname)
{
    free(tuntap->dev_name);
    tuntap->dev_name = xstrdup(devname);
}

// Set TUN/TAP device ID
void tuntap_set_devid(tuntap_t *tuntap, const char *devid)
{
    free(tuntap->dev_id);
    tuntap->dev_id = xstrdup(devid);
}

tuntap_t *tuntap_open(const char *devname, bool tap)
{
    tuntap_t *tuntap = _tuntap_open(devname, tap);

    if (!tuntap) {
        logger(LOG_ERR, "Failed to open %s device", TUNTAP_IS_TAP_STR(tap));
        return NULL;
    }

    // Setup read/write function pointers
    // If emulation is enabled the init function sets up its own read/write functions
    // If it is disabled we can use the driver's read/write functions directly
    if (tuntap->emu.enabled) {
        tuntap->emu.init(tuntap);
    } else {
        tuntap->read = tuntap->drv.read;
        tuntap->write = tuntap->drv.write;
    }

    // Setup parse_packethdr function pointer
    tuntap->parse_packethdr = tuntap->is_tap
                            ? tap_to_packethdr
                            : tun_to_packethdr;

    if (tuntap->drv.is_tap == tuntap->is_tap) {
        logger(LOG_INFO, "Opened %s device: %s",
            TUNTAP_IS_TAP_STR(tuntap->drv.is_tap),
            tuntap->dev_name);
    } else {
        // If the driver is not running on the requested layer and emulation is
        // disabled the virtual network won't work
        if (!tuntap->emu.enabled) {
            logger(LOG_ERR, "Opened %s device but %s emulation is not supported",
                TUNTAP_IS_TAP_STR(tuntap->drv.is_tap),
                TUNTAP_IS_TAP_STR(tuntap->is_tap));
            tuntap_close(tuntap);
            return NULL;
        }

        logger(LOG_INFO, "Opened %s device: %s (with %s emulation)",
            TUNTAP_IS_TAP_STR(tuntap->drv.is_tap),
            tuntap->dev_name,
            TUNTAP_IS_TAP_STR(tuntap->is_tap));
    }

    return tuntap;
}

void tuntap_close(tuntap_t *tuntap)
{
    logger(LOG_INFO, "Closing %s device: %s",
        TUNTAP_IS_TAP_STR(tuntap->drv.is_tap),
        tuntap->dev_name);

    // Stop and free the emulation layer
    if (tuntap->emu.enabled)
        tuntap->emu.deinit(tuntap);

    // Close and free the driver
    tuntap->drv.close(tuntap);

    // Free common resources and the tuntap_t pointer
    free(tuntap->dev_name);
    free(tuntap->dev_id);
    free(tuntap);
}
