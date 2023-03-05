#include "macros.h"
#include "logger.h"
#include "xalloc.h"
#include "tuntap.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define ETH_DEST_OFFSET         (0)
#define ETH_SRC_OFFSET          (6)
#define ETH_HDR_SIZE            (14)

#define IP4_DEST_OFFSET         (16)
#define IP4_SRC_OFFSET          (12)
#define IP4_HDR_SIZE            (20)

#define IP6_DEST_OFFSET         (24)
#define IP6_SRC_OFFSET          (8)
#define IP6_HDR_SIZE            (40)

#define IP_HDR_VERSION(ip_pkt)  ((((const uint8_t *) ip_pkt)[0] & 0xF0) >> 4)

// Parse TAP packet header to *hdr
static bool tap_to_packethdr(tuntap_packethdr_t *hdr, const void *packet, size_t packet_size)
{
    if (packet_size < ETH_HDR_SIZE)
        return false;

    return netaddr_dton(&hdr->dest, MAC, ((const uint8_t *) packet) + ETH_DEST_OFFSET)
        && netaddr_dton(&hdr->src,  MAC, ((const uint8_t *) packet) + ETH_SRC_OFFSET);
}

// Parse TUN packet header to *hdr
static bool tun_to_packethdr(tuntap_packethdr_t *hdr, const void *packet, size_t packet_size)
{
    if (packet_size == 0)
        return false;

    switch (IP_HDR_VERSION(packet)) {
        case 4: // IPv4 packet
            if (packet_size < IP4_HDR_SIZE)
                return false;

            return netaddr_dton(&hdr->src,  IP4, ((const uint8_t *) packet) + IP4_SRC_OFFSET)
                && netaddr_dton(&hdr->dest, IP4, ((const uint8_t *) packet) + IP4_DEST_OFFSET);

        case 6: // IPv6 packet
            if (packet_size < IP6_HDR_SIZE)
                return false;

            return netaddr_dton(&hdr->src,  IP6, ((const uint8_t *) packet) + IP6_SRC_OFFSET)
                && netaddr_dton(&hdr->dest, IP6, ((const uint8_t *) packet) + IP6_DEST_OFFSET);

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

// Allocate an empty tuntap_t
// Initializes the driver information from *drv (all of the function pointers
// must be valid)
// is_tap is the requested/emulated layer used by tuntap_read()/tuntap_write()
tuntap_t *tuntap_empty(const struct tuntap_drv *drv, const bool is_tap)
{
    tuntap_t *tuntap = xzalloc(sizeof(tuntap_t));

    tuntap->drv = *drv;
    tuntap->is_tap = is_tap;

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

    tuntap->parse_packethdr = tuntap->is_tap
                            ? tap_to_packethdr
                            : tun_to_packethdr;

    if (tuntap->drv.is_tap == tuntap->is_tap) {
        logger(LOG_INFO, "Opened %s device: %s",
            TUNTAP_IS_TAP_STR(tuntap->drv.is_tap),
            tuntap->dev_name);
    } else {
        logger(LOG_ERR, "Opened %s device: %s (but expected %s)",
            TUNTAP_IS_TAP_STR(tuntap->drv.is_tap),
            tuntap->dev_name,
            TUNTAP_IS_TAP_STR(tuntap->is_tap));
        tuntap_close_at(&tuntap);
    }

    return tuntap;
}

void tuntap_close(tuntap_t *tuntap)
{
    logger(LOG_INFO, "Closing %s device: %s",
        TUNTAP_IS_TAP_STR(tuntap->drv.is_tap),
        tuntap->dev_name);

    // Close and free the driver
    tuntap->drv.close(tuntap);

    // Free common resources and the tuntap_t pointer
    free(tuntap->dev_name);
    free(tuntap->dev_id);
    free(tuntap);
}
