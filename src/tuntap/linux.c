#include "logger.h"
#include "xalloc.h"
#include "tuntap.h"
#include "macros.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>

// https://github.com/torvalds/linux/blob/master/Documentation/networking/tuntap.rst
// https://www.kernel.org/doc/html/latest/networking/tuntap.html

#define tuntap_filepath "/dev/net/tun"

static bool _tuntap_read(tuntap_t *tuntap, void *buf, size_t buf_size, size_t *pkt_size)
{
    ssize_t n = read(tuntap->data.fd, buf, buf_size);

    if (n < 0) {
        if (IO_WOULDBLOCK(errno)) {
            *pkt_size = 0;
            return true;
        }

        logger(LOG_CRIT, "%s: read: %s", tuntap->dev_name, strerror(errno));
        return false;
    }
    *pkt_size = (size_t) n;
    return true;
}

static bool _tuntap_write(tuntap_t *tuntap, const void *packet, size_t packet_size)
{
    ssize_t n = write(tuntap->data.fd, packet, packet_size);

    if (n < 0) {
        logger(LOG_CRIT, "%s: write: %s", tuntap->dev_name, strerror(errno));
        return false;
    }
    return true;
}

static void _tuntap_init_aio_event(tuntap_t *tuntap, aio_event_t *event)
{
    event->fd = tuntap->data.fd;
}

static void _tuntap_close(tuntap_t *tuntap)
{
    close(tuntap->data.fd);
}

tuntap_t *tuntap_open(const char *devname, bool tap)
{
    tuntap_t *tuntap;
    struct ifreq ifr;
    int fd;

    if ((fd = open(tuntap_filepath, O_RDWR)) < 0) {
        logger(LOG_CRIT, "Failed to open %s: %s", tuntap_filepath, strerror(errno));
        return NULL;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = tap ? (IFF_TAP | IFF_NO_PI)
                        : (IFF_TUN | IFF_NO_PI);

    if (devname)
        strncpy(ifr.ifr_name, devname, IFNAMSIZ - 1);

    if (ioctl(fd, TUNSETIFF, (void *) &ifr) < 0) {
        logger(LOG_CRIT, "ioctl(%d, %s): %s: %s", fd, "TUNSETIFF", devname, strerror(errno));
        close(fd);
        return NULL;
    }

    if (!tuntap_nonblock(fd)) {
        close(fd);
        return NULL;
    }

    tuntap = tuntap_empty(tap, _tuntap_close, _tuntap_read, _tuntap_write, _tuntap_init_aio_event);
    tuntap_set_devname(tuntap, ifr.ifr_name);

    tuntap->data.fd = fd;

    logger(LOG_INFO, "Opened %s device: %s (fd: %d)",
        tuntap->is_tap ? "TAP" : "TUN",
        tuntap->dev_name,
        tuntap->data.fd);

    return tuntap;
}
