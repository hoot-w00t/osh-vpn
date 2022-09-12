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

tuntap_t *tuntap_open(const char *devname, bool tap)
{
    tuntap_t *tuntap;
    struct ifreq ifr;
    int fd;

    if ((fd = open(tuntap_filepath, O_RDWR)) < 0) {
        logger(LOG_CRIT, "Failed to open " tuntap_filepath ": %s", strerror(errno));
        return NULL;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = tap ? (IFF_TAP | IFF_NO_PI)
                        : (IFF_TUN | IFF_NO_PI);
    if (devname) {
        size_t devname_len = strlen(devname);

        if (devname_len < IFNAMSIZ) {
            memcpy(ifr.ifr_name, devname, devname_len);
        } else {
            memcpy(ifr.ifr_name, devname, IFNAMSIZ);
        }
    }

    if (ioctl(fd, TUNSETIFF, (void *) &ifr) < 0) {
        logger(LOG_CRIT, "ioctl(%i, TUNSETIFF): %s: %s", fd, devname, strerror(errno));
        close(fd);
        return NULL;
    }

    if (!tuntap_nonblock(fd)) {
        close(fd);
        return NULL;
    }

    tuntap = tuntap_empty(tap);
    tuntap->dev_name_size = IFNAMSIZ + 1;
    tuntap->dev_name = xzalloc(tuntap->dev_name_size);
    strcpy(tuntap->dev_name, ifr.ifr_name);
    tuntap->data.fd = fd;

    logger(LOG_INFO, "Opened %s device: %s (fd: %i)",
        tuntap->is_tap ? "TAP" : "TUN",
        tuntap->dev_name,
        tuntap->data.fd);
    return tuntap;
}

void tuntap_close(tuntap_t *tuntap)
{
    close(tuntap->data.fd);
    tuntap_free_common(tuntap);
    free(tuntap);
}

bool tuntap_read(tuntap_t *tuntap, void *buf, size_t buf_size, size_t *pkt_size)
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

bool tuntap_write(tuntap_t *tuntap, const void *packet, size_t packet_size)
{
    ssize_t n = write(tuntap->data.fd, packet, packet_size);

    if (n < 0) {
        logger(LOG_CRIT, "%s: write: %s", tuntap->dev_name, strerror(errno));
        return false;
    }
    return true;
}

int tuntap_pollfd(tuntap_t *tuntap)
{
    return tuntap->data.fd;
}
