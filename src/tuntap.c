#include "logger.h"
#include "xalloc.h"
#include "tuntap.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

// Set O_NONBLOCK for fd
static bool tuntap_nonblock(int fd)
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

// Allocate a zeroed-out tuntap_t
// Set is_tap
static tuntap_t *tuntap_empty(bool is_tap)
{
    tuntap_t *tuntap = xzalloc(sizeof(tuntap_t));

    tuntap->is_tap = is_tap;
    return tuntap;
}

// Free common allocated resources in tuntap_t
static void tuntap_free_common(tuntap_t *tuntap)
{
    free(tuntap->dev_name);
    free(tuntap->dev_id);
}

#if defined(_WIN32) || defined(__CYGWIN__)
#define unused __attribute__((unused))

tuntap_t *tuntap_open(unused const char *devname, unused bool tap)
{
    logger(LOG_CRIT, "TUN/TAP device is not yet supported on Windows");
    return NULL;
}

void tuntap_close(unused tuntap_t *tuntap)
{
    tuntap_free_common(tuntap);
    free(tuntap);
}

bool tuntap_read(unused tuntap_t *tuntap, unused void *buf,
    unused size_t buf_size, unused size_t *pkt_size)
{
    logger(LOG_CRIT, "TUN/TAP device is not yet supported on Windows");
    return false;
}

bool tuntap_write(unused tuntap_t *tuntap, unused void *packet,
    unused size_t packet_size)
{
    logger(LOG_CRIT, "TUN/TAP device is not yet supported on Windows");
    return false;
}

int tuntap_pollfd(unused tuntap_t *tuntap)
{
    logger(LOG_CRIT, "TUN/TAP device is not yet supported on Windows");
    return -1;
}
#else
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>

#define tuntap_filepath "/dev/net/tun"

// https://github.com/torvalds/linux/blob/master/Documentation/networking/tuntap.rst

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
    ifr.ifr_flags = tap ? IFF_TAP : IFF_TUN;
    if (devname) strncpy(ifr.ifr_name, devname, IFNAMSIZ);

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
    tuntap->fd = fd;

    logger(LOG_INFO, "Opened %s device: %s (fd: %i)",
        tuntap->is_tap ? "TAP" : "TUN",
        tuntap->dev_name,
        tuntap->fd);
    return tuntap;
}

void tuntap_close(tuntap_t *tuntap)
{
    close(tuntap->fd);
    tuntap_free_common(tuntap);
    free(tuntap);
}

bool tuntap_read(tuntap_t *tuntap, void *buf, size_t buf_size, size_t *pkt_size)
{
    ssize_t n = read(tuntap->fd, buf, buf_size);

    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            *pkt_size = 0;
            return true;
        }

        logger(LOG_CRIT, "%s: read: %s", tuntap->dev_name, strerror(errno));
        return false;
    }
    *pkt_size = (size_t) n;
    return true;
}

bool tuntap_write(tuntap_t *tuntap, void *packet, size_t packet_size)
{
    ssize_t n = write(tuntap->fd, packet, packet_size);

    if (n < 0) {
        logger(LOG_CRIT, "%s: write: %s", tuntap->dev_name, strerror(errno));
        return false;
    }
    return true;
}

int tuntap_pollfd(tuntap_t *tuntap)
{
    return tuntap->fd;
}
#endif