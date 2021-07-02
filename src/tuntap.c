#include "logger.h"
#include <stdbool.h>
#include <string.h>
#include <errno.h>

#if defined(_WIN32) || defined(__CYGWIN__)
int tuntap_open(__attribute__((unused)) char *dev,
    __attribute__((unused)) const bool tap)
{
    logger(LOG_CRIT, "TUN/TAP device is not yet supported on Windows");
    return false;
}
#else
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>

// https://github.com/torvalds/linux/blob/master/Documentation/networking/tuntap.rst

int tuntap_open(char *dev, const bool tap)
{
    struct ifreq ifr;
    int fd;

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        logger(LOG_CRIT, "Unable to open /dev/net/tun: %s", strerror(errno));
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = tap ? IFF_TAP : IFF_TUN;
    if (dev) memcpy(ifr.ifr_name, dev, IFNAMSIZ);

    if (ioctl(fd, TUNSETIFF, (void *) &ifr) < 0) {
        logger(LOG_CRIT, "ioctl: configure device %s: %s", dev, strerror(errno));
        close(fd);
        return -1;
    }

    strcpy(dev, ifr.ifr_name);
    logger(LOG_INFO, "Opened %s device: %s (fd: %i)", tap ? "TAP" : "TUN", dev, fd);
    return fd;
}
#endif