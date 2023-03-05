#include "macros.h"
#include "logger.h"
#include "xalloc.h"
#include "tuntap.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>

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
