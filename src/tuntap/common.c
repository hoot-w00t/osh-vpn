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
tuntap_t *tuntap_empty(
    bool is_tap,
    tuntap_func_close_t func_close,
    tuntap_func_read_t func_read,
    tuntap_func_write_t func_write,
    tuntap_func_init_aio_event_t func_init_aio_event)
{
    tuntap_t *tuntap = xzalloc(sizeof(tuntap_t));

    tuntap->is_tap = is_tap;

    tuntap->close = func_close;
    tuntap->read = func_read;
    tuntap->write = func_write;
    tuntap->init_aio_event = func_init_aio_event;
    return tuntap;
}

// Set TUN/TAP device name
void tuntap_set_devname(tuntap_t *tuntap, const char *devname,
    const size_t devname_len)
{
    free(tuntap->dev_name);

    tuntap->dev_name = xzalloc(devname_len + 1);
    memcpy(tuntap->dev_name, devname, devname_len);
}

// Set TUN/TAP device ID
void tuntap_set_devid(tuntap_t *tuntap, const char *devid,
    const size_t devid_len)
{
    free(tuntap->dev_id);

    tuntap->dev_id = xzalloc(devid_len + 1);
    memcpy(tuntap->dev_id, devid, devid_len);
}

void tuntap_close(tuntap_t *tuntap)
{
    // Close and free the driver
    tuntap->close(tuntap);

    // Free common resources and the tuntap_t pointer
    free(tuntap->dev_name);
    free(tuntap->dev_id);
    free(tuntap);
}
