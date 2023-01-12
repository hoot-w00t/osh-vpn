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

// Allocate a zeroed-out tuntap_t
// Initialize is_tap
tuntap_t *tuntap_empty(bool is_tap)
{
    tuntap_t *tuntap = xzalloc(sizeof(tuntap_t));

    tuntap->is_tap = is_tap;
    return tuntap;
}

// Set the TUN/TAP API function pointers
void tuntap_set_funcs(tuntap_t *tuntap,
    tuntap_func_close_t func_close,
    tuntap_func_read_t func_read,
    tuntap_func_write_t func_write,
    tuntap_func_init_aio_event_t func_init_aio_event)
{
    tuntap->close = func_close;
    tuntap->read = func_read;
    tuntap->write = func_write;
    tuntap->init_aio_event = func_init_aio_event;
}

// Free common allocated resources in tuntap_t
void tuntap_free_common(tuntap_t *tuntap)
{
    free(tuntap->dev_name);
    free(tuntap->dev_id);
}
