#include "tuntap.h"
#include "logger.h"

// Dummy TUN/TAP device that doesn't do anything

static bool _tuntap_read(
    __attribute__((unused)) tuntap_t *tuntap,
    __attribute__((unused)) void *buf,
    __attribute__((unused)) size_t buf_size,
    size_t *pkt_size)
{
    *pkt_size = 0;
    logger_debug(DBG_TUNTAP, "%s of %zu bytes", "Read", *pkt_size);
    return true;
}

static bool _tuntap_write(
    __attribute__((unused)) tuntap_t *tuntap,
    __attribute__((unused)) const void *packet,
    size_t packet_size)
{
    logger_debug(DBG_TUNTAP, "%s of %zu bytes", "Write", packet_size);
    return true;
}

static void _tuntap_init_aio_event(
    __attribute__((unused)) tuntap_t *tuntap,
    aio_event_t *event)
{
    event->enabled = false;
}

static void _tuntap_close(__attribute__((unused)) tuntap_t *tuntap)
{
}

tuntap_t *_tuntap_open(const char *devname, bool tap)
{
    const struct tuntap_drv tuntap_drv = {
        .is_tap = tap,
        .close = _tuntap_close,
        .read = _tuntap_read,
        .write = _tuntap_write,
        .init_aio_event = _tuntap_init_aio_event,
    };
    tuntap_t *tuntap;

    tuntap = tuntap_empty(&tuntap_drv, tap);
    if (devname) {
        tuntap_set_devname(tuntap, devname);
    } else {
        char name[32];

        tuntap_generate_devname(name, sizeof(name), "dummy");
        tuntap_set_devname(tuntap, name);
    }

    logger_debug(DBG_TUNTAP, "Created dummy %s device: %s",
        TUNTAP_IS_TAP_STR(tuntap_drv.is_tap), tuntap->dev_name);
    return tuntap;
}
