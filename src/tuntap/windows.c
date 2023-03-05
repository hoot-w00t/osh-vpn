#include "tuntap.h"

// tap-windows.c
tuntap_t *tuntap_open_tap_windows(const char *devname, bool tap);

tuntap_t *_tuntap_open(const char *devname, bool tap)
{
    return tuntap_open_tap_windows(devname, tap);
}
