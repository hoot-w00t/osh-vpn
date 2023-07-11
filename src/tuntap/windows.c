#include "tuntap.h"

tuntap_t *tuntap_open_tap_windows(const char *devname, bool tap);
tuntap_t *tuntap_open_wintun(const char *devname, bool tap);

#define try_open_device(name) if (!tuntap) tuntap = tuntap_open_ ## name (devname, tap)

tuntap_t *_tuntap_open(const char *devname, bool tap)
{
    tuntap_t *tuntap = NULL;

    // If device works in layer 2 prefer tap-windows, otherwise prefer Wintun
    if (tap) {
        try_open_device(tap_windows);
        try_open_device(wintun);
    } else {
        try_open_device(wintun);
        try_open_device(tap_windows);
    }

    return tuntap;
}
