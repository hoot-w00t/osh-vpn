#include "device_mode.h"

// Return the name of the device mode
const char *device_mode_name(device_mode_t devmode)
{
    switch (devmode) {
        case MODE_NODEVICE: return "NoDevice";
        case MODE_TAP     : return "TAP";
        case MODE_TUN     : return "TUN";
        case MODE_DYNAMIC : return "Dynamic";
             default      : return device_mode_name_unknown;
    }
}

// Returns true if the device mode is a TAP device
bool device_mode_is_tap(device_mode_t devmode)
{
    switch (devmode) {
        case MODE_TAP:
            return true;

        default:
            return false;
    }
}