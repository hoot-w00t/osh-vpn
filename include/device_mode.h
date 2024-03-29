#ifndef _OSH_DEVICE_MODE_H
#define _OSH_DEVICE_MODE_H

#include <stdbool.h>

typedef enum device_mode {
    MODE_NODEVICE = 0, // No TUN/TAP device will be opened and used
                       // This daemon will only relay network packets

    MODE_TAP,          // Open the device in TAP mode (Layer 2)
    MODE_TUN,          // Open the device in TUN mode (Layer 3)

    MODE_DYNAMIC,      // Open the device in TUN mode, handles IP attributions
                       // automatically

    _LAST_DEVICE_MODE_ENTRY // must always be the last entry
} device_mode_t;

#define device_mode_name_unknown "Unknown mode"

const char *device_mode_name(device_mode_t devmode);
bool device_mode_is_tap(device_mode_t devmode);

#endif