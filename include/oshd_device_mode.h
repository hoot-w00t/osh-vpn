#ifndef _OSH_OSHD_DEVICE_MODE
#define _OSH_OSHD_DEVICE_MODE

typedef enum device_mode {
    MODE_NODEVICE = 0, // No TUN/TAP device will be opened and used
                       // This daemon will only relay network packets

    MODE_TAP,          // Open the device in TAP mode (Layer 2)
    MODE_TUN           // Open the device in TUN mode (Layer 3)
} device_mode_t;

// Defined in oshd_device.c
const char *device_mode_name(device_mode_t devmode);
bool device_mode_is_tap(device_mode_t devmode);

#endif