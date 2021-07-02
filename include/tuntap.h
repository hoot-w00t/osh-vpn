#ifndef _OSH_TUNTAP_H
#define _OSH_TUNTAP_H

#include <stdbool.h>

// Open TUN/TAP device with name *dev
// If tap is true the device will use layer 2 instead of layer 3 (TUN)
// Returns true on success, false on error
int tuntap_open(char *dev, const bool tap);

#endif