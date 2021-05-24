#ifndef _OSH_TUNTAP_H
#define _OSH_TUNTAP_H

#include <stdbool.h>

int tuntap_open(char *dev, const bool tap);

#endif