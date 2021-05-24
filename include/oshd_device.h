#ifndef _OSH_OSHD_DEVICE_H
#define _OSH_OSHD_DEVICE_H

#include "node.h"

void oshd_read_tuntap_pkt(void);
bool oshd_write_tuntap_pkt(uint8_t *data, uint16_t data_len);

#endif