#ifndef _OSH_OSHD_PROCESS_PACKET_H
#define _OSH_OSHD_PROCESS_PACKET_H

#include "client.h"

bool oshd_process_packet(client_t *c, void *packet,
    const cipher_seqno_t packet_seqno);

#endif
