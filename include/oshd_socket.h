#ifndef _OSH_OSHD_SOCKET_H
#define _OSH_OSHD_SOCKET_H

#include "node.h"

bool oshd_accept(void);
bool oshd_connect_queue(const char *address, const uint16_t port, time_t delay);
bool oshd_connect_async(node_t *node);
bool oshd_connect(const char *address, const uint16_t port, time_t delay);
bool node_send_queued(node_t *node);
bool node_recv_queued(node_t *node);
bool oshd_process_packet(node_t *node);

#endif