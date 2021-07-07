#ifndef _OSH_OSHD_SOCKET_H
#define _OSH_OSHD_SOCKET_H

#include "node.h"

bool oshd_accept(void);
bool oshd_connect_queue(endpoint_group_t *endpoints, time_t delay);
bool oshd_connect_async(node_t *node);
bool node_send_queued(node_t *node);
bool node_recv_queued(node_t *node);

#endif