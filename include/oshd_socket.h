#ifndef _OSH_OSHD_SOCKET_H
#define _OSH_OSHD_SOCKET_H

#include "node.h"

bool oshd_connect_queue(endpoint_group_t *endpoints, time_t delay);
void oshd_server_add(int server_fd);

#endif