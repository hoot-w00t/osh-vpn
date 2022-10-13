#ifndef _OSH_OSHD_SOCKET_H
#define _OSH_OSHD_SOCKET_H

#include "client.h"

bool oshd_connect_queue(node_id_t *nid);
void oshd_server_add(int server_fd);

#endif
