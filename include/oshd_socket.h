#ifndef _OSH_OSHD_SOCKET_H
#define _OSH_OSHD_SOCKET_H

#include "client.h"

bool oshd_client_connect(node_id_t *nid, endpoint_t *endpoint);
void oshd_server_add(int server_fd);

#endif
