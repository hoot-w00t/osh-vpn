#ifndef _OSH_TCP_H
#define _OSH_TCP_H

#include "sock.h"
#include "endpoints.h"
#include <stddef.h>
#include <stdint.h>

sock_t tcp_bind(const endpoint_t *endpoint, const int backlog);

sock_t tcp_outgoing_socket(const struct sockaddr *sa, const socklen_t sa_len);

#endif
