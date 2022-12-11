#ifndef _OSH_TCP_H
#define _OSH_TCP_H

#include "endpoints.h"
#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>

int tcp_bind(const endpoint_t *endpoint, const int backlog);

int tcp_outgoing_socket(const struct sockaddr *sa, const socklen_t sa_len);

#endif
