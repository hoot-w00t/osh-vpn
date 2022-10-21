#ifndef _OSH_TCP_H
#define _OSH_TCP_H

#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>

int tcp4_bind(const char *addr,
              const uint16_t port,
              const int backlog);
int tcp6_bind(const char *addr,
              const uint16_t port,
              const int backlog);

int tcp_outgoing_socket(const struct sockaddr *sa, const socklen_t sa_len);

#endif
