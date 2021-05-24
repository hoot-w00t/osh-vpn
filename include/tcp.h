#ifndef _OSH_TCP_H
#define _OSH_TCP_H

#include <stddef.h>
#include <stdint.h>

int tcp4_bind(const char *addr,
              const uint16_t port,
              const int backlog);
int tcp6_bind(const char *addr,
              const uint16_t port,
              const int backlog);
int tcp_outgoing_socket(const char *hostname, const uint16_t port,
    char *d_addr, size_t d_addr_len,
    struct sockaddr *d_sin, socklen_t d_sin_len);
int tcp_connect(const char *hostname, const uint16_t port,
    char *d_addr, size_t d_addr_len);

#endif