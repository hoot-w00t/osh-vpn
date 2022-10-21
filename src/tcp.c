#include "logger.h"
#include "xalloc.h"
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

// Create listening TCP4 socket bound to an *addr and port
// If *addr is NULL bind to all interfaces
// Returns the socket file descriptor or -1 on error
int tcp4_bind(const char *addr,
              const uint16_t port,
              const int backlog)
{
    const char *addr2 = addr ? addr : "0.0.0.0";
    struct sockaddr_in sin;
    int s;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    if (addr) {
        if (inet_pton(AF_INET, addr, &sin.sin_addr) != 1) {
            logger(LOG_ERR, "tcp4_bind: %s: %s", addr, strerror(errno));
            return -1;
        }
    } else {
        sin.sin_addr.s_addr = INADDR_ANY;
    }

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        logger(LOG_ERR, "socket: %s", strerror(errno));
        return -1;
    }
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &(int) {1}, sizeof(int));

    if (bind(s, (struct sockaddr *) &sin, sizeof(sin)) != 0) {
        logger(LOG_ERR, "bind: %s:%u: %s", addr2, port, strerror(errno));
        close(s);
        return -1;
    }
    if (listen(s, backlog) != 0) {
        logger(LOG_ERR, "listen: %s:%u: %s", addr2, port, strerror(errno));
        close(s);
        return -1;
    }

    logger(LOG_INFO, "Listening on %s:%u (tcp4)", addr2, port);
    return s;
}

// Create listening TCP6 socket bound to an *addr and port
// If *addr is NULL bind to all interfaces
// Returns the socket file descriptor or -1 on error
int tcp6_bind(const char *addr,
              const uint16_t port,
              const int backlog)
{
    const char *addr2 = addr ? addr : "::";
    struct sockaddr_in6 sin;
    int s;

    memset(&sin, 0, sizeof(sin));
    sin.sin6_family = AF_INET6;
    sin.sin6_port = htons(port);
    if (addr) {
        if (inet_pton(AF_INET6, addr, &sin.sin6_addr) != 1) {
            logger(LOG_ERR, "tcp6_bind: %s: %s", addr, strerror(errno));
            return -1;
        }
    } else {
        sin.sin6_addr = in6addr_any;
    }

    s = socket(AF_INET6, SOCK_STREAM, 0);
    if (s < 0) {
        logger(LOG_ERR, "socket: %s", strerror(errno));
        return -1;
    }
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &(int) {1}, sizeof(int));

    // Disable dual IPv6/4 socket
    setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &(int) {1}, sizeof(int));

    if (bind(s, (struct sockaddr *) &sin, sizeof(sin)) != 0) {
        logger(LOG_ERR, "bind: %s:%u: %s", addr2, port, strerror(errno));
        close(s);
        return -1;
    }
    if (listen(s, backlog) != 0) {
        logger(LOG_ERR, "listen: %s:%u: %s", addr2, port, strerror(errno));
        close(s);
        return -1;
    }

    logger(LOG_INFO, "Listening on %s:%u (tcp6)", addr2, port);
    return s;
}

// Create a TCP socket to connect to a remote server using *sa
// Returns the socket file descriptor or -1 on error
int tcp_outgoing_socket(const struct sockaddr *sa, const socklen_t sa_len)
{
    int s;

    if (sa_len < sizeof(*sa)) {
        logger(LOG_ERR, "%s: %s", __func__, "sa_len is too small");
        return -1;
    }

    if ((s = socket(sa->sa_family, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        logger(LOG_ERR, "%s: %s: %s", __func__, "socket", strerror(errno));
        return -1;
    }

    return s;
}
