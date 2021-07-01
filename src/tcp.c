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

// Create a TCP socket to connect to a remote server without trying to connect
// Returns the socket file descriptor or -1 on error
int tcp_outgoing_socket(const char *hostname, const uint16_t port,
    char *d_addr, size_t d_addr_len,
    struct sockaddr *d_sin, socklen_t d_sin_len)
{
    struct addrinfo *addrinfo = NULL;
    struct sockaddr *sin;
    socklen_t sin_len;
    char address[INET6_ADDRSTRLEN];
    int err, s;

    if ((err = getaddrinfo(hostname, NULL, NULL, &addrinfo))) {
        logger(LOG_ERR, "%s: %s", hostname, gai_strerror(err));
        return -1;
    }
    sin = addrinfo->ai_addr;
    memset(address, 0, sizeof(address));

    if (addrinfo->ai_family == AF_INET6) {
        struct sockaddr_in6 *conn = (struct sockaddr_in6 *) sin;

        inet_ntop(AF_INET6, &conn->sin6_addr, address, sizeof(address));
        conn->sin6_port = htons(port);
        sin_len = sizeof(struct sockaddr_in6);
    } else {
        struct sockaddr_in *conn = (struct sockaddr_in *) sin;

        inet_ntop(AF_INET, &conn->sin_addr, address, sizeof(address));
        conn->sin_port = htons(port);
        sin_len = sizeof(struct sockaddr_in);
    }

    if ((s = socket(addrinfo->ai_family, SOCK_STREAM, 0)) < 0) {
        logger(LOG_ERR, "socket: %s", strerror(errno));
        freeaddrinfo(addrinfo);
        return -1;
    }

    strncpy(d_addr, address, d_addr_len - 1);
    memcpy(d_sin, sin, (sin_len < d_sin_len) ? sin_len : d_sin_len);
    freeaddrinfo(addrinfo);
    return s;
}

// Create a TCP connection to a remote server
// Returns the socket file descriptor or -1 on error
int tcp_connect(const char *hostname, const uint16_t port,
    char *d_addr, size_t d_addr_len)
{
    struct addrinfo *addrinfo = NULL;
    struct sockaddr *sin;
    char address[INET6_ADDRSTRLEN];
    int err, s;

    if ((err = getaddrinfo(hostname, NULL, NULL, &addrinfo))) {
        logger(LOG_ERR, "%s: %s", hostname, gai_strerror(err));
        return -1;
    }
    sin = addrinfo->ai_addr;
    memset(address, 0, sizeof(address));

    if (addrinfo->ai_family == AF_INET6) {
        struct sockaddr_in6 *conn = (struct sockaddr_in6 *) sin;

        inet_ntop(AF_INET6, &conn->sin6_addr, address, sizeof(address));
        conn->sin6_port = htons(port);
    } else {
        struct sockaddr_in *conn = (struct sockaddr_in *) sin;

        inet_ntop(AF_INET, &conn->sin_addr, address, sizeof(address));
        conn->sin_port = htons(port);
    }

    if ((s = socket(addrinfo->ai_family, SOCK_STREAM, 0)) < 0) {
        logger(LOG_ERR, "socket: %s", strerror(errno));
        freeaddrinfo(addrinfo);
        return -1;
    }

    logger(LOG_INFO, "Trying to connect to %s:%u...", address, port);
    if (connect(s, sin, sizeof(struct sockaddr_in6)) < 0) {
        logger(LOG_ERR, "connect: %s:%u: %s", address, port, strerror(errno));
        close(s);
        freeaddrinfo(addrinfo);
        return -1;
    }
    strncpy(d_addr, address, d_addr_len - 1);
    logger(LOG_INFO, "Established connection with %s:%u", address, port);

    freeaddrinfo(addrinfo);
    return s;
}