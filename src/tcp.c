#include "tcp.h"
#include "logger.h"
#include "xalloc.h"
#include <stdlib.h>

// Create listening TCP socket bound to the given endpoint
// Returns the socket file descriptor or -1 on error
sock_t tcp_bind(const endpoint_t *endpoint, const int backlog)
{
    struct sockaddr_storage sa;
    sock_t s;
    unsigned int opt;

    // Create TCP socket address
    if (!endpoint_to_sockaddr((struct sockaddr *) &sa, sizeof(sa), endpoint)) {
        logger(LOG_ERR, "%s: Failed to create sockaddr from %s",
            __func__, endpoint->addrstr);
        return invalid_sock_t;
    }

    // Create socket
    s = sock_open(sa.ss_family, SOCK_STREAM, IPPROTO_TCP);
    if (s == invalid_sock_t) {
        logger(LOG_ERR, "%s: %s: %s", __func__, "sock_open", sock_strerror(sock_errno));
        return invalid_sock_t;
    }

    opt = 1;
    sock_setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // Disable dual IPv6/4 socket
    if (sa.ss_family == AF_INET6) {
        opt = 1;
        sock_setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt));
    }

    // Bind the socket to its address and port
    if (sock_bind(s, (const struct sockaddr *) &sa, sizeof(sa)) != 0) {
        logger(LOG_ERR, "%s: %s: %s: %s", __func__, "sock_bind",
            endpoint->addrstr, sock_strerror(sock_errno));
        sock_close(s);
        return invalid_sock_t;
    }

    // Put the socket in listening mode
    if (sock_listen(s, backlog) != 0) {
        logger(LOG_ERR, "%s: %s: %s: %s", __func__, "sock_listen",
            endpoint->addrstr, sock_strerror(sock_errno));
        sock_close(s);
        return invalid_sock_t;
    }

    logger(LOG_INFO, "Listening on %s (tcp)", endpoint->addrstr);
    return s;
}

// Create a TCP socket to connect to a remote server using *sa
// Returns the socket file descriptor or -1 on error
sock_t tcp_outgoing_socket(const struct sockaddr *sa, const socklen_t sa_len)
{
    sock_t s;

    if (sa_len < (socklen_t) sizeof(*sa)) {
        logger(LOG_ERR, "%s: %s", __func__, "sa_len is too small");
        return invalid_sock_t;
    }

    if ((s = sock_open(sa->sa_family, SOCK_STREAM, IPPROTO_TCP)) == invalid_sock_t) {
        logger(LOG_ERR, "%s: %s: %s", __func__, "sock_open", sock_strerror(sock_errno));
        return invalid_sock_t;
    }

    return s;
}
