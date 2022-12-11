#include "tcp.h"
#include "logger.h"
#include "xalloc.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

// Create listening TCP socket bound to the given endpoint
// Returns the socket file descriptor or -1 on error
int tcp_bind(const endpoint_t *endpoint, const int backlog)
{
    struct sockaddr_storage sa;
    int s;
    unsigned int opt;

    // Create TCP socket address
    if (!endpoint_to_sockaddr((struct sockaddr *) &sa, sizeof(sa), endpoint)) {
        logger(LOG_ERR, "%s: Failed to create sockaddr from %s",
            __func__, endpoint->addrstr);
        return -1;
    }

    // Create socket
    s = socket(sa.ss_family, SOCK_STREAM, IPPROTO_TCP);
    if (s < 0) {
        logger(LOG_ERR, "%s: %s: %s", __func__, "socket", strerror(errno));
        return -1;
    }

    opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // Disable dual IPv6/4 socket
    if (sa.ss_family == AF_INET6) {
        opt = 1;
        setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt));
    }

    // Bind the socket to its address and port
    if (bind(s, (const struct sockaddr *) &sa, sizeof(sa)) != 0) {
        logger(LOG_ERR, "%s: %s: %s: %s", __func__, "bind",
            endpoint->addrstr, strerror(errno));
        close(s);
        return -1;
    }

    // Put the socket in listening mode
    if (listen(s, backlog) != 0) {
        logger(LOG_ERR, "%s: %s: %s: %s", __func__, "listen",
            endpoint->addrstr, strerror(errno));
        close(s);
        return -1;
    }

    logger(LOG_INFO, "Listening on %s (tcp)", endpoint->addrstr);
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
