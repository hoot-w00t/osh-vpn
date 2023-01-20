#ifndef _OSH_SOCK_H
#define _OSH_SOCK_H

#include "macros.h"
#include "endianness.h"
#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>

#if PLATFORM_IS_WINDOWS
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #include "macros_windows.h"

    typedef SOCKET                  sock_t;
    #define PRI_SOCK_T              "%" PRIuPTR
    #define invalid_sock_t          (INVALID_SOCKET)

    typedef DWORD                   sock_errno_t;
    #define sock_errno              WSAGetLastError()
    #define sock_strerror(err)      win_strerror(err)

    #define sock_ewouldblock(err)   ((err) == WSAEWOULDBLOCK)
    #define sock_eisconn(err)       ((err) == WSAEISCONN)
    #define sock_einprogress(err)   ((err) == WSAEINPROGRESS || (err) == WSAEALREADY)

    #define sock_shut_rd            SD_RECEIVE
    #define sock_shut_wr            SD_SEND
    #define sock_shut_rdwr          SD_BOTH

    // There is no SIGPIPE on Windows
    #define MSG_NOSIGNAL 0

#else
    #include <netinet/in.h>
    #include <netinet/tcp.h>
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <unistd.h>
    #include <errno.h>
    #include <string.h>

    typedef int                     sock_t;
    #define PRI_SOCK_T              "%d"
    #define invalid_sock_t          (-1)

    typedef int                     sock_errno_t;
    #define sock_errno              errno
    #define sock_strerror(err)      strerror(err)

    #define sock_ewouldblock(err)   ((err) == EAGAIN || (err) == EWOULDBLOCK)
    #define sock_eisconn(err)       ((err) == EISCONN)
    #define sock_einprogress(err)   ((err) == EINPROGRESS || (err) == EALREADY)

    #define sock_shut_rd            SHUT_RD
    #define sock_shut_wr            SHUT_WR
    #define sock_shut_rdwr          SHUT_RDWR
#endif

// Initialize sockets (if the platform requires it)
// Returns 0 on success, -1 on error
int sock_init(void);

// De-initialize sockets (if the platform requires it)
// Returns 0 on success, -1 on error
int sock_deinit(void);

// Set socket to non-blocking
// Returns 0 on success, -1 on error
int sock_set_nonblocking(sock_t s);

// socket()
static inline sock_t sock_open(int domain, int type, int protocol)
{
    return socket(domain, type, protocol);
}

// close() / closesocket()
static inline int sock_close(sock_t s)
{
#if PLATFORM_IS_WINDOWS
    return closesocket(s);
#else
    return close(s);
#endif
}

// shutdown()
// how should be used with the SOCK_SHUT_* definitions
static inline int sock_shutdown(sock_t s, int how)
{
    return shutdown(s, how);
}

// getsockopt()
static inline int sock_getsockopt(sock_t s, int level, int optname,
    void *optval, socklen_t *optlen)
{
    return getsockopt(s, level, optname, optval, optlen);
}

// setsockopt()
static inline int sock_setsockopt(sock_t s, int level, int optname,
    const void *optval, socklen_t optlen)
{
    return setsockopt(s, level, optname, optval, optlen);
}

// bind()
static inline int sock_bind(sock_t s, const struct sockaddr *addr, socklen_t addrlen)
{
    return bind(s, addr, addrlen);
}

// listen()
static inline int sock_listen(sock_t s, int backlog)
{
    return listen(s, backlog);
}

// accept()
static inline sock_t sock_accept(sock_t s, struct sockaddr *addr, socklen_t *addrlen)
{
    return accept(s, addr, addrlen);
}

// connect()
static inline int sock_connect(sock_t s, const struct sockaddr *addr, socklen_t addrlen)
{
    return connect(s, addr, addrlen);
}

// send()
static inline ssize_t sock_send(sock_t s, const void *buf, size_t len, int flags)
{
    return send(s, buf, len, flags);
}

// recv()
static inline ssize_t sock_recv(sock_t s, void *buf, size_t len, int flags)
{
    return recv(s, buf, len, flags);
}

#endif
