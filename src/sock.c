#include "sock.h"
#include "logger.h"
#include <fcntl.h>

int sock_init(void)
{
#if PLATFORM_IS_WINDOWS
    // Major version is low byte, minor version is high byte
    const unsigned int req_major = 2u;
    const unsigned int req_minor = 2u;
    const WORD req_version = MAKEWORD(req_major, req_minor);
    WSADATA d;
    int err;

    err = WSAStartup(req_version, &d);
    if (err != 0) {
        logger(LOG_CRIT, "%s: %s: %s", __func__, "WSAStartup", sock_strerror(err));
        return -1;
    }

    const unsigned int got_major = LOBYTE(d.wVersion);
    const unsigned int got_minor = HIBYTE(d.wVersion);

    if (req_major != got_major || req_minor != got_minor) {
        logger(LOG_ERR, "Requested Winsock v%u.%u but got v%u.%u",
            req_major, req_minor, got_major, got_minor);
        return -1;
    }

    logger_debug(DBG_SOCKETS, "Initialized Winsock v%u.%u", got_major, got_minor);
#endif

    return 0;
}

int sock_deinit(void)
{
#if PLATFORM_IS_WINDOWS
    if (WSACleanup() != 0) {
        logger(LOG_CRIT, "%s: %s: %s", __func__, "WSACleanup", sock_strerror(sock_errno));
        return -1;
    }
#endif

    return 0;
}

int sock_set_nonblocking(sock_t s)
{
#if PLATFORM_IS_WINDOWS
    u_long val = 1;

    if (ioctlsocket(s, FIONBIO, &val) != 0)
        return -1;
    return 0;
#else
    int flags;

    if ((flags = fcntl(s, F_GETFL, 0)) < 0)
        return flags;
    return fcntl(s, F_SETFL, flags | O_NONBLOCK);
#endif
}
