#include "sock.h"
#include "logger.h"
#include <fcntl.h>

int sock_init(void)
{
    return 0;
}

int sock_deinit(void)
{
    return 0;
}

int sock_set_nonblocking(sock_t s)
{
    int flags;

    if ((flags = fcntl(s, F_GETFL, 0)) < 0)
        return flags;
    return fcntl(s, F_SETFL, flags | O_NONBLOCK);
}
