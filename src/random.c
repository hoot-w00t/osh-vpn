#include "random.h"
#include "logger.h"
#include "macros.h"
#include <string.h>
#include <errno.h>

#if PLATFORM_IS_LINUX
#include <sys/random.h>

bool random_bytes(void *buf, size_t buf_size)
{
    ssize_t r = getrandom(buf, buf_size, GRND_NONBLOCK);

    if (r < 0) {
        logger(LOG_ERR, "%s: %s: %s", __func__, "getrandom", strerror(errno));
        return false;
    }

    if ((unsigned) r != buf_size) {
        logger(LOG_ERR, "%s: %s: Written %zi/%zu bytes", __func__, "getrandom",
            r, buf_size);
        return false;
    }

    return true;
}
#else // /dev/random

#include <fcntl.h>
#include <unistd.h>
#define random_filepath "/dev/random"

// Write buf_size random bytes starting at buf
// This function can block
// Returns false on any error (including incomplete reads)
bool random_bytes(void *buf, size_t buf_size)
{
    int fd = open(random_filepath, O_RDONLY);
    size_t total = 0;
    ssize_t rbytes;

    if (fd < 0) {
        logger(LOG_ERR, "random_bytes: open: %s: %s",
            random_filepath, strerror(errno));
        return false;
    }

    while (total < buf_size) {
        if ((rbytes = read(fd, ((uint8_t *) buf) + total, buf_size - total)) <= 0) {
            if (errno == EINTR)
                continue;

            logger(LOG_ERR, "random_bytes: read: %s: %s (%zi, %zu/%zu bytes)",
                random_filepath, strerror(errno), rbytes, total, buf_size);
            break;
        }
        total += rbytes;
    }
    close(fd);
    return total == buf_size;
}
#endif
