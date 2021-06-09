#include "random.h"
#include "logger.h"
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

// Read buf_size random bytes starting at buf
bool read_random_bytes(uint8_t *buf, size_t buf_size)
{
    int fd = open("/dev/random", O_RDONLY);
    size_t total = 0;
    ssize_t rbytes;

    if (fd < 0) {
        logger(LOG_ERR, "read_random_bytes: open: %s", strerror(errno));
        return false;
    }
    while (total < buf_size) {
        if ((rbytes = read(fd, buf + total, buf_size - total)) <= 0) {
            logger(LOG_ERR, "read_random_bytes: read: %s", strerror(errno));
            break;
        }
        total += rbytes;
    }
    close(fd);
    return total == buf_size;
}