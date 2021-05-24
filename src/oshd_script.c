#include "logger.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>

// Execute command and log any error
// Returns the same value as system(cmd)
int oshd_script(const char *cmd)
{
    int status;

    logger(LOG_INFO, "Executing: %s", cmd);
    status = system(cmd);
    if (status < 0) {
        logger(LOG_ERR, "system(): %s: %s", cmd, strerror(errno));
    } else if (status > 0) {
        logger(LOG_ERR, "%s: Exit code %i", cmd, status);
    }
    return status;
}