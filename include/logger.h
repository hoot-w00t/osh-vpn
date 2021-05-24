#ifndef _OSH_LOGGER_H
#define _OSH_LOGGER_H

#include <stdarg.h>

typedef enum loglevel {
    LOG_CRIT = 0,
    LOG_ERR,
    LOG_WARN,
    LOG_INFO,
    LOG_DEBUG
} loglevel_t;

void logger_set_level(loglevel_t level);
loglevel_t logger_get_level(void);
void logger_inc_level(void);
void logger_dec_level(void);
void logger(loglevel_t level, const char *format, ...);

#endif