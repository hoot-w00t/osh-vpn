#include "logger.h"
#include <stdio.h>

static loglevel_t logging_level = LOG_WARN;

void logger_set_level(loglevel_t level)
{
    logging_level = level;
}

loglevel_t logger_get_level(void)
{
    return logging_level;
}

void logger_inc_level(void)
{
    logging_level += 1;
}

void logger_dec_level(void)
{
    if (logging_level > 0)
        logging_level -= 1;
}

static const char *level_name(loglevel_t level)
{
    switch (level) {
        case LOG_CRIT: return "Critical";
        case LOG_ERR : return "Error";
        case LOG_WARN: return "Warning";
        case LOG_INFO: return "Info";
        default      : return "Debug";
    }
}

void logger(loglevel_t level, const char *format, ...)
{
    va_list ap;
    static char buf[256];

    if (level <= logging_level) {
        va_start(ap, format);
        vsnprintf(buf, sizeof(buf), format, ap);
        va_end(ap);
        printf("%s: %s\n", level_name(level), buf);
    }
}