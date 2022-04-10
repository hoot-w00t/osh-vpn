#include "logger.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

static bool enabled_debug[debug_what_size] = {0};
static const char *debug_names[debug_what_size] = {
    "oshd",
    "tuntap",
    "routing",
    "netbuffer",
    "nodetree",
    "cmd",
    "conf",
    "sockets",
    "events",
    "authentication",
    "encryption",
    "handshake",
    "stateexg",
    "endpoints",
    "netroute"
};

static loglevel_t logger_level = LOG_INFO;
static const char *level_names[loglevel_size] = {
    "Critical",
    "Error",
    "Warning",
    "Info"
};

// Set logging level
void logger_set_level(loglevel_t level)
{
    logger_level = level;
}

// Set logging level by name
bool logger_set_level_name(const char *name)
{
    for (loglevel_t i = 0; i < loglevel_size; ++i) {
        if (!strcasecmp(name, level_names[i])) {
            logger_set_level(i);
            return true;
        }
    }
    return false;
}

// Returns the current logging level
loglevel_t logger_get_level(void)
{
    return logger_level;
}

// Returns the logging level name
const char *logger_get_level_name(loglevel_t level)
{
    return level_names[level];
}

// Toggle debugging for what
void logger_toggle_debug(debug_what_t what)
{
    if (what < debug_what_size)
        enabled_debug[what] = !enabled_debug[what];
}

// Toggle debugging for *name
// If *name is not valid, returns false
bool logger_toggle_debug_name(const char *name)
{
    for (debug_what_t i = 0; i < debug_what_size; ++i) {
        if (!strcasecmp(name, debug_names[i])) {
            logger_toggle_debug(i);
            return true;
        }
    }
    return false;
}

// Returns the name of what
const char *logger_get_debug_name(debug_what_t what)
{
    return debug_names[what];
}

// Returns true if what is being debugged
bool logger_is_debugged(debug_what_t what)
{
    return enabled_debug[what];
}

static void logger_print(const char *level, const char *format, va_list ap)
{
    const time_t curr_time = time(NULL);
    static char fmt_buf[256];
    static char time_buf[32];

    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S",
        localtime(&curr_time));
    vsnprintf(fmt_buf, sizeof(fmt_buf), format, ap);
    printf("%s: %s: %s\n", time_buf, level, fmt_buf);
    fflush(stdout);
}

// Log a message of level
_logger_attr
void logger(loglevel_t level, const char *format, ...)
{
    va_list ap;

    if (level <= logger_level) {
        va_start(ap, format);
        logger_print(level_names[level], format, ap);
        va_end(ap);
    }
}

// Log a message if what is being debugged
_logger_debug_attr
void logger_debug(debug_what_t what, const char *format, ...)
{
    va_list ap;
    char level[48];

    if (enabled_debug[what]) {
        va_start(ap, format);
        snprintf(level, sizeof(level), "Debug: %s", logger_get_debug_name(what));
        logger_print(level, format, ap);
        va_end(ap);
    }
}