#include "logger.h"
#include "macros_assert.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>

static bool enabled_debug[debug_what_size] = {0};
static const char *debug_names[debug_what_size] = {
    "oshd",
    "tuntap",
    "tuntap_traffic",
    "tuntap_emu",
    "routing",
    "netbuffer",
    "nodetree",
    "cmd",
    "conf",
    "signals",
    "sockets",
    "events",
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

static pthread_mutex_t logger_mutex = PTHREAD_MUTEX_INITIALIZER;

// Lock logger mutex
static void logger_lock(void)
{
    assert(pthread_mutex_lock(&logger_mutex) == 0);
}

// Unlock logger mutex
static void logger_unlock(void)
{
    assert(pthread_mutex_unlock(&logger_mutex) == 0);
}

// Reverse string
static void logger_revstr(char *s)
{
    const size_t len = strlen(s);
    const size_t halflen = len / 2;
    char c;

    for (size_t i = 0; i < halflen; ++i) {
        c = s[i];
        s[i] = s[len - i - 1];
        s[len - i - 1] = c;
    }
}

// Convert unsigned integer value to string
// buf must not be NULL
// buflen must be > 0
// base must not be NULL
#define _uint_tostr(TYPE, NAME)                                                         \
static size_t NAME ## _tostr(char *buf, size_t buflen, TYPE value, const char *base)    \
{                                                                                       \
    const TYPE baselen = strlen(base);                                                  \
    size_t currlen = 0;                                                                 \
                                                                                        \
    do {                                                                                \
        if ((currlen + 1) >= buflen)                                                    \
            break;                                                                      \
                                                                                        \
        buf[currlen++] = base[value % baselen];                                         \
        value /= baselen;                                                               \
    } while (value > 0);                                                                \
                                                                                        \
    buf[currlen] = '\0';                                                                \
    logger_revstr(buf);                                                                 \
    return currlen;                                                                     \
}

_uint_tostr(uintmax_t, uintmax)

#define charset_base10 "0123456789"

// Set logging level
void logger_set_level(loglevel_t level)
{
    logger_lock();
    logger_level = level;
    logger_unlock();
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
    logger_lock();
    loglevel_t value = logger_level;
    logger_unlock();

    return value;
}

// Returns the logging level name
const char *logger_get_level_name(loglevel_t level)
{
    return level_names[level];
}

// Toggle debugging for what
void logger_toggle_debug(debug_what_t what)
{
    logger_lock();
    if (what < debug_what_size)
        enabled_debug[what] = !enabled_debug[what];
    logger_unlock();
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
    logger_lock();
    bool value = enabled_debug[what];
    logger_unlock();

    return value;
}

// Write message to stdout (or stderr if is_error is true)
// Returns the number of bytes written
// This function is async-signal-safe
//
// Note: The written message can overlap with other stdout/stderr outputs
size_t logger_write_msg(const char *msg, bool is_error)
{
    // Note: We can't lock here because it is not async-signal-safe

    ssize_t result = 0;

    if (msg != NULL)
        result = write(is_error ? 2 : 1, msg, strlen(msg));

    return (result < 0) ? 0 : (size_t) result;
}

// Write unsigned int using logger_write_msg()
// This function is async-signal-safe
size_t logger_write_uint(uintmax_t value, bool is_error)
{
    char buf[32];

    uintmax_tostr(buf, sizeof(buf), value, charset_base10);
    return logger_write_msg(buf, is_error);
}

static void logger_print(const char *level, const char *format, va_list ap)
{
    const time_t curr_time = time(NULL);
    char fmt_buf[256];
    char time_buf[32];

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

    logger_lock();
    if (logger_is_level_enabled(level, logger_level)) {
        va_start(ap, format);
        logger_print(level_names[level], format, ap);
        va_end(ap);
    }
    logger_unlock();
}

// Log a message if what is being debugged
_logger_debug_attr
void logger_debug(debug_what_t what, const char *format, ...)
{
    va_list ap;
    char level[48];

    logger_lock();
    if (enabled_debug[what]) {
        va_start(ap, format);
        snprintf(level, sizeof(level), "Debug: %s", logger_get_debug_name(what));
        logger_print(level, format, ap);
        va_end(ap);
    }
    logger_unlock();
}
