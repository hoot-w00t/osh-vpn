#ifndef _OSH_LOGGER_H
#define _OSH_LOGGER_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum loglevel {
    LOG_CRIT = 0,
    LOG_ERR,
    LOG_WARN,
    LOG_INFO,
    _last_loglevel_entry // must always be the last entry
} loglevel_t;
#define loglevel_size (_last_loglevel_entry)

typedef enum debug_what {
    DBG_OSHD = 0,
    DBG_TUNTAP,
    DBG_TUNTAP_TRAFFIC,
    DBG_TUNTAP_EMU,
    DBG_ROUTING,
    DBG_NETBUFFER,
    DBG_NODETREE,
    DBG_CMD,
    DBG_CONF,
    DBG_SIGNALS,
    DBG_SOCKETS,
    DBG_EVENTS,
    DBG_ENCRYPTION,
    DBG_HANDSHAKE,
    DBG_STATEEXG,
    DBG_ENDPOINTS,
    DBG_NETROUTE,
    _last_debug_what_entry // must always be the last entry
} debug_what_t;
#define debug_what_size (_last_debug_what_entry)

void logger_set_level(loglevel_t level);
bool logger_set_level_name(const char *name);
loglevel_t logger_get_level(void);
const char *logger_get_level_name(loglevel_t level);
#define logger_is_level_enabled(msg_level, logger_level) ((msg_level) <= (logger_level))

void logger_toggle_debug(debug_what_t what);
bool logger_toggle_debug_name(const char *name);
const char *logger_get_debug_name(debug_what_t what);
bool logger_is_debugged(debug_what_t what);

size_t logger_write_msg(const char *msg, bool is_error);
size_t logger_write_uint(uintmax_t value, bool is_error);

#ifdef __USE_MINGW_ANSI_STDIO
#define _logger_fmt gnu_printf
#else
#define _logger_fmt printf
#endif

#define _logger_attr __attribute__((format(_logger_fmt, 2, 3)))
#define _logger_debug_attr __attribute__((format(_logger_fmt, 2, 3)))

_logger_attr
void logger(loglevel_t level, const char *format, ...);

_logger_debug_attr
void logger_debug(debug_what_t what, const char *format, ...);

#endif
