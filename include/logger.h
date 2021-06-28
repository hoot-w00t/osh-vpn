#ifndef _OSH_LOGGER_H
#define _OSH_LOGGER_H

#include <stdarg.h>
#include <stdbool.h>

typedef enum loglevel {
    LOG_CRIT = 0,
    LOG_ERR,
    LOG_WARN,
    LOG_INFO
} loglevel_t;
#define loglevel_size (4)

typedef enum debug_what {
    DBG_OSHD = 0,
    DBG_TUNTAP,
    DBG_ROUTING,
    DBG_NETBUFFER,
    DBG_NODETREE,
    DBG_CMD,
    DBG_CONF,
    DBG_SOCKETS,
    DBG_EVENTS,
    DBG_AUTHENTICATION,
    DBG_ENCRYPTION,
    DBG_HANDSHAKE,
    DBG_STATEEXG,
    DBG_RESOLVER
} debug_what_t;
#define debug_what_size (14)

void logger_set_level(loglevel_t level);
bool logger_set_level_name(const char *name);
loglevel_t logger_get_level(void);
const char *logger_get_level_name(loglevel_t level);

void logger_toggle_debug(debug_what_t what);
bool logger_toggle_debug_name(const char *name);
const char *logger_get_debug_name(debug_what_t what);
bool logger_is_debugged(debug_what_t what);

#define _logger_attr __attribute__((format(printf, 2, 3)))
#define _logger_debug_attr __attribute__((format(printf, 2, 3)))

_logger_attr
void logger(loglevel_t level, const char *format, ...);

_logger_debug_attr
void logger_debug(debug_what_t what, const char *format, ...);

#endif