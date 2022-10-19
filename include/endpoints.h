#ifndef _OSH_ENDPOINTS_H
#define _OSH_ENDPOINTS_H

#include "netarea.h"
#include "oshd_clock.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Endpoints expire after 60 minutes
#define ENDPOINT_EXPIRY (3600)

typedef enum endpoint_type endpoint_type_t;
typedef enum endpoint_socktype endpoint_socktype_t;
typedef struct endpoint endpoint_t;
typedef struct endpoint_group endpoint_group_t;

// Type of the endpoint's value
enum endpoint_type {
    ENDPOINT_TYPE_HOSTNAME = 0,
    ENDPOINT_TYPE_IP4,
    ENDPOINT_TYPE_IP6,
    _endpoint_type_last
};
#define ENDPOINT_TYPE_UNKNOWN ENDPOINT_TYPE_HOSTNAME

// Socket types with which the endpoint is compatible
enum endpoint_socktype {
    ENDPOINT_SOCKTYPE_NONE  = 0,
    ENDPOINT_SOCKTYPE_TCP   = (1 << 0),
    _endpoint_socktype_last
};

struct endpoint {
    char *value;
    uint16_t port;

    netarea_t area;
    endpoint_type_t type;
    endpoint_socktype_t socktype;

    bool can_expire;
    struct timespec last_refresh;

    int priority;

    endpoint_t *next;
};

struct endpoint_group {
    endpoint_t *head;
    size_t count;
    endpoint_t *selected;

    // true if we should never give up trying to connect to those endpoints
    bool always_retry;

    // true while Osh is trying to connect to any endpoint in this group
    bool is_connecting;

    // Name of the node which owns this group
    char *owner_name;

    // Debug ID used to better identify the group in log messages
    char *debug_id;
};

endpoint_group_t *endpoint_group_create(const char *owner_name, const char *debug_id);
void endpoint_group_free(endpoint_group_t *group);
void endpoint_group_clear(endpoint_group_t *group);

endpoint_t *endpoint_group_find(endpoint_group_t *group, const char *value,
    const uint16_t port);
endpoint_t *endpoint_group_find_after(endpoint_t *after,
    const char *value, const uint16_t port);
endpoint_t *endpoint_group_find_duplicate(endpoint_group_t *group,
    const char *value, const uint16_t port, const endpoint_socktype_t socktype, const bool can_expire);

endpoint_t *endpoint_group_insert_back(endpoint_group_t *group,
    const char *value, const uint16_t port, const endpoint_socktype_t socktype, const bool can_expire);
endpoint_t *endpoint_group_insert_after(endpoint_t *after, endpoint_group_t *group,
    const char *value, const uint16_t port, const endpoint_socktype_t socktype, const bool can_expire);
endpoint_t *endpoint_group_insert_sorted(endpoint_group_t *group,
    const char *value, const uint16_t port, const endpoint_socktype_t socktype, const bool can_expire);
void endpoint_group_insert_sorted_ep(endpoint_group_t *group,
    const endpoint_t *endpoint);
void endpoint_group_insert_group(endpoint_group_t *dest,
    const endpoint_group_t *src);

void endpoint_group_del(endpoint_group_t *group, endpoint_t *endpoint);
bool endpoint_group_del_expired(endpoint_group_t *group);

endpoint_t *endpoint_group_selected(endpoint_group_t *group);
endpoint_t *endpoint_group_select_next(endpoint_group_t *group);
endpoint_t *endpoint_group_select_first(endpoint_group_t *group);
#define endpoint_group_is_empty(group) ((group)->head == NULL)

#define endpoint_group_is_connecting(group) ((group)->is_connecting)
void endpoint_group_set_is_connecting(endpoint_group_t *group, bool is_connecting);

#define foreach_endpoint(endpoint, group) \
    for (endpoint_t *endpoint = (group)->head; endpoint; endpoint = endpoint->next)

#define foreach_endpoint_const(endpoint, group) \
    for (const endpoint_t *endpoint = (group)->head; endpoint; endpoint = endpoint->next)

#endif
