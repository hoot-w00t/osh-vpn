#ifndef _OSH_ENDPOINTS_H
#define _OSH_ENDPOINTS_H

#include "netarea.h"
#include "oshd_clock.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Endpoints expire after 60 minutes
#define ENDPOINT_EXPIRY (3600)

typedef struct endpoint endpoint_t;
typedef struct endpoint_group endpoint_group_t;

struct endpoint {
    char *hostname;
    uint16_t port;
    netarea_t area;

    bool can_expire;
    struct timespec last_refresh;

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
    // If NULL is passed as an owner name, has_owner is false and the owner name
    // is set to the group's pointer
    char *owner_name;
    bool has_owner;
};

endpoint_group_t *endpoint_group_create(const char *owner_name);
void endpoint_group_free(endpoint_group_t *group);
void endpoint_group_clear(endpoint_group_t *group);

endpoint_t *endpoint_group_find(endpoint_group_t *group, const char *hostname,
    uint16_t port);

endpoint_t *endpoint_group_add(endpoint_group_t *group, const char *hostname,
    uint16_t port, netarea_t area, bool can_expire);
void endpoint_group_add_ep(endpoint_group_t *group, const endpoint_t *endpoint);
void endpoint_group_add_group(endpoint_group_t *dest,
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

#endif