#ifndef _OSH_ENDPOINTS_H
#define _OSH_ENDPOINTS_H

#include "netarea.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct endpoint {
    char *hostname;
    uint16_t port;
    netarea_t area;
} endpoint_t;

void endpoint_set(endpoint_t *endpoint, const char *hostname, uint16_t port,
    netarea_t area);
#define endpoint_set_ep(ep1, ep2) \
    endpoint_set(ep1, (ep2)->hostname, (ep2)->port, (ep2)->area)
void endpoint_free(endpoint_t *endpoint);
bool endpoint_eq(const endpoint_t *endpoint, const char *hostname,
    uint16_t port);
#define endpoint_eq_ep(ep1, ep2) \
    endpoint_eq(ep1, (ep2)->hostname, (ep2)->port)


typedef struct endpoint_group {
    endpoint_t *endpoints;
    size_t endpoints_count;
    size_t selected;
} endpoint_group_t;

endpoint_group_t *endpoint_group_create(void);
endpoint_group_t *endpoint_group_dup(const endpoint_group_t *group);
void endpoint_group_free(endpoint_group_t *group);

const endpoint_t *endpoint_group_find(const endpoint_group_t *group,
    const char *hostname, uint16_t port);
#define endpoint_group_find_ep(group, endpoint) \
    endpoint_group_find(group, (endpoint)->hostname, (endpoint)->port)

bool endpoint_group_add(endpoint_group_t *group, const char *hostname,
    uint16_t port, netarea_t area);
#define endpoint_group_add_ep(group, endpoint) \
    endpoint_group_add(group, (endpoint)->hostname, (endpoint)->port, (endpoint)->area)
size_t endpoint_group_add_group(endpoint_group_t *dest,
    const endpoint_group_t *src);

void endpoint_group_clear(endpoint_group_t *group);

// Returns the currently selected endpoint in the group
// Returns NULL if no endpoint is selected
static inline endpoint_t *endpoint_group_selected_ep(const endpoint_group_t *group)
{
    if (group->selected < group->endpoints_count)
        return &group->endpoints[group->selected];
    return NULL;
}

// Returns the number of endpoints left in the list (after the selected endpoint)
static inline size_t endpoint_group_remaining(const endpoint_group_t *group)
{
    if (group->selected >= group->endpoints_count)
        return 0;
    return group->endpoints_count - group->selected;
}

// Select the next endpoint in the group
// Returns the remaining number of endpoints in the group
static inline bool endpoint_group_select_next(endpoint_group_t *group)
{
    if (group->selected < group->endpoints_count)
        group->selected += 1;
    return endpoint_group_remaining(group);
}

// Select the first endpoint in the group
// Returns the number of endpoints in the group
static inline size_t endpoint_group_select_start(endpoint_group_t *group)
{
    group->selected = 0;
    return endpoint_group_remaining(group);
}

#endif