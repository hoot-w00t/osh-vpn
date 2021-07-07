#include "endpoints.h"
#include "xalloc.h"
#include <stdlib.h>
#include <string.h>

// Set endpoint's hostname, port and area
void endpoint_set(endpoint_t *endpoint, const char *hostname, uint16_t port,
    netarea_t area)
{
    endpoint->hostname = xstrdup(hostname);
    endpoint->port = port;
    endpoint->area = area;
}

// Free allocated resources in endpoint but not the endpoint pointer
void endpoint_free(endpoint_t *endpoint)
{
    if (endpoint)
        free(endpoint->hostname);
}

// Returns true if endpoint has the same hostname and port
bool endpoint_eq(const endpoint_t *endpoint, const char *hostname,
    uint16_t port)
{
    return    !strcmp(endpoint->hostname, hostname)
           && endpoint->port == port;
}


// Allocate an empty endpoint group
endpoint_group_t *endpoint_group_create(void *userdata)
{
    endpoint_group_t *group = xzalloc(sizeof(endpoint_group_t));

    group->userdata = userdata;
    return group;
}

// Allocate a copy of group
endpoint_group_t *endpoint_group_dup(const endpoint_group_t *group)
{
    endpoint_group_t *dup = endpoint_group_create(group->userdata);

    dup->endpoints_count = group->endpoints_count;
    dup->selected = group->selected;
    dup->endpoints = xreallocarray(dup->endpoints, dup->endpoints_count,
        sizeof(endpoint_t));

    for (size_t i = 0; i < dup->endpoints_count; ++i)
        endpoint_set_ep(&dup->endpoints[i], &group->endpoints[i]);
    return dup;
}

// Free endpoint group
void endpoint_group_free(endpoint_group_t *group)
{
    if (group)
        endpoint_group_clear(group);
    free(group);
}

// Search for an endpoint with hostname and port
// Returns a pointer to the endpoint if it found
// Returns NULL if it cannot be found
const endpoint_t *endpoint_group_find(const endpoint_group_t *group,
    const char *hostname, uint16_t port)
{
    for (size_t i = 0; i < group->endpoints_count; ++i) {
        if (endpoint_eq(&group->endpoints[i], hostname, port))
            return &group->endpoints[i];
    }
    return NULL;
}

// Bubble-sort group by netarea in the same order as the enum
static void endpoint_group_sort(endpoint_group_t *group)
{
    bool sorted = false;

    while (!sorted) {
        sorted = true;

        for (size_t i = 1; i < group->endpoints_count; ++i) {
            if (group->endpoints[i - 1].area > group->endpoints[i].area) {
                endpoint_t tmp;

                memcpy(&tmp, &group->endpoints[i - 1], sizeof(endpoint_t));
                memcpy(&group->endpoints[i - 1], &group->endpoints[i], sizeof(endpoint_t));
                memcpy(&group->endpoints[i], &tmp, sizeof(endpoint_t));

                sorted = false;
            }
        }
    }
}

// Add a new endpoint to the group
// If an endpoint with the same hostname and port is already in the group,
// nothing is changed
// Returns true if the endpoint was added, false otherwise
bool endpoint_group_add(endpoint_group_t *group, const char *hostname,
    uint16_t port, netarea_t area)
{
    if (endpoint_group_find(group, hostname, port))
        return false;

    group->endpoints = xreallocarray(group->endpoints,
        group->endpoints_count + 1, sizeof(endpoint_t));
    endpoint_set(&group->endpoints[group->endpoints_count], hostname, port, area);
    group->endpoints_count += 1;
    endpoint_group_sort(group);
    return true;
}

// Add all endpoints from src to dest (avoids duplicate endpoints)
// Returns the number of new endpoints added to dest
size_t endpoint_group_add_group(endpoint_group_t *dest,
    const endpoint_group_t *src)
{
    size_t added = 0;

    for (size_t i = 0; i < src->endpoints_count; ++i) {
        if (endpoint_group_add_ep(dest, &src->endpoints[i]))
            added += 1;
    }
    return added;
}

// Clear all endpoints from group
void endpoint_group_clear(endpoint_group_t *group)
{
    for (size_t i = 0; i < group->endpoints_count; ++i)
        endpoint_free(&group->endpoints[i]);
    free(group->endpoints);
    group->endpoints = NULL;
    group->endpoints_count = 0;
    group->selected = 0;
}