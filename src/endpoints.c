#include "endpoints.h"
#include "xalloc.h"
#include "logger.h"
#include "node.h"
#include "oshd.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Allocate a new endpoint
static endpoint_t *endpoint_create(const char *hostname, uint16_t port,
    netarea_t area, bool can_expire)
{
    endpoint_t *endpoint = xzalloc(sizeof(endpoint_t));

    endpoint->hostname = xstrdup(hostname);
    endpoint->port = port;
    endpoint->area = area;
    endpoint->can_expire = can_expire;
    return endpoint;
}

// Free endpoint and its allocated resources
static void endpoint_free(endpoint_t *endpoint)
{
    if (endpoint) {
        free(endpoint->hostname);
        free(endpoint);
    }
}

// Returns true if endpoint has the same hostname and port
static bool endpoint_eq(const endpoint_t *endpoint, const char *hostname,
    uint16_t port)
{
    return    !strcmp(endpoint->hostname, hostname)
           &&  endpoint->port == port;
}

// Create an empty endpoint group
endpoint_group_t *endpoint_group_create(const char *owner_name)
{
    endpoint_group_t *group = xzalloc(sizeof(endpoint_group_t));

    if (owner_name) {
        group->owner_name = xstrdup(owner_name);
        group->has_owner = true;
    } else {
        char owner_ptr[32];

        snprintf(owner_ptr, sizeof(owner_ptr), "%p", group);
        group->owner_name = xstrdup(owner_ptr);
        group->has_owner = false;
    }
    return group;
}

// Free endpoint group and its allocated resources
void endpoint_group_free(endpoint_group_t *group)
{
    if (!group)
        return;

    logger_debug(DBG_ENDPOINTS, "Freeing endpoint group %p (%s)",
        group, group->owner_name);
    endpoint_group_clear(group);
    free(group->owner_name);
    free(group);
}

// Delete all endpoints from group
void endpoint_group_clear(endpoint_group_t *group)
{
    endpoint_t *i = group->head;
    endpoint_t *next;

    while (i) {
        next = i->next;
        endpoint_free(i);
        i = next;
    }
    group->head = NULL;
    group->selected = NULL;
    group->count = 0;

    logger_debug(DBG_ENDPOINTS, "Cleared all endpoints from group %p (%s)",
        group, group->owner_name);
}

// Searches for an endpoint matching hostname and port
// Returns NULL if it cannot be found
endpoint_t *endpoint_group_find(endpoint_group_t *group, const char *hostname,
    uint16_t port)
{
    foreach_endpoint(endpoint, group) {
        if (endpoint_eq(endpoint, hostname, port))
            return endpoint;
    }
    return NULL;
}

// Refresh an endpoint
static void endpoint_refresh(const endpoint_group_t *group, endpoint_t *endpoint)
{
    // Update last_refresh timestamp
    oshd_gettime(&endpoint->last_refresh);
    logger_debug(DBG_ENDPOINTS, "Refreshed endpoint %s:%u from group %p (%s)",
        endpoint->hostname, endpoint->port, group, group->owner_name);
}

// Add an endpoint to the group
// If a matching endpoint is already in the group it will only be refreshed and
// nothing else will be changed
// Returns the endpoint pointer if it was added, returns NULL if it was already
// in the group
endpoint_t *endpoint_group_add(endpoint_group_t *group, const char *hostname,
    uint16_t port, netarea_t area, bool can_expire)
{
    endpoint_t *endpoint = endpoint_group_find(group, hostname, port);
    endpoint_t *added = NULL;

    if (!endpoint) {
        endpoint_t **i = &group->head;

        endpoint = endpoint_create(hostname, port, area, can_expire);
        added = endpoint;

        // Insert the new endpoint sorted by its area
        while (*i) {
            // Endpoints that don't expire always come first
            if (!endpoint->can_expire && (*i)->can_expire)
                break;

            // Otherwise sort them using the area in ascending order
            if ((*i)->area > endpoint->area)
                break;

            i = &(*i)->next;
        }
        endpoint->next = *i;
        *i = endpoint;
        group->count += 1;

        // Endpoints which can't expire are endpoints from the configuration
        // file, having those in the group means that we should never give up
        // trying to connect to a node
        if (!can_expire)
            group->always_retry = true;

        logger_debug(DBG_ENDPOINTS, "Added endpoint %s:%u to group %p (%s)",
            endpoint->hostname, endpoint->port, group, group->owner_name);

        // Automatically select the first item if a connection is not underway
        if (!endpoint_group_is_connecting(group))
            endpoint_group_select_first(group);
    }

    endpoint_refresh(group, endpoint);
    return added;
}

// Same as endpoint_group_add but gets the values from endpoint
void endpoint_group_add_ep(endpoint_group_t *group, const endpoint_t *endpoint)
{
    endpoint_group_add(group, endpoint->hostname, endpoint->port,
        endpoint->area, endpoint->can_expire);
}

// Add all endpoints from src to dest, does the same as endpoint_group_add
void endpoint_group_add_group(endpoint_group_t *dest,
    const endpoint_group_t *src)
{
    // Stop early if we try to merge the same group
    if (dest != src) {
        foreach_endpoint(endpoint, src) {
            endpoint_group_add_ep(dest, endpoint);
        }
    }
}

// Delete endpoint from group
void endpoint_group_del(endpoint_group_t *group, endpoint_t *endpoint)
{
    endpoint_t **i = &group->head;

    // If the selected endpoint is the one we are deleting, select the next one
    if (group->selected == endpoint)
        endpoint_group_select_next(group);

    while (*i) {
        if (*i == endpoint) {
            *i = (*i)->next;
            group->count -= 1;

            logger_debug(DBG_ENDPOINTS,
                "Deleted endpoint %s:%u from group %p (%s)",
                endpoint->hostname, endpoint->port, group, group->owner_name);

            endpoint_free(endpoint);
            break;
        }
        i = &(*i)->next;
    }
}

// Delete expired endpoints from group
// Returns true if endpoints were deleted
bool endpoint_group_del_expired(endpoint_group_t *group)
{
    struct timespec now;
    struct timespec delta;
    bool deleted = false;
    endpoint_t *endpoint = group->head;
    endpoint_t *next;

    oshd_gettime(&now);
    while (endpoint) {
        next = endpoint->next;

        timespecsub(&now, &endpoint->last_refresh, &delta);
        if (delta.tv_sec >= ENDPOINT_EXPIRY) {
            if (endpoint->can_expire) {
                endpoint_group_del(group, endpoint);
                deleted = true;
            } else {
                endpoint_refresh(group, endpoint);
                if (oshd.shareendpoints)
                    client_queue_endpoint_broadcast(NULL, endpoint, group);
            }
        }

        endpoint = next;
    }
    return deleted;
}

// Returns the selected endpoint
// Returns NULL if no endpoint is selected (either the group is empty or
endpoint_t *endpoint_group_selected(endpoint_group_t *group)
{
    return group->selected;
}

// Select the next endpoint and return its pointer
endpoint_t *endpoint_group_select_next(endpoint_group_t *group)
{
    if (group->selected) {
        logger_debug(DBG_ENDPOINTS,
            "Selecting next endpoint in group %p owned by %s (%p -> %p)",
            group, group->owner_name, group->selected, group->selected->next);
        group->selected = group->selected->next;
    }
    return group->selected;
}

// Select the first endpoint in the group and return its pointer
endpoint_t *endpoint_group_select_first(endpoint_group_t *group)
{
    logger_debug(DBG_ENDPOINTS,
        "Selecting first endpoint in group %p owned by %s (%p)",
        group, group->owner_name, group->head);
    group->selected = group->head;
    return group->selected;
}

// Sets the is_connecting variable in the group
void endpoint_group_set_is_connecting(endpoint_group_t *group, bool is_connecting)
{
    group->is_connecting = is_connecting;
    logger_debug(DBG_ENDPOINTS, "Set is_connecting to %s for group %p (%s)",
        group->is_connecting ? "true" : "false",
        group,
        group->owner_name);
}
