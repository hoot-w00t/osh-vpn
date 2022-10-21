#include "endpoints.h"
#include "xalloc.h"
#include "logger.h"
#include "node.h"
#include "oshd.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>

// Return the endpoint type name
const char *endpoint_type_name(const endpoint_type_t type)
{
    switch (type) {
        case ENDPOINT_TYPE_UNKNOWN : return "Unknown";
        case ENDPOINT_TYPE_HOSTNAME: return "Hostname";
        case ENDPOINT_TYPE_IP4     : return "IPv4";
        case ENDPOINT_TYPE_IP6     : return "IPv6";
             default               : return "Unknown";
    }
}

// Determine the endpoint type of the value
static endpoint_type_t endpoint_type_from_value(const char *value)
{
    netaddr_t addr;

    if (netaddr_pton(&addr, value)) {
        switch (addr.type) {
            case IP4: return ENDPOINT_TYPE_IP4;
            case IP6: return ENDPOINT_TYPE_IP6;
            default : return ENDPOINT_TYPE_UNKNOWN;
        }
    } else {
        return ENDPOINT_TYPE_HOSTNAME;
    }
}

// Determine the netarea_t of the value
static netarea_t endpoint_area_from_value(const char *value, const endpoint_type_t type)
{
    netaddr_t addr;

    switch (type) {
        case ENDPOINT_TYPE_IP4:
        case ENDPOINT_TYPE_IP6:
            return netaddr_pton(&addr, value) ? netaddr_area(&addr) : NETAREA_UNK;

        default:
            return NETAREA_UNK;
    }
}

// Return the endpoint's priority value
static int endpoint_calc_priority(const endpoint_t *endpoint)
{
    if (!endpoint->can_expire)
        return -1;

    switch (endpoint->type) {
        case ENDPOINT_TYPE_HOSTNAME:
            return _netarea_last;

        case ENDPOINT_TYPE_IP4:
        case ENDPOINT_TYPE_IP6:
            return endpoint->area;

        default:
            return _netarea_last + 1;
    }
}

// Allocate a new endpoint
endpoint_t *endpoint_create(const char *value, const uint16_t port,
    const endpoint_socktype_t socktype, const bool can_expire)
{
    endpoint_t *endpoint = xzalloc(sizeof(endpoint_t));

    endpoint->value = xstrdup(value);
    endpoint->port = port;
    endpoint->socktype = socktype;
    endpoint->can_expire = can_expire;

    endpoint->type = endpoint_type_from_value(value);
    endpoint->area = endpoint_area_from_value(value, endpoint->type);
    endpoint->priority = endpoint_calc_priority(endpoint);

    return endpoint;
}

// Free endpoint and its allocated resources
void endpoint_free(endpoint_t *endpoint)
{
    if (endpoint) {
        free(endpoint->value);
        free(endpoint);
    }
}

// Duplicate existing endpoint
endpoint_t *endpoint_dup(const endpoint_t *original)
{
    return endpoint_create(original->value, original->port,
        original->socktype, original->can_expire);
}

// Returns true if endpoint has the same value and port
static bool endpoint_eq(const endpoint_t *endpoint, const char *value,
    const uint16_t port)
{
    return    !strcmp(endpoint->value, value)
           &&  endpoint->port == port;
}

// Refresh an endpoint
static void endpoint_refresh(const endpoint_group_t *group, endpoint_t *endpoint)
{
    // Update last_refresh timestamp
    oshd_gettime(&endpoint->last_refresh);
    logger_debug(DBG_ENDPOINTS, "%s: Refreshed endpoint %s:%u",
        group->debug_id, endpoint->value, endpoint->port);
}

// Returns true if the endpoint is part of the group
static bool is_endpoint_ptr_in_group(const endpoint_t *endpoint,
    const endpoint_group_t *group)
{
    foreach_endpoint_const(it, group) {
        if (it == endpoint)
            return true;
    }
    return false;
}

// Create an empty endpoint group
endpoint_group_t *endpoint_group_create(const char *owner_name, const char *debug_id)
{
    const size_t debug_id_size = strlen(owner_name) + strlen(debug_id) + 2;
    endpoint_group_t *group = xzalloc(sizeof(endpoint_group_t));

    group->owner_name = xstrdup(owner_name);
    group->debug_id = xzalloc(debug_id_size);
    snprintf(group->debug_id, debug_id_size, "%s:%s", owner_name, debug_id);
    return group;
}

// Free endpoint group and its allocated resources
void endpoint_group_free(endpoint_group_t *group)
{
    if (!group)
        return;

    logger_debug(DBG_ENDPOINTS, "%s: Freeing group", group->debug_id);
    endpoint_group_clear(group);
    free(group->owner_name);
    free(group->debug_id);
    free(group);
}

// Delete all endpoints from group
void endpoint_group_clear(endpoint_group_t *group)
{
    endpoint_t *i = group->head;
    endpoint_t *next;

    logger_debug(DBG_ENDPOINTS, "%s: Clearing endpoints", group->debug_id);

    while (i) {
        next = i->next;
        endpoint_free(i);
        i = next;
    }
    group->head = NULL;
    group->selected = NULL;
    group->count = 0;
}

// Returns the first matching endpoint starting at element *start
static endpoint_t *_endpoint_group_find(endpoint_t *start,
    const char *value, const uint16_t port)
{
    for (endpoint_t *it = start; it != NULL; it = it->next) {
        if (endpoint_eq(it, value, port))
            return it;
    }
    return NULL;
}

// Searches for the first endpoint matching value and port
// Returns NULL if it cannot be found
endpoint_t *endpoint_group_find(endpoint_group_t *group, const char *value,
    const uint16_t port)
{
    return _endpoint_group_find(group->head, value, port);
}

// Searches for the first endpoint matching value and port starting at the
// element *after->next
// Returns NULL if it cannot be found
endpoint_t *endpoint_group_find_after(endpoint_t *after,
    const char *value, const uint16_t port)
{
    return _endpoint_group_find(after->next, value, port);
}

// Find a duplicate endpoint (taking can_expire and socktype into account)
// Returns NULL if the endpoint does not yet exist
endpoint_t *endpoint_group_find_duplicate(endpoint_group_t *group,
    const char *value, const uint16_t port, const endpoint_socktype_t socktype, const bool can_expire)
{
    endpoint_t *endpoint = endpoint_group_find(group, value, port);

    while (endpoint) {
        // If the matching endpoint and the new one have the same can_expire
        // value the existing one can inherit the socktype value of the new one
        if (endpoint->can_expire == can_expire)
            return endpoint;

        // If the matching endpoint has all the socket types of the new one, it
        // can be considered as a duplicate
        if ((endpoint->socktype & socktype) == socktype)
            return endpoint;

        // Find the next occurence of the endpoint
        endpoint = endpoint_group_find_after(endpoint, value, port);
    }

    // No duplicates were found
    return NULL;
}

// Insert *endpoint at the location pointed to by **it
// **it must be part of the *group linked list
// Returns the inserted endpoint
static endpoint_t *endpoint_group_insert_at2(endpoint_t **it, endpoint_group_t *group,
    endpoint_t *endpoint)
{
    endpoint->next = *it;
    *it = endpoint;
    group->count += 1;
    return endpoint;
}

// Insert a new endpoint at the location pointed to by **it
// **it must be part of the *group linked list
// Returns the inserted endpoint
static endpoint_t *endpoint_group_insert_at(endpoint_t **it, endpoint_group_t *group,
    const char *value, const uint16_t port, const endpoint_socktype_t socktype, const bool can_expire)
{
    endpoint_t *endpoint = endpoint_create(value, port, socktype, can_expire);

    return endpoint_group_insert_at2(it, group, endpoint);
}

// Insert a new endpoint at the end of the group and returns it
endpoint_t *endpoint_group_insert_back(endpoint_group_t *group,
    const char *value, const uint16_t port, const endpoint_socktype_t socktype, const bool can_expire)
{
    endpoint_t **it = &group->head;

    while (*it)
        it = &(*it)->next;

    return endpoint_group_insert_at(it, group, value, port, socktype, can_expire);
}

// Insert a new endpoint after the given element and returns it
endpoint_t *endpoint_group_insert_after(endpoint_t *after, endpoint_group_t *group,
    const char *value, const uint16_t port, const endpoint_socktype_t socktype, const bool can_expire)
{
    // This should never happen
    if (!is_endpoint_ptr_in_group(after, group)) {
        logger(LOG_CRIT, "%s:%i: %s: endpoint pointer is not part of the given group",
            __FILE__, __LINE__, __func__);
        abort();
    }

    return endpoint_group_insert_at(&after->next, group, value, port, socktype, can_expire);
}

// Insert an endpoint to the group sorted by priority
// If a matching endpoint is already in the group it will only be refreshed and
// nothing else will be changed
// Returns the endpoint pointer if it was added, returns NULL if it was already
// in the group
endpoint_t *endpoint_group_insert_sorted(endpoint_group_t *group,
    const char *value, const uint16_t port, const endpoint_socktype_t socktype, const bool can_expire)
{
    endpoint_t *endpoint = endpoint_group_find_duplicate(group, value, port, socktype, can_expire);
    endpoint_t *added = NULL;
    endpoint_t **it;

    if (endpoint) {
        // The same endpoint already exists in the group

        // Add the socket types of the new endpoint to the existing one
        endpoint->socktype |= socktype;
    } else {
        // The endpoint does not already exist in the group, create it

        it = &group->head;
        endpoint = endpoint_create(value, port, socktype, can_expire);
        added = endpoint;

        while (*it) {
            // Sort by ascending priority value
            if (endpoint->priority < (*it)->priority)
                break;

            it = &(*it)->next;
        }
        endpoint_group_insert_at2(it, group, endpoint);

        // Endpoints which can't expire are endpoints from the configuration
        // file, having those in the group means that we should never give up
        // trying to connect to a node
        if (!can_expire)
            group->always_retry = true;

        logger_debug(DBG_ENDPOINTS, "%s: Added endpoint %s:%u",
            group->debug_id, endpoint->value, endpoint->port);

        // Automatically select the first item if a connection is not underway
        if (!endpoint_group_is_connecting(group))
            endpoint_group_select_first(group);
    }

    endpoint_refresh(group, endpoint);
    return added;
}

// Same as endpoint_group_insert_sorted but gets the values from endpoint
void endpoint_group_insert_sorted_ep(endpoint_group_t *group,
    const endpoint_t *endpoint)
{
    endpoint_group_insert_sorted(group, endpoint->value, endpoint->port,
        endpoint->socktype, endpoint->can_expire);
}

// Insert all endpoints from src to dest, using endpoint_group_insert_sorted
void endpoint_group_insert_group(endpoint_group_t *dest,
    const endpoint_group_t *src)
{
    // Stop early if we try to merge the same group
    if (dest == src)
        return;

    foreach_endpoint_const(endpoint, src) {
        endpoint_group_insert_sorted_ep(dest, endpoint);
    }
}

// Delete endpoint from group
void endpoint_group_del(endpoint_group_t *group, endpoint_t *endpoint)
{
    endpoint_t **it = &group->head;

    // If the selected endpoint is the one we are deleting, select the next one
    if (group->selected == endpoint)
        endpoint_group_select_next(group);

    while (*it) {
        if (*it == endpoint) {
            *it = (*it)->next;
            group->count -= 1;

            logger_debug(DBG_ENDPOINTS, "%s: Deleted endpoint %s:%u",
                group->debug_id, endpoint->value, endpoint->port);

            endpoint_free(endpoint);
            break;
        }
        it = &(*it)->next;
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

// Lookup DNS addresses of the endpoint's value and add those after it
// This function can delete/modify existing endpoints in the group
// Returns false on error
bool endpoint_lookup(endpoint_t *endpoint, endpoint_group_t *group)
{
    struct addrinfo *addrinfo = NULL;
    int ai_err;

    logger_debug(DBG_ENDPOINTS, "Resolving hostname %s", endpoint->value);
    ai_err = getaddrinfo(endpoint->value, NULL, NULL, &addrinfo);
    if (ai_err != 0) {
        logger(LOG_ERR, "Failed to resolve %s: %s", endpoint->value, gai_strerror(ai_err));
        return false;
    }

    endpoint_t *after = endpoint;
    bool found;
    netaddr_t addr;
    char addrp[INET6_ADDRSTRLEN];

    for (struct addrinfo *it = addrinfo; it != NULL; it = it->ai_next) {
        switch (it->ai_family) {
        case AF_INET:
            found =    netaddr_dton(&addr, IP4, &((struct sockaddr_in *) it->ai_addr)->sin_addr)
                    && netaddr_ntop(addrp, sizeof(addrp), &addr);
            break;

        case AF_INET6:
            found =    netaddr_dton(&addr, IP6, &((struct sockaddr_in6 *) it->ai_addr)->sin6_addr)
                    && netaddr_ntop(addrp, sizeof(addrp), &addr);
            break;

        default:
            found = false;
            break;
        }

        // If this endpoint is not compatible or could not be decoded, skip it
        if (!found)
            continue;

        endpoint_socktype_t new_socktype = endpoint->socktype;

        // Check if the endpoint already exists
        if (endpoint_group_find(group, addrp, endpoint->port)) {
            endpoint_t *old_endpoint = endpoint_group_find_after(after, addrp, endpoint->port);

            // The endpoint already exists before the current one, skip it
            if (!old_endpoint) {
                logger_debug(DBG_ENDPOINTS, "%s: Ignoring looked up endpoint %s (%s)",
                    group->debug_id, addrp, "already exists");
                continue;
            }

            // The endpoint exists after the current one, move it here by
            // deleting and re-inserting it
            new_socktype |= old_endpoint->socktype;
            endpoint_group_del(group, old_endpoint);
        }

        // Insert the new endpoint
        logger_debug(DBG_ENDPOINTS, "%s: Inserting looked up endpoint %s:%u",
                    group->debug_id, addrp, endpoint->port);
        after = endpoint_group_insert_after(after, group,
            addrp, endpoint->port, new_socktype, endpoint->can_expire);
    }

    freeaddrinfo(addrinfo);
    return true;
}

// Initialize a socket address from an endpoint
// Returns false on error
bool endpoint_to_sockaddr(struct sockaddr *sa, const socklen_t sa_len,
    const endpoint_t *endpoint)
{
    switch (endpoint->type) {
        case ENDPOINT_TYPE_IP4: {
            struct sockaddr_in *sin = (struct sockaddr_in *) sa;

            if (sa_len < sizeof(*sin))
                return false;

            memset(sa, 0, sa_len);
            if (inet_pton(AF_INET, endpoint->value, &sin->sin_addr) != 1)
                return false;
            sin->sin_family = AF_INET;
            sin->sin_port = htons(endpoint->port);
            return true;
        }

        case ENDPOINT_TYPE_IP6: {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) sa;

            if (sa_len < sizeof(*sin6))
                return false;

            memset(sa, 0, sa_len);
            if (inet_pton(AF_INET6, endpoint->value, &sin6->sin6_addr) != 1)
                return false;
            sin6->sin6_family = AF_INET6;
            sin6->sin6_port = htons(endpoint->port);
            return true;
        }

        default:
            return false;
    }
}

// Create an endpoint from a socket address
// Returns NULL on error
endpoint_t *endpoint_from_sockaddr(const struct sockaddr *sa, const socklen_t sa_len,
    const endpoint_socktype_t socktype, const bool can_expire)
{
    char addr_value[INET6_ADDRSTRLEN];

    if (sa_len < sizeof(sa->sa_family))
        return NULL;

    switch (sa->sa_family) {
        case AF_INET: {
            const struct sockaddr_in *sin = (const struct sockaddr_in *) sa;

            if (sa_len < sizeof(*sin))
                return NULL;

            if (!inet_ntop(AF_INET, &sin->sin_addr, addr_value, sizeof(addr_value)))
                return NULL;

            return endpoint_create(addr_value, ntohs(sin->sin_port), socktype, can_expire);
        }

        case AF_INET6: {
            const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *) sa;

            if (sa_len < sizeof(*sin6))
                return NULL;

            if (!inet_ntop(AF_INET6, &sin6->sin6_addr, addr_value, sizeof(addr_value)))
                return NULL;

            return endpoint_create(addr_value, ntohs(sin6->sin6_port), socktype, can_expire);
        }

        default:
            return NULL;
    }
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
        logger_debug(DBG_ENDPOINTS, "%s: Select next endpoint (%p -> %p)",
            group->debug_id, group->selected, group->selected->next);

        group->selected = group->selected->next;
    }
    return group->selected;
}

// Select the first endpoint in the group and return its pointer
endpoint_t *endpoint_group_select_first(endpoint_group_t *group)
{
    if (group->selected != group->head) {
        logger_debug(DBG_ENDPOINTS, "%s: Select first endpoint (%p)",
            group->debug_id, group->head);

        group->selected = group->head;
    }
    return group->selected;
}

// Sets the is_connecting variable in the group
void endpoint_group_set_is_connecting(endpoint_group_t *group, bool is_connecting)
{
    group->is_connecting = is_connecting;
    logger_debug(DBG_ENDPOINTS, "%s: Set is_connecting to %s", group->debug_id,
        group->is_connecting ? "true" : "false");
}
