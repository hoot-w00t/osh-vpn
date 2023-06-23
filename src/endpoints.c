#include "endpoints.h"
#include "xalloc.h"
#include "logger.h"
#include "node.h"
#include "oshd.h"
#include "oshd_clock.h"
#include "macros_assert.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void endpoint_refresh(const endpoint_group_t *group, endpoint_t *endpoint);

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

// Determine the netarea_t of the value
static netarea_t endpoint_calc_area(const endpoint_t *endpoint)
{
    netaddr_t addr;

    switch (endpoint->type) {
        case ENDPOINT_TYPE_IP4:
            netaddr_dton_ip4(&addr, endpoint->data.ip4.addr);
            return netaddr_area(&addr);

        case ENDPOINT_TYPE_IP6:
            netaddr_dton_ip6(&addr, endpoint->data.ip6.addr);
            return netaddr_area(&addr);

        default:
            return NETAREA_UNK;
    }
}

// Return the endpoint's priority value
static int endpoint_calc_priority(const endpoint_t *endpoint)
{
    int priority;

    if (!endpoint_can_expire(endpoint))
        return -1;

    priority = 0;

    if (endpoint->flags & ENDPOINT_FLAG_EPHEMERAL)
        priority += _netarea_last + 1;

    switch (endpoint->type) {
        case ENDPOINT_TYPE_HOSTNAME:
            priority += _netarea_last;
            break;

        case ENDPOINT_TYPE_IP4:
        case ENDPOINT_TYPE_IP6:
            priority += endpoint->area;
            break;

        default:
            priority += _netarea_last + 1;
            break;
    }

    return priority;
}

// Initialize endpoint type and socket address from character value and port
static void endpoint_data_from_charvalue(endpoint_t *endpoint,
    const char *value, const uint16_t port)
{
    struct in_addr tmp_addr4;
    struct in6_addr tmp_addr6;

    memset(&endpoint->data, 0, sizeof(endpoint->data));

    if (inet_pton(AF_INET, value, &tmp_addr4) == 1) {
        // IPv4 address

        endpoint->data.ip4.addr = tmp_addr4;
        endpoint->data.ip4.port = htons(port);
        endpoint->type = ENDPOINT_TYPE_IP4;

    } else if (inet_pton(AF_INET6, value, &tmp_addr6) == 1) {
        // IPv6 address

        endpoint->data.ip6.addr = tmp_addr6;
        endpoint->data.ip6.port = htons(port);
        endpoint->type = ENDPOINT_TYPE_IP6;

    } else {
        // Hostname (or unknown value)

        strncpy(endpoint->data.host.hostname, value, ENDPOINT_HOSTNAME_MAXLEN);
        endpoint->data.host.port = htons(port);
        endpoint->type = ENDPOINT_TYPE_HOSTNAME;
    }
}

// Allocate new addrstr of len + 10 bytes (for additional characters, the
// port number and the terminating byte)
// Frees previously allocated addrstr (if any)
static void endpoint_alloc_addrstr(endpoint_t *endpoint, size_t len)
{
    free(endpoint->addrstr);
    endpoint->addrstr_size = len + 16;
    endpoint->addrstr = xalloc(endpoint->addrstr_size);
}

// Format endpoint->addrstr from socket address
// Returns false on error
static bool endpoint_format_addrstr(endpoint_t *endpoint)
{
    switch (endpoint->type) {
        case ENDPOINT_TYPE_HOSTNAME: {
            endpoint_alloc_addrstr(endpoint, strlen(endpoint->data.host.hostname));
            snprintf(endpoint->addrstr, endpoint->addrstr_size, "%s:%u",
                endpoint->data.host.hostname, ntohs(endpoint->data.host.port));
            return true;
        }

        case ENDPOINT_TYPE_IP4: {
            char addrp[INET_ADDRSTRLEN];

            if (!inet_ntop(AF_INET, &endpoint->data.ip4.addr, addrp, sizeof(addrp)))
                return false;

            endpoint_alloc_addrstr(endpoint, strlen(addrp));
            snprintf(endpoint->addrstr, endpoint->addrstr_size, "%s:%u",
                addrp, ntohs(endpoint->data.ip4.port));
            return true;
        }

        case ENDPOINT_TYPE_IP6: {
            char addrp[INET6_ADDRSTRLEN];

            if (!inet_ntop(AF_INET6, &endpoint->data.ip6.addr, addrp, sizeof(addrp)))
                return false;

            endpoint_alloc_addrstr(endpoint, strlen(addrp));
            snprintf(endpoint->addrstr, endpoint->addrstr_size, "[%s]:%u",
                addrp, ntohs(endpoint->data.ip6.port));
            return true;
        }

        default:
            return false;
    }
}

// Allocate an empty endpoint
static endpoint_t *endpoint_alloc(void)
{
    return xzalloc(sizeof(endpoint_t));
}

// Initialize remaining members of the endpoint after the address was set
static void endpoint_init2(endpoint_t *endpoint,
    const endpoint_proto_t proto, const endpoint_flags_t flags)
{
    endpoint->proto = proto;
    endpoint->flags = flags;

    endpoint->area = endpoint_calc_area(endpoint);
    endpoint->priority = endpoint_calc_priority(endpoint);

    if (!endpoint_format_addrstr(endpoint)) {
        const char *errstr = "(format error)";

        endpoint_alloc_addrstr(endpoint, strlen(errstr));
        snprintf(endpoint->addrstr, endpoint->addrstr_size, "%s", errstr);
    }
}

// Create a new endpoint from a character string
endpoint_t *endpoint_create(const char *value, const uint16_t port,
    const endpoint_proto_t proto, const endpoint_flags_t flags)
{
    endpoint_t *endpoint = endpoint_alloc();

    endpoint_data_from_charvalue(endpoint, value, port);
    endpoint_init2(endpoint, proto, flags);
    return endpoint;
}

// Free endpoint and its allocated resources
void endpoint_free(endpoint_t *endpoint)
{
    if (endpoint) {
        free(endpoint->addrstr);
        free(endpoint);
    }
}

// Duplicate existing endpoint
endpoint_t *endpoint_dup(const endpoint_t *original)
{
    endpoint_t *endpoint = endpoint_alloc();

    // Copy the original endpoint address
    endpoint->type = original->type;
    memcpy(&endpoint->data, &original->data, sizeof(endpoint->data));

    // Initialize members that cannot be shared
    endpoint_init2(endpoint, original->proto, original->flags);
    return endpoint;
}

// Modify endpoint flags
// If the endpoint is part of a group it can be passed to also refresh the endpoint
// If group is NULL the endpoint is not refreshed
//
// These flags must not be modified directly because internals of the endpoint
// are initialized based on some flags and need to be updated if they change
void endpoint_set_flags(endpoint_group_t *group, endpoint_t *endpoint,
    const endpoint_flags_t flags)
{
    endpoint_init2(endpoint, endpoint->proto, flags);
    if (group)
        endpoint_refresh(group, endpoint);
}

// Returns true if both endpoints have the same socket addresses (same types,
// addresses and ports)
static bool endpoint_eq(const endpoint_t *s1, const endpoint_t *s2)
{
    if (s1->type != s2->type)
        return false;

    switch (s1->type) {
        case ENDPOINT_TYPE_HOSTNAME:
            return    !strcmp(s1->data.host.hostname, s2->data.host.hostname)
                   &&  s1->data.host.port == s2->data.host.port;

        case ENDPOINT_TYPE_IP4:
            return    !memcmp(&s1->data.ip4.addr, &s2->data.ip4.addr, sizeof(s1->data.ip4.addr))
                   &&  s1->data.ip4.port == s2->data.ip4.port;

        case ENDPOINT_TYPE_IP6:
            return    !memcmp(&s1->data.ip6.addr, &s2->data.ip6.addr, sizeof(s1->data.ip6.addr))
                   &&  s1->data.ip6.port == s2->data.ip6.port;

        default:
            // This should never happen
            return false;
    }
}

// Refresh an endpoint
static void endpoint_refresh(const endpoint_group_t *group, endpoint_t *endpoint)
{
    time_t expire_delay;

    // Local endpoints always have the same expiration delay
    //
    // Ephemeral endpoints expire faster when they are not local because they
    // are considered unreachable (when relevant, they are used right away)
    // Local ephemeral endpoints use the local expiration delay because they
    // shouldn't need to be re-announced often
    //
    // Other endpoints use the default remote expiration delay which is bigger
    // than the local delay to allow refreshing valid endpoints before they
    // expire on remote nodes
    if (endpoint->flags & ENDPOINT_FLAG_EXPIRY_LOCAL)
        expire_delay = ENDPOINT_EXPIRY_LOCAL;
    else if (endpoint->flags & ENDPOINT_FLAG_EPHEMERAL)
        expire_delay = ENDPOINT_EXPIRY_EPHEMERAL;
    else
        expire_delay = ENDPOINT_EXPIRY_REMOTE;

    logger_debug(DBG_ENDPOINTS, "%s: Refreshing endpoint %s (%" PRI_TIME_T "s, %s)",
        group->debug_id, endpoint->addrstr, (pri_time_t) expire_delay,
        endpoint_can_expire(endpoint) ? "can expire" : "never expires");

    oshd_gettime(&endpoint->expire_after);
    endpoint->expire_after.tv_sec += expire_delay;
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
static endpoint_t *_endpoint_group_find(endpoint_t *start, const endpoint_t *endpoint)
{
    for (endpoint_t *it = start; it != NULL; it = it->next) {
        if (endpoint_eq(it, endpoint))
            return it;
    }
    return NULL;
}

// Returns the first exactly matching endpoint starting at element *start
static endpoint_t *_endpoint_group_find_exact(endpoint_t *start, const endpoint_t *endpoint)
{
    for (endpoint_t *it = start; it != NULL; it = it->next) {
        if (endpoint_eq(it, endpoint) && it->proto == endpoint->proto)
            return it;
    }
    return NULL;
}

// Searches for the first endpoint matching value and port
// Returns NULL if it cannot be found
endpoint_t *endpoint_group_find(endpoint_group_t *group, const endpoint_t *endpoint)
{
    return _endpoint_group_find(group->head, endpoint);
}

// Searches for the first endpoint exactly matching
// Returns NULL if it cannot be found
endpoint_t *endpoint_group_find_exact(endpoint_group_t *group, const endpoint_t *endpoint)
{
    return _endpoint_group_find_exact(group->head, endpoint);
}

// Searches for the first endpoint matching value and port starting at the
// element *after->next
// Returns NULL if it cannot be found
endpoint_t *endpoint_group_find_after(endpoint_t *after, const endpoint_t *endpoint)
{
    return _endpoint_group_find(after->next, endpoint);
}

// Searches for the first endpoint exactly matching starting at the element
// *after->next
// Returns NULL if it cannot be found
endpoint_t *endpoint_group_find_exact_after(endpoint_t *after, const endpoint_t *endpoint)
{
    return _endpoint_group_find_exact(after->next, endpoint);
}

// Find a duplicate endpoint (taking ENDPOINT_FLAG_CAN_EXPIRE and proto into account)
// Returns NULL if the endpoint does not yet exist
endpoint_t *endpoint_group_find_duplicate(endpoint_group_t *group, const endpoint_t *endpoint)
{
    endpoint_t *it = endpoint_group_find(group, endpoint);

    while (it) {
        // If the matching endpoint and the new one have the same ENDPOINT_FLAG_CAN_EXPIRE
        // attribute the existing one can inherit the protocol value of the new one
        if (endpoint_can_expire(it) == endpoint_can_expire(endpoint))
            return it;

        // If the matching endpoint has all the protocols of the new one, it
        // can be considered as a duplicate
        if ((it->proto & endpoint->proto) == endpoint->proto)
            return it;

        // Find the next occurrence of the endpoint
        it = endpoint_group_find_after(it, endpoint);
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
    const endpoint_t *endpoint)
{
    endpoint_t *new_endpoint = endpoint_dup(endpoint);

    return endpoint_group_insert_at2(it, group, new_endpoint);
}

// Insert a new endpoint at the end of the group and returns it
endpoint_t *endpoint_group_insert_back(endpoint_group_t *group,
    const endpoint_t *endpoint)
{
    endpoint_t **it = &group->head;

    while (*it)
        it = &(*it)->next;

    return endpoint_group_insert_at(it, group, endpoint);
}

// Insert a new endpoint after the given element and returns it
endpoint_t *endpoint_group_insert_after(endpoint_t *after, endpoint_group_t *group,
    const endpoint_t *endpoint)
{
    // The endpoint after which we insert a new endpoint must be part of the
    // given group, otherwise it will mess up the group
    assert(is_endpoint_ptr_in_group(after, group) == true);
    return endpoint_group_insert_at(&after->next, group, endpoint);
}

// Insert an endpoint to the group sorted by priority
// If a matching endpoint is already in the group it will only be refreshed and
// nothing else will be changed
// Returns true if the endpoint was added, false if it already existed
// If inserted_endpoint is not NULL, set it to the group endpoint
bool endpoint_group_insert_sorted(endpoint_group_t *group,
    const endpoint_t *original, endpoint_t **inserted_endpoint)
{
    endpoint_t *endpoint = endpoint_group_find_duplicate(group, original);
    endpoint_t **it;
    bool added = false;

    if (endpoint) {
        // The same endpoint already exists in the group

        // Add the socket protocols of the new endpoint to the existing one
        endpoint->proto |= original->proto;

        // Preserve the endpoint's private flags but use the new endpoint's
        // public flags
        const endpoint_flags_t correct_flags = (endpoint->flags & ENDPOINT_FLAG_PRIVATE_MASK)
                                             | (original->flags & ENDPOINT_FLAG_PUBLIC_MASK);

        if (endpoint->flags != correct_flags)
            endpoint_set_flags(NULL, endpoint, correct_flags);

    } else {
        // The endpoint does not already exist in the group, create it

        it = &group->head;
        endpoint = endpoint_dup(original);
        added = true;

        while (*it) {
            // Sort by ascending priority value
            if (endpoint->priority < (*it)->priority)
                break;

            it = &(*it)->next;
        }
        endpoint_group_insert_at2(it, group, endpoint);

        logger_debug(DBG_ENDPOINTS, "%s: Added endpoint %s",
            group->debug_id, endpoint->addrstr);

        // Automatically select the first item if a connection is not underway
        if (!endpoint_group_is_connecting(group))
            endpoint_group_select_first(group);
    }

    endpoint_refresh(group, endpoint);
    if (inserted_endpoint)
        *inserted_endpoint = endpoint;
    return added;
}

// Insert all endpoints from src to dest, using endpoint_group_insert_sorted
void endpoint_group_insert_group(endpoint_group_t *dest,
    const endpoint_group_t *src)
{
    // Stop early if we try to merge the same group
    if (dest == src)
        return;

    foreach_endpoint_const(endpoint, src) {
        endpoint_group_insert_sorted(dest, endpoint, NULL);
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

            logger_debug(DBG_ENDPOINTS, "%s: Deleted endpoint %s",
                group->debug_id, endpoint->addrstr);

            endpoint_free(endpoint);
            break;
        }
        it = &(*it)->next;
    }
}

// Delete expired endpoints from *group
// Endpoints that do not expire are refreshed instead of deleted
// All expired endpoints' flags are ORed in *expired_flags
// *now must be initialized with oshd_gettime()
// *next_expire is set to the remaining time before endpoints expire if that
// delay is smaller than *next_expire
// Returns true if at least one endpoint has expired
bool endpoint_group_del_expired(endpoint_group_t *group, time_t *next_expire,
    endpoint_flags_t *expired_flags, const struct timespec *now)
{
    bool expired = false;
    endpoint_t *endpoint = group->head;
    endpoint_t *next;
    struct timespec delta;

    *expired_flags = ENDPOINT_FLAG_NONE;
    while (endpoint) {
        next = endpoint->next;

        timespecsub(&endpoint->expire_after, now, &delta);
        if (delta.tv_sec < 0) {
            endpoint->had_expired = true;
            expired = true;
            *expired_flags |= endpoint->flags;

            if (endpoint_can_expire(endpoint)) {
                endpoint_group_del(group, endpoint);
            } else {
                endpoint_refresh(group, endpoint);
            }
        } else {
            endpoint->had_expired = false;
            if (delta.tv_sec < *next_expire)
                *next_expire = delta.tv_sec + 1;
        }

        endpoint = next;
    }
    return expired;
}

// Lookup DNS addresses of the endpoint's value and add those after it
// This function can delete/modify existing endpoints in the group
// Returns false on error
bool endpoint_lookup(endpoint_t *endpoint, endpoint_group_t *group)
{
    struct addrinfo *addrinfo = NULL;
    int ai_err;
    char ai_service[8];

    if (endpoint->type != ENDPOINT_TYPE_HOSTNAME) {
        logger(LOG_ERR, "Failed to resolve '%s': %s", endpoint->addrstr,
            "Not a hostname");
        return false;
    }

    snprintf(ai_service, sizeof(ai_service), "%u", ntohs(endpoint->data.host.port));
    logger_debug(DBG_ENDPOINTS, "Resolving hostname %s:%s",
        endpoint->data.host.hostname, ai_service);
    ai_err = getaddrinfo(endpoint->data.host.hostname, ai_service, NULL, &addrinfo);
    if (ai_err != 0) {
        logger(LOG_ERR, "Failed to resolve '%s': %s", endpoint->data.host.hostname,
            gai_strerror(ai_err));
        return false;
    }

    endpoint_t *after = endpoint;
    endpoint_t *lookedup = NULL;

    for (struct addrinfo *it = addrinfo; it != NULL; it = it->ai_next) {
        endpoint_free(lookedup);
        lookedup = endpoint_from_sockaddr(it->ai_addr, it->ai_addrlen,
            endpoint->proto, ENDPOINT_FLAG_CAN_EXPIRE);

        // If this endpoint is not compatible or could not be decoded, skip it
        if (!lookedup)
            continue;

        // Check if the endpoint already exists in the group
        if (endpoint_group_find_exact(group, lookedup)) {
            // Check if it exists after the current one
            endpoint_t *old_endpoint = endpoint_group_find_exact_after(after, lookedup);

            if (old_endpoint) {
                // The endpoint exists after the current one, we will move it by
                // deleting and re-inserting it
                endpoint_group_del(group, old_endpoint);
            } else {
                // If it exists before the current one, skip it
                logger_debug(DBG_ENDPOINTS, "%s: Ignoring looked up endpoint %s (%s)",
                    group->debug_id, lookedup->addrstr, "already exists");
                continue;
            }
        }

        // Insert the new endpoint
        logger_debug(DBG_ENDPOINTS, "%s: Inserting looked up endpoint %s",
            group->debug_id, lookedup->addrstr);
        after = endpoint_group_insert_after(after, group, lookedup);
    }
    endpoint_free(lookedup);
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

            if (sa_len < (socklen_t) sizeof(*sin))
                return false;

            memset(sa, 0, sa_len);
            sin->sin_family = AF_INET;
            sin->sin_addr = endpoint->data.ip4.addr;
            sin->sin_port = endpoint->data.ip4.port;
            return true;
        }

        case ENDPOINT_TYPE_IP6: {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) sa;

            if (sa_len < (socklen_t) sizeof(*sin6))
                return false;

            memset(sa, 0, sa_len);
            sin6->sin6_family = AF_INET6;
            sin6->sin6_addr = endpoint->data.ip6.addr;
            sin6->sin6_port = endpoint->data.ip6.port;
            return true;
        }

        default:
            return false;
    }
}

// Create an endpoint from a socket address
// Returns NULL on error
endpoint_t *endpoint_from_sockaddr(const struct sockaddr *sa, const socklen_t sa_len,
    const endpoint_proto_t proto, const endpoint_flags_t flags)
{
    endpoint_t *endpoint;

    if (sa_len < (socklen_t) sizeof(sa->sa_family))
        return NULL;

    switch (sa->sa_family) {
        case AF_INET: {
            const struct sockaddr_in *sin = (const struct sockaddr_in *) sa;

            if (sa_len < (socklen_t) sizeof(*sin))
                return NULL;

            endpoint = endpoint_alloc();
            endpoint->type = ENDPOINT_TYPE_IP4;
            endpoint->data.ip4.port = sin->sin_port;
            endpoint->data.ip4.addr = sin->sin_addr;
            endpoint_init2(endpoint, proto, flags);
            return endpoint;
        }

        case AF_INET6: {
            const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *) sa;

            if (sa_len < (socklen_t) sizeof(*sin6))
                return NULL;

            endpoint = endpoint_alloc();
            endpoint->type = ENDPOINT_TYPE_IP6;
            endpoint->data.ip6.port = sin6->sin6_port;
            endpoint->data.ip6.addr = sin6->sin6_addr;
            endpoint_init2(endpoint, proto, flags);
            return endpoint;
        }

        default:
            return NULL;
    }
}

// Returns true if c is a valid hostname character
static bool endpoint_valid_hostname_char(const char c)
{
    const char valid_charset[] = \
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.";

    for (size_t i = 0; valid_charset[i] != 0; ++i) {
        if (c == valid_charset[i])
            return true;
    }
    return false;
}

// Returns true if the hostname only contains valid characters
static bool endpoint_valid_hostname(const char *hostname, const size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        if (!endpoint_valid_hostname_char(hostname[i]))
            return false;
    }
    return true;
}

// Get endpoint flags from oshpacket_endpoint_t public flags (host byte order)
static endpoint_flags_t get_flags_from_packet(const uint16_t public_flags)
{
    // Endpoints received from other nodes always expire and cannot have a local
    // expiry delay
    return (((endpoint_flags_t) public_flags) << 16) | ENDPOINT_FLAG_CAN_EXPIRE;
}

// Get public flags for oshpacket_endpoint_t (host byte order)
static uint16_t get_public_flags(const endpoint_flags_t flags)
{
    return (uint16_t) ((flags >> 16) & 0xFFFFu);
}

// Create endpoint packet from an existing endpoint (except owner_name)
bool endpoint_to_packet(const endpoint_t *endpoint,
    oshpacket_endpoint_t *pkt, endpoint_data_t *data, size_t *data_size)
{
    switch (endpoint->type) {
        case ENDPOINT_TYPE_HOSTNAME:
            *data_size = sizeof(endpoint->data.host.port);
            *data_size += strlen(endpoint->data.host.hostname);
            break;

        case ENDPOINT_TYPE_IP4:
            *data_size = sizeof(endpoint->data.ip4);
            break;

        case ENDPOINT_TYPE_IP6:
            *data_size = sizeof(endpoint->data.ip6);
            break;

        default: return false;
    }

    pkt->type = endpoint->type;
    pkt->proto = endpoint->proto;
    pkt->flags = htons(get_public_flags(endpoint->flags));
    memcpy(data, &endpoint->data, *data_size);
    return true;
}

// Create endpoint from an endpoint packet
// Returns NULL on error
endpoint_t *endpoint_from_packet(const oshpacket_endpoint_t *pkt,
    const endpoint_data_t *data, const size_t data_size)
{
    endpoint_t *endpoint;

    switch (pkt->type) {
        case ENDPOINT_TYPE_HOSTNAME:
            // data_size must not be equal to the data->host structure size, as
            // the last byte is the hostname string's terminator
            if (data_size <= sizeof(data->host.port) || data_size >= sizeof(data->host))
                return NULL;

            if (!endpoint_valid_hostname(data->host.hostname, data_size - sizeof(data->host.port)))
                return NULL;

            break;

        case ENDPOINT_TYPE_IP4:
            if (data_size != sizeof(data->ip4))
                return NULL;
            break;

        case ENDPOINT_TYPE_IP6:
            if (data_size != sizeof(data->ip6))
                return NULL;
            break;

        default: return NULL;
    }

    endpoint = endpoint_alloc();
    endpoint->type = pkt->type;
    memcpy(&endpoint->data, data, data_size);
    endpoint_init2(endpoint, pkt->proto, get_flags_from_packet(ntohs(pkt->flags)));
    return endpoint;
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
            group->debug_id, (void *) group->selected, (void *) group->selected->next);

        group->selected = group->selected->next;
    }
    return group->selected;
}

// Select the first endpoint in the group and return its pointer
endpoint_t *endpoint_group_select_first(endpoint_group_t *group)
{
    if (group->selected != group->head) {
        logger_debug(DBG_ENDPOINTS, "%s: Select first endpoint (%p)",
            group->debug_id, (void *) group->head);

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
