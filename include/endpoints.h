#ifndef _OSH_ENDPOINTS_H
#define _OSH_ENDPOINTS_H

#include "sock.h"
#include "netarea.h"
#include "oshd_clock.h"
#include "oshpacket.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// We need to manually define the node_id_t type to prevent include loops
// (node.h/client.h includes endpoints.h)
typedef struct node_id node_id_t;

// Endpoint expiration delays
#define ENDPOINT_EXPIRY_REMOTE      (3600) // 60m
#define ENDPOINT_EXPIRY_LOCAL       (1800) // 30m
#define ENDPOINT_EXPIRY_EPHEMERAL   (60)   // 1m

// Shortest delay
#define ENDPOINT_EXPIRY_SHORTEST    ENDPOINT_EXPIRY_EPHEMERAL

// Type of the endpoint's value
typedef enum endpoint_type {
    ENDPOINT_TYPE_UNKNOWN = 0,
    ENDPOINT_TYPE_HOSTNAME,
    ENDPOINT_TYPE_IP4,
    ENDPOINT_TYPE_IP6,
    _endpoint_type_last
} endpoint_type_t;

// Socket protocols with which the endpoint is compatible
typedef enum endpoint_proto {
    ENDPOINT_PROTO_NONE  = 0,
    ENDPOINT_PROTO_TCP   = (1 << 0),
    _endpoint_proto_last
} endpoint_proto_t;

// Endpoint flags
// These flags are stored on at least a 32-bit integer
// The 16 first bits are private and only used internally
// The 16 last bits are public and can be exchanged with other nodes
typedef enum endpoint_flags {
    ENDPOINT_FLAG_NONE          = 0u,           // No flags

    // Private flags (internal)
    ENDPOINT_FLAG_CAN_EXPIRE    = (1u << 0),    // If set, the endpoint can be deleted when it expires
    ENDPOINT_FLAG_EXPIRY_LOCAL  = (1u << 1),    // If set, the endpoint's expiration delay is smaller

    // Public flags
    ENDPOINT_FLAG_EPHEMERAL     = (1u << 16),   // If set, the endpoint is very likely unreachable
                                                // It will have a lower priority, faster expiration and may be ignored by other nodes
                                                // It should be used when exchanging endpoints with specific nodes (like external network addresses)
} endpoint_flags_t;

typedef struct endpoint endpoint_t;
typedef struct endpoint_group endpoint_group_t;

#define ENDPOINT_HOSTNAME_MAXLEN (255)
struct __attribute__((packed)) endpoint_hostname {
    uint16_t port;
    char hostname[ENDPOINT_HOSTNAME_MAXLEN + 1];
};

struct __attribute__((packed)) endpoint_ip4 {
    uint16_t port;
    struct in_addr addr;
};

struct __attribute__((packed)) endpoint_ip6 {
    uint16_t port;
    struct in6_addr addr;
};

typedef union endpoint_data {
    struct endpoint_hostname host;
    struct endpoint_ip4 ip4;
    struct endpoint_ip6 ip6;
} endpoint_data_t;

#define ENDPOINT_ADDRSTR_MAXLEN (ENDPOINT_HOSTNAME_MAXLEN + 8)

struct endpoint {
    // Type of the address data
    endpoint_type_t type;

    // Address data
    endpoint_data_t data;

    // Socket protocol(s) with which the endpoint can be used
    endpoint_proto_t proto;

    // Presentation string of the socket address/port
    char *addrstr;
    size_t addrstr_size;

    endpoint_flags_t flags;

    // Timestamp after which the endpoint expires
    struct timespec expire_after;

    // This variable is set by endpoint_group_del_expired() to mark expired
    // endpoints that are not deleted
    bool had_expired;

    netarea_t area;
    int priority;

    // Next endpoint in the linked list (when part of an endpoint_group_t)
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

const char *endpoint_type_name(const endpoint_type_t type);

endpoint_t *endpoint_create(const char *value, const uint16_t port,
    const endpoint_proto_t proto, const endpoint_flags_t flags);
void endpoint_free(endpoint_t *endpoint);
endpoint_t *endpoint_dup(const endpoint_t *original);
void endpoint_set_flags(endpoint_group_t *group, endpoint_t *endpoint,
    const endpoint_flags_t flags);

// true if the endpoint has flag ENDPOINT_FLAG_CAN_EXPIRE
static inline bool endpoint_can_expire(const endpoint_t *endpoint)
{
    return (endpoint->flags & ENDPOINT_FLAG_CAN_EXPIRE) != 0;
}

endpoint_group_t *endpoint_group_create(const char *owner_name, const char *debug_id);
void endpoint_group_free(endpoint_group_t *group);
void endpoint_group_clear(endpoint_group_t *group);

endpoint_t *endpoint_group_find(endpoint_group_t *group, const endpoint_t *endpoint);
endpoint_t *endpoint_group_find_exact(endpoint_group_t *group, const endpoint_t *endpoint);
endpoint_t *endpoint_group_find_after(endpoint_t *after,const endpoint_t *endpoint);
endpoint_t *endpoint_group_find_exact_after(endpoint_t *after, const endpoint_t *endpoint);
endpoint_t *endpoint_group_find_duplicate(endpoint_group_t *group, const endpoint_t *endpoint);

endpoint_t *endpoint_group_insert_back(endpoint_group_t *group,
    const endpoint_t *endpoint);
endpoint_t *endpoint_group_insert_after(endpoint_t *after, endpoint_group_t *group,
    const endpoint_t *endpoint);
bool endpoint_group_insert_sorted(endpoint_group_t *group,
    const endpoint_t *original, const endpoint_t **inserted_endpoint);
void endpoint_group_insert_group(endpoint_group_t *dest,
    const endpoint_group_t *src);

void endpoint_group_del(endpoint_group_t *group, endpoint_t *endpoint);
bool endpoint_group_del_expired(endpoint_group_t *group, time_t *next_expire,
    endpoint_flags_t *expired_flags, const struct timespec *now);

bool endpoint_lookup(endpoint_t *endpoint, endpoint_group_t *group);
bool endpoint_to_sockaddr(struct sockaddr *sa, const socklen_t sa_len,
    const endpoint_t *endpoint);
endpoint_t *endpoint_from_sockaddr(const struct sockaddr *sa, const socklen_t sa_len,
    const endpoint_proto_t proto, const endpoint_flags_t flags);

bool endpoint_to_packet(const endpoint_t *endpoint,
    oshpacket_endpoint_t *pkt, endpoint_data_t *data, size_t *data_size);
endpoint_t *endpoint_from_packet(const oshpacket_endpoint_t *pkt,
    const endpoint_data_t *data, const size_t data_size);

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
