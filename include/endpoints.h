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

// Endpoints expire after 60 minutes
#define ENDPOINT_EXPIRY (3600)

typedef enum endpoint_type endpoint_type_t;
typedef enum endpoint_socktype endpoint_socktype_t;
typedef struct endpoint endpoint_t;
typedef struct endpoint_group endpoint_group_t;

// Type of the endpoint's value
enum endpoint_type {
    ENDPOINT_TYPE_UNKNOWN = 0,
    ENDPOINT_TYPE_HOSTNAME,
    ENDPOINT_TYPE_IP4,
    ENDPOINT_TYPE_IP6,
    _endpoint_type_last
};

// Socket types with which the endpoint is compatible
enum endpoint_socktype {
    ENDPOINT_SOCKTYPE_NONE  = 0,
    ENDPOINT_SOCKTYPE_TCP   = (1 << 0),
    _endpoint_socktype_last
};

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

    // Socket type(s) with which the endpoint can be used
    endpoint_socktype_t socktype;

    // Presentation string of the socket address/port
    char *addrstr;
    size_t addrstr_size;

    bool can_expire;
    struct timespec last_refresh;

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
    const endpoint_socktype_t socktype, const bool can_expire);
void endpoint_free(endpoint_t *endpoint);
endpoint_t *endpoint_dup(const endpoint_t *original);

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
endpoint_t *endpoint_group_insert_sorted(endpoint_group_t *group,
    const endpoint_t *original);
void endpoint_group_insert_group(endpoint_group_t *dest,
    const endpoint_group_t *src);

void endpoint_group_del(endpoint_group_t *group, endpoint_t *endpoint);
bool endpoint_group_del_expired(endpoint_group_t *group, node_id_t *owner);

bool endpoint_lookup(endpoint_t *endpoint, endpoint_group_t *group);
bool endpoint_to_sockaddr(struct sockaddr *sa, const socklen_t sa_len,
    const endpoint_t *endpoint);
endpoint_t *endpoint_from_sockaddr(const struct sockaddr *sa, const socklen_t sa_len,
    const endpoint_socktype_t socktype, const bool can_expire);

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
