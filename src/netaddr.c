#include "netaddr.h"
#include "xalloc.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>

// Lookup hostname and place the resolved address in addr
// Returns false on error (errors are not logged)
bool netaddr_lookup(netaddr_t *addr, const char *hostname)
{
    struct addrinfo *addrinfo = NULL;
    bool success;

    if (getaddrinfo(hostname, NULL, NULL, &addrinfo))
        return false;

    switch (addrinfo->ai_family) {
        case AF_INET:
            success = netaddr_dton(addr, IP4,
                &((struct sockaddr_in *) addrinfo->ai_addr)->sin_addr);
            break;

        case AF_INET6:
            success = netaddr_dton(addr, IP6,
                &((struct sockaddr_in6 *) addrinfo->ai_addr)->sin6_addr);
            break;

        default:
            success = false;
            break;
    }
    freeaddrinfo(addrinfo);
    return success;
}

// Convert netaddr_t data to a text address in *dest
bool netaddr_ntop(char *dest, size_t maxlen, const netaddr_t *addr)
{
    switch (addr->type) {
        case MAC:
            snprintf(dest, maxlen, "%02x:%02x:%02x:%02x:%02x:%02x",
                addr->data.mac.addr[0],
                addr->data.mac.addr[1],
                addr->data.mac.addr[2],
                addr->data.mac.addr[3],
                addr->data.mac.addr[4],
                addr->data.mac.addr[5]);
            return true;

        case IP4:
            return inet_ntop(AF_INET, &addr->data.ip4, dest, maxlen) != NULL;

        case IP6:
            return inet_ntop(AF_INET6, &addr->data.ip6, dest, maxlen) != NULL;

        default:
            return false;
    }
}

// Convert IP4/IP6 netaddr_t to a text address:port
bool netaddr_ntop2(char *dest, size_t maxlen, const netaddr_t *addr,
    const uint16_t port)
{
    char tmp[INET6_ADDRSTRLEN];

    switch (addr->type) {
        case IP4:
            if (!inet_ntop(AF_INET, &addr->data.ip4, tmp, sizeof(tmp)))
                return false;

            snprintf(dest, maxlen, "%s:%u", tmp, port);
            return true;

        case IP6:
            if (!inet_ntop(AF_INET6, &addr->data.ip6, tmp, sizeof(tmp)))
                return false;

            snprintf(dest, maxlen, "[%s]:%u", tmp, port);
            return true;

        default:
            return false;
    }
}

// Convert text address to netaddr_t data and put it into *dest
bool netaddr_pton(netaddr_t *dest, const char *data)
{
    unsigned int buf[6];

    if (sscanf(data, "%2x:%2x:%2x:%2x:%2x:%2x",
               &buf[0], &buf[1], &buf[2],
               &buf[3], &buf[4], &buf[5]) == 6)
    {
        dest->type = MAC;
        dest->data.mac.addr[0] = (uint8_t) buf[0];
        dest->data.mac.addr[1] = (uint8_t) buf[1];
        dest->data.mac.addr[2] = (uint8_t) buf[2];
        dest->data.mac.addr[3] = (uint8_t) buf[3];
        dest->data.mac.addr[4] = (uint8_t) buf[4];
        dest->data.mac.addr[5] = (uint8_t) buf[5];
        return true;

    } else if (inet_pton(AF_INET, data, &dest->data.ip4) > 0) {
        dest->type = IP4;
        return true;

    } else if (inet_pton(AF_INET6, data, &dest->data.ip6) > 0) {
        dest->type = IP6;
        return true;

    } else {
        return false;
    }
}

// Convert network address data to netaddr_t and put it into *dest
// Depending on type, data should point to:
//     MAC: struct netaddr_data_mac
//     IP4: struct in_addr
//     IP6: struct in6_addr
bool netaddr_dton(netaddr_t *dest, netaddr_type_t type, const void *data)
{
    dest->type = type;
    switch (type) {
        case MAC:
            dest->data.mac = *((struct netaddr_data_mac *) data);
            return true;

        case IP4:
            dest->data.ip4 = *((struct in_addr *) data);
            return true;

        case IP6:
            dest->data.ip6 = *((struct in6_addr *) data);
            return true;

        default:
            return false;
    }
}

// Copy netaddr from *src to *dest
void netaddr_cpy(netaddr_t *dest, const netaddr_t *src)
{
    memcpy(dest, src, sizeof(netaddr_t));
}

// Returns an allocated copy of *src
netaddr_t *netaddr_dup(netaddr_t *src)
{
    netaddr_t *dup = xalloc(sizeof(netaddr_t));

    netaddr_cpy(dup, src);
    return dup;
}

// Returns true if *s1 and *s2 are equal
bool netaddr_eq(const netaddr_t *s1, const netaddr_t *s2)
{
    if (s1->type != s2->type)
        return false;

    switch (s1->type) {
    case MAC: return !memcmp(&s1->data.mac, &s2->data.mac, sizeof(s1->data.mac));
    case IP4: return !memcmp(&s1->data.ip4, &s2->data.ip4, sizeof(s1->data.ip4));
    case IP6: return !memcmp(&s1->data.ip6, &s2->data.ip6, sizeof(s1->data.ip6));
     default: return false;
    }
}

// Create a network mask from cidr
// The address type is left unchanged
void netaddr_mask_from_cidr(netaddr_t *mask, cidr_t cidr)
{
    if (cidr > 128)
        cidr = 128;

    memset(&mask->data, 0, sizeof(mask->data.b));
    for (cidr_t i = 0; i < cidr; ++i)
        mask->data.b[(i / 8)] |= (1 << (7 - (i % 8)));
}

// Returns the CIDR from a network mask
cidr_t netaddr_cidr_from_mask(const netaddr_t *mask)
{
    cidr_t cidr = 0;

    while (mask->data.b[(cidr / 8)] & (1 << (7 - (cidr % 8))))
        ++cidr;
    return cidr;
}

// Masks addr using mask to masked_addr
// Set the masked_addr->type to addr->type, ignores mask->type
void netaddr_mask(netaddr_t *masked_addr, const netaddr_t *addr,
    const netaddr_t *mask)
{
    masked_addr->type = addr->type;
    for (size_t i = 0; i < sizeof(masked_addr->data.b); ++i)
        masked_addr->data.b[i] = addr->data.b[i] & mask->data.b[i];
}

// Masks addr using cidr to masked_addr
// Set the masked_addr->type to addr->type
// This is a wrapper that creates a mask and uses netaddr_mask
void netaddr_mask_cidr(netaddr_t *masked_addr, const netaddr_t *addr,
    cidr_t cidr)
{
    netaddr_t mask;

    netaddr_mask_from_cidr(&mask, cidr);
    netaddr_mask(masked_addr, addr, &mask);
}

// Returns true if *addr is all zero
bool netaddr_is_zero(const netaddr_t *addr)
{
    const uint8_t zero[16] = {0};

    switch (addr->type) {
        case MAC: return !memcmp(&addr->data.mac, zero, sizeof(addr->data.mac));
        case IP4: return !memcmp(&addr->data.ip4, zero, sizeof(addr->data.ip4));
        case IP6: return !memcmp(&addr->data.ip6, zero, sizeof(addr->data.ip6));
         default: return false;
    }
}

// Returns true if *addr is a loopback address
bool netaddr_is_loopback(const netaddr_t *addr)
{
    switch (addr->type) {
        case IP4:
            return NETADDR_IP4_NET(addr, 0xff000000, 0x7f000000);

        case IP6:
            return IN6_IS_ADDR_LOOPBACK(&addr->data.ip6);

        default:
            return false;
    }
}

// Returns the area of addr
netarea_t netaddr_area(const netaddr_t *addr)
{
    switch (addr->type) {
        case IP4: {
            if (   NETADDR_IP4_NET(addr, 0xff000000, 0x0a000000)  // 10.0.0.0/8
                || NETADDR_IP4_NET(addr, 0xfff00000, 0xac100000)  // 172.16.0.0/12
                || NETADDR_IP4_NET(addr, 0xffff0000, 0xc0a80000)) // 192.168.0.0/16
            {
                return NETAREA_LAN;
            }

            return NETAREA_WAN;
        }

        case IP6:
            if (   IN6_IS_ADDR_LINKLOCAL(&addr->data.ip6)
                || IN6_IS_ADDR_SITELOCAL(&addr->data.ip6))
            {
                return NETAREA_LAN;
            }

            return NETAREA_WAN;

        default: return NETAREA_UNK;
    }
}