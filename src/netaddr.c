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
bool netaddr_ntop(char *dest, uint32_t maxlen, const netaddr_t *addr)
{
    switch (addr->type) {
        case MAC:
            snprintf(dest, maxlen, "%02x:%02x:%02x:%02x:%02x:%02x",
                     addr->data[0], addr->data[1], addr->data[2],
                     addr->data[3], addr->data[4], addr->data[5]);
            return true;
        case IP4:

            return inet_ntop(AF_INET, addr->data, dest, maxlen) != 0;
        case IP6:
            return inet_ntop(AF_INET6, addr->data, dest, maxlen) != 0;
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
        dest->data[0] = (uint8_t) buf[0];
        dest->data[1] = (uint8_t) buf[1];
        dest->data[2] = (uint8_t) buf[2];
        dest->data[3] = (uint8_t) buf[3];
        dest->data[4] = (uint8_t) buf[4];
        dest->data[5] = (uint8_t) buf[5];
        return true;
    } else if (inet_pton(AF_INET, data, dest->data) > 0) {
        dest->type = IP4;
        return true;
    } else if (inet_pton(AF_INET6, data, dest->data) > 0) {
        dest->type = IP6;
        return true;
    } else {
        return false;
    }
}

// Convert network address data to netaddr_t and put it into *dest
// Depending on type, data should point to:
//     MAC: a 6 bytes array
//     IP4: struct in_addr
//     IP6: struct in6_addr
bool netaddr_dton(netaddr_t *dest, netaddr_type_t type, const void *data)
{
    dest->type = type;
    switch (type) {
        case MAC:
            memcpy(dest->data, data, 6);
            memset(dest->data + 6, 0, sizeof(dest->data) - 6);
            return true;
        case IP4:
            *((in_addr_t *) dest->data) = ((struct in_addr *) data)->s_addr;
            memset(dest->data + 4, 0, sizeof(dest->data) - 4);
            return true;
        case IP6:
            memcpy(dest->data, data, sizeof(struct in6_addr));
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
        case MAC:
            return !memcmp(s1->data, s2->data, 6);
        case IP4:
            return !memcmp(s1->data, s2->data, 4);
        case IP6:
            return !memcmp(s1->data, s2->data, 16);
        default:
            return false;
    }
}

// Create a network mask from cidr
// The address type is left unchanged
void netaddr_mask_from_cidr(netaddr_t *mask, cidr_t cidr)
{
    if (cidr > 128)
        cidr = 128;

    memset(mask->data, 0, 16);
    for (cidr_t i = 0; i < cidr; ++i)
        mask->data[(i / 8)] |= (1 << (cidr % 8));
}

// Returns the CIDR from a network mask
cidr_t netaddr_cidr_from_mask(const netaddr_t *mask)
{
    cidr_t cidr = 0;

    while (mask->data[(cidr / 8)] & (1 << (cidr % 8)))
        ++cidr;
    return cidr;
}

// Masks addr using mask to masked_addr
// Set the masked_addr->type to addr->type, ignores mask->type
void netaddr_mask(netaddr_t *masked_addr, const netaddr_t *addr,
    const netaddr_t *mask)
{
    masked_addr->type = addr->type;
    for (uint8_t i = 0; i < 16; ++i)
        masked_addr->data[i] = addr->data[i] & mask->data[i];
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

// Returns true if *addr is a loopback address
bool netaddr_is_loopback(const netaddr_t *addr)
{
    const uint8_t ip6_loopback[16] = {0, 0, 0, 0, 0, 0, 0, 0,
                                      0, 0, 0, 0, 0, 0, 0, 1};

    switch (addr->type) {
        case IP4:
            return addr->data[0] == 0x7F;
        case IP6:
            return !memcmp(addr->data, ip6_loopback, sizeof(ip6_loopback));
        default:
            return false;
    }
}

// Returns the area of addr
netarea_t netaddr_area(const netaddr_t *addr)
{
    switch (addr->type) {
        case IP4: {
            // 10.0.0.0/8
            if (addr->data[0] == 10)
                return NETAREA_LAN;

            // 172.16.0.0/12
            if (addr->data[0] == 172 && addr->data[1] >= 16 && addr->data[1] <= 31)
                return NETAREA_LAN;

            // 192.168.0.0/16
            if (addr->data[0] == 192 && addr->data[1] == 168)
                return NETAREA_LAN;

            return NETAREA_WAN;
        }

        case IP6:
            return NETAREA_WAN;

        default: return NETAREA_UNK;
    }
}