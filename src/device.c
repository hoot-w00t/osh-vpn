#include "oshd.h"
#include "oshd_cmd.h"
#include "device_mode.h"
#include "random.h"
#include "logger.h"
#include "macros.h"
#include "xalloc.h"
#include "crypto/hash.h"
#include <string.h>
#include <errno.h>
#include <unistd.h>

#if (TUNTAP_BUFSIZE > OSHPACKET_PAYLOAD_MAXSIZE)
#warning "TUNTAP_BUFSIZE is bigger than OSHPACKET_PAYLOAD_MAXSIZE, this may lead to packet loss"
#endif

// AIO userdata structure for the TUN/TAP device
typedef struct device_aio_data {
    uint8_t buf[TUNTAP_BUFSIZE];
} device_aio_data_t;

// Error callback for the TUN/TAP device
// Stops the daemon on any error
static void device_aio_error(aio_event_t *event, aio_poll_event_t revents)
{
    logger(LOG_CRIT, "TUN/TAP device error (fd: " PRI_AIO_FD_T ", revents: " AIO_PE_FMT ")",
        event->fd, revents);
    aio_event_del(event);
    oshd_stop();
}

// Read callback of the TUN/TAP device
// Read available packets from the device and route them on the network
// TODO: Refactor this to use the TUN/TAP device from userdata instead of the
//       global one
//       Not sure why Osh would ever need to manage multiple TUN/TAP devices but
//       it would be cleaner anyways
static void device_aio_read(aio_event_t *event)
{
    node_id_t *me = node_id_find_local();
    device_aio_data_t *data = (device_aio_data_t *) event->userdata;
    size_t pkt_size;
    tuntap_packethdr_t pkt_hdr;
    const netroute_t *route;

    // Only process packets from the TUN/TAP device if the daemon is running
    if (!oshd.run)
        return;

    if (!tuntap_read(oshd.tuntap, data->buf, sizeof(data->buf), &pkt_size)) {
        oshd_stop();
        return;
    }
    if (pkt_size == 0)
        return;

    // Decode the packet's header
    if (!tuntap_parse_packethdr(oshd.tuntap, &pkt_hdr, data->buf, pkt_size)) {
        logger(LOG_CRIT, "%s: Failed to parse network packet",
            oshd.tuntap->dev_name);
        return;
    }

    // Lookup the source address in the routing table, if it doesn't exist or
    // another node owns it, take ownership and advertise it
    route = netroute_lookup(oshd.route_table, &pkt_hdr.src);
    if (!route || (route->owner != me && route->owner != NULL)) {
        netroute_add(oshd.route_table, &pkt_hdr.src,
            netaddr_max_prefixlen(pkt_hdr.src.type), me, ROUTE_LOCAL_EXPIRY);
        client_queue_route_add_local(NULL, &pkt_hdr.src, 1, true);
    }

    // Lookup the destination address, if there is no route or we own it, drop
    // the packet
    route = netroute_lookup(oshd.route_table, &pkt_hdr.dest);
    if (!route || route->owner == me)
        return;

    if (route->owner) {
        // This can fail if we don't have a route to the destination node
        // (which should not happen in this case as routes owned by offline
        //  nodes are removed)
        client_queue_packet_data(route->owner, data->buf, pkt_size);
    } else {
        // This route is a broadcast
        client_queue_packet_data_broadcast(NULL, data->buf, pkt_size);
    }

    if (logger_is_debugged(DBG_TUNTAP_TRAFFIC)) {
        char pkt_src[NETADDR_ADDRSTRLEN];
        char pkt_dest[NETADDR_ADDRSTRLEN];

        netaddr_ntop(pkt_src, sizeof(pkt_src), &pkt_hdr.src);
        netaddr_ntop(pkt_dest, sizeof(pkt_dest), &pkt_hdr.dest);

        logger_debug(DBG_TUNTAP_TRAFFIC, "%s: %s: %s -> %s (%zu bytes, to %s)",
            oshd.tuntap->dev_name, oshd.name, pkt_src, pkt_dest, pkt_size,
            netroute_owner_name(route));
    }
}

static void device_aio_del(aio_event_t *event)
{
    free(event->userdata);

    // The TUN/TAP device itself is not closed here because it is not tied to
    // this event
}

// Add an aio event for the TUN/TAP device
void device_add(tuntap_t *tuntap)
{
    aio_event_t event;

    aio_event_init_base(&event);
    tuntap_init_aio_event(tuntap, &event);

    // TODO: Maybe check that tuntap_init_aio_event() didn't modify callbacks,
    //       userdata and poll events

    event.poll_events = AIO_READ;
    event.userdata = xzalloc(sizeof(device_aio_data_t));
    event.cb_add = NULL;
    event.cb_delete = device_aio_del;
    event.cb_read = device_aio_read;
    event.cb_write = NULL;
    event.cb_error = device_aio_error;

    aio_event_add(oshd.aio, &event);
}

// Compute a hash using the network name, node name and the seed
// This is used to create pseudo-random stable IP addresses
static void stable_addr_hash(uint8_t dest[HASH_SHA3_512_SIZE], size_t seed)
{
    char str[(NODE_NAME_SIZE * 2) + 32];
    int r;

    memset(str, 0, sizeof(str));

    r = snprintf(str, sizeof(str), "%s%s%zu",
        oshd.network_name, oshd.name, seed);
    if (r <= 0 || r == sizeof(str))
        logger(LOG_WARN, "stable_addr_hash: truncated string");

    memset(dest, 0, HASH_SHA3_512_SIZE);
    hash_oneshot(HASH_SHA3_512, dest, HASH_SHA3_512_SIZE, str, strlen(str));
}

// Initialize other member variables of a dynamic address using its address
// The address must be set before
static void dynamic_addr_format(dynamic_addr_t *daddr,
    netaddr_prefixlen_t prefixlen)
{
    daddr->route_prefixlen = netaddr_max_prefixlen(daddr->addr.type);
    daddr->prefixlen = daddr->route_prefixlen;
    if (prefixlen < daddr->prefixlen)
        daddr->prefixlen = prefixlen;

    netaddr_ntop(daddr->addr_str, sizeof(daddr->addr_str), &daddr->addr);
    snprintf(daddr->prefixlen_str, sizeof(daddr->prefixlen_str),
        "%u", daddr->prefixlen);
}

// Generate dynamic IPv4 address using 8 bytes from data_len
static void dynamic_addr_v4(netaddr_t *addr, const void *data, size_t data_len)
{
    uint32_t v[2];

    if (data_len < sizeof(v)) {
        memset(v, 0, sizeof(v));
    } else {
        memcpy(v, data, sizeof(v));
    }

    netaddr_cpy(addr, &oshd.dynamic_prefix4);

    // 169.254.0.0/24 and 169.254.255.0/24 are reserved
    addr->data.b[2] = (v[0] % 254) + 1;
    addr->data.b[3] = v[1] % 256;
}

// Generate a stable IPv6 prefix from the network name
// Initializes oshd.dynamic_prefix6, oshd.dynamic_prefixlen6 and
// oshd.dynamic_prefix6_str
// Sets environment variable CMD_ENV_DYNAMIC_PREFIX6
void device_dynamic_gen_prefix6(void)
{
    uint8_t h[HASH_SHA3_512_SIZE];

    memset(h, 0, sizeof(h));
    hash_oneshot(HASH_SHA3_512, h, sizeof(h), oshd.network_name, strlen(oshd.network_name));

    oshd.dynamic_prefixlen6 = 64;

    oshd.dynamic_prefix6.type = IP6;
    memset(&oshd.dynamic_prefix6.data.ip6, 0, sizeof(oshd.dynamic_prefix6.data.ip6));
    memcpy(&oshd.dynamic_prefix6.data.ip6, h, oshd.dynamic_prefixlen6 / 8);
    oshd.dynamic_prefix6.data.b[0] = 0xfd;

    netaddr_ntop(oshd.dynamic_prefix6_str, sizeof(oshd.dynamic_prefix6_str),
        &oshd.dynamic_prefix6);

    oshd_cmd_setenv(CMD_ENV_DYNAMIC_PREFIX6, oshd.dynamic_prefix6_str);
}

// Generate a stable IPv4 prefix
// Initializes oshd.dynamic_prefix4, oshd.dynamic_prefixlen4 and
// oshd.dynamic_prefix4_str
// Sets environment variable CMD_ENV_DYNAMIC_PREFIX4
void device_dynamic_gen_prefix4(void)
{
    oshd.dynamic_prefixlen4 = 16;

    oshd.dynamic_prefix4.type = IP4;
    oshd.dynamic_prefix4.data.b[0] = 169;
    oshd.dynamic_prefix4.data.b[1] = 254;
    oshd.dynamic_prefix4.data.b[2] = 0;
    oshd.dynamic_prefix4.data.b[3] = 0;

    netaddr_ntop(oshd.dynamic_prefix4_str, sizeof(oshd.dynamic_prefix4_str),
        &oshd.dynamic_prefix4);

    oshd_cmd_setenv(CMD_ENV_DYNAMIC_PREFIX4, oshd.dynamic_prefix4_str);
}

// Generate a stable dynamic IPv6 address
// The IPv6 prefix must have been generated before calling this function
void device_dynamic_gen_addr6_stable(dynamic_addr_t *daddr, size_t seed)
{
    uint8_t hash[HASH_SHA3_512_SIZE];

    stable_addr_hash(hash, seed);
    netaddr_cpy(&daddr->addr, &oshd.dynamic_prefix6);
    memcpy(daddr->addr.data.b + 8, hash, 8);
    dynamic_addr_format(daddr, oshd.dynamic_prefixlen6);
}

// Generate a random dynamic IPv6 address
// The IPv6 prefix must have been generated before calling this function
void device_dynamic_gen_addr6_random(dynamic_addr_t *daddr)
{
    netaddr_cpy(&daddr->addr, &oshd.dynamic_prefix6);
    random_bytes(daddr->addr.data.b + 8, 8);
    dynamic_addr_format(daddr, oshd.dynamic_prefixlen6);
}

// Generate a stable dynamic IPv4 address
// The IPv4 prefix must have been generated before calling this function
void device_dynamic_gen_addr4_stable(dynamic_addr_t *daddr, size_t seed)
{
    uint8_t hash[HASH_SHA3_512_SIZE];

    stable_addr_hash(hash, seed);
    dynamic_addr_v4(&daddr->addr, hash, sizeof(hash));
    dynamic_addr_format(daddr, oshd.dynamic_prefixlen4);
}

// Generate a random dynamic IPv4 address
// The IPv4 prefix must have been generated before calling this function
void device_dynamic_gen_addr4_random(dynamic_addr_t *daddr)
{
    uint32_t data[2];

    random_bytes(data, sizeof(data));
    dynamic_addr_v4(&daddr->addr, data, sizeof(data));
    dynamic_addr_format(daddr, oshd.dynamic_prefixlen4);
}

// Add the dynamic address to the TUN/TAP device
// Returns false on error
bool device_dynamic_add(tuntap_t *tuntap, const dynamic_addr_t *daddr)
{
    return oshd_cmd_add_ip(tuntap->dev_name, &daddr->addr, daddr->prefixlen);
}

// Delete the dynamic address from the TUN/TAP device
// Returns false on error
bool device_dynamic_del(tuntap_t *tuntap, const dynamic_addr_t *daddr)
{
    return oshd_cmd_del_ip(tuntap->dev_name, &daddr->addr, daddr->prefixlen);
}
