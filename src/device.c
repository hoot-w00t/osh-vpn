#include "oshd.h"
#include "oshd_cmd.h"
#include "device_mode.h"
#include "netpacket.h"
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
    netpacket_t pkt_hdr;
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
    if (!netpacket_from_data(&pkt_hdr, data->buf, oshd.tuntap->is_tap)) {
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

    if (logger_is_debugged(DBG_TUNTAP)) {
        char pkt_src[INET6_ADDRSTRLEN];
        char pkt_dest[INET6_ADDRSTRLEN];

        netaddr_ntop(pkt_src, sizeof(pkt_src), &pkt_hdr.src);
        netaddr_ntop(pkt_dest, sizeof(pkt_dest), &pkt_hdr.dest);

        logger_debug(DBG_TUNTAP, "%s: %s: %s -> %s (%zu bytes, to %s)",
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
static void stable_addr_hash(uint8_t dest[EVP_MAX_MD_SIZE], size_t seed)
{
    char str[(NODE_NAME_SIZE * 2) + 32];
    int r;
    unsigned int h_size;

    memset(str, 0, sizeof(str));

    r = snprintf(str, sizeof(str), "%s%s%zu",
        oshd.network_name, oshd.name, seed);
    if (r <= 0 || r == sizeof(str))
        logger(LOG_WARN, "stable_addr_hash: truncated string");

    memset(dest, 0, EVP_MAX_MD_SIZE);
    hash_sha3_512(str, strlen(str), dest, &h_size);
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
// Sets environment variable OSHD_DYNAMIC_PREFIX6
void device_dynamic_gen_prefix6(void)
{
    uint8_t h[EVP_MAX_MD_SIZE];
    unsigned int h_size;

    memset(h, 0, sizeof(h));
    hash_sha3_512(oshd.network_name, strlen(oshd.network_name), h, &h_size);

    oshd.dynamic_prefixlen6 = 64;

    oshd.dynamic_prefix6.type = IP6;
    memset(&oshd.dynamic_prefix6.data.ip6, 0, sizeof(oshd.dynamic_prefix6.data.ip6));
    memcpy(&oshd.dynamic_prefix6.data.ip6, h, oshd.dynamic_prefixlen6 / 8);
    oshd.dynamic_prefix6.data.b[0] = 0xfd;

    netaddr_ntop(oshd.dynamic_prefix6_str, sizeof(oshd.dynamic_prefix6_str),
        &oshd.dynamic_prefix6);

    oshd_cmd_setenv("OSHD_DYNAMIC_PREFIX6", oshd.dynamic_prefix6_str);
}

// Generate a stable IPv4 prefix
// Initializes oshd.dynamic_prefix4, oshd.dynamic_prefixlen4 and
// oshd.dynamic_prefix4_str
// Sets environment variable OSHD_DYNAMIC_PREFIX4
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

    oshd_cmd_setenv("OSHD_DYNAMIC_PREFIX4", oshd.dynamic_prefix4_str);
}

// Generate a stable dynamic IPv6 address
// The IPv6 prefix must have been generated before calling this function
void device_dynamic_gen_addr6_stable(dynamic_addr_t *daddr, size_t seed)
{
    uint8_t hash[EVP_MAX_MD_SIZE];

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
    uint8_t hash[EVP_MAX_MD_SIZE];

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

// Set environment variables OSHD_DYNAMIC_ADDR and OSHD_DYNAMIC_PREFIXLEN with
// the dynamic address' values
// Returns false on error
static bool set_dynamic_addr_env(const dynamic_addr_t *daddr)
{
    return    oshd_cmd_setenv("OSHD_DYNAMIC_ADDR",      daddr->addr_str)
           && oshd_cmd_setenv("OSHD_DYNAMIC_PREFIXLEN", daddr->prefixlen_str);
}

// Add the dynamic address to the TUN/TAP device
// Returns false on error
bool device_dynamic_add(const dynamic_addr_t *daddr)
{
    if (!set_dynamic_addr_env(daddr))
        return false;

    switch (daddr->addr.type) {
        case IP6: return oshd_cmd_execute("DynamicAddIP6");
        case IP4: return oshd_cmd_execute("DynamicAddIP4");
        default: return false;
    }
}

// Delete the dynamic address from the TUN/TAP device
// Returns false on error
bool device_dynamic_del(const dynamic_addr_t *daddr)
{
    if (!set_dynamic_addr_env(daddr))
        return false;

    switch (daddr->addr.type) {
        case IP6: return oshd_cmd_execute("DynamicDelIP6");
        case IP4: return oshd_cmd_execute("DynamicDelIP4");
        default: return false;
    }
}

#if PLATFORM_IS_LINUX

#define ip_bin         "/sbin/ip"
#define ip_dev         "dev \"$OSHD_DEVICE\""
#define ip_addr_prefix "\"$OSHD_DYNAMIC_ADDR/$OSHD_DYNAMIC_PREFIXLEN\""

#define ip_link_up   ip_bin " link set up " ip_dev
#define ip_link_down ip_bin " link set down " ip_dev

#define ip_addr_add  ip_bin " addr add " ip_addr_prefix " " ip_dev
#define ip_addr_del  ip_bin " addr del " ip_addr_prefix " " ip_dev

void device_dynamic_init_commands(void)
{
    oshd_cmd_tryset("DynamicEnableDev",  ip_link_up);
    oshd_cmd_tryset("DynamicDisableDev", ip_link_down);
    oshd_cmd_tryset("DynamicAddIP6", ip_addr_add);
    oshd_cmd_tryset("DynamicAddIP4", ip_addr_add);
    oshd_cmd_tryset("DynamicDelIP6", ip_addr_del);
    oshd_cmd_tryset("DynamicDelIP4", ip_addr_del);
}

#elif PLATFORM_IS_WINDOWS

#define netsh_bin "C:\\Windows\\System32\\netsh.exe"

#define ip6_iface "interface ipv6"
#define ip4_iface "interface ipv4"

#define ip6_dev "interface=\"%OSHD_DEVICE%\""
#define ip4_dev "name=\"%OSHD_DEVICE%\""

#define ip_addr "address=\"%OSHD_DYNAMIC_ADDR%\""
#define ip_addr_prefix "address=\"%OSHD_DYNAMIC_ADDR%/%OSHD_DYNAMIC_PREFIXLEN%\""

void device_dynamic_init_commands(void)
{
    oshd_cmd_tryset("DynamicAddIP6", netsh_bin " " ip6_iface " add addr " ip6_dev " " ip_addr_prefix);
    oshd_cmd_tryset("DynamicAddIP4", netsh_bin " " ip4_iface " add addr " ip4_dev " " ip_addr_prefix);
    oshd_cmd_tryset("DynamicDelIP6", netsh_bin " " ip6_iface " del addr " ip6_dev " " ip_addr);
    oshd_cmd_tryset("DynamicDelIP4", netsh_bin " " ip4_iface " del addr " ip4_dev " " ip_addr);
}

#else
#warning "Unsupported platform for device_dynamic_init_commands"

void device_dynamic_init_commands(void)
{
}
#endif
