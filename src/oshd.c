#define _OSH_OSHD_C

#include "oshd_cmd.h"
#include "oshd_discovery.h"
#include "oshd_socket.h"
#include "oshd.h"

#include "device.h"
#include "events.h"
#include "tcp.h"
#include "tuntap.h"
#include "xalloc.h"
#include "logger.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

// Global variable
oshd_t oshd;

// Timeout for aio_poll
// Never times out by default (-1)
static ssize_t poll_timeout = -1;

// Set file descriptor flag O_NONBLOCK
int set_nonblocking(int fd)
{
    int flags;

    if ((flags = fcntl(fd, F_GETFL, 0)) < 0) return flags;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

// The first time we get a signal, set oshd_run to false
// If oshd_run is already false, call exit()
static void oshd_signal_exit(int sig)
{
    if (oshd.run) {
        logger_debug(DBG_OSHD, "Received exit signal");
        oshd_stop();
    } else {
        logger(LOG_CRIT, "Uncaught exit signal: %s", strsignal(sig));
        exit(EXIT_FAILURE);
    }
}

// When we get this signal, dump the digraph of the network to stdout
static void oshd_signal_digraph(__attribute__((unused)) int sig)
{
    logger_debug(DBG_OSHD, "Received digraph signal");
    node_tree_dump_digraph();
}

// Stop the daemon
// Set the oshd.run variable to false
// Then for all nodes: disable reconnection and queue GOODBYE packets
void oshd_stop(void)
{
    logger_debug(DBG_OSHD, "Gracefully stopping");
    oshd.run = false;
    poll_timeout = 1000;
    for (size_t i = 0; i < oshd.clients_count; ++i) {
        client_reconnect_disable(oshd.clients[i]);
        if (oshd.clients[i]->connected) {
            client_queue_goodbye(oshd.clients[i]);
        } else {
            aio_event_del(oshd.clients[i]->aio_event);
        }
    }
}

// Initialize oshd
bool oshd_init(void)
{
    oshd.aio = aio_create();

    if (!event_init())
        return false;

    if (oshd.device_mode != MODE_NODEVICE) {
        oshd.tuntap = tuntap_open(oshd.tuntap_devname,
            device_mode_is_tap(oshd.device_mode));

        if (!oshd.tuntap)
            return false;

        // Set the OSHD_DEVICE environment variable to the TUN/TAP device name
        if (!oshd_cmd_setenv("OSHD_DEVICE", oshd.tuntap->dev_name))
            return false;

        device_add(oshd.tuntap);
    }

    if (oshd.server_enabled) {
        int fd4 = tcp4_bind(NULL, oshd.server_port, OSHD_TCP_SERVER_BACKLOG);
        int fd6 = tcp6_bind(NULL, oshd.server_port, OSHD_TCP_SERVER_BACKLOG);

        // If no server was opened, stop here
        if (fd4 < 0 && fd6 < 0)
            return false;

        if (fd4 >= 0)
            oshd_server_add(fd4);
        if (fd6 >= 0)
            oshd_server_add(fd6);
    }

    // Create our local node's ID in the tree
    node_id_t *me = node_id_add(oshd.name);

    // We are the one and only local node
    me->local_node = true;

    // Load our own public key
    logger_debug(DBG_OSHD, "Loading the daemon's public key");
    if (!pkey_save_pubkey(oshd.privkey, &me->pubkey_raw, &me->pubkey_raw_size))
        return false;
    me->pubkey = pkey_load_ed25519_pubkey(me->pubkey_raw, me->pubkey_raw_size);
    if (!me->pubkey)
        return false;
    me->pubkey_local = true;

    // Add the loaded public keys to the tree
    for (size_t i = 0; i < oshd.conf_pubkeys_size; ++i) {
        node_id_t *nid = node_id_add(oshd.conf_pubkeys[i].node_name);

        // The daemon's public key is always obtained from the loaded private
        // key, we can safely ignore public keys for the daemon without throwing
        // an error
        if (nid->local_node) {
            logger_debug(DBG_OSHD, "Ignoring the configured public key for this daemon");
            continue;
        }

        // Load the node's public key
        logger_debug(DBG_OSHD, "Loading the public key for %s", nid->name);
        nid->pubkey = oshd.conf_pubkeys[i].pkey;
        oshd.conf_pubkeys[i].pkey = NULL;
        if (!pkey_save_pubkey(nid->pubkey, &nid->pubkey_raw, &nid->pubkey_raw_size))
            return false;
        nid->pubkey_local = true;
    }

    // Add manually configured local routes
    for (size_t i = 0; i < oshd.conf_routes_size; ++i) {
        netroute_add(oshd.route_table, &oshd.conf_routes[i].addr,
            oshd.conf_routes[i].prefixlen, me, ROUTE_NEVER_EXPIRE);
    }

    // When using the dynamic device mode we automatically find and assign IP
    // addresses to the TUN/TAP device
    if (oshd.device_mode == MODE_DYNAMIC) {
        // Initialize device configuration commands
        device_dynamic_init_commands();

        // Generate IPv4/IPv6 prefixes and addresses
        device_dynamic_gen_prefix6();
        device_dynamic_gen_prefix4();
        if (oshd.dynamic_addr_stable) {
            device_dynamic_gen_addr6_stable(&oshd.dynamic_addrs[0], 0);
            device_dynamic_gen_addr4_stable(&oshd.dynamic_addrs[1], 0);
        } else {
            device_dynamic_gen_addr6_random(&oshd.dynamic_addrs[0]);
            device_dynamic_gen_addr4_random(&oshd.dynamic_addrs[1]);
        }

        // Make sure to enable the TUN/TAP device
        if (!oshd_cmd_execute("DynamicEnableDev"))
            return false;

        logger(LOG_INFO, "Dynamic IPv6 prefix: %s/%u",
            oshd.dynamic_prefix6_str, oshd.dynamic_prefixlen6);
        logger(LOG_INFO, "Dynamic IPv4 prefix: %s/%u",
            oshd.dynamic_prefix4_str, oshd.dynamic_prefixlen4);

        // Add our dynamic addresses to the routing table and configure them on
        // the TUN/TAP device (exit if this fails)
        for (size_t i = 0; i < dynamic_addr_count; ++i) {
            const dynamic_addr_t *daddr = &oshd.dynamic_addrs[i];

            logger(LOG_INFO, "Dynamic address: %s/%s", daddr->addr_str,
                daddr->prefixlen_str);

            netroute_add(oshd.route_table, &daddr->addr, daddr->route_prefixlen,
                me, ROUTE_NEVER_EXPIRE);

            if (!device_dynamic_add(daddr))
                return false;
        }
    }

    // Execute the DevUp command after all TUN/TAP environment variables were set
    if (oshd.tuntap && !oshd_cmd_execute("DevUp"))
        return false;

    signal(SIGINT, oshd_signal_exit);
    signal(SIGTERM, oshd_signal_exit);
    signal(SIGUSR1, oshd_signal_digraph);

    return true;
}

// Free all allocated resources for/by oshd_init/oshd_loop
void oshd_free(void)
{
    oshd.run = false;
    aio_free(oshd.aio);
    free(oshd.tuntap_devname);
    if (oshd.tuntap) {
        // Execute the DevDown command before cleaning up dynamic addresses
        // If the device mode is dynamic
        oshd_cmd_execute("DevDown");

        if (oshd.device_mode == MODE_DYNAMIC) {
            // Delete our dynamic addresses from the TUN/TAP device
            for (size_t i = 0; i < dynamic_addr_count; ++i)
                device_dynamic_del(&oshd.dynamic_addrs[i]);

            // Disable the TUN/TAP device
            oshd_cmd_execute("DynamicDisableDev");
        }

        tuntap_close(oshd.tuntap);
    }
    for (size_t i = 0; i < oshd.clients_count; ++i)
        client_destroy(oshd.clients[i]);
    free(oshd.clients);

    // Free routing tables
    netroute_table_free(oshd.route_table);

    // We have to reset those in case the event queue tries to remove nodes
    // This is to safely cancel these events
    oshd.clients_count = 0;
    oshd.clients = NULL;

    for (size_t i = 0; i < oshd.remote_count; ++i)
        endpoint_group_free(oshd.remote_endpoints[i]);
    free(oshd.remote_endpoints);

    oshd_cmd_unset_all();

    for (size_t i = 0; i < oshd.node_tree_count; ++i)
        node_id_free(oshd.node_tree[i]);
    free(oshd.node_tree);
    free(oshd.node_tree_ordered_hops);

    for (size_t i = 0; i < oshd.excluded_devices_count; ++i)
        free(oshd.excluded_devices[i]);
    free(oshd.excluded_devices);

    event_cancel_queue();

    pkey_free(oshd.privkey);
    free(oshd.digraph_file);

    for (size_t i = 0; i < oshd.conf_pubkeys_size; ++i)
        pkey_free(oshd.conf_pubkeys[i].pkey);
    free(oshd.conf_pubkeys);

    free(oshd.conf_routes);
}

void oshd_loop(void)
{
    ssize_t events;

    // Discover network devices' addresses
    if (oshd.tuntap)
        oshd_discover_local_routes();
    if (oshd.discoverendpoints)
        oshd_discover_local_endpoints();

    // Queue the connections to our remotes
    for (size_t i = 0; i < oshd.remote_count; ++i) {
        oshd_connect_queue(oshd.remote_endpoints[i], oshd.reconnect_delay_min);
    }

    // Osh actually starts
    event_queue_periodic_ping();
    event_queue_expire_endpoints();
    event_queue_expire_routes();
    if (oshd.automatic_connections)
        event_queue_automatic_connections();

    // We continue running while oshd.run is true and there are still connected
    // nodes
    // When oshd.run is set to false all nodes should gracefully close and the
    // clients_count should get to 0 before the program can finally exit
    logger_debug(DBG_OSHD, "Entering main loop");
    while (oshd.run || oshd.clients_count) {
        // Poll for events on all sockets and the TUN/TAP device
        // If timed events use a timerfd they will be triggered by an aio_poll()
        // callback
        // Otherwise we have to call the event_process_queued() function each
        // iteration and we timeout aio_poll() for the next timed event
#ifdef EVENTS_USE_TIMERFD
        events = aio_poll(oshd.aio, poll_timeout);
#else
        // FIXME: Handle poll_timeout
        event_process_queued();
        events = aio_poll(oshd.aio, event_get_timeout_ms());
#endif

        if (events < 0) {
            oshd_stop();
            break;
        }

        logger_debug(DBG_OSHD, "Polled %zi/%zu events",
            events, aio_events_count(oshd.aio));
    }
    logger_debug(DBG_OSHD, "Exiting main loop");
}
