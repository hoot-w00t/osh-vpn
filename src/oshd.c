#define _OSH_OSHD_C

#include "oshd_cmd.h"
#include "oshd_device.h"
#include "oshd_socket.h"
#include "oshd_route.h"
#include "oshd.h"

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
#include <poll.h>
#include <signal.h>
#include <dirent.h>
#include <ifaddrs.h>
#include <netdb.h>

// Global variable
oshd_t oshd;

static struct pollfd *pfd = NULL;
static size_t pfd_off = 0;
static size_t pfd_count = 0;

// Discover all addresses on the TUN/TAP device and add them to our local routes
void oshd_discover_local_routes(void)
{
    struct ifaddrs *ifaces;
    char addrw[INET6_ADDRSTRLEN];
    netaddr_t addr;

    if (getifaddrs(&ifaces) < 0) {
        logger(LOG_ERR, "getifaddrs: %s", strerror(errno));
        return;
    }

    for (struct ifaddrs *ifa = ifaces; ifa; ifa = ifa->ifa_next) {
        if (   !ifa->ifa_name
            || !ifa->ifa_addr
            || !(   ifa->ifa_addr->sa_family == AF_INET
                 || ifa->ifa_addr->sa_family == AF_INET6))
        {
            // Skip this entry if it has no name, no address or an address
            // family that is not IPv4/6
            continue;
        }

        size_t af_size = ifa->ifa_addr->sa_family == AF_INET
            ? sizeof(struct sockaddr_in)
            : sizeof(struct sockaddr_in6);

        int err = getnameinfo(ifa->ifa_addr, af_size, addrw, sizeof(addrw),
            NULL, 0, NI_NUMERICHOST);

        if (err) {
            logger(LOG_ERR, "getnameinfo: %s", gai_strerror(err));
            continue;
        }

        memset(&addr, 0, sizeof(addr));
        if (!netaddr_pton(&addr, addrw))
            continue;

        // If this interface is our TUN/TAP device add the address to our
        // local routes
        // If this is a TAP device these addresses will be used for the
        // resolver, the MAC addresses are discovered automatically
        if (   oshd.tuntap
            && (   (oshd.tuntap->dev_name && !strcmp(ifa->ifa_name, oshd.tuntap->dev_name))
                || (oshd.tuntap->dev_id   && !strcmp(ifa->ifa_name, oshd.tuntap->dev_id))))
        {
            oshd_route_add_local(&addr);
            logger(LOG_INFO, "Discovered local route %s (%s)", addrw,
                oshd.tuntap->dev_name);
        }
    }

    freeifaddrs(ifaces);
}

// Discover endpoints from the network devices (excluding the TUN/TAP device and
// the devices explicitly excluded)
// Clear the previous endpoints of the local node and add those new endpoints
void oshd_discover_local_endpoints(void)
{
    struct ifaddrs *ifaces;
    char addrw[INET6_ADDRSTRLEN];
    netaddr_t addr;
    node_id_t *local_id = node_id_find_local();

    endpoint_group_clear(local_id->endpoints);

    if (getifaddrs(&ifaces) < 0) {
        logger(LOG_ERR, "getifaddrs: %s", strerror(errno));
        return;
    }

    for (struct ifaddrs *ifa = ifaces; ifa; ifa = ifa->ifa_next) {
        if (   !ifa->ifa_name
            || !ifa->ifa_addr
            || !(   ifa->ifa_addr->sa_family == AF_INET
                 || ifa->ifa_addr->sa_family == AF_INET6))
        {
            // Skip this entry if it has no name, no address or an address
            // family that is not IPv4/6
            continue;
        }

        // If this interface is our TUN/TAP device, skip it
        if (   oshd.tuntap
            && (   (oshd.tuntap->dev_name && !strcmp(ifa->ifa_name, oshd.tuntap->dev_name))
                || (oshd.tuntap->dev_id   && !strcmp(ifa->ifa_name, oshd.tuntap->dev_id))))
        {
            continue;
        }

        size_t af_size = ifa->ifa_addr->sa_family == AF_INET
            ? sizeof(struct sockaddr_in)
            : sizeof(struct sockaddr_in6);

        int err = getnameinfo(ifa->ifa_addr, af_size, addrw, sizeof(addrw),
            NULL, 0, NI_NUMERICHOST);

        if (err) {
            logger(LOG_ERR, "getnameinfo: %s", gai_strerror(err));
            continue;
        }

        memset(&addr, 0, sizeof(addr));
        if (!netaddr_pton(&addr, addrw))
            continue;

        // TODO: Add a parameter allow which interfaces can be discovered
        //       instead of excluding those that shouldn't be

        // Check if this device is excluded
        bool excluded = false;

        for (size_t i = 0; i < oshd.excluded_devices_count; ++i) {
            if (!strcmp(ifa->ifa_name, oshd.excluded_devices[i])) {
                excluded = true;
                break;
            }
        }
        if (excluded) {
            logger_debug(DBG_OSHD, "Excluded device: %s (%s)", addrw, ifa->ifa_name);
            continue;
        }

        // Zeroed out addresses are obviously not valid
        if (netaddr_is_zero(&addr)) {
            logger_debug(DBG_OSHD, "Ignoring zeroed: %s (%s)", addrw, ifa->ifa_name);
            continue;
        }

        // Otherwise if this address is a loopback address, ignore it
        if (netaddr_is_loopback(&addr)) {
            logger_debug(DBG_OSHD, "Ignoring loopback: %s (%s)", addrw, ifa->ifa_name);
            continue;
        }

        // Finally discover the local endpoint
        logger_debug(DBG_ENDPOINTS, "Discovered %s endpoint: %s (%s)",
            netarea_name(netaddr_area(&addr)), addrw, ifa->ifa_name);
        endpoint_group_add(local_id->endpoints,
            addrw, oshd.server_port, netaddr_area(&addr));
    }

    gettimeofday(&local_id->endpoints_last_update, NULL);
    freeifaddrs(ifaces);
}

// Load a private or a public key from the keys directory
// name should be a node's name
// Returns NULL on error
EVP_PKEY *oshd_open_key(const char *name, bool private)
{
    const size_t filename_len = strlen(oshd.keys_dir) + strlen(name) + 5;
    char *filename = xalloc(filename_len);
    EVP_PKEY *pkey;

    snprintf(filename, filename_len, "%s%s.%s", oshd.keys_dir, name,
        private ? "key" : "pub");
    logger_debug(DBG_OSHD, "Opening %s key '%s'",
        private ? "private" : "public", filename);
    pkey = private ? pkey_load_privkey_pem(filename)
                   : pkey_load_pubkey_pem(filename);
    free(filename);
    return pkey;
}

// Load public keys from the keys directory
// Returns false on error
bool oshd_open_keys(const char *dirname)
{
    DIR *dir = opendir(dirname);
    struct dirent *ent;

    if (!dir) {
        logger(LOG_ERR, "Failed to open %s: %s", dirname, strerror(errno));
        return false;
    }

    while ((ent = readdir(dir))) {
        char *filename = xstrdup(ent->d_name);
        char *ext = strrchr(filename, '.');

        if (ext && !strcmp(ext, ".pub")) {
            // This is a public key file, we extract the node's name by
            // removing the extension
            *ext = 0;

            // filename now contains the node's name
            if (node_valid_name(filename)) {
                node_id_t *id;

                logger_debug(DBG_OSHD, "Opening public key for %s", filename);
                id = node_id_add(filename);
                pkey_free(id->pubkey);
                free(id->pubkey_raw);
                id->pubkey_raw = NULL;
                if ((id->pubkey = oshd_open_key(filename, false))) {
                    id->pubkey_local = true;
                    if (!pkey_save_ed25519_pubkey(id->pubkey, &id->pubkey_raw,
                            &id->pubkey_raw_size))
                    {
                        pkey_free(id->pubkey);
                        id->pubkey = NULL;
                        logger(LOG_ERR, "Failed to export raw public key for %s", id->name);
                    }
                }
            } else {
                logger(LOG_ERR, "Failed to open public key for '%s': Invalid name",
                    filename);
            }
        }
        free(filename);
    }
    closedir(dir);
    return true;
}

// Set file descriptor flag O_NONBLOCK
int set_nonblocking(int fd)
{
    int flags;

    if ((flags = fcntl(fd, F_GETFL, 0)) < 0) return flags;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

// Realloc pfd to hold all file descriptors
static void pfd_resize(void)
{
    pfd_count = pfd_off + oshd.nodes_count;
    pfd = xreallocarray(pfd, pfd_count, sizeof(struct pollfd));
    for (size_t i = 0; i < oshd.nodes_count; ++i) {
        oshd.nodes[i]->pfd = &pfd[i + pfd_off];
        pfd[i + pfd_off].fd = oshd.nodes[i]->fd;
        pfd[i + pfd_off].events = 0;

        if (!oshd.nodes[i]->finish_and_disconnect)
            pfd[i + pfd_off].events |= POLLIN;

        if (   netbuffer_data_size(oshd.nodes[i]->io.sendq)
            || !oshd.nodes[i]->connected)
        {
            pfd[i + pfd_off].events |= POLLOUT;
        }
    }
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
    for (size_t i = 0; i < oshd.nodes_count; ++i) {
        node_reconnect_disable(oshd.nodes[i]);
        if (oshd.nodes[i]->connected) {
            node_queue_goodbye(oshd.nodes[i]);
        } else {
            event_queue_node_remove(oshd.nodes[i]);
        }
    }
}

// Initialize oshd
bool oshd_init(void)
{
    int offset = 0;

    if (oshd.device_mode != MODE_NODEVICE) {
        oshd.tuntap = tuntap_open(oshd.tuntap_devname,
            device_mode_is_tap(oshd.device_mode));

        if (!oshd.tuntap)
            return false;

        setenv("OSHD_DEVICE", oshd.tuntap->dev_name, 1);
        if (!oshd_cmd_execute("DevUp"))
            return false;
        pfd_off += 1;
    }

    if (oshd.server_enabled) {
        if ((oshd.server_fd = tcp4_bind(NULL, oshd.server_port, 10)) < 0)
            return false;
        pfd_off += 1;
    }

    pfd_resize();
    if (oshd.tuntap) {
        pfd[offset].fd = tuntap_pollfd(oshd.tuntap);
        pfd[offset].events = POLLIN;
        offset += 1;
    }
    if (oshd.server_enabled) {
        pfd[offset].fd = oshd.server_fd;
        pfd[offset].events = POLLIN;
        offset += 1;
    }

    // Create our local node's ID in the tree
    node_id_t *me = node_id_add(oshd.name);

    // We are the one and only local node
    me->local_node = true;

    // Load our local node's private
    if (!(oshd.privkey = oshd_open_key(oshd.name, true)))
        return false;

    // Load all public keys in the keys directory
    if (!oshd_open_keys(oshd.keys_dir))
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
    free(oshd.tuntap_devname);
    if (oshd.tuntap) {
        oshd_cmd_execute("DevDown");
        tuntap_close(oshd.tuntap);
    }
    if (oshd.server_fd > 0) {
        close(oshd.server_fd);
    }

    for (size_t i = 0; i < oshd.nodes_count; ++i)
        node_destroy(oshd.nodes[i]);
    free(oshd.nodes);
    free(pfd);

    // We have to reset those in case the event queue tries to remove nodes
    // This is to safely cancel these events
    oshd.nodes_count = 0;
    oshd.nodes = NULL;

    for (size_t i = 0; i < oshd.remote_count; ++i)
        endpoint_group_free(oshd.remote_endpoints[i]);
    free(oshd.remote_endpoints);

    oshd_cmd_unset_all();

    for (size_t i = 0; i < oshd.node_tree_count; ++i)
        node_id_free(oshd.node_tree[i]);
    free(oshd.node_tree);

    free(oshd.local_routes);
    for (size_t i = 0; i < oshd.routes_count; ++i)
        oshd_route_free(oshd.routes[i]);
    free(oshd.routes);

    free(oshd.resolver_tld);
    free(oshd.resolver_file);

    for (size_t i = 0; i < oshd.excluded_devices_count; ++i)
        free(oshd.excluded_devices[i]);
    free(oshd.excluded_devices);

    event_cancel_queue();

    free(oshd.keys_dir);
    pkey_free(oshd.privkey);
    free(oshd.digraph_file);
}

void oshd_loop(void)
{
    int events;

    // Update the resolver with its initial state
    oshd_resolver_update();

    // Discover network devices' addresses
    if (oshd.tuntap)
        oshd_discover_local_routes();
    if (oshd.shareendpoints)
        oshd_discover_local_endpoints();

    // Queue the connections to our remotes
    for (size_t i = 0; i < oshd.remote_count; ++i) {
        oshd_connect_queue(oshd.remote_endpoints[i], oshd.reconnect_delay_min);
    }

    // Osh actually starts
    event_queue_periodic_ping();
    event_queue_periodic_endpoints();

    // We continue running while oshd.run is true and there are still connected
    // nodes
    // When oshd.run is set to false all nodes should gracefully close and the
    // nodes_count should get to 0 before the program can finally exit
    logger_debug(DBG_OSHD, "Entering main loop");
    while (oshd.run || oshd.nodes_count) {
        // Process queued events
        event_process_queued();
        if (oshd.nodes_updated) {
            logger_debug(DBG_OSHD, "Nodes updated, resizing pfd");
            oshd.nodes_updated = false;
            pfd_resize();
        }

        // Poll for events on all sockets and the TUN/TAP device
        events = poll(pfd, pfd_count, 500);
        if (events < 0) {
            // Polling errors can occur when receiving signals, in this case the
            // error isn't actually from the polling so we can ignore it
            if (errno == EINTR)
                continue;

            logger(LOG_CRIT, "poll: %s", strerror(errno));
            oshd_stop();
            return;
        }

        logger_debug(DBG_OSHD, "Polled %i/%zu events", events, pfd_count);

        // We then iterate over all our file descriptors to handle the events
        for (size_t i = 0; events > 0 && i < pfd_count; ++i) {
            if (!pfd[i].revents)
                continue;

            --events;

            if (pfd[i].fd == tuntap_pollfd(oshd.tuntap)) {
                if ((pfd[i].revents & POLLIN) && oshd.run) {
                    // Data is available on the TUN/TAP device
                    oshd_read_tuntap_pkt();
                }
            } else if (pfd[i].fd == oshd.server_fd) {
                if ((pfd[i].revents & POLLIN) && oshd.run) {
                    // The server is ready to accept an incoming connection
                    oshd_accept();
                }
            } else {
                if (pfd[i].revents & (POLLERR | POLLHUP)) {
                    logger(LOG_ERR, "%s: %s", oshd.nodes[i - pfd_off]->addrw,
                        (pfd[i].revents & POLLHUP) ? "socket closed"
                                                   : "socket error");

                    event_queue_node_remove(oshd.nodes[i - pfd_off]);
                } else {
                    if (pfd[i].revents & POLLIN) {
                        // A node is ready to receive data
                        node_recv_queued(oshd.nodes[i - pfd_off]);
                    }
                    if (pfd[i].revents & POLLOUT) {
                        if (!oshd.nodes[i - pfd_off]->connected) {
                            // If a node is not connected yet, we check it to see if the
                            // socket has finished connecting
                            oshd_connect_async(oshd.nodes[i - pfd_off]);
                        } else {
                            // A node is ready to send queued data
                            node_send_queued(oshd.nodes[i - pfd_off]);
                        }
                    }
                }
            }
        }
    }
}