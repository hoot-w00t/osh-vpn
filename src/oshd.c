#define _OSH_OSHD_C

#include "oshd_cmd.h"
#include "oshd_device.h"
#include "oshd_discovery.h"
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

// Global variable
oshd_t oshd;

static struct pollfd *pfd = NULL;
static size_t pfd_off = 0;
static size_t pfd_count = 0;

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
        oshd.server_fd = tcp4_bind(NULL, oshd.server_port, 10);
        oshd.server_fd6 = tcp6_bind(NULL, oshd.server_port, 10);

        // If no server was opened, stop here
        if (oshd.server_fd < 0 && oshd.server_fd6 < 0)
            return false;

        if (oshd.server_fd > 0)
            pfd_off += 1;
        if (oshd.server_fd6 > 0)
            pfd_off += 1;
    }

    pfd_resize();
    if (oshd.tuntap) {
        pfd[offset].fd = tuntap_pollfd(oshd.tuntap);
        pfd[offset].events = POLLIN;
        offset += 1;
    }
    if (oshd.server_enabled) {
        if (oshd.server_fd > 0) {
            pfd[offset].fd = oshd.server_fd;
            pfd[offset].events = POLLIN;
            offset += 1;
        }
        if (oshd.server_fd6 > 0) {
            pfd[offset].fd = oshd.server_fd6;
            pfd[offset].events = POLLIN;
            offset += 1;
        }
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
    if (oshd.server_fd > 0)
        close(oshd.server_fd);
    if (oshd.server_fd6 > 0)
        close(oshd.server_fd6);

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
    free(oshd.node_tree_ordered_hops);

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
    event_queue_endpoints_refresh();
    if (oshd.automatic_connections)
        event_queue_automatic_connections();

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

            if (oshd.tuntap && pfd[i].fd == tuntap_pollfd(oshd.tuntap)) {
                if ((pfd[i].revents & POLLIN) && oshd.run) {
                    // Data is available on the TUN/TAP device
                    oshd_read_tuntap_pkt();
                }
            } else if (pfd[i].fd == oshd.server_fd || pfd[i].fd == oshd.server_fd6) {
                if ((pfd[i].revents & POLLIN) && oshd.run) {
                    // The server is ready to accept an incoming connection
                    oshd_accept(pfd[i].fd);
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