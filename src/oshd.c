#define _OSH_OSHD_C

#include "oshd_script.h"
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

// Global variable
oshd_t oshd;

static struct pollfd *pfd = NULL;
static size_t pfd_off = 0;
static size_t pfd_count = 0;

// Set file descriptor flag O_NONBLOCK
int set_nonblocking(int fd)
{
    int flags;

    if ((flags = fcntl(fd, F_GETFL, 0)) < 0) return flags;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

// Realloc pfd to hold all file descriptors
void pfd_resize(void)
{
    pfd_count = pfd_off + oshd.nodes_count;
    pfd = xrealloc(pfd, sizeof(struct pollfd) * pfd_count);
}

// Update TUN/TAP, server and nodes POLLIN/POLLOUT events
void pfd_update(void)
{
    for (size_t i = 0; i < oshd.nodes_count; ++i) {
        pfd[i + pfd_off].fd = oshd.nodes[i]->fd;
        if (oshd.nodes[i]->io.sendq_ptr) {
            pfd[i + pfd_off].events = POLLIN | POLLOUT;
        } else {
            pfd[i + pfd_off].events = POLLIN;
        }
    }
}

// Add a node
void node_add(node_t *node)
{
    oshd.nodes = xrealloc(oshd.nodes, sizeof(node_t *) * (oshd.nodes_count + 1));
    oshd.nodes[oshd.nodes_count] = node;
    oshd.nodes_count += 1;
    pfd_resize();
    pfd_update();
}

// Remove a node and update pfd
void node_remove(node_t *node)
{
    size_t i;

    for (i = 0; i < oshd.nodes_count && oshd.nodes[i] != node; ++i);
    node_destroy(node);
    for (; i + 1 < oshd.nodes_count; ++i) {
        oshd.nodes[i] = oshd.nodes[i + 1];
    }
    oshd.nodes_count -= 1;
    if (oshd.nodes_count) {
        oshd.nodes = xrealloc(oshd.nodes, sizeof(node_t *) * (oshd.nodes_count));
    } else {
        free(oshd.nodes);
        oshd.nodes = NULL;
    }
    pfd_resize();
    pfd_update();
}

// The first time we get a signal, set oshd_run to false
// If oshd_run is already false, call exit()
static void oshd_signal_exit(__attribute__((unused)) int sig)
{
    if (oshd.run) {
        oshd.run = false;
    } else {
        logger(LOG_CRIT, "Uncaught exit signal: %s", strsignal(sig));
        exit(EXIT_FAILURE);
    }
}

// Initialize oshd
bool oshd_init(void)
{
    int offset = 0;

    if (oshd.tuntap_used) {
        if ((oshd.tuntap_fd = tuntap_open(oshd.tuntap_dev, oshd.is_tap)) < 0)
            return false;
        set_nonblocking(oshd.tuntap_fd);
        setenv("OSHD_DEVICE", oshd.tuntap_dev, 1);
        if (oshd.cmd_devup) {
            if (oshd_script(oshd.cmd_devup) != 0)
                return false;
        }
        pfd_off += 1;
    }

    if (oshd.server_enabled) {
        if ((oshd.server_fd = tcp4_bind(NULL, oshd.server_port, 10)) < 0)
            return false;
        pfd_off += 1;
    }

    pfd_resize();
    if (oshd.tuntap_used) {
        pfd[offset].fd = oshd.tuntap_fd;
        pfd[offset].events = POLLIN;
        offset += 1;
    }
    if (oshd.server_enabled) {
        pfd[offset].fd = oshd.server_fd;
        pfd[offset].events = POLLIN;
        offset += 1;
    }

    signal(SIGINT, oshd_signal_exit);
    signal(SIGTERM, oshd_signal_exit);
    return true;
}

// Free all allocated resources for/by oshd_init/oshd_loop
void oshd_free(void)
{
    oshd.run = false;
    if (oshd.tuntap_fd > 0) {
        if (oshd.cmd_devdown)
            oshd_script(oshd.cmd_devdown);
        close(oshd.tuntap_fd);
    }
    if (oshd.server_fd > 0) {
        close(oshd.server_fd);
    }

    for (size_t i = 0; i < oshd.nodes_count; ++i)
        node_destroy(oshd.nodes[i]);
    free(oshd.nodes);
    free(pfd);

    for (size_t i = 0; i < oshd.remote_count; ++i)
        free(oshd.remote_addrs[i]);
    free(oshd.remote_addrs);
    free(oshd.remote_ports);

    free(oshd.cmd_devup);
    free(oshd.cmd_devdown);

    for (size_t i = 0; i < oshd.node_tree_count; ++i)
        node_id_free(oshd.node_tree[i]);
    free(oshd.node_tree);

    free(oshd.local_routes);
    for (size_t i = 0; i < oshd.routes_count; ++i)
        netroute_free(oshd.routes[i]);
    free(oshd.routes);
}

void oshd_loop(void)
{
    int events;

    // Queue the connections to our remotes
    for (size_t i = 0; i < oshd.remote_count; ++i) {
        oshd_connect_queue(oshd.remote_addrs[i], oshd.remote_ports[i],
            oshd.reconnect_delay_min);
    }

    // Osh actually starts
    oshd.run = true;
    event_queue_periodic_ping();

    while (oshd.run) {
        // Process queued events
        event_process_queued();

        // Update our polling structure
        pfd_update();

        // Poll for events on all sockets and the TUN/TAP device
        events = poll(pfd, pfd_count, 100);

        if (events < 0) {
            // Polling errors can occur when receiving signals, in this case the
            // error isn't actually from the polling so we can ignore it
            if (errno == EINTR)
                continue;

            logger(LOG_CRIT, "poll: %s", strerror(errno));
            oshd.run = false;
            break;
        }

        // We then iterate over all our file descriptors to handle the events
        for (size_t i = 0; i < pfd_count; ++i) {
            if (pfd[i].fd == oshd.tuntap_fd) {
                if (pfd[i].revents & POLLIN) {
                    // Data is available on the TUN/TAP device
                    oshd_read_tuntap_pkt();
                    break;
                }
            } else if (pfd[i].fd == oshd.server_fd) {
                if (pfd[i].revents & POLLIN) {
                    // The server is ready to accept an incoming connection
                    oshd_accept();
                    break;
                }
            } else if (!oshd.nodes[i - pfd_off]->connected) {
                // If a node is not connected yet, we check it to see if the
                // socket has finished connecting
                if (!oshd_connect_async(oshd.nodes[i - pfd_off]))
                    break;
            } else {
                if (pfd[i].revents & POLLIN) {
                    // A node is ready to receive data
                    if (!node_recv_queued(oshd.nodes[i - pfd_off]))
                        break;
                }
                if (pfd[i].revents & POLLOUT) {
                    // A node is ready to send queued data
                    if (!node_send_queued(oshd.nodes[i - pfd_off]))
                        break;
                }
            }
        }
    }
}