#include "logger.h"
#include "xalloc.h"
#include "tuntap.h"
#include "netaddr.h"
#include "macros_windows.h"
#include "netutil.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "tap-windows.h"
#include <windows.h>
#include <winioctl.h>
#include <winerror.h>
#include <pthread.h>

// This code for interfacing with the tap-windows6 driver is heavily inspired by
// https://github.com/OpenVPN/openvpn/blob/master/src/openvpn/tun.c

typedef struct tt_data_win {
    void *device_handle;     // Windows file handle for the TUN/TAP device
    int pollfd_read;         // File descriptor of a pipe for reading from the device
    int pollfd_write;        // File descriptor of the same pipe for writing on it
    pthread_t pollfd_thread; // Thread to pipe the adapter's data to pollfd_read
    pthread_mutex_t pollfd_mtx;      // Mutex to prevent writing and reading at the
                                     // same time on the pollfd pipe
    pthread_cond_t pollfd_cond;      // Condition to block the pollfd thread when the
                                     // pipe is full until tuntap_read is called
    pthread_mutex_t pollfd_cond_mtx; // Mutex for the condition
    void *read_ol;  // TUN/TAP overlapped structure for reading
    void *write_ol; // TUN/TAP overlapped structure for writing

    pthread_mutex_t write_mtx; // Mutex used by tuntap_write()

    struct netaddr_data_mac mac_int; // The device's MAC address
    struct netaddr_data_mac mac_ext; // Generic MAC address for TUN emulation

    bool tun_emu; // true if the device is supposed to operate at layer 3
                  // Enables an emulation layer to provide this transparently
    uint8_t tun_pkt[TUNTAP_BUFSIZE]; // TUN packet buffer
} tt_data_win_t;
#define tuntap_data(tt) ((tt_data_win_t *) (tt)->data.ptr)

// Enable the TUN/TAP device
// The adapter is not enabled by default and cannot be used before enabling it
static bool tuntap_device_enable(tuntap_t *tuntap)
{
    ULONG status = 1;
    DWORD len;

    if (!DeviceIoControl(tuntap_data(tuntap)->device_handle, TAP_WIN_IOCTL_SET_MEDIA_STATUS,
            &status, sizeof(status), &status, sizeof(status), &len, NULL))
    {
        logger(LOG_CRIT, "Failed to enable TUN/TAP device %s: %s", tuntap->dev_name,
            win_strerror_last());
        return false;
    }
    return true;
}

// Retrieve the device's MAC address
static bool tuntap_device_get_mac(tuntap_t *tuntap)
{
    DWORD len;

    if (!DeviceIoControl(tuntap_data(tuntap)->device_handle, TAP_WIN_IOCTL_GET_MAC,
            NULL, 0,
            &tuntap_data(tuntap)->mac_int, sizeof(tuntap_data(tuntap)->mac_int),
            &len, NULL))
    {
        logger(LOG_CRIT, "Failed to get TUN/TAP device's MAC address %s: %s",
            tuntap->dev_name, win_strerror_last());
        return false;
    }

    if (len != sizeof(tuntap_data(tuntap)->mac_int)) {
        logger(LOG_CRIT, "Invalid MAC address from TUN/TAP device %s",
            tuntap->dev_name);
        return false;
    }

    // Generate a different valid MAC address for TUN emulation
    memcpy(&tuntap_data(tuntap)->mac_ext, &tuntap_data(tuntap)->mac_int,
        sizeof(tuntap_data(tuntap)->mac_int));
    tuntap_data(tuntap)->mac_ext.addr[3] ^= 0xFF;
    tuntap_data(tuntap)->mac_ext.addr[4] ^= 0xFF;
    tuntap_data(tuntap)->mac_ext.addr[5] ^= 0xFF;

    return true;
}

// Check if the packet is an ARP IPv4 request
// This also checks if the source protocol address is zeroed out:
//   Windows sends a few probes targeting its own IP address to check
//   for conflicts and sets the sender protocol address to 0.0.0.0 on
//   those probes
static bool is_arp_v4req(const struct arp_v4r *pkt, const size_t pkt_size)
{
    if (   pkt_size               != sizeof(*pkt)
        || pkt->hw_type           != htons(1)
        || pkt->proto_type        != htons(0x0800)
        || pkt->hw_addr_length    != sizeof(pkt->sender_hw_addr)
        || pkt->proto_addr_length != sizeof(pkt->sender_proto_addr)
        || pkt->operation         != htons(1)
        || pkt->sender_proto_addr == 0)
    {
        return false;
    }
    return true;
}

// Write a reply packet to *arp_reply
static void make_arp_v4reply(
    struct arp_v4r *arp_reply,
    const struct arp_v4r *arp_req,
    const struct netaddr_data_mac *reply_mac_addr)
{
    // Copy identical fields
    arp_reply->hw_type = arp_req->hw_type;
    arp_reply->proto_type = arp_req->proto_type;
    arp_reply->hw_addr_length = arp_req->hw_addr_length;
    arp_reply->proto_addr_length = arp_req->proto_addr_length;

    // Operation type 2 is a reply
    arp_reply->operation = htons(2);

    // Swap existing addresses copy the queried MAC address
    memcpy(arp_reply->target_hw_addr, arp_req->sender_hw_addr, sizeof(arp_req->sender_hw_addr));
    memcpy(arp_reply->sender_hw_addr, reply_mac_addr, sizeof(*reply_mac_addr));
    arp_reply->sender_proto_addr = arp_req->target_proto_addr;
    arp_reply->target_proto_addr = arp_req->sender_proto_addr;
}

// Check if the IPv6 packet is an ICMP6 Neighbor Sollicitation
static bool is_ipv6_icmp_ns(const struct ipv6_icmp_ns_pkt *pkt,
    const size_t pkt_size)
{
    if (pkt_size < sizeof(*pkt))
        return false;

    return    pkt->hdr.next_header == IPPROTO_ICMPV6
           && pkt->icmp.type == 135;
}

// Write a reply neighbor advertisement to *reply
static void make_ipv6_icmp_na(
    struct ipv6_icmp_na_pkt *reply,
    const struct ipv6_icmp_ns_pkt *req,
    const struct netaddr_data_mac *reply_mac_addr)
{
    struct ipv6_pseudo hdr_pseudo;

    // Initialize the header (re-using identical values from the source packet)
    memcpy(&reply->hdr, &req->hdr, sizeof(req->hdr));
    reply->hdr.payload_length = htons(sizeof(reply->icmp));
    reply->hdr.hop_limit = 255;
    memcpy(reply->hdr.src_addr, req->icmp.target_address, 16);
    memcpy(reply->hdr.dst_addr, req->hdr.src_addr, 16);

    // Create the neighbor advertisement
    reply->icmp.type = 136;
    reply->icmp.code = 0;
    reply->icmp.checksum = 0;
    reply->icmp.flags = htonl(0x60000000); // Sollicited + Override
    memcpy(reply->icmp.target_address, req->icmp.target_address, 16);
    reply->icmp.mac_addr_type = 2;
    reply->icmp.length = 1;
    memcpy(reply->icmp.mac_addr, reply_mac_addr, sizeof(*reply_mac_addr));

    // Initialize the pseudo header for the checksum
    memcpy(&hdr_pseudo.dst, reply->hdr.dst_addr, 16);
    memcpy(&hdr_pseudo.src, reply->hdr.src_addr, 16);
    hdr_pseudo.length = reply->hdr.payload_length;
    hdr_pseudo.next = htonl(IPPROTO_ICMPV6);

    // Compute the checksum
    reply->icmp.checksum = icmp6_checksum(&hdr_pseudo, &reply->icmp,
        sizeof(reply->icmp));
}

// Returns true if the packet is TUN-compatible and can be read by tuntap_read()
// This function also handles ARP/NDP probes/replies
static bool tun_handle(tuntap_t *tuntap, uint16_t ether_type,
    const void *packet, size_t packet_size)
{
    switch (ether_type) {
    case 0x0800: // IPv4
        return true;

    case 0x86DD: // IPv6
    {
        if (!is_ipv6_icmp_ns(packet, packet_size))
            return true;

        struct ipv6_icmp_na_pkt icmp6_na;

        // Create and write the neighbor advertisement
        logger_debug(DBG_TUNTAP, "Replying to neighbor sollicitation of %zu bytes", packet_size);
        make_ipv6_icmp_na(&icmp6_na, packet, &tuntap_data(tuntap)->mac_ext);
        tuntap_write(tuntap, &icmp6_na, sizeof(icmp6_na));
        return false;
    }

    case 0x0806: // ARP
    {
        const struct arp_v4r *arp_req = (const struct arp_v4r *) packet;

        // If the ARP packet is not a MAC/IPv4 probe, ignore itx
        if (!is_arp_v4req(arp_req, packet_size)) {
            logger_debug(DBG_TUNTAP, "Ignored ARP packet of %zu bytes", packet_size);
            return false;
        }

        struct arp_v4r arp_reply;

        // Create and write the ARP reply
        logger_debug(DBG_TUNTAP, "Replying to ARP request of %zu bytes", packet_size);
        make_arp_v4reply(&arp_reply, arp_req, &tuntap_data(tuntap)->mac_ext);
        tuntap_write(tuntap, &arp_reply, sizeof(arp_reply));
        return false;
    }

    default: // Drop all other protocols
        logger_debug(DBG_TUNTAP, "Dropped packet of %zu bytes (ether type: 0x%04X)",
            packet_size, ether_type);
        return false;
    }
}

// Read from the device handle and write the data to the pollfd pipe
#define pollfd_hdr_size (sizeof(DWORD))
static void *tuntap_pollfd_thread(void *data)
{
    tuntap_t *tuntap = (tuntap_t *) data;
    OVERLAPPED *ol = (OVERLAPPED *) tuntap_data(tuntap)->read_ol;

    uint8_t _buf[pollfd_hdr_size + TUNTAP_BUFSIZE];
    uint8_t *buf = _buf + pollfd_hdr_size;
    DWORD buf_size = sizeof(_buf) - pollfd_hdr_size;
    DWORD read_bytes;
    DWORD err;
    int ierr;

    while (1) {
        // Reset the overlapped event
        ResetEvent(ol->hEvent);

        // Read the next TAP packet
        if (ReadFile(tuntap_data(tuntap)->device_handle, buf, buf_size, &read_bytes, ol)) {
            // The read returned immediately
            SetEvent(ol->hEvent);
            logger_debug(DBG_TUNTAP, "Immediate read of %u bytes", read_bytes);
        } else {
            // The read did not finish immediately
            err = GetLastError();
            if (err == ERROR_IO_PENDING) {
                // The read is queued, wait for it to finish
                GetOverlappedResult(ol->hEvent, ol, &read_bytes, TRUE);
                logger_debug(DBG_TUNTAP, "Async read of %u bytes", read_bytes);
            } else {
                // There was an error
                logger(LOG_CRIT, "%s: Failed to read from device handle: %s",
                    tuntap->dev_name, win_strerror(err));
                break;
            }
        }

        if (tuntap_data(tuntap)->tun_emu) {
            const uint16_t ether_type = ntohs(*((uint16_t *) &buf[12]));

            if (read_bytes <= 14)
                continue;

            read_bytes -= 14;
            memmove(buf, buf + 14, read_bytes);

            if (!tun_handle(tuntap, ether_type, buf, read_bytes))
                continue;
        }

        // Write the packet's size
        *((DWORD *) _buf) = read_bytes;

        // Write the packet size followed by the packet data to the pollfd pipe
        size_t total_size = read_bytes + pollfd_hdr_size;
        ssize_t wb;

retry_write:
        // Lock the pollfd mutex before writing
        ierr = pthread_mutex_lock(&tuntap_data(tuntap)->pollfd_mtx);
        if (ierr) {
            logger(LOG_CRIT, "pollfd_thread: Failed to lock pollfd_mtx: %s",
                strerror(ierr));
            break;
        }

        wb = write(tuntap_data(tuntap)->pollfd_write, _buf, total_size);

        // Unlock mutex after writing
        ierr = pthread_mutex_unlock(&tuntap_data(tuntap)->pollfd_mtx);
        if (ierr) {
            logger(LOG_CRIT, "pollfd_thread: Failed to unlock pollfd_mtx: %s",
                strerror(ierr));
            break;
        }

        if (wb < 0 || (size_t) wb != total_size) {
            if (IO_WOULDBLOCK(errno)) {
                // If write() will block we have to wait until tuntap_read is called
                // This will happen when the pipe is full, after enough calls from
                // tuntap_read the pipe won't be full anymore so we can retry to write
                // the packet to it
                // If we block on the write() call it will deadlock the whole program
                // because the mutex won't ever be unlocked
                ierr = pthread_mutex_lock(&tuntap_data(tuntap)->pollfd_cond_mtx);
                if (ierr) {
                    logger(LOG_CRIT, "pollfd_thread: Failed to lock pollfd_cond_mtx: %s",
                        strerror(ierr));
                    break;
                }

                logger_debug(DBG_TUNTAP, "pollfd_thread: write is blocking, waiting");
                pthread_cond_wait(&tuntap_data(tuntap)->pollfd_cond, &tuntap_data(tuntap)->pollfd_cond_mtx);

                ierr = pthread_mutex_unlock(&tuntap_data(tuntap)->pollfd_cond_mtx);
                if (ierr) {
                    logger(LOG_CRIT, "pollfd_thread: Failed to lock pollfd_cond_mtx: %s",
                        strerror(ierr));
                    break;
                }
                logger_debug(DBG_TUNTAP, "pollfd_thread: write should no longer block, retrying");
                goto retry_write;
            }

            logger(LOG_CRIT, "%s: Failed to write packet to pollfd: %s (%zi/%u)",
                tuntap->dev_name, strerror(errno), wb, read_bytes);
        }
    }

    // The pipe is not useful anymore, close it
    close(tuntap_data(tuntap)->pollfd_read);
    close(tuntap_data(tuntap)->pollfd_write);
    tuntap_data(tuntap)->pollfd_read = -1;
    tuntap_data(tuntap)->pollfd_write = -1;

    logger(LOG_CRIT, "tuntap_pollfd_thread exiting");
    pthread_exit(NULL);
}

tuntap_t *tuntap_open(const char *devname, bool tap)
{
    // We cannot create a TAP device on the fly, it must already exist so we
    // need to have its name to find and open it
    if (!devname || strlen(devname) == 0) {
        logger(LOG_CRIT, "The device name must be set on Windows");
        return NULL;
    }

    // The file handle of the TUN/TAP adapter
    HANDLE adapter_handle = INVALID_HANDLE_VALUE;

    // The status is an int but it's simpler to cast it to an ssize_t for
    // format strings
    ssize_t hkey_status;

    // The network connections registry key contains the network adapters of
    // the system
    HKEY netconn_key = NULL;

    // This subkey will be used for each adapter
    HKEY adapter_subkey = NULL;

    // Open the network connections key
    hkey_status = RegOpenKeyExA(HKEY_LOCAL_MACHINE, NETWORK_CONNECTIONS_KEY, 0,
        KEY_READ, &netconn_key);
    if (hkey_status != ERROR_SUCCESS) {
        logger(LOG_CRIT, "Failed to open %s: %s", NETWORK_CONNECTIONS_KEY,
            win_strerror(hkey_status));
        goto err;
    }

    char adapter_id[64];
    char adapter_path[256];
    char adapter_name[256];
    DWORD adapter_name_len;
    char adapter_subpath[256];

    // Iterate over all the adapters in the network connections key
    for (DWORD i = 0;; ++i) {
        hkey_status = RegEnumKeyA(netconn_key, i, adapter_id, sizeof(adapter_id));
        if (hkey_status != ERROR_SUCCESS) {
            // There are no more items in the key, break out of the loop
            if (hkey_status == ERROR_NO_MORE_ITEMS)
                break;

            logger(LOG_CRIT, "Failed to enumerate %s: index %u: %s",
                NETWORK_CONNECTIONS_KEY, i, win_strerror(hkey_status));
            goto err;
        }

        // The descriptions key is not an adapter, skip it
        if (!strcmp(adapter_id, "Descriptions"))
            continue;

        // Create the registry path of the adapter's key and open it
        snprintf(adapter_path, sizeof(adapter_path), "%s\\%s\\Connection",
            NETWORK_CONNECTIONS_KEY, adapter_id);
        hkey_status = RegOpenKeyExA(HKEY_LOCAL_MACHINE, adapter_path, 0,
            KEY_READ, &adapter_subkey);
        if (hkey_status != ERROR_SUCCESS) {
            logger(LOG_WARN, "Failed to open %s: index %u: %s", adapter_path,
                i, win_strerror(hkey_status));
            continue;
        }

        // Read the adapter's name from the key
        adapter_name_len = sizeof(adapter_name);
        hkey_status = RegQueryValueExA(adapter_subkey, "Name", 0, 0,
            (BYTE *) adapter_name, &adapter_name_len);
        RegCloseKey(adapter_subkey);
        if (hkey_status != ERROR_SUCCESS) {
            logger(LOG_CRIT, "Failed to query %s: index %u: %s", adapter_path,
                i, win_strerror(hkey_status));
            goto err;
        }

        // Check if this adapter is the one requested
        logger_debug(DBG_TUNTAP, "Enumerated adapter '%s' (%s)", adapter_name,
            adapter_id);
        if (!strcmp(devname, adapter_name)) {
            // This is our requested adapter
            logger_debug(DBG_TUNTAP, "Found the requested device: '%s' (%s)",
                adapter_name, adapter_id);

            // Create the path to the adapter file and try to open it
            snprintf(adapter_subpath, sizeof(adapter_subpath), "%s%s%s",
                USERMODEDEVICEDIR, adapter_id, TAP_WIN_SUFFIX);
            adapter_handle = CreateFile(adapter_subpath, OPEN_EXISTING, 0, 0,
                OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, 0);

            if (adapter_handle == INVALID_HANDLE_VALUE) {
                logger(LOG_CRIT, "Failed to open %s: %s", adapter_subpath,
                    win_strerror_last());
            }
            break;
        }
    }

    // Close the network connections key
    RegCloseKey(netconn_key);
    netconn_key = NULL;

    // If no adapter was opened then we either couldn't find or open the
    // requested adapter
    if (adapter_handle == INVALID_HANDLE_VALUE) {
        logger(LOG_CRIT, "No adapter found for TUN/TAP device %s", devname);
        return NULL;
    }

    // Create the TUN/TAP device
    tuntap_t *tuntap = tuntap_empty(tap);
    tt_data_win_t *data;

    // Copy the adapter's name and ID
    tuntap->dev_name = xstrdup(adapter_name);
    tuntap->dev_name_size = strlen(tuntap->dev_name) + 1;
    tuntap->dev_id = xstrdup(adapter_id);
    tuntap->dev_id_size = strlen(tuntap->dev_id) + 1;

    // Allocate the tuntap data
    tuntap->data.ptr = xzalloc(sizeof(tt_data_win_t));
    data = tuntap_data(tuntap);

    // The tap-windows6 driver only supports TAP (layer 2) mode, so in order to
    // work with a TUN network Osh will translate between both layers
    data->tun_emu = !tap;

    // Set the handle
    data->device_handle = adapter_handle;

    // Create the OVERLAPPED structures and events for reading and writing
    // asynchronously from/to the TUN/TAP device
    data->read_ol = xzalloc(sizeof(OVERLAPPED));
    ((OVERLAPPED *) data->read_ol)->hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (((OVERLAPPED *) data->read_ol)->hEvent == NULL) {
        logger(LOG_CRIT, "Failed to create read event handle: %s", win_strerror_last());
        tuntap_close(tuntap);
        return NULL;
    }

    data->write_ol = xzalloc(sizeof(OVERLAPPED));
    ((OVERLAPPED *) data->write_ol)->hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (((OVERLAPPED *) data->write_ol)->hEvent == NULL) {
        logger(LOG_CRIT, "Failed to create write event handle: %s", win_strerror_last());
        tuntap_close(tuntap);
        return NULL;
    }

    // Create a Unix pipe to poll local packets from the device
    int pollfd_pipe[2];

    if (pipe(pollfd_pipe) < 0) {
        logger(LOG_CRIT, "Failed to create pollfd pipe: %s", strerror(errno));
        tuntap_close(tuntap);
        return NULL;
    }
    data->pollfd_read = pollfd_pipe[0];
    data->pollfd_write = pollfd_pipe[1];

    // Both file descriptors need to be non-blocking, a blocking write() will
    // deadlock the program
    tuntap_nonblock(data->pollfd_read);
    tuntap_nonblock(data->pollfd_write);

    // Enable the adapter
    if (!tuntap_device_enable(tuntap)) {
        tuntap_close(tuntap);
        return NULL;
    }

    // Get the device's MAC address
    if (!tuntap_device_get_mac(tuntap)) {
        tuntap_close(tuntap);
        return NULL;
    }

    // Initialize destination/source MAC addresses of the TUN packets
    // These don't change so we can initialize them here
    memcpy(data->tun_pkt + 0, &data->mac_int, sizeof(data->mac_int));
    memcpy(data->tun_pkt + 6, &data->mac_ext, sizeof(data->mac_ext));

    int err;

    // Initialize the pollfd mutex
    err = pthread_mutex_init(&data->pollfd_mtx, NULL);
    if (err) {
        logger(LOG_CRIT, "Failed to create pollfd mutex: %s", strerror(err));
        tuntap_close(tuntap);
        return NULL;
    }

    // Initialize the pollfd condition and its mutex
    err = pthread_cond_init(&data->pollfd_cond, NULL);
    if (err) {
        logger(LOG_CRIT, "Failed to create pollfd condition: %s", strerror(err));
        tuntap_close(tuntap);
        return NULL;
    }

    err = pthread_mutex_init(&data->pollfd_cond_mtx, NULL);
    if (err) {
        logger(LOG_CRIT, "Failed to create pollfd condition mutex: %s", strerror(err));
        tuntap_close(tuntap);
        return NULL;
    }

    // Initialize tuntap_write() mutex
    err = pthread_mutex_init(&data->write_mtx, NULL);
    if (err) {
        logger(LOG_CRIT, "Failed to create tuntap_write() mutex: %s", strerror(err));
        tuntap_close(tuntap);
        return NULL;
    }

    // Create the thread to read from the device handle and write the packets to
    // the pollfd pipe
    err = pthread_create(&data->pollfd_thread, NULL,
        &tuntap_pollfd_thread, tuntap);
    if (err) {
        logger(LOG_CRIT, "Failed to create pollfd thread: %s", strerror(err));
        data->pollfd_thread = NULL;
        tuntap_close(tuntap);
        return NULL;
    }

    logger(LOG_INFO, "Opened %s device: %s (%s) (handle: %p, pollfd: %i <- %i)",
        tuntap->is_tap ? "TAP" : "TUN",
        tuntap->dev_name,
        tuntap->dev_id,
        data->device_handle,
        data->pollfd_read,
        data->pollfd_write);
    return tuntap;

err:
    if (netconn_key)
        RegCloseKey(netconn_key);
    if (adapter_handle == INVALID_HANDLE_VALUE)
        CloseHandle(adapter_handle);
    return NULL;
}

void tuntap_close(tuntap_t *tuntap)
{
    tt_data_win_t *data = tuntap_data(tuntap);

    // Cancel the pollfd thread before freeing data that it uses
    if (data->pollfd_thread) {
        pthread_cancel(data->pollfd_thread);
        pthread_join(data->pollfd_thread, NULL);
    }

    // Free the OVERLAPPED structures and close the event handles
    if (data->read_ol) {
        CloseHandle(((OVERLAPPED *) data->read_ol)->hEvent);
        free(data->read_ol);
    }
    if (data->write_ol) {
        CloseHandle(((OVERLAPPED *) data->write_ol)->hEvent);
        free(data->write_ol);
    }

    // Close the device handle
    CloseHandle(data->device_handle);

    // Close the pollfd pipe
    if (data->pollfd_read > 0)
        close(data->pollfd_read);
    if (data->pollfd_write > 0)
        close(data->pollfd_write);

    // Destroy the pollfd mutex and condition
    pthread_mutex_destroy(&data->pollfd_mtx);
    pthread_cond_destroy(&data->pollfd_cond);
    pthread_mutex_destroy(&data->pollfd_cond_mtx);
    pthread_mutex_destroy(&data->write_mtx);

    // Free the tuntap data
    free(tuntap->data.ptr);

    // Free the common parts of the tuntap_t structure and the structure itself
    tuntap_free_common(tuntap);
    free(tuntap);
}

bool tuntap_read(tuntap_t *tuntap, void *buf, size_t buf_size, size_t *pkt_size)
{
    tt_data_win_t *data = tuntap_data(tuntap);
    bool success = false;
    DWORD size;
    ssize_t n;
    int err;

    // Lock the mutex before reading
    err = pthread_mutex_lock(&data->pollfd_mtx);
    if (err) {
        logger(LOG_CRIT, "tuntap_read: Failed to lock pollfd_mtx: %s",
            strerror(err));
        goto end;
    }

    // Read the size of the next packet on the pipe
    n = read(data->pollfd_read, &size, pollfd_hdr_size);
    if (n < 0) {
        // If the read would block, no more data is ready to be read on the pipe
        if (IO_WOULDBLOCK(errno)) {
            *pkt_size = 0;
            success = true;
            goto end;
        }

        // Otherwise the error will be handled by the caller
        goto end;
    }

    // The packet size must be fully read
    if (n != pollfd_hdr_size) {
        logger(LOG_CRIT, "tuntap_read: Incomplete packet header (%zi/%zu bytes)",
            n, pollfd_hdr_size);
        errno = EIO;
        goto end;
    }

    // The destination buffer must be large enough to hold the packet
    if (size > buf_size) {
        logger(LOG_CRIT, "tuntap_read: Buffer size is too small (%u/%zu bytes)",
            size, buf_size);
        errno = EINVAL;
        goto end;
    }

    // Read the packet
    n = read(data->pollfd_read, buf, size);
    if (n < 0)
        goto end;
    if (n != size) {
        logger(LOG_CRIT, "tuntap_read: Incomplete packet (%zi/%u bytes)",
            n, size);
        errno = EIO;
        goto end;
    }

    // Set the read packet's size
    *pkt_size = size;
    success = true;

end:
    // Always unlock the mutex after all reads are done
    err = pthread_mutex_unlock(&data->pollfd_mtx);
    if (err) {
        logger(LOG_CRIT, "tuntap_read: Failed to unlock pollfd_mtx: %s",
            strerror(err));
        return false;
    }

    // Signal the condition for the pollfd thread
    logger_debug(DBG_TUNTAP, "tuntap_read: Signaling pollfd_cond");
    err = pthread_cond_signal(&data->pollfd_cond);
    if (err) {
        logger(LOG_CRIT, "tuntap_read: Failed to signal pollfd_cond: %s",
            strerror(err));
        return false;
    }

    return success;
}

static bool _unsafe_tuntap_write(tuntap_t *tuntap, const void *packet, size_t packet_size)
{
    OVERLAPPED *ol = (OVERLAPPED *) tuntap_data(tuntap)->write_ol;
    DWORD written_bytes;

    if (tuntap_data(tuntap)->tun_emu) {
        // Make sure that we won't overflow
        if ((14 + packet_size) > sizeof(tuntap_data(tuntap)->tun_pkt)) {
            logger(LOG_CRIT, "tuntap_write: packet_size is too big for the TUN packet buffer");
            return false;
        }

        // Initialize fake Ethernet frame header
        // Destination/source MAC addresses don't change and are already
        // initialized in tuntap_open()

        // Ether type
        switch (((const uint8_t *) packet)[0] >> 4) {
        case 4: // IPv4
            *((uint16_t *) &tuntap_data(tuntap)->tun_pkt[12]) = htons(0x0800);
            break;
        case 6: // IPv6
            *((uint16_t *) &tuntap_data(tuntap)->tun_pkt[12]) = htons(0x86DD);
            break;
        default: // Any other value defaults to an ARP packet
            *((uint16_t *) &tuntap_data(tuntap)->tun_pkt[12]) = htons(0x0806);
            break;
        }

        // Append the actual packet
        memcpy(tuntap_data(tuntap)->tun_pkt + 14, packet, packet_size);

        // Use the encapsulated packet
        packet = tuntap_data(tuntap)->tun_pkt;
        packet_size += 14;
    }

    // Reset the overlapped event handle
    ResetEvent(ol->hEvent);
    if (WriteFile(tuntap_data(tuntap)->device_handle,
                  packet,
                  (DWORD) packet_size,
                  &written_bytes,
                  ol))
    {
        // The packet was written immediately
        SetEvent(ol->hEvent);
        logger_debug(DBG_TUNTAP, "Immediate write of %u bytes", written_bytes);
        return true;
    } else {
        DWORD err = GetLastError();

        if (err == ERROR_IO_PENDING) {
            // The packet will be written asynchronously
            logger_debug(DBG_TUNTAP, "Async write of %u bytes (pending)",
                (DWORD) packet_size);
            return true;
        } else {
            // The packet could not be written
            logger(LOG_CRIT, "%s: Failed to write %u bytes to device handle: %s",
                tuntap->dev_name, (DWORD) packet_size, win_strerror(err));
            return false;
        }
    }
}

bool tuntap_write(tuntap_t *tuntap, const void *packet, size_t packet_size)
{
    bool result;
    int err;

    err = pthread_mutex_lock(&tuntap_data(tuntap)->write_mtx);
    if (err) {
        logger(LOG_CRIT, "tuntap_write: Failed to lock mutex: %s", strerror(err));
        return false;
    }

    result = _unsafe_tuntap_write(tuntap, packet, packet_size);

    err = pthread_mutex_unlock(&tuntap_data(tuntap)->write_mtx);
    if (err) {
        logger(LOG_CRIT, "tuntap_write: Failed to unlock mutex: %s", strerror(err));
        return false;
    }

    return result;
}

void tuntap_init_aio_event(tuntap_t *tuntap, aio_event_t *event)
{
    event->fd = tuntap_data(tuntap)->pollfd_read;
}
