#include "logger.h"
#include "xalloc.h"
#include "tuntap.h"
#include "netaddr.h"
#include "netutil.h"
#include "tuntap/tap-windows.h"
#include "macros_windows.h"
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <winioctl.h>

// This code for interfacing with the tap-windows6 driver is heavily inspired by
// https://github.com/OpenVPN/openvpn/blob/master/src/openvpn/tun.c

typedef struct tt_data_win {
    void *device_handle;     // Windows file handle for the TUN/TAP device

    OVERLAPPED read_ol;  // Overlapped structure for reading
    OVERLAPPED write_ol; // Overlapped structure for writing

    uint8_t read_buf[TUNTAP_BUFSIZE];   // Buffer used for overlapped reads
    uint8_t write_buf[TUNTAP_BUFSIZE];  // Buffer used for overlapped writes

    bool write_pending; // true while an overlapped write is active

    struct netaddr_data_mac mac_int;    // The device's MAC address
    struct netaddr_data_mac mac_ext;    // Generic MAC address for TUN emulation
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

// Initiate an asynchronous read which will be processed by the AIO event loop
// This function must not be called if an overlapped read is pending
static bool initiate_overlapped_read(tuntap_t *tuntap)
{
    // Read the next TAP packet
    if (ReadFile(tuntap_data(tuntap)->device_handle, tuntap_data(tuntap)->read_buf,
            TUNTAP_BUFSIZE, NULL, &tuntap_data(tuntap)->read_ol))
    {
        // The read returned immediately
        SetEvent(tuntap_data(tuntap)->read_ol.hEvent);
        logger_debug(DBG_TUNTAP, "%s: %s", __func__, "immediate");
    } else {
        // The read did not finish immediately
        const DWORD err = GetLastError();

        if (err == ERROR_IO_PENDING) {
            // The read is queued, wait for it to finish
            logger_debug(DBG_TUNTAP, "%s: %s", __func__, "async");
        } else {
            // There was an error
            logger(LOG_CRIT, "%s: %s", __func__, win_strerror(err));
            return false;
        }
    }

    return true;
}

static void _tuntap_close(tuntap_t *tuntap)
{
    // Cancel any pending I/O read/write
    if (!CancelIoEx(tuntap_data(tuntap)->device_handle, NULL)) {
        const DWORD err = GetLastError();

        // ERROR_NOT_FOUND is returned when there was nothing to cancel
        if (err != ERROR_NOT_FOUND)
            logger(LOG_ERR, "%s: %s: %s", __func__, "CancelIoEx", win_strerror(err));
    }

    // Wait until overlapped I/O is finished
    DWORD bytes_transferred;

    GetOverlappedResult(tuntap_data(tuntap)->device_handle,
        &tuntap_data(tuntap)->read_ol, &bytes_transferred, TRUE);
    GetOverlappedResult(tuntap_data(tuntap)->device_handle,
        &tuntap_data(tuntap)->write_ol, &bytes_transferred, TRUE);

    // Free the OVERLAPPED events
    if (tuntap_data(tuntap)->read_ol.hEvent)
        CloseHandle(tuntap_data(tuntap)->read_ol.hEvent);
    if (tuntap_data(tuntap)->write_ol.hEvent)
        CloseHandle(tuntap_data(tuntap)->write_ol.hEvent);

    // Close the device handle
    CloseHandle(tuntap_data(tuntap)->device_handle);

    // Free the tuntap data
    free(tuntap->data.ptr);

    // Free the common parts of the tuntap_t structure and the structure itself
    tuntap_free_common(tuntap);
    free(tuntap);
}

static bool _tuntap_read(tuntap_t *tuntap, void *buf, size_t buf_size, size_t *pkt_size)
{
    // Ethernet header offset to add to layer 3 packets
    const size_t tun_offset = tuntap_is_tun(tuntap) ? 14 : 0;
    tt_data_win_t *data = tuntap_data(tuntap);
    DWORD read_bytes;
    DWORD size_without_offset;

    // Initialize the result values for a successful read of 0 bytes which
    // will be identified as a recoverable tuntap_read() error
    // Some error cases below will return true to use this soft error case
    *pkt_size = 0;

    if (!GetOverlappedResult(data->device_handle, &data->read_ol, &read_bytes, FALSE)) {
        const DWORD err = GetLastError();

        // This should not happen, if it does this shouldn't be a fatal error
        if (err == ERROR_IO_INCOMPLETE) {
            logger(LOG_WARN, "%s: %s: %s", __func__, "GetOverlappedResult",
                "Invoked but the read is still pending");
            return true;
        }

        logger(LOG_ERR, "%s: %s: %s", __func__, "GetOverlappedResult",
            win_strerror(err));
        return false;
    }

    // At this point the read is finished, so we have to always initiate a new
    // overlapped read before returning or no more packets will be read from the
    // device

    // The packet is invalid
    if (read_bytes <= tun_offset)
        return initiate_overlapped_read(tuntap);

    size_without_offset = read_bytes - tun_offset;

    // With TUN emulation some packets will be read but are not compatible
    // with layer 3 (ARP/NDP)
    if (tuntap_is_tun(tuntap)) {
        const uint16_t ether_type = ntohs(*((uint16_t *) &data->read_buf[12]));

        // If the packet is not TUN compatible, don't return it
        if (!tun_handle(tuntap, ether_type, data->read_buf + tun_offset, size_without_offset))
            return initiate_overlapped_read(tuntap);
    }

    // The destination buffer must be large enough to hold the packet
    if (size_without_offset > buf_size) {
        logger(LOG_CRIT, "%s: Buffer size is too small (%lu/%zu bytes)",
            __func__, size_without_offset, buf_size);
        errno = EINVAL;
        initiate_overlapped_read(tuntap);
        return false;
    }

    // Set the read packet's size and copy it
    memcpy(buf, data->read_buf + tun_offset, size_without_offset);
    *pkt_size = size_without_offset;
    return initiate_overlapped_read(tuntap);
}

static bool _tuntap_write(tuntap_t *tuntap, const void *packet, size_t packet_size)
{
    // Ethernet header offset to add to layer 3 packets
    const size_t tun_offset = tuntap_is_tun(tuntap) ? 14 : 0;
    const size_t size_with_offset = packet_size + tun_offset;
    tt_data_win_t *data = tuntap_data(tuntap);
    DWORD written_bytes;

    // If a previous write was not finished we have to wait until it is
    if (data->write_pending) {
        if (!GetOverlappedResult(data->device_handle, &data->write_ol,
                &written_bytes, FALSE))
        {
            const DWORD err = GetLastError();

            if (err == ERROR_IO_PENDING) {
                // The write is still in progress, drop the current packet
                logger(LOG_WARN,
                    "%s: Dropping packet of %zu bytes (previous overlapped write still pending)",
                    __func__, packet_size);
                return true;
            } else {
                // The previous write failed
                logger(LOG_ERR, "%s: %s: %s", __func__, "GetOverlappedResult",
                    win_strerror(err));
                return false;
            }
        }

        // Write is finished
        data->write_pending = false;
        logger_debug(DBG_TUNTAP, "Async write of %lu bytes (finished)", written_bytes);
    }

    // Check that the packet can fit in the write buffer
    if (size_with_offset > TUNTAP_BUFSIZE) {
        logger(LOG_WARN,
            "%s: Dropping packet bigger than the buffer size (%zu/%d, offset %zu)",
            __func__, size_with_offset, TUNTAP_BUFSIZE, tun_offset);
        return true;
    }

    // Copy the packet to the write buffer
    // This must be done in case the overlapped write can run in the background
    // and the packet pointer is unsafe to use after returning
    memcpy(data->write_buf + tun_offset, packet, packet_size);

    // If the device is in TUN mode, add an Ethernet header
    if (tuntap_is_tun(tuntap)) {
        // Destination/source MAC addresses don't change and are already
        // initialized in tuntap_open()

        // Ether type
        switch (((const uint8_t *) packet)[0] >> 4) {
        case 4: // IPv4
            *((uint16_t *) &data->write_buf[12]) = htons(0x0800);
            break;
        case 6: // IPv6
            *((uint16_t *) &data->write_buf[12]) = htons(0x86DD);
            break;
        default: // Any other value defaults to an ARP packet
            *((uint16_t *) &data->write_buf[12]) = htons(0x0806);
            break;
        }
    }

    // Write the packet
    if (WriteFile(data->device_handle, data->write_buf, size_with_offset,
            &written_bytes, &data->write_ol))
    {
        // The packet was written immediately
        SetEvent(data->write_ol.hEvent);
        logger_debug(DBG_TUNTAP, "Immediate write of %lu bytes", written_bytes);

    } else {
        const DWORD err = GetLastError();

        if (err == ERROR_IO_PENDING) {
            // The packet will be written asynchronously
            logger_debug(DBG_TUNTAP, "Async write of %zu bytes (pending)",
                packet_size);
            data->write_pending = true;
        } else {
            // The packet could not be written
            logger(LOG_CRIT, "%s: Failed to write %zu bytes to device handle: %s",
                tuntap->dev_name, packet_size, win_strerror(err));
            return false;
        }
    }

    return true;
}

static void _tuntap_init_aio_event(tuntap_t *tuntap, aio_event_t *event)
{
    aio_event_set_handles(event, tuntap_data(tuntap)->read_ol.hEvent, true, NULL, true);
}

tuntap_t *tuntap_open_tap_windows(const char *devname, bool tap)
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

            logger(LOG_CRIT, "Failed to enumerate %s: index %lu: %s",
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
            logger(LOG_WARN, "Failed to open %s: index %lu: %s", adapter_path,
                i, win_strerror(hkey_status));
            continue;
        }

        // Read the adapter's name from the key
        adapter_name_len = sizeof(adapter_name);
        hkey_status = RegQueryValueExA(adapter_subkey, "Name", 0, 0,
            (BYTE *) adapter_name, &adapter_name_len);
        RegCloseKey(adapter_subkey);
        if (hkey_status != ERROR_SUCCESS) {
            logger(LOG_CRIT, "Failed to query %s: index %lu: %s", adapter_path,
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
    // The tap-windows6 driver only supports TAP (layer 2) mode, so in order to
    // work with a TUN network Osh will translate between both layers
    tuntap_t *tuntap = tuntap_empty(tap);
    tt_data_win_t *data;

    tuntap_set_funcs(tuntap, _tuntap_close, _tuntap_read, _tuntap_write, _tuntap_init_aio_event);

    // Copy the adapter's name and ID
    tuntap->dev_name = xstrdup(adapter_name);
    tuntap->dev_name_size = strlen(tuntap->dev_name) + 1;
    tuntap->dev_id = xstrdup(adapter_id);
    tuntap->dev_id_size = strlen(tuntap->dev_id) + 1;

    // Allocate the tuntap data
    // Initialize all members to 0 since error handling checks those
    tuntap->data.ptr = xzalloc(sizeof(tt_data_win_t));
    data = tuntap_data(tuntap);

    // Set the handle
    data->device_handle = adapter_handle;

    // Initialize the OVERLAPPED structures and events for reading/writing
    // asynchronously from/to the TUN/TAP device
    data->read_ol.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (data->read_ol.hEvent == NULL) {
        logger(LOG_CRIT, "Failed to create read event handle: %s", win_strerror_last());
        goto err_tuntap;
    }

    data->write_ol.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (data->write_ol.hEvent == NULL) {
        logger(LOG_CRIT, "Failed to create write event handle: %s", win_strerror_last());
        goto err_tuntap;
    }

    // Enable the adapter
    if (!tuntap_device_enable(tuntap))
        goto err_tuntap;

    // Get the device's MAC address
    if (!tuntap_device_get_mac(tuntap))
        goto err_tuntap;

    // Initialize destination/source MAC addresses of the TUN packets if the
    // device is in TUN mode
    // These don't change so we can initialize them here once
    if (tuntap_is_tun(tuntap)) {
        // We don't check the buffer size as it should always be big enough
        memcpy(data->write_buf + 0, &data->mac_int, sizeof(data->mac_int));
        memcpy(data->write_buf + 6, &data->mac_ext, sizeof(data->mac_ext));
    }

    // Initiate reading from the device
    if (!initiate_overlapped_read(tuntap))
        goto err_tuntap;

    logger(LOG_INFO, "Opened %s device: %s (%s, handle: %p)",
        tuntap->is_tap ? "TAP" : "TUN",
        tuntap->dev_name,
        tuntap->dev_id,
        data->device_handle);

    return tuntap;

err: // Initialization error, no tuntap_t created yet
    if (netconn_key)
        RegCloseKey(netconn_key);
    if (adapter_handle == INVALID_HANDLE_VALUE)
        CloseHandle(adapter_handle);
    return NULL;

err_tuntap: // TUN/TAP error after tuntap_t was created
    tuntap_close(tuntap);
    return NULL;
}
