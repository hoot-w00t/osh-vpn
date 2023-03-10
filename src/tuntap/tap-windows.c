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
    bool write_pending;  // true while an overlapped write is active

    uint8_t read_buf[TUNTAP_BUFSIZE];   // Buffer used for overlapped reads
    uint8_t write_buf[TUNTAP_BUFSIZE];  // Buffer used for overlapped writes

    struct eth_addr mac_addr; // TAP interface MAC address
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

static bool _tuntap_get_macaddr(tuntap_t *tuntap, struct eth_addr *addr)
{
    DWORD len;

    if (!DeviceIoControl(tuntap_data(tuntap)->device_handle, TAP_WIN_IOCTL_GET_MAC,
            NULL, 0, addr->addr, ETH_ALEN, &len, NULL))
    {
        logger(LOG_ERR, "%s: %s: %s", __func__, "DeviceIoControl", win_strerror_last());
        return false;
    }

    if (len != ETH_ALEN) {
        logger(LOG_ERR, "%s: Unexpected address length %lu", __func__, len);
        return false;
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
}

static bool _tuntap_read(tuntap_t *tuntap, void *buf, size_t buf_size, size_t *pkt_size)
{
    tt_data_win_t *data = tuntap_data(tuntap);
    DWORD read_bytes;

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
    if (read_bytes == 0)
        return initiate_overlapped_read(tuntap);

    // The destination buffer must be large enough to hold the packet
    if (read_bytes > buf_size) {
        logger(LOG_CRIT, "%s: Buffer size is too small (%lu/%zu bytes)",
            __func__, read_bytes, buf_size);
        errno = EINVAL;
        initiate_overlapped_read(tuntap);
        return false;
    }

    // Set the read packet's size and copy it
    memcpy(buf, data->read_buf, read_bytes);
    *pkt_size = read_bytes;
    return initiate_overlapped_read(tuntap);
}

static bool _tuntap_write(tuntap_t *tuntap, const void *packet, size_t packet_size)
{
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
    if (packet_size > TUNTAP_BUFSIZE) {
        logger(LOG_WARN,
            "%s: Dropping packet bigger than the buffer size (%zu/%d)",
            __func__, packet_size, TUNTAP_BUFSIZE);
        return true;
    }

    // Copy the packet to the write buffer
    // This must be done because the overlapped write can run in the background
    // and the packet pointer is unsafe to use after returning
    memcpy(data->write_buf, packet, packet_size);

    // Write the packet
    if (WriteFile(data->device_handle, data->write_buf, packet_size,
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
    const struct tuntap_drv tuntap_drv = {
        .is_tap = true, // tap-windows6 driver only supports TAP (layer 2)
        .close = _tuntap_close,
        .read = _tuntap_read,
        .write = _tuntap_write,
        .init_aio_event = _tuntap_init_aio_event
    };

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
        logger(LOG_CRIT, "No adapter found for TUN/TAP device %s", adapter_name);
        return NULL;
    }
    logger_debug(DBG_TUNTAP, "Opened adapter: %s (handle: %p)",
        adapter_subpath, adapter_handle);

    // Create the TUN/TAP device
    tuntap_t *tuntap = tuntap_empty(&tuntap_drv, tap);
    tt_data_win_t *data;

    // Copy the adapter's name and ID
    tuntap_set_devname(tuntap, adapter_name);
    tuntap_set_devid(tuntap, adapter_id);

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

    // Get the adapter's MAC address
    if (!_tuntap_get_macaddr(tuntap, &data->mac_addr)) {
        logger(LOG_WARN, "Failed to get the adapter's MAC address");
        memset(&data->mac_addr, 0, sizeof(data->mac_addr));
    }

    // Initiate reading from the device
    if (!initiate_overlapped_read(tuntap))
        goto err_tuntap;

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
