#include "logger.h"
#include "xalloc.h"
#include "tuntap.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

// Set O_NONBLOCK for fd
static bool tuntap_nonblock(int fd)
{
    int flags;

    if ((flags = fcntl(fd, F_GETFL, 0)) < 0) {
        logger(LOG_ERR, "fcntl(%i, F_GETFL): %s", fd, strerror(errno));
        return false;
    }

    flags |= O_NONBLOCK;
    if (fcntl(fd, F_SETFL, flags) < 0) {
        logger(LOG_ERR, "fcntl(%i, F_SETFL, %i): %s", fd, flags, strerror(errno));
        return false;
    }
    return true;
}

// Allocate a zeroed-out tuntap_t
// Set is_tap
static tuntap_t *tuntap_empty(bool is_tap)
{
    tuntap_t *tuntap = xzalloc(sizeof(tuntap_t));

    tuntap->is_tap = is_tap;
    return tuntap;
}

// Free common allocated resources in tuntap_t
static void tuntap_free_common(tuntap_t *tuntap)
{
    free(tuntap->dev_name);
    free(tuntap->dev_id);
}

#if defined(_WIN32) || defined(__CYGWIN__)
// The code for interfacing with the tap-windows6 driver is heavily inspired by
// https://github.com/OpenVPN/openvpn/blob/master/src/openvpn/tun.c

#include "tap-windows.h"
#include <windows.h>
#include <winioctl.h>
#include <winerror.h>
#include <stdio.h>

static const char *win_strerror(DWORD errcode)
{
    static char errstr[256];

    if (!FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, NULL, errcode, 0,
        errstr, sizeof(errstr), NULL))
    {
        snprintf(errstr, sizeof(errstr), "Error code %u (FormatMessage failed with %u)",
            errcode, GetLastError());
    } else {
        // Remove the newline at the end of the error string
        // TODO: There could be a better way of doing this, this is very ugly
        size_t errstr_len = strlen(errstr);

        if (   errstr_len > 0
            && (errstr[errstr_len - 1] == '\n' || errstr[errstr_len - 1] == '\r'))
        {
            errstr[errstr_len - 1] = '\0';
            errstr_len -= 1;
            if (   errstr_len > 0
                && (errstr[errstr_len - 1] == '\n' || errstr[errstr_len - 1] == '\r'))
            {
                errstr[errstr_len - 1] = '\0';
                errstr_len -= 1;
            }
        }
    }
    return errstr;
}
#define win_strerror_last() win_strerror(GetLastError())

// Enable the TUN/TAP device
// The adapter is not enabled by default and cannot be used before enabling it
static bool tuntap_device_enable(tuntap_t *tuntap)
{
    ULONG status = 1;
    DWORD len;

    if (!DeviceIoControl(tuntap->device_handle, TAP_WIN_IOCTL_SET_MEDIA_STATUS,
            &status, sizeof(status), &status, sizeof(status), &len, NULL))
    {
        logger(LOG_CRIT, "Failed to enable TUN/TAP device %s: %s", tuntap->dev_name,
            win_strerror_last());
        return false;
    }
    return true;
}

// Read from the device handle and write the data to the pollfd pipe
#define pollfd_buf_offset (sizeof(DWORD))
static void *tuntap_pollfd_thread(void *data)
{
    tuntap_t *tuntap = (tuntap_t *) data;
    OVERLAPPED *ol = (OVERLAPPED *) tuntap->read_ol;

    uint8_t _buf[2048 + pollfd_buf_offset];
    uint8_t *buf = _buf + pollfd_buf_offset;
    DWORD buf_size = sizeof(_buf) - pollfd_buf_offset;
    DWORD read_bytes;
    DWORD err;

    while (1) {
        // Reset the overlapped event
        ResetEvent(ol->hEvent);

        // Read the next TAP packet
        if (ReadFile(tuntap->device_handle, buf, buf_size, &read_bytes, ol)) {
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

        // Write the packet's size
        *((DWORD *) _buf) = read_bytes;

        // Write the packet size followed by the packet data to the pollfd pipe
        size_t total_size = read_bytes + sizeof(DWORD);
        ssize_t wb = write(tuntap->pollfd_write, _buf, total_size);

        if (wb < 0 || (size_t) wb != total_size) {
            logger(LOG_CRIT, "%s: Failed to write packet to pollfd: %s (%zi/%u)",
                tuntap->dev_name, strerror(errno), wb, read_bytes);
        }
    }

    // The pipe is not useful anymore, close it
    close(tuntap->pollfd_read);
    close(tuntap->pollfd_write);
    tuntap->pollfd_read = -1;
    tuntap->pollfd_write = -1;

    logger(LOG_CRIT, "tuntap_pollfd_thread exitting");
    pthread_exit(NULL);
}

tuntap_t *tuntap_open(const char *devname, bool tap)
{
    // The tap-windows6 driver only supports TAP (layer 2) mode
    if (!tap) {
        logger(LOG_CRIT, "TUN devices are not yet supported on Windows");
        return NULL;
    }

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

    // Copy the adapter's name and ID
    tuntap->dev_name = xstrdup(adapter_name);
    tuntap->dev_name_size = strlen(tuntap->dev_name) + 1;
    tuntap->dev_id = xstrdup(adapter_id);
    tuntap->dev_id_size = strlen(tuntap->dev_id) + 1;

    // Set the handle
    tuntap->device_handle = adapter_handle;

    // Create the OVERLAPPED structures and events for reading and writing
    // asynchronously from/to the TUN/TAP device
    tuntap->read_ol = xzalloc(sizeof(OVERLAPPED));
    ((OVERLAPPED *) tuntap->read_ol)->hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (((OVERLAPPED *) tuntap->read_ol)->hEvent == NULL) {
        logger(LOG_CRIT, "Failed to create read event handle: %s", win_strerror_last());
        tuntap_close(tuntap);
        return NULL;
    }

    tuntap->write_ol = xzalloc(sizeof(OVERLAPPED));
    ((OVERLAPPED *) tuntap->write_ol)->hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (((OVERLAPPED *) tuntap->write_ol)->hEvent == NULL) {
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
    tuntap->pollfd_read = pollfd_pipe[0];
    tuntap->pollfd_write = pollfd_pipe[1];

    // Only the reading file descriptor needs to be non-blocking as it will have
    // to return EAGAIN or EWOULDBLOCK when no more data is ready to be read
    // from the pipe
    // The writing file descriptor should block and can because it will be on a
    // separate thread
    tuntap_nonblock(tuntap->pollfd_read);

    // Enable the adapter
    if (!tuntap_device_enable(tuntap)) {
        tuntap_close(tuntap);
        return NULL;
    }

    // Create the thread to read from the device handle and write the packets to
    // the pollfd pipe
    int err = pthread_create(&tuntap->pollfd_thread, NULL,
        &tuntap_pollfd_thread, tuntap);
    if (err) {
        logger(LOG_CRIT, "Failed to create pollfd thread: %s", strerror(err));
        tuntap->pollfd_thread = NULL;
        tuntap_close(tuntap);
        return NULL;
    }

    logger(LOG_INFO, "Opened %s device: %s (%s) (handle: %p, pollfd: %i <- %i)",
        tuntap->is_tap ? "TAP" : "TUN",
        tuntap->dev_name,
        tuntap->dev_id,
        tuntap->device_handle,
        tuntap->pollfd_read,
        tuntap->pollfd_write);
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
    // Cancel the pollfd thread before freeing data that it uses
    if (tuntap->pollfd_thread) {
        pthread_cancel(tuntap->pollfd_thread);
        pthread_join(tuntap->pollfd_thread, NULL);
    }

    // Free the OVERLAPPED structures and close the event handles
    if (tuntap->read_ol) {
        CloseHandle(((OVERLAPPED *) tuntap->read_ol)->hEvent);
        free(tuntap->read_ol);
    }
    if (tuntap->write_ol) {
        CloseHandle(((OVERLAPPED *) tuntap->write_ol)->hEvent);
        free(tuntap->write_ol);
    }

    // Close the device handle
    CloseHandle(tuntap->device_handle);

    // Close the pollfd pipe
    if (tuntap->pollfd_read > 0)
        close(tuntap->pollfd_read);
    if (tuntap->pollfd_write > 0)
        close(tuntap->pollfd_write);

    // Free the common parts of the tuntap_t structure and the structure itself
    tuntap_free_common(tuntap);
    free(tuntap);
}

bool tuntap_read(tuntap_t *tuntap, void *buf, size_t buf_size, size_t *pkt_size)
{
    DWORD size;
    ssize_t n;

    // Read the size of the next packet on the pipe
    n = read(tuntap->pollfd_read, &size, sizeof(DWORD));
    if (n < 0) {
        // If the read would block, no more data is ready to be read on the pipe
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            *pkt_size = 0;
            return true;
        }

        // Otherwise the error will be handled by the caller
        return false;
    }

    // The packet size must be fully read
    if (n != sizeof(DWORD)) {
        logger(LOG_CRIT, "tuntap_read: Incomplete packet size (%zi/%zu bytes)",
            n, sizeof(DWORD));
        errno = EIO;
        return false;
    }

    // The destination buffer must be large enough to hold the packet
    if (size > buf_size) {
        logger(LOG_CRIT, "tuntap_read: Buffer size is too small (%u/%zu bytes)",
            size, buf_size);
        errno = EINVAL;
        return false;
    }

    // Read the packet
    n = read(tuntap->pollfd_read, buf, size);
    if (n < 0)
        return false;
    if (n != size) {
        logger(LOG_CRIT, "tuntap_read: Incomplete packet (%zi/%u bytes)",
            n, size);
        errno = EIO;
        return false;
    }

    // Set the read packet's size
    *pkt_size = size;
    return true;
}

bool tuntap_write(tuntap_t *tuntap, void *packet, size_t packet_size)
{
    OVERLAPPED *ol = (OVERLAPPED *) tuntap->write_ol;
    DWORD written_bytes;

    // Reset the overlapped event handle
    ResetEvent(ol->hEvent);
    if (WriteFile(tuntap->device_handle, packet, (DWORD) packet_size, &written_bytes, ol)) {
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

int tuntap_pollfd(tuntap_t *tuntap)
{
    return tuntap->pollfd_read;
}
#else
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>

#define tuntap_filepath "/dev/net/tun"

// https://github.com/torvalds/linux/blob/master/Documentation/networking/tuntap.rst

tuntap_t *tuntap_open(const char *devname, bool tap)
{
    tuntap_t *tuntap;
    struct ifreq ifr;
    int fd;

    if ((fd = open(tuntap_filepath, O_RDWR)) < 0) {
        logger(LOG_CRIT, "Failed to open " tuntap_filepath ": %s", strerror(errno));
        return NULL;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = tap ? (IFF_TAP | IFF_NO_PI)
                        : (IFF_TUN | IFF_NO_PI);
    if (devname) {
        size_t devname_len = strlen(devname);

        if (devname_len < IFNAMSIZ) {
            memcpy(ifr.ifr_name, devname, devname_len);
        } else {
            memcpy(ifr.ifr_name, devname, IFNAMSIZ);
        }
    }

    if (ioctl(fd, TUNSETIFF, (void *) &ifr) < 0) {
        logger(LOG_CRIT, "ioctl(%i, TUNSETIFF): %s: %s", fd, devname, strerror(errno));
        close(fd);
        return NULL;
    }

    if (!tuntap_nonblock(fd)) {
        close(fd);
        return NULL;
    }

    tuntap = tuntap_empty(tap);
    tuntap->dev_name_size = IFNAMSIZ + 1;
    tuntap->dev_name = xzalloc(tuntap->dev_name_size);
    strcpy(tuntap->dev_name, ifr.ifr_name);
    tuntap->fd = fd;

    logger(LOG_INFO, "Opened %s device: %s (fd: %i)",
        tuntap->is_tap ? "TAP" : "TUN",
        tuntap->dev_name,
        tuntap->fd);
    return tuntap;
}

void tuntap_close(tuntap_t *tuntap)
{
    close(tuntap->fd);
    tuntap_free_common(tuntap);
    free(tuntap);
}

bool tuntap_read(tuntap_t *tuntap, void *buf, size_t buf_size, size_t *pkt_size)
{
    ssize_t n = read(tuntap->fd, buf, buf_size);

    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            *pkt_size = 0;
            return true;
        }

        logger(LOG_CRIT, "%s: read: %s", tuntap->dev_name, strerror(errno));
        return false;
    }
    *pkt_size = (size_t) n;
    return true;
}

bool tuntap_write(tuntap_t *tuntap, void *packet, size_t packet_size)
{
    ssize_t n = write(tuntap->fd, packet, packet_size);

    if (n < 0) {
        logger(LOG_CRIT, "%s: write: %s", tuntap->dev_name, strerror(errno));
        return false;
    }
    return true;
}

int tuntap_pollfd(tuntap_t *tuntap)
{
    return tuntap->fd;
}
#endif