#include "logger.h"
#include "xalloc.h"
#include "tuntap.h"
#include "macros.h"
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
} tt_data_win_t;
#define tuntap_data(tt) ((tt_data_win_t *) (tt)->data.ptr)

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

    if (!DeviceIoControl(tuntap_data(tuntap)->device_handle, TAP_WIN_IOCTL_SET_MEDIA_STATUS,
            &status, sizeof(status), &status, sizeof(status), &len, NULL))
    {
        logger(LOG_CRIT, "Failed to enable TUN/TAP device %s: %s", tuntap->dev_name,
            win_strerror_last());
        return false;
    }
    return true;
}

// Read from the device handle and write the data to the pollfd pipe
#define pollfd_hdr_size (sizeof(DWORD))
static void *tuntap_pollfd_thread(void *data)
{
    tuntap_t *tuntap = (tuntap_t *) data;
    OVERLAPPED *ol = (OVERLAPPED *) tuntap_data(tuntap)->read_ol;

    uint8_t _buf[pollfd_hdr_size + 2048];
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
    tt_data_win_t *data;

    // Copy the adapter's name and ID
    tuntap->dev_name = xstrdup(adapter_name);
    tuntap->dev_name_size = strlen(tuntap->dev_name) + 1;
    tuntap->dev_id = xstrdup(adapter_id);
    tuntap->dev_id_size = strlen(tuntap->dev_id) + 1;

    // Allocate the tuntap data
    tuntap->data.ptr = xzalloc(sizeof(tt_data_win_t));
    data = tuntap_data(tuntap);

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

bool tuntap_write(tuntap_t *tuntap, void *packet, size_t packet_size)
{
    OVERLAPPED *ol = (OVERLAPPED *) tuntap_data(tuntap)->write_ol;
    DWORD written_bytes;

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

int tuntap_pollfd(tuntap_t *tuntap)
{
    return tuntap_data(tuntap)->pollfd_read;
}