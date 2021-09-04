#ifndef _OSH_TUNTAP_H
#define _OSH_TUNTAP_H

#include <stdbool.h>
#include <stddef.h>

#if defined(_WIN32) || defined(__CYGWIN__)
#include <pthread.h>
#endif

struct tuntap {
    // true if the device is running in layer 2
    bool is_tap;

    // Device name
    char *dev_name;
    size_t dev_name_size;

    // Device ID (depends on the platform)
    char *dev_id;
    size_t dev_id_size;

#if defined(_WIN32) || defined(__CYGWIN__)
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
#else
    // Device's file descriptor
    int fd;
#endif
};

typedef struct tuntap tuntap_t;

// Open TUN/TAP device
// If devname is NULL or empty the device name will be determined automatically
// (if possible)
// If tap is true the device will use layer 2 (TAP), otherwise it will use
// layer 3 (TUN)
// Returns NULL on error
tuntap_t *tuntap_open(const char *devname, bool tap);

// Close TUN/TAP device and free all resources
// The pointer will also be freed, it should not be used after calling this
// function
void tuntap_close(tuntap_t *tuntap);

// Read a packet from the TUN/TAP device to buf which should be of buf_size
// Sets *pkt_size to the actual size of the packet (<= buf_size)
// If *pkt_size is 0 there are no packets ready to be read
// Returns false on error
bool tuntap_read(tuntap_t *tuntap, void *buf, size_t buf_size, size_t *pkt_size);

// Write a packet to the TUN/TAP device
// Returns false on error
bool tuntap_write(tuntap_t *tuntap, void *packet, size_t packet_size);

// Returns a non-blocking file descriptor that can be used by poll()
int tuntap_pollfd(tuntap_t *tuntap);

// Close TUN/TAP device pointed by tuntap, sets it to NULL after
static inline void tuntap_close_at(tuntap_t **tuntap)
{
    tuntap_close(*tuntap);
    *tuntap = NULL;
}

#endif