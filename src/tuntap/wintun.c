#include "tuntap/wintun.h"
#include "tuntap.h"
#include "logger.h"
#include "xalloc.h"
#include "macros_windows.h"
#include "macros_assert.h"
#include <stdbool.h>
#include <string.h>

struct wintun_ctx {
    HMODULE Wintun;

    WINTUN_CREATE_ADAPTER_FUNC *WintunCreateAdapter;
    WINTUN_CLOSE_ADAPTER_FUNC *WintunCloseAdapter;
    WINTUN_OPEN_ADAPTER_FUNC *WintunOpenAdapter;
    WINTUN_GET_ADAPTER_LUID_FUNC *WintunGetAdapterLUID;
    WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC *WintunGetRunningDriverVersion;
    WINTUN_DELETE_DRIVER_FUNC *WintunDeleteDriver;
    WINTUN_SET_LOGGER_FUNC *WintunSetLogger;
    WINTUN_START_SESSION_FUNC *WintunStartSession;
    WINTUN_END_SESSION_FUNC *WintunEndSession;
    WINTUN_GET_READ_WAIT_EVENT_FUNC *WintunGetReadWaitEvent;
    WINTUN_RECEIVE_PACKET_FUNC *WintunReceivePacket;
    WINTUN_RELEASE_RECEIVE_PACKET_FUNC *WintunReleaseReceivePacket;
    WINTUN_ALLOCATE_SEND_PACKET_FUNC *WintunAllocateSendPacket;
    WINTUN_SEND_PACKET_FUNC *WintunSendPacket;
};
#define wintun_setfunc(ctx, funcname) \
    ((*(FARPROC *) &(ctx)->funcname = GetProcAddress((ctx)->Wintun, #funcname)) == NULL)

static bool wintun_init(struct wintun_ctx *ctx)
{
    ctx->Wintun = LoadLibraryExW(L"wintun.dll", NULL,
        LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);

    if (!ctx->Wintun)
        return false;

    if (   wintun_setfunc(ctx, WintunCreateAdapter)
        || wintun_setfunc(ctx, WintunCloseAdapter)
        || wintun_setfunc(ctx, WintunOpenAdapter)
        || wintun_setfunc(ctx, WintunGetAdapterLUID)
        || wintun_setfunc(ctx, WintunGetRunningDriverVersion)
        || wintun_setfunc(ctx, WintunDeleteDriver)
        || wintun_setfunc(ctx, WintunSetLogger)
        || wintun_setfunc(ctx, WintunStartSession)
        || wintun_setfunc(ctx, WintunEndSession)
        || wintun_setfunc(ctx, WintunGetReadWaitEvent)
        || wintun_setfunc(ctx, WintunReceivePacket)
        || wintun_setfunc(ctx, WintunReleaseReceivePacket)
        || wintun_setfunc(ctx, WintunAllocateSendPacket)
        || wintun_setfunc(ctx, WintunSendPacket))
    {
        DWORD err = GetLastError();
        FreeLibrary(ctx->Wintun);
        SetLastError(err);
        return false;
    }

    return true;
}

static void wintun_free(struct wintun_ctx *ctx)
{
    if (ctx->Wintun)
        FreeLibrary(ctx->Wintun);
    memset(ctx, 0, sizeof(*ctx));
}

static void wintun_copy_ctx(struct wintun_ctx *dest, const struct wintun_ctx *src)
{
    *dest = *src;
}

typedef struct tt_data_win {
    struct wintun_ctx wintun_ctx;

    WINTUN_ADAPTER_HANDLE adapter;
    WINTUN_SESSION_HANDLE session;

    DWORD version;

    HANDLE read_wait_event;
} tt_data_win_t;
#define tuntap_data(tt) ((tt_data_win_t *) (tt)->data.ptr)
#define tuntap_wintun(tt) tuntap_data(tt)->wintun_ctx

static void _tuntap_close(tuntap_t *tuntap)
{
    logger_debug(DBG_TUNTAP, "Ending session");
    tuntap_wintun(tuntap).WintunEndSession(tuntap_data(tuntap)->session);

    logger_debug(DBG_TUNTAP, "Closing adapter");
    tuntap_wintun(tuntap).WintunCloseAdapter(tuntap_data(tuntap)->adapter);

    logger_debug(DBG_TUNTAP, "Freeing Wintun");
    wintun_free(&tuntap_wintun(tuntap));

    free(tuntap->data.ptr);
}

static bool _tuntap_read(tuntap_t *tuntap, void *buf, size_t buf_size, size_t *pkt_size)
{
    DWORD wt_packet_size;
    BYTE *wt_packet = tuntap_wintun(tuntap).WintunReceivePacket(tuntap_data(tuntap)->session, &wt_packet_size);

    if (wt_packet) {
        const bool packet_can_be_written = wt_packet_size <= buf_size;

        if (packet_can_be_written) {
            memcpy(buf, wt_packet, wt_packet_size);
            *pkt_size = wt_packet_size;
        } else {
            logger(LOG_ERR, "%s: Packet size (%lu bytes) exceeds buffer size (%zu bytes)",
                __func__, wt_packet_size, buf_size);
            errno = EINVAL;
        }

        tuntap_wintun(tuntap).WintunReleaseReceivePacket(tuntap_data(tuntap)->session, wt_packet);

        // Set the internal read_wait_event manually because it is automatically reset
        // We need to do this to keep signaling the event loop until no more packets are available
        //
        // This works with Wintun 0.14.1 but may break on other versions
        SetEvent(tuntap_data(tuntap)->read_wait_event);

        return packet_can_be_written;

    } else {
        const DWORD err = GetLastError();

        *pkt_size = 0;

        // No more packets are available for reading, this is not an error
        if (err == ERROR_NO_MORE_ITEMS)
            return true;

        logger(LOG_ERR, "%s: %s", __func__, win_strerror(err));
        return false;
    }
}

static bool _tuntap_write(tuntap_t *tuntap, const void *packet, size_t packet_size)
{
    BYTE *wt_packet = tuntap_wintun(tuntap).WintunAllocateSendPacket(tuntap_data(tuntap)->session, packet_size);

    if (!wt_packet) {
        const DWORD err = GetLastError();

        // This can happen if the ring is full, not actually an error
        if (err == ERROR_BUFFER_OVERFLOW) {
            logger_debug(DBG_TUNTAP, "Ring is full, dropping packet of %zu bytes", packet_size);
            return true;
        }

        logger(LOG_ERR, "%s: %s", __func__, win_strerror(err));
        return false;
    }

    memcpy(wt_packet, packet, packet_size);
    tuntap_wintun(tuntap).WintunSendPacket(tuntap_data(tuntap)->session, wt_packet);
    return true;
}

static void _tuntap_init_aio_event(tuntap_t *tuntap, aio_event_t *event)
{
    aio_event_set_handles(event, tuntap_data(tuntap)->read_wait_event, false, NULL, false);
}

static WINTUN_ADAPTER_HANDLE create_adapter(struct wintun_ctx *ctx, const char *devname)
{
    size_t wide_devname_len;
    wchar_t *wide_devname;
    WINTUN_ADAPTER_HANDLE adapter;

    wide_devname_len = strlen(devname) + 1;
    wide_devname = xzalloc(wide_devname_len * sizeof(wchar_t));
    assert(MultiByteToWideChar(CP_ACP, 0, devname, -1, wide_devname, wide_devname_len) > 0);
    adapter = ctx->WintunCreateAdapter(wide_devname, L"Osh", NULL);

    free(wide_devname);
    return adapter;
}

static void logger_callback(
    WINTUN_LOGGER_LEVEL wt_level,
    __attribute__((unused)) DWORD64 wt_timestamp,
    const WCHAR *wt_message)
{
    loglevel_t level;

    switch (wt_level) {
        case WINTUN_LOG_INFO: level = LOG_INFO; break;
        case WINTUN_LOG_WARN: level = LOG_WARN; break;
        case WINTUN_LOG_ERR:  level = LOG_ERR;  break;
        default:
            logger(LOG_WARN, "Discarded Wintun log message with unknown level");
            return;
    }

    if (logger_is_level_enabled(level, logger_get_level())) {
        size_t msg_len;
        char *msg;

        msg_len = 1024;
        msg = xalloc(msg_len);
        assert(WideCharToMultiByte(CP_UTF8, 0, wt_message, -1, msg, msg_len, NULL, NULL) > 0);
        logger(level, "Wintun: %s", msg);
        free(msg);
    }
}

tuntap_t *tuntap_open_wintun(const char *devname, bool tap)
{
    const struct tuntap_drv tuntap_drv = {
        .is_tap = false, // WinTUN only supports TUN (layer 3)
        .close = _tuntap_close,
        .read = _tuntap_read,
        .write = _tuntap_write,
        .init_aio_event = _tuntap_init_aio_event
    };

    // Initialize device name
    char final_devname[128];

    if (devname) {
        const size_t maxlen = sizeof(final_devname) - 1;
        const size_t devname_len = strlen(devname);

        if (devname_len > maxlen)
            logger(LOG_WARN, "TUN/TAP device name is too long, it will be truncated");
        strncpy(final_devname, devname, maxlen);
    } else {
        tuntap_generate_devname(final_devname, sizeof(final_devname), "OshWintun");
    }

    // Initiliaze Wintun and create adapter
    struct wintun_ctx wintun_ctx;
    WINTUN_ADAPTER_HANDLE adapter;
    WINTUN_SESSION_HANDLE session;

    logger_debug(DBG_TUNTAP, "Initializing Wintun");
    if (!wintun_init(&wintun_ctx)) {
        logger(LOG_ERR, "Failed to initialize Wintun: %s", win_strerror(GetLastError()));
        return NULL;
    }

    wintun_ctx.WintunSetLogger(logger_callback);

    logger_debug(DBG_TUNTAP, "Creating adapter %s", final_devname);
    adapter = create_adapter(&wintun_ctx, final_devname);
    if (!adapter) {
        logger(LOG_ERR, "Failed to create adapter %s: %s", final_devname, win_strerror(GetLastError()));
        wintun_free(&wintun_ctx);
        return NULL;
    }

    logger_debug(DBG_TUNTAP, "Starting session");
    session = wintun_ctx.WintunStartSession(adapter, 0x400000);
    if (!session) {
        logger(LOG_ERR, "Failed to start session with adapter %s: %s", final_devname, win_strerror(GetLastError()));
        wintun_ctx.WintunCloseAdapter(adapter);
        wintun_free(&wintun_ctx);
        return NULL;
    }

    // Network adapter was created successfully, create tuntap_t
    tuntap_t *tuntap;

    tuntap = tuntap_empty(&tuntap_drv, tap);
    tuntap_set_devname(tuntap, final_devname);
    tuntap->data.ptr = xzalloc(sizeof(tt_data_win_t));

    wintun_copy_ctx(&tuntap_wintun(tuntap), &wintun_ctx);
    tuntap_data(tuntap)->adapter = adapter;
    tuntap_data(tuntap)->session = session;

    tuntap_data(tuntap)->version = tuntap_wintun(tuntap).WintunGetRunningDriverVersion();
    tuntap_data(tuntap)->read_wait_event = tuntap_wintun(tuntap).WintunGetReadWaitEvent(tuntap_data(tuntap)->session);

    logger_debug(DBG_TUNTAP, "Opened Wintun device %s (v%lu.%lu)",
        tuntap->dev_name,
        (tuntap_data(tuntap)->version >> 16) & 0xff,
        (tuntap_data(tuntap)->version >> 0) & 0xff);

    return tuntap;
}
