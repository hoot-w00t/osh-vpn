#include "signals.h"
#include "signals_callbacks.h"
#include "macros_assert.h"
#include "logger.h"
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

#if PLATFORM_IS_WINDOWS
#include "macros_windows.h"
#else
#include <fcntl.h>
#endif

typedef void (*signal_callback_t)(void);

typedef struct signal_handler {
    const signal_t *signals;    // Array of signal numbers
    const size_t signals_count; // Number of signals in the array

    signal_callback_t callback; // Function called when one of the signals is
                                // received

    // Pipe/handle used with the AIO event
    // FIXME: Data races are possible on pipe_write once our catching function
    //        is setup, this may cause a SetEvent/write on an undefined file
    //        descriptor
#if PLATFORM_IS_WINDOWS
    HANDLE pipe_write;
#else
    int pipe_write;
#endif
} signal_handler_t;

#if PLATFORM_IS_WINDOWS
    #define DEFAULT_PIPE_WRITE NULL

    static const signal_t _exit_signals[] = {CTRL_C_EVENT, CTRL_BREAK_EVENT, CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT};

    #define DIGRAPH_SIGNALS         NULL
    #define DIGRAPH_SIGNALS_COUNT   0
#else
    #define DEFAULT_PIPE_WRITE -1

    static const signal_t _exit_signals[] = {SIGINT, SIGTERM};
    static const signal_t _digraph_signals[] = {SIGUSR1};

    #define DIGRAPH_SIGNALS         _digraph_signals
    #define DIGRAPH_SIGNALS_COUNT   sizeof(DIGRAPH_SIGNALS) / sizeof(*DIGRAPH_SIGNALS)
#endif

#define EXIT_SIGNALS                _exit_signals
#define EXIT_SIGNALS_COUNT          sizeof(EXIT_SIGNALS) / sizeof(*EXIT_SIGNALS)

#define signal_handlers_count (2)
static signal_handler_t signal_handlers[signal_handlers_count] = {
    {
        .signals = EXIT_SIGNALS,
        .signals_count = EXIT_SIGNALS_COUNT,
        .callback = oshd_signal_exit,
        .pipe_write = DEFAULT_PIPE_WRITE
    },
    {
        .signals = DIGRAPH_SIGNALS,
        .signals_count = DIGRAPH_SIGNALS_COUNT,
        .callback = oshd_signal_digraph,
        .pipe_write = DEFAULT_PIPE_WRITE
    }
};

// FIXME: Possible data race
static bool signal_handler_debug = false;

// Get the signal handler
// Returns NULL if the signal isn't registered
static signal_handler_t *get_signal_handler(signal_t sig)
{
    for (size_t i = 0; i < signal_handlers_count; ++i) {
        signal_handler_t *sh = &signal_handlers[i];

        for (size_t j = 0; j < sh->signals_count; ++j) {
            if (sh->signals[j] == sig)
                return sh;
        }
    }

    return NULL;
}

// Log message and signal number
// This function is async-signal-safe
static void safe_log_signal(const char *msg, signal_t sig, bool is_error)
{
    logger_write_msg(msg, is_error);
    logger_write_msg(" (", is_error);
    logger_write_uint((uintmax_t) sig, is_error);
    logger_write_msg(")\n", is_error);
}

// Signal handler return value
#if PLATFORM_IS_WINDOWS
    #define SIGHANDLER_RETVAL           WINBOOL WINAPI
    #define return_sighandler(success)  return ((success) ? TRUE : FALSE)
#else
    #define SIGHANDLER_RETVAL           void
    #define return_sighandler(success)  return
#endif

// Signal handler function to catch signals
// Sends the signal using the linked pipe_write (doesn't check if pipe_write is
//   valid)
static SIGHANDLER_RETVAL _catch_signal_func(signal_t sig)
{
    signal_handler_t *sh;

    if (signal_handler_debug)
        safe_log_signal("Caught signal", sig, false);

    sh = get_signal_handler(sig);

    if (sh) {
#if PLATFORM_IS_WINDOWS
        SetEvent(sh->pipe_write);
#else
        const uint8_t b = 0;
        const ssize_t n = write(sh->pipe_write, &b, sizeof(b));

        if (n != (ssize_t) sizeof(b))
            safe_log_signal("Failed to write to signal pipe", sig, true);
#endif
        return_sighandler(true);
    } else {
        safe_log_signal("Caught signal without handler", sig, true);
        return_sighandler(false);
    }
}

// Enable or disable catching a signal with _catch_signal_func()
static void catch_signal(bool enable, signal_t sig)
{
    if (enable) {
        logger_debug(DBG_SIGNALS, "%s signal " PRI_SIGNAL_T " (%s)",
            "Enabling", sig, signal_name(sig));

#if PLATFORM_IS_WINDOWS
        SetConsoleCtrlHandler(_catch_signal_func, TRUE);
#else
        signal(sig, _catch_signal_func);
#endif
    } else {
        logger_debug(DBG_SIGNALS, "%s signal " PRI_SIGNAL_T " (%s)",
            "Disabling", sig, signal_name(sig));

#if PLATFORM_IS_WINDOWS
        SetConsoleCtrlHandler(NULL, FALSE);
#else
        signal(sig, SIG_DFL);
#endif
    }
}

// Enable or disable catching all signals of a handler
// Signals are always disabled if pipe_write is not valid
static void catch_signal_handler(bool enable, const signal_handler_t *sh)
{
    if (sh->pipe_write == DEFAULT_PIPE_WRITE && enable) {
        logger_debug(DBG_SIGNALS, "Force disabling signal with default pipe write");
        enable = false;
    }

    for (size_t i = 0; i < sh->signals_count; ++i)
        catch_signal(enable, sh->signals[i]);
}

static void signal_aio_delete(aio_event_t *event)
{
    signal_handler_t *sh = (signal_handler_t *) event->userdata;

    catch_signal_handler(false, sh);

#if PLATFORM_IS_WINDOWS
    logger_debug(DBG_SIGNALS, "Closing event handle %p", event->read_handle);
    if (event->read_handle)
        CloseHandle(event->read_handle);
#else
    logger_debug(DBG_SIGNALS, "Closing read pipe %d", event->fd);
    close(event->fd);
#endif
}

static void signal_aio_read(aio_event_t *event)
{
    signal_handler_t *sh = (signal_handler_t *) event->userdata;

    // Read/reset signal from the pipe
#if PLATFORM_IS_WINDOWS
    ResetEvent(event->read_handle);
#else
    uint8_t b;
    const ssize_t n = read(event->fd, &b, sizeof(b));

    if (n != (ssize_t) sizeof(b) || b != 0) {
        if (!IO_WOULDBLOCK(errno)) {
            logger(LOG_ERR, "%s: %s: %s", __func__, "read", strerror(errno));
            aio_event_del(event);
        }
        return;
    }
#endif

    assert(sh->callback != NULL);
    sh->callback();

    // Some backends clear the signal catch function after receiving a signal so
    // we must re-enable it
    catch_signal_handler(true, sh);
}

static void signal_aio_error(
    aio_event_t *event,
    __attribute__((unused)) aio_poll_event_t revents)
{
    logger(LOG_ERR, "Signal pipe broken");
    aio_event_del(event);
}

// Create signal pipe and add AIO event
// Returns false on error (errors are not critical, but signals won't be caught)
static bool create_signal_pipe(aio_t *aio, signal_handler_t *sh)
{
    aio_event_t base_event;

    aio_event_init_base(&base_event);
    base_event.userdata = sh;
    base_event.poll_events = AIO_READ;
    base_event.cb_delete = signal_aio_delete;
    base_event.cb_read = signal_aio_read;
    base_event.cb_error = signal_aio_error;

#if PLATFORM_IS_WINDOWS
    sh->pipe_write = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (sh->pipe_write == NULL) {
        logger(LOG_ERR, "%s: %s: %s", "__func__", "CreateEvent", win_strerror_last());
        return false;
    }
    logger_debug(DBG_SIGNALS, "Created event handle %p", sh->pipe_write);
    aio_event_set_handles(&base_event, sh->pipe_write, true, NULL, false);
#else
    int pipefd[2];

    if (pipe(pipefd) < 0) {
        logger(LOG_ERR, "%s: %s: %s", __func__, "pipe", strerror(errno));
        return false;
    }
    fcntl(pipefd[0], F_SETFL, O_NONBLOCK);
    fcntl(pipefd[1], F_SETFL, O_NONBLOCK);
    logger_debug(DBG_SIGNALS, "Created pipe %d -> %d", pipefd[1], pipefd[0]);
    sh->pipe_write = pipefd[1];
    base_event.fd = pipefd[0];
#endif

    aio_event_add(aio, &base_event);
    return true;
}

void signal_init(aio_t *aio)
{
    logger_debug(DBG_SIGNALS, "Initializing signal handlers");

    signal_handler_debug = logger_is_debugged(DBG_SIGNALS);
    for (size_t i = 0; i < signal_handlers_count; ++i) {
        signal_handler_t *sh = &signal_handlers[i];

        if (sh->pipe_write == DEFAULT_PIPE_WRITE && sh->signals_count > 0) {
            assert(sh->signals != NULL);
            if (create_signal_pipe(aio, sh))
                catch_signal_handler(true, sh);
        }
    }
}

void signal_deinit(void)
{
    logger_debug(DBG_SIGNALS, "De-initializing signal handlers");

    for (size_t i = 0; i < signal_handlers_count; ++i) {
        signal_handler_t *sh = &signal_handlers[i];

        catch_signal_handler(false, sh);

#if PLATFORM_IS_WINDOWS
        // pipe_write handle is closed by the AIO event's delete callback
#else
        logger_debug(DBG_SIGNALS, "Closing write pipe %d", sh->pipe_write);
        close(sh->pipe_write);
#endif

        sh->pipe_write = DEFAULT_PIPE_WRITE;
    }

    signal_handler_debug = false;
}

// Return the name of a signal
// This function is async-signal-safe
const char *signal_name(signal_t sig)
{
#define name_case(x) case x: return #x

    switch (sig) {
#if PLATFORM_IS_WINDOWS
        name_case(CTRL_C_EVENT);
        name_case(CTRL_BREAK_EVENT);
        name_case(CTRL_CLOSE_EVENT);
        name_case(CTRL_LOGOFF_EVENT);
        name_case(CTRL_SHUTDOWN_EVENT);
#else
        name_case(SIGINT);
        name_case(SIGILL);
        name_case(SIGABRT);
        name_case(SIGFPE);
        name_case(SIGSEGV);
        name_case(SIGTERM);
        name_case(SIGHUP);
        name_case(SIGQUIT);
        name_case(SIGTRAP);
        name_case(SIGKILL);
        name_case(SIGPIPE);
        name_case(SIGALRM);
        name_case(SIGURG);
        name_case(SIGSTOP);
        name_case(SIGTSTP);
        name_case(SIGCONT);
        name_case(SIGCHLD);
        name_case(SIGTTIN);
        name_case(SIGTTOU);
        name_case(SIGPOLL);
        name_case(SIGXFSZ);
        name_case(SIGXCPU);
        name_case(SIGVTALRM);
        name_case(SIGPROF);
        name_case(SIGUSR1);
        name_case(SIGUSR2);
#endif

        default: return "Unknown";
    }

#undef signal_name_case
}
