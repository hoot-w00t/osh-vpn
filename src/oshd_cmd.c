#include "logger.h"
#include "xalloc.h"
#include "macros.h"
#include "macros_windows.h"
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>

#if PLATFORM_IS_WINDOWS
#include <windows.h>
#include <stdio.h>

#ifdef WIFEXITED
#undef WIFEXITED
#endif
#define WIFEXITED(status) (true)

#ifdef WEXITSTATUS
#undef WEXITSTATUS
#endif
#define WEXITSTATUS(status) (status)
#else
#include <unistd.h>
#include <sys/wait.h>
#endif

typedef struct command {
    char *name;    // Command name (not case sensitive)
    char *cmdline; // Actual command to execute
} command_t;

static command_t commands[] = {
    { .name = "DevUp"  , .cmdline = NULL },
    { .name = "DevDown", .cmdline = NULL },

    // Dynamic device mode commands to configure the TUN/TAP device
    { .name = "DynamicEnableDev" , .cmdline = NULL },
    { .name = "DynamicDisableDev", .cmdline = NULL },
    { .name = "DynamicAddIP6"    , .cmdline = NULL },
    { .name = "DynamicAddIP4"    , .cmdline = NULL },
    { .name = "DynamicDelIP6"    , .cmdline = NULL },
    { .name = "DynamicDelIP4"    , .cmdline = NULL },

    { NULL, NULL }
};

// Returns a pointer to the command if it exists, NULL otherwise
static command_t *find_command(const char *name)
{
    for (size_t i = 0; commands[i].name; ++i) {
        if (!strcasecmp(name, commands[i].name))
            return &commands[i];
    }

    // This error should never show up, if it does the code has a glitch
    logger(LOG_CRIT, "Invalid command name '%s'", name);
    return NULL;
}

// Set the actual command to execute for this command
void oshd_cmd_set(const char *name, const char *cmdline)
{
    command_t *cmd = find_command(name);

    if (cmd) {
        logger_debug(DBG_CMD, "Setting %s command to '%s'", cmd->name, cmdline);
        free(cmd->cmdline);
        cmd->cmdline = xstrdup(cmdline);
    }
}

// Set the command to execute if it is currently not set
// If the command is already set, this is ignored
void oshd_cmd_tryset(const char *name, const char *cmdline)
{
    const command_t *cmd = find_command(name);

    if (cmd && !cmd->cmdline)
        oshd_cmd_set(name, cmdline);
}

// Disable the command line, free the allocated memory
void oshd_cmd_unset(const char *name)
{
    command_t *cmd = find_command(name);

    if (cmd) {
        logger_debug(DBG_CMD, "Unsetting %s command", cmd->name);
        free(cmd->cmdline);
        cmd->cmdline = NULL;
    }
}

// Disable all commands and free the allocated memory
void oshd_cmd_unset_all(void)
{
    for (size_t i = 0; commands[i].name; ++i) {
        free(commands[i].cmdline);
        commands[i].cmdline = NULL;
    }
}

// Set environment variable
bool oshd_cmd_setenv(const char *variable, const char *value)
{
    logger_debug(DBG_CMD, "Setting environment variable %s to '%s'",
        variable, value);

#if PLATFORM_IS_WINDOWS
    if (!SetEnvironmentVariable(variable, value)) {
        logger(LOG_ERR, "Failed to set environment variable %s to '%s': %s",
            variable, value, win_strerror_last());
        return false;
    }
#else
    if (setenv(variable, value, 1) < 0) {
        logger(LOG_ERR, "Failed to set environment variable %s to '%s': %s",
            variable, value, strerror(errno));
        return false;
    }
#endif

    return true;
}

// Unset environment variable
bool oshd_cmd_unsetenv(const char *variable)
{
    logger_debug(DBG_CMD, "Unsetting environment variable %s", variable);

#if PLATFORM_IS_WINDOWS
    if (!SetEnvironmentVariable(variable, NULL)) {
        logger(LOG_ERR, "Failed to unset environment variable %s: %s",
            variable, win_strerror_last());
        return false;
    }
#else
    if (unsetenv(variable) < 0) {
        logger(LOG_ERR, "Failed to unset environment variable %s: %s",
            variable, strerror(errno));
        return false;
    }
#endif

    return true;
}

#if PLATFORM_IS_WINDOWS
#define shell_filename "cmd.exe"
#define shell_fullpath "C:\\Windows\\System32\\" shell_filename

static int oshd_system(const char *command)
{
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    DWORD retcode;
    char process_cmdline[1024];

    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));
    snprintf(process_cmdline, sizeof(process_cmdline), "%s /Q /C %s",
        shell_fullpath, command);

    if (!CreateProcess(NULL, process_cmdline,
        NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
    {
        logger(LOG_CRIT, "%s: %s: %s", __func__, "CreateProcess",
            win_strerror_last());
        errno = ENOEXEC;
        return -1;
    }

    WaitForSingleObject(pi.hThread, INFINITE);
    GetExitCodeProcess(pi.hProcess, &retcode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return (int) retcode;
}
#else
#define oshd_system(command) system(command)
#endif

// Execute command associated to *name
// Returns true on success, false on error
bool oshd_cmd_execute(const char *name)
{
    command_t *cmd = find_command(name);
    int status;

    if (!cmd) return false;

    // If there is no command to execute, return a success
    if (!cmd->cmdline) return true;

    logger(LOG_INFO, "Executing %s command: '%s'", cmd->name, cmd->cmdline);
    if ((status = oshd_system(cmd->cmdline)) < 0) {
        logger(LOG_ERR, "Failed to execute %s command: %s", cmd->name,
            strerror(errno));
        return false;
    }

    if (WIFEXITED(status)) {
        int exit_status = WEXITSTATUS(status);

        if (exit_status == 0)
            return true;
        logger(LOG_ERR, "%s command exited with code %i", cmd->name, exit_status);
    } else {
        logger(LOG_ERR, "%s command terminated abnormally (status: %i)",
            cmd->name, status);
    }
    return false;
}
