#include "logger.h"
#include "xalloc.h"
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <sys/wait.h>
#include <unistd.h>

typedef struct command {
    char *name;    // Command name (not case sensitive)
    char *cmdline; // Actual command to execute
} command_t;

static command_t commands[] = {
    { .name = "DevUp"  , .cmdline = NULL },
    { .name = "DevDown", .cmdline = NULL },
    { .name = "OnResolverUpdate", .cmdline = NULL },
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

#if defined(_WIN32) || defined(__CYGWIN__)
#define shell_filename "cmd.exe"
#define shell_fullpath "C:\\Windows\\System32\\" shell_filename

static int oshd_system(const char *command)
{
    pid_t pid = fork();

    if (pid < 0) {
        return -1;
    } else if (pid > 0) {
        int status = -1;

        if (waitpid(pid, &status, 0) != pid) {
            logger(LOG_CRIT, "oshd_system: waitpid(%i): %s", pid, strerror(errno));
            return -1;
        }
        return status;
    } else {
        execl(shell_fullpath, shell_filename, "/q", "/c", command, NULL);
        logger(LOG_CRIT, "oshd_system: execl: %s", strerror(errno));
        abort();
    }
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