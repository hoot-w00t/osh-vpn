#include "oshd_cmd.h"
#include "logger.h"
#include "xalloc.h"
#include "macros.h"
#include "macros_windows.h"
#include "macros_assert.h"
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
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
    const char *name;   // Command name (not case sensitive)
    char *cmdline;      // Actual command to execute
} command_t;

static command_t commands[] = {
    // Commands executed on events
    { .name = CMD_ON_DEV_UP,      .cmdline = NULL },
    { .name = CMD_ON_DEV_DOWN,    .cmdline = NULL },

    // Commands to configure the TUN/TAP device
    { .name = CMD_ENABLE_DEV,     .cmdline = NULL },
    { .name = CMD_DISABLE_DEV,    .cmdline = NULL },
    { .name = CMD_ADD_IP6,        .cmdline = NULL },
    { .name = CMD_ADD_IP4,        .cmdline = NULL },
    { .name = CMD_DEL_IP6,        .cmdline = NULL },
    { .name = CMD_DEL_IP4,        .cmdline = NULL },

    { .name = NULL, .cmdline = NULL }
};

// Returns a pointer to the command (NULL if invalid)
static command_t *find_command_by_name(const char *name)
{
    assert(name != NULL);

    for (size_t i = 0; commands[i].name != NULL; ++i) {
        if (!strcmp(name, commands[i].name))
            return &commands[i];
    }

    // This should never happen, if it does something went wrong
    logger(LOG_CRIT, "%s: Invalid command '%s'", __func__, name);
    return NULL;
}

// Set the actual command to execute for this command
void oshd_cmd_set(const char *name, const char *cmdline)
{
    command_t *cmd = find_command_by_name(name);

    if (cmd) {
        assert(cmdline != NULL);
        logger_debug(DBG_CMD, "Setting %s command to '%s'", cmd->name, cmdline);
        free(cmd->cmdline);
        cmd->cmdline = xstrdup(cmdline);
    }
}

// Set the command to execute if it is currently not set
// If the command is already set, this is ignored
void oshd_cmd_tryset(const char *name, const char *cmdline)
{
    const command_t *cmd = find_command_by_name(name);

    if (cmd && !cmd->cmdline)
        oshd_cmd_set(name, cmdline);
}

// Disable the command line, free the allocated memory
void oshd_cmd_unset(const char *name)
{
    command_t *cmd = find_command_by_name(name);

    if (cmd) {
        logger_debug(DBG_CMD, "Unsetting %s command", cmd->name);
        free(cmd->cmdline);
        cmd->cmdline = NULL;
    }
}

// Disable all commands and free the allocated memory
void oshd_cmd_unset_all(void)
{
    for (size_t i = 0; commands[i].name != NULL; ++i) {
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

// oshd_cmd_tryset_builtins()
#if (OSHD_CMD_TUNTAP_CFG == OSHD_CMD_TUNTAP_CFG_LINUX_IPROUTE2)
    #define ip_bin          "ip"
    #define ip_dev          "dev \"${" CMD_ENV_DEVICE "}\""
    #define ip_addr_prefix  "\"${" CMD_ENV_ADDRESS "}/${" CMD_ENV_PREFIXLEN "}\""

    #define ip_link_up      ip_bin " link set up " ip_dev
    #define ip_link_down    ip_bin " link set down " ip_dev

    #define ip_addr_add(af) ip_bin " -" af " address add " ip_addr_prefix " " ip_dev
    #define ip_addr_del(af) ip_bin " -" af " address del " ip_addr_prefix " " ip_dev

    void oshd_cmd_tryset_builtins(void)
    {
        oshd_cmd_tryset(CMD_ENABLE_DEV, ip_link_up);
        oshd_cmd_tryset(CMD_DISABLE_DEV, ip_link_down);
        oshd_cmd_tryset(CMD_ADD_IP6, ip_addr_add("6"));
        oshd_cmd_tryset(CMD_ADD_IP4, ip_addr_add("4"));
        oshd_cmd_tryset(CMD_DEL_IP6, ip_addr_del("6"));
        oshd_cmd_tryset(CMD_DEL_IP4, ip_addr_del("4"));
    }

#elif (OSHD_CMD_TUNTAP_CFG == OSHD_CMD_TUNTAP_CFG_LINUX_NET_TOOLS)
    #define ifconfig_bin            "ifconfig"
    #define ifconfig_dev            "\"${" CMD_ENV_DEVICE "}\""
    #define ifconfig_addr_prefix    "\"${" CMD_ENV_ADDRESS "}/${" CMD_ENV_PREFIXLEN "}\""
    #define ifconfig_addr_mask      "\"${" CMD_ENV_ADDRESS "}\" netmask \"${" CMD_ENV_MASK "}\""

    #define ifconfig_cmd            ifconfig_bin " " ifconfig_dev

    void oshd_cmd_tryset_builtins(void)
    {
        oshd_cmd_tryset(CMD_ENABLE_DEV,  ifconfig_cmd " up");
        oshd_cmd_tryset(CMD_DISABLE_DEV, ifconfig_cmd " down");
        oshd_cmd_tryset(CMD_ADD_IP6, ifconfig_cmd " inet6 add " ifconfig_addr_prefix);
        oshd_cmd_tryset(CMD_ADD_IP4, ifconfig_cmd " inet " ifconfig_addr_mask);
        oshd_cmd_tryset(CMD_DEL_IP6, ifconfig_cmd " inet6 del " ifconfig_addr_prefix);
        oshd_cmd_tryset(CMD_DEL_IP4, ifconfig_cmd " inet 0.0.0.0");
    }

#elif (OSHD_CMD_TUNTAP_CFG == OSHD_CMD_TUNTAP_CFG_WIN_NETSH)
    #define netsh_bin "netsh.exe"

    #define ip6_iface "interface ipv6"
    #define ip4_iface "interface ipv4"

    #define ip6_dev "interface=\"%" CMD_ENV_DEVICE "%\""
    #define ip4_dev "name=\"%" CMD_ENV_DEVICE "%\""

    #define ip_addr "address=\"%" CMD_ENV_ADDRESS "%\""
    #define ip_addr_prefix "address=\"%" CMD_ENV_ADDRESS "%/%" CMD_ENV_PREFIXLEN "%\""

    void oshd_cmd_tryset_builtins(void)
    {
        oshd_cmd_tryset(CMD_ADD_IP6, netsh_bin " " ip6_iface " add addr " ip6_dev " " ip_addr_prefix);
        oshd_cmd_tryset(CMD_ADD_IP4, netsh_bin " " ip4_iface " add addr " ip4_dev " " ip_addr_prefix);
        oshd_cmd_tryset(CMD_DEL_IP6, netsh_bin " " ip6_iface " del addr " ip6_dev " " ip_addr);
        oshd_cmd_tryset(CMD_DEL_IP4, netsh_bin " " ip4_iface " del addr " ip4_dev " " ip_addr);
    }

#else
    #warning "Unknown OSHD_CMD_TUNTAP_CFG, oshd_cmd_tryset_builtins() will not work"

    void oshd_cmd_tryset_builtins(void)
    {
    }

#endif

#define oshd_system(command) system(command)

// Execute command associated to *name
// Returns true on success, false on error
static bool oshd_cmd_execute(const char *name)
{
    command_t *cmd = find_command_by_name(name);
    int status;

    if (!cmd) return false;

    // If there is no command to execute, return a success
    if (!cmd->cmdline) {
        logger_debug(DBG_CMD, "%s command not executed because it is unset", cmd->name);
        return true;
    }

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

// Set CMD_ENV_DEVICE
bool oshd_cmd_setenv_devname(const char *devname)
{
    return oshd_cmd_setenv(CMD_ENV_DEVICE, devname);
}

// Set CMD_ENV_ADDRESS, CMD_ENV_MASK and CMD_ENV_PREFIXLEN
bool oshd_cmd_setenv_addr(const netaddr_t *addr, const netaddr_prefixlen_t prefixlen)
{
    char addr_str[NETADDR_ADDRSTRLEN];
    netaddr_t mask;
    char mask_str[NETADDR_ADDRSTRLEN];
    char prefixlen_str[16];

    return netaddr_ntop(addr_str, sizeof(addr_str), addr)
        && netaddr_mask_from_prefix(&mask, addr->type, prefixlen)
        && netaddr_ntop(mask_str, sizeof(mask_str), &mask)
        && snprintf(prefixlen_str, sizeof(prefixlen_str), "%u", (unsigned int) prefixlen) > 0
        && oshd_cmd_setenv(CMD_ENV_ADDRESS, addr_str)
        && oshd_cmd_setenv(CMD_ENV_MASK, mask_str)
        && oshd_cmd_setenv(CMD_ENV_PREFIXLEN, prefixlen_str);
}

bool oshd_cmd_on_dev_up(const char *devname)
{
    return oshd_cmd_setenv_devname(devname) && oshd_cmd_execute(CMD_ON_DEV_UP);
}

bool oshd_cmd_on_dev_down(const char *devname)
{
    return oshd_cmd_setenv_devname(devname) && oshd_cmd_execute(CMD_ON_DEV_DOWN);
}

bool oshd_cmd_enable_dev(const char *devname)
{
    return oshd_cmd_setenv_devname(devname) && oshd_cmd_execute(CMD_ENABLE_DEV);
}

bool oshd_cmd_disable_dev(const char *devname)
{
    return oshd_cmd_setenv_devname(devname) && oshd_cmd_execute(CMD_DISABLE_DEV);
}

bool oshd_cmd_add_ip(const char *devname, const netaddr_t *addr, const netaddr_prefixlen_t prefixlen)
{
    if (!oshd_cmd_setenv_devname(devname) || !oshd_cmd_setenv_addr(addr, prefixlen))
        return false;

    switch (addr->type) {
        case IP4: return oshd_cmd_execute(CMD_ADD_IP4);
        case IP6: return oshd_cmd_execute(CMD_ADD_IP6);
        default: return false;
    }
}

bool oshd_cmd_del_ip(const char *devname, const netaddr_t *addr, const netaddr_prefixlen_t prefixlen)
{
    if (!oshd_cmd_setenv_devname(devname) || !oshd_cmd_setenv_addr(addr, prefixlen))
        return false;

    switch (addr->type) {
        case IP4: return oshd_cmd_execute(CMD_DEL_IP4);
        case IP6: return oshd_cmd_execute(CMD_DEL_IP6);
        default: return false;
    }
}
