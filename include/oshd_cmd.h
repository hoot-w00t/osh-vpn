#ifndef _OSH_OSHD_CMD_H
#define _OSH_OSHD_CMD_H

#include "macros.h"
#include "netaddr.h"
#include <stdbool.h>

#define OSHD_CMD_TUNTAP_CFG_UNKNOWN                 0
#define OSHD_CMD_TUNTAP_CFG_LINUX_IPROUTE2          1
#define OSHD_CMD_TUNTAP_CFG_LINUX_NET_TOOLS         2
#define OSHD_CMD_TUNTAP_CFG_WIN_NETSH               3

#ifndef OSHD_CMD_TUNTAP_CFG
    #if PLATFORM_IS_LINUX
        #define OSHD_CMD_TUNTAP_CFG OSHD_CMD_TUNTAP_CFG_LINUX_IPROUTE2
    #elif PLATFORM_IS_WINDOWS
        #define OSHD_CMD_TUNTAP_CFG OSHD_CMD_TUNTAP_CFG_WIN_NETSH
    #else
        #define OSHD_CMD_TUNTAP_CFG OSHD_CMD_TUNTAP_CFG_UNKNOWN
    #endif
#endif

#define CMD_ON_DEV_UP   "OnDevUp"
#define CMD_ON_DEV_DOWN "OnDevDown"
#define CMD_ENABLE_DEV  "EnableDev"
#define CMD_DISABLE_DEV "DisableDev"
#define CMD_ADD_IP6     "AddIP6"
#define CMD_ADD_IP4     "AddIP4"
#define CMD_DEL_IP6     "DelIP6"
#define CMD_DEL_IP4     "DelIP4"

#define CMD_ENV_DEVICE              "OSHD_DEVICE"
#define CMD_ENV_ADDRESS             "OSHD_ADDRESS"
#define CMD_ENV_MASK                "OSHD_MASK"
#define CMD_ENV_PREFIXLEN           "OSHD_PREFIXLEN"
#define CMD_ENV_DYNAMIC_PREFIX4     "OSHD_DYNAMIC_PREFIX4"
#define CMD_ENV_DYNAMIC_PREFIX6     "OSHD_DYNAMIC_PREFIX6"

void oshd_cmd_set(const char *name, const char *cmdline);
void oshd_cmd_tryset(const char *name, const char *cmdline);
void oshd_cmd_unset(const char *name);
void oshd_cmd_unset_all(void);

bool oshd_cmd_setenv(const char *variable, const char *value);
bool oshd_cmd_unsetenv(const char *variable);

bool oshd_cmd_setenv_devname(const char *devname);
bool oshd_cmd_setenv_addr(const netaddr_t *addr, const netaddr_prefixlen_t prefixlen);

// Try to set default commands
void oshd_cmd_tryset_builtins(void);

bool oshd_cmd_on_dev_up(const char *devname);
bool oshd_cmd_on_dev_down(const char *devname);
bool oshd_cmd_enable_dev(const char *devname);
bool oshd_cmd_disable_dev(const char *devname);
bool oshd_cmd_add_ip(const char *devname, const netaddr_t *addr, const netaddr_prefixlen_t prefixlen);
bool oshd_cmd_del_ip(const char *devname, const netaddr_t *addr, const netaddr_prefixlen_t prefixlen);

#endif
