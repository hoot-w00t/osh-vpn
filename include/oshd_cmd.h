#ifndef _OSH_OSHD_CMD_H
#define _OSH_OSHD_CMD_H

#include <stdbool.h>

void oshd_cmd_set(const char *name, const char *cmdline);
void oshd_cmd_unset(const char *name);
void oshd_cmd_unset_all(void);

bool oshd_cmd_setenv(const char *variable, const char *value);
bool oshd_cmd_unsetenv(const char *variable);

bool oshd_cmd_execute(const char *name);

#endif