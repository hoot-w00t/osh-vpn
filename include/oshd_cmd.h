#ifndef _OSH_OSHD_CMD_H
#define _OSH_OSHD_CMD_H

#include <stdbool.h>

bool oshd_cmd_set(const char *name, const char *cmdline);
void oshd_cmd_unset(const char *name);
void oshd_cmd_unset_all(void);
int oshd_cmd_execute(const char *name);

#endif