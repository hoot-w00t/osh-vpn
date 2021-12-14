#ifndef _OSH_OSHD_CONF_H
#define _OSH_OSHD_CONF_H

void oshd_init_conf(void);
bool oshd_load_conf(const char *filename);
void oshd_conf_set_keysdir(const char *dir);

#endif