#include <stddef.h>

#ifndef _OSH_XALLOC_H
#define _OSH_XALLOC_H

void *xalloc(size_t size);
void *xzalloc(size_t size);
void *xrealloc(void *ptr, size_t size);
char *xstrdup(const char *s);

#endif
