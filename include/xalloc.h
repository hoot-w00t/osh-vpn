#ifndef _OSH_XALLOC_H
#define _OSH_XALLOC_H

#include <stddef.h>

#define _xalloc_attr __attribute__((__malloc__))

_xalloc_attr
void *xalloc(size_t size);

_xalloc_attr
void *xzalloc(size_t size);

_xalloc_attr
void *xrealloc(void *ptr, size_t size);

_xalloc_attr
char *xstrdup(const char *s);

_xalloc_attr
void *xmemdup(const void *s, size_t size);

#endif