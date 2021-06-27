#ifndef _OSH_XALLOC_H
#define _OSH_XALLOC_H

#include <stddef.h>

void *xalloc(size_t size) __attribute__((__malloc__));
void *xzalloc(size_t size) __attribute__((__malloc__));
void *xrealloc(void *ptr, size_t size) __attribute__((__malloc__));
char *xstrdup(const char *s) __attribute__((__malloc__));
void *xmemdup(const void *s, size_t size) __attribute__((__malloc__));

#endif