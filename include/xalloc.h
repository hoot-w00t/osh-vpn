#ifndef _OSH_XALLOC_H
#define _OSH_XALLOC_H

#include <stddef.h>

#define _xalloc_attr __attribute__((__malloc__, returns_nonnull, warn_unused_result))
#define _xrealloc_attr __attribute__((__malloc__, warn_unused_result))

// These are common definitions used in each xalloc function
// This is to help identify which allocation fails if it does, currently it
// passes the file, line and parent function where the xalloc function is called
#define _xalloc_args __FILE__, __LINE__, __func__
#define _xalloc_args_proto const char *_file, size_t _line, const char *_func
#define _xalloc_fmt "%s:%zu: %s: "
#define _xalloc_fmt_args _file, _line, _func

_xalloc_attr
void *_xalloc(_xalloc_args_proto, size_t size);
#define xalloc(size) _xalloc(_xalloc_args, size)

_xalloc_attr
void *_xzalloc(_xalloc_args_proto, size_t size);
#define xzalloc(size) _xzalloc(_xalloc_args, size)

_xrealloc_attr
void *_xrealloc(_xalloc_args_proto, void *ptr, size_t size);
#define xrealloc(ptr, size) _xrealloc(_xalloc_args, ptr, size)

_xrealloc_attr
void *_xreallocarray(_xalloc_args_proto, void *ptr, size_t nmemb, size_t size);
#define xreallocarray(ptr, nmemb, size) _xreallocarray(_xalloc_args, ptr, nmemb, size)

_xalloc_attr
char *_xstrdup(_xalloc_args_proto, const char *s);
#define xstrdup(s) _xstrdup(_xalloc_args, s)

_xalloc_attr
void *_xmemdup(_xalloc_args_proto, const void *s, size_t size);
#define xmemdup(s, size) _xmemdup(_xalloc_args, s, size)

#endif