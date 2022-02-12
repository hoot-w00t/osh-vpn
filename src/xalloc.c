#include "xalloc.h"
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>

// Allocate size bytes of memory
// abort() if allocation fails
_xalloc_attr
void *_xalloc(_xalloc_args_proto, size_t size)
{
    void *ptr = malloc(size);

    if (!ptr) {
        fprintf(stderr, _xalloc_fmt "xalloc(%zu) failed\n",
            _xalloc_fmt_args, size);
        abort();
    }
    return ptr;
}

// Allocate size bytes of memory initialized with value 0
// abort() if allocation fails
_xalloc_attr
void *_xzalloc(_xalloc_args_proto, size_t size)
{
    void *ptr = calloc(size, 1);

    if (!ptr) {
        fprintf(stderr, _xalloc_fmt "xzalloc(%zu) failed\n",
            _xalloc_fmt_args, size);
        abort();
    }
    return ptr;
}

// Re-size *ptr to size bytes
// If size is 0, frees *ptr and returns NULL
// abort() if allocation fails
_xrealloc_attr
void *_xrealloc(_xalloc_args_proto, void *ptr, size_t size)
{
    void *newptr;

    if (size == 0) {
        free(ptr);
        return NULL;
    }
    if (!(newptr = realloc(ptr, size))) {
        fprintf(stderr, _xalloc_fmt "xrealloc(%p, %zu) failed\n",
            _xalloc_fmt_args, ptr, size);
        abort();
    }
    return newptr;
}

// Re-size ptr to (nmemb * size) bytes
// If size is 0, frees ptr and returns NULL
// abort() if the allocation fails or if the multiplication overflows
_xrealloc_attr
void *_xreallocarray(_xalloc_args_proto, void *ptr, size_t nmemb, size_t size)
{
    const size_t newsize = nmemb * size;
    void *newptr;

    if (nmemb && (newsize / nmemb) != size) {
        fprintf(stderr, _xalloc_fmt "xreallocarray(%p, %zu, %zu) overflow\n",
            _xalloc_fmt_args, ptr, nmemb, size);
        abort();
    }
    if (newsize == 0) {
        free(ptr);
        return NULL;
    }
    if (!(newptr = realloc(ptr, newsize))) {
        fprintf(stderr, _xalloc_fmt "xreallocarray(%p, %zu, %zu) failed\n",
            _xalloc_fmt_args, ptr, nmemb, size);
        abort();
    }
    return newptr;
}

// Duplicate *s
// abort() is allocation fails
_xalloc_attr
char *_xstrdup(_xalloc_args_proto, const char *s)
{
    char *dup = strdup(s);

    if (!dup) {
        fprintf(stderr, _xalloc_fmt "xstrdup(\"%s\") failed\n",
            _xalloc_fmt_args, s);
        abort();
    }
    return dup;
}

// Duplicate size bytes starting at s
// Returns NULL if size is 0
_xmemdup_attr
void *_xmemdup(_xalloc_args_proto, const void *s, size_t size)
{
    void *newptr;

    if (size == 0)
        return NULL;
    if (!(newptr = malloc(size))) {
        fprintf(stderr, _xalloc_fmt "xmemdup(%p, %zu) failed\n",
            _xalloc_fmt_args, s, size);
        abort();
    }
    memcpy(newptr, s, size);
    return newptr;
}