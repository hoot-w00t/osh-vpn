#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>

// Allocate size bytes of memory
// abort() if allocation fails
void *xalloc(size_t size)
{
    void *ptr = malloc(size);

    if (!ptr) {
        fprintf(stderr, "xalloc failed (%zu bytes)\n", size);
        abort();
    }
    return ptr;
}

// Allocate size bytes of memory initialized with value 0
// abort() if allocation fails
void *xzalloc(size_t size)
{
    void *ptr = calloc(size, 1);

    if (!ptr) {
        fprintf(stderr, "xzalloc failed (%zu bytes)\n", size);
        abort();
    }
    return ptr;
}

// Re-size *ptr to size bytes
// If size is 0, frees *ptr and returns NULL
// abort() if allocation fails
void *xrealloc(void *ptr, size_t size)
{
    void *newptr;

    if (size == 0) {
        free(ptr);
        return NULL;
    }
    if (!(newptr = realloc(ptr, size))) {
        fprintf(stderr, "xrealloc failed (%p, %zu bytes)\n", ptr, size);
        abort();
    }
    return newptr;
}

// Duplicate *s
// abort() is allocation fails
char *xstrdup(const char *s)
{
    char *dup = strdup(s);

    if (!dup) {
        fprintf(stderr, "xstrdup failed (%p, %zu chars)\n", s, strlen(s));
        abort();
    }
    return dup;
}