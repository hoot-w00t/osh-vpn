#ifndef OSH_MEMZERO_H_
#define OSH_MEMZERO_H_

#include <stddef.h>

// Zero memory
// The pointer must not be NULL
// The length must be greater than 0
void memzero(void *ptr, size_t len);

// Call memzero() and free pointer
void memzero_free(void *ptr, size_t len);

// Call memzero() on strlen() bytes of pointer
void memzero_str(char *s);

// Call memzero_str() and free pointer
void memzero_str_free(char *s);

#endif
