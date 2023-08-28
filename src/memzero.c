#include "memzero.h"
#include "macros.h"
#include "macros_assert.h"
#include <stdlib.h>

#if PLATFORM_IS_WINDOWS
    #include <windows.h>
#else
    #include <string.h>
#endif

// Hint the compiler that a pointer's memory is being read
// This is to try prevent a dead store optimization on memzero()
#define memory_used_asm(ptr) __asm__ __volatile__ ("" : : "r"(ptr) : "memory")

void memzero(void *ptr, size_t len)
{
    assert(ptr != NULL);
    assert(len > 0);

#if PLATFORM_IS_WINDOWS
    SecureZeroMemory(ptr, len);
#elif defined(HAVE_MEMSET_EXPLICIT)
    memset_explicit(ptr, 0, len);
#elif defined(HAVE_EXPLICIT_BZERO)
    explicit_bzero(ptr, len);
#elif defined(HAVE_MEMSET_S)
    assert(memset_s(ptr, (rsize_t) len, 0, (rsize_t) len) == 0);
#else
    memset(ptr, 0, len);
    memory_used_asm(ptr);
#endif
}

void memzero_free(void *ptr, size_t len)
{
    memzero(ptr, len);
    free(ptr);
}

void memzero_str(char *s)
{
    const size_t len = strlen(s);

    memzero(s, len);
}

void memzero_str_free(char *s)
{
    memzero_str(s);
    free(s);
}
