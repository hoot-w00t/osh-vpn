#ifndef _OSH_MACROS_ASSERT_H
#define _OSH_MACROS_ASSERT_H

#include <assert.h>

// STATIC_ASSERT
#if defined(__STDC_VERSION__)
    #if (__STDC_VERSION__ >= 201112L) // C11
        #define STATIC_ASSERT _Static_assert
    #else
        #error "__STDC_VERSION__ doesn't support static assertion"
    #endif
#else
    #error "__STDC_VERSION__ is undefined"
#endif

#define STATIC_ASSERT_NOMSG(expr) STATIC_ASSERT(expr, #expr)

#endif
