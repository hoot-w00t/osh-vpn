#ifndef OSH_MACROS_BITFIELDS_H_
#define OSH_MACROS_BITFIELDS_H_

#include <stdint.h>

#define BIT_SET(x, bit)         ((x) |= (UINT64_C(1) << (bit)))
#define BIT_CLEAR(x, bit)       ((x) &= ~(UINT64_C(1) << (bit)))
#define BIT_TEST(x, bit)        ((x) & (UINT64_C(1) << (bit)))
#define BIT_GET(x, bit)         (((x) >> (bit)) & UINT64_C(1))

#endif
