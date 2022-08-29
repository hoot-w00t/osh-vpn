#ifndef _OSH_MACROS_BITFIELDS_H
#define _OSH_MACROS_BITFIELDS_H

// Set a single bit
#define BIT_SET(x, bit)     (x |= (1u << (bit)))

// Clear a single bit
#define BIT_CLEAR(x, bit)   (x &= ~(1u << (bit)))

// Test a single bit
#define BIT_TEST(x, bit)    ((x) & (1u << (bit)))

// Get a single bit
#define BIT_GET(x, bit)     (((x) >> (bit)) & 1u)

#endif
