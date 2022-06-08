/*  Written in 2018 by David Blackman and Sebastiano Vigna (vigna@acm.org)

To the extent possible under law, the author has dedicated all copyright
and related and neighboring rights to this software to the public domain
worldwide. This software is distributed without any warranty.

See <http://creativecommons.org/publicdomain/zero/1.0/>. */

/* This Xoshiro256** source code originates from:
    https://prng.di.unimi.it/xoshiro256starstar.c */

#include "random.h"
#include "logger.h"
#include <stdint.h>
#include <stdlib.h>

/* This is xoshiro256** 1.0, one of our all-purpose, rock-solid
   generators. It has excellent (sub-ns) speed, a state (256 bits) that is
   large enough for any parallel application, and it passes all tests we
   are aware of.

   For generating just floating-point numbers, xoshiro256+ is even faster.

   The state must be seeded so that it is not everywhere zero. If you have
   a 64-bit seed, we suggest to seed a splitmix64 generator and use its
   output to fill s. */

static inline uint64_t rotl(const uint64_t x, int k)
{
	return (x << k) | (x >> (64 - k));
}

static uint64_t s[4];

// Randomly seed Xoshiro256** state
bool random_xoshiro256_seed(void)
{
    const int max_attempts = 32;

    for (int i = 0; i < max_attempts; ++i) {
        if (!random_bytes(s, sizeof(s))) {
            logger(LOG_ERR, "Failed to seed Xoshiro256**: random_bytes failed");
            return false;
        }

        // The state must be all zeros, if any of the values is not zero the
        // seeding is done
        if (s[0] != 0 || s[1] != 0 || s[2] != 0 || s[3] != 0)
            return true;
    }

    // If we get here none of the random_bytes attempts were successful
    logger(LOG_ERR,"Failed to seed Xoshiro256** after %i attempts",
        max_attempts);

    return false;
}

// Generate a pseudo-random 64-bit number using Xoshiro256**
uint64_t random_xoshiro256(void)
{
	const uint64_t result = rotl(s[1] * 5, 7) * 9;

	const uint64_t t = s[1] << 17;

	s[2] ^= s[0];
	s[3] ^= s[1];
	s[1] ^= s[2];
	s[0] ^= s[3];

	s[2] ^= t;

	s[3] = rotl(s[3], 45);

	return result;
}
