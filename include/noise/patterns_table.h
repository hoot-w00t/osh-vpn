#ifndef OSH_NOISE_PATTERNS_TABLE_H_
#define OSH_NOISE_PATTERNS_TABLE_H_

#include "constants.h"

// Some patterns are supported but do not have test vectors
// Their support can be enabled by defining NOISE_SUPPORT_UNTESTED_PATTERNS to 1

// Some patterns are supported and were implemented for testing but are not
// actually used by Osh
// Their support can be enabled by defining NOISE_SUPPORT_UNUSED_PATTERNS to 1

#ifndef OSH_NOISE_PATTERNS_TABLE_C_
    extern const struct noise_pattern *noise_patterns;
#endif

static inline bool noise_pattern_is_last(const struct noise_pattern *pattern)
{
    return pattern->pattern_name == NULL;
}

size_t noise_get_pattern_count(void);
const struct noise_pattern *noise_get_pattern(const char *pattern_name);

#define foreach_noise_pattern(pattern) \
    for (const struct noise_pattern *pattern = noise_patterns; !noise_pattern_is_last(pattern); ++pattern)

#endif
