#define OSH_NOISE_PATTERNS_TABLE_C_
#include "noise/patterns_table.h"
#include <string.h>

#if NOISE_SUPPORT_UNTESTED_PATTERNS
    #warning "Untested Noise handshake patterns are enabled, this should only be done for testing"
#endif

// TODO: Don't compile patterns unused by Osh (unless NOISE_SUPPORT_UNUSED_PATTERNS is true)

static const struct noise_pattern noise_patterns_array[] = {
    {
        .pattern_name = "IK",

        .pre_msgs = {
            {
                .from_initiator = false,
                .tokens = { NOISE_TOK_S },
                .tokens_count = 1
            }
        },
        .pre_msgs_count = 1,

        .msgs = {
            {
                .from_initiator = true,
                .tokens = { NOISE_TOK_E, NOISE_TOK_ES, NOISE_TOK_S, NOISE_TOK_SS },
                .tokens_count = 4
            },
            {
                .from_initiator = false,
                .tokens = { NOISE_TOK_E, NOISE_TOK_EE, NOISE_TOK_SE },
                .tokens_count = 3
            }
        },
        .msgs_count = 2
    },

    {
        .pattern_name = "IKpsk2",
        .psk_mode = true,

        .pre_msgs = {
            {
                .from_initiator = false,
                .tokens = { NOISE_TOK_S },
                .tokens_count = 1
            }
        },
        .pre_msgs_count = 1,

        .msgs = {
            {
                .from_initiator = true,
                .tokens = { NOISE_TOK_E, NOISE_TOK_ES, NOISE_TOK_S, NOISE_TOK_SS },
                .tokens_count = 4
            },
            {
                .from_initiator = false,
                .tokens = { NOISE_TOK_E, NOISE_TOK_EE, NOISE_TOK_SE, NOISE_TOK_PSK },
                .tokens_count = 4
            }
        },
        .msgs_count = 2
    },

    {
        .pattern_name = "IKpsk0+psk2",
        .psk_mode = true,

        .pre_msgs = {
            {
                .from_initiator = false,
                .tokens = { NOISE_TOK_S },
                .tokens_count = 1
            }
        },
        .pre_msgs_count = 1,

        .msgs = {
            {
                .from_initiator = true,
                .tokens = { NOISE_TOK_PSK, NOISE_TOK_E, NOISE_TOK_ES, NOISE_TOK_S, NOISE_TOK_SS },
                .tokens_count = 5
            },
            {
                .from_initiator = false,
                .tokens = { NOISE_TOK_E, NOISE_TOK_EE, NOISE_TOK_SE, NOISE_TOK_PSK },
                .tokens_count = 4
            }
        },
        .msgs_count = 2
    },

    {
        .pattern_name = "XK",

        .pre_msgs = {
            {
                .from_initiator = false,
                .tokens = { NOISE_TOK_S },
                .tokens_count = 1
            }
        },
        .pre_msgs_count = 1,

        .msgs = {
            {
                .from_initiator = true,
                .tokens = { NOISE_TOK_E, NOISE_TOK_ES },
                .tokens_count = 2
            },
            {
                .from_initiator = false,
                .tokens = { NOISE_TOK_E, NOISE_TOK_EE },
                .tokens_count = 2
            },
            {
                .from_initiator = true,
                .tokens = { NOISE_TOK_S, NOISE_TOK_SE },
                .tokens_count = 2
            }
        },
        .msgs_count = 3
    },

    {
        .pattern_name = "XKpsk3",
        .psk_mode = true,

        .pre_msgs = {
            {
                .from_initiator = false,
                .tokens = { NOISE_TOK_S },
                .tokens_count = 1
            }
        },
        .pre_msgs_count = 1,

        .msgs = {
            {
                .from_initiator = true,
                .tokens = { NOISE_TOK_E, NOISE_TOK_ES },
                .tokens_count = 2
            },
            {
                .from_initiator = false,
                .tokens = { NOISE_TOK_E, NOISE_TOK_EE },
                .tokens_count = 2
            },
            {
                .from_initiator = true,
                .tokens = { NOISE_TOK_S, NOISE_TOK_SE, NOISE_TOK_PSK },
                .tokens_count = 3
            }
        },
        .msgs_count = 3
    },

    {
        .pattern_name = "XKpsk0+psk3",
        .psk_mode = true,

        .pre_msgs = {
            {
                .from_initiator = false,
                .tokens = { NOISE_TOK_S },
                .tokens_count = 1
            }
        },
        .pre_msgs_count = 1,

        .msgs = {
            {
                .from_initiator = true,
                .tokens = { NOISE_TOK_PSK, NOISE_TOK_E, NOISE_TOK_ES },
                .tokens_count = 3
            },
            {
                .from_initiator = false,
                .tokens = { NOISE_TOK_E, NOISE_TOK_EE },
                .tokens_count = 2
            },
            {
                .from_initiator = true,
                .tokens = { NOISE_TOK_S, NOISE_TOK_SE, NOISE_TOK_PSK },
                .tokens_count = 3
            }
        },
        .msgs_count = 3
    },

    {
        .pattern_name = "IX",

        .pre_msgs = {0},
        .pre_msgs_count = 0,

        .msgs = {
            {
                .from_initiator = true,
                .tokens = { NOISE_TOK_E, NOISE_TOK_S },
                .tokens_count = 2,
            },
            {
                .from_initiator = false,
                .tokens = { NOISE_TOK_E, NOISE_TOK_EE, NOISE_TOK_SE, NOISE_TOK_S, NOISE_TOK_ES },
                .tokens_count = 5,
            }
        },
        .msgs_count = 2
    },

    {
        .pattern_name = "IXpsk2",
        .psk_mode = true,

        .pre_msgs = {0},
        .pre_msgs_count = 0,

        .msgs = {
            {
                .from_initiator = true,
                .tokens = { NOISE_TOK_E, NOISE_TOK_S },
                .tokens_count = 2,
            },
            {
                .from_initiator = false,
                .tokens = { NOISE_TOK_E, NOISE_TOK_EE, NOISE_TOK_SE, NOISE_TOK_S, NOISE_TOK_ES, NOISE_TOK_PSK },
                .tokens_count = 6,
            }
        },
        .msgs_count = 2
    },

#if NOISE_SUPPORT_UNTESTED_PATTERNS
    {
        // FIXME: This pattern is not tested, it may not follow validity rules and its implementation may not be correct
        .pattern_name = "IXpsk1+psk2",
        .psk_mode = true,

        .pre_msgs = {0},
        .pre_msgs_count = 0,

        .msgs = {
            {
                .from_initiator = true,
                .tokens = { NOISE_TOK_E, NOISE_TOK_S, NOISE_TOK_PSK },
                .tokens_count = 3,
            },
            {
                .from_initiator = false,
                .tokens = { NOISE_TOK_E, NOISE_TOK_EE, NOISE_TOK_SE, NOISE_TOK_S, NOISE_TOK_ES, NOISE_TOK_PSK },
                .tokens_count = 6,
            }
        },
        .msgs_count = 2
    },
#endif

    {
        .pattern_name = "XX",

        .pre_msgs = {0},
        .pre_msgs_count = 0,

        .msgs = {
            {
                .from_initiator = true,
                .tokens = { NOISE_TOK_E },
                .tokens_count = 1
            },
            {
                .from_initiator = false,
                .tokens = { NOISE_TOK_E, NOISE_TOK_EE, NOISE_TOK_S, NOISE_TOK_ES },
                .tokens_count = 4
            },
            {
                .from_initiator = true,
                .tokens = { NOISE_TOK_S, NOISE_TOK_SE },
                .tokens_count = 2
            }
        },
        .msgs_count = 3
    },

    {
        .pattern_name = "XXpsk3",
        .psk_mode = true,

        .pre_msgs = {0},
        .pre_msgs_count = 0,

        .msgs = {
            {
                .from_initiator = true,
                .tokens = { NOISE_TOK_E },
                .tokens_count = 1
            },
            {
                .from_initiator = false,
                .tokens = { NOISE_TOK_E, NOISE_TOK_EE, NOISE_TOK_S, NOISE_TOK_ES },
                .tokens_count = 4
            },
            {
                .from_initiator = true,
                .tokens = { NOISE_TOK_S, NOISE_TOK_SE, NOISE_TOK_PSK },
                .tokens_count = 3
            }
        },
        .msgs_count = 3
    },

#if NOISE_SUPPORT_UNTESTED_PATTERNS
    {
        // FIXME: This pattern is not tested, it may not follow validity rules and its implementation may not be correct
        .pattern_name = "XXpsk2+psk3",
        .psk_mode = true,

        .pre_msgs = {0},
        .pre_msgs_count = 0,

        .msgs = {
            {
                .from_initiator = true,
                .tokens = { NOISE_TOK_E },
                .tokens_count = 1
            },
            {
                .from_initiator = false,
                .tokens = { NOISE_TOK_E, NOISE_TOK_EE, NOISE_TOK_S, NOISE_TOK_ES, NOISE_TOK_PSK },
                .tokens_count = 5
            },
            {
                .from_initiator = true,
                .tokens = { NOISE_TOK_S, NOISE_TOK_SE, NOISE_TOK_PSK },
                .tokens_count = 3
            }
        },
        .msgs_count = 3
    },
#endif

    {
        .pattern_name = "KK",

        .pre_msgs = {
            {
                .from_initiator = true,
                .tokens = { NOISE_TOK_S },
                .tokens_count = 1
            },
            {
                .from_initiator = false,
                .tokens = { NOISE_TOK_S },
                .tokens_count = 1
            }
        },
        .pre_msgs_count = 2,

        .msgs = {
            {
                .from_initiator = true,
                .tokens = { NOISE_TOK_E, NOISE_TOK_ES, NOISE_TOK_SS },
                .tokens_count = 3
            },
            {
                .from_initiator = false,
                .tokens = { NOISE_TOK_E, NOISE_TOK_EE, NOISE_TOK_SE },
                .tokens_count = 3
            }
        },
        .msgs_count = 2
    },

    {
        .pattern_name = "KKpsk0",
        .psk_mode = true,

        .pre_msgs = {
            {
                .from_initiator = true,
                .tokens = { NOISE_TOK_S },
                .tokens_count = 1
            },
            {
                .from_initiator = false,
                .tokens = { NOISE_TOK_S },
                .tokens_count = 1
            }
        },
        .pre_msgs_count = 2,

        .msgs = {
            {
                .from_initiator = true,
                .tokens = { NOISE_TOK_PSK, NOISE_TOK_E, NOISE_TOK_ES, NOISE_TOK_SS },
                .tokens_count = 4
            },
            {
                .from_initiator = false,
                .tokens = { NOISE_TOK_E, NOISE_TOK_EE, NOISE_TOK_SE },
                .tokens_count = 3
            }
        },
        .msgs_count = 2
    },

    {
        .pattern_name = "KKpsk2",
        .psk_mode = true,

        .pre_msgs = {
            {
                .from_initiator = true,
                .tokens = { NOISE_TOK_S },
                .tokens_count = 1
            },
            {
                .from_initiator = false,
                .tokens = { NOISE_TOK_S },
                .tokens_count = 1
            }
        },
        .pre_msgs_count = 2,

        .msgs = {
            {
                .from_initiator = true,
                .tokens = { NOISE_TOK_E, NOISE_TOK_ES, NOISE_TOK_SS },
                .tokens_count = 3
            },
            {
                .from_initiator = false,
                .tokens = { NOISE_TOK_E, NOISE_TOK_EE, NOISE_TOK_SE, NOISE_TOK_PSK },
                .tokens_count = 4
            }
        },
        .msgs_count = 2
    },

    {
        .pattern_name = "KKpsk0+psk2",
        .psk_mode = true,

        .pre_msgs = {
            {
                .from_initiator = true,
                .tokens = { NOISE_TOK_S },
                .tokens_count = 1
            },
            {
                .from_initiator = false,
                .tokens = { NOISE_TOK_S },
                .tokens_count = 1
            }
        },
        .pre_msgs_count = 2,

        .msgs = {
            {
                .from_initiator = true,
                .tokens = { NOISE_TOK_PSK, NOISE_TOK_E, NOISE_TOK_ES, NOISE_TOK_SS },
                .tokens_count = 4
            },
            {
                .from_initiator = false,
                .tokens = { NOISE_TOK_E, NOISE_TOK_EE, NOISE_TOK_SE, NOISE_TOK_PSK },
                .tokens_count = 4
            }
        },
        .msgs_count = 2
    },

    { // array terminator, invalid
        .pattern_name = NULL,
        .pre_msgs = {0},
        .pre_msgs_count = 0,
        .msgs = {0},
        .msgs_count = 0
    }
};

const struct noise_pattern *noise_patterns = noise_patterns_array;

size_t noise_get_pattern_count(void)
{
    size_t i = 0;

    while (!noise_pattern_is_last(&noise_patterns[i]))
        i += 1;
    return i;
}

const struct noise_pattern *noise_get_pattern(const char *pattern_name)
{
    foreach_noise_pattern(pattern) {
        if (!strcmp(pattern_name, pattern->pattern_name))
            return pattern;
    }
    return NULL;
}
