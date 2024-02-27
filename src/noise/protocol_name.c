#include "noise/protocol_name.h"
#include <ctype.h>
#include <string.h>

typedef bool (*next_token_check)(char c);

static bool next_token_is_underscore(char c)
{
    return c == '_';
}

/* Unused yet, for parsing pattern modifiers

static bool next_token_is_pattern_name(char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
}

static bool next_token_is_not_pattern_name(char c)
{
    return !next_token_is_pattern_name(c);
}

static bool next_token_is_additional_modifier(char c)
{
    return c == '+';
}
*/

static char *next_token(char *s, size_t *len, next_token_check tokchk)
{
    for (*len = 0; s != NULL && s[*len] != '\0' && !tokchk(s[*len]); *len += 1);

    if (*len == 0) {
        return NULL;
    } else {
        // remove and skip underscore for the next token
        s[*len] = '\0';
        return s + *len + 1;
    }
}

#define next_underscore(s, len) next_token(s, len, next_token_is_underscore)
/* Unused yet, for parsing pattern modifiers

#define first_modifier(s, len) next_token(s, len, next_token_is_not_pattern_name)
#define next_modifier(s, len) next_token(s, len, next_token_is_additional_modifier)
*/

bool noise_parse_protocol_name(struct noise_protocol_name *parsed,
    const char *protocol_name)
{
    memset(parsed, 0, sizeof(*parsed));
    strncpy(parsed->buf, protocol_name, sizeof(parsed->buf) - 1);

    // Note: Pattern modifiers are not separated from the base pattern, all
    //       supported modifiers and their combinations are defined as distinct
    //       patterns (see patterns table)

    parsed->prefix = parsed->buf;
    parsed->pattern   = next_underscore(parsed->prefix,    &parsed->prefix_len);
    parsed->dh_name   = next_underscore(parsed->pattern,   &parsed->pattern_len);
    parsed->ciph_name = next_underscore(parsed->dh_name,   &parsed->dh_name_len);
    parsed->hash_name = next_underscore(parsed->ciph_name, &parsed->ciph_name_len);
    parsed->hash_name_len = parsed->hash_name ? strlen(parsed->hash_name) : 0;

    if (   strcmp(parsed->prefix, "Noise") != 0
        || parsed->pattern == NULL
        || parsed->dh_name == NULL
        || parsed->ciph_name == NULL
        || parsed->hash_name == NULL)
    {
        return false;
    }

    return true;
}
