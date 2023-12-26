#ifndef OSH_NOISE_CONSTANTS_H_
#define OSH_NOISE_CONSTANTS_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define NOISE_PROTOCOL_NAME_MAXLEN          255
#define NOISE_PSK_LEN                       32

#define NOISE_CIPHER_KEY_MAXLEN             32
#define NOISE_CIPHER_IV_MAXLEN              12
#define NOISE_CIPHER_MAC_MAXLEN             16
#define NOISE_HASH_MAXLEN                   64
#define NOISE_DH_MAXLEN                     32

#define NOISE_MAX_PRE_MESSAGES              2
#define NOISE_MAX_MESSAGES                  4
#define NOISE_MAX_TOKENS_PER_MESSAGE        8

#define NOISE_MAX_NONCE                     (UINT64_MAX - 1)

// Note: This macro only checks if the nonce is in a valid range, it cannot
//       validate nonces manually set with noise_cipherstate_set_nonce()
#define noise_nonce_is_valid(nonce)         ((nonce) < NOISE_MAX_NONCE)

// Structure for parsing protocol name
struct noise_protocol_name {
    char buf[NOISE_PROTOCOL_NAME_MAXLEN + 1];

    char *prefix;
    size_t prefix_len;

    char *pattern;
    size_t pattern_len;

    char *dh_name;
    size_t dh_name_len;

    char *ciph_name;
    size_t ciph_name_len;

    char *hash_name;
    size_t hash_name_len;
};

// Tokens of a handshake
enum noise_pattern_token {
    NOISE_TOK_NONE = 0, // invalid / no token

    NOISE_TOK_E,
    NOISE_TOK_S,
    NOISE_TOK_EE,
    NOISE_TOK_SS,
    NOISE_TOK_ES,
    NOISE_TOK_SE,
    NOISE_TOK_PSK,

    NOISE_TOK_LAST // invalid / last token
};
#define NOISE_TOK_COUNT NOISE_TOK_LAST

// A single handshake (pre-)message
struct noise_message {
    // true for  ->
    // false for <-
    bool from_initiator;

    enum noise_pattern_token tokens[NOISE_MAX_TOKENS_PER_MESSAGE];
    size_t tokens_count;
};

// Definition of a handshake pattern
struct noise_pattern {
    const char *pattern_name;

    // This must be true only if at least one psk token exists in the messages
    bool psk_mode;

    struct noise_message pre_msgs[NOISE_MAX_PRE_MESSAGES];
    size_t pre_msgs_count;

    struct noise_message msgs[NOISE_MAX_MESSAGES];
    size_t msgs_count;
};

#endif
