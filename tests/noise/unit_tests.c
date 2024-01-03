#include "noise/protocol_name.h"
#include "noise/handshakestate.h"
#include "noise/patterns_table.h"
#include "noise/crypto_table.h"
#include <stdio.h>
#include <criterion/criterion.h>

Test(noise_handshakestate_create, invalid_protocol_name_1)
{
    const size_t len = 15;
    char s[len + 1];

    for (size_t i = 0; i < len; ++i) {
        memset(s, 0, sizeof(s));
        for (size_t j = 0; j < i; ++j)
            strcat(s, "_");

        cr_assert(noise_handshakestate_create(s, true) == NULL, "was able to create invalid protocol %s", s);
    }

    for (size_t i = 0; i < (len - strlen("Noise")); ++i) {
        memset(s, 0, sizeof(s));
        strcpy(s, "Noise");
        for (size_t j = 0; j < i; ++j)
            strcat(s, "_");

        cr_assert(noise_handshakestate_create(s, true) == NULL, "was able to create invalid protocol %s", s);
    }
}

Test(noise_handshakestate_create, supported_protocol_names)
{
    const size_t len = NOISE_PROTOCOL_NAME_MAXLEN;
    char s[len + 1];
    noise_handshakestate_t *h;

    for (unsigned int pattern_idx = 0; noise_patterns[pattern_idx].pattern_name != NULL; ++pattern_idx) {
        for (unsigned int dh_idx = 0; noise_dh_table[dh_idx].dh_name != NULL; ++dh_idx) {
            for (unsigned int ciph_idx = 0; noise_cipher_table[ciph_idx].ciph_name != NULL; ++ciph_idx) {
                for (unsigned int hash_idx = 0; noise_hash_table[hash_idx].hash_name != NULL; ++hash_idx) {
                    snprintf(s, sizeof(s), "Noise_%s_%s_%s_%s",
                        noise_patterns[pattern_idx].pattern_name,
                        noise_dh_table[dh_idx].dh_name,
                        noise_cipher_table[ciph_idx].ciph_name,
                        noise_hash_table[hash_idx].hash_name);

                    h = noise_handshakestate_create(s, true);
                    cr_assert(h != NULL, "failed to create supported protocol %s", s);
                    noise_handshakestate_destroy(h);
                }
            }
        }
    }
}

static void assert_message_tokens(const struct noise_message *msg, bool *has_psk_token)
{
    cr_assert(msg->tokens_count <= NOISE_MAX_TOKENS_PER_MESSAGE);

    for (unsigned int i = 0; i < NOISE_MAX_TOKENS_PER_MESSAGE; ++i) {
        if (i < msg->tokens_count) {
            cr_assert(msg->tokens[i] != NOISE_TOK_NONE);
            if (msg->tokens[i] == NOISE_TOK_PSK)
                *has_psk_token = true;
        } else {
            cr_assert(msg->tokens[i] == NOISE_TOK_NONE);
        }
    }
}

static void assert_message_from_initiator(const struct noise_message *msgs, unsigned int count, unsigned int i)
{
    if (i < count) {
        if (i > 0)
            cr_assert(msgs[i - 1].from_initiator != msgs[i].from_initiator);
    } else {
        cr_assert(msgs[i].from_initiator == false);
    }
}

Test(noise_patterns_table, validate_patterns_table)
{
    foreach_noise_pattern(pattern) {
        cr_assert(pattern != NULL);
        cr_assert(pattern->pattern_name != NULL);
        cr_assert(strlen(pattern->pattern_name) > 0);
        cr_assert(pattern->pre_msgs_count <= NOISE_MAX_PRE_MESSAGES);
        cr_assert(pattern->msgs_count <= NOISE_MAX_MESSAGES);

        bool has_psk_token = false;

        for (unsigned int i = 0; i < NOISE_MAX_PRE_MESSAGES; ++i) {
            const struct noise_message *msg = &pattern->pre_msgs[i];

            if (i >= pattern->pre_msgs_count)
                cr_assert(msg->tokens_count == 0);
            assert_message_from_initiator(pattern->pre_msgs, pattern->pre_msgs_count, i);
            assert_message_tokens(msg, &has_psk_token);
        }

        for (unsigned int i = 0; i < NOISE_MAX_MESSAGES; ++i) {
            const struct noise_message *msg = &pattern->msgs[i];

            if (i >= pattern->msgs_count)
                cr_assert(msg->tokens_count == 0);
            assert_message_from_initiator(pattern->msgs, pattern->msgs_count, i);
            assert_message_tokens(msg, &has_psk_token);
        }

        cr_assert(pattern->psk_mode == has_psk_token);
    }
}
