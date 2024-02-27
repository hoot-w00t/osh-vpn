#ifdef NDEBUG
    #warning "Undefining NDEBUG"
    #undef NDEBUG
#endif

#include "noise/handshakestate.h"
#include "noise/crypto_table.h"
#include "noise/patterns_table.h"
#include "crypto/keypair.h"
#include "logger.h"
#include "xalloc.h"
#include "macros_assert.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

static const char *hexcharset = "0123456789abcdef";
static const size_t hexcharset_len = 16;

static size_t char_index(const char c, const char *s)
{
    for (size_t i = 0; s[i] != '\0'; ++i) {
        if (s[i] == c)
            return i;
    }
    return SIZE_MAX;
}

static uint8_t _hex_to_byte(const char *s)
{
    const uint8_t hi = (uint8_t) char_index(s[0], hexcharset);
    const uint8_t lo = (uint8_t) char_index(s[1], hexcharset);

    assert(hi < hexcharset_len);
    assert(lo < hexcharset_len);
    return ((hi & 0xF) << 4) | (lo & 0xF);
}

static void _byte_to_hex(char *s, const uint8_t b)
{
    const uint8_t hi = (b >> 4) & 0xF;
    const uint8_t lo = b & 0xF;

    s[0] = hexcharset[hi];
    s[1] = hexcharset[lo];
}

static void hex_to_bytes(uint8_t **b, size_t *b_len, const char *h)
{
    const size_t h_len = strlen(h);

    assert((h_len % 2) == 0);
    *b_len = h_len / 2;
    *b = xalloc(*b_len);

    for (size_t i = 0; i < *b_len; ++i)
        (*b)[i] = _hex_to_byte(&h[i * 2]);
}

static void bytes_to_hex(char **h, const uint8_t *b, size_t b_len)
{
    const size_t h_len = (b_len * 2) + 1;

    *h = xzalloc(h_len);
    for (size_t i = 0; i < b_len; ++i)
        _byte_to_hex(&(*h)[i * 2], b[i]);
}

struct test_psk {
    uint8_t *psk;
    size_t psk_len;
};

static char *protocol_name = NULL;
static uint8_t *init_prologue = NULL;
static size_t init_prologue_len = 0;
static keypair_t *init_static = NULL;
static keypair_t *init_ephemeral = NULL;
static keypair_t *init_remote_static = NULL;
static struct test_psk *init_psks = NULL;
static size_t init_psks_count = 0;
static uint8_t *resp_prologue = NULL;
static size_t resp_prologue_len = 0;
static keypair_t *resp_static = NULL;
static keypair_t *resp_ephemeral = NULL;
static keypair_t *resp_remote_static = NULL;
static struct test_psk *resp_psks = NULL;
static size_t resp_psks_count = 0;

static FILE *output_file = NULL;
#define dump_output ((output_file == NULL) ? stdout : output_file)

struct test_message {
    uint8_t *payload;
    size_t payload_len;
};
static struct test_message *messages = NULL;
static size_t messages_count = 0;

static bool create_keypair(keypair_t **keypair, keypair_type_t type, bool public,
    const void *key, const size_t key_len)
{
    keypair_destroy(*keypair);
    *keypair = keypair_create(type);

    if (public)
        return keypair_set_public_key(*keypair, key, key_len);
    else
        return keypair_set_private_key(*keypair, key, key_len);
}

static void set_keypair(keypair_t **keypair, bool public)
{
    uint8_t *key;
    size_t key_len;

    hex_to_bytes(&key, &key_len, optarg);

    if (key_len == KEYPAIR_X25519_KEYLEN)
        create_keypair(keypair, KEYPAIR_X25519, public, key, key_len);
    else if (key_len == KEYPAIR_X448_KEYLEN)
        create_keypair(keypair, KEYPAIR_X448, public, key, key_len);
    else
        fprintf(stderr, "Unknown key of %zu bytes\n", key_len);

    free(key);
}

static void set_bytes(uint8_t **b, size_t *b_len)
{
    free(*b);
    hex_to_bytes(b, b_len, optarg);
}

static void parse_opt(int opt)
{
    switch (opt) {
        case 1:
            free(protocol_name);
            protocol_name = xstrdup(optarg);
            break;

        case 2: set_bytes(&init_prologue, &init_prologue_len); break;
        case 3: set_keypair(&init_static, false); break;
        case 4: set_keypair(&init_ephemeral, false); break;
        case 5: set_keypair(&init_remote_static, true); break;

        case 6: set_bytes(&resp_prologue, &resp_prologue_len); break;
        case 7: set_keypair(&resp_static, false); break;
        case 8: set_keypair(&resp_ephemeral, false); break;
        case 9: set_keypair(&resp_remote_static, true); break;

        case 10:
            messages_count += 1;
            messages = xrealloc(messages, sizeof(*messages) * messages_count);

            memset(&messages[messages_count - 1], 0, sizeof(struct test_message));
            set_bytes(&messages[messages_count - 1].payload,
                &messages[messages_count - 1].payload_len);
            break;

        case 11:
            init_psks_count += 1;
            init_psks = xrealloc(init_psks, sizeof(struct test_psk) * init_psks_count);

            memset(&init_psks[init_psks_count - 1], 0, sizeof(struct test_psk));
            set_bytes(&init_psks[init_psks_count - 1].psk,
                &init_psks[init_psks_count - 1].psk_len);
            break;

        case 12:
            resp_psks_count += 1;
            resp_psks = xrealloc(resp_psks, sizeof(struct test_psk) * resp_psks_count);

            memset(&resp_psks[resp_psks_count - 1], 0, sizeof(struct test_psk));
            set_bytes(&resp_psks[resp_psks_count - 1].psk,
                &resp_psks[resp_psks_count - 1].psk_len);
            break;

        case 100:
            if (output_file)
                fclose(output_file);
            output_file = fopen(optarg, "w");
            break;

        case 101: {
            FILE *out = dump_output;

            for (unsigned int pattern_idx = 0; noise_patterns[pattern_idx].pattern_name != NULL; ++pattern_idx) {
                for (unsigned int dh_idx = 0; noise_dh_table[dh_idx].dh_name != NULL; ++dh_idx) {
                    for (unsigned int ciph_idx = 0; noise_cipher_table[ciph_idx].ciph_name != NULL; ++ciph_idx) {
                        for (unsigned int hash_idx = 0; noise_hash_table[hash_idx].hash_name != NULL; ++hash_idx) {
                            fprintf(out, "Noise_%s_%s_%s_%s\n",
                                noise_patterns[pattern_idx].pattern_name,
                                noise_dh_table[dh_idx].dh_name,
                                noise_cipher_table[ciph_idx].ciph_name,
                                noise_hash_table[hash_idx].hash_name);
                        }
                    }
                }
            }
            exit(EXIT_SUCCESS);
        }

        default:
            fprintf(stderr, "Invalid argument\n");
            exit(EXIT_FAILURE);
    }
}

static void parse_args(int ac, char **av)
{
    const char shortopts[] = "";
    const struct option longopts[] = {
        {"protocol_name",               required_argument,  NULL,   1},
        {"init_prologue",               required_argument,  NULL,   2},
        {"init_static",                 required_argument,  NULL,   3},
        {"init_ephemeral",              required_argument,  NULL,   4},
        {"init_remote_static",          required_argument,  NULL,   5},
        {"resp_prologue",               required_argument,  NULL,   6},
        {"resp_static",                 required_argument,  NULL,   7},
        {"resp_ephemeral",              required_argument,  NULL,   8},
        {"resp_remote_static",          required_argument,  NULL,   9},
        {"message",                     required_argument,  NULL,  10},
        {"init_psks",                   required_argument,  NULL,  11},
        {"resp_psks",                   required_argument,  NULL,  12},
        {"output-file",                 required_argument,  NULL, 100},
        {"print-supported",             no_argument,        NULL, 101},
        {NULL, 0, NULL, 0}
    };
    int opt;
    int opt_val;

    while ((opt = getopt_long(ac, av, shortopts, longopts, &opt_val)) > 0) {
        //fprintf(stdout, "Parse opt %d ('%s')\n", opt, optarg);
        parse_opt(opt);
        //fprintf(stdout, "Finished opt %d\n", opt);
    }
}

static void dump_literal(const char *s)
{
    if (s) {
        fprintf(dump_output, "%s", s);
    }
}

static void dump_str(const char *name, const char *s, const char *footer)
{
    if (s) {
        fprintf(dump_output, "\"%s\": \"%s\"", name, s);
    }
    if (footer) {
        dump_literal(footer);
    }
}

static void dump_literal_bytes(const uint8_t *b, const size_t b_len, const char *footer)
{
    char *h;

    if (b) {
        bytes_to_hex(&h, b, b_len);
        fprintf(dump_output, "\"%s\"", h);
        dump_literal(footer);
        free(h);
    }
}

static void dump_bytes(const char *name, const uint8_t *b, const size_t b_len, const char *footer)
{
    char *h;

    if (b) {
        bytes_to_hex(&h, b, b_len);
        dump_str(name, h, footer);
        free(h);
    }
}

static void dump_payload(const uint8_t *payload, const size_t payload_len, const char *footer)
{
    dump_bytes("payload", payload, payload_len, footer);
}

static void dump_ciphertext(
    const uint8_t *ciphertext, const size_t ciphertext_len,
    const uint8_t *mac, const size_t mac_len,
    const char *footer)
{
    size_t total_len = ciphertext_len + mac_len;
    uint8_t *total_buf = xalloc(total_len);

    if (ciphertext)
        memcpy(total_buf, ciphertext, ciphertext_len);
    if (mac)
        memcpy(total_buf + ciphertext_len, mac, mac_len);
    dump_bytes("ciphertext", total_buf, total_len, footer);
    free(total_buf);
}

static void dump_key(const char *name, const keypair_t *keypair, bool public, const char *footer)
{
    if (keypair) {
        if (public) {
            dump_bytes(name, keypair_get_public_key(keypair), keypair_get_public_key_length(keypair), footer);
        } else {
            dump_bytes(name, keypair_get_private_key(keypair), keypair_get_private_key_length(keypair), footer);
        }
    }
}

#define JSON_EOL_NEXT ",\n"
#define JSON_EOL_LAST "\n"

int main(int ac, char **av)
{
    noise_handshakestate_t *init_handshake = NULL;
    noise_handshakestate_t *resp_handshake = NULL;
    const loglevel_t initial_loglevel = logger_get_level();

    parse_args(ac, av);
    assert(protocol_name != NULL);

    init_handshake = noise_handshakestate_create(protocol_name, true);
    resp_handshake = noise_handshakestate_create(protocol_name, false);
    assert(init_handshake != NULL);
    assert(resp_handshake != NULL);

    assert(noise_handshakestate_set_prologue(init_handshake, init_prologue, init_prologue_len) == true);
    assert(noise_handshakestate_set_prologue(resp_handshake, resp_prologue, resp_prologue_len) == true);

    // these checks log expected errors, no need to actually print them
    logger_set_level(LOG_CRIT);
    assert(noise_handshakestate_set_prologue(init_handshake, NULL, 0) == false);
    assert(noise_handshakestate_set_prologue(init_handshake, init_prologue, init_prologue_len) == false);
    assert(noise_handshakestate_set_prologue(resp_handshake, NULL, 0) == false);
    assert(noise_handshakestate_set_prologue(resp_handshake, resp_prologue, resp_prologue_len) == false);
    logger_set_level(initial_loglevel);

    if (keypair_has_private_key(init_static))
        assert(noise_handshakestate_set_s(init_handshake, init_static) == true);
    if (keypair_has_private_key(init_ephemeral))
        assert(noise_handshakestate_set_e(init_handshake, init_ephemeral) == true);
    if (keypair_has_public_key(init_remote_static))
        assert(noise_handshakestate_set_rs(init_handshake, init_remote_static) == true);
    if (keypair_has_private_key(resp_static))
        assert(noise_handshakestate_set_s(resp_handshake, resp_static) == true);
    if (keypair_has_private_key(resp_ephemeral))
        assert(noise_handshakestate_set_e(resp_handshake, resp_ephemeral) == true);
    if (keypair_has_public_key(resp_remote_static))
        assert(noise_handshakestate_set_rs(resp_handshake, resp_remote_static) == true);

    assert(init_handshake != NULL);
    assert(resp_handshake != NULL);

    dump_literal("{\n");
    dump_str("protocol_name", protocol_name, JSON_EOL_NEXT);
    dump_bytes("init_prologue", init_prologue, init_prologue_len, JSON_EOL_NEXT);
    dump_bytes("resp_prologue", resp_prologue, resp_prologue_len, JSON_EOL_NEXT);
    dump_key("init_static", init_static, false, JSON_EOL_NEXT);
    dump_key("init_ephemeral", init_ephemeral, false, JSON_EOL_NEXT);
    dump_key("init_remote_static", init_remote_static, true, JSON_EOL_NEXT);
    if (init_psks_count > 0) {
        dump_literal("\"init_psks\": [\n");
        for (size_t i = 0; i < init_psks_count; ++i)
            dump_literal_bytes(init_psks[i].psk, init_psks[i].psk_len, ((i + 1) < init_psks_count) ? JSON_EOL_NEXT : JSON_EOL_LAST);
        dump_literal("]" JSON_EOL_NEXT);
    }
    dump_key("resp_static", resp_static, false, JSON_EOL_NEXT);
    dump_key("resp_ephemeral", resp_ephemeral, false, JSON_EOL_NEXT);
    dump_key("resp_remote_static", resp_remote_static, true, JSON_EOL_NEXT);
    if (resp_psks_count > 0) {
        dump_literal("\"resp_psks\": [\n");
        for (size_t i = 0; i < resp_psks_count; ++i)
            dump_literal_bytes(resp_psks[i].psk, resp_psks[i].psk_len, ((i + 1) < resp_psks_count) ? JSON_EOL_NEXT : JSON_EOL_LAST);
        dump_literal("]" JSON_EOL_NEXT);
    }

    bool initiator = true;
    const bool is_one_way = noise_handshakestate_is_one_way(init_handshake);
    assert(is_one_way == noise_handshakestate_is_one_way(resp_handshake));
    const size_t buffer_maxlen = 1024;
    uint8_t *buffer = xalloc(buffer_maxlen);
    uint8_t *temp_buffer = xalloc(buffer_maxlen);
    size_t buffer_len;
    size_t temp_buffer_len;
    size_t init_handshake_hash_len = noise_handshakestate_get_handshake_hash_length(init_handshake);
    size_t resp_handshake_hash_len = noise_handshakestate_get_handshake_hash_length(resp_handshake);
    assert(init_handshake_hash_len != 0);
    assert(resp_handshake_hash_len != 0);
    assert(init_handshake_hash_len == resp_handshake_hash_len);
    uint8_t *init_handshake_hash = xalloc(init_handshake_hash_len);
    uint8_t *resp_handshake_hash = xalloc(resp_handshake_hash_len);
    const size_t mac_len = noise_handshakestate_get_maclen(init_handshake);
    assert(mac_len > 0);
    assert(mac_len == noise_handshakestate_get_maclen(resp_handshake));
    uint8_t *mac = xalloc(mac_len);

    bool has_split = false;
    noise_cipherstate_t *init_send_cipher = NULL;
    noise_cipherstate_t *init_recv_cipher = NULL;
    noise_cipherstate_t *resp_send_cipher = NULL;
    noise_cipherstate_t *resp_recv_cipher = NULL;
    size_t init_current_psk = 0;
    size_t resp_current_psk = 0;

    dump_literal("\"messages\": [\n");
    for (size_t i = 0; i < messages_count; ++i) {
        const struct test_message *msg = &messages[i];

        if (i > 0)
            dump_literal(JSON_EOL_NEXT); // end line of previous message closing bracket
        dump_literal("{\n");

        buffer_len = 0;
        temp_buffer_len = 0;

        if ((init_current_psk < init_psks_count) && noise_handshakestate_need_next_psk(init_handshake)) {
            assert(noise_handshakestate_set_next_psk(init_handshake, init_psks[init_current_psk].psk, init_psks[init_current_psk].psk_len) == true);
            assert(noise_handshakestate_need_next_psk(init_handshake) == false);
            init_current_psk += 1;
        }

        if ((resp_current_psk < resp_psks_count) && noise_handshakestate_need_next_psk(resp_handshake)) {
            assert(noise_handshakestate_set_next_psk(resp_handshake, resp_psks[resp_current_psk].psk, resp_psks[resp_current_psk].psk_len) == true);
            assert(noise_handshakestate_need_next_psk(resp_handshake) == false);
            resp_current_psk += 1;
        }

        if (has_split) {
            noise_cipherstate_t *send_cipher;
            noise_cipherstate_t *recv_cipher;

            if (is_one_way) {
                send_cipher = init_send_cipher;
                recv_cipher = resp_recv_cipher;
            } else {
                if (initiator) {
                    send_cipher = init_send_cipher;
                    recv_cipher = resp_recv_cipher;
                } else {
                    send_cipher = resp_send_cipher;
                    recv_cipher = init_recv_cipher;
                }
            }
            initiator = !initiator;

            assert(msg->payload_len <= buffer_maxlen);
            assert(noise_cipherstate_encrypt_with_ad_postinc(send_cipher, NULL, 0, msg->payload, msg->payload_len,
                buffer, &buffer_len, mac, mac_len) == true);

            dump_payload(msg->payload, msg->payload_len, JSON_EOL_NEXT);
            dump_ciphertext(buffer, buffer_len, mac, mac_len, JSON_EOL_LAST);

            assert(noise_cipherstate_decrypt_with_ad_postinc(recv_cipher, NULL, 0, buffer, buffer_len,
                temp_buffer, &temp_buffer_len, mac, mac_len) == true);

            assert(temp_buffer_len == msg->payload_len);
            assert(!memcmp(temp_buffer, msg->payload, msg->payload_len));

        } else {
            noise_handshakestate_t *ctx_write;
            noise_handshakestate_t *ctx_read;
            struct fixedbuf handshake_packet;
            struct fixedbuf handshake_write_payload;
            struct fixedbuf handshake_read_payload;

            if (initiator) {
                ctx_write = init_handshake;
                ctx_read = resp_handshake;
            } else {
                ctx_write = resp_handshake;
                ctx_read = init_handshake;
            }
            initiator = !initiator;

            fixedbuf_init_output(&handshake_packet, buffer, buffer_maxlen);
            fixedbuf_init_input(&handshake_write_payload, msg->payload, msg->payload_len);
            fixedbuf_init_output(&handshake_read_payload, temp_buffer, buffer_maxlen);

            assert(noise_handshakestate_expects_write(ctx_write) == true);
            assert(noise_handshakestate_expects_write(ctx_read) == false);
            assert(noise_handshakestate_expects_read(ctx_write) == false);
            assert(noise_handshakestate_expects_read(ctx_read) == true);

            assert(handshake_write_payload.len == msg->payload_len);
            assert(noise_handshakestate_write_msg(ctx_write, &handshake_packet, &handshake_write_payload) == true);
            dump_payload(handshake_write_payload.ptr, handshake_write_payload.len, JSON_EOL_NEXT);
            dump_ciphertext(handshake_packet.ptr, handshake_packet.len, NULL, 0, JSON_EOL_LAST);
            assert(noise_handshakestate_read_msg(ctx_read, &handshake_packet, &handshake_read_payload) == true);
            assert(handshake_read_payload.len == handshake_write_payload.len);
            assert(!memcmp(handshake_read_payload.ptr, handshake_write_payload.ptr, handshake_read_payload.len));

            const bool init_ready_to_split = noise_handshakestate_ready_to_split(init_handshake);
            const bool resp_ready_to_split = noise_handshakestate_ready_to_split(resp_handshake);
            assert(init_ready_to_split == resp_ready_to_split);

            bool init_has_split;
            bool resp_has_split;

            if (is_one_way) {
                assert(noise_handshakestate_split(init_handshake, &init_send_cipher, &init_recv_cipher) == false);
                assert(noise_handshakestate_split(resp_handshake, &resp_send_cipher, &resp_recv_cipher) == false);

                init_has_split = noise_handshakestate_split_one_way(init_handshake, &init_send_cipher);
                resp_has_split = noise_handshakestate_split_one_way(resp_handshake, &resp_recv_cipher);
            } else {
                assert(noise_handshakestate_split_one_way(init_handshake, &init_send_cipher) == false);
                assert(noise_handshakestate_split_one_way(resp_handshake, &resp_recv_cipher) == false);

                init_has_split = noise_handshakestate_split(init_handshake, &init_send_cipher, &init_recv_cipher);
                resp_has_split = noise_handshakestate_split(resp_handshake, &resp_send_cipher, &resp_recv_cipher);
            }

            assert(init_has_split == resp_has_split);
            assert(init_ready_to_split == init_has_split);
            has_split = init_has_split && resp_has_split;

            if (has_split) {
                if (is_one_way) {
                    assert(init_send_cipher != NULL);
                    assert(init_recv_cipher == NULL);
                    assert(resp_send_cipher == NULL);
                    assert(resp_recv_cipher != NULL);
                } else {
                    assert(init_send_cipher != NULL);
                    assert(init_recv_cipher != NULL);
                    assert(resp_send_cipher != NULL);
                    assert(resp_recv_cipher != NULL);
                }

                assert(noise_handshakestate_expects_write(ctx_write) == false);
                assert(noise_handshakestate_expects_write(ctx_read) == false);
                assert(noise_handshakestate_expects_read(ctx_write) == false);
                assert(noise_handshakestate_expects_read(ctx_read) == false);

                assert(noise_handshakestate_get_handshake_hash(init_handshake, init_handshake_hash, init_handshake_hash_len) == true);
                assert(noise_handshakestate_get_handshake_hash(resp_handshake, resp_handshake_hash, resp_handshake_hash_len) == true);
                assert(!memcmp(init_handshake_hash, resp_handshake_hash, init_handshake_hash_len));
                noise_handshakestate_destroy(init_handshake);
                noise_handshakestate_destroy(resp_handshake);
            }
        }

        dump_literal("}");
    }

    dump_literal(JSON_EOL_LAST);
    dump_literal("]");
    dump_literal(JSON_EOL_NEXT);
    dump_bytes("handshake_hash", init_handshake_hash, init_handshake_hash_len, JSON_EOL_LAST);
    dump_literal("}");
    dump_literal(JSON_EOL_LAST);

    noise_cipherstate_destroy(init_send_cipher);
    noise_cipherstate_destroy(init_recv_cipher);
    noise_cipherstate_destroy(resp_send_cipher);
    noise_cipherstate_destroy(resp_recv_cipher);
    free(buffer);
    free(temp_buffer);
    free(init_handshake_hash);
    free(resp_handshake_hash);
    free(mac);

    free(protocol_name);
    free(init_prologue);
    keypair_destroy(init_static);
    keypair_destroy(init_ephemeral);
    keypair_destroy(init_remote_static);
    free(resp_prologue);
    keypair_destroy(resp_static);
    keypair_destroy(resp_ephemeral);
    keypair_destroy(resp_remote_static);
    for (size_t i = 0; i < init_psks_count; ++i) {
        free(init_psks[i].psk);
    }
    free(init_psks);
    for (size_t i = 0; i < resp_psks_count; ++i) {
        free(resp_psks[i].psk);
    }
    free(resp_psks);
    for (size_t i = 0; i < messages_count; ++i) {
        free(messages[i].payload);
    }
    free(messages);

    if (output_file) {
        fflush(output_file);
        fclose(output_file);
    }
    return 0;
}
