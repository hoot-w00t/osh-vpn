#include "noise/handshakestate.h"
#include "noise/crypto_table.h"
#include "noise/patterns_table.h"
#include "noise/protocol_name.h"
#include "xalloc.h"
#include "macros_assert.h"
#include "logger.h"
#include "memzero.h"
#include <stdlib.h>
#include <string.h>

// FIXME: Add an "error-lock" to make sure that the handshake state context is
//        not going to go into an undefined state after an unexpected error
//        i.e. once we encounter an error (after noise_handshakestate_create())
//             the context fully resets or is locked down to prevent calling any
//             member function on it (apart from error getters and noise_handshakestate_destroy())

struct noise_handshakestate {
    noise_symmetricstate_t *symmetric;

    cipher_type_t cipher_type;
    size_t maclen;

    hash_type_t hash_type;
    size_t hash_len;

    keypair_type_t keypair_type;
    size_t keypair_secretlen;
    uint8_t keypair_secret[NOISE_DH_MAXLEN];    // used as temporary buffer for DH secrets
    keypair_t *s;
    keypair_t *e;
    keypair_t *rs;
    keypair_t *re;

    bool has_sent_e;
    bool has_mixed_psk;
    bool psk_need_next;
    uint8_t next_psk[NOISE_PSK_LEN];

    bool initiator;
    struct noise_protocol_name protocol;
    const struct noise_pattern *pattern;
    unsigned int curr_msg_idx;

    bool has_processed_prologue;
    bool has_processed_pre_messages;
    bool has_split;

    struct {
        // 7.3 rule 2
        bool written_e;
        bool written_s;
        bool read_e;
        bool read_s;

        // 7.3 rule 3
        bool processed_ee;
        bool processed_es;
        bool processed_se;
        bool processed_ss;
    } validity;
};

__attribute__((warn_unused_result))
static bool mix_initiator_public_key(noise_handshakestate_t *ctx)
{
    const keypair_t *key = ctx->initiator ? ctx->s : ctx->rs;

    return noise_symmetricstate_mix_hash(ctx->symmetric, keypair_get_public_key(key), keypair_get_public_key_length(key));
}

__attribute__((warn_unused_result))
static bool mix_responder_public_key(noise_handshakestate_t *ctx)
{
    const keypair_t *key = ctx->initiator ? ctx->rs : ctx->s;

    return noise_symmetricstate_mix_hash(ctx->symmetric, keypair_get_public_key(key), keypair_get_public_key_length(key));
}

noise_handshakestate_t *noise_handshakestate_create(const char *protocol_name, bool initiator)
{
    noise_handshakestate_t *ctx = xzalloc(sizeof(*ctx));

    // Parse protocol name and lookup DH, cipher, hash and pattern
    if (!noise_parse_protocol_name(&ctx->protocol, protocol_name)) {
        logger(LOG_ERR, "%s: Failed to parse Noise protocol name: '%s'",
            __func__, protocol_name);
        goto fail;
    }

    if (!noise_get_dh_type(ctx->protocol.dh_name, &ctx->keypair_type)) {
        logger(LOG_ERR, "%s: Unsupported DH '%s'", __func__, ctx->protocol.dh_name);
        goto fail;
    }
    if (!noise_get_cipher_type(ctx->protocol.ciph_name, &ctx->cipher_type)) {
        logger(LOG_ERR, "%s: Unsupported cipher '%s'", __func__, ctx->protocol.ciph_name);
        goto fail;
    }
    if (!noise_get_hash_type(ctx->protocol.hash_name, &ctx->hash_type)) {
        logger(LOG_ERR, "%s: Unsupported hash '%s'", __func__, ctx->protocol.hash_name);
        goto fail;
    }

    ctx->pattern = noise_get_pattern(ctx->protocol.pattern);
    if (ctx->pattern == NULL) {
        logger(LOG_ERR, "%s: Unsupported pattern '%s'", __func__, ctx->protocol.pattern);
        goto fail;
    }
    assert(ctx->pattern->pre_msgs_count <= NOISE_MAX_PRE_MESSAGES);
    assert(ctx->pattern->msgs_count <= NOISE_MAX_MESSAGES);

    // Initialize context
    ctx->initiator = initiator;
    ctx->has_split = false;
    ctx->has_sent_e = false;
    ctx->has_mixed_psk = false;
    ctx->has_processed_prologue = false;
    ctx->has_processed_pre_messages = false;
    ctx->curr_msg_idx = 0;

    ctx->validity.written_e = false;
    ctx->validity.written_s = false;
    ctx->validity.read_e = false;
    ctx->validity.read_s = false;
    ctx->validity.processed_ee = false;
    ctx->validity.processed_es = false;
    ctx->validity.processed_se = false;
    ctx->validity.processed_ss = false;

    ctx->psk_need_next = true;
    STATIC_ASSERT_NOMSG(sizeof(ctx->next_psk) == NOISE_PSK_LEN);
    memzero(ctx->next_psk, NOISE_PSK_LEN);

    // Create keypairs
    ctx->s = keypair_create(ctx->keypair_type);
    ctx->e = keypair_create(ctx->keypair_type);
    ctx->rs = keypair_create(ctx->keypair_type);
    ctx->re = keypair_create(ctx->keypair_type);
    if (ctx->s == NULL || ctx->e == NULL || ctx->rs == NULL || ctx->re == NULL) {
        logger(LOG_ERR, "%s: Failed to create keypairs", __func__);
        goto fail;
    }

    // Initialize temporary buffer for DH secrets
    ctx->keypair_secretlen = keypair_get_secret_length(ctx->e);
    assert(ctx->keypair_secretlen > 0);
    assert(ctx->keypair_secretlen <= NOISE_DH_MAXLEN);

    // Create symmetric state
    ctx->maclen = cipher_get_mac_size_from_type(ctx->cipher_type);
    ctx->hash_len = hash_type_length(ctx->hash_type);
    assert(ctx->maclen > 0);
    assert(ctx->maclen <= NOISE_CIPHER_MAC_MAXLEN);
    assert(ctx->hash_len > 0);
    assert(ctx->hash_len <= NOISE_HASH_MAXLEN);

    ctx->symmetric = noise_symmetricstate_create(protocol_name, ctx->cipher_type, ctx->hash_type);
    if (ctx->symmetric == NULL) {
        logger(LOG_ERR, "%s: Failed to create symmetric state", __func__);
        goto fail;
    }

    return ctx;

fail:
    noise_handshakestate_destroy(ctx);
    return NULL;
}

void noise_handshakestate_destroy(noise_handshakestate_t *ctx)
{
    if (ctx) {
        noise_symmetricstate_destroy(ctx->symmetric);

        keypair_destroy(ctx->s);
        keypair_destroy(ctx->e);
        keypair_destroy(ctx->rs);
        keypair_destroy(ctx->re);

        memzero(ctx->keypair_secret, NOISE_DH_MAXLEN);
        memzero(ctx->next_psk, NOISE_PSK_LEN);

        free(ctx);
    }
}

// Return current message from pattern (NULL if no messages are left)
__attribute__((warn_unused_result))
static const struct noise_message *get_curr_msg(const noise_handshakestate_t *ctx)
{
    const struct noise_message *msg;

    if (ctx->curr_msg_idx >= ctx->pattern->msgs_count)
        return NULL;

    msg = &ctx->pattern->msgs[ctx->curr_msg_idx];
    assert(msg->tokens_count <= NOISE_MAX_TOKENS_PER_MESSAGE);
    return msg;
}

size_t noise_handshakestate_get_maclen(const noise_handshakestate_t *ctx)
{
    return ctx->maclen;
}

bool noise_handshakestate_set_s(noise_handshakestate_t *ctx, const keypair_t *s)
{
    return keypair_has_private_key(s) && keypair_copy_private_key(ctx->s, s);
}

bool noise_handshakestate_set_e(noise_handshakestate_t *ctx, const keypair_t *e)
{
    return keypair_has_private_key(e) && keypair_copy_private_key(ctx->e, e);
}

bool noise_handshakestate_set_rs(noise_handshakestate_t *ctx, const keypair_t *rs)
{
    return keypair_has_public_key(rs) && keypair_copy_public_key(ctx->rs, rs);
}

bool noise_handshakestate_set_re(noise_handshakestate_t *ctx, const keypair_t *re)
{
    return keypair_has_public_key(re) && keypair_copy_public_key(ctx->re, re);
}

const keypair_t *noise_handshakestate_get_s(const noise_handshakestate_t *ctx)
{
    return ctx->s;
}

const keypair_t *noise_handshakestate_get_rs(const noise_handshakestate_t *ctx)
{
    return ctx->rs;
}

bool noise_handshakestate_is_initiator(const noise_handshakestate_t *ctx)
{
    return ctx->initiator;
}

bool noise_handshakestate_expects_write(const noise_handshakestate_t *ctx)
{
    const struct noise_message *msg = get_curr_msg(ctx);

    if (msg == NULL)
        return false;

    return ctx->initiator ? msg->from_initiator : !(msg->from_initiator);
}

bool noise_handshakestate_expects_read(const noise_handshakestate_t *ctx)
{
    const struct noise_message *msg = get_curr_msg(ctx);

    if (msg == NULL)
        return false;

    return ctx->initiator ? !(msg->from_initiator) : msg->from_initiator;
}

// Set the next PSK that will be used by the "psk" token
// The PSK otherwise defaults to a zeroed buffer, and it is reset back to that
// zeroed state after it was consumed (dummy PSK)
bool noise_handshakestate_set_next_psk(noise_handshakestate_t *ctx, const void *psk, size_t len)
{
    STATIC_ASSERT_NOMSG(sizeof(ctx->next_psk) == NOISE_PSK_LEN);

    if (psk == NULL || len != NOISE_PSK_LEN || !ctx->pattern->psk_mode) {
        memzero(ctx->next_psk, NOISE_PSK_LEN);
        return false;
    }

    memcpy(ctx->next_psk, psk, NOISE_PSK_LEN);
    ctx->psk_need_next = false;
    return true;
}

bool noise_handshakestate_need_next_psk(const noise_handshakestate_t *ctx)
{
    return ctx->pattern->psk_mode && ctx->psk_need_next;
}

// Mix prologue
__attribute__((warn_unused_result))
static bool process_prologue(noise_handshakestate_t *ctx,
    const void *prologue, const size_t prologue_len)
{
    const uint8_t empty = 0;

    if (ctx->has_processed_prologue) {
        logger(LOG_ERR, "%s: Already processed prologue", __func__);
        return false;
    }

    // Mix handshake prologue
    if (prologue != NULL && prologue_len > 0) {
        if (!noise_symmetricstate_mix_hash(ctx->symmetric, prologue, prologue_len))
            return false;
    } else {
        if (!noise_symmetricstate_mix_hash(ctx->symmetric, &empty, 0))
            return false;
    }

    ctx->has_processed_prologue = true;
    return true;
}

bool noise_handshakestate_set_prologue(noise_handshakestate_t *ctx, const void *prologue, size_t prologue_len)
{
    return process_prologue(ctx, prologue, prologue_len);
}

// Mix empty prologue (if none was set) and process pattern pre-messages
__attribute__((warn_unused_result))
static bool process_pre_messages(noise_handshakestate_t *ctx)
{
    if (ctx->has_processed_pre_messages) {
        logger(LOG_ERR, "%s: Already processed pre-messages", __func__);
        return false;
    }

    // Mix empty prologue
    if (!ctx->has_processed_prologue) {
        if (!process_prologue(ctx, NULL, 0))
            return false;
    }

    // Process pre-messages
    for (unsigned int i = 0; i < ctx->pattern->pre_msgs_count; ++i) {
        const struct noise_message *premsg = &ctx->pattern->pre_msgs[i];

        assert(premsg->tokens_count <= NOISE_MAX_TOKENS_PER_MESSAGE);
        for (unsigned int j = 0; j < premsg->tokens_count; ++j) {
            switch (premsg->tokens[j]) {
                case NOISE_TOK_S:
                    if (premsg->from_initiator) {
                        if (!mix_initiator_public_key(ctx))
                            return false;
                    } else {
                        if (!mix_responder_public_key(ctx))
                            return false;
                    }
                    break;

                default:
                    logger(LOG_ERR, "%s: Invalid pre-message %u token %u for %s",
                        __func__, i, j, ctx->pattern->pattern_name);
                    return false;
            }
        }
    }

    ctx->has_processed_pre_messages = true;
    return true;
}

static bool handshake_dh(noise_handshakestate_t *ctx, keypair_t *local_keypair, keypair_t *remote_keypair)
{
    bool success = false;

    assert(local_keypair != NULL);
    assert(remote_keypair != NULL);

    success = keypair_kex_dh(local_keypair, remote_keypair, ctx->keypair_secret, ctx->keypair_secretlen)
           && noise_symmetricstate_mix_key(ctx->symmetric, ctx->keypair_secret, ctx->keypair_secretlen);

    memzero(ctx->keypair_secret, NOISE_DH_MAXLEN);
    return success;
}

// DH (same for write/read)
static bool noise_handshakestate_ee(noise_handshakestate_t *ctx)
{
    if (ctx->validity.processed_ee) {
        logger(LOG_ERR, "%s: Already processed %s token", __func__, "ee");
        return false;
    }
    ctx->validity.processed_ee = true;

    return handshake_dh(ctx, ctx->e, ctx->re);
}

static bool noise_handshakestate_es(noise_handshakestate_t *ctx)
{
    if (ctx->validity.processed_es) {
        logger(LOG_ERR, "%s: Already processed %s token", __func__, "es");
        return false;
    }
    ctx->validity.processed_es = true;

    return ctx->initiator
         ? handshake_dh(ctx, ctx->e, ctx->rs)
         : handshake_dh(ctx, ctx->s, ctx->re);
}

static bool noise_handshakestate_se(noise_handshakestate_t *ctx)
{
    if (ctx->validity.processed_se) {
        logger(LOG_ERR, "%s: Already processed %s token", __func__, "se");
        return false;
    }
    ctx->validity.processed_se = true;

    return ctx->initiator
         ? handshake_dh(ctx, ctx->s, ctx->re)
         : handshake_dh(ctx, ctx->e, ctx->rs);
}

static bool noise_handshakestate_ss(noise_handshakestate_t *ctx)
{
    if (ctx->validity.processed_ss) {
        logger(LOG_ERR, "%s: Already processed %s token", __func__, "ss");
        return false;
    }
    ctx->validity.processed_ss = true;

    return handshake_dh(ctx, ctx->s, ctx->rs);
}

static bool noise_handshakestate_psk(noise_handshakestate_t *ctx)
{
    bool success;

    if (!ctx->pattern->psk_mode)
        return false;

    STATIC_ASSERT_NOMSG(sizeof(ctx->next_psk) == NOISE_PSK_LEN);
    success = noise_symmetricstate_mix_key_and_hash(ctx->symmetric, ctx->next_psk, NOISE_PSK_LEN);
    memzero(ctx->next_psk, NOISE_PSK_LEN);
    ctx->psk_need_next = true;
    if (success)
        ctx->has_mixed_psk = true;
    return success;
}

// Write
static bool noise_handshakestate_write_payload(
    noise_handshakestate_t *ctx,
    struct fixedbuf *output,
    const void *payload,
    size_t payload_len)
{
    // 7.3 validity rule 4
    if (ctx->initiator) {
        if (ctx->validity.processed_se && !ctx->validity.processed_ee)
            return false;
        if (ctx->validity.processed_ss && !ctx->validity.processed_es)
            return false;
    } else {
        if (ctx->validity.processed_es && !ctx->validity.processed_ee)
            return false;
        if (ctx->validity.processed_ss && !ctx->validity.processed_se)
            return false;
    }

    if (noise_symmetricstate_has_key(ctx->symmetric)) {
        // PSK validity rule (see Noise Protocol specification 9.3)
        if (ctx->has_mixed_psk && !ctx->has_sent_e)
            return false;

        uint8_t *buf = xalloc(payload_len);
        uint8_t *mac = xalloc(ctx->maclen);
        size_t len;
        bool success;

        success = noise_symmetricstate_encrypt_and_hash(ctx->symmetric, payload, payload_len, buf, &len, mac, ctx->maclen)
               && fixedbuf_append(output, buf, len)
               && fixedbuf_append(output, mac, ctx->maclen);

        if (payload_len > 0)
            memzero(buf, payload_len);
        free(buf);
        memzero_free(mac, ctx->maclen);

        return success;
    } else {
        return noise_symmetricstate_mix_hash(ctx->symmetric, payload, payload_len)
            && fixedbuf_append(output, payload, payload_len);
    }
}

static bool noise_handshakestate_write_e(noise_handshakestate_t *ctx, struct fixedbuf *output)
{
    const void *pub;
    size_t publen;

    if (ctx->validity.written_e) {
        logger(LOG_ERR, "%s: Already written e token", __func__);
        return false;
    }
    ctx->validity.written_e = true;

    if (!keypair_has_private_key(ctx->e)) {
        if (!keypair_generate_random(ctx->e))
            return false;
    }

    pub = keypair_get_public_key(ctx->e);
    publen = keypair_get_public_key_length(ctx->e);

    if (!noise_symmetricstate_mix_hash(ctx->symmetric, pub, publen))
        return false;
    if (ctx->pattern->psk_mode) {
        if (!noise_symmetricstate_mix_key(ctx->symmetric, pub, publen))
            return false;
    }
    if (!fixedbuf_append(output, pub, publen))
        return false;

    ctx->has_sent_e = true;
    return true;
}

static bool noise_handshakestate_write_s(noise_handshakestate_t *ctx, struct fixedbuf *output)
{
    if (ctx->validity.written_s) {
        logger(LOG_ERR, "%s: Already written s token", __func__);
        return false;
    }
    ctx->validity.written_s = true;

    return noise_handshakestate_write_payload(ctx, output,
        keypair_get_public_key(ctx->s), keypair_get_public_key_length(ctx->s));
}


// Read
static bool noise_handshakestate_read_payload(noise_handshakestate_t *ctx,
    const void *payload, const size_t payload_len,
    void *mac, const size_t mac_len,
// FIXME: Make *mac const once noise_symmetricstate_decrypt_and_hash() *mac becomes const
    struct fixedbuf *output)
{
    bool success = false;
    const size_t plaintext_maxlen = payload_len;
    uint8_t *plaintext = xalloc(plaintext_maxlen);
    size_t len;

    if (!noise_symmetricstate_decrypt_and_hash(ctx->symmetric, payload, payload_len,
            plaintext, &len, mac, mac_len))
    {
        goto end;
    }

    if (len > 0 && output) {
        if (!fixedbuf_append(output, plaintext, len))
            goto end;
    }

    success = true;

end:
    if (plaintext_maxlen > 0)
        memzero(plaintext, plaintext_maxlen);
    free(plaintext);
    return success;
}

static bool noise_handshakestate_read_e(noise_handshakestate_t *ctx, struct fixedbuf *input, size_t *input_offset)
{
    const size_t publen = keypair_get_public_key_length(ctx->re);
    void *pub = fixedbuf_get(input, input_offset, publen);

    if (ctx->validity.read_e) {
        logger(LOG_ERR, "%s: Already read e token", __func__);
        return false;
    }
    ctx->validity.read_e = true;

    if (!pub)
        return false;
    if (keypair_has_public_key(ctx->re))
        return false;
    if (!keypair_set_public_key(ctx->re, pub, publen))
        return false;

    if (!noise_symmetricstate_mix_hash(ctx->symmetric, keypair_get_public_key(ctx->re), keypair_get_public_key_length(ctx->re)))
        return false;
    if (ctx->pattern->psk_mode) {
        if (!noise_symmetricstate_mix_key(ctx->symmetric, keypair_get_public_key(ctx->re), keypair_get_public_key_length(ctx->re)))
            return false;
    }

    return true;
}

static bool noise_handshakestate_read_s(noise_handshakestate_t *ctx, struct fixedbuf *input, size_t *input_offset)
{
    bool success = false;

    if (ctx->validity.read_s) {
        logger(LOG_ERR, "%s: Already read s token", __func__);
        return false;
    }
    ctx->validity.read_s = true;

    if (noise_symmetricstate_has_key(ctx->symmetric)) {
        const size_t ciphertext_len = keypair_get_public_key_length(ctx->rs);
        const void *ciphertext = fixedbuf_get(input, input_offset, ciphertext_len);
        void *mac = fixedbuf_get(input, input_offset, ctx->maclen);
        // FIXME: Make *mac const once noise_handshakestate_read_payload() *mac becomes const

        struct fixedbuf plaintext;

        fixedbuf_init_output(&plaintext, NULL, keypair_get_public_key_length(ctx->rs));

        plaintext.ptr = xzalloc(plaintext.maxlen);

        if (!noise_handshakestate_read_payload(ctx, ciphertext, ciphertext_len, mac, ctx->maclen, &plaintext)) {
            memzero_free(plaintext.ptr, plaintext.maxlen);
            return false;
        }

        if (plaintext.len != plaintext.maxlen) {
            memzero_free(plaintext.ptr, plaintext.maxlen);
            return false;
        }

        success = keypair_set_public_key(ctx->rs, plaintext.ptr, plaintext.len);
        memzero_free(plaintext.ptr, plaintext.maxlen);
    } else {
        const size_t keylen = keypair_get_public_key_length(ctx->rs);
        const void *key = fixedbuf_get(input, input_offset, keylen);

        success = noise_symmetricstate_mix_hash(ctx->symmetric, key, keylen)
               && keypair_set_public_key(ctx->rs, key, keylen);
    }

    return success;
}

bool noise_handshakestate_write_msg(noise_handshakestate_t *ctx,
    struct fixedbuf *output, const struct fixedbuf *payload)
{
    const uint8_t empty = 0;
    const struct noise_message *msg;

    if (!ctx->has_processed_pre_messages) {
        if (!process_pre_messages(ctx))
            return false;
    }

    msg = get_curr_msg(ctx);
    if (msg == NULL || !noise_handshakestate_expects_write(ctx))
        return false;

    for (unsigned int i = 0; i < msg->tokens_count; ++i) {
        switch (msg->tokens[i]) {
            case NOISE_TOK_E:
                if (!noise_handshakestate_write_e(ctx, output))
                    return false;
                break;

            case NOISE_TOK_S:
                if (!noise_handshakestate_write_s(ctx, output))
                    return false;
                break;

            case NOISE_TOK_EE:
                if (!noise_handshakestate_ee(ctx))
                    return false;
                break;

            case NOISE_TOK_ES:
                if (!noise_handshakestate_es(ctx))
                    return false;
                break;

            case NOISE_TOK_SE:
                if (!noise_handshakestate_se(ctx))
                    return false;
                break;

            case NOISE_TOK_SS:
                if (!noise_handshakestate_ss(ctx))
                    return false;
                break;

            case NOISE_TOK_PSK:
                if (!noise_handshakestate_psk(ctx))
                    return false;
                break;

            default:
                logger(LOG_CRIT, "%s: Invalid message %u token %u for %s",
                    __func__, ctx->curr_msg_idx, i, ctx->pattern->pattern_name);
                return false;
        }
    }

    if (fixedbuf_has_data(payload)) {
        if (!noise_handshakestate_write_payload(ctx, output, payload->ptr, payload->len))
            return false;
    } else {
        if (!noise_handshakestate_write_payload(ctx, output, &empty, 0))
            return false;
    }

    ctx->curr_msg_idx += 1;
    return true;
}

bool noise_handshakestate_read_msg(noise_handshakestate_t *ctx,
    struct fixedbuf *input, struct fixedbuf *payload)
{
    const struct noise_message *msg;
    size_t input_offset;

    if (!ctx->has_processed_pre_messages) {
        if (!process_pre_messages(ctx))
            return false;
    }

    if (input == NULL || payload == NULL)
        return false;

    msg = get_curr_msg(ctx);
    if (msg == NULL || !noise_handshakestate_expects_read(ctx))
        return false;

    input_offset = 0;
    for (unsigned int i = 0; i < msg->tokens_count; ++i) {
        switch (msg->tokens[i]) {
            case NOISE_TOK_E:
                if (!noise_handshakestate_read_e(ctx, input, &input_offset))
                    return false;
                break;

            case NOISE_TOK_S:
                if (!noise_handshakestate_read_s(ctx, input, &input_offset))
                    return false;
                break;

            case NOISE_TOK_EE:
                if (!noise_handshakestate_ee(ctx))
                    return false;
                break;

            case NOISE_TOK_ES:
                if (!noise_handshakestate_es(ctx))
                    return false;
                break;

            case NOISE_TOK_SE:
                if (!noise_handshakestate_se(ctx))
                    return false;
                break;

            case NOISE_TOK_SS:
                if (!noise_handshakestate_ss(ctx))
                    return false;
                break;

            case NOISE_TOK_PSK:
                if (!noise_handshakestate_psk(ctx))
                    return false;
                break;

            default:
                logger(LOG_CRIT, "%s: Invalid message %u token %u for %s",
                    __func__, ctx->curr_msg_idx, i, ctx->pattern->pattern_name);
                return false;
        }
    }

    const size_t remaining_len = fixedbuf_get_remaining_length(input, &input_offset);
    bool success;

    if (noise_symmetricstate_has_key(ctx->symmetric)) {
        if (remaining_len < ctx->maclen)
            return false;

        const size_t ciphertext_len = remaining_len - ctx->maclen;
        void *ciphertext = fixedbuf_get(input, &input_offset, ciphertext_len);
        void *mac = fixedbuf_get(input, &input_offset, ctx->maclen);

        success = noise_handshakestate_read_payload(ctx, ciphertext, ciphertext_len, mac, ctx->maclen, payload);

    } else if (remaining_len != 0) {
        void *plaintext = fixedbuf_get(input, &input_offset, remaining_len);

        if (plaintext == NULL)
            return false;

        success = noise_symmetricstate_mix_hash(ctx->symmetric, plaintext, remaining_len)
               && fixedbuf_append(payload, plaintext, remaining_len);
    } else {
        success = true;
    }

    if (success)
        ctx->curr_msg_idx += 1;
    return success;
}

bool noise_handshakestate_ready_to_split(const noise_handshakestate_t *ctx)
{
    return  get_curr_msg(ctx) == NULL
        &&  ctx->has_processed_prologue
        &&  ctx->has_processed_pre_messages
        &&  ctx->curr_msg_idx == ctx->pattern->msgs_count
        && !ctx->has_split;
}

bool noise_handshakestate_split(noise_handshakestate_t *ctx,
    noise_cipherstate_t **c1, noise_cipherstate_t **c2)
{
    bool success;

    if (!noise_handshakestate_ready_to_split(ctx))
        return false;

    success = ctx->initiator
         ? noise_symmetricstate_split(ctx->symmetric, c1, c2)
         : noise_symmetricstate_split(ctx->symmetric, c2, c1);
    ctx->has_split = success;
    return success;
}

bool noise_handshakestate_get_handshake_hash(const noise_handshakestate_t *ctx, void *dest, size_t dest_len)
{
    if (!ctx->has_split || dest == NULL || dest_len != ctx->hash_len)
        return false;

    memcpy(dest, noise_symmetricstate_get_handshake_hash(ctx->symmetric), ctx->hash_len);
    return true;
}

size_t noise_handshakestate_get_handshake_hash_length(const noise_handshakestate_t *ctx)
{
    return ctx->hash_len;
}
