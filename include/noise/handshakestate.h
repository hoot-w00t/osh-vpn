#ifndef OSH_NOISE_HANDSHAKESTATE_H_
#define OSH_NOISE_HANDSHAKESTATE_H_

#include "noise/symmetricstate.h"
#include "buffer/fixedbuf.h"
#include "crypto/keypair.h"
#include <stdbool.h>

typedef struct noise_handshakestate noise_handshakestate_t;

__attribute__((warn_unused_result))
noise_handshakestate_t *noise_handshakestate_create(const char *protocol_name, bool initiator);
void noise_handshakestate_destroy(noise_handshakestate_t *ctx);

size_t noise_handshakestate_get_maclen(const noise_handshakestate_t *ctx);

__attribute__((warn_unused_result))
bool noise_handshakestate_set_s(noise_handshakestate_t *ctx, const keypair_t *s);
__attribute__((warn_unused_result))
bool noise_handshakestate_set_e(noise_handshakestate_t *ctx, const keypair_t *e);
__attribute__((warn_unused_result))
bool noise_handshakestate_set_rs(noise_handshakestate_t *ctx, const keypair_t *rs);
__attribute__((warn_unused_result))
bool noise_handshakestate_set_re(noise_handshakestate_t *ctx, const keypair_t *re);
const keypair_t *noise_handshakestate_get_s(const noise_handshakestate_t *ctx);
const keypair_t *noise_handshakestate_get_rs(const noise_handshakestate_t *ctx);

bool noise_handshakestate_is_initiator(const noise_handshakestate_t *ctx);

bool noise_handshakestate_expects_write(const noise_handshakestate_t *ctx);
bool noise_handshakestate_expects_read(const noise_handshakestate_t *ctx);

bool noise_handshakestate_set_next_psk(noise_handshakestate_t *ctx, const void *psk, size_t len);
bool noise_handshakestate_need_next_psk(const noise_handshakestate_t *ctx);

__attribute__((warn_unused_result))
bool noise_handshakestate_set_prologue(noise_handshakestate_t *ctx, const void *prologue, size_t prologue_len);

__attribute__((warn_unused_result))
bool noise_handshakestate_write_msg(noise_handshakestate_t *ctx,
    struct fixedbuf *output, const struct fixedbuf *payload);
__attribute__((warn_unused_result))
bool noise_handshakestate_read_msg(noise_handshakestate_t *ctx,
    struct fixedbuf *input, struct fixedbuf *payload);

__attribute__((warn_unused_result))
bool noise_handshakestate_ready_to_split(const noise_handshakestate_t *ctx);
__attribute__((warn_unused_result))
bool noise_handshakestate_split(noise_handshakestate_t *ctx,
    noise_cipherstate_t **c1, noise_cipherstate_t **c2);

__attribute__((warn_unused_result))
bool noise_handshakestate_get_handshake_hash(const noise_handshakestate_t *ctx, void *dest, size_t dest_len);
size_t noise_handshakestate_get_handshake_hash_length(const noise_handshakestate_t *ctx);

#endif
