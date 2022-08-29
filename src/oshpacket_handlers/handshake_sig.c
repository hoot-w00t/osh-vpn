#include "oshd.h"
#include "logger.h"
#include <stdlib.h>
#include <string.h>

// Queue a HELLO packet with our authentication result and other options if
// needed
// If the authentication failed this will also fail
static bool queue_hello(client_t *c)
{
    oshpacket_hello_t packet;

    logger_debug(DBG_HANDSHAKE, "%s: Creating HELLO packet", c->addrw);
    memset(&packet, 0, sizeof(packet));
    logger_debug(DBG_HANDSHAKE, "%s: Local options 0x%08X", c->addrw, packet.options);
    packet.options = htonl(packet.options);

    logger_debug(DBG_HANDSHAKE, "%s: Queuing HELLO packet", c->addrw);
    return client_queue_packet(c, c->handshake_id, HELLO,
        &packet, sizeof(packet));
}

bool oshpacket_handler_handshake_sig(client_t *c,
    __attribute__((unused)) oshpacket_hdr_t *hdr, void *payload)
{
    const oshpacket_handshake_sig_t *sig_packet = (const oshpacket_handshake_sig_t *) payload;

    // If the handshake is not in progress we can't process this
    if (   !c->handshake_in_progress
        || !c->handshake_id
        || !c->handshake_sig_data)
    {
        logger(LOG_ERR, "%s: Received HANDSHAKE_SIG but no handshake is in progress",
            c->addrw);
        return false;
    }

    // Make sure that the remote node has a public key
    if (!c->handshake_id->pubkey) {
        logger(LOG_ERR, "%s: Handshake failed: No public key", c->addrw);
        return false;
    }

    // Make sure that the remote node's public key is trusted
    // We must verify it here even if this check is redundant
    if (!c->handshake_id->pubkey_local && !oshd.remote_auth) {
        logger(LOG_ERR, "%s: Handshake failed: No trusted public key", c->addrw);
        return false;
    }

    // Verify the handshake signature
    logger_debug(DBG_HANDSHAKE, "%s: %s has a %s public key",
        c->addrw, c->handshake_id->name,
        c->handshake_id->pubkey_local ? "local" : "remote");

    c->handshake_valid_signature = pkey_verify(c->handshake_id->pubkey,
        c->handshake_sig_data, sizeof(oshpacket_handshake_sig_data_t),
        sig_packet->sig, sizeof(sig_packet->sig));

    // We no longer need this data
    free(c->handshake_sig_data);
    c->handshake_sig_data = NULL;

    // If the signature verification failed, this connection cannot be trusted
    if (!c->handshake_valid_signature) {
        logger(LOG_ERR, "%s: Handshake failed: Signature verification failed for %s",
            c->addrw, c->handshake_id->name);
        return false;
    }

    logger_debug(DBG_HANDSHAKE, "%s: Valid signature from %s",
        c->addrw, c->handshake_id->name);

    // If we have a recv_cipher_next, we can start using it now as this packet
    // is the last to be sent with the old cipher
    if (c->recv_cipher_next) {
        logger_debug(DBG_HANDSHAKE, "%s: Replacing old recv cipher with the new one",
            c->addrw);
        cipher_free(c->recv_cipher);
        c->recv_cipher = c->recv_cipher_next;
        c->recv_cipher_next = NULL;
    }

    // If this is the first handshake, we can finalize the authentication
    // Otherwise this step is already done and the handshake is only renewing
    // the encryption keys

    if (c->authenticated) {
        // If we are already authenticated, this handshake is only renewing the
        // encryption keys, it is finished now
        client_finish_handshake(c);
        return true;
    } else {
        // If we are not authenticated yet this handshake is the first one, we
        // have one last step to finalize the authentication
        // The handshake will finish after HELLO packets are processed
        return queue_hello(c);
    }
}

bool oshpacket_handler_handshake_sig_auth(
    client_t *c, __attribute__((unused)) node_id_t *src,
    oshpacket_hdr_t *hdr, void *payload)
{
    return oshpacket_handler_handshake_sig(c, hdr, payload);
}
