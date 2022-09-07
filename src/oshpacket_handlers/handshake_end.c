#include "node.h"
#include "logger.h"

bool oshpacket_handler_handshake_end(client_t *c,
    __attribute__((unused)) node_id_t *src,
    __attribute__((unused)) oshpacket_hdr_t *hdr,
    __attribute__((unused)) void *payload)
{
    // If the handshake is not in progress we can't process this
    if (   !c->handshake_in_progress
        || !c->handshake_sig_data_complete
        || !c->handshake_valid_signature)
    {
        logger(LOG_ERR,
            "%s: Received HANDSHAKE_END but no handshake is in progress",
            c->addrw);
        return false;
    }

    // This should never happen
    if (!c->recv_cipher_next) {
        logger(LOG_CRIT,
            "%s: Received HANDSHAKE_END but there is no recv_cipher_next",
            c->addrw);
        return false;
    }

    // Start using the new recv cipher stored in c->recv_cipher_next
    logger_debug(DBG_HANDSHAKE, "%s: Rotating recv cipher", c->addrw);
    cipher_free(c->recv_cipher);
    c->recv_cipher = c->recv_cipher_next;
    c->recv_cipher_next = NULL;

    // The handshake is now over
    client_finish_handshake(c);

    return true;
}
