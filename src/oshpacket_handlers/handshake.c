#include "oshd.h"
#include "logger.h"
#include <stdlib.h>
#include <string.h>

// Copy the remote node's handshake packet to signature data and fill up the
// initiator/receiver names and public keys
static void handshake_copy_to_sig_data(client_t *c, const oshpacket_handshake_t *handshake)
{
    const node_id_t *me = node_id_find_local();
    const node_id_t *nid_initiator;
    const node_id_t *nid_receiver;
    oshpacket_handshake_t *remote_handshake;

    if (c->initiator) {
        nid_initiator = me;
        nid_receiver = c->handshake_id;
        remote_handshake = &c->handshake_sig_data->receiver_handshake;
    } else {
        nid_initiator = c->handshake_id;
        nid_receiver = me;
        remote_handshake = &c->handshake_sig_data->initiator_handshake;
    }

    // Copy the remote node's handshake packet
    logger_debug(DBG_HANDSHAKE, "%s: Copying %s to signature data",
        c->addrw, "remote handshake");
    memcpy(remote_handshake, handshake, sizeof(*handshake));

    // Copy the nodes' names and public keys
    logger_debug(DBG_HANDSHAKE, "%s: Copying %s to signature data",
        c->addrw, "initiator ID");
    memcpy(c->handshake_sig_data->initiator_name, nid_initiator->name, NODE_NAME_SIZE);
    memcpy(c->handshake_sig_data->initiator_pubkey, nid_initiator->pubkey_raw, HANDSHAKE_PUBKEY_SIZE);

    logger_debug(DBG_HANDSHAKE, "%s: Copying %s to signature data",
        c->addrw, "receiver ID");
    memcpy(c->handshake_sig_data->receiver_name, nid_receiver->name, NODE_NAME_SIZE);
    memcpy(c->handshake_sig_data->receiver_pubkey, nid_receiver->pubkey_raw, HANDSHAKE_PUBKEY_SIZE);

    // The handshake signature data is now fully initialized
    c->handshake_sig_data_complete = true;
}

// Sign the client's handshake_sig_data using the daemon's private key
// The signature is copied to *sig
static bool handshake_sign_data(const client_t *c, uint8_t *sig, size_t sig_size)
{
    uint8_t *tmp_sig = NULL;
    size_t tmp_sig_size;

    logger_debug(DBG_HANDSHAKE, "%s: Signing handshake signature data", c->addrw);
    if (!pkey_sign(oshd.privkey,
            c->handshake_sig_data, sizeof(oshpacket_handshake_sig_data_t),
            &tmp_sig, &tmp_sig_size))
    {
        logger(LOG_ERR, "%s: Failed to sign handshake signature data", c->addrw);
        return false;
    }

    if (tmp_sig_size != sig_size) {
        logger(LOG_ERR, "%s: Invalid handshake signature size (%zu but expected %zu)",
            c->addrw, tmp_sig_size, sig_size);
        free(tmp_sig);
        return false;
    }

    memcpy(sig, tmp_sig, HANDSHAKE_SIG_SIZE);
    free(tmp_sig);
    return true;
}

// Finish handshake signature data initialization (remote handshake + IDs), sign
// it with the daemon's private key and queue HANDSHAKE_SIG
// The handshake signature data is already allocated and initialized by the
// client_queue_handshake() function, which copies our local handshake packet
static bool queue_handshakes_signature(client_t *c, const oshpacket_handshake_t *handshake)
{
    const node_id_t *me = node_id_find_local();
    oshpacket_handshake_sig_t sig_packet;

    // Make sure both nodes have a valid public key, this should never fail
    if (   !me->pubkey_raw
        ||  me->pubkey_raw_size != HANDSHAKE_PUBKEY_SIZE
        || !c->handshake_id->pubkey_raw
        ||  c->handshake_id->pubkey_raw_size != HANDSHAKE_PUBKEY_SIZE)
    {
        logger(LOG_ERR, "%s: Handshake failed: Invalid public keys", c->addrw);
        return false;
    }

    // Copy the remaining handshake data and sign it
    handshake_copy_to_sig_data(c, handshake);
    if (!handshake_sign_data(c, sig_packet.sig, sizeof(sig_packet.sig)))
        return false;

    // Finally send the signature
    logger_debug(DBG_HANDSHAKE, "%s: Queuing handshake signature", c->addrw);
    return client_queue_packet_direct(c, HANDSHAKE_SIG,
        &sig_packet, sizeof(sig_packet));
}

bool oshpacket_handler_handshake(client_t *c, oshpacket_t *pkt)
{
    const oshpacket_handshake_t *handshake = (const oshpacket_handshake_t *) pkt->payload;

    // If we have a recv_cipher_next already, another handshake was already
    // processed but we are still waiting for the HANDSHAKE_SIG packet from
    // the other node
    if (c->recv_cipher_next) {
        logger(LOG_ERR,
            "%s: Received another handshake before the previous was complete",
            c->addrw);
        return false;
    }

    // Reject additional handshakes before authentication
    if (!c->authenticated && (c->recv_cipher || c->send_cipher)) {
        logger(LOG_ERR,
            "%s: Received another handshake before authentication (%s)",
            c->addrw, "ciphers");
        return false;
    }
    if (c->handshake_id) {
        logger(LOG_ERR,
            "%s: Received another handshake before authentication (%s)",
            c->addrw, "handshake id");
        return false;
    }

    // Find the other node's ID (or the one it pretends to be)
    logger_debug(DBG_HANDSHAKE, "%s: Looking up remote node ID by hash", c->addrw);
    c->handshake_id = node_id_find_by_hash(handshake->sender.id_hash,
        handshake->sender.id_salt, sizeof(handshake->sender.id_salt));

    if (!c->handshake_id) {
        logger(LOG_ERR,
            "%s: Handshake failed: Unknown remote node (name and/or public key)",
            c->addrw);
        return false;
    }

    logger_debug(DBG_HANDSHAKE, "%s: The remote node pretends to be %s",
        c->addrw, c->handshake_id->name);

    // Prevent internal connections
    if (c->handshake_id->local_node) {
        logger(LOG_ERR, "%s: Handshake failed: The remote node is myself", c->addrw);
        return false;
    }

    // If the node's public key is not trusted, fail early as the signature
    // verification will fail later
    if (!c->handshake_id->pubkey_local && !oshd.remote_auth) {
        logger(LOG_ERR, "%s: Handshake failed: No trusted public key for %s",
            c->addrw, c->handshake_id->name);
        return false;
    }

    // If no handshake is currently in progress it means that the other node
    // initiated it, we have to initiate it on our side too
    if (!c->handshake_in_progress) {
        if (!client_queue_handshake(c))
            return false;
    }

    // Sign the handshakes and send the signature
    // The handshake will finish after we receive and can verify the other
    // node's signature
    return queue_handshakes_signature(c, handshake);
}

bool oshpacket_handler_handshake_auth(
    client_t *c,
    __attribute__((unused)) node_id_t *src,
    oshpacket_t *pkt)
{
    return oshpacket_handler_handshake(c, pkt);
}
