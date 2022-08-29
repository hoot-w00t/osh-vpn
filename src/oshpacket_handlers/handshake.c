#include "oshd.h"
#include "logger.h"
#include "events.h"
#include "crypto/hash.h"
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

// Load remote node's ECDH public keys
static bool handshake_load_ecdh_pubkeys(client_t *c, const oshpacket_handshake_t *handshake,
    EVP_PKEY **send_pubkey, EVP_PKEY **recv_pubkey)
{
    logger_debug(DBG_HANDSHAKE, "%s: Loading remote public ECDH keys", c->addrw);
    *send_pubkey = pkey_load_x25519_pubkey(handshake->ecdh_keys.send,
        sizeof(handshake->ecdh_keys.send));
    *recv_pubkey = pkey_load_x25519_pubkey(handshake->ecdh_keys.recv,
        sizeof(handshake->ecdh_keys.recv));

    if (*send_pubkey == NULL || *recv_pubkey == NULL) {
        logger(LOG_ERR, "%s: Handshake failed: Failed to load remote ECDH public keys", c->addrw);
        pkey_free(*send_pubkey);
        pkey_free(*recv_pubkey);
        return false;
    }

    return true;
}

bool oshpacket_handler_handshake(client_t *c, __attribute__((unused)) oshpacket_hdr_t *hdr,
    void *payload)
{
    const oshpacket_handshake_t *handshake = (const oshpacket_handshake_t *) payload;

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

    // Load the remote node's public keys
    EVP_PKEY *r_send_pubkey;
    EVP_PKEY *r_recv_pubkey;

    if (!handshake_load_ecdh_pubkeys(c, handshake, &r_send_pubkey, &r_recv_pubkey))
        return false;

    // Calculate the shared secret for both keys
    // Each node sends its own send_pubkey and recv_pubkey, so in order to link
    // them correctly we need to calculate our own send key with the other
    // node's recv key, the same applies for our recv key
    uint8_t *send_secret;
    uint8_t *recv_secret;
    size_t send_secret_size;
    size_t recv_secret_size;
    bool secret_success = true;

    logger_debug(DBG_HANDSHAKE, "%s: Computing send_secret", c->addrw);
    if (pkey_derive(c->send_key, r_recv_pubkey, &send_secret, &send_secret_size)) {
        logger_debug(DBG_HANDSHAKE, "%s: Computing recv_secret", c->addrw);
        if (!pkey_derive(c->recv_key, r_send_pubkey, &recv_secret, &recv_secret_size)) {
            secret_success = false;
            free(send_secret);
        }
    } else {
        secret_success = false;
    }

    // We no longer need the public keys now
    pkey_free(c->send_key);
    pkey_free(c->recv_key);
    c->send_key = NULL;
    c->recv_key = NULL;
    pkey_free(r_send_pubkey);
    pkey_free(r_recv_pubkey);

    // All the above if statements are here to prevent memory leaks
    if (!secret_success) {
        logger(LOG_ERR, "%s: Handshake failed: Failed to compute secrets",
            c->addrw);
        return false;
    }

    // We now calculate the SHA3-512 hashes of the two secrets which we will use
    // to create the keys and IV of our ciphers
    uint8_t send_hash[EVP_MAX_MD_SIZE];
    uint8_t recv_hash[EVP_MAX_MD_SIZE];
    unsigned int send_hash_size;
    unsigned int recv_hash_size;

    logger_debug(DBG_HANDSHAKE, "%s: Hashing shared secrets", c->addrw);
    if (   !hash_sha3_512(send_secret, send_secret_size, send_hash, &send_hash_size)
        || !hash_sha3_512(recv_secret, recv_secret_size, recv_hash, &recv_hash_size))
    {
        free(send_secret);
        free(recv_secret);
        logger(LOG_ERR, "%s: Handshake failed: Failed to hash secrets",
            c->addrw);
        return false;
    }
    free(send_secret);
    free(recv_secret);

    // Create the send/recv ciphers using the two hashes
    logger_debug(DBG_HANDSHAKE, "%s: Creating send_cipher", c->addrw);
    cipher_t *new_send_cipher = cipher_create_aes_256_gcm(
            true, send_hash, 32, send_hash + 32, 12);

    logger_debug(DBG_HANDSHAKE, "%s: Creating recv_cipher", c->addrw);
    cipher_t *new_recv_cipher = cipher_create_aes_256_gcm(
            false, recv_hash, 32, recv_hash + 32, 12);

    if (!new_send_cipher || !new_recv_cipher) {
        logger(LOG_ERR, "%s: Handshake failed: Failed to create ciphers",
            c->addrw);
        cipher_free(new_send_cipher);
        cipher_free(new_recv_cipher);
        return false;
    }

    // If we don't have any ciphers yet we will use the ones we just generated
    // But if we do, we will have to wait until we receive the HANDSHAKE_SIG
    // packet from the other node before using the new recv cipher, as it will
    // be the last packet sent using the old recv cipher
    // This allows us to renew the encryption keys without disrupting
    // communications
    if (c->send_cipher && c->recv_cipher) {
        // Ciphers were in use before

        // Send the signature now with the old send cipher before replacing it
        if (!queue_handshakes_signature(c, handshake))
            return false;

        // Start using the new send cipher immediately
        logger_debug(DBG_HANDSHAKE, "%s: Replacing old send cipher with the new one",
            c->addrw);
        cipher_free(c->send_cipher);
        c->send_cipher = new_send_cipher;

        // Keep the new recv cipher on the side for now
        logger_debug(DBG_HANDSHAKE, "%s: Storing new recv cipher", c->addrw);
        c->recv_cipher_next = new_recv_cipher;
    } else {
        // No ciphers were in use before
        logger_debug(DBG_HANDSHAKE, "%s: Using both ciphers immediately",
            c->addrw);

        // This is basically a no-op because both ciphers should be NULL, but
        // just in case one isn't
        cipher_free(c->send_cipher);
        cipher_free(c->recv_cipher);

        // We start using our ciphers immediately
        c->send_cipher = new_send_cipher;
        c->recv_cipher = new_recv_cipher;

        // Send the signature now that we have setup the ciphers
        if (!queue_handshakes_signature(c, handshake))
            return false;
    }

    // After the initial handshake we want to renew the encryption keys
    // regularly
    // The function will re-queue the event if it already exists
    event_queue_handshake_renew(c);

    return true;
}

bool oshpacket_handler_handshake_auth(
    client_t *c, __attribute__((unused)) node_id_t *src,
    oshpacket_hdr_t *hdr, void *payload)
{
    return oshpacket_handler_handshake(c, hdr, payload);
}
