#include "oshd.h"
#include "logger.h"
#include "events.h"
#include "crypto/hkdf.h"
#include <stdlib.h>
#include <string.h>

// Queue a HELLO packet with our authentication result and other options if
// needed
// If the authentication failed this will also fail
static bool queue_hello(client_t *c)
{
    oshpacket_hello_t packet;

    // If we initiated the connection but the remote node is not the one that
    // we were expecting, gracefully disconnect
    if (   c->initiator
        && c->reconnect_nid
        && c->reconnect_nid != c->handshake_id)
    {
        logger(LOG_WARN, "%s: Connected to %s but expected %s",
            c->addrw, c->handshake_id->name, c->reconnect_nid->name);
        return client_queue_goodbye(c);
    }

    logger_debug(DBG_HANDSHAKE, "%s: Creating HELLO packet", c->addrw);
    memset(&packet, 0, sizeof(packet));
    logger_debug(DBG_HANDSHAKE, "%s: Local options 0x%08X", c->addrw, packet.options);
    packet.options = htonl(packet.options);

    logger_debug(DBG_HANDSHAKE, "%s: Queuing HELLO packet", c->addrw);
    return client_queue_packet_direct(c, HELLO, &packet, sizeof(packet));
}

// Load remote node's ECDH public keys
static bool handshake_load_ecdh_pubkey(client_t *c,
    const oshpacket_handshake_t *handshake, EVP_PKEY **ecdh_pubkey)
{
    logger_debug(DBG_HANDSHAKE, "%s: Loading remote public ECDH key", c->addrw);
    *ecdh_pubkey = pkey_load_x25519_pubkey(handshake->ecdh_pubkey,
        sizeof(handshake->ecdh_pubkey));

    if (*ecdh_pubkey == NULL) {
        logger(LOG_ERR, "%s: Handshake failed: %s", c->addrw,
            "Failed to load remote ECDH public key");
        pkey_free(*ecdh_pubkey);
        return false;
    }

    return true;
}

// Load the remote node's public ECDH key and derive the shared secret with our
// own, returns false on error
// The resulting secret is dynamically allocated and placed into *ecdh_secret
static bool handshake_compute_ecdh_secret(client_t *c, uint8_t **ecdh_secret,
    size_t *ecdh_secret_size)
{
    EVP_PKEY *remote_ecdh_pubkey;
    bool success;

    // Load the remote node's public ECDH key
    if (!handshake_load_ecdh_pubkey(c,
            c->initiator ? &c->handshake_sig_data->receiver_handshake
                         : &c->handshake_sig_data->initiator_handshake,
            &remote_ecdh_pubkey))
    {
        return false;
    }

    logger_debug(DBG_HANDSHAKE, "%s: Computing ECDH secret", c->addrw);
    success = pkey_derive(c->ecdh_key, remote_ecdh_pubkey,
        ecdh_secret, ecdh_secret_size);

    // We no longer need the ECDH keys now
    pkey_free(remote_ecdh_pubkey);
    pkey_free(c->ecdh_key);
    c->ecdh_key = NULL;

    return success;
}

// Derive bytes using HKDF to *hkdf
static bool handshake_compute_hkdf(const client_t *c, const void *secret,
    size_t secret_size, handshake_hkdf_keys_t *hkdf)
{
    char label_initiator_name[NODE_NAME_SIZE + 1];
    char label_receiver_name[NODE_NAME_SIZE + 1];
    char label[16 + (NODE_NAME_SIZE * 2) + 1];
    uint8_t salt[HANDSHAKE_NONCE_SIZE * 2];

    memset(hkdf, 0, sizeof(*hkdf));

    // TODO: Consider using the nonces in the label instead of the salt
    logger_debug(DBG_HANDSHAKE, "%s: HKDF: Initializing label", c->addrw);
    memset(label_initiator_name, 0, sizeof(label_initiator_name));
    memset(label_receiver_name, 0, sizeof(label_receiver_name));
    memcpy(label_initiator_name, c->handshake_sig_data->initiator_name, NODE_NAME_SIZE);
    memcpy(label_receiver_name,  c->handshake_sig_data->receiver_name,  NODE_NAME_SIZE);
    snprintf(label, sizeof(label), "osh client %s %s",
        label_initiator_name, label_receiver_name);

    logger_debug(DBG_HANDSHAKE, "%s: HKDF: Initializing salt", c->addrw);
    memcpy(salt + 0,                    c->handshake_sig_data->initiator_handshake.nonce, HANDSHAKE_NONCE_SIZE);
    memcpy(salt + HANDSHAKE_NONCE_SIZE, c->handshake_sig_data->receiver_handshake.nonce,  HANDSHAKE_NONCE_SIZE);

    logger_debug(DBG_HANDSHAKE, "%s: HKDF: Deriving %zu bytes", c->addrw, sizeof(*hkdf));
    return hkdf_derive(secret, secret_size, salt, sizeof(salt),
        label, strlen(label), hkdf, sizeof(*hkdf));
}

// Create the send/recv ciphers from the HKDF secret keys
static bool handshake_create_ciphers(const client_t *c, const handshake_hkdf_keys_t *hkdf,
    cipher_t **send_cipher, cipher_t **recv_cipher)
{
    logger_debug(DBG_HANDSHAKE, "%s: Creating ciphers", c->addrw);

    if (c->initiator) {
        *send_cipher = cipher_create_aes_256_gcm(true,
            hkdf->initiator_cipher_key, sizeof(hkdf->initiator_cipher_key),
            hkdf->initiator_cipher_iv,  sizeof(hkdf->initiator_cipher_iv));
        *recv_cipher = cipher_create_aes_256_gcm(false,
            hkdf->receiver_cipher_key, sizeof(hkdf->receiver_cipher_key),
            hkdf->receiver_cipher_iv,  sizeof(hkdf->receiver_cipher_iv));
    } else {
        *send_cipher = cipher_create_aes_256_gcm(true,
            hkdf->receiver_cipher_key, sizeof(hkdf->receiver_cipher_key),
            hkdf->receiver_cipher_iv,  sizeof(hkdf->receiver_cipher_iv));
        *recv_cipher = cipher_create_aes_256_gcm(false,
            hkdf->initiator_cipher_key, sizeof(hkdf->initiator_cipher_key),
            hkdf->initiator_cipher_iv,  sizeof(hkdf->initiator_cipher_iv));
    }

    if (*send_cipher == NULL || *recv_cipher == NULL) {
        logger(LOG_ERR, "%s: Handshake failed: %s",
            c->addrw, "Failed to create ciphers");
        cipher_free(*send_cipher);
        cipher_free(*recv_cipher);
        return false;
    }

    return true;
}

// Use the handshakes in c->handshake_sig_data to setup new encryption ciphers
// for this client
// This function does ECDH, HKDF and cipher rotation
static bool handshake_setup_new_ciphers(client_t *c)
{
    uint8_t *ecdh_secret;
    size_t ecdh_secret_size;
    handshake_hkdf_keys_t hkdf;
    bool hkdf_success;
    cipher_t *new_send_cipher;
    cipher_t *new_recv_cipher;

    // Calculate the shared secret
    if (!handshake_compute_ecdh_secret(c, &ecdh_secret, &ecdh_secret_size)) {
        logger(LOG_ERR, "%s: Handshake failed: %s", c->addrw,
            "Failed to compute ECDH secret");
        return false;
    }

    // Derive secret bytes
    hkdf_success = handshake_compute_hkdf(c, ecdh_secret, ecdh_secret_size, &hkdf);
    free(ecdh_secret);

    if (!hkdf_success) {
        logger(LOG_ERR, "%s: Handshake failed: %s",
            c->addrw, "HKDF failed");
        return false;
    }

    // Create the ciphers
    if (!handshake_create_ciphers(c, &hkdf, &new_send_cipher, &new_recv_cipher))
        return false;

    // Start using the new ciphers
    // There are two possibilites:
    // - This is the initial handshake, no ciphers were in use before so we will
    //   start using both right away
    //
    // - This is an intermediate handshake, ciphers are already in use so we
    //   need to rotate them without disrupting
    //   We will send a HANDSHAKE_END packet encrypted using the old send cipher
    //   and then use the new send cipher, it marks the end of the old cipher
    //   We will keep the new recv cipher in a variable and we will start using
    //   it when we receive the other node's HANDSHAKE_END packet

    if (c->send_cipher && c->recv_cipher) {
        // Ciphers were in use before

        // Send the HANDSHAKE_END
        if (!client_queue_packet_empty(c, HANDSHAKE_END))
            return false;

        // Start using the new send cipher immediately
        logger_debug(DBG_HANDSHAKE, "%s: Rotating send cipher", c->addrw);
        cipher_free(c->send_cipher);
        c->send_cipher = new_send_cipher;

        // Keep the new recv cipher on the side for now
        c->recv_cipher_next = new_recv_cipher;
    } else {
        // No ciphers were in use before
        logger_debug(DBG_HANDSHAKE, "%s: Using both ciphers now", c->addrw);

        // This is basically a no-op because both ciphers should be NULL, but
        // just in case one isn't
        cipher_free(c->send_cipher);
        cipher_free(c->recv_cipher);

        // We start using our ciphers immediately
        c->send_cipher = new_send_cipher;
        c->recv_cipher = new_recv_cipher;
    }

    return true;
}

bool oshpacket_handler_handshake_sig(client_t *c,
    __attribute__((unused)) oshpacket_hdr_t *hdr, void *payload)
{
    const oshpacket_handshake_sig_t *sig_packet = (const oshpacket_handshake_sig_t *) payload;

    // If the handshake is not in progress we can't process this signature
    if (   !c->handshake_in_progress
        || !c->handshake_id
        || !c->handshake_sig_data)
    {
        logger(LOG_ERR, "%s: Received unexpected %s: %s",
            c->addrw, "HANDSHAKE_SIG", "No handshake is in progress");
        return false;
    }

    // If the signature data is not filled in we received a signature before the
    // remote node's handshake
    if (!c->handshake_sig_data_complete) {
        logger(LOG_ERR, "%s: Received unexpected %s: %s",
            c->addrw, "HANDSHAKE_SIG", "Handshake is incomplete");
        return false;
    }

    // Make sure that the remote node has a public key
    if (!c->handshake_id->pubkey) {
        logger(LOG_ERR, "%s: Handshake failed: %s", c->addrw, "No public key");
        return false;
    }

    // Make sure that the remote node's public key is trusted
    // We must verify it here even if this check is redundant
    if (!c->handshake_id->pubkey_local && !oshd.remote_auth) {
        logger(LOG_ERR, "%s: Handshake failed: %s", c->addrw, "No trusted public key");
        return false;
    }

    // Verify the handshake signature
    logger_debug(DBG_HANDSHAKE, "%s: %s has a %s public key",
        c->addrw, c->handshake_id->name,
        c->handshake_id->pubkey_local ? "local" : "remote");

    c->handshake_valid_signature = pkey_verify(c->handshake_id->pubkey,
        c->handshake_sig_data, sizeof(oshpacket_handshake_sig_data_t),
        sig_packet->sig, sizeof(sig_packet->sig));

    // If the signature verification failed, this connection cannot be trusted
    if (!c->handshake_valid_signature) {
        logger(LOG_ERR, "%s: Handshake failed: %s",
            c->addrw, "Signature verification failed");
        return false;
    }

    logger_debug(DBG_HANDSHAKE, "%s: Valid signature from %s",
        c->addrw, c->handshake_id->name);

    // The remote node has proven its identity, we can now create and use the
    // encryption ciphers
    if (!handshake_setup_new_ciphers(c)) {
        logger(LOG_ERR, "%s: Handshake failed: %s",
            c->addrw, "Failed to setup encryption ciphers");
        return false;
    }

    // Renew the encryption keys after a while
    event_queue_handshake_renew(c);

    // If this is the first handshake, we can finalize the authentication
    // Otherwise this step is already done and the handshake is only renewing
    // the encryption keys
    if (c->authenticated) {
        // If we are already authenticated, this handshake is only renewing the
        // encryption keys, it will be finished after receiving the other
        // node's HANDSHAKE_END packet
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
