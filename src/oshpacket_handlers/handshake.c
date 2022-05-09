#include "node.h"
#include "logger.h"
#include "xalloc.h"
#include "events.h"
#include "crypto/hash.h"
#include <stdlib.h>
#include <string.h>

bool oshpacket_handler_handshake(node_t *node, __attribute__((unused)) oshpacket_hdr_t *hdr,
    void *payload)
{
    const oshpacket_handshake_t *handshake = (const oshpacket_handshake_t *) payload;

    // If we have a recv_cipher_next already, another handshake was already
    // processed but we are still waiting for the HANDSHAKE_END packet from
    // the other node
    if (node->recv_cipher_next) {
        logger(LOG_ERR,
            "%s: Received HANDSHAKE but another one is in progress",
            node->addrw);
        return false;
    }

    // Reject additional handshakes before authentication
    if ((node->recv_cipher || node->send_cipher) && !node->authenticated) {
        logger(LOG_ERR, "%s: Received another handshake before authentication",
            node->addrw);
        return false;
    }

    // If no HANDSHAKE is currently in progress it means the other node
    // initiated it, we have to initiate it on our side too to be able to
    // process it
    if (!node->handshake_in_progress) {
        if (!node_queue_handshake(node))
            return false;
    }

    // If the remote node is authenticated, we can verify the keys' signature
    // now, otherwise we copy them to a temporary buffer and the verification
    // will happen right after authentication
    // The keys must always be signed to prevent MITM attacks
    if (node->authenticated) {
        if (!pkey_verify(node->id->pubkey,
                handshake->keys.both, sizeof(handshake->keys.both),
                handshake->sig, sizeof(handshake->sig)))
        {
            logger(LOG_ERR, "%s: %s: Handshake signature verification failed",
                    node->addrw, node->id->name);
            return false;
        }
        logger_debug(DBG_HANDSHAKE, "%s: %s: Valid handshake signature",
            node->addrw, node->id->name);
    } else {
        logger_debug(DBG_HANDSHAKE,
            "%s: Keeping unauthenticated handshake packet for verification",
            node->addrw);
        node->unauth_handshake = xmemdup(handshake, sizeof(oshpacket_handshake_t));
    }

    // Load the remote node's public keys
    logger_debug(DBG_HANDSHAKE, "%s: Loading the remote node's public keys", node->addrw);
    EVP_PKEY *r_send_pubkey = pkey_load_x25519_pubkey(handshake->keys.k.send,
        sizeof(handshake->keys.k.send));
    EVP_PKEY *r_recv_pubkey = pkey_load_x25519_pubkey(handshake->keys.k.recv,
        sizeof(handshake->keys.k.recv));

    if (!r_send_pubkey || !r_recv_pubkey) {
        pkey_free(r_send_pubkey);
        pkey_free(r_recv_pubkey);
        logger(LOG_ERR, "%s: Handshake failed: Failed to load public keys", node->addrw);
        return false;
    }

    // Calculate the shared secret for both keys
    // Each node sends its own send_pubkey and recv_pubkey, so in order to link
    // them correctly we need to calculate our own send key with the other
    // node's recv key, the same applies for our recv key
    uint8_t *send_secret;
    uint8_t *recv_secret;
    size_t send_secret_size;
    size_t recv_secret_size;
    bool secret_success = true;

    logger_debug(DBG_HANDSHAKE, "%s: Computing send_secret", node->addrw);
    if (pkey_derive(node->send_key, r_recv_pubkey, &send_secret, &send_secret_size)) {
        logger_debug(DBG_HANDSHAKE, "%s: Computing recv_secret", node->addrw);
        if (!pkey_derive(node->recv_key, r_send_pubkey, &recv_secret, &recv_secret_size)) {
            secret_success = false;
            free(send_secret);
        }
    } else {
        secret_success = false;
    }

    // We no longer need the public keys now
    pkey_free(node->send_key);
    pkey_free(node->recv_key);
    node->send_key = NULL;
    node->recv_key = NULL;
    pkey_free(r_send_pubkey);
    pkey_free(r_recv_pubkey);

    // All the above if statements are here to prevent memory leaks
    if (!secret_success) {
        logger(LOG_ERR, "%s: Handshake failed: Failed to compute secrets",
            node->addrw);
        return false;
    }

    // We now calculate the SHA3-512 hashes of the two secrets which we will use
    // to create the keys and IV of our ciphers
    uint8_t send_hash[EVP_MAX_MD_SIZE];
    uint8_t recv_hash[EVP_MAX_MD_SIZE];
    unsigned int send_hash_size;
    unsigned int recv_hash_size;

    logger_debug(DBG_HANDSHAKE, "%s: Hashing shared secrets", node->addrw);
    if (   !hash_sha3_512(send_secret, send_secret_size, send_hash, &send_hash_size)
        || !hash_sha3_512(recv_secret, recv_secret_size, recv_hash, &recv_hash_size))
    {
        free(send_secret);
        free(recv_secret);
        logger(LOG_ERR, "%s: Handshake failed: Failed to hash secrets",
            node->addrw);
        return false;
    }
    free(send_secret);
    free(recv_secret);

    // Create the send/recv ciphers using the two hashes
    logger_debug(DBG_HANDSHAKE, "%s: Creating send_cipher", node->addrw);
    cipher_t *new_send_cipher = cipher_create_aes_256_gcm(
            true, send_hash, 32, send_hash + 32, 12);

    logger_debug(DBG_HANDSHAKE, "%s: Creating recv_cipher", node->addrw);
    cipher_t *new_recv_cipher = cipher_create_aes_256_gcm(
            false, recv_hash, 32, recv_hash + 32, 12);

    if (!new_send_cipher || !new_recv_cipher) {
        logger(LOG_ERR, "%s: Handshake failed: Failed to create ciphers",
            node->addrw);
        cipher_free(new_send_cipher);
        cipher_free(new_recv_cipher);
        return false;
    }

    // If we don't have any ciphers yet we will use the ones we just generated
    // But if we do, we will have to send a HANDSHAKE_END packet to indicate
    // that all packets we send after this one will use the new send cipher
    // We will then also have to wait until we receive the HANDSHAKE_END packet
    // from the other node before using the new recv cipher
    // This allows us to renew the encryption keys without disrupting
    // communications
    if (node->send_cipher && node->recv_cipher) {
        // Ciphers were in use before

        // Queue the HANDSHAKE_END packet
        logger_debug(DBG_HANDSHAKE, "%s: Queuing HANDSHAKE_END packet",
            node->addrw);
        if (!node_queue_handshake_end(node)) {
            free(new_send_cipher);
            free(new_recv_cipher);
            return false;
        }

        // Start using the new send cipher immediately
        logger_debug(DBG_HANDSHAKE, "%s: Replacing old send cipher with the new one",
            node->addrw);
        cipher_free(node->send_cipher);
        node->send_cipher = new_send_cipher;

        // Keep the new recv cipher on the side for now
        logger_debug(DBG_HANDSHAKE, "%s: Storing new recv cipher", node->addrw);
        node->recv_cipher_next = new_recv_cipher;
    } else {
        // No ciphers were in use before
        logger_debug(DBG_HANDSHAKE, "%s: Using both ciphers immediately",
            node->addrw);

        // This is basically a no-op because both ciphers should be NULL, but
        // just in case one isn't
        cipher_free(node->send_cipher);
        cipher_free(node->recv_cipher);

        // We start using our ciphers immediately
        node->send_cipher = new_send_cipher;
        node->recv_cipher = new_recv_cipher;

        // The handshake is over
        node->handshake_in_progress = false;
    }

    // After the initial handshake we want to renew the encryption keys
    // regularly
    // The function will re-queue the event if it already exists
    event_queue_handshake_renew(node);

    // After the first handshake we should be unauthenticated and will start
    // the authentication process
    if (!node->handshake_in_progress && !node->authenticated)
        return node_queue_hello_challenge(node);

    return true;
}

bool oshpacket_handler_handshake_auth(
    node_t *node, __attribute__((unused)) node_id_t *src,
    oshpacket_hdr_t *hdr, void *payload)
{
    return oshpacket_handler_handshake(node, hdr, payload);
}

bool oshd_process_handshake_end(node_t *node,
    __attribute__((unused)) node_id_t *src,
    __attribute__((unused)) oshpacket_hdr_t *hdr,
    __attribute__((unused)) void *payload)
{
    // If the handshake is not in progress we can't process this
    if (!node->handshake_in_progress) {
        logger(LOG_ERR, "%s: Received HANDSHAKE_END but no handshake is in progress",
            node->addrw);
        return false;
    }

    // This shouldn't happen but in the case where there is no
    // recv_cipher_next, we fail safely
    if (!node->recv_cipher_next) {
        logger(LOG_CRIT, "%s: Received HANDSHAKE_END but there is no recv_cipher_next",
            node->addrw);
        return false;
    }

    // We can start using the next recv cipher stored in node->recv_cipher_next
    logger_debug(DBG_HANDSHAKE, "%s: Replacing old recv cipher with the new one",
        node->addrw);
    cipher_free(node->recv_cipher);
    node->recv_cipher = node->recv_cipher_next;
    node->recv_cipher_next = NULL;

    // The handshake is now over
    node->handshake_in_progress = false;

    return true;
}