#include "node.h"
#include "logger.h"
#include <string.h>

bool oshpacket_handler_pubkey(
    node_t *node,
    __attribute__((unused)) node_id_t *src,
    oshpacket_hdr_t *hdr,
    void *payload)
{
    if (node->state_exg) {
        // Broadcast the public keys to our end of the network
        logger_debug(DBG_STATEEXG,
            "%s: %s: State exchange: Relaying PUBKEY packet",
            node->addrw, node->id->name);
        node_queue_packet_broadcast(node, PUBKEY, payload,
            hdr->payload_size);
    }

    const size_t count = hdr->payload_size / sizeof(oshpacket_pubkey_t);
    const oshpacket_pubkey_t *pubkeys = (const oshpacket_pubkey_t *) payload;
    char node_name[NODE_NAME_SIZE + 1];
    memset(node_name, 0, sizeof(node_name));

    for (size_t i = 0; i < count; ++i) {
        memcpy(node_name, pubkeys[i].node_name, NODE_NAME_SIZE);
        if (!node_valid_name(node_name)) {
            logger(LOG_ERR, "%s: %s: Public key: Invalid name", node->addrw,
                node->id->name);
            return false;
        }

        node_id_t *id = node_id_find(node_name);

        if (!id) {
            logger(LOG_ERR, "%s: %s: Public key: Unknown node: %s",
                node->addrw, node->id->name, node_name);
            return false;
        }

        logger_debug(DBG_AUTHENTICATION, "%s: %s: Loading public key for %s",
            node->addrw, node->id->name, node_name);
        if (!node_id_set_pubkey(id, pubkeys[i].node_pubkey,
                sizeof(pubkeys[i].node_pubkey)))
        {
            logger(LOG_ERR, "%s: %s: Failed to load public key for %s",
                node->addrw, node->id->name, node_name);
            return false;
        }
    }

    return true;
}