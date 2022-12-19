#include "node.h"
#include "logger.h"
#include <string.h>

bool oshpacket_handler_pubkey(
    client_t *c,
    __attribute__((unused)) node_id_t *src,
    oshpacket_t *pkt)
{
    const size_t count = pkt->payload_size / sizeof(oshpacket_pubkey_t);
    const oshpacket_pubkey_t *pubkeys = (const oshpacket_pubkey_t *) pkt->payload;
    char node_name[NODE_NAME_SIZE + 1];
    memset(node_name, 0, sizeof(node_name));

    for (size_t i = 0; i < count; ++i) {
        memcpy(node_name, pubkeys[i].node_name, NODE_NAME_SIZE);
        if (!node_valid_name(node_name)) {
            logger(LOG_ERR, "%s: %s: Public key: Invalid name", c->addrw,
                c->id->name);
            return false;
        }

        node_id_t *id = node_id_find(node_name);

        if (!id) {
            logger(LOG_ERR, "%s: %s: Public key: Unknown node: %s",
                c->addrw, c->id->name, node_name);
            return false;
        }

        logger_debug(DBG_HANDSHAKE, "%s: %s: Loading public key for %s",
            c->addrw, c->id->name, node_name);
        if (!node_id_set_pubkey(id, pubkeys[i].node_pubkey,
                sizeof(pubkeys[i].node_pubkey)))
        {
            logger(LOG_ERR, "%s: %s: Failed to load public key for %s",
                c->addrw, c->id->name, node_name);
            return false;
        }
    }

    return true;
}
