#include "node.h"
#include "logger.h"

bool oshpacket_handler_goodbye_unauth(node_t *node,
    __attribute__((unused)) oshpacket_hdr_t *hdr,
    __attribute__((unused)) void *payload)
{
    logger(LOG_INFO, "%s: Gracefully disconnecting", node->addrw);
    return false;
}

bool oshpacket_handler_goodbye(node_t *node,
    __attribute__((unused)) node_id_t *src,
    __attribute__((unused)) oshpacket_hdr_t *hdr,
    __attribute__((unused)) void *payload)
{
    logger(LOG_INFO, "%s: %s: Gracefully disconnecting",
        node->addrw, node->id->name);
    return false;
}