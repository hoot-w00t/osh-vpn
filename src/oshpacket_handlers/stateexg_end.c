#include "node.h"
#include "logger.h"

bool oshpacket_handler_stateexg_end(node_t *node,
    __attribute__((unused)) node_id_t *src,
    __attribute__((unused)) oshpacket_hdr_t *hdr,
    __attribute__((unused)) void *payload)
{
    logger_debug(DBG_STATEEXG, "%s: %s: Finished state exchange",
        node->addrw, node->id->name);
    node->state_exg = false;
    return true;
}