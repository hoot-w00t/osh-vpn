#include "node.h"
#include "logger.h"

bool oshpacket_handler_stateexg_end(client_t *c,
    __attribute__((unused)) node_id_t *src,
    __attribute__((unused)) oshpacket_hdr_t *hdr,
    __attribute__((unused)) void *payload)
{
    logger_debug(DBG_STATEEXG, "%s: %s: Finished state exchange",
        c->addrw, c->id->name);
    c->state_exg = false;
    return true;
}
