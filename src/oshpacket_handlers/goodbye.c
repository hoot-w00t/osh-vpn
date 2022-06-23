#include "node.h"
#include "logger.h"

bool oshpacket_handler_goodbye_unauth(client_t *c,
    __attribute__((unused)) oshpacket_hdr_t *hdr,
    __attribute__((unused)) void *payload)
{
    logger(LOG_INFO, "%s: Gracefully disconnecting", c->addrw);
    return false;
}

bool oshpacket_handler_goodbye(client_t *c,
    __attribute__((unused)) node_id_t *src,
    __attribute__((unused)) oshpacket_hdr_t *hdr,
    __attribute__((unused)) void *payload)
{
    logger(LOG_INFO, "%s: %s: Gracefully disconnecting",
        c->addrw, c->id->name);
    return false;
}
