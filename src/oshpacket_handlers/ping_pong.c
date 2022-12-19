#include "node.h"
#include "logger.h"

bool oshpacket_handler_ping(client_t *c,
    __attribute__((unused)) node_id_t *src,
    __attribute__((unused)) oshpacket_t *pkt)
{
    return client_queue_pong(c);
}

bool oshpacket_handler_pong(client_t *c,
    __attribute__((unused)) node_id_t *src,
    __attribute__((unused)) oshpacket_t *pkt)
{
    if (!c->rtt_await) {
        logger(LOG_WARN, "%s: %s: Received unexpected PONG",
            c->addrw, c->id->name);
        return true;
    }

    oshd_gettime(&c->rtt_pong);
    timespecsub(&c->rtt_pong, &c->rtt_ping, &c->rtt_delta);
    c->rtt = (c->rtt_delta.tv_sec * 1000) + (c->rtt_delta.tv_nsec / 1000000);
    c->rtt_await = false;
    logger_debug(DBG_SOCKETS, "%s: %s: RTT %ims", c->addrw, c->id->name, c->rtt);
    return true;
}
