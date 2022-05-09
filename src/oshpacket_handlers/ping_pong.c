#include "node.h"
#include "logger.h"

bool oshpacket_handler_ping(node_t *node,
    __attribute__((unused)) node_id_t *src,
    __attribute__((unused)) oshpacket_hdr_t *hdr,
    __attribute__((unused)) void *payload)
{
    return node_queue_pong(node);
}

bool oshpacket_handler_pong(node_t *node,
    __attribute__((unused)) node_id_t *src,
    __attribute__((unused)) oshpacket_hdr_t *hdr,
    __attribute__((unused)) void *payload)
{
    if (!node->rtt_await) {
        logger(LOG_WARN, "%s: %s: Received unexpected PONG",
            node->addrw, node->id->name);
        return true;
    }

    oshd_gettime(&node->rtt_pong);
    timespecsub(&node->rtt_pong, &node->rtt_ping, &node->rtt_delta);
    node->rtt = (node->rtt_delta.tv_sec * 1000) + (node->rtt_delta.tv_nsec / 1000000);
    node->rtt_await = false;
    logger_debug(DBG_SOCKETS, "%s: %s: RTT %ims", node->addrw, node->id->name, node->rtt);
    return true;
}