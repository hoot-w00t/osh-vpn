#ifndef _OSH_OSHPACKET_HANDLERS_H
#define _OSH_OSHPACKET_HANDLERS_H

#include "oshpacket.h"

// Functions defined under src/oshpacket_handlers/

// data.c
bool oshpacket_handler_data(node_t *node, node_id_t *src,
    oshpacket_hdr_t *hdr, void *payload);

// devmode.c
bool oshpacket_handler_devmode(node_t *node, node_id_t *src,
    oshpacket_hdr_t *hdr, void *payload);

// edge.c
bool oshpacket_handler_edge_add(node_t *node, node_id_t *src,
    oshpacket_hdr_t *hdr, void *payload);
bool oshpacket_handler_edge_del(node_t *node, node_id_t *src,
    oshpacket_hdr_t *hdr, void *payload);

// endpoint.c
bool oshpacket_handler_endpoint(node_t *node, node_id_t *src,
    oshpacket_hdr_t *hdr, void *payload);

// goodbye.c
bool oshpacket_handler_goodbye_unauth(node_t *node,
    oshpacket_hdr_t *hdr, void *payload);
bool oshpacket_handler_goodbye(node_t *node, node_id_t *src,
    oshpacket_hdr_t *hdr, void *payload);

// handshake.c
bool oshpacket_handler_handshake(node_t *node,
    oshpacket_hdr_t *hdr, void *payload);
bool oshpacket_handler_handshake_auth(node_t *node, node_id_t *src,
    oshpacket_hdr_t *hdr, void *payload);
bool oshd_process_handshake_end(node_t *node, node_id_t *src,
    oshpacket_hdr_t *hdr, void *payload);

// hello.c
bool oshpacket_handler_hello_challenge(node_t *node, oshpacket_hdr_t *hdr,
    void *payload);
bool oshpacket_handler_hello_response(node_t *node, oshpacket_hdr_t *hdr,
    void *payload);
bool oshpacket_handler_hello_end(node_t *node, oshpacket_hdr_t *hdr,
    void *payload);

// ping_pong.c
bool oshpacket_handler_ping(node_t *node, node_id_t *src,
    oshpacket_hdr_t *hdr, void *payload);
bool oshpacket_handler_pong(node_t *node, node_id_t *src,
    oshpacket_hdr_t *hdr, void *payload);

// pubkey.c
bool oshpacket_handler_pubkey(node_t *node, node_id_t *src,
    oshpacket_hdr_t *hdr, void *payload);

// route.c
bool oshpacket_handler_route(node_t *node, node_id_t *src,
    oshpacket_hdr_t *hdr, void *payload);

// stateexg_end.c
bool oshpacket_handler_stateexg_end(node_t *node, node_id_t *src,
    oshpacket_hdr_t *hdr, void *payload);

#endif