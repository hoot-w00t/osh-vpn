#ifndef _OSH_OSHPACKET_HANDLERS_H
#define _OSH_OSHPACKET_HANDLERS_H

#include "oshpacket.h"

// Functions defined under src/oshpacket_handlers/

// data.c
bool oshpacket_handler_data(client_t *c, node_id_t *src,
    oshpacket_hdr_t *hdr, void *payload);

// devmode.c
bool oshpacket_handler_devmode(client_t *c, node_id_t *src,
    oshpacket_hdr_t *hdr, void *payload);

// edge.c
bool oshpacket_handler_edge_add(client_t *c, node_id_t *src,
    oshpacket_hdr_t *hdr, void *payload);
bool oshpacket_handler_edge_del(client_t *c, node_id_t *src,
    oshpacket_hdr_t *hdr, void *payload);

// endpoint.c
bool oshpacket_handler_endpoint(client_t *c, node_id_t *src,
    oshpacket_hdr_t *hdr, void *payload);

// goodbye.c
bool oshpacket_handler_goodbye_unauth(client_t *c,
    oshpacket_hdr_t *hdr, void *payload);
bool oshpacket_handler_goodbye(client_t *c, node_id_t *src,
    oshpacket_hdr_t *hdr, void *payload);

// handshake.c
bool oshpacket_handler_handshake(client_t *c,
    oshpacket_hdr_t *hdr, void *payload);
bool oshpacket_handler_handshake_auth(client_t *c, node_id_t *src,
    oshpacket_hdr_t *hdr, void *payload);

// handshake_sig.c
bool oshpacket_handler_handshake_sig(client_t *c,
    oshpacket_hdr_t *hdr, void *payload);
bool oshpacket_handler_handshake_sig_auth(client_t *c, node_id_t *src,
    oshpacket_hdr_t *hdr, void *payload);

// hello.c
bool oshpacket_handler_hello(client_t *c,
    oshpacket_hdr_t *hdr, void *payload);

// ping_pong.c
bool oshpacket_handler_ping(client_t *c, node_id_t *src,
    oshpacket_hdr_t *hdr, void *payload);
bool oshpacket_handler_pong(client_t *c, node_id_t *src,
    oshpacket_hdr_t *hdr, void *payload);

// pubkey.c
bool oshpacket_handler_pubkey(client_t *c, node_id_t *src,
    oshpacket_hdr_t *hdr, void *payload);

// route.c
bool oshpacket_handler_route(client_t *c, node_id_t *src,
    oshpacket_hdr_t *hdr, void *payload);

// stateexg_end.c
bool oshpacket_handler_stateexg_end(client_t *c, node_id_t *src,
    oshpacket_hdr_t *hdr, void *payload);

#endif
