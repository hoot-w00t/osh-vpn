#ifndef _OSH_OSHPACKET_HANDLERS_H
#define _OSH_OSHPACKET_HANDLERS_H

#include "oshpacket.h"

// Functions defined under src/oshpacket_handlers/

// data.c
bool oshpacket_handler_data(client_t *c, node_id_t *src, oshpacket_t *pkt);

// devmode.c
bool oshpacket_handler_devmode(client_t *c, node_id_t *src, oshpacket_t *pkt);

// edge.c
bool oshpacket_handler_edge_add(client_t *c, node_id_t *src, oshpacket_t *pkt);
bool oshpacket_handler_edge_del(client_t *c, node_id_t *src, oshpacket_t *pkt);

// endpoint.c
bool oshpacket_handler_endpoint(client_t *c, node_id_t *src, oshpacket_t *pkt);

// goodbye.c
bool oshpacket_handler_goodbye_unauth(client_t *c, oshpacket_t *pkt);
bool oshpacket_handler_goodbye(client_t *c, node_id_t *src, oshpacket_t *pkt);

// handshake.c
bool oshpacket_handler_handshake(client_t *c, oshpacket_t *pkt);
bool oshpacket_handler_handshake_auth(client_t *c, node_id_t *src, oshpacket_t *pkt);

// handshake_end.c
bool oshpacket_handler_handshake_end(client_t *c, node_id_t *src, oshpacket_t *pkt);

// handshake_sig.c
bool oshpacket_handler_handshake_sig(client_t *c, oshpacket_t *pkt);
bool oshpacket_handler_handshake_sig_auth(client_t *c, node_id_t *src, oshpacket_t *pkt);

// hello.c
bool oshpacket_handler_hello(client_t *c, oshpacket_t *pkt);

// ping_pong.c
bool oshpacket_handler_ping(client_t *c, node_id_t *src, oshpacket_t *pkt);
bool oshpacket_handler_pong(client_t *c, node_id_t *src, oshpacket_t *pkt);

// pubkey.c
bool oshpacket_handler_pubkey(client_t *c, node_id_t *src, oshpacket_t *pkt);

// route.c
bool oshpacket_handler_route(client_t *c, node_id_t *src, oshpacket_t *pkt);

// stateexg_end.c
bool oshpacket_handler_stateexg_end(client_t *c, node_id_t *src, oshpacket_t *pkt);

#endif
