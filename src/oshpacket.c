#include "oshpacket.h"
#include "oshpacket_handlers.h"
#include "logger.h"
#include "node.h"

// Generic default handlers for invalid packet types
static bool unauth_handler_reject(client_t *c, oshpacket_t *pkt)
{
    logger(LOG_ERR, "%s: Rejecting %s packet",
        c->addrw, oshpacket_type_name(pkt->hdr->type));
    return false;
}

static bool handler_reject(client_t *c, node_id_t *src, oshpacket_t *pkt)
{
    logger(LOG_ERR, "%s: %s: Rejecting %s packet from %s",
        c->addrw, c->id->name, oshpacket_type_name(pkt->hdr->type), src->name);
    return false;
}

// The packet types must be in the same order as the enumeration, otherwise the
// lookup will return an invalid definition
// The name and both handlers must never be NULL, as those will be used without
// checking their values first
static const oshpacket_def_t oshpacket_table[OSHPACKET_TYPE_COUNT] = {
    {
        .type = OSHPKT_HANDSHAKE,
        .name = "HANDSHAKE",
        .handler_unauth = oshpacket_handler_handshake,
        .handler = oshpacket_handler_handshake_auth,
        .can_be_forwarded = false,
        .can_be_sent_unencrypted = true,
        .is_reliable = true,
        .payload_size_type = OSHPACKET_PAYLOAD_SIZE_FIXED,
        .payload_size = sizeof(oshpacket_handshake_t)
    },
    {
        .type = OSHPKT_HANDSHAKE_SIG,
        .name = "HANDSHAKE_SIG",
        .handler_unauth = oshpacket_handler_handshake_sig,
        .handler = oshpacket_handler_handshake_sig_auth,
        .can_be_forwarded = false,
        .can_be_sent_unencrypted = true,
        .is_reliable = true,
        .payload_size_type = OSHPACKET_PAYLOAD_SIZE_FIXED,
        .payload_size = sizeof(oshpacket_handshake_sig_t)
    },
    {
        .type = OSHPKT_HANDSHAKE_END,
        .name = "HANDSHAKE_END",
        .handler_unauth = unauth_handler_reject,
        .handler = oshpacket_handler_handshake_end,
        .can_be_forwarded = false,
        .can_be_sent_unencrypted = false,
        .is_reliable = true,
        .payload_size_type = OSHPACKET_PAYLOAD_SIZE_FIXED,
        .payload_size = 0
    },
    {
        .type = OSHPKT_HELLO,
        .name = "HELLO",
        .handler_unauth = oshpacket_handler_hello,
        .handler = handler_reject,
        .can_be_forwarded = false,
        .can_be_sent_unencrypted = false,
        .is_reliable = true,
        .payload_size_type = OSHPACKET_PAYLOAD_SIZE_FIXED,
        .payload_size = sizeof(oshpacket_hello_t)
    },
    {
        .type = OSHPKT_DEVMODE,
        .name = "DEVMODE",
        .handler_unauth = unauth_handler_reject,
        .handler = oshpacket_handler_devmode,
        .can_be_forwarded = false,
        .can_be_sent_unencrypted = false,
        .is_reliable = true,
        .payload_size_type = OSHPACKET_PAYLOAD_SIZE_VARIABLE,
        .payload_size = 0
    },
    {
        .type = OSHPKT_GOODBYE,
        .name = "GOODBYE",
        .handler_unauth = oshpacket_handler_goodbye_unauth,
        .handler = oshpacket_handler_goodbye,
        .can_be_forwarded = false,
        .can_be_sent_unencrypted = true,
        .is_reliable = true,
        .payload_size_type = OSHPACKET_PAYLOAD_SIZE_FIXED,
        .payload_size = 0
    },
    {
        .type = OSHPKT_PING,
        .name = "PING",
        .handler_unauth = unauth_handler_reject,
        .handler = oshpacket_handler_ping,
        .can_be_forwarded = false,
        .can_be_sent_unencrypted = false,
        .is_reliable = true,
        .payload_size_type = OSHPACKET_PAYLOAD_SIZE_FIXED,
        .payload_size = 0
    },
    {
        .type = OSHPKT_PONG,
        .name = "PONG",
        .handler_unauth = unauth_handler_reject,
        .handler = oshpacket_handler_pong,
        .can_be_forwarded = false,
        .can_be_sent_unencrypted = false,
        .is_reliable = true,
        .payload_size_type = OSHPACKET_PAYLOAD_SIZE_FIXED,
        .payload_size = 0
    },
    {
        .type = OSHPKT_DATA,
        .name = "DATA",
        .handler_unauth = unauth_handler_reject,
        .handler = oshpacket_handler_data,
        .can_be_forwarded = true,
        .can_be_sent_unencrypted = false,
        .is_reliable = false,
        .payload_size_type = OSHPACKET_PAYLOAD_SIZE_VARIABLE,
        .payload_size = 0
    },
    {
        .type = OSHPKT_PUBKEY,
        .name = "PUBKEY",
        .handler_unauth = unauth_handler_reject,
        .handler = oshpacket_handler_pubkey,
        .can_be_forwarded = true,
        .can_be_sent_unencrypted = false,
        .is_reliable = true,
        .payload_size_type = OSHPACKET_PAYLOAD_SIZE_FRAGMENTED,
        .payload_size = sizeof(oshpacket_pubkey_t)
    },
    {
        .type = OSHPKT_ENDPOINT,
        .name = "ENDPOINT",
        .handler_unauth = unauth_handler_reject,
        .handler = oshpacket_handler_endpoint,
        .can_be_forwarded = true,
        .can_be_sent_unencrypted = false,
        .is_reliable = true,
        .payload_size_type = OSHPACKET_PAYLOAD_SIZE_VARIABLE,
        .payload_size = 0
    },
    {
        .type = OSHPKT_EDGE_ADD,
        .name = "EDGE_ADD",
        .handler_unauth = unauth_handler_reject,
        .handler = oshpacket_handler_edge_add,
        .can_be_forwarded = true,
        .can_be_sent_unencrypted = false,
        .is_reliable = true,
        .payload_size_type = OSHPACKET_PAYLOAD_SIZE_FRAGMENTED,
        .payload_size = sizeof(oshpacket_edge_t)
    },
    {
        .type = OSHPKT_EDGE_DEL,
        .name = "EDGE_DEL",
        .handler_unauth = unauth_handler_reject,
        .handler = oshpacket_handler_edge_del,
        .can_be_forwarded = true,
        .can_be_sent_unencrypted = false,
        .is_reliable = true,
        .payload_size_type = OSHPACKET_PAYLOAD_SIZE_FRAGMENTED,
        .payload_size = sizeof(oshpacket_edge_t)
    },
    {
        .type = OSHPKT_ROUTE_ADD,
        .name = "ROUTE_ADD",
        .handler_unauth = unauth_handler_reject,
        .handler = oshpacket_handler_route,
        .can_be_forwarded = true,
        .can_be_sent_unencrypted = false,
        .is_reliable = true,
        .payload_size_type = OSHPACKET_PAYLOAD_SIZE_FRAGMENTED,
        .payload_size = sizeof(oshpacket_route_t)
    }
};

const char *oshpacket_type_name(oshpacket_type_t type)
{
    if (oshpacket_type_valid(type))
        return oshpacket_table[type].name;
    return "UNKNOWN";
}

const oshpacket_def_t *oshpacket_lookup(oshpacket_type_t type)
{
    if (oshpacket_type_valid(type))
        return &oshpacket_table[type];
    return NULL;
}

// Returns true if the given payload size is valid for this packet type
bool oshpacket_payload_size_valid(const oshpacket_def_t *def,
    const size_t payload_size)
{
    // Verify the payload size
    switch (def->payload_size_type) {
        // A variable size means that the handler will verify the size
        case OSHPACKET_PAYLOAD_SIZE_VARIABLE: return true;

        // The payload size must match the expected size
        case OSHPACKET_PAYLOAD_SIZE_FIXED:
            return payload_size == def->payload_size;

        // The payload size must be a multiple of the expected size
        case OSHPACKET_PAYLOAD_SIZE_FRAGMENTED:
            return  payload_size >= def->payload_size
                && (payload_size  % def->payload_size) == 0;

        // The default case should never occur
        default: return false;
    }
}

// Get the size in bytes from startptr to endptr
static size_t ptrsize(const void *startptr, const void *endptr)
{
    return ((const uint8_t *) endptr) - ((const uint8_t *) startptr);
}

// Initialize oshpacket_t members from raw packet data
// Pointers and sizes passed to this function must be valid
void oshpacket_init(oshpacket_t *pkt, void *packet, size_t packet_size,
    cipher_seqno_t seqno)
{
    const size_t min_size = sizeof(oshpacket_hdr_t) + CIPHER_TAG_SIZE;

    if (packet_size < min_size) {
        logger(LOG_CRIT, "%s: %s", __func__, "packet_size is too small");
        abort();
    }

    pkt->seqno = seqno;
    pkt->packet = packet;
    pkt->packet_size = packet_size;

    pkt->cipher_tag_size = CIPHER_TAG_SIZE;
    pkt->cipher_tag = ((uint8_t *) packet) + packet_size - pkt->cipher_tag_size;

    pkt->hdr = OSHPACKET_HDR(packet);
    pkt->payload = OSHPACKET_PAYLOAD(pkt->hdr);
    pkt->payload_size = ptrsize(pkt->payload, pkt->cipher_tag);

    pkt->encrypted = OSHPACKET_PRIVATE_HDR(pkt->hdr);
    pkt->encrypted_size = ptrsize(pkt->encrypted, pkt->cipher_tag);
}
