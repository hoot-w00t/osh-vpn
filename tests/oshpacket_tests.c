#include "oshpacket.h"
#include <criterion/criterion.h>

Test(oshpacket_hdr_t, oshpacket_hdr_sizes)
{
    oshpacket_hdr_t hdr;

    cr_assert_eq(OSHPACKET_PUBLIC_HDR_SIZE + OSHPACKET_PRIVATE_HDR_SIZE, OSHPACKET_HDR_SIZE);
    cr_assert_eq(sizeof(hdr), OSHPACKET_HDR_SIZE);
    cr_assert_eq(sizeof(hdr) + OSHPACKET_PAYLOAD_MAXSIZE, OSHPACKET_MAXSIZE);
    cr_assert_eq(sizeof(hdr.flags), sizeof(uint8_t));
    cr_assert_eq(sizeof(hdr.dest), sizeof(hdr.dest.unicast));
    cr_assert_eq(sizeof(hdr.dest.broadcast), sizeof(hdr.dest.unicast));

    cr_assert_eq(sizeof(hdr.payload_size), sizeof(uint16_t));
    cr_assert_leq(OSHPACKET_PAYLOAD_MAXSIZE, UINT16_MAX);
}

Test(oshpacket_hdr_t, oshpacket_hdr_macros)
{
    oshpacket_hdr_t hdr;
    uint8_t *ptr = (uint8_t *) &hdr;

    cr_assert_eq(ptr, (uint8_t *) OSHPACKET_HDR(&hdr));
    cr_assert_eq(ptr + OSHPACKET_PUBLIC_HDR_SIZE, (uint8_t *) OSHPACKET_PRIVATE_HDR(&hdr));
    cr_assert_eq(ptr + OSHPACKET_HDR_SIZE,        (uint8_t *) OSHPACKET_PAYLOAD(&hdr));

    cr_assert_eq(OSHPACKET_HDR(&hdr),         OSHPACKET_HDR_CONST(&hdr));
    cr_assert_eq(OSHPACKET_PRIVATE_HDR(&hdr), OSHPACKET_PRIVATE_HDR_CONST(&hdr));
    cr_assert_eq(OSHPACKET_PAYLOAD(&hdr),     OSHPACKET_PAYLOAD_CONST(&hdr));
}

// The bit-field should be ordered from MSB to LSB
Test(oshpacket_hdr_t, oshpacket_hdr_flags_ordering)
{
    oshpacket_hdr_t hdr;

    memset(&hdr, 0, sizeof(hdr));
    BIT_SET(hdr.flags, OSHPACKET_HDR_FLAG_BROADCAST);
    cr_assert_eq(hdr.flags, 0x80u);
}

Test(oshpacket_hello_t, oshpacket_hello_options)
{
    oshpacket_hello_t packet;

    cr_assert_eq(sizeof(packet.options), sizeof(uint32_t));

    memset(&packet, 0, sizeof(packet));

    BIT_SET(packet.options, 31);
    cr_assert_eq(packet.options, 0x80000000u);
}

Test(oshpacket_type_valid, oshpacket_type_is_valid)
{
    for (oshpacket_type_t i = 0; i < _LAST_OSHPACKET_TYPE_ENTRY; ++i)
        cr_assert_eq(oshpacket_type_valid(i), true);
    cr_assert_eq(oshpacket_type_valid(_LAST_OSHPACKET_TYPE_ENTRY), false);
}

Test(oshpacket_type_name, oshpacket_type_has_name)
{
    for (oshpacket_type_t i = 0; i < _LAST_OSHPACKET_TYPE_ENTRY; ++i) {
        cr_assert_neq(oshpacket_type_name(i), NULL);
        cr_assert_str_neq(oshpacket_type_name(i), "UNKNOWN");
    }
    cr_assert_neq(oshpacket_type_name(_LAST_OSHPACKET_TYPE_ENTRY), NULL);
    cr_assert_str_eq(oshpacket_type_name(_LAST_OSHPACKET_TYPE_ENTRY), "UNKNOWN");
}

static inline bool type_can_be_forwarded(const oshpacket_type_t type)
{
    return !(   type == HANDSHAKE
             || type == HANDSHAKE_SIG
             || type == HANDSHAKE_END
             || type == HELLO
             || type == GOODBYE
             || type == PING
             || type == PONG
             || type == DEVMODE);
}

static inline bool type_can_be_sent_unencrypted(const oshpacket_type_t type)
{
    return type == HANDSHAKE
        || type == HANDSHAKE_SIG
        || type == GOODBYE;
}

static inline bool type_is_reliable(const oshpacket_type_t type)
{
    return type != DATA;
}

Test(oshpacket_lookup, oshpacket_lookup_has_valid_information)
{
    const oshpacket_def_t *p;

    for (oshpacket_type_t i = 0; i < _LAST_OSHPACKET_TYPE_ENTRY; ++i) {
        p = oshpacket_lookup(i);

        cr_assert_eq(p->type, i);
        cr_assert_not_null(p->name);
        cr_assert_str_eq(p->name, oshpacket_type_name(i));
        cr_assert_not_null(p->handler_unauth);
        cr_assert_not_null(p->handler);
        cr_assert_leq(p->payload_size, OSHPACKET_PAYLOAD_MAXSIZE);
        switch (p->payload_size_type) {
            case OSHPACKET_PAYLOAD_SIZE_VARIABLE:
                cr_assert_eq(p->payload_size, 0);
                break;
            case OSHPACKET_PAYLOAD_SIZE_FIXED:
                break;
            case OSHPACKET_PAYLOAD_SIZE_FRAGMENTED:
                // Fragmented payload size cannot be 0 because it would trigger
                // a division by zero fault
                cr_assert_neq(p->payload_size, 0);
                break;
            default:
                cr_assert_fail("Invalid oshpacket payload size");
        }

        cr_assert_eq(p->can_be_forwarded, type_can_be_forwarded(p->type));
        cr_assert_eq(p->can_be_sent_unencrypted, type_can_be_sent_unencrypted(p->type));
        cr_assert_eq(p->is_reliable, type_is_reliable(p->type));
    }
}

Test(oshpacket_lookup, oshpacket_lookup_invalid_types)
{
    for (int i = -1024; i < 0; ++i)
        cr_assert_null(oshpacket_lookup(i));
    for (int i = _LAST_OSHPACKET_TYPE_ENTRY; i < 1024; ++i)
        cr_assert_null(oshpacket_lookup(i));
}

Test(oshpacket_payload_size_valid, variable_size)
{
    const oshpacket_def_t def = {
        .type = _LAST_OSHPACKET_TYPE_ENTRY,
        .name = NULL,
        .handler_unauth = NULL,
        .handler = NULL,
        .can_be_forwarded = false,
        .payload_size_type = OSHPACKET_PAYLOAD_SIZE_VARIABLE,
        .payload_size = 0
    };

    for (size_t i = 0; i < OSHPACKET_PAYLOAD_MAXSIZE; ++i)
        cr_assert_eq(oshpacket_payload_size_valid(&def, i), true);
}

Test(oshpacket_payload_size_valid, fixed_size)
{
    oshpacket_def_t def = {
        .type = _LAST_OSHPACKET_TYPE_ENTRY,
        .name = NULL,
        .handler_unauth = NULL,
        .handler = NULL,
        .can_be_forwarded = false,
        .payload_size_type = OSHPACKET_PAYLOAD_SIZE_FIXED,
        .payload_size = 0
    };

    for (size_t i = 0; i < OSHPACKET_PAYLOAD_MAXSIZE; ++i) {
        def.payload_size = i;
        for (size_t j = 0; j < OSHPACKET_PAYLOAD_MAXSIZE; ++j) {
            if (i == j) {
                cr_assert_eq(oshpacket_payload_size_valid(&def, j), true);
            } else {
                cr_assert_eq(oshpacket_payload_size_valid(&def, j), false);
            }
        }
    }
}

Test(oshpacket_payload_size_valid, fragmented_size)
{
    oshpacket_def_t def = {
        .type = _LAST_OSHPACKET_TYPE_ENTRY,
        .name = NULL,
        .handler_unauth = NULL,
        .handler = NULL,
        .can_be_forwarded = false,
        .payload_size_type = OSHPACKET_PAYLOAD_SIZE_FRAGMENTED,
        .payload_size = 0
    };

    for (size_t i = 1; i < OSHPACKET_PAYLOAD_MAXSIZE; ++i) {
        def.payload_size = i;
        for (size_t j = 1; j < OSHPACKET_PAYLOAD_MAXSIZE; ++j) {
            if ((j % def.payload_size) == 0) {
                cr_assert_eq(oshpacket_payload_size_valid(&def, j), true);
            } else {
                cr_assert_eq(oshpacket_payload_size_valid(&def, j), false);
            }
        }
    }
}

Test(oshpacket_payload_size_valid, invalid_payload_size_type)
{
    const oshpacket_def_t def = {
        .type = _LAST_OSHPACKET_TYPE_ENTRY,
        .name = NULL,
        .handler_unauth = NULL,
        .handler = NULL,
        .can_be_forwarded = false,
        .payload_size_type = 0xFF,
        .payload_size = 0
    };

    for (size_t i = 0; i < OSHPACKET_PAYLOAD_MAXSIZE; ++i)
        cr_assert_eq(oshpacket_payload_size_valid(&def, i), false);
}

Test(oshpacket_devmode_t, check_dynamic_devmode_packet_struct)
{
    uint8_t buf[sizeof(oshpacket_devmode_dynamic_t)];
    oshpacket_devmode_t *regular = (oshpacket_devmode_t *) buf;
    oshpacket_devmode_dynamic_t *dyn = (oshpacket_devmode_dynamic_t *) buf;

    cr_assert_eq(sizeof(*regular), sizeof(dyn->devmode_pkt));
    cr_assert_eq(&dyn->network_name, ((uint8_t *) regular) + sizeof(*regular));
}

Test(oshpacket_t, oshpacket_init)
{
    const cipher_seqno_t e_seqno = 0xABCDEF;
    const size_t e_bytes_size = OSHPACKET_MAXSIZE;
    uint8_t e_bytes[e_bytes_size];
    oshpacket_t pkt;

    memset(e_bytes, 0, e_bytes_size);
    oshpacket_init(&pkt, e_bytes, e_bytes_size, e_seqno);

    cr_assert_eq(pkt.seqno, e_seqno);
    cr_assert_eq(pkt.packet, e_bytes);
    cr_assert_eq(pkt.packet_size, e_bytes_size);

    cr_assert_eq(pkt.cipher_tag_size, CIPHER_TAG_SIZE);
    cr_assert_eq(pkt.cipher_tag, e_bytes + e_bytes_size - CIPHER_TAG_SIZE);

    cr_assert_eq(pkt.hdr, pkt.packet);
    cr_assert_eq(pkt.payload, pkt.hdr + 1);
    cr_assert_eq(pkt.payload_size, e_bytes_size - sizeof(oshpacket_hdr_t) - CIPHER_TAG_SIZE);

    cr_assert_eq(pkt.encrypted, ((uint8_t *) pkt.hdr) + sizeof(uint16_t));
    cr_assert_eq(pkt.encrypted_size, e_bytes_size - sizeof(uint16_t) - CIPHER_TAG_SIZE);

    cr_assert_eq(OSHPACKET_CALC_SIZE(pkt.payload_size), pkt.packet_size);
}
