#include "oshpacket.h"
#include <criterion/criterion.h>

Test(oshpacket_hdr_t, oshpacket_hdr_sizes)
{
    oshpacket_hdr_t hdr;

    cr_assert_eq(OSHPACKET_PUBLIC_HDR_SIZE + OSHPACKET_PRIVATE_HDR_SIZE, OSHPACKET_HDR_SIZE);
    cr_assert_eq(sizeof(hdr), OSHPACKET_HDR_SIZE);
    cr_assert_eq(sizeof(hdr) + OSHPACKET_PAYLOAD_MAXSIZE, OSHPACKET_MAXSIZE);
    cr_assert_eq(sizeof(hdr.flags), sizeof(hdr.flags.u));
    cr_assert_eq(sizeof(hdr.flags.s), sizeof(hdr.flags.u));
    cr_assert_eq(sizeof(hdr.dest), sizeof(hdr.dest.unicast));
    cr_assert_eq(sizeof(hdr.dest.broadcast), sizeof(hdr.dest.unicast));

    cr_assert_eq(sizeof(hdr.payload_size), sizeof(uint16_t));
    cr_assert_leq(OSHPACKET_PAYLOAD_MAXSIZE, UINT16_MAX);
}

Test(oshpacket_hdr_t, oshpacket_hdr_macros)
{
    oshpacket_hdr_t hdr;
    void *ptr = (void *) &hdr;

    cr_assert_eq(ptr, (void *) OSHPACKET_HDR(&hdr));
    cr_assert_eq(ptr + OSHPACKET_PUBLIC_HDR_SIZE, (void *) OSHPACKET_PRIVATE_HDR(&hdr));
    cr_assert_eq(ptr + OSHPACKET_HDR_SIZE,        (void *) OSHPACKET_PAYLOAD(&hdr));

    cr_assert_eq(OSHPACKET_HDR(&hdr),         OSHPACKET_HDR_CONST(&hdr));
    cr_assert_eq(OSHPACKET_PRIVATE_HDR(&hdr), OSHPACKET_PRIVATE_HDR_CONST(&hdr));
    cr_assert_eq(OSHPACKET_PAYLOAD(&hdr),     OSHPACKET_PAYLOAD_CONST(&hdr));
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

Test(oshpacket_lookup, oshpacket_lookup_has_valid_information)
{
    const oshpacket_t *p;

    for (oshpacket_type_t i = 0; i < _LAST_OSHPACKET_TYPE_ENTRY; ++i) {
        p = oshpacket_lookup(i);

        cr_assert_eq(p->type, i);
        cr_assert_not_null(p->name);
        cr_assert_str_eq(p->name, oshpacket_type_name(i));
        cr_assert_not_null(p->handler_unauth);
        cr_assert_not_null(p->handler);
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
    const oshpacket_t def = {
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
    oshpacket_t def = {
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
    oshpacket_t def = {
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
    const oshpacket_t def = {
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
    cr_assert_eq(&dyn->network_name, ((void *) regular) + sizeof(*regular));
}
