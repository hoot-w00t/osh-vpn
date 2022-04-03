#include "oshpacket.h"
#include <criterion/criterion.h>

Test(oshpacket_hdr_t, oshpacket_hdr_sizes)
{
    oshpacket_hdr_t hdr;

    cr_assert_eq(OSHPACKET_PUBLIC_HDR_SIZE + OSHPACKET_PRIVATE_HDR_SIZE, OSHPACKET_HDR_SIZE);
    cr_assert_eq(sizeof(hdr), OSHPACKET_HDR_SIZE);
    cr_assert_eq(sizeof(hdr) + OSHPACKET_PAYLOAD_MAXSIZE, OSHPACKET_MAXSIZE);
}

Test(oshpacket_hdr_t, oshpacket_hdr_macros)
{
    oshpacket_hdr_t hdr;
    void *ptr = (void *) &hdr;

    cr_assert_eq(ptr, (void *) OSHPACKET_HDR(&hdr));
    cr_assert_eq(ptr + OSHPACKET_PUBLIC_HDR_SIZE, (void *) OSHPACKET_PRIVATE_HDR(&hdr));
    cr_assert_eq(ptr + OSHPACKET_HDR_SIZE, (void *) OSHPACKET_PAYLOAD(&hdr));
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