#include "device_mode.h"
#include <criterion/criterion.h>

Test(device_mode_name, device_mode_has_name)
{
    for (device_mode_t i = 0; i < _LAST_DEVICE_MODE_ENTRY; ++i) {
        cr_assert_neq(device_mode_name(i), NULL);
        cr_assert_str_neq(device_mode_name(i), device_mode_name_unknown);
    }
    cr_assert_neq(device_mode_name(_LAST_DEVICE_MODE_ENTRY), NULL);
    cr_assert_str_eq(device_mode_name(_LAST_DEVICE_MODE_ENTRY), device_mode_name_unknown);
}

Test(device_mode_is_tap, device_mode_is_tap)
{
    for (device_mode_t i = 0; i < _LAST_DEVICE_MODE_ENTRY; ++i) {
        switch (i) {
            case MODE_TAP:
                cr_assert_eq(device_mode_is_tap(i), true);
                break;

            default:
                cr_assert_eq(device_mode_is_tap(i), false);
                break;
        }
    }
    cr_assert_eq(device_mode_is_tap(_LAST_DEVICE_MODE_ENTRY), false);
}