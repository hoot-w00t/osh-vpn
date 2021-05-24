#include "easyconf.h"
#include <criterion/criterion.h>

static const char param1[] = "param1";
static const char param2[] = "param2";
static const char param3[] = "param3";
static const char param4[] = "param4";
static const char value1[] = "value1";
static const char value2[] = "value2";
static const char value3[] = "value3";
static const char value4[] = "value4";

static ec_t *create_4param_ec(void)
{
    ec_t *ec = ec_create();

    cr_assert_neq(ec, NULL);
    cr_assert_eq(ec_set(ec, param1, value1), 0);
    cr_assert_eq(ec_set(ec, param2, value2), 0);
    cr_assert_eq(ec_set(ec, param3, value3), 0);
    cr_assert_eq(ec_set(ec, param4, value4), 0);
    return ec;
}

Test(ec_create, ec_create)
{
    ec_t *ec = ec_create();

    cr_assert_neq(ec, NULL);
    ec_destroy(ec);
}

Test(ec_destroy, null_pointer)
{
    ec_destroy(NULL);
    cr_assert_eq(1, 1);
}

Test(ec_find, find_last)
{
    ec_t *ec = create_4param_ec();

    cr_assert_eq(ec_find(ec, NULL), NULL);

    cr_assert_neq(ec_find(ec, "param1"), NULL);
    cr_assert_neq(ec_find(ec, NULL), NULL);
    cr_assert_str_eq(ec_find(ec, NULL)->name, param1);
    cr_assert_str_eq(ec_find(ec, NULL)->value, value1);

    cr_assert_neq(ec_find(ec, "param2"), NULL);
    cr_assert_neq(ec_find(ec, NULL), NULL);
    cr_assert_str_eq(ec_find(ec, NULL)->name, param2);
    cr_assert_str_eq(ec_find(ec, NULL)->value, value2);

    cr_assert_neq(ec_find(ec, "param3"), NULL);
    cr_assert_neq(ec_find(ec, NULL), NULL);
    cr_assert_str_eq(ec_find(ec, NULL)->name, param3);
    cr_assert_str_eq(ec_find(ec, NULL)->value, value3);

    cr_assert_neq(ec_find(ec, "param4"), NULL);
    cr_assert_neq(ec_find(ec, NULL), NULL);
    cr_assert_str_eq(ec_find(ec, NULL)->name, param4);
    cr_assert_str_eq(ec_find(ec, NULL)->value, value4);

    cr_assert_eq(ec_find(ec, "invalid"), NULL);
    cr_assert_eq(ec_find(ec, NULL), NULL);
}

Test(ec_set, add_parameters)
{
    const char first_param[] = "first_param";
    const char first_value[] = "first_value";
    const char second_param[] = "second_param";
    const char second_value[] = "second_value";
    ec_t *ec = ec_create();

    cr_assert_neq(ec, NULL);
    cr_assert_eq(ec_set(ec, first_param, first_value), 0);
    cr_assert_eq(ec_set(ec, second_param, second_value), 0);
    cr_assert_str_eq(ec->head->name, first_param);
    cr_assert_str_eq(ec->head->value, first_value);
    cr_assert_str_eq(ec->tail->name, second_param);
    cr_assert_str_eq(ec->tail->value, second_value);
    ec_destroy(ec);
}

Test(ec_set, modify_parameter)
{
    const char param[] = "param";
    const char first_value[] = "first_value";
    const char second_value[] = "second_value";
    ec_t *ec = ec_create();

    cr_assert_neq(ec, NULL);
    cr_assert_eq(ec_set(ec, param, first_value), 0);
    cr_assert_eq(ec->head, ec->tail);
    cr_assert_str_eq(ec->head->name, param);
    cr_assert_str_eq(ec->head->value, first_value);
    cr_assert_eq(ec_set(ec, param, second_value), 0);
    cr_assert_eq(ec->head, ec->tail);
    cr_assert_str_eq(ec->head->name, param);
    cr_assert_str_eq(ec->head->value, second_value);
    ec_destroy(ec);
}

Test(ec_unset, unset_head)
{
    ec_t *ec = create_4param_ec();

    // head == param1
    cr_assert_neq(ec->head, NULL);
    cr_assert_neq(ec->tail, NULL);
    cr_assert_neq(ec->head, ec->tail);
    cr_assert_str_eq(ec->head->name, param1);
    cr_assert_str_eq(ec->head->value, value1);
    cr_assert_eq(ec->head->prev, NULL);
    cr_assert_neq(ec->head->next, NULL);
    cr_assert_eq(ec_unset(ec, param1), 0);

    // head == param2
    cr_assert_neq(ec->head, NULL);
    cr_assert_neq(ec->tail, NULL);
    cr_assert_neq(ec->head, ec->tail);
    cr_assert_str_eq(ec->head->name, param2);
    cr_assert_str_eq(ec->head->value, value2);
    cr_assert_eq(ec->head->prev, NULL);
    cr_assert_neq(ec->head->next, NULL);
    cr_assert_eq(ec_unset(ec, param2), 0);

    // head == param3
    cr_assert_neq(ec->head, NULL);
    cr_assert_neq(ec->tail, NULL);
    cr_assert_neq(ec->head, ec->tail);
    cr_assert_str_eq(ec->head->name, param3);
    cr_assert_str_eq(ec->head->value, value3);
    cr_assert_eq(ec->head->prev, NULL);
    cr_assert_neq(ec->head->next, NULL);
    cr_assert_eq(ec_unset(ec, param3), 0);

    // head == param4
    cr_assert_neq(ec->head, NULL);
    cr_assert_eq(ec->head, ec->tail);
    cr_assert_str_eq(ec->head->name, param4);
    cr_assert_str_eq(ec->head->value, value4);
    cr_assert_eq(ec->head->prev, NULL);
    cr_assert_eq(ec->head->next, NULL);
    cr_assert_eq(ec_unset(ec, param4), 0);

    // head == NULL
    cr_assert_eq(ec->head, NULL);
    cr_assert_eq(ec->tail, NULL);
    cr_assert_eq(ec_unset(ec, param1), -1);
    cr_assert_eq(ec_unset(ec, param2), -1);
    cr_assert_eq(ec_unset(ec, param3), -1);
    cr_assert_eq(ec_unset(ec, param4), -1);
    ec_destroy(ec);
}

Test(ec_unset, unset_tail)
{
    ec_t *ec = create_4param_ec();

    // tail == param4
    cr_assert_neq(ec->head, NULL);
    cr_assert_neq(ec->tail, NULL);
    cr_assert_neq(ec->head, ec->tail);
    cr_assert_str_eq(ec->tail->name, param4);
    cr_assert_str_eq(ec->tail->value, value4);
    cr_assert_eq(ec->tail->next, NULL);
    cr_assert_neq(ec->tail->prev, NULL);
    cr_assert_eq(ec_unset(ec, param4), 0);

    // tail == param3
    cr_assert_neq(ec->head, NULL);
    cr_assert_neq(ec->tail, NULL);
    cr_assert_neq(ec->head, ec->tail);
    cr_assert_str_eq(ec->tail->name, param3);
    cr_assert_str_eq(ec->tail->value, value3);
    cr_assert_eq(ec->tail->next, NULL);
    cr_assert_neq(ec->tail->prev, NULL);
    cr_assert_eq(ec_unset(ec, param3), 0);

    // tail == param2
    cr_assert_neq(ec->head, NULL);
    cr_assert_neq(ec->tail, NULL);
    cr_assert_neq(ec->head, ec->tail);
    cr_assert_str_eq(ec->tail->name, param2);
    cr_assert_str_eq(ec->tail->value, value2);
    cr_assert_eq(ec->tail->next, NULL);
    cr_assert_neq(ec->tail->prev, NULL);
    cr_assert_eq(ec_unset(ec, param2), 0);

    // tail == param1
    cr_assert_neq(ec->head, NULL);
    cr_assert_eq(ec->head, ec->tail);
    cr_assert_str_eq(ec->tail->name, param1);
    cr_assert_str_eq(ec->tail->value, value1);
    cr_assert_eq(ec->tail->next, NULL);
    cr_assert_eq(ec->tail->prev, NULL);
    cr_assert_eq(ec_unset(ec, param1), 0);

    // tail == NULL
    cr_assert_eq(ec->head, NULL);
    cr_assert_eq(ec->tail, NULL);
    cr_assert_eq(ec_unset(ec, param1), -1);
    cr_assert_eq(ec_unset(ec, param2), -1);
    cr_assert_eq(ec_unset(ec, param3), -1);
    cr_assert_eq(ec_unset(ec, param4), -1);
    ec_destroy(ec);
}

Test(ec_unset, unset_middle)
{
    ec_t *ec = create_4param_ec();

    // head - param1 <-> param2 <-> param3 <-> param4 - tail
    cr_assert_neq(ec->head, NULL);
    cr_assert_neq(ec->tail, NULL);
    cr_assert_str_eq(ec->head->name, param1);
    cr_assert_str_eq(ec->head->value, value1);
    cr_assert_str_eq(ec->tail->name, param4);
    cr_assert_str_eq(ec->tail->value, value4);
    cr_assert_neq(ec->head, ec->tail);
    // assert from head to tail
    cr_assert_str_eq(ec->head->name, param1);
    cr_assert_str_eq(ec->head->value, value1);
    cr_assert_str_eq(ec->head->next->name, param2);
    cr_assert_str_eq(ec->head->next->value, value2);
    cr_assert_str_eq(ec->head->next->next->name, param3);
    cr_assert_str_eq(ec->head->next->next->value, value3);
    cr_assert_str_eq(ec->head->next->next->next->name, param4);
    cr_assert_str_eq(ec->head->next->next->next->value, value4);
    // assert from tail to head
    cr_assert_str_eq(ec->tail->name, param4);
    cr_assert_str_eq(ec->tail->value, value4);
    cr_assert_str_eq(ec->tail->prev->name, param3);
    cr_assert_str_eq(ec->tail->prev->value, value3);
    cr_assert_str_eq(ec->tail->prev->prev->name, param2);
    cr_assert_str_eq(ec->tail->prev->prev->value, value2);
    cr_assert_str_eq(ec->tail->prev->prev->prev->name, param1);
    cr_assert_str_eq(ec->tail->prev->prev->prev->value, value1);

    cr_assert_eq(ec_unset(ec, param2), 0);

    // head - param1 <-> param3 <-> param4 - tail
    cr_assert_neq(ec->head, NULL);
    cr_assert_neq(ec->tail, NULL);
    cr_assert_str_eq(ec->tail->name, param4);
    cr_assert_str_eq(ec->tail->value, value4);
    cr_assert_neq(ec->head, ec->tail);
    // assert from head to tail
    cr_assert_str_eq(ec->head->name, param1);
    cr_assert_str_eq(ec->head->value, value1);
    cr_assert_str_eq(ec->head->next->name, param3);
    cr_assert_str_eq(ec->head->next->value, value3);
    cr_assert_str_eq(ec->head->next->next->name, param4);
    cr_assert_str_eq(ec->head->next->next->value, value4);
    // assert from tail to head
    cr_assert_str_eq(ec->tail->name, param4);
    cr_assert_str_eq(ec->tail->value, value4);
    cr_assert_str_eq(ec->tail->prev->name, param3);
    cr_assert_str_eq(ec->tail->prev->value, value3);
    cr_assert_str_eq(ec->tail->prev->prev->name, param1);
    cr_assert_str_eq(ec->tail->prev->prev->value, value1);

    cr_assert_eq(ec_unset(ec, param3), 0);

    // head - param1 <-> param4 - tail
    cr_assert_neq(ec->head, NULL);
    cr_assert_neq(ec->tail, NULL);
    cr_assert_str_eq(ec->tail->name, param4);
    cr_assert_str_eq(ec->tail->value, value4);
    cr_assert_neq(ec->head, ec->tail);
    // assert from head to tail
    cr_assert_str_eq(ec->head->name, param1);
    cr_assert_str_eq(ec->head->value, value1);
    cr_assert_str_eq(ec->head->next->name, param4);
    cr_assert_str_eq(ec->head->next->value, value4);
    // assert from tail to head
    cr_assert_str_eq(ec->tail->name, param4);
    cr_assert_str_eq(ec->tail->value, value4);
    cr_assert_str_eq(ec->tail->prev->name, param1);
    cr_assert_str_eq(ec->tail->prev->value, value1);

    cr_assert_eq(ec->head->prev, NULL);
    cr_assert_eq(ec->tail->next, NULL);
    ec_destroy(ec);
}

Test(ec_unset, unset_non_existent)
{
    ec_t *empty = ec_create();
    ec_t *ec = create_4param_ec();

    cr_assert_neq(empty, NULL);
    cr_assert_eq(ec_unset(empty, "invalid_param"), -1);
    cr_assert_eq(ec_unset(ec, "invalid_param"), -1);

    // head - param1 <-> param2 <-> param3 <-> param4 - tail
    cr_assert_neq(ec->head, NULL);
    cr_assert_neq(ec->tail, NULL);
    cr_assert_str_eq(ec->head->name, param1);
    cr_assert_str_eq(ec->head->value, value1);
    cr_assert_str_eq(ec->tail->name, param4);
    cr_assert_str_eq(ec->tail->value, value4);
    cr_assert_neq(ec->head, ec->tail);
    // assert from head to tail
    cr_assert_str_eq(ec->head->name, param1);
    cr_assert_str_eq(ec->head->value, value1);
    cr_assert_str_eq(ec->head->next->name, param2);
    cr_assert_str_eq(ec->head->next->value, value2);
    cr_assert_str_eq(ec->head->next->next->name, param3);
    cr_assert_str_eq(ec->head->next->next->value, value3);
    cr_assert_str_eq(ec->head->next->next->next->name, param4);
    cr_assert_str_eq(ec->head->next->next->next->value, value4);
    // assert from tail to head
    cr_assert_str_eq(ec->tail->name, param4);
    cr_assert_str_eq(ec->tail->value, value4);
    cr_assert_str_eq(ec->tail->prev->name, param3);
    cr_assert_str_eq(ec->tail->prev->value, value3);
    cr_assert_str_eq(ec->tail->prev->prev->name, param2);
    cr_assert_str_eq(ec->tail->prev->prev->value, value2);
    cr_assert_str_eq(ec->tail->prev->prev->prev->name, param1);
    cr_assert_str_eq(ec->tail->prev->prev->prev->value, value1);

    ec_destroy(empty);
    ec_destroy(ec);
}

Test(ec_load_from_file, ec_load_from_file)
{
    ec_t *ec = ec_load_from_file("./tests/test.conf");

    cr_assert_neq(ec, NULL);
    cr_assert_str_eq(ecp_value(ec_find(ec, "L1")), "Lorem ipsum dolor sit amet, consectetur adipiscing elit.");
    cr_assert_str_eq(ecp_value(ec_find(ec, "L2")), "Sed non risus.");
    cr_assert_str_eq(ecp_value(ec_find(ec, "L3")), "Suspendisse lectus tortor, dignissim sit amet, adipiscing nec,");
    cr_assert_str_eq(ecp_value(ec_find(ec, "L4")), "ultricies sed, dolor.");
    ec_destroy(ec);
}