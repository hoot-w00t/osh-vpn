#include "easyconf.h"
#include <criterion/criterion.h>
#include <string.h>

Test(ecp_empty, ecp_empty)
{
    ecp_t *ecp = ecp_empty();

    cr_assert_neq(ecp, NULL);
    cr_assert_eq(ecp->name, NULL);
    cr_assert_eq(ecp->value, NULL);
    cr_assert_eq(ecp->next, NULL);
    cr_assert_eq(ecp->prev, NULL);
    ecp_free(ecp);
}

Test(ecp_free, null_pointer)
{
    ecp_free(NULL);
    cr_assert_eq(1, 1);
}

Test(ecp_create, with_name_and_value)
{
    const char o_name[] = "param_name";
    const char o_value[] = "param_value";
    ecp_t *ecp = ecp_create(o_name, o_value);

    cr_assert_neq(ecp, NULL);
    cr_assert_neq(ecp->name, o_name);
    cr_assert_str_eq(ecp->name, o_name);
    cr_assert_neq(ecp->value, o_value);
    cr_assert_str_eq(ecp->value, o_value);
    cr_assert_eq(ecp->next, NULL);
    cr_assert_eq(ecp->prev, NULL);
    ecp_free(ecp);
}

Test(ecp_create, without_value)
{
    const char o_name[] = "param_name";
    ecp_t *ecp = ecp_create(o_name, NULL);

    cr_assert_neq(ecp, NULL);
    cr_assert_neq(ecp->name, o_name);
    cr_assert_str_eq(ecp->name, o_name);
    cr_assert_eq(ecp->value, NULL);
    cr_assert_eq(ecp->next, NULL);
    cr_assert_eq(ecp->prev, NULL);
    ecp_free(ecp);
}

Test(ecp_create, without_name)
{
    const char o_value[] = "param_value";
    ecp_t *ecp = ecp_create(NULL, o_value);

    cr_assert_eq(ecp, NULL);
}

Test(ecp_dup, null_pointer)
{
    cr_assert_eq(ecp_dup(NULL), NULL);
}

Test(ecp_dup, ecp_dup)
{
    const char o_name[] = "param_name";
    const char o_value[] = "param_value";
    ecp_t *ecp = ecp_create(o_name, o_value);
    ecp_t *dup = ecp_dup(ecp);

    cr_assert_neq(ecp, NULL);
    cr_assert_neq(dup, NULL);
    cr_assert_neq(ecp, dup);
    cr_assert_neq(ecp->name, dup->name);
    cr_assert_neq(ecp->value, dup->value);
    cr_assert_str_eq(ecp->name, dup->name);
    cr_assert_str_eq(ecp->value, dup->value);
    ecp_free(ecp);
    ecp_free(dup);
}

Test(ecp_set_name, null_pointer)
{
    const char o_name[] = "param_name";
    const char o_value[] = "param_value";
    ecp_t *ecp = ecp_create(o_name, o_value);

    cr_assert_neq(ecp, NULL);
    cr_assert_eq(ecp_set_name(ecp, NULL), -1);
    cr_assert_eq(ecp_set_name(NULL, NULL), -1);
    ecp_free(ecp);
}

Test(ecp_set_name, ecp_set_name)
{
    const char o_name[] = "param_name";
    const char o_value[] = "param_value";
    const char o_name2[] = "param_name2";
    ecp_t *ecp = ecp_create(o_name, o_value);

    cr_assert_neq(ecp, NULL);
    cr_assert_eq(ecp_set_name(ecp, o_name2), 0);
    cr_assert_str_eq(ecp->name, o_name2);
    ecp_free(ecp);
}

Test(ecp_set_value, null_pointer)
{
    const char o_name[] = "param_name";
    const char o_value[] = "param_value";
    ecp_t *ecp = ecp_create(o_name, o_value);

    cr_assert_neq(ecp, NULL);
    cr_assert_eq(ecp_set_value(ecp, NULL), 0);
    cr_assert_eq(ecp->value, NULL);
    cr_assert_eq(ecp_set_value(NULL, NULL), -1);
    ecp_free(ecp);
}

Test(ecp_set_value, ecp_set_value)
{
    const char o_name[] = "param_name";
    const char o_value[] = "param_value";
    const char o_value2[] = "param_value2";
    ecp_t *ecp = ecp_create(o_name, o_value);

    cr_assert_neq(ecp, NULL);
    cr_assert_eq(ecp_set_value(ecp, o_value2), 0);
    cr_assert_str_eq(ecp->value, o_value2);
    ecp_free(ecp);
}

Test(ecp_name, null_pointer)
{
    cr_assert_eq(ecp_name(NULL), NULL);
}

Test(ecp_value, null_pointer)
{
    cr_assert_eq(ecp_value(NULL), NULL);
}

Test(ecp_parse_line, parse_invalid_line)
{
    ecp_t *ecp = ecp_parse_line(" \t\t ");
    ecp_t *ecp2 = ecp_parse_line("\t  \t");

    cr_assert_eq(ecp, NULL);
    cr_assert_eq(ecp2, NULL);
}

Test(ecp_parse_line, parse_empty_line)
{
    ecp_t *ecp = ecp_parse_line("");

    cr_assert_eq(ecp, NULL);
}

Test(ecp_parse_line, null_pointer)
{
    ecp_t *ecp = ecp_parse_line(NULL);

    cr_assert_eq(ecp, NULL);
}

Test(ecp_parse_line, with_name_only)
{
    ecp_t *ecp = ecp_parse_line("Param");

    cr_assert_neq(ecp, NULL);
    cr_assert_eq(ecp->next, NULL);
    cr_assert_eq(ecp->prev, NULL);
    cr_assert_neq(ecp->name, NULL);
    cr_assert_eq(ecp->value, NULL);
    cr_assert_str_eq(ecp->name, "Param");
    ecp_free(ecp);
}

Test(ecp_parse_line, with_name_and_value)
{
    ecp_t *ecp = ecp_parse_line("Param   \t \tValue\t");

    cr_assert_neq(ecp, NULL);
    cr_assert_eq(ecp->next, NULL);
    cr_assert_eq(ecp->prev, NULL);
    cr_assert_neq(ecp->name, NULL);
    cr_assert_neq(ecp->value, NULL);
    cr_assert_str_eq(ecp->name, "Param");
    cr_assert_str_eq(ecp->value, "Value");
    ecp_free(ecp);
}

Test(ecp_parse_line, with_comment)
{
    ecp_t *ecp = ecp_parse_line("Param Value # Comment");

    cr_assert_neq(ecp, NULL);
    cr_assert_eq(ecp->next, NULL);
    cr_assert_eq(ecp->prev, NULL);
    cr_assert_neq(ecp->name, NULL);
    cr_assert_neq(ecp->value, NULL);
    cr_assert_str_eq(ecp->name, "Param");
    cr_assert_str_eq(ecp->value, "Value");
    ecp_free(ecp);
}

Test(ecp_parse_line, with_escaped_comment)
{
    ecp_t *ecp = ecp_parse_line("Param Value \\# # Comment");

    cr_assert_neq(ecp, NULL);
    cr_assert_eq(ecp->next, NULL);
    cr_assert_eq(ecp->prev, NULL);
    cr_assert_neq(ecp->name, NULL);
    cr_assert_neq(ecp->value, NULL);
    cr_assert_str_eq(ecp->name, "Param");
    cr_assert_str_eq(ecp->value, "Value #");
    ecp_free(ecp);
}