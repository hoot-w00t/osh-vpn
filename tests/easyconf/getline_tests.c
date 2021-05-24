#include "getline.h"
#include <stdio.h>
#include <criterion/criterion.h>

Test(ec_getline, reading_test_dot_conf)
{
    char *line;
    FILE *file = fopen("./tests/test.conf", "r");

    cr_assert_neq(file, NULL);
    line = ec_getline(file);
    cr_assert_neq(line, NULL);
    cr_assert_str_eq(line, "L1  Lorem ipsum dolor sit amet, consectetur adipiscing elit.\n");
    free(line);

    line = ec_getline(file);
    cr_assert_neq(line, NULL);
    cr_assert_str_eq(line, "L2  Sed non risus.\n");
    free(line);

    line = ec_getline(file);
    cr_assert_neq(line, NULL);
    cr_assert_str_eq(line, "L3  Suspendisse lectus tortor, dignissim sit amet, adipiscing nec,\n");
    free(line);

    line = ec_getline(file);
    cr_assert_neq(line, NULL);
    cr_assert_str_eq(line, "\n");
    free(line);

    line = ec_getline(file);
    cr_assert_neq(line, NULL);
    cr_assert_str_eq(line, "L4  ultricies sed, dolor.");
    free(line);

    line = ec_getline(file);
    cr_assert_eq(line, NULL);
    cr_assert_neq(feof(file), 0);
    fclose(file);
}