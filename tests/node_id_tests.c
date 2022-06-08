#include "oshd.h"
#include <criterion/criterion.h>

static void init_node_tree(void)
{
    oshd.node_tree = NULL;
    oshd.node_tree_count = 0;
    oshd.node_tree_ordered_hops = NULL;
}

static void free_node_tree(void)
{
    for (size_t i = 0; i < oshd.node_tree_count; ++i)
        node_id_free(oshd.node_tree[i]);
    free(oshd.node_tree);
    free(oshd.node_tree_ordered_hops);
    init_node_tree();
}

Test(node_has_seen_brd_id, test_list,
    .init = init_node_tree,
    .fini = free_node_tree)
{
    const oshpacket_brd_id_t brd_id_test_count = seen_brd_id_maxsize * 8;
    oshpacket_brd_id_t brd_id;
    size_t count = 0;
    node_id_t *nid;

    init_node_tree();
    nid = node_id_add("test_brd_id");
    cr_assert_not_null(nid);

    cr_assert_eq(sizeof(nid->seen_brd_id), sizeof(oshpacket_brd_id_t) * seen_brd_id_maxsize);
    for (size_t i = 0; i < seen_brd_id_maxsize; ++i)
        cr_assert_eq(nid->seen_brd_id[i], 0);
    cr_assert_eq(nid->seen_brd_id_count, 0);
    cr_assert_eq(count, 0);
    cr_assert_geq(brd_id_test_count, seen_brd_id_maxsize);
    cr_assert_eq(brd_id_test_count % seen_brd_id_maxsize, 0);

    for (brd_id = 1; brd_id <= brd_id_test_count; ++brd_id) {
        cr_assert_eq(node_has_seen_brd_id(nid, brd_id), false);
        if (count < seen_brd_id_maxsize)
            count += 1;
        cr_assert_eq(nid->seen_brd_id_count, count);

        for (size_t i = 0; i < count; ++i) {
            for (int j = 0; j < 8; ++j)
                cr_assert_eq(node_has_seen_brd_id(nid, brd_id - i), true);
        }
        for (size_t i = 0; i < count; ++i)
            cr_assert_eq(nid->seen_brd_id[i], brd_id - i);
        for (size_t i = count; i < seen_brd_id_maxsize; ++i)
            cr_assert_eq(nid->seen_brd_id[i], 0);
    }

    for (brd_id = brd_id_test_count - seen_brd_id_maxsize; brd_id <= brd_id_test_count; ++brd_id)
        cr_assert_eq(node_has_seen_brd_id(nid, brd_id), false);

    free_node_tree();
}
