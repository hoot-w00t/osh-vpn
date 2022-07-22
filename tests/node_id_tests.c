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

Test(node_brd_id_was_seen, test_list,
    .init = init_node_tree,
    .fini = free_node_tree)
{
    const oshpacket_brd_id_t test_count = 8192;
    oshpacket_brd_id_t brd_id;
    oshpacket_brd_id_t popped;
    size_t count = 0;
    node_id_t *nid;

    // Initialize dummy node
    init_node_tree();
    nid = node_id_add("test_brd_id");
    cr_assert_not_null(nid);

    // Make sure that the seen_brd_id array is properly initialized
    cr_assert_null(nid->seen_brd_id);
    cr_assert_eq(nid->seen_brd_id_count, 0);

    // Try seeing test_count broadcast IDs
    for (brd_id = 1; brd_id <= test_count; ++brd_id) {
        cr_assert_eq(node_brd_id_was_seen(nid, brd_id), false);
        count += 1;
        cr_assert_eq(nid->seen_brd_id_count, count);

        for (size_t i = nid->seen_brd_id_count; i > 0; --i)
            cr_assert_eq(nid->seen_brd_id[i - 1].brd_id, i);
    }

    for (popped = 1; popped <= test_count; ++popped) {
        node_brd_id_pop(nid, 1);
        cr_assert_eq(nid->seen_brd_id_count, test_count - popped);

        for (size_t i = nid->seen_brd_id_count; i > 0; --i)
            cr_assert_eq(nid->seen_brd_id[i - 1].brd_id, popped + i);
    }

    cr_assert_null(nid->seen_brd_id);
    cr_assert_eq(nid->seen_brd_id_count, 0);

    for (size_t i = 0; i < 1024; ++i) {
        node_brd_id_pop(nid, i);
        cr_assert_null(nid->seen_brd_id);
        cr_assert_eq(nid->seen_brd_id_count, 0);
    }

    free_node_tree();
}
