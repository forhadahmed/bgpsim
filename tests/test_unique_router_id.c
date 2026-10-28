/*
 * BGP Unique Router ID Test Suite
 *
 * Tests automatic unique router ID assignment when no explicit router-id is configured.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "bgpsim.h"
#include "bgp_router.h"
#include "test_result.h"
#include "bgp_neighbor.h"

/*
 * test_result with the arguments in the order that this file uses.
 */
static void assert_test(const char *test_name, int condition) {
    test_result(condition, test_name);
}

static void format_router_id(uint32_t router_id, char *buf, size_t buf_size) {
    struct in_addr addr;

    addr.s_addr = htonl(router_id);
    inet_ntop(AF_INET, &addr, buf, buf_size);
}

static bgp_sim_t *create_test_sim(void) {
    bgp_sim_t *sim = calloc(1, sizeof(*sim));

    if (sim == NULL) {
        fprintf(stderr, "Failed to allocate simulator for test\n");
        exit(1);
    }

    bgp_init_simulator(sim);
    /*
     * Keep this test purely in-process: it validates router-id assignment,
     * not live router thread behavior. Force config-loading mode even when
     * the target is built standalone outside the unit-test wrapper.
     */
    sim->config_loading = 1;
    return sim;
}

static void destroy_test_sim(bgp_sim_t *sim) {
    if (sim == NULL) {
        return;
    }

    bgp_shutdown_sim(sim);
    free(sim);
}

static void test_first_router_id(void) {
    bgp_sim_t *sim = create_test_sim();
    char       router_id_str[INET_ADDRSTRLEN];
    int        condition;

    bgp_add_router(sim, 65001);
    format_router_id(sim->routers[0]->router_id, router_id_str, sizeof(router_id_str));

    condition = (strcmp(router_id_str, "10.0.1.1") == 0);
    assert_test("First router gets 10.0.1.1", condition);
    if (!condition) {
        printf("  Expected: 10.0.1.1, Got: %s\n", router_id_str);
    }

    destroy_test_sim(sim);
}

static void test_second_router_id(void) {
    bgp_sim_t *sim = create_test_sim();
    char       router_id_str[INET_ADDRSTRLEN];
    int        condition;

    bgp_add_router(sim, 65001);
    bgp_add_router(sim, 65002);
    format_router_id(sim->routers[1]->router_id, router_id_str, sizeof(router_id_str));

    condition = (strcmp(router_id_str, "10.0.1.2") == 0);
    assert_test("Second router gets 10.0.1.2", condition);
    if (!condition) {
        printf("  Expected: 10.0.1.2, Got: %s\n", router_id_str);
    }

    destroy_test_sim(sim);
}

static void test_multiple_unique_ids(void) {
    bgp_sim_t *sim = create_test_sim();
    const int  num_routers = 10;
    int        all_unique = 1;

    for (int i = 0; i < num_routers; i++) {
        bgp_add_router(sim, 65000 + i);
    }

    for (int i = 0; i < num_routers; i++) {
        for (int j = i + 1; j < num_routers; j++) {
            if (sim->routers[i]->router_id == sim->routers[j]->router_id) {
                char id_i[INET_ADDRSTRLEN];
                char id_j[INET_ADDRSTRLEN];

                all_unique = 0;
                format_router_id(sim->routers[i]->router_id, id_i, sizeof(id_i));
                format_router_id(sim->routers[j]->router_id, id_j, sizeof(id_j));
                printf("  Collision: Router %d (%s) == Router %d (%s)\n", i, id_i, j, id_j);
            }
        }
    }

    assert_test("Multiple routers have unique auto-generated IDs", all_unique);
    destroy_test_sim(sim);
}

static void test_same_as_suffix_unique_ids(void) {
    bgp_sim_t *sim = create_test_sim();
    char       id0[INET_ADDRSTRLEN];
    char       id1[INET_ADDRSTRLEN];
    int        condition;

    bgp_add_router(sim, 65001);
    bgp_add_router(sim, 65257);

    format_router_id(sim->routers[0]->router_id, id0, sizeof(id0));
    format_router_id(sim->routers[1]->router_id, id1, sizeof(id1));

    condition = (sim->routers[0]->router_id != sim->routers[1]->router_id);
    assert_test("Routers with same AS suffix get different IDs", condition);
    if (!condition) {
        printf("  Router 0 (AS 65001): %s\n", id0);
        printf("  Router 1 (AS 65257): %s\n", id1);
    }

    destroy_test_sim(sim);
}

static void test_many_routers_unique_ids(void) {
    bgp_sim_t *sim = create_test_sim();
    const int  num_routers = 1000;
    int        all_unique = 1;

    for (int i = 0; i < num_routers; i++) {
        if (bgp_add_router(sim, 65000 + i) != 1) all_unique = 0;
    }
    all_unique = all_unique && sim->router_count == num_routers;

    for (int i = 0; i < sim->router_count; i++) {
        for (int j = i + 1; j < sim->router_count; j++) {
            if (sim->routers[i]->router_id == sim->routers[j]->router_id) {
                char id_i[INET_ADDRSTRLEN];
                char id_j[INET_ADDRSTRLEN];

                all_unique = 0;
                format_router_id(sim->routers[i]->router_id, id_i, sizeof(id_i));
                format_router_id(sim->routers[j]->router_id, id_j, sizeof(id_j));
                printf("  Collision: Router %d (%s) == Router %d (%s)\n", i, id_i, j, id_j);
            }
        }
    }

    assert_test("Many routers (> 256) still get unique IDs", all_unique);
    destroy_test_sim(sim);
}

static void test_auto_ids_not_configured(void) {
    bgp_sim_t *sim = create_test_sim();
    int        condition;

    bgp_add_router(sim, 65001);
    condition = (sim->routers[0]->router_id_configured == 0);

    assert_test("router_id_configured flag is 0 for auto-generated IDs", condition);
    destroy_test_sim(sim);
}

static void test_manual_router_id_override(void) {
    bgp_sim_t *sim = create_test_sim();
    char       router_id_str[INET_ADDRSTRLEN];
    int        condition;

    bgp_add_router(sim, 65001);
    bgp_set_router_id(sim, 65001, "192.168.100.1");
    format_router_id(sim->routers[0]->router_id, router_id_str, sizeof(router_id_str));

    condition = (strcmp(router_id_str, "192.168.100.1") == 0) &&
                (sim->routers[0]->router_id_configured == 1);
    assert_test("Manual router-id overrides auto-generated ID", condition);
    if (!condition) {
        printf("  Expected: 192.168.100.1 (configured=1)\n");
        printf("  Got: %s (configured=%d)\n", router_id_str, sim->routers[0]->router_id_configured);
    }

    destroy_test_sim(sim);
}

static void test_mixed_manual_and_auto_ids(void) {
    bgp_sim_t *sim = create_test_sim();
    char       id0[INET_ADDRSTRLEN];
    char       id1[INET_ADDRSTRLEN];
    char       id2[INET_ADDRSTRLEN];
    int        condition;

    bgp_add_router(sim, 65001);
    bgp_add_router(sim, 65002);
    bgp_set_router_id(sim, 65002, "1.2.3.4");
    bgp_add_router(sim, 65003);

    format_router_id(sim->routers[0]->router_id, id0, sizeof(id0));
    format_router_id(sim->routers[1]->router_id, id1, sizeof(id1));
    format_router_id(sim->routers[2]->router_id, id2, sizeof(id2));

    condition = (strcmp(id0, "10.0.1.1") == 0) &&
                (strcmp(id1, "1.2.3.4") == 0) &&
                (strcmp(id2, "10.0.1.3") == 0) &&
                (sim->routers[0]->router_id_configured == 0) &&
                (sim->routers[1]->router_id_configured == 1) &&
                (sim->routers[2]->router_id_configured == 0);

    assert_test("Mixed manual and auto-generated IDs work together", condition);
    if (!condition) {
        printf("  Router 0: %s (configured=%d, expected 10.0.1.1, configured=0)\n",
               id0, sim->routers[0]->router_id_configured);
        printf("  Router 1: %s (configured=%d, expected 1.2.3.4, configured=1)\n",
               id1, sim->routers[1]->router_id_configured);
        printf("  Router 2: %s (configured=%d, expected 10.0.1.3, configured=0)\n",
               id2, sim->routers[2]->router_id_configured);
    }

    destroy_test_sim(sim);
}

static void test_collision_fallback_id(void) {
    bgp_sim_t *sim = create_test_sim();
    char       id0[INET_ADDRSTRLEN];
    char       id1[INET_ADDRSTRLEN];
    char       id2[INET_ADDRSTRLEN];
    int        condition;

    bgp_add_router(sim, 65001);
    bgp_add_router(sim, 65002);
    bgp_set_router_id(sim, 65002, "10.0.1.3");
    bgp_add_router(sim, 65003);

    format_router_id(sim->routers[0]->router_id, id0, sizeof(id0));
    format_router_id(sim->routers[1]->router_id, id1, sizeof(id1));
    format_router_id(sim->routers[2]->router_id, id2, sizeof(id2));

    condition = (strcmp(id2, "192.168.1.3") == 0);
    assert_test("Auto-generated ID uses fallback when collision detected", condition);
    if (!condition) {
        printf("  Router 0: %s\n", id0);
        printf("  Router 1: %s (manual)\n", id1);
        printf("  Router 2: %s (expected 192.168.1.3 due to collision)\n", id2);
    }

    destroy_test_sim(sim);
}

static void test_router_id_pattern(void) {
    bgp_sim_t *sim = create_test_sim();
    int test_indices[] = {0, 1, 5, 10, 100, 255, 256, 257};
    int  num_tests = (int)(sizeof(test_indices) / sizeof(test_indices[0]));
    int  condition;
    int  last_idx;
    char expected_id[INET_ADDRSTRLEN];
    char actual_id[INET_ADDRSTRLEN];

    for (int i = 0; i < num_tests; i++) {
        for (int j = sim->router_count; j <= test_indices[i]; j++) {
            bgp_add_router(sim, 65000 + j);
        }

        format_router_id(UINT32_C(0x0a000101) + (uint32_t)test_indices[i], expected_id, sizeof(expected_id));
        format_router_id(sim->routers[test_indices[i]]->router_id, actual_id, sizeof(actual_id));

        if (strcmp(expected_id, actual_id) != 0) {
            printf("  Router %d: Expected %s, Got %s\n", test_indices[i], expected_id, actual_id);
        }
    }

    last_idx = sim->router_count - 1;
    format_router_id(UINT32_C(0x0a000101) + (uint32_t)last_idx, expected_id, sizeof(expected_id));
    format_router_id(sim->routers[last_idx]->router_id, actual_id, sizeof(actual_id));

    condition = (strcmp(expected_id, actual_id) == 0);
    assert_test("Router ID follows 10.0.X.Y pattern correctly", condition);
    destroy_test_sim(sim);
}

int main(void) {
    printf("========================================\n");
    printf("BGP Unique Router ID Test Suite\n");
    printf("========================================\n\n");

    test_first_router_id();
    test_second_router_id();
    test_multiple_unique_ids();
    test_same_as_suffix_unique_ids();
    test_many_routers_unique_ids();
    test_auto_ids_not_configured();
    test_manual_router_id_override();
    test_mixed_manual_and_auto_ids();
    test_collision_fallback_id();
    test_router_id_pattern();

    printf("\n========================================\n");
    printf("Test Summary\n");
    printf("========================================\n");
    printf("Total tests run:    %d\n", tests_passed + tests_failed);
    printf("Tests passed:       %d\n", tests_passed);
    printf("Tests failed:       %d\n", tests_failed);
    printf("========================================\n\n");

    if (tests_failed == 0) {
        printf("%s %s\n\n", TEST_BADGE_PASS, "All tests passed!");
        return 0;
    }

    printf("%s %s\n\n", TEST_BADGE_FAIL, "Some tests failed");
    return 1;
}
