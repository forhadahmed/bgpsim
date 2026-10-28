/*
 * BGP RIB-OUT Generator Unit Tests
 * Comprehensive testing of prefix generation, path attributes, and iterator pattern
 */

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "bgpsim.h"
#include "bgp_ribout.h"
#include "test_result.h"
#include "test_helpers.h"
#include "bgp_ribout_config.h"

#define TEST_ASSERT(condition, message) test_result((condition), (message))

static void test_compact_inventories(void) {
    static const struct {
        const char *keyword, *value;
        uint32_t    count, last;
        uint32_t (*at)(const bgp_ribout_config_t *, uint32_t);
    } cases[] = {
        {"path-id", "0 x 1000000", 1000000, 999999, bgp_ribout_path_ids_at},
        {"label", "16 x 1000", 1000, 1015, bgp_ribout_labels_at},
        {"label2", "16 x 1000", 1000, 1015, bgp_ribout_label2s_at},
        {"ethernet-tag", "1 x 640", 640, 640, bgp_ribout_ethernet_tags_at},
        {"distinguisher", "1 x 20480", 20480, 20480, bgp_ribout_distinguishers_at},
        {"color", "1 x 1000000 co 01", 1000000, 1000000, bgp_ribout_colors_at},
        {"preference", "1 x 20480", 20480, 20480, bgp_ribout_preferences_at},
        {"binding-sid", "mpls 16 x 20480", 20480, 20495, bgp_ribout_binding_sids_at},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); i++) {
        bgp_ribout_config_t block;
        bgp_ribout_init(&block, "compact");
        int                  parsed = bgp_ribout_edit(&block, cases[i].keyword, cases[i].value, 0) == 0;
        bgp_ribout_config_t *copy = parsed ? bgp_ribout_config_clone(&block) : NULL;
        int valid = copy && cases[i].at(&block, cases[i].count - 1) == cases[i].last &&
                    cases[i].at(copy, cases[i].count - 1) == cases[i].last &&
                    bgp_ribout_config_bytes(&block) < sizeof(block) + 256 &&
                    bgp_ribout_config_bytes(copy) < sizeof(block) + 256;
        if (valid) valid = bgp_ribout_edit(&block, cases[i].keyword, "", 1) == 0 &&
                           cases[i].at(copy, cases[i].count - 1) == cases[i].last;
        TEST_ASSERT(valid, cases[i].keyword);
        bgp_ribout_config_clone_free(copy);
        bgp_ribout_destroy(&block);
    }
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "rd-scale");
    int                   parsed = bgp_ribout_edit(&block, "rd", "65000:1 x 1000000", 0) == 0;
    route_distinguisher_t expected = rd_create_type0(65000, 1000000);
    route_distinguisher_t last = parsed ? bgp_ribout_rds_at(&block, 999999) : (route_distinguisher_t){0};
    TEST_ASSERT(parsed && !memcmp(&last, &expected, sizeof(last)) &&
                bgp_ribout_config_bytes(&block) < sizeof(block) + 256,
                "One million RDs retain only the base and count");
    bgp_ribout_destroy(&block);
}

static int test_binding_sid_is_mpls(const srpolicy_binding_sid_t *binding_sid, uint32_t label) {
    return binding_sid &&
           binding_sid->type == SRPOLICY_BINDING_SID_MPLS &&
           binding_sid->mpls_label == label;
}

static int test_binding_sid_equal(const srpolicy_binding_sid_t *a, const srpolicy_binding_sid_t *b) {
    if (!a || !b || a->type != b->type || a->flags != b->flags) {
        return 0;
    }

    if (a->type == SRPOLICY_BINDING_SID_MPLS) {
        return a->mpls_label == b->mpls_label;
    }
    if (a->type == SRPOLICY_BINDING_SID_SRV6) {
        return memcmp(a->srv6_sid, b->srv6_sid, sizeof(a->srv6_sid)) == 0;
    }

    return 1;
}

static uint16_t test_read_u16_be(const uint8_t *ptr) {
    return (uint16_t)(((uint16_t)ptr[0] << 8) | ptr[1]);
}

/*
 * Test 1: IPv4 Prefix Parsing and Generation
 */
void test_ipv4_prefix_parsing() {
    printf("\n=== Test 1: IPv4 Prefix Parsing and Generation ===\n");

    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test1");

    // Parse prefix
    int result = bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/16 x 5");
    TEST_ASSERT(result == 0, "Parse IPv4 prefix syntax");
    TEST_ASSERT(block.prefix_spec.af == AF_INET, "IPv4 address family detected");
    TEST_ASSERT(block.prefix_spec.prefix_len == 16, "Prefix length is 16");
    TEST_ASSERT(block.prefix_spec.count == 5, "Prefix count is 5");

    // Generate prefixes
    char prefix_str[MAX_PREFIX_STRING_LEN];

    bgp_prefix_to_string(&block.prefix_spec, 0, prefix_str, sizeof(prefix_str));
    TEST_ASSERT(strcmp(prefix_str, "10.0.0.0/16") == 0, "First prefix is 10.0.0.0/16");

    // Each index is one whole /16 block further on.
    bgp_prefix_to_string(&block.prefix_spec, 1, prefix_str, sizeof(prefix_str));
    TEST_ASSERT(strcmp(prefix_str, "10.1.0.0/16") == 0, "Second prefix is 10.1.0.0/16");

    bgp_prefix_to_string(&block.prefix_spec, 4, prefix_str, sizeof(prefix_str));
    TEST_ASSERT(strcmp(prefix_str, "10.4.0.0/16") == 0, "Fifth prefix is 10.4.0.0/16");
    bgp_ribout_destroy(&block);
}

/*
 * Test 2: IPv6 Prefix Parsing and Generation
 */
void test_ipv6_prefix_parsing() {
    printf("\n=== Test 2: IPv6 Prefix Parsing and Generation ===\n");

    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test2");

    // Parse prefix
    int result = bgp_ribout_parse_prefix(&block, "prefix 2001:db8::/32 x 3");
    TEST_ASSERT(result == 0, "Parse IPv6 prefix syntax");
    TEST_ASSERT(block.prefix_spec.af == AF_INET6, "IPv6 address family detected");
    TEST_ASSERT(block.prefix_spec.prefix_len == 32, "Prefix length is 32");
    TEST_ASSERT(block.prefix_spec.count == 3, "Prefix count is 3");

    // Generate prefixes
    char prefix_str[MAX_PREFIX_STRING_LEN];

    bgp_prefix_to_string(&block.prefix_spec, 0, prefix_str, sizeof(prefix_str));
    TEST_ASSERT(strstr(prefix_str, "2001:db8::") != NULL, "First prefix contains 2001:db8::");

    // Each index is one whole /32 block further on.
    bgp_prefix_to_string(&block.prefix_spec, 1, prefix_str, sizeof(prefix_str));
    TEST_ASSERT(strcmp(prefix_str, "2001:db9::/32") == 0, "Second prefix is 2001:db9::/32");

    bgp_prefix_to_string(&block.prefix_spec, 2, prefix_str, sizeof(prefix_str));
    TEST_ASSERT(strcmp(prefix_str, "2001:dba::/32") == 0, "Third prefix is 2001:dba::/32");
    bgp_ribout_destroy(&block);
}

/*
 * Test 3: Path-ID List Parsing and Cycling
 */
void test_path_id_parsing() {
    printf("\n=== Test 3: Path-ID List Parsing and Cycling ===\n");

    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test3");

    // Parse path-id list
    int result = bgp_ribout_parse_path_ids(&block, "path-id 0 1 2 3");
    TEST_ASSERT(result == 0, "Parse path-id list");
    TEST_ASSERT(block.path_id_count == 4, "Path-ID count is 4");
    TEST_ASSERT(bgp_ribout_path_ids_at(&block, 0) == 0, "First path-id is 0");
    TEST_ASSERT(bgp_ribout_path_ids_at(&block, 1) == 1, "Second path-id is 1");
    TEST_ASSERT(bgp_ribout_path_ids_at(&block, 2) == 2, "Third path-id is 2");
    TEST_ASSERT(bgp_ribout_path_ids_at(&block, 3) == 3, "Fourth path-id is 3");

    // Test single path-id
    bgp_ribout_destroy(&block);
    bgp_ribout_init(&block, "test3b");
    result = bgp_ribout_parse_path_ids(&block, "path-id 100");
    TEST_ASSERT(result == 0, "Parse single path-id");
    TEST_ASSERT(block.path_id_count == 1, "Path-ID count is 1");
    TEST_ASSERT(bgp_ribout_path_ids_at(&block, 0) == 100, "Path-id is 100");
    bgp_ribout_destroy(&block);
}

/*
 * Test 4: Next-hop Parsing (Single IP)
 */
void test_next_hop_single_ip() {
    printf("\n=== Test 4: Next-hop Parsing (Single IP) ===\n");

    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test4");

    // Set up prefix first (required for AF matching)
    bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/24 x 10");

    // Parse single next_hop
    int result = bgp_ribout_parse_next_hop(&block, "next-hop 192.168.1.1");
    TEST_ASSERT(result == 0, "Parse single next_hop IP");
    TEST_ASSERT(block.next_hop_spec.af == AF_INET, "Next-hop is IPv4");
    TEST_ASSERT(block.next_hop_spec.count == 1, "Next-hop count is 1");

    // Generate next_hop
    char nh_str[MAX_PREFIX_STRING_LEN];
    bgp_next_hop_to_string(&block.next_hop_spec, 0, nh_str, sizeof(nh_str));
    TEST_ASSERT(strcmp(nh_str, "192.168.1.1") == 0, "Next-hop string is correct");

    bgp_next_hop_to_string(&block.next_hop_spec, 5, nh_str, sizeof(nh_str));
    TEST_ASSERT(strcmp(nh_str, "192.168.1.1") == 0, "Next-hop wraps to same value");
    bgp_ribout_destroy(&block);
}

/*
 * Test 5: Next-hop Parsing (Prefix with Multiple and Wrapping)
 */
void test_next_hop_wrapping() {
    printf("\n=== Test 5: Next-hop Parsing (Prefix with Multiple and Wrapping) ===\n");

    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test5");

    // Set up prefix first
    bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/24 x 10");

    // Parse next_hop as prefix with count
    int result = bgp_ribout_parse_next_hop(&block, "next-hop 192.168.1.1 x 3");
    TEST_ASSERT(result == 0, "Parse next_hop prefix with count");
    TEST_ASSERT(block.next_hop_spec.count == 3, "Next-hop count is 3");

    // Generate next_hops with wrapping
    char nh_str[MAX_PREFIX_STRING_LEN];

    bgp_next_hop_to_string(&block.next_hop_spec, 0, nh_str, sizeof(nh_str));
    TEST_ASSERT(strcmp(nh_str, "192.168.1.1") == 0, "First next_hop is 192.168.1.1");

    bgp_next_hop_to_string(&block.next_hop_spec, 1, nh_str, sizeof(nh_str));
    TEST_ASSERT(strcmp(nh_str, "192.168.1.2") == 0, "Second next_hop is 192.168.1.2");

    bgp_next_hop_to_string(&block.next_hop_spec, 2, nh_str, sizeof(nh_str));
    TEST_ASSERT(strcmp(nh_str, "192.168.1.3") == 0, "Third next_hop is 192.168.1.3");

    // Test wrapping
    bgp_next_hop_to_string(&block.next_hop_spec, 3, nh_str, sizeof(nh_str));
    TEST_ASSERT(strcmp(nh_str, "192.168.1.1") == 0, "Fourth next_hop wraps to 192.168.1.1");

    bgp_next_hop_to_string(&block.next_hop_spec, 4, nh_str, sizeof(nh_str));
    TEST_ASSERT(strcmp(nh_str, "192.168.1.2") == 0, "Fifth next_hop wraps to 192.168.1.2");
    bgp_ribout_destroy(&block);
}

/*
 * Test 6: AS-Path Parsing (Sequence)
 */
void test_aspath_sequence() {
    printf("\n=== Test 6: AS-Path Parsing (Sequence) ===\n");

    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test6");

    // Parse AS sequence
    int result = bgp_ribout_parse_aspath(&block, "as-path 100 200 300");
    TEST_ASSERT(result == 0, "Parse AS-path sequence");
    TEST_ASSERT(block.aspath_segment_count == 1, "One AS-path segment");
    TEST_ASSERT(block.aspath_segments[0].type == ASPATH_SEQUENCE, "Segment is sequence type");
    TEST_ASSERT(block.aspath_segments[0].value_count == 3, "Sequence has 3 values");
    TEST_ASSERT(block.aspath_segments[0].as_values[0] == 100, "First AS is 100");
    TEST_ASSERT(block.aspath_segments[0].as_values[1] == 200, "Second AS is 200");
    TEST_ASSERT(block.aspath_segments[0].as_values[2] == 300, "Third AS is 300");

    // Generate AS-path string
    char aspath_str[MAX_ASPATH_STRING_LEN];
    bgp_aspath_to_string(block.aspath_segments, block.aspath_segment_count, aspath_str, sizeof(aspath_str));
    TEST_ASSERT(strcmp(aspath_str, "100 200 300") == 0, "AS-path string is correct");
    bgp_ribout_destroy(&block);
}

/*
 * Test 7: AS-Path Parsing (AS Set)
 */
void test_aspath_set() {
    printf("\n=== Test 7: AS-Path Parsing (AS Set) ===\n");

    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test7");

    // Parse AS set
    int result = bgp_ribout_parse_aspath(&block, "as-path { 10 20 30 }");
    TEST_ASSERT(result == 0, "Parse AS-path set");
    TEST_ASSERT(block.aspath_segment_count == 1, "One AS-path segment");
    TEST_ASSERT(block.aspath_segments[0].type == ASPATH_SET, "Segment is set type");
    TEST_ASSERT(block.aspath_segments[0].value_count == 3, "Set has 3 values");

    // Generate AS-path string
    char aspath_str[MAX_ASPATH_STRING_LEN];
    bgp_aspath_to_string(block.aspath_segments, block.aspath_segment_count, aspath_str, sizeof(aspath_str));
    TEST_ASSERT(strstr(aspath_str, "{") != NULL, "AS-path contains opening brace");
    TEST_ASSERT(strstr(aspath_str, "}") != NULL, "AS-path contains closing brace");
    TEST_ASSERT(strstr(aspath_str, "10") != NULL, "AS-path contains 10");
    TEST_ASSERT(strstr(aspath_str, "20") != NULL, "AS-path contains 20");
    TEST_ASSERT(strstr(aspath_str, "30") != NULL, "AS-path contains 30");
    bgp_ribout_destroy(&block);
}

/*
 * Test 8: AS-Path Parsing (Random Segment)
 */
void test_aspath_random() {
    printf("\n=== Test 8: AS-Path Parsing (Random Segment) ===\n");

    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test8");

    // Parse random AS segment
    int result = bgp_ribout_parse_aspath(&block, "as-path [rand(100) x 5]");
    TEST_ASSERT(result == 0, "Parse random AS-path segment");
    TEST_ASSERT(block.aspath_segment_count == 1, "One AS-path segment");
    TEST_ASSERT(block.aspath_segments[0].type == ASPATH_RANDOM, "Segment is random type");
    TEST_ASSERT(block.aspath_segments[0].rand_max == 100, "Random max is 100");
    TEST_ASSERT(block.aspath_segments[0].rand_count == 5, "Random count is 5");

    /*
     * Random AS-path segments stay symbolic until a concrete generated path
     * resolves them through the per-ribout RNG.
     */
    char aspath_str[MAX_ASPATH_STRING_LEN];
    bgp_aspath_to_string(block.aspath_segments, block.aspath_segment_count, aspath_str, sizeof(aspath_str));
    TEST_ASSERT(strcmp(aspath_str, "[rand(100) x 5]") == 0, "Random AS-path string preserves symbolic rand() syntax");
    bgp_ribout_destroy(&block);
}

/*
 * Test 8a: AS-Path Parsing (Random Segment Shorthand)
 */
void test_aspath_random_shorthand() {
    printf("\n=== Test 8a: AS-Path Parsing (Random Segment Shorthand) ===\n");

    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test8a");

    // Parse shorthand random AS segment: rand(N) is equivalent to [rand(N) x 1]
    int result = bgp_ribout_parse_aspath(&block, "as-path rand(50)");
    TEST_ASSERT(result == 0, "Parse shorthand random AS-path segment");
    TEST_ASSERT(block.aspath_segment_count == 1, "One AS-path segment");
    TEST_ASSERT(block.aspath_segments[0].type == ASPATH_RANDOM, "Segment is random type");
    TEST_ASSERT(block.aspath_segments[0].rand_max == 50, "Random max is 50");
    TEST_ASSERT(block.aspath_segments[0].rand_count == 1, "Random count is 1 (shorthand default)");

    // Shorthand random segments also stay symbolic until generation time.
    char aspath_str[MAX_ASPATH_STRING_LEN];
    bgp_aspath_to_string(block.aspath_segments, block.aspath_segment_count, aspath_str, sizeof(aspath_str));
    TEST_ASSERT(strcmp(aspath_str, "rand(50)") == 0,
                "Shorthand random AS-path string preserves symbolic rand() syntax");

    // Test mixed form: sequence + shorthand random
    bgp_ribout_destroy(&block);
    bgp_ribout_init(&block, "test8b");
    result = bgp_ribout_parse_aspath(&block, "as-path 100 200 rand(75)");
    TEST_ASSERT(result == 0, "Parse sequence + shorthand random");
    TEST_ASSERT(block.aspath_segment_count == 2, "Two AS-path segments");
    TEST_ASSERT(block.aspath_segments[0].type == ASPATH_SEQUENCE, "First segment is sequence");
    TEST_ASSERT(block.aspath_segments[1].type == ASPATH_RANDOM, "Second segment is random");
    TEST_ASSERT(block.aspath_segments[1].rand_max == 75, "Random max is 75");
    TEST_ASSERT(block.aspath_segments[1].rand_count == 1, "Random count is 1");
    bgp_ribout_destroy(&block);
}

/*
 * Test 9: AS-Path Parsing (Mixed Segments)
 */
void test_aspath_mixed() {
    printf("\n=== Test 9: AS-Path Parsing (Mixed Segments) ===\n");

    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test9");

    // Parse mixed AS-path
    int result = bgp_ribout_parse_aspath(&block, "as-path 100 200 { 10 20 } [rand(50) x 3]");
    TEST_ASSERT(result == 0, "Parse mixed AS-path");
    TEST_ASSERT(block.aspath_segment_count == 3, "Three AS-path segments");

    TEST_ASSERT(block.aspath_segments[0].type == ASPATH_SEQUENCE, "First segment is sequence");
    TEST_ASSERT(block.aspath_segments[0].value_count == 2, "First segment has 2 values");

    TEST_ASSERT(block.aspath_segments[1].type == ASPATH_SET, "Second segment is set");
    TEST_ASSERT(block.aspath_segments[1].value_count == 2, "Second segment has 2 values");

    TEST_ASSERT(block.aspath_segments[2].type == ASPATH_RANDOM, "Third segment is random");
    TEST_ASSERT(block.aspath_segments[2].rand_count == 3, "Random segment has 3 AS numbers");
    bgp_ribout_destroy(&block);
}

/*
 * Test 10: Local Preference (Fixed Value)
 */
void test_localpref_fixed() {
    printf("\n=== Test 10: Local Preference (Fixed Value) ===\n");

    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test10");

    // Parse fixed localpref
    int result = bgp_ribout_parse_localpref(&block, "localpref 150");
    TEST_ASSERT(result == 0, "Parse fixed localpref");
    TEST_ASSERT(block.localpref_spec.mode == BGP_U32_MODE_FIXED, "Localpref is fixed type");
    TEST_ASSERT(block.localpref_spec.value == 150, "Localpref value is 150");
    bgp_ribout_destroy(&block);
}

/*
 * Test 11: Local Preference (Random Value)
 */
void test_localpref_random() {
    printf("\n=== Test 11: Local Preference (Random Value) ===\n");

    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test11");

    // Parse random localpref
    int result = bgp_ribout_parse_localpref(&block, "localpref rand(500)");
    TEST_ASSERT(result == 0, "Parse random localpref");
    TEST_ASSERT(block.localpref_spec.mode == BGP_U32_MODE_RANDOM, "Localpref is random type");
    TEST_ASSERT(block.localpref_spec.value == 500, "Localpref max is 500");
    bgp_ribout_destroy(&block);
}

/*
 * Test 11a: Local Preference (Deterministic Range)
 */
void test_localpref_range() {
    printf("\n=== Test 11a: Local Preference (Deterministic Range) ===\n");

    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;
    bgp_gen_path_t      path1;
    bgp_gen_path_t      path2;
    bgp_gen_path_t      path3;

    bgp_ribout_init(&block, "test11a");
    bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/24 x 3");

    TEST_ASSERT(bgp_ribout_parse_localpref(&block, "localpref range(150,152)") == 0, "Parse ranged localpref");
    TEST_ASSERT(block.localpref_spec.mode == BGP_U32_MODE_RANGE, "Localpref is range type");
    TEST_ASSERT(block.localpref_spec.range_start == 150 &&
                block.localpref_spec.range_end == 152,
                "Localpref range bounds are stored");

    TEST_ASSERT(bgp_ribout_generator_init(&gen, &block) == 0, "Range localpref generator initializes");
    TEST_ASSERT(bgp_ribout_generator_next(&gen, &path1) == 0 &&
                bgp_ribout_generator_next(&gen, &path2) == 0 &&
                bgp_ribout_generator_next(&gen, &path3) == 0,
                "Range localpref generator produces three paths");
    TEST_ASSERT(path1.local_pref == 150 &&
                path2.local_pref == 151 &&
                path3.local_pref == 152,
                "Localpref range rotates deterministically across paths");
    bgp_ribout_destroy(&block);
}

/*
 * Test 11b: Local Preference (Random Range)
 */
void test_localpref_randrange() {
    printf("\n=== Test 11b: Local Preference (Random Range) ===\n");

    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;
    bgp_gen_path_t      path1;
    bgp_gen_path_t      path2;
    test_env_guard_t    randseed_guard;

    test_env_guard_capture(&randseed_guard, "RANDSEED");
    setenv("RANDSEED", "111", 1);
    bgp_ribout_init(&block, "test11b");
    bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/24 x 2");

    TEST_ASSERT(bgp_ribout_parse_localpref(&block, "localpref randrange(200,300)") == 0, "Parse localpref randrange");
    TEST_ASSERT(block.localpref_spec.mode == BGP_U32_MODE_RANDOM_RANGE, "Localpref is random-range type");
    TEST_ASSERT(block.localpref_spec.range_start == 200 &&
                block.localpref_spec.range_end == 300,
                "Localpref random-range bounds are stored");

    TEST_ASSERT(bgp_ribout_generator_init(&gen, &block) == 0, "Randrange localpref generator initializes");
    TEST_ASSERT(bgp_ribout_generator_next(&gen, &path1) == 0, "Randrange localpref generator produces first path");
    TEST_ASSERT(path1.local_pref >= 200 && path1.local_pref <= 300,
                "Randrange localpref stays within configured bounds");

    bgp_ribout_generator_reset(&gen);
    TEST_ASSERT(bgp_ribout_generator_next(&gen, &path2) == 0, "Randrange localpref reproduces first path after reset");
    TEST_ASSERT(path1.local_pref == path2.local_pref, "Seeded localpref randrange is deterministic");
    test_env_guard_restore(&randseed_guard, "RANDSEED");
    bgp_ribout_destroy(&block);
}

void test_full_width_random_range() {
    printf("\n=== Full-width uint32 random ranges ===\n");
    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;
    bgp_gen_path_t      paths[4];
    int                 ok = 1;

    bgp_ribout_init(&block, "full-width");
    TEST_ASSERT(bgp_ribout_edit(&block, "distinguisher", "1", 0) == 0 &&
                bgp_ribout_edit(&block, "color", "100", 0) == 0 &&
                bgp_ribout_edit(&block, "endpoint", "192.0.2.1 x 4", 0) == 0 &&
                bgp_ribout_edit(&block, "rt", "192.0.2.1:100", 0) == 0 &&
                bgp_ribout_edit(&block, "segment-list", "1 weight 1 mpls 16001", 0) == 0 &&
                bgp_ribout_edit(&block, "localpref", "randrange(0,4294967295)", 0) == 0 &&
                bgp_ribout_edit(&block, "med", "randrange(0,4294967295)", 0) == 0 &&
                bgp_ribout_edit(&block, "preference", "randrange(0,4294967295)", 0) == 0 &&
                bgp_ribout_generator_init(&gen, &block) == 0,
                "All uint32 attributes accept the full random range");
    for (size_t i = 0; i < 4; i++) {
        ok &= bgp_ribout_generator_next(&gen, &paths[i]) == 0 && paths[i].has_med && paths[i].has_preference;
    }
    TEST_ASSERT(ok && !bgp_ribout_generator_has_next(&gen), "Full-width ranges generate every path without a fault");
    TEST_ASSERT(paths[0].local_pref != paths[1].local_pref && paths[0].med != paths[1].med &&
                paths[0].preference != paths[1].preference,
                "Full-width random values advance rather than collapsing to a fixed value");
    bgp_ribout_generator_reset(&gen);
    bgp_gen_path_t replay;
    TEST_ASSERT(bgp_ribout_generator_next(&gen, &replay) == 0 && replay.local_pref == paths[0].local_pref &&
                replay.med == paths[0].med && replay.preference == paths[0].preference,
                "Reset reproduces the full-width random sequence");
    TEST_ASSERT(bgp_ribout_edit(&block, "localpref", "randrange(4294967295,4294967295)", 0) == 0 &&
                bgp_ribout_edit(&block, "med", "randrange(0,0)", 0) == 0 &&
                bgp_ribout_generator_init(&gen, &block) == 0 &&
                bgp_ribout_generator_next(&gen, &replay) == 0 && replay.local_pref == UINT32_MAX && replay.med == 0,
                "Single-value random ranges preserve zero and UINT32_MAX");
    bgp_ribout_destroy(&block);
}

/*
 * Test 12: Origin Attribute Parsing
 */
void test_origin_parsing() {
    printf("\n=== Test 12: Origin Attribute Parsing ===\n");

    bgp_ribout_config_t block;

    // Test IGP
    bgp_ribout_init(&block, "test12a");
    int result = bgp_ribout_parse_origin(&block, "origin igp");
    TEST_ASSERT(result == 0, "Parse origin IGP");
    TEST_ASSERT(block.origin == ORIGIN_IGP, "Origin is IGP");
    TEST_ASSERT(strcmp(bgp_origin_to_string(block.origin), "igp") == 0, "Origin string is 'igp'");

    // Test EGP
    bgp_ribout_init(&block, "test12b");
    result = bgp_ribout_parse_origin(&block, "origin egp");
    TEST_ASSERT(result == 0, "Parse origin EGP");
    TEST_ASSERT(block.origin == ORIGIN_EGP, "Origin is EGP");
    TEST_ASSERT(strcmp(bgp_origin_to_string(block.origin), "egp") == 0, "Origin string is 'egp'");

    // Test Incomplete
    bgp_ribout_init(&block, "test12c");
    result = bgp_ribout_parse_origin(&block, "origin incomplete");
    TEST_ASSERT(result == 0, "Parse origin Incomplete");
    TEST_ASSERT(block.origin == ORIGIN_INCOMPLETE, "Origin is Incomplete");
    TEST_ASSERT(strcmp(bgp_origin_to_string(block.origin), "incomplete") == 0, "Origin string is 'incomplete'");
    bgp_ribout_destroy(&block);
}

/*
 * Test 13: Generator Initialization and Total Path Count
 */
void test_generator_init() {
    printf("\n=== Test 13: Generator Initialization and Total Path Count ===\n");

    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;

    bgp_ribout_init(&block, "test13");
    bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/24 x 10");
    bgp_ribout_parse_path_ids(&block, "path-id 0 1 2 3");

    int result = bgp_ribout_generator_init(&gen, &block);
    TEST_ASSERT(result == 0, "Generator initialization successful");
    TEST_ASSERT(gen.initialized == 1, "Generator marked as initialized");
    TEST_ASSERT(gen.total_paths == 40, "Total paths = 10 prefixes × 4 path-ids = 40");
    TEST_ASSERT(bgp_ribout_gen_total_paths(&gen) == 40, "Total paths getter returns 40");
    bgp_ribout_destroy(&block);
}

/*
 * Test 14: Generator Path Iteration (Basic)
 */
void test_generator_iteration() {
    printf("\n=== Test 14: Generator Path Iteration (Basic) ===\n");

    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;
    bgp_gen_path_t      path;

    bgp_ribout_init(&block, "test14");
    bgp_ribout_parse_prefix(&block, "prefix 192.168.0.0/24 x 3");
    bgp_ribout_parse_path_ids(&block, "path-id 10 20");
    bgp_ribout_parse_next_hop(&block, "next-hop 10.0.0.1");
    bgp_ribout_parse_aspath(&block, "as-path 100 200");
    bgp_ribout_parse_localpref(&block, "localpref 150");
    bgp_ribout_parse_origin(&block, "origin igp");

    bgp_ribout_generator_init(&gen, &block);

    // Total should be 3 prefixes × 2 path-ids = 6 paths
    TEST_ASSERT(gen.total_paths == 6, "Total paths is 6");

    // Iterate through all paths
    int count = 0;
    while (bgp_ribout_generator_has_next(&gen)) {
        int result = bgp_ribout_generator_next(&gen, &path);
        TEST_ASSERT(result == 0, "Generator next() successful");
        count++;
    }

    TEST_ASSERT(count == 6, "Generated 6 paths");
    TEST_ASSERT(!bgp_ribout_generator_has_next(&gen), "Generator exhausted after 6 paths");
    bgp_ribout_destroy(&block);
}

/*
 * Test 15: Generator Path-ID Cycling
 */
void test_generator_path_id_cycling() {
    printf("\n=== Test 15: Generator Path-ID Cycling ===\n");

    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;
    bgp_gen_path_t      path;
    char                prefix_str[64];

    bgp_ribout_init(&block, "test15");
    bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/24 x 2");
    bgp_ribout_parse_path_ids(&block, "path-id 100 200 300");
    bgp_ribout_parse_next_hop(&block, "next-hop 1.1.1.1");
    bgp_ribout_parse_aspath(&block, "as-path 1000");

    bgp_ribout_generator_init(&gen, &block);

    // Path 1: prefix=10.0.0.0/24, path-id=100
    bgp_ribout_generator_next(&gen, &path);
    test_path_prefix_to_string(&path, prefix_str, sizeof(prefix_str));
    TEST_ASSERT(strcmp(prefix_str, "10.0.0.0/24") == 0, "Path 1: prefix is 10.0.0.0/24");
    TEST_ASSERT(path.path_id == 100, "Path 1: path-id is 100");

    // Path 2: prefix=10.0.0.0/24, path-id=200
    bgp_ribout_generator_next(&gen, &path);
    test_path_prefix_to_string(&path, prefix_str, sizeof(prefix_str));
    TEST_ASSERT(strcmp(prefix_str, "10.0.0.0/24") == 0, "Path 2: prefix is 10.0.0.0/24");
    TEST_ASSERT(path.path_id == 200, "Path 2: path-id is 200");

    // Path 3: prefix=10.0.0.0/24, path-id=300
    bgp_ribout_generator_next(&gen, &path);
    test_path_prefix_to_string(&path, prefix_str, sizeof(prefix_str));
    TEST_ASSERT(strcmp(prefix_str, "10.0.0.0/24") == 0, "Path 3: prefix is 10.0.0.0/24");
    TEST_ASSERT(path.path_id == 300, "Path 3: path-id is 300");

    // Path 4: prefix=10.0.1.0/24, path-id=100 (wraps to first path-id)
    bgp_ribout_generator_next(&gen, &path);
    test_path_prefix_to_string(&path, prefix_str, sizeof(prefix_str));
    TEST_ASSERT(strcmp(prefix_str, "10.0.1.0/24") == 0, "Path 4: prefix is 10.0.1.0/24");
    TEST_ASSERT(path.path_id == 100, "Path 4: path-id wraps to 100");

    // Path 5: prefix=10.0.1.0/24, path-id=200
    bgp_ribout_generator_next(&gen, &path);
    test_path_prefix_to_string(&path, prefix_str, sizeof(prefix_str));
    TEST_ASSERT(strcmp(prefix_str, "10.0.1.0/24") == 0, "Path 5: prefix is 10.0.1.0/24");
    TEST_ASSERT(path.path_id == 200, "Path 5: path-id is 200");

    // Path 6: prefix=10.0.1.0/24, path-id=300
    bgp_ribout_generator_next(&gen, &path);
    test_path_prefix_to_string(&path, prefix_str, sizeof(prefix_str));
    TEST_ASSERT(strcmp(prefix_str, "10.0.1.0/24") == 0, "Path 6: prefix is 10.0.1.0/24");
    TEST_ASSERT(path.path_id == 300, "Path 6: path-id is 300");
    bgp_ribout_destroy(&block);
}

/*
 * Test 16: Generator Next-hop Wrapping
 */
void test_generator_next_hop_wrapping() {
    printf("\n=== Test 16: Generator Next-hop Wrapping ===\n");

    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;
    bgp_gen_path_t      path;
    char                next_hop_str[64];

    bgp_ribout_init(&block, "test16");
    bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/24 x 5");
    bgp_ribout_parse_path_ids(&block, "path-id 0");
    bgp_ribout_parse_next_hop(&block, "next-hop 192.168.1.1 x 2"); /* Only 2 next_hops */
    bgp_ribout_parse_aspath(&block, "as-path 100");

    bgp_ribout_generator_init(&gen, &block);

    // Path 1: next_hop should be 192.168.1.1
    bgp_ribout_generator_next(&gen, &path);
    test_path_next_hop_to_string(&path, next_hop_str, sizeof(next_hop_str));
    TEST_ASSERT(strcmp(next_hop_str, "192.168.1.1") == 0, "Path 1: next_hop is 192.168.1.1");

    // Path 2: next_hop should be 192.168.1.2
    bgp_ribout_generator_next(&gen, &path);
    test_path_next_hop_to_string(&path, next_hop_str, sizeof(next_hop_str));
    TEST_ASSERT(strcmp(next_hop_str, "192.168.1.2") == 0, "Path 2: next_hop is 192.168.1.2");

    // Path 3: next_hop should wrap to 192.168.1.1
    bgp_ribout_generator_next(&gen, &path);
    test_path_next_hop_to_string(&path, next_hop_str, sizeof(next_hop_str));
    TEST_ASSERT(strcmp(next_hop_str, "192.168.1.1") == 0, "Path 3: next_hop wraps to 192.168.1.1");

    // Path 4: next_hop should be 192.168.1.2
    bgp_ribout_generator_next(&gen, &path);
    test_path_next_hop_to_string(&path, next_hop_str, sizeof(next_hop_str));
    TEST_ASSERT(strcmp(next_hop_str, "192.168.1.2") == 0, "Path 4: next_hop is 192.168.1.2");

    // Path 5: next_hop should wrap to 192.168.1.1 again
    bgp_ribout_generator_next(&gen, &path);
    test_path_next_hop_to_string(&path, next_hop_str, sizeof(next_hop_str));
    TEST_ASSERT(strcmp(next_hop_str, "192.168.1.1") == 0, "Path 5: next_hop wraps to 192.168.1.1");
    bgp_ribout_destroy(&block);
}

/*
 * Test 17: Generator Reset
 */
void test_generator_reset() {
    printf("\n=== Test 17: Generator Reset ===\n");

    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;
    bgp_gen_path_t      path;
    char                prefix_str[64];

    bgp_ribout_init(&block, "test17");
    bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/24 x 2");
    bgp_ribout_parse_path_ids(&block, "path-id 10 20");
    bgp_ribout_parse_next_hop(&block, "next-hop 1.1.1.1");
    bgp_ribout_parse_aspath(&block, "as-path 100");

    bgp_ribout_generator_init(&gen, &block);

    // Generate 2 paths
    bgp_ribout_generator_next(&gen, &path);
    bgp_ribout_generator_next(&gen, &path);
    TEST_ASSERT(gen.paths_generated == 2, "Generated 2 paths");

    // Reset generator
    bgp_ribout_generator_reset(&gen);
    TEST_ASSERT(gen.paths_generated == 0, "Path count reset to 0");
    TEST_ASSERT(gen.current_prefix_idx == 0, "Prefix index reset to 0");
    TEST_ASSERT(gen.current_path_id_idx == 0, "Path-ID index reset to 0");
    TEST_ASSERT(bgp_ribout_generator_has_next(&gen), "Generator has paths after reset");

    // Verify we can iterate again
    bgp_ribout_generator_next(&gen, &path);
    test_path_prefix_to_string(&path, prefix_str, sizeof(prefix_str));
    TEST_ASSERT(strcmp(prefix_str, "10.0.0.0/24") == 0, "After reset: first prefix is 10.0.0.0/24");
    TEST_ASSERT(path.path_id == 10, "After reset: first path-id is 10");
    bgp_ribout_destroy(&block);
}

/*
 * Test 17a: Deterministic RNG With RANDSEED Override
 */
void test_generator_randseed_is_deterministic() {
    printf("\n=== Test 17a: Deterministic RNG With RANDSEED Override ===\n");

    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;
    bgp_gen_path_t      path1;
    bgp_gen_path_t      path2;
    char                aspath1[MAX_ASPATH_STRING_LEN];
    char                aspath2[MAX_ASPATH_STRING_LEN];
    test_env_guard_t    randseed_guard;

    test_env_guard_capture(&randseed_guard, "RANDSEED");
    setenv("RANDSEED", "424242", 1);
    bgp_ribout_init(&block, "seeded-random");
    bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/24 x 2");
    bgp_ribout_parse_path_ids(&block, "path-id 10 20");
    bgp_ribout_parse_aspath(&block, "as-path 65001 [rand(500) x 3]");
    bgp_ribout_parse_localpref(&block, "localpref rand(300)");
    bgp_ribout_parse_med(&block, "med rand(25)");

    TEST_ASSERT(bgp_ribout_generator_init(&gen, &block) == 0, "Seeded generator initializes successfully");
    TEST_ASSERT(bgp_ribout_generator_next(&gen, &path1) == 0, "Seeded generator produces first path");
    bgp_aspath_to_string(path1.aspath_segments, path1.aspath_segment_count, aspath1, sizeof(aspath1));

    bgp_ribout_generator_reset(&gen);
    TEST_ASSERT(bgp_ribout_generator_next(&gen, &path2) == 0, "Seeded generator reproduces first path after reset");
    bgp_aspath_to_string(path2.aspath_segments, path2.aspath_segment_count, aspath2, sizeof(aspath2));

    TEST_ASSERT(path1.local_pref == path2.local_pref, "Seeded random localpref repeats after reset");
    TEST_ASSERT(path1.med == path2.med, "Seeded random MED repeats after reset");
    TEST_ASSERT(strcmp(aspath1, aspath2) == 0, "Seeded random AS-path repeats after reset");
    test_env_guard_restore(&randseed_guard, "RANDSEED");
    bgp_ribout_destroy(&block);
}

/*
 * Test 17b: Default Seed Tracks Ribout Name
 */
void test_generator_default_seed_tracks_name() {
    printf("\n=== Test 17b: Default Seed Tracks Name ===\n");

    bgp_ribout_config_t block_a;
    bgp_ribout_config_t block_b;
    bgp_ribout_config_t block_c;
    bgp_ribout_gen_t    gen_a;
    bgp_ribout_gen_t    gen_b;
    bgp_ribout_gen_t    gen_c;
    bgp_gen_path_t      path_a;
    bgp_gen_path_t      path_b;
    bgp_gen_path_t      path_c;

    bgp_ribout_init(&block_a, "same-name");
    bgp_ribout_init(&block_b, "same-name");
    bgp_ribout_init(&block_c, "different-name");

    bgp_ribout_parse_prefix(&block_a, "prefix 10.0.0.0/24");
    bgp_ribout_parse_prefix(&block_b, "prefix 10.0.0.0/24");
    bgp_ribout_parse_prefix(&block_c, "prefix 10.0.0.0/24");
    bgp_ribout_parse_localpref(&block_a, "localpref rand(1000)");
    bgp_ribout_parse_localpref(&block_b, "localpref rand(1000)");
    bgp_ribout_parse_localpref(&block_c, "localpref rand(1000)");
    bgp_ribout_parse_aspath(&block_a, "as-path [rand(1000) x 2]");
    bgp_ribout_parse_aspath(&block_b, "as-path [rand(1000) x 2]");
    bgp_ribout_parse_aspath(&block_c, "as-path [rand(1000) x 2]");

    TEST_ASSERT(bgp_ribout_generator_init(&gen_a, &block_a) == 0, "Default-seed generator A initializes");
    TEST_ASSERT(bgp_ribout_generator_init(&gen_b, &block_b) == 0, "Default-seed generator B initializes");
    TEST_ASSERT(bgp_ribout_generator_init(&gen_c, &block_c) == 0, "Default-seed generator C initializes");
    TEST_ASSERT(bgp_ribout_generator_next(&gen_a, &path_a) == 0 &&
                bgp_ribout_generator_next(&gen_b, &path_b) == 0 &&
                bgp_ribout_generator_next(&gen_c, &path_c) == 0,
                "Default-seed generators all produce a path");

    TEST_ASSERT(path_a.local_pref == path_b.local_pref, "Same ribout name yields same default random localpref");
    TEST_ASSERT(path_a.aspath_segments[0].as_values[0] ==
                path_b.aspath_segments[0].as_values[0] &&
                path_a.aspath_segments[0].as_values[1] ==
                path_b.aspath_segments[0].as_values[1],
                "Same ribout name yields same default random AS-path values");
    TEST_ASSERT(path_a.local_pref != path_c.local_pref ||
                path_a.aspath_segments[0].as_values[0] !=
                    path_c.aspath_segments[0].as_values[0] ||
                path_a.aspath_segments[0].as_values[1] !=
                    path_c.aspath_segments[0].as_values[1],
                "Different ribout names perturb the default seed");
    bgp_ribout_destroy(&block_a);
    bgp_ribout_destroy(&block_b);
    bgp_ribout_destroy(&block_c);
}

/*
 * Test 18: Edge Case - Large Prefix Count
 */
void test_large_prefix_count() {
    printf("\n=== Test 18: Edge Case - Large Prefix Count ===\n");

    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;

    bgp_ribout_init(&block, "test18");
    bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/24 x 100000");
    bgp_ribout_parse_path_ids(&block, "path-id 0 1 2 3 4");

    int result = bgp_ribout_generator_init(&gen, &block);
    TEST_ASSERT(result == 0, "Generator handles large prefix count");
    TEST_ASSERT(gen.total_paths == 500000, "Total paths = 100000 × 5 = 500000");

    // Verify we can generate paths without pre-allocating
    bgp_gen_path_t path;
    result = bgp_ribout_generator_next(&gen, &path);
    TEST_ASSERT(result == 0, "Can generate path from large set");
    bgp_ribout_destroy(&block);
}

/*
 * Test 19: Edge Case - Single Prefix, Many Path-IDs
 */
void test_single_prefix_many_path_ids() {
    printf("\n=== Test 19: Edge Case - Single Prefix, Many Path-IDs ===\n");

    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;
    bgp_gen_path_t      path;
    char                prefix_str[64];

    bgp_ribout_init(&block, "test19");
    bgp_ribout_parse_prefix(&block, "prefix 10.1.1.0/24 x 1");
    bgp_ribout_parse_path_ids(&block, "path-id 1 2 3 4 5 6 7 8 9 10");
    bgp_ribout_parse_next_hop(&block, "next-hop 1.1.1.1");
    bgp_ribout_parse_aspath(&block, "as-path 100");

    bgp_ribout_generator_init(&gen, &block);
    TEST_ASSERT(gen.total_paths == 10, "Total paths = 1 × 10 = 10");

    // All 10 paths should have the same prefix
    for (int i = 0; i < 10; i++) {
        bgp_ribout_generator_next(&gen, &path);
        test_path_prefix_to_string(&path, prefix_str, sizeof(prefix_str));
        TEST_ASSERT(strcmp(prefix_str, "10.1.1.0/24") == 0, "All paths have same prefix");
    }
    bgp_ribout_destroy(&block);
}

/*
 * Test 20: Full Integration Test
 */
void test_full_integration() {
    printf("\n=== Test 20: Full Integration Test ===\n");

    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;
    bgp_gen_path_t      path;
    char                prefix_str[64];
    char                next_hop_str[64];

    bgp_ribout_init(&block, "integration");

    // Configure complete network block
    bgp_ribout_parse_prefix(&block, "prefix 172.16.0.0/16 x 10");
    bgp_ribout_parse_path_ids(&block, "path-id 0 1 2 3");
    bgp_ribout_parse_next_hop(&block, "next-hop 10.10.10.1 x 5");
    bgp_ribout_parse_aspath(&block, "as-path 100 200 { 10 20 } [rand(50) x 3]");
    bgp_ribout_parse_localpref(&block, "localpref 200");
    bgp_ribout_parse_origin(&block, "origin incomplete");

    int result = bgp_ribout_generator_init(&gen, &block);
    TEST_ASSERT(result == 0, "Integration: generator init successful");
    TEST_ASSERT(gen.total_paths == 40, "Integration: total paths = 10 × 4 = 40");

    // Generate first path and verify all attributes
    bgp_ribout_generator_next(&gen, &path);

    test_path_prefix_to_string(&path, prefix_str, sizeof(prefix_str));
    TEST_ASSERT(strcmp(prefix_str, "172.16.0.0/16") == 0, "Integration: prefix correct");
    TEST_ASSERT(path.path_id == 0, "Integration: path-id correct");
    test_path_next_hop_to_string(&path, next_hop_str, sizeof(next_hop_str));
    TEST_ASSERT(strcmp(next_hop_str, "10.10.10.1") == 0, "Integration: next_hop correct");
    TEST_ASSERT(path.aspath_segment_count > 0, "Integration: AS-path generated");
    TEST_ASSERT(path.local_pref == 200, "Integration: localpref correct");
    TEST_ASSERT(path.origin == ORIGIN_INCOMPLETE, "Integration: origin correct");

    // Consume all remaining paths
    int count = 1;
    while (bgp_ribout_generator_has_next(&gen)) {
        bgp_ribout_generator_next(&gen, &path);
        count++;
    }

    TEST_ASSERT(count == 40, "Integration: all 40 paths generated");
    bgp_ribout_destroy(&block);
}

/*
 * Test 21: Single Prefix (No x count)
 */
void test_single_prefix_no_count() {
    printf("\n=== Test 21: Single Prefix (No x count) ===\n");

    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test21");

    // Parse prefix without x count
    int result = bgp_ribout_parse_prefix(&block, "prefix 192.168.10.0/24");
    TEST_ASSERT(result == 0, "Parse prefix without x count");
    TEST_ASSERT(block.prefix_spec.count == 1, "Prefix count defaults to 1");
    TEST_ASSERT(block.prefix_spec.prefix_len == 24, "Prefix length is 24");

    // Generate single prefix
    char prefix_str[MAX_PREFIX_STRING_LEN];
    bgp_prefix_to_string(&block.prefix_spec, 0, prefix_str, sizeof(prefix_str));
    TEST_ASSERT(strcmp(prefix_str, "192.168.10.0/24") == 0, "Single prefix generated correctly");

    // Test with generator
    bgp_ribout_parse_path_ids(&block, "path-id 0 1");
    bgp_ribout_parse_next_hop(&block, "next-hop 10.0.0.1");
    bgp_ribout_parse_aspath(&block, "as-path 100");

    bgp_ribout_gen_t gen;
    bgp_ribout_generator_init(&gen, &block);
    TEST_ASSERT(gen.total_paths == 2, "Total paths = 1 prefix × 2 path-ids = 2");

    bgp_gen_path_t path;
    char           path_prefix_str[64];
    bgp_ribout_generator_next(&gen, &path);
    test_path_prefix_to_string(&path, path_prefix_str, sizeof(path_prefix_str));
    TEST_ASSERT(strcmp(path_prefix_str, "192.168.10.0/24") == 0, "First path has correct prefix");
    TEST_ASSERT(path.path_id == 0, "First path has path-id 0");

    bgp_ribout_generator_next(&gen, &path);
    test_path_prefix_to_string(&path, path_prefix_str, sizeof(path_prefix_str));
    TEST_ASSERT(strcmp(path_prefix_str, "192.168.10.0/24") == 0, "Second path has same prefix");
    TEST_ASSERT(path.path_id == 1, "Second path has path-id 1");
    bgp_ribout_destroy(&block);
}

/*
 * Test 22: Next-hop IP with x count (Should warn and ignore)
 */
void test_next_hop_ip_with_count_warning() {
    printf("\n=== Test 22: Next-hop IP with x count (Should warn and ignore) ===\n");

    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test22");

    bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/24 x 5");

    // Parse next_hop as IP with x count - should warn and treat as single IP
    printf("  (Expect warning about ignoring x count for IP next_hop)\n");
    int result = bgp_ribout_parse_next_hop(&block, "next-hop 192.168.1.1 x 5");
    TEST_ASSERT(result == 0, "Parsing succeeds despite warning");
    TEST_ASSERT(block.next_hop_spec.count == 5, "Next-hop count 5");

    // All next_hops should be the same
    char nh_str[MAX_PREFIX_STRING_LEN];
    bgp_next_hop_to_string(&block.next_hop_spec, 0, nh_str, sizeof(nh_str));
    TEST_ASSERT(strcmp(nh_str, "192.168.1.1") == 0, "Next-hop is 192.168.1.1");

    bgp_next_hop_to_string(&block.next_hop_spec, 10, nh_str, sizeof(nh_str));
    TEST_ASSERT(strcmp(nh_str, "192.168.1.1") == 0, "All next_hops wrap to same IP");
    bgp_ribout_destroy(&block);
}

/*
 * Test 23: Next-hop Prefix with x count (Should work)
 */
void test_next_hop_prefix_with_count() {
    printf("\n=== Test 23: Next-hop Prefix with x count (Should work) ===\n");

    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test23");

    bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/24 x 5");

    // Parse next_hop as prefix with x count - should work
    int result = bgp_ribout_parse_next_hop(&block, "next-hop 192.168.1.0 x 3");
    TEST_ASSERT(result == 0, "Parse next_hop prefix with count");
    TEST_ASSERT(block.next_hop_spec.count == 3, "Next-hop count is 3");

    // Generate next_hops
    char nh_str[MAX_PREFIX_STRING_LEN];
    bgp_next_hop_to_string(&block.next_hop_spec, 0, nh_str, sizeof(nh_str));
    TEST_ASSERT(strcmp(nh_str, "192.168.1.0") == 0, "First next_hop is 192.168.1.0");

    bgp_next_hop_to_string(&block.next_hop_spec, 1, nh_str, sizeof(nh_str));
    TEST_ASSERT(strcmp(nh_str, "192.168.1.1") == 0, "Second next_hop is 192.168.1.1");

    bgp_next_hop_to_string(&block.next_hop_spec, 2, nh_str, sizeof(nh_str));
    TEST_ASSERT(strcmp(nh_str, "192.168.1.2") == 0, "Third next_hop is 192.168.1.2");
    bgp_ribout_destroy(&block);
}

/*
 * Test 24: Next-hop Prefix without x count (Should default to 1)
 */
void test_next_hop_prefix_no_count() {
    printf("\n=== Test 24: Next-hop Prefix without x count (Should default to 1) ===\n");

    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test24");

    bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/24 x 5");

    // Parse next_hop as prefix without count
    int result = bgp_ribout_parse_next_hop(&block, "next-hop 192.168.100.0");
    TEST_ASSERT(result == 0, "Parse next_hop prefix without count");
    TEST_ASSERT(block.next_hop_spec.count == 1, "Next-hop count defaults to 1");

    // All indices should generate same next_hop
    char nh_str[MAX_PREFIX_STRING_LEN];
    bgp_next_hop_to_string(&block.next_hop_spec, 0, nh_str, sizeof(nh_str));
    TEST_ASSERT(strcmp(nh_str, "192.168.100.0") == 0, "First next_hop is 192.168.100.0");

    bgp_next_hop_to_string(&block.next_hop_spec, 3, nh_str, sizeof(nh_str));
    TEST_ASSERT(strcmp(nh_str, "192.168.100.0") == 0, "All next_hops wrap to same");
    bgp_ribout_destroy(&block);
}

/*
 * Test 25: Multiple RIB-OUTs With Different Families
 */
void test_multiple_ribouts_different_families() {
    printf("\n=== Test 25: Multiple RIB-OUTs With Different Families ===\n");

    bgp_sim_t sim;
    bgp_init_simulator(&sim);

    bgp_sim_add_ribout(&sim, "ipv4-block");
    bgp_ribout_parse_prefix(sim.ribouts[0], "prefix 10.0.0.0/24 x 10");
    bgp_ribout_parse_path_ids(sim.ribouts[0], "path-id 0");

    bgp_sim_add_ribout(&sim, "ipv6-block");
    bgp_ribout_parse_prefix(sim.ribouts[1], "prefix 2001:db8::/32 x 10");
    bgp_ribout_parse_path_ids(sim.ribouts[1], "path-id 0");

    TEST_ASSERT(sim.ribout_count == 2, "Two ribouts with different families");
    TEST_ASSERT(sim.ribouts[0]->prefix_spec.af == AF_INET, "First ribout is IPv4");
    TEST_ASSERT(sim.ribouts[1]->prefix_spec.af == AF_INET6, "Second ribout is IPv6");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 26: Multiple Generators On The Same Block
 */
void test_multiple_generators_same_block() {
    printf("\n=== Test 26: Multiple Generators On The Same Block ===\n");

    bgp_ribout_config_t block;
    bgp_ribout_gen_t gen1, gen2;
    bgp_gen_path_t path1, path2;
    char prefix_str1[64], prefix_str2[64];

    bgp_ribout_init(&block, "test26");
    bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/24 x 5");
    bgp_ribout_parse_path_ids(&block, "path-id 0 1");

    bgp_ribout_generator_init(&gen1, &block);
    bgp_ribout_generator_init(&gen2, &block);
    bgp_ribout_generator_next(&gen1, &path1);
    bgp_ribout_generator_next(&gen2, &path2);

    test_path_prefix_to_string(&path1, prefix_str1, sizeof(prefix_str1));
    test_path_prefix_to_string(&path2, prefix_str2, sizeof(prefix_str2));
    TEST_ASSERT(strcmp(prefix_str1, prefix_str2) == 0, "Independent generators start at the same prefix");
    bgp_ribout_destroy(&block);
}

/*
 * Test 27: Generator Reflects Updated RIB-OUT Configuration
 */
void test_ribout_modification_sequence() {
    printf("\n=== Test 27: Generator Reflects Updated RIB-OUT Configuration ===\n");

    bgp_ribout_config_t block;
    bgp_ribout_gen_t gen1, gen2;
    uint64_t total1, total2;

    bgp_ribout_init(&block, "test27");
    bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/24 x 10");
    bgp_ribout_parse_path_ids(&block, "path-id 0");
    bgp_ribout_generator_init(&gen1, &block);
    total1 = gen1.total_paths;

    bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/24 x 20");
    bgp_ribout_generator_init(&gen2, &block);
    total2 = gen2.total_paths;

    TEST_ASSERT(total2 == total1 * 2, "Modified configuration affects new generators");
    bgp_ribout_destroy(&block);
}

/*
 * Test 28: Mixed AS-Path Segment Types
 */
void test_complex_aspath_all_types() {
    printf("\n=== Test 28: Mixed AS-Path Segment Types ===\n");

    bgp_ribout_config_t block;
    int                 result;

    bgp_ribout_init(&block, "test28");
    result = bgp_ribout_parse_aspath(&block, "as-path 100 200 { 300 400 } [rand(500) x 10]");

    TEST_ASSERT(result >= 0, "Parse AS-path with sequence, set, and random segments");
    TEST_ASSERT(block.aspath_segment_count == 3, "Three AS-path segments created");
    TEST_ASSERT(block.aspath_segments[0].type == ASPATH_SEQUENCE, "First segment is sequence");
    TEST_ASSERT(block.aspath_segments[1].type == ASPATH_SET, "Second segment is set");
    TEST_ASSERT(block.aspath_segments[2].type == ASPATH_RANDOM, "Third segment is random");
    bgp_ribout_destroy(&block);
}

/*
 * Test 29: Partial Generation Leaves Remaining Paths Available
 */
void test_generator_partial_generation() {
    printf("\n=== Test 29: Partial Generation Leaves Remaining Paths Available ===\n");

    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;

    bgp_ribout_init(&block, "test29");
    bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/24 x 10");
    bgp_ribout_parse_path_ids(&block, "path-id 0");
    bgp_ribout_generator_init(&gen, &block);

    for (int i = 0; i < 5; i++) {
        bgp_gen_path_t path;
        bgp_ribout_generator_next(&gen, &path);
    }

    TEST_ASSERT(bgp_ribout_generator_has_next(&gen) == 1, "Generator still has paths after partial generation");
    TEST_ASSERT(gen.paths_generated == 5, "Five paths recorded as generated");

    for (int i = 0; i < 5; i++) {
        bgp_gen_path_t path;
        bgp_ribout_generator_next(&gen, &path);
    }

    TEST_ASSERT(bgp_ribout_generator_has_next(&gen) == 0, "Generator is exhausted after full generation");
    bgp_ribout_destroy(&block);
}

/*
 * Test 30: Multiple RIB-OUT Blocks Remain Independent
 */
void test_multiple_ribouts_independent() {
    printf("\n=== Test 30: Multiple RIB-OUT Blocks Remain Independent ===\n");

    bgp_sim_t sim;
    bgp_init_simulator(&sim);

    bgp_sim_add_ribout(&sim, "block1");
    bgp_ribout_parse_prefix(sim.ribouts[0], "prefix 10.0.0.0/24 x 10");
    bgp_ribout_parse_path_ids(sim.ribouts[0], "path-id 0");
    bgp_ribout_parse_localpref(sim.ribouts[0], "localpref 100");

    bgp_sim_add_ribout(&sim, "block2");
    bgp_ribout_parse_prefix(sim.ribouts[1], "prefix 172.16.0.0/16 x 20");
    bgp_ribout_parse_path_ids(sim.ribouts[1], "path-id 0 1");
    bgp_ribout_parse_localpref(sim.ribouts[1], "localpref 150");

    bgp_sim_add_ribout(&sim, "block3");
    bgp_ribout_parse_prefix(sim.ribouts[2], "prefix 192.168.0.0/24 x 5");
    bgp_ribout_parse_path_ids(sim.ribouts[2], "path-id 0");
    bgp_ribout_parse_localpref(sim.ribouts[2], "localpref rand(200)");

    TEST_ASSERT(sim.ribout_count == 3, "Three ribouts created");
    TEST_ASSERT(sim.ribouts[0]->localpref_spec.value == 100, "First block keeps localpref 100");
    TEST_ASSERT(sim.ribouts[1]->localpref_spec.value == 150, "Second block keeps localpref 150");
    TEST_ASSERT(sim.ribouts[2]->localpref_spec.mode == BGP_U32_MODE_RANDOM, "Third block keeps random localpref");
    bgp_shutdown_sim(&sim);
}

/*
 * Test 31: Default Attribute Values
 */
void test_default_values() {
    printf("\n=== Test 31: Default Attribute Values ===\n");

    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test31");

    TEST_ASSERT(block.localpref_spec.mode == BGP_U32_MODE_FIXED, "Default localpref type is fixed");
    TEST_ASSERT(block.localpref_spec.value == 100, "Default localpref value is 100");
    TEST_ASSERT(block.origin == ORIGIN_IGP, "Default origin is IGP");
    bgp_ribout_destroy(&block);
}

static void setup_srpolicy_generator_block(bgp_ribout_config_t *block,
                                           const char *endpoint_line,
                                           const char *next_hop_line) {
    bgp_ribout_init(block, "srpolicy");
    bgp_ribout_parse_distinguisher(block, "distinguisher 100 101");
    bgp_ribout_parse_color(block, "color 200 201");
    bgp_ribout_parse_endpoint(block, endpoint_line);
    bgp_ribout_parse_path_ids(block, "path-id 7 8");
    if (next_hop_line) {
        bgp_ribout_parse_next_hop(block, next_hop_line);
    }
    bgp_ribout_parse_rt(block, "rt 192.0.2.10:100");
    bgp_ribout_parse_preference(block, "preference 300 400");
    bgp_ribout_parse_binding_sid(block, "binding-sid mpls 16000 16001");
    bgp_ribout_parse_segment_list(block, "segment-list 1 weight 10 mpls 16010 16011");
    bgp_ribout_parse_aspath(block, "as-path 65001 65002");
    bgp_ribout_parse_localpref(block, "localpref 250");
    bgp_ribout_parse_origin(block, "origin egp");
}

static void format_mac_string(const uint8_t mac[6], char *buffer, size_t buffer_len) {
    snprintf(buffer, buffer_len, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void setup_evpn_type2_generator_block(bgp_ribout_config_t *block,
                                             const char *ip_line,
                                             const char *next_hop_line) {
    bgp_ribout_init(block, "evpn2");
    bgp_ribout_parse_rd(block, "rd 65000:320 65000:321");
    bgp_ribout_parse_ethernet_tag(block, "ethernet-tag 10 20");
    bgp_ribout_parse_mac(block, "mac 00:11:22:33:44:00 x 2");
    if (ip_line) {
        bgp_ribout_parse_ip(block, ip_line);
    }
    bgp_ribout_parse_label(block, "label 30000 30001");
    bgp_ribout_parse_label2(block, "label2 40000 40001");
    bgp_ribout_parse_esi(block, "esi 00:00:00:00:00:00:00:00:00:00 " "00:00:00:00:00:00:00:00:00:01");
    bgp_ribout_parse_path_ids(block, "path-id 7 8");
    if (next_hop_line) {
        bgp_ribout_parse_next_hop(block, next_hop_line);
    }
    bgp_ribout_parse_rt(block, "rt 65000:320");
    bgp_ribout_parse_aspath(block, "as-path 65001 65002");
    bgp_ribout_parse_localpref(block, "localpref 250");
    bgp_ribout_parse_origin(block, "origin igp");
}

void test_srpolicy_generator_total_paths() {
    printf("\n=== Test 32: SR Policy Generator Total Paths ===\n");

    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;

    setup_srpolicy_generator_block(&block, "endpoint 10.0.0.1 x 4", "next-hop 192.0.2.1 x 2");

    TEST_ASSERT(bgp_ribout_generator_init(&gen, &block) == 0, "SR Policy generator initialization successful");
    TEST_ASSERT(gen.total_paths == 32,
                "SR Policy total paths = 2 distinguishers x 2 colors x 4 endpoints x 2 path-ids");
    TEST_ASSERT(bgp_ribout_gen_total_paths(&gen) == 32, "SR Policy total path getter matches generator state");
    bgp_ribout_destroy(&block);
}

void test_srpolicy_generator_order_and_attr_rotation() {
    printf("\n=== Test 33: SR Policy Generator Order And Attr Rotation ===\n");

    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;
    bgp_gen_path_t      path;
    char                endpoint_str[INET6_ADDRSTRLEN];
    char                next_hop_str[INET6_ADDRSTRLEN];

    setup_srpolicy_generator_block(&block, "endpoint 10.0.0.1 x 2", "next-hop 192.0.2.1 x 2");

    TEST_ASSERT(bgp_ribout_generator_init(&gen, &block) == 0, "SR Policy order test generator initialized");
    TEST_ASSERT(gen.total_paths == 16, "SR Policy order test total paths = 2 x 2 x 2 x 2");

    bgp_ribout_generator_next(&gen, &path);
    inet_ntop(AF_INET, &path.endpoint_addr.ipv4, endpoint_str, sizeof(endpoint_str));
    test_path_next_hop_to_string(&path, next_hop_str, sizeof(next_hop_str));
    TEST_ASSERT(path.distinguisher == 100 && path.color == 200 &&
                strcmp(endpoint_str, "10.0.0.1") == 0 && path.path_id == 7,
                "Path 1 starts at first distinguisher/color/endpoint/path-id");
    TEST_ASSERT(strcmp(next_hop_str, "192.0.2.1") == 0 &&
                path.preference == 300 &&
                test_binding_sid_is_mpls(&path.binding_sid, 16000),
                "Path 1 uses first rotating SR attributes");

    bgp_ribout_generator_next(&gen, &path);
    inet_ntop(AF_INET, &path.endpoint_addr.ipv4, endpoint_str, sizeof(endpoint_str));
    test_path_next_hop_to_string(&path, next_hop_str, sizeof(next_hop_str));
    TEST_ASSERT(path.distinguisher == 100 && path.color == 200 &&
                strcmp(endpoint_str, "10.0.0.1") == 0 && path.path_id == 8,
                "Path 2 advances path-id before any other SR NLRI dimension");
    TEST_ASSERT(strcmp(next_hop_str, "192.0.2.2") == 0 &&
                path.preference == 400 &&
                test_binding_sid_is_mpls(&path.binding_sid, 16001),
                "Path 2 advances the rotating SR attribute knobs");

    bgp_ribout_generator_next(&gen, &path);
    inet_ntop(AF_INET, &path.endpoint_addr.ipv4, endpoint_str, sizeof(endpoint_str));
    test_path_next_hop_to_string(&path, next_hop_str, sizeof(next_hop_str));
    TEST_ASSERT(path.distinguisher == 100 && path.color == 200 &&
                strcmp(endpoint_str, "10.0.0.2") == 0 && path.path_id == 7,
                "Path 3 advances endpoint after path-id wraps");
    TEST_ASSERT(strcmp(next_hop_str, "192.0.2.1") == 0 &&
                path.preference == 300 &&
                test_binding_sid_is_mpls(&path.binding_sid, 16000),
                "Path 3 wraps rotating SR attributes independently of NLRI advancement");

    for (int i = 0; i < 5; i++) {
        bgp_ribout_generator_next(&gen, &path);
    }
    inet_ntop(AF_INET, &path.endpoint_addr.ipv4, endpoint_str, sizeof(endpoint_str));
    TEST_ASSERT(path.distinguisher == 100 && path.color == 201 &&
                strcmp(endpoint_str, "10.0.0.2") == 0 && path.path_id == 8,
                "Path 8 finishes the second color before distinguisher changes");

    bgp_ribout_generator_next(&gen, &path);
    inet_ntop(AF_INET, &path.endpoint_addr.ipv4, endpoint_str, sizeof(endpoint_str));
    TEST_ASSERT(path.distinguisher == 101 && path.color == 200 &&
                strcmp(endpoint_str, "10.0.0.1") == 0 && path.path_id == 7,
                "Path 9 advances distinguisher after color/endpoint/path-id space is exhausted");
    bgp_ribout_destroy(&block);
}

void test_srpolicy_generator_default_next_hop() {
    printf("\n=== Test 34: SR Policy Default Next-Hop ===\n");

    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;
    bgp_gen_path_t      path;
    char                next_hop_str[INET6_ADDRSTRLEN];

    setup_srpolicy_generator_block(&block, "endpoint 2001:db8::1 x 2", NULL);

    TEST_ASSERT(bgp_ribout_generator_init(&gen, &block) == 0, "SR Policy default next-hop generator initialized");
    TEST_ASSERT(bgp_ribout_generator_next(&gen, &path) == 0, "SR Policy generator produced first IPv6 path");
    test_path_next_hop_to_string(&path, next_hop_str, sizeof(next_hop_str));
    TEST_ASSERT(path.family == BGP_RIBOUT_FAMILY_SR_POLICY_IPV6 &&
                path.endpoint_af == AF_INET6,
                "SR Policy default next-hop test resolves IPv6 family from endpoint");
    TEST_ASSERT(path.next_hop_af == AF_INET &&
                strcmp(next_hop_str, "0.0.0.0") == 0,
                "SR Policy default next-hop stays the strict 4-octet all-zero value");
    bgp_ribout_destroy(&block);
}

void test_srpolicy_segment_lists_do_not_multiply_paths() {
    printf("\n=== Test 35: SR Policy Segment-Lists Do Not Multiply Paths ===\n");

    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;

    setup_srpolicy_generator_block(&block, "endpoint 10.0.0.1 x 2", "next-hop 192.0.2.1");
    bgp_ribout_parse_segment_list(&block, "segment-list 2 weight 20 mpls 16020 16021");

    TEST_ASSERT(bgp_ribout_generator_init(&gen, &block) == 0, "SR Policy segment-list test generator initialized");
    TEST_ASSERT(gen.total_paths == 16, "SR Policy segment-lists stay block-wide and do not multiply path count");
    bgp_ribout_destroy(&block);
}

void test_srpolicy_extended_tunnel_knobs() {
    printf("\n=== Test 36: SR Policy Extended Tunnel Knobs ===\n");

    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;
    bgp_gen_path_t      path1;
    bgp_gen_path_t      path2;
    char                sid_str[INET6_ADDRSTRLEN];

    bgp_ribout_init(&block, "srpolicy-extended");
    bgp_ribout_parse_distinguisher(&block, "distinguisher 100");
    bgp_ribout_parse_color(&block, "color 200");
    bgp_ribout_parse_endpoint(&block, "endpoint 2001:db8::1");
    bgp_ribout_parse_path_ids(&block, "path-id 7 8");
    bgp_ribout_parse_rt(&block, "rt 192.0.2.10:100");
    bgp_ribout_parse_enlp(&block, "enlp 3 4");
    bgp_ribout_parse_priority(&block, "priority range(7,8)");
    bgp_ribout_parse_preference(&block, "preference 300");
    bgp_ribout_parse_binding_sid(&block, "binding-sid srv6 fc00:0:77::1 x 2");
    bgp_ribout_parse_segment_list(&block,
                                  "segment-list 7 weight 70 srv6 "
                                  "2001:db8:7::1 behavior 4660 structure 48 16 16 48 "
                                  "2001:db8:7::2");

    TEST_ASSERT(bgp_ribout_generator_init(&gen, &block) == 0, "Extended SR Policy generator initializes");
    TEST_ASSERT(bgp_ribout_generator_next(&gen, &path1) == 0 &&
                bgp_ribout_generator_next(&gen, &path2) == 0,
                "Extended SR Policy generator emits first two paths");

    TEST_ASSERT(path1.has_enlp && path1.enlp == 3 &&
                path1.has_priority && path1.priority == 7,
                "First SR path carries ENLP and priority");
    TEST_ASSERT(path2.has_enlp && path2.enlp == 4 &&
                path2.has_priority && path2.priority == 8,
                "Second SR path rotates ENLP and priority");

    inet_ntop(AF_INET6, path1.binding_sid.srv6_sid, sid_str, sizeof(sid_str));
    TEST_ASSERT(path1.binding_sid.type == SRPOLICY_BINDING_SID_SRV6 &&
                strcmp(sid_str, "fc00:0:77::1") == 0,
                "First SR path uses the first SRv6 Binding SID");
    inet_ntop(AF_INET6, path2.binding_sid.srv6_sid, sid_str, sizeof(sid_str));
    TEST_ASSERT(path2.binding_sid.type == SRPOLICY_BINDING_SID_SRV6 &&
                strcmp(sid_str, "fc00:0:77::2") == 0,
                "Second SR path rotates the SRv6 Binding SID");

    TEST_ASSERT(block.segment_lists[0].segments[0].has_srv6_behavior &&
                block.segment_lists[0].segments[0].srv6_behavior.endpoint_behavior == 4660 &&
                block.segment_lists[0].segments[0].srv6_behavior.locator_block_len == 48 &&
                block.segment_lists[0].segments[0].srv6_behavior.argument_len == 48,
                "Configured SRv6 segment keeps behavior and structure");
    bgp_ribout_destroy(&block);
}

void test_evpn_type2_generator_total_paths() {
    printf("\n=== Test 36: EVPN Type 2 Generator Total Paths ===\n");

    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;

    setup_evpn_type2_generator_block(&block, "ip 192.0.2.1 x 2", "next-hop 192.0.2.10 x 2");

    TEST_ASSERT(bgp_ribout_generator_init(&gen, &block) == 0, "EVPN Type 2 generator initialization successful");
    TEST_ASSERT(gen.total_paths == 32,
                "EVPN Type 2 total paths = 2 RDs x 2 Ethernet Tags x 2 MACs x 2 IPs x 2 path-ids");
    TEST_ASSERT(bgp_ribout_gen_total_paths(&gen) == 32, "EVPN Type 2 total path getter matches generator state");
    bgp_ribout_destroy(&block);
}

void test_evpn_type2_generator_order_and_attr_rotation() {
    printf("\n=== Test 37: EVPN Type 2 Generator Order And Attr Rotation ===\n");

    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;
    bgp_gen_path_t      path;
    char                mac_str[32];
    char                ip_str[INET6_ADDRSTRLEN];
    char                next_hop_str[INET6_ADDRSTRLEN];

    setup_evpn_type2_generator_block(&block, "ip 192.0.2.1 x 2", "next-hop 192.0.2.10 x 2");

    TEST_ASSERT(bgp_ribout_generator_init(&gen, &block) == 0, "EVPN Type 2 order test generator initialized");
    TEST_ASSERT(gen.total_paths == 32, "EVPN Type 2 order test total paths = 2 x 2 x 2 x 2 x 2");

    bgp_ribout_generator_next(&gen, &path);
    format_mac_string(path.mac_addr, mac_str, sizeof(mac_str));
    inet_ntop(AF_INET, &path.ip_addr.ipv4, ip_str, sizeof(ip_str));
    test_path_next_hop_to_string(&path, next_hop_str, sizeof(next_hop_str));
    TEST_ASSERT(path.has_mac && path.has_ip && path.has_label2, "Path 1 includes MAC, IP, and optional label2");
    TEST_ASSERT(path.has_rd && strcmp(mac_str, "00:11:22:33:44:00") == 0 &&
                strcmp(ip_str, "192.0.2.1") == 0 &&
                path.ethernet_tag_id == 10 &&
                path.path_id == 7,
                "Path 1 starts at first RD/Ethernet-Tag/MAC/IP/path-id tuple");
    TEST_ASSERT(path.label == 30000 && path.label2 == 40000 &&
                strcmp(next_hop_str, "192.0.2.10") == 0,
                "Path 1 uses the first rotating EVPN Type 2 encoded-field and attribute values");

    bgp_ribout_generator_next(&gen, &path);
    format_mac_string(path.mac_addr, mac_str, sizeof(mac_str));
    inet_ntop(AF_INET, &path.ip_addr.ipv4, ip_str, sizeof(ip_str));
    test_path_next_hop_to_string(&path, next_hop_str, sizeof(next_hop_str));
    TEST_ASSERT(strcmp(mac_str, "00:11:22:33:44:00") == 0 &&
                strcmp(ip_str, "192.0.2.1") == 0 &&
                path.path_id == 8,
                "Path 2 advances path-id before any EVPN Type 2 primary dimension");
    TEST_ASSERT(path.label == 30001 && path.label2 == 40001 &&
                strcmp(next_hop_str, "192.0.2.11") == 0,
                "Path 2 advances rotating label, label2, and next-hop values");

    bgp_ribout_generator_next(&gen, &path);
    format_mac_string(path.mac_addr, mac_str, sizeof(mac_str));
    inet_ntop(AF_INET, &path.ip_addr.ipv4, ip_str, sizeof(ip_str));
    TEST_ASSERT(strcmp(mac_str, "00:11:22:33:44:00") == 0 &&
                strcmp(ip_str, "192.0.2.2") == 0 &&
                path.path_id == 7,
                "Path 3 advances the optional IP fanout after path-id wraps");
    TEST_ASSERT(path.label == 30000 && path.label2 == 40000,
                "Path 3 wraps EVPN Type 2 encoded-field rotators independently of NLRI advancement");

    bgp_ribout_generator_next(&gen, &path);
    bgp_ribout_generator_next(&gen, &path);
    format_mac_string(path.mac_addr, mac_str, sizeof(mac_str));
    inet_ntop(AF_INET, &path.ip_addr.ipv4, ip_str, sizeof(ip_str));
    TEST_ASSERT(strcmp(mac_str, "00:11:22:33:44:01") == 0 &&
                strcmp(ip_str, "192.0.2.1") == 0 &&
                path.path_id == 7,
                "Path 5 advances MAC after the per-MAC IP space is exhausted");
    bgp_ribout_destroy(&block);
}

void test_evpn_type2_generator_default_next_hop() {
    printf("\n=== Test 38: EVPN Type 2 Default Next-Hop ===\n");

    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;
    bgp_gen_path_t      path;
    char                next_hop_str[INET6_ADDRSTRLEN];

    setup_evpn_type2_generator_block(&block, "ip 2001:db8::1 x 2", NULL);

    TEST_ASSERT(bgp_ribout_generator_init(&gen, &block) == 0, "EVPN Type 2 default next-hop generator initialized");
    TEST_ASSERT(bgp_ribout_generator_next(&gen, &path) == 0, "EVPN Type 2 generator produced first path");
    test_path_next_hop_to_string(&path, next_hop_str, sizeof(next_hop_str));
    TEST_ASSERT(path.family == BGP_RIBOUT_FAMILY_EVPN_TYPE2 &&
                path.ip_af == AF_INET6,
                "EVPN Type 2 default next-hop test keeps IPv6 host-binding IP state");
    TEST_ASSERT(path.next_hop_af == AF_INET &&
                strcmp(next_hop_str, "0.0.0.0") == 0,
                "EVPN Type 2 default next-hop stays the strict 4-octet all-zero value");
    bgp_ribout_destroy(&block);
}

void test_evpn_type2_secondary_fields_do_not_multiply_paths() {
    printf("\n=== Test 39: EVPN Type 2 Secondary Fields Do Not Multiply Paths ===\n");

    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;

    setup_evpn_type2_generator_block(&block, "ip 192.0.2.1 x 2", "next-hop 192.0.2.10");

    TEST_ASSERT(bgp_ribout_generator_init(&gen, &block) == 0, "EVPN Type 2 secondary-field test generator initialized");
    TEST_ASSERT(gen.total_paths == 32, "EVPN Type 2 label, label2, and ESI rotators do not multiply total path count");
    bgp_ribout_destroy(&block);
}

void test_evpn_type2_ext_community_rotators() {
    printf("\n=== Test 40: EVPN Type 2 Ext-Community Rotators ===\n");

    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;
    bgp_gen_path_t      path1;
    bgp_gen_path_t      path2;

    bgp_ribout_init(&block, "evpn2-ext-comms");
    bgp_ribout_parse_rd(&block, "rd 65000:320");
    bgp_ribout_parse_ethernet_tag(&block, "ethernet-tag 10");
    bgp_ribout_parse_mac(&block, "mac 00:11:22:33:44:00");
    bgp_ribout_parse_ip(&block, "ip 192.0.2.1");
    bgp_ribout_parse_label(&block, "label 30000");
    bgp_ribout_parse_path_ids(&block, "path-id 7 8");
    bgp_ribout_parse_next_hop(&block, "next-hop 192.0.2.10");
    bgp_ribout_parse_rt(&block, "rt 65000:320");
    bgp_ribout_parse_encap(&block, "encap vxlan nvgre");
    bgp_ribout_parse_router_mac(&block, "router-mac 02:00:00:00:00:01 " "02:00:00:00:00:02");
    bgp_ribout_parse_aspath(&block, "as-path 65001 65002");
    bgp_ribout_parse_localpref(&block, "localpref 250");
    bgp_ribout_parse_origin(&block, "origin igp");

    TEST_ASSERT(bgp_ribout_generator_init(&gen, &block) == 0, "EVPN Type 2 ext-community generator initialized");
    TEST_ASSERT(gen.total_paths == 2, "EVPN Type 2 encap and router-mac stay attr-side and do not multiply paths");
    TEST_ASSERT(bgp_ribout_generator_next(&gen, &path1) == 0 &&
                bgp_ribout_generator_next(&gen, &path2) == 0,
                "EVPN Type 2 generator emits two paths for attr rotation");

    TEST_ASSERT(path1.ext_comm_len == 24 && path2.ext_comm_len == 24,
                "EVPN Type 2 paths carry RT, encap, and router-mac ext communities");
    TEST_ASSERT(path1.ext_comm_data[8] == 0x03 && path1.ext_comm_data[9] == 0x0c &&
                test_read_u16_be(path1.ext_comm_data + 14) == 8,
                "First EVPN Type 2 path uses VXLAN encap");
    TEST_ASSERT(path2.ext_comm_data[8] == 0x03 && path2.ext_comm_data[9] == 0x0c &&
                test_read_u16_be(path2.ext_comm_data + 14) == 9,
                "Second EVPN Type 2 path rotates to NVGRE encap");
    TEST_ASSERT(path1.ext_comm_data[16] == 0x06 && path1.ext_comm_data[17] == 0x03 &&
                memcmp(path1.ext_comm_data + 18, (const uint8_t[]){0x02,0x00,0x00,0x00,0x00,0x01}, 6) == 0,
                "First EVPN Type 2 path uses the first router-mac");
    TEST_ASSERT(path2.ext_comm_data[16] == 0x06 && path2.ext_comm_data[17] == 0x03 &&
                memcmp(path2.ext_comm_data + 18, (const uint8_t[]){0x02,0x00,0x00,0x00,0x00,0x02}, 6) == 0,
                "Second EVPN Type 2 path rotates the router-mac");
    bgp_ribout_destroy(&block);
}

void test_evpn_type2_identifier_shorthand_generation() {
    printf("\n=== Test 41: EVPN Type 2 Identifier Shorthand Generation ===\n");

    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;
    bgp_gen_path_t      path1;
    bgp_gen_path_t      path2;
    char                mac_str[32];

    bgp_ribout_init(&block, "evpn2-short");
    bgp_ribout_parse_rd(&block, "rd 65000:330");
    bgp_ribout_parse_ethernet_tag(&block, "ethernet-tag 10");
    bgp_ribout_parse_mac(&block, "mac 1 x 2");
    bgp_ribout_parse_ip(&block, "ip 192.0.2.1");
    bgp_ribout_parse_label(&block, "label 33000");
    bgp_ribout_parse_esi(&block, "esi 00112233445566778899 x 2");
    bgp_ribout_parse_path_ids(&block, "path-id 7");
    bgp_ribout_parse_next_hop(&block, "next-hop 192.0.2.10");
    bgp_ribout_parse_rt(&block, "rt 65000:330");
    bgp_ribout_parse_router_mac(&block, "router-mac 1 2");

    TEST_ASSERT(bgp_ribout_generator_init(&gen, &block) == 0, "EVPN Type 2 shorthand generator initializes");
    TEST_ASSERT(gen.total_paths == 2, "EVPN Type 2 shorthand generator keeps MAC count as the only path multiplier");
    TEST_ASSERT(bgp_ribout_generator_next(&gen, &path1) == 0 &&
                bgp_ribout_generator_next(&gen, &path2) == 0,
                "EVPN Type 2 shorthand generator emits two paths");

    format_mac_string(path1.mac_addr, mac_str, sizeof(mac_str));
    TEST_ASSERT(strcmp(mac_str, "00:00:00:00:00:01") == 0 &&
                path1.esi.type == 0x00 &&
                memcmp(path1.esi.value, (const uint8_t[]){0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99}, 9) == 0 &&
                path1.ext_comm_len == 16 &&
                memcmp(path1.ext_comm_data + 10, (const uint8_t[]){0x00,0x00,0x00,0x00,0x00,0x01}, 6) == 0,
                "First shorthand EVPN Type 2 path expands MAC/ESI/router-mac correctly");

    format_mac_string(path2.mac_addr, mac_str, sizeof(mac_str));
    TEST_ASSERT(strcmp(mac_str, "00:00:00:00:00:02") == 0 &&
                path2.esi.type == 0x00 &&
                memcmp(path2.esi.value, (const uint8_t[]){0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x9a}, 9) == 0 &&
                path2.ext_comm_len == 16 &&
                memcmp(path2.ext_comm_data + 10, (const uint8_t[]){0x00,0x00,0x00,0x00,0x00,0x02}, 6) == 0,
                "Second shorthand EVPN Type 2 path advances MAC/ESI/router-mac");
    bgp_ribout_destroy(&block);
}

/*
 * Test 42: SR Policy Rand Knobs Use Deterministic RANDSEED
 */
void test_srpolicy_random_knobs_honor_randseed() {
    printf("\n=== Test 42: SR Policy Rand Knobs Use Deterministic RANDSEED ===\n");

    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;
    bgp_gen_path_t      path1;
    bgp_gen_path_t      path2;
    test_env_guard_t    randseed_guard;

    test_env_guard_capture(&randseed_guard, "RANDSEED");
    setenv("RANDSEED", "777", 1);
    bgp_ribout_init(&block, "sr-rand");
    bgp_ribout_parse_distinguisher(&block, "distinguisher 100");
    bgp_ribout_parse_color(&block, "color 200");
    bgp_ribout_parse_endpoint(&block, "endpoint 10.0.0.1 x 2");
    bgp_ribout_parse_rt(&block, "rt 192.0.2.10:100");
    bgp_ribout_parse_preference(&block, "preference rand(4096)");
    bgp_ribout_parse_binding_sid(&block, "binding-sid mpls randrange(16,1048575)");
    bgp_ribout_parse_segment_list(&block, "segment-list 1 weight 10 mpls 16010 16011");

    TEST_ASSERT(bgp_ribout_generator_init(&gen, &block) == 0, "SR Policy random-knob generator initializes");
    TEST_ASSERT(bgp_ribout_generator_next(&gen, &path1) == 0, "SR Policy random-knob generator produces first path");
    TEST_ASSERT(path1.preference >= 1 && path1.preference <= 4096,
                "SR Policy random preference stays within configured range");
    TEST_ASSERT(path1.binding_sid.type == SRPOLICY_BINDING_SID_MPLS &&
                path1.binding_sid.mpls_label >= 16 &&
                path1.binding_sid.mpls_label <= 1048575,
                "SR Policy random binding SID stays within strict BSID MPLS label range");

    bgp_ribout_generator_reset(&gen);
    TEST_ASSERT(bgp_ribout_generator_next(&gen, &path2) == 0,
                "SR Policy random-knob generator reproduces first path after reset");
    TEST_ASSERT(path1.preference == path2.preference, "Seeded SR Policy preference is deterministic");
    TEST_ASSERT(test_binding_sid_equal(&path1.binding_sid, &path2.binding_sid),
                "Seeded SR Policy binding SID is deterministic");
    test_env_guard_restore(&randseed_guard, "RANDSEED");
    bgp_ribout_destroy(&block);
}

/*
 * Parse one component into a new block and compare the operator/value pairs of its first alternative with RFC 8955
 * section 4.2.1 bytes worked out by hand.
 */
static int flowspec_ops_are(const char *keyword, const char *args, uint8_t type,
                            const uint8_t *ops, const uint32_t *values, uint8_t count) {
    bgp_ribout_config_t block;
    int                 same;

    bgp_ribout_init(&block, "fs-ops");
    same = bgp_ribout_flowspec_parse_component(&block, keyword, args) == 0 &&
           block.flowspec->components[type].alternatives[0].num_values == count;
    for (uint8_t i = 0; same && i < count; i++) {
        const flowspec_op_value_t *ov = &block.flowspec->components[type].alternatives[0].values[i];

        same = (ov->op == ops[i] && ov->value == values[i]);
    }
    bgp_ribout_destroy(&block);
    return same;
}

/*
 * Parse one component into a new block and compare its canonical text with expected.
 */
static int flowspec_text_is(const char *keyword, const char *args, uint8_t type, const char *expected) {
    bgp_ribout_config_t block;
    char                text[256];
    int                 same;

    bgp_ribout_init(&block, "fs-text");
    same = bgp_ribout_flowspec_parse_component(&block, keyword, args) == 0 &&
           bgp_ribout_flowspec_component_to_string(&block, type, text, sizeof(text)) == 1 &&
           strcmp(text, expected) == 0;
    bgp_ribout_destroy(&block);
    return same;
}

/*
 * 1 when the component text is rejected.
 */
static int flowspec_rejects(const char *keyword, const char *args) {
    bgp_ribout_config_t block;
    int                 rejected;

    bgp_ribout_init(&block, "fs-bad");
    rejected = bgp_ribout_flowspec_parse_component(&block, keyword, args) < 0;
    bgp_ribout_destroy(&block);
    return rejected;
}

/*
 * Test 43: FlowSpec Expression Parsing
 */
void test_flowspec_expression_parsing() {
    printf("\n=== Test 43: FlowSpec Expression Parsing ===\n");

    {
        bgp_ribout_config_t block;
        int dst_all, dst_more, src_all, src_more;

        bgp_ribout_init(&block, "fs-offset");
        dst_all = bgp_ribout_parse_prefix(&block, "prefix 2001:db8::/120-128 x 256") == 0;
        dst_more = bgp_ribout_parse_prefix(&block, "prefix 2001:db8::/120-128 x 257") < 0;
        src_all = bgp_ribout_flowspec_parse_component(&block, "src-prefix", "2001:db8::/56-64 x 256") == 0;
        src_more = bgp_ribout_flowspec_parse_component(&block, "src-prefix", "2001:db8::/56-64 x 257") < 0;
        bgp_ribout_destroy(&block);
        TEST_ASSERT(dst_all && dst_more && src_all && src_more,
                    "An offset prefix has 2^(length - offset) keys on the wire: x more than that is rejected");
    }

    bgp_ribout_config_t block;

    TEST_ASSERT(flowspec_ops_are("protocol", "6", FLOWSPEC_IP_PROTOCOL,
                                 (const uint8_t[]){0x81}, (const uint32_t[]){6}, 1),
                "A bare 6 is end + 1-octet + eq (0x81)");
    TEST_ASSERT(flowspec_ops_are("port", "!=5", FLOWSPEC_PORT,
                                 (const uint8_t[]){0x86}, (const uint32_t[]){5}, 1),
                "!=5 is lt + gt (0x86)");
    TEST_ASSERT(flowspec_ops_are("packet-length", "<=1500", FLOWSPEC_PACKET_LEN,
                                 (const uint8_t[]){0x95}, (const uint32_t[]){1500}, 1),
                "<=1500 picks the 2-octet width (0x95)");
    TEST_ASSERT(flowspec_ops_are("flow-label", ">70000", FLOWSPEC_FLOW_LABEL,
                                 (const uint8_t[]){0xa2}, (const uint32_t[]){70000}, 1),
                ">70000 picks the 4-octet width (0xa2)");
    TEST_ASSERT(flowspec_ops_are("dst-port", "80:2", FLOWSPEC_DEST_PORT,
                                 (const uint8_t[]){0x91}, (const uint32_t[]){80}, 1),
                "80:2 forces the 2-octet width (0x91)");
    TEST_ASSERT(flowspec_ops_are("icmp-code", "true", FLOWSPEC_ICMP_CODE,
                                 (const uint8_t[]){0x87}, (const uint32_t[]){0}, 1) &&
                flowspec_ops_are("icmp-code", "false", FLOWSPEC_ICMP_CODE,
                                 (const uint8_t[]){0x80}, (const uint32_t[]){0}, 1),
                "true and false set all or none of lt/gt/eq");
    TEST_ASSERT(flowspec_ops_are("dst-port", ">=1024&<=2048 80", FLOWSPEC_DEST_PORT,
                                 (const uint8_t[]){0x13, 0x55, 0x81},
                                 (const uint32_t[]){1024, 2048, 80}, 3),
                "& sets the AND bit; a space starts an OR term; only the last pair ends the list");
    TEST_ASSERT(flowspec_ops_are("tcp-flags", "syn+ack !rst", FLOWSPEC_TCP_FLAGS,
                                 (const uint8_t[]){0x01, 0x83},
                                 (const uint32_t[]){FLOWSPEC_TCP_SYN | FLOWSPEC_TCP_ACK, FLOWSPEC_TCP_RST}, 2),
                "Bare bitmask bits set the match bit (all set); ! adds not");
    TEST_ASSERT(flowspec_ops_are("tcp-flags", "!any(fin):2", FLOWSPEC_TCP_FLAGS,
                                 (const uint8_t[]){0x92}, (const uint32_t[]){FLOWSPEC_TCP_FIN}, 1),
                "!any(fin):2 is end + 2-octet + not, without match (0x92)");
    TEST_ASSERT(flowspec_ops_are("fragment", "any(isf) ff+lf", FLOWSPEC_FRAGMENT,
                                 (const uint8_t[]){0x00, 0x81},
                                 (const uint32_t[]){FLOWSPEC_FRAG_ISF, FLOWSPEC_FRAG_FF | FLOWSPEC_FRAG_LF}, 2),
                "Fragment names map to RFC 8955 section 4.2.2.12 bits");
    TEST_ASSERT(flowspec_rejects("protocol", "=6") && flowspec_rejects("tcp-flags", "=syn") &&
                flowspec_rejects("tcp-flags", "any(syn") && flowspec_rejects("protocol", "6&") &&
                flowspec_rejects("tcp-flags", "any()"),
                "= is not an operator; any() needs bits and its closing bracket");

    bgp_ribout_init(&block, "fs-gen");
    TEST_ASSERT(bgp_ribout_flowspec_parse_component(&block, "protocol", "each(6, 17 >=250)") == 0 &&
                block.flowspec->components[FLOWSPEC_IP_PROTOCOL].alternative_count == 2 &&
                block.flowspec->components[FLOWSPEC_IP_PROTOCOL].alternatives[1].num_values == 2,
                "each() makes one alternative per item; an item may be an OR list");
    TEST_ASSERT(bgp_ribout_flowspec_parse_component(&block, "dst-port", "1000 x 64") == 0 &&
                block.flowspec->components[FLOWSPEC_DEST_PORT].step_count == 64 &&
                block.flowspec->components[FLOWSPEC_DEST_PORT].alternatives[0].values[0].op == 0x91,
                "1000 x 64 steps one comparison; the width fits the last value (1063, 2 octets)");
    TEST_ASSERT(bgp_ribout_flowspec_instances(&block) == 128, "Components multiply: 2 protocols x 64 ports");
    bgp_ribout_destroy(&block);

    TEST_ASSERT(flowspec_rejects("protocol", "each(6)") && flowspec_rejects("protocol", "each(6,,17)") &&
                flowspec_rejects("protocol", "each(6, 17") && flowspec_rejects("dst-port", "80 x 0") &&
                flowspec_rejects("dst-port", ">=1&<=2 x 3") && flowspec_rejects("tcp-flags", "syn x 2") &&
                flowspec_rejects("dst-port", "4294967295 x 2"),
                "each() needs two items; x needs one numeric comparison, a count, and 32-bit values");

    TEST_ASSERT(flowspec_text_is("dst-port", ">=1024&<=2048 80:2", FLOWSPEC_DEST_PORT,
                                 "dst-port >=1024&<=2048 80:2") &&
                flowspec_text_is("tcp-flags", "18 !any(fin):2", FLOWSPEC_TCP_FLAGS, "tcp-flags syn+ack !any(fin):2") &&
                flowspec_text_is("protocol", "each( 6,17 )", FLOWSPEC_IP_PROTOCOL, "protocol each(6, 17)") &&
                flowspec_text_is("dst-port", "1000 x 64", FLOWSPEC_DEST_PORT, "dst-port 1000 x 64") &&
                flowspec_text_is("src-prefix", "2001:db8::/16-64 x 4", FLOWSPEC_SRC_PREFIX,
                                 "src-prefix 2001:db8::/16-64 x 4"),
                "Canonical text: bare equality, any(), each(), x count, widths only where they differ");
}

/*
 * An IPv4 FlowSpec VPN block: 2 destination x 2 source prefixes x 2 protocols, 2 RDs, 2 path-ids, and a mark that
 * rotates between two values.
 */
static void setup_flowspec_generator_block(bgp_ribout_config_t *block) {
    bgp_ribout_init(block, "flowspec");
    bgp_ribout_parse_address_family(block, "address-family ipv4 flowspec-vpn");
    bgp_ribout_parse_rd(block, "rd 65000:1 65000:2");
    bgp_ribout_parse_path_ids(block, "path-id 7 8");
    bgp_ribout_parse_prefix(block, "prefix 10.0.0.0/24 x 2");
    bgp_ribout_flowspec_parse_component(block, "src-prefix", "192.0.2.0/30 x 2");
    bgp_ribout_flowspec_parse_component(block, "protocol", "each(6, 17)");
    bgp_ribout_flowspec_parse_action(block, "mark 10 46");
}

/*
 * The path is the given NLRI instance with RD index rd and path-id path_id, and its mark is dscp.
 */
static int flowspec_path_is(const bgp_ribout_config_t *block, const bgp_gen_path_t *path,
                            uint64_t instance, uint32_t rd, uint32_t path_id, uint8_t dscp) {
    route_distinguisher_t expected_rd = bgp_ribout_rds_at(block, rd);
    return path->has_flowspec && path->flowspec_instance == instance &&
           path->has_rd && memcmp(&path->rd, &expected_rd, sizeof(path->rd)) == 0 &&
           path->path_id == path_id && path->ext_comm_len == 8 && path->ext_comm_data[7] == dscp;
}

/*
 * The preview text of NLRI instance is expected.
 */
static int flowspec_instance_text_is(const bgp_ribout_config_t *block, uint64_t instance, const char *expected) {
    char text[256];

    bgp_ribout_flowspec_nlri_to_string(block, instance, text, sizeof(text));
    return strcmp(text, expected) == 0;
}

/*
 * Test 44: FlowSpec Generator Order And Totals
 */
void test_flowspec_generator_order_and_totals() {
    printf("\n=== Test 44: FlowSpec Generator Order And Totals ===\n");

    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;
    bgp_gen_path_t      path;
    bgp_gen_path_t      paths[32];
    int                 count = 0;

    setup_flowspec_generator_block(&block);

    TEST_ASSERT(bgp_ribout_resolve_family(&block) == BGP_RIBOUT_FAMILY_FLOWSPEC_VPN_IPV4,
                "FlowSpec block resolves to IPv4 FlowSpec VPN");
    TEST_ASSERT(bgp_ribout_generator_init(&gen, &block) == 0, "FlowSpec generator initialization successful");
    TEST_ASSERT(gen.total_paths == 32 && bgp_ribout_total_paths(&block) == 32,
                "FlowSpec total paths = 2 dst x 2 src x 2 protocols x 2 RDs x 2 path-ids");

    while (count < 32 && bgp_ribout_generator_has_next(&gen) &&
           bgp_ribout_generator_next(&gen, &paths[count]) == 0) {
        count++;
    }
    TEST_ASSERT(count == 32 && !bgp_ribout_generator_has_next(&gen),
                "FlowSpec generator emits exactly the total path count");
    TEST_ASSERT(flowspec_path_is(&block, &paths[0], 0, 0, 7, 10) &&
                paths[0].prefix_af == AF_INET && paths[0].next_hop_af == 0,
                "Path 1 is instance 0 at the first RD and path-id, without a next hop");
    TEST_ASSERT(flowspec_path_is(&block, &paths[1], 0, 0, 8, 46),
                "Path 2 advances the path-id first; the mark rotates per path");
    TEST_ASSERT(flowspec_path_is(&block, &paths[2], 0, 1, 7, 10), "Path 3 advances the RD after the path-id wraps");
    TEST_ASSERT(flowspec_path_is(&block, &paths[4], 1, 0, 7, 10) &&
                flowspec_path_is(&block, &paths[31], 7, 1, 8, 46),
                "Every 4 paths (RD x path-id) advance the NLRI instance");
    TEST_ASSERT(flowspec_instance_text_is(&block, 0, "prefix 10.0.0.0/24 src-prefix 192.0.2.0/30 protocol 6") &&
                flowspec_instance_text_is(&block, 1, "prefix 10.0.0.0/24 src-prefix 192.0.2.0/30 protocol 17") &&
                flowspec_instance_text_is(&block, 2, "prefix 10.0.0.0/24 src-prefix 192.0.2.4/30 protocol 6") &&
                flowspec_instance_text_is(&block, 4, "prefix 10.0.1.0/24 src-prefix 192.0.2.0/30 protocol 6"),
                "Instances step the last component fastest, then src-prefix, then the destination");

    bgp_ribout_generator_reset(&gen);
    TEST_ASSERT(bgp_ribout_generator_next(&gen, &path) == 0 &&
                flowspec_path_is(&block, &path, 0, 0, 7, 10),
                "FlowSpec generator reset restarts at instance 0 and the first mark");

    bgp_ribout_destroy(&block);
}

/*
 * Test 45: Color Parsing And Family
 * Parse a color line into a new block; the block keeps the values for the caller to check.
 */
static int color_parses(bgp_ribout_config_t *block, const char *line) {
    bgp_ribout_init(block, "color");
    return bgp_ribout_parse_color(block, line) == 0;
}

static void test_color_set_validation(void) {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "color-set");
    int ok = bgp_ribout_edit(&block, "color", "set 100 co 01 300 co 10 200", 0) == 0;
    TEST_ASSERT(ok && block.color_set && !block.color_rotate && block.color_count == 3 &&
                bgp_ribout_colors_at(&block, 1) == 300 && bgp_ribout_color_co_at(&block, 1) == BGP_COLOR_CO_ANY,
                "Color set preserves input order and per-value CO types");
    bgp_ribout_config_t before = block;
    const char *bad[] = {"set", "set rotate 1", "rotate set 1", "set 1 co 2", "set -1", "set 4294967296",
                        "set 1 x 1000000", "set range(1,1000000)", "set 4294967295 x 2"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(*bad); i++) {
        TEST_ASSERT(bgp_ribout_edit(&block, "color", bad[i], 0) < 0 && !memcmp(&before, &block, sizeof(block)), bad[i]);
    }
    TEST_ASSERT(bgp_ribout_edit(&block, "color", "set 4294967294 x 2 co 01", 0) == 0 &&
                block.color_set && block.color_count == 2 && bgp_ribout_colors_at(&block, 1) == UINT32_MAX,
                "Color set sequences retain the full unsigned Color range");
    TEST_ASSERT(bgp_ribout_edit(&block, "color", "set range(5,7) co 10", 0) == 0 &&
                block.color_count == 3 && bgp_ribout_color_co_at(&block, 2) == BGP_COLOR_CO_ANY,
                "Color set accepts compact ranges with shared CO types");
    bgp_ribout_edit(&block, "prefix", "10.0.0.0/24 x 2", 0);
    bgp_ribout_edit(&block, "next-hop", "192.0.2.1", 0);
    bgp_ribout_edit(&block, "rotate-period", "2", 0);
    bgp_ribout_gen_t gen;
    TEST_ASSERT(bgp_ribout_generator_init(&gen, &block) == 0 && gen.total_paths == 2,
                "A fixed Color set neither multiplies paths nor participates in rotate-period");
    bgp_ribout_config_t *copy = bgp_ribout_config_clone(&block);
    TEST_ASSERT(copy && copy->color_set && copy->colors != block.colors &&
                bgp_ribout_edit(&block, "color", "9 10", 0) == 0 && !block.color_set &&
                bgp_ribout_colors_at(copy, 2) == 7, "Color set snapshots own their values; ordinary lists restore rotation");
    bgp_ribout_config_clone_free(copy);
    bgp_ribout_edit(&block, "color", "set 1 2", 0);
    TEST_ASSERT(bgp_ribout_edit(&block, "color", "", 1) == 0 && !block.color_set && !block.color_count,
                "no color clears set mode and its inventory");
    bgp_ribout_destroy(&block);

    bgp_ribout_init(&block, "policy");
    bgp_ribout_edit(&block, "address-family", "ipv4 srpolicy", 0);
    TEST_ASSERT(bgp_ribout_edit(&block, "color", "set 100 200", 0) < 0,
                "An explicitly configured SR Policy rejects color set");
    bgp_ribout_edit(&block, "address-family", "", 1);
    bgp_ribout_edit(&block, "color", "set 100 200", 0);
    bgp_ribout_edit(&block, "distinguisher", "1", 0);
    bgp_ribout_edit(&block, "endpoint", "192.0.2.1", 0);
    bgp_ribout_edit(&block, "rt", "192.0.2.1:1", 0);
    bgp_ribout_edit(&block, "segment-list", "1 weight 1 mpls 16000", 0);
    TEST_ASSERT(bgp_ribout_resolve_family(&block) == BGP_RIBOUT_FAMILY_SR_POLICY_IPV4 &&
                bgp_ribout_generator_init(&gen, &block) < 0,
                "Family inference after a Color set cannot treat it as SR Policy NLRI colors");
    bgp_ribout_destroy(&block);
}

void test_color_parsing_and_family() {
    printf("\n=== Test 45: Color Parsing And Family ===\n");

    bgp_ribout_config_t block;

    TEST_ASSERT(color_parses(&block, "color 4 co 01 7 9 co 11") && block.color_count == 3 &&
                bgp_ribout_colors_at(&block, 0) == 4 && bgp_ribout_color_co_at(&block, 0) == BGP_COLOR_CO_NULL &&
                bgp_ribout_colors_at(&block, 1) == 7 && bgp_ribout_color_co_at(&block, 1) == BGP_COLOR_CO_SPECIFIC &&
                bgp_ribout_colors_at(&block, 2) == 9 && bgp_ribout_color_co_at(&block, 2) == BGP_COLOR_CO_RESERVED,
                "A co after a list value sets the CO type of that value only");
    bgp_ribout_destroy(&block);
    TEST_ASSERT(color_parses(&block, "color 1 x 3 co 10") && block.color_count == 3 &&
                bgp_ribout_colors_at(&block, 2) == 3 && bgp_ribout_color_co_at(&block, 0) == BGP_COLOR_CO_ANY &&
                bgp_ribout_color_co_at(&block, 2) == BGP_COLOR_CO_ANY,
                "A co at the end of a sequence sets the CO type of every value");
    bgp_ribout_destroy(&block);
    TEST_ASSERT(color_parses(&block, "color range(5,6) co 01") && block.color_count == 2 &&
                bgp_ribout_colors_at(&block, 1) == 6 && bgp_ribout_color_co_at(&block, 1) == BGP_COLOR_CO_NULL,
                "A co at the end of a range sets the CO type of every value");
    bgp_ribout_destroy(&block);
    TEST_ASSERT(color_parses(&block, "color 200 201") && bgp_ribout_color_co_at(&block, 0) == 0 && bgp_ribout_color_co_at(&block, 1) == 0,
                "Without co every value has CO type 00");
    bgp_ribout_destroy(&block);

    bgp_ribout_init(&block, "color-bad");
    TEST_ASSERT(bgp_ribout_parse_color(&block, "color co 01 1") < 0 &&
                bgp_ribout_parse_color(&block, "color 1 co 2") < 0 &&
                bgp_ribout_parse_color(&block, "color 1 co") < 0 &&
                bgp_ribout_parse_color(&block, "color 1 co 01 x 3") < 0 &&
                bgp_ribout_parse_color(&block, "color 1 x 3 co 01 co 10") < 0,
                "co needs a value before it and CO bits 00-11; it must end a sequence");
    bgp_ribout_destroy(&block);

    bgp_ribout_init(&block, "color-sr");
    bgp_ribout_parse_address_family(&block, "address-family ipv4 srpolicy");
    TEST_ASSERT(bgp_ribout_parse_color(&block, "color 1 co 01") < 0 &&
                bgp_ribout_parse_color(&block, "color 1 co 00") == 0,
                "An explicit SR Policy block rejects a CO type other than 00");
    bgp_ribout_destroy(&block);

    bgp_ribout_init(&block, "color-only");
    bgp_ribout_parse_color(&block, "color 1");
    TEST_ASSERT(bgp_ribout_resolve_family(&block) == BGP_RIBOUT_FAMILY_NONE,
                "color alone gives no family (it no longer marks SR Policy)");
    bgp_ribout_parse_prefix(&block, "prefix 10.1.0.0/24");
    TEST_ASSERT(bgp_ribout_resolve_family(&block) == BGP_RIBOUT_FAMILY_IPV4_UNICAST,
                "prefix + color resolves to IPv4 unicast");
    bgp_ribout_destroy(&block);

    bgp_ribout_init(&block, "color-policy");
    bgp_ribout_parse_distinguisher(&block, "distinguisher 1");
    bgp_ribout_parse_color(&block, "color 1");
    bgp_ribout_parse_endpoint(&block, "endpoint 10.255.0.201");
    TEST_ASSERT(bgp_ribout_resolve_family(&block) == BGP_RIBOUT_FAMILY_SR_POLICY_IPV4,
                "distinguisher + color + endpoint still resolves to SR Policy");
    bgp_ribout_destroy(&block);

    bgp_ribout_init(&block, "color-evpn");
    bgp_ribout_parse_rd(&block, "rd 65000:1");
    bgp_ribout_parse_label(&block, "label 100");
    bgp_ribout_parse_mac(&block, "mac 00:00:5e:00:53:01");
    bgp_ribout_parse_color(&block, "color 5");
    TEST_ASSERT(bgp_ribout_resolve_family(&block) == BGP_RIBOUT_FAMILY_EVPN_TYPE2,
                "EVPN Type 2 fields + color resolve to EVPN Type 2");
    bgp_ribout_destroy(&block);
}

/*
 * Test 46: Color Community Rotation
 * The extended communities of the path are exactly one Color community, the library encoding of (color, co_type).
 */
static int path_has_only_color(const bgp_gen_path_t *path, uint32_t color, uint8_t co_type) {
    bgp_path_attr_t *expected = bgp_attr_create_ext_comm_color(color, co_type);
    int              same = expected && path->ext_comm_len == 8 && memcmp(path->ext_comm_data, expected->value, 8) == 0;

    bgp_path_attr_free(expected);
    return same;
}

void test_color_community_rotation() {
    printf("\n=== Test 46: Color Community Rotation ===\n");

    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;
    bgp_gen_path_t      paths[6];
    int                 count = 0;
    int                 lockstep = 1;

    bgp_ribout_init(&block, "colored");
    bgp_ribout_parse_prefix(&block, "prefix 10.1.0.0/24 x 6");
    bgp_ribout_parse_next_hop(&block, "next-hop 10.255.0.201 x 3");
    bgp_ribout_parse_color(&block, "color 1 x 3 co 01");

    TEST_ASSERT(bgp_ribout_generator_init(&gen, &block) == 0 && gen.total_paths == 6,
                "color does not multiply unicast paths (6 prefixes, 6 paths)");
    while (count < 6 && bgp_ribout_generator_has_next(&gen) && bgp_ribout_generator_next(&gen, &paths[count]) == 0) {
        count++;
    }
    for (int i = 0; i < count; i++) {
        lockstep &= path_has_only_color(&paths[i], 1u + (uint32_t)(i % 3), BGP_COLOR_CO_NULL) &&
                    (ntohl(paths[i].next_hop_addr.ipv4.s_addr) & 0xFFu) == 201u + (uint32_t)(i % 3);
    }
    TEST_ASSERT(count == 6 && lockstep, "Path i carries color 1 + i mod 3 (CO 01) and next hop .201 + i mod 3");
    bgp_ribout_destroy(&block);

    bgp_ribout_init(&block, "colored-policy");
    bgp_ribout_parse_distinguisher(&block, "distinguisher 1");
    bgp_ribout_parse_color(&block, "color 1 x 3");
    bgp_ribout_parse_endpoint(&block, "endpoint 10.255.0.201");
    bgp_ribout_parse_rt(&block, "rt 10.255.0.5:0");
    bgp_ribout_parse_segment_list(&block, "segment-list 1 weight 1 mpls 16001");
    count = 0;
    TEST_ASSERT(bgp_ribout_generator_init(&gen, &block) == 0 && gen.total_paths == 3,
                "SR Policy colors still multiply the paths");
    while (count < 3 && bgp_ribout_generator_has_next(&gen) && bgp_ribout_generator_next(&gen, &paths[count]) == 0) {
        count++;
    }
    // The only extended community is the RT (0x0102), so no Color community is added.
    TEST_ASSERT(count == 3 && paths[0].color == 1 && paths[2].color == 3 &&
                paths[0].ext_comm_len == 8 && paths[0].ext_comm_data[0] == 0x01 && paths[0].ext_comm_data[1] == 0x02 &&
                paths[2].ext_comm_len == 8,
                "SR Policy color goes to the NLRI, not to a Color community");
    bgp_ribout_destroy(&block);

    bgp_ribout_init(&block, "colored-policy-co");
    bgp_ribout_parse_distinguisher(&block, "distinguisher 1");
    bgp_ribout_parse_color(&block, "color 1 co 01");
    bgp_ribout_parse_endpoint(&block, "endpoint 10.255.0.201");
    bgp_ribout_parse_rt(&block, "rt 10.255.0.5:0");
    TEST_ASSERT(bgp_ribout_generator_init(&gen, &block) < 0,
                "An inferred SR Policy block with a CO type fails at generation");
    bgp_ribout_destroy(&block);
}

/*
 * The local administrator of the path's first extended community, a route target from rt-set: four octets after a
 * two-octet AS (type 0x00, RFC 4360), two after a four-octet AS such as 65551 (type 0x02, RFC 5668).
 */
static uint32_t path_rt_value(const bgp_gen_path_t *path) {
    const uint8_t *rt = path->ext_comm_data;

    if (rt[0] == 0x02) {
        return ((uint32_t)rt[6] << 8) | rt[7];
    }
    return ((uint32_t)rt[4] << 24) | ((uint32_t)rt[5] << 16) | ((uint32_t)rt[6] << 8) | rt[7];
}

/*
 * label rotate: one label per path in turn, in step with rt-set, so path i carries RT 65551:(i % 100 + 1) and label
 * 24001 + i % 100; the path count is the prefix count. A plain label list multiplies the paths instead.
 */
void test_label_rotate_follows_rt_set() {
    printf("\n=== label rotate: per-path labels in step with rt-set ===\n");
    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;
    bgp_gen_path_t      path;
    int                 aligned = 1;
    int                 generated = 0;

    bgp_ribout_init(&block, "vrfs");
    bgp_ribout_parse_prefix(&block, "prefix 10.20.0.0/24 x 250");
    bgp_ribout_parse_rd(&block, "rd 65551:1");
    bgp_ribout_parse_next_hop(&block, "next-hop 192.0.2.1");
    for (int first = 1; first <= 100; first += 25) {
        char line[512];
        int  len = snprintf(line, sizeof(line), "rt-set");

        for (int i = first; i < first + 25; i++) {
            len += snprintf(line + len, sizeof(line) - (size_t)len, " [65551:%d]", i);
        }
        TEST_ASSERT(bgp_ribout_parse_rt_set(&block, line) == 0, "rt-set lines append 25 sets each");
    }
    TEST_ASSERT(block.rt_set_count == 100, "100 explicit RT sets retain their order");
    TEST_ASSERT(bgp_ribout_parse_label(&block, "label rotate 24001 x 100") == 0 && block.label_rotate &&
                    block.label_count == 100,
                "Parse label rotate <base> x <count>");
    TEST_ASSERT(bgp_ribout_total_paths(&block) == 250, "Rotating labels do not multiply the paths");

    TEST_ASSERT(bgp_ribout_generator_init(&gen, &block) == 0, "Generator initializes");
    while (bgp_ribout_generator_has_next(&gen) && bgp_ribout_generator_next(&gen, &path) == 0) {
        aligned = aligned && path.label == 24001u + (uint32_t)(generated % 100) &&
                  path_rt_value(&path) == (uint32_t)(generated % 100) + 1;
        generated++;
    }
    TEST_ASSERT(generated == 250 && aligned, "Path i carries label 24001 + i % 100 and RT 65551:(i % 100 + 1)");

    TEST_ASSERT(bgp_ribout_parse_label(&block, "label 24001 x 100") == 0 && !block.label_rotate &&
                    bgp_ribout_total_paths(&block) == 25000,
                "A plain label list multiplies the paths again");
    TEST_ASSERT(bgp_ribout_parse_label(&block, "label rotate 24001 24002") == 0 && block.label_rotate &&
                    block.label_count == 2,
                "Parse label rotate with a value list");
    TEST_ASSERT(bgp_ribout_parse_label(&block, "label rotate") < 0, "label rotate needs values");
    bgp_ribout_destroy(&block);
}

/*
 * ip rotate binds MAC i to IP i (mod the IP count) in an EVPN Type 2 ribout; Type 2 labels and rt-set rotate in step,
 * so the binding, its labels and its route targets go together. Plain ip multiplies the MACs.
 */
void test_ip_rotate_binds_macs() {
    printf("\n=== ip rotate: EVPN Type 2 MAC/IP bindings ===\n");
    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;
    bgp_gen_path_t      path;
    int                 bound = 1;
    int                 generated = 0;

    bgp_ribout_init(&block, "hosts");
    bgp_ribout_parse_rd(&block, "rd 65551:7");
    bgp_ribout_parse_mac(&block, "mac 02:00:00:00:00:01 x 200");
    bgp_ribout_parse_next_hop(&block, "next-hop 192.0.2.1");
    bgp_ribout_parse_label(&block, "label 20001 x 100");
    bgp_ribout_parse_label2(&block, "label2 30001 x 100");
    bgp_ribout_parse_rt_set(&block, "rt-set [65551:1] [65551:2] [65551:3] [65551:4] [65551:5] [65551:6] [65551:7] "
                                    "[65551:8] [65551:9] [65551:10]");
    TEST_ASSERT(bgp_ribout_parse_ip(&block, "ip rotate 10.1.0.1 x 200") == 0 && block.ip_rotate &&
                    block.ip_spec.count == 200,
                "Parse ip rotate <ip> x <count>");
    TEST_ASSERT(bgp_ribout_total_paths(&block) == 200, "Rotating IPs do not multiply the MACs");
    TEST_ASSERT(bgp_ribout_generator_init(&gen, &block) == 0, "Generator initializes");
    while (bgp_ribout_generator_has_next(&gen) && bgp_ribout_generator_next(&gen, &path) == 0) {
        uint32_t ip = ntohl(path.ip_addr.ipv4.s_addr);

        bound = bound && path.has_ip && path.mac_addr[5] == (uint8_t)(1 + generated) &&
                path.mac_addr[4] == (uint8_t)((1 + generated) >> 8) && ip == 0x0A010001u + (uint32_t)generated &&
                path.label == 20001u + (uint32_t)(generated % 100) &&
                path.label2 == 30001u + (uint32_t)(generated % 100) &&
                path_rt_value(&path) == (uint32_t)(generated % 10) + 1;
        generated++;
    }
    TEST_ASSERT(generated == 200 && bound, "Path i binds MAC i to IP i, with label, label2 and RT i in turn");

    TEST_ASSERT(bgp_ribout_parse_ip(&block, "ip rotate 10.1.0.1 x 50") == 0, "Parse fewer rotating IPs than MACs");
    TEST_ASSERT(bgp_ribout_generator_init(&gen, &block) == 0, "Generator initializes again");
    bound = 1;
    for (int i = 0; i < 120 && bgp_ribout_generator_next(&gen, &path) == 0; i++) {
        bound = bound && ntohl(path.ip_addr.ipv4.s_addr) == 0x0A010001u + (uint32_t)(i % 50);
    }
    TEST_ASSERT(bound, "Path i carries IP i mod the IP count");

    TEST_ASSERT(bgp_ribout_parse_ip(&block, "ip 10.1.0.1 x 4") == 0 && !block.ip_rotate &&
                    bgp_ribout_total_paths(&block) == 800,
                "Plain ip multiplies the MACs again");
    TEST_ASSERT(bgp_ribout_parse_ip(&block, "ip rotate 2001:db8::1") == 0 && block.ip2_rotate &&
                    block.ip2_spec.af == AF_INET6 && block.ip2_spec.count == 1 && block.ip_spec.af == AF_INET &&
                    block.ip_spec.count == 4,
                "An IPv6 ip line adds the second address family, the IPv4 one stays");
    TEST_ASSERT(bgp_ribout_parse_ip(&block, "ip rotate") < 0 && bgp_ribout_parse_ip(&block, "ip rotate x 4") < 0 &&
                    bgp_ribout_parse_ip(&block, "ip rotate 10.1.0.1 x 0") < 0,
                "Reject ip rotate without an address or with count 0");
    bgp_ribout_destroy(&block);
}

/*
 * The assigned number of an RD with a two-octet field (types 1 and 2, RFC 4364 section 4.2).
 */
static uint32_t rd_assigned16(const route_distinguisher_t *rd) {
    return ((uint32_t)rd->value[4] << 8) | rd->value[5];
}

/*
 * The route targets' local administrators of a path, in rt-set order.
 */
static uint32_t path_rt_at(const bgp_gen_path_t *path, int n) {
    const uint8_t *rt = path->ext_comm_data + 8 * n;

    return rt[0] == 0x02 ? (((uint32_t)rt[6] << 8) | rt[7]) :
                           (((uint32_t)rt[4] << 24) | ((uint32_t)rt[5] << 16) | ((uint32_t)rt[6] << 8) | rt[7]);
}

/*
 * One VRF per rotation step: rd rotate, an rt-set sequence and label rotate, all of period 100 (rotate-period checks
 * it), give path i the RD, route targets and label of VRF i % 100 + 1 without multiplying the prefixes.
 */
void test_rd_rotate_and_rt_set_sequence() {
    printf("\n=== rd rotate, rt-set <set> x <count>, rotate-period ===\n");
    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;
    bgp_gen_path_t      path;
    int                 in_step = 1;
    int                 generated = 0;

    bgp_ribout_init(&block, "vrfs");
    bgp_ribout_parse_prefix(&block, "prefix 10.20.0.0/24 x 250");
    bgp_ribout_parse_next_hop(&block, "next-hop 192.0.2.1");
    TEST_ASSERT(bgp_ribout_parse_rd(&block, "rd rotate 65551:1 x 100") == 0 && block.rd_rotate &&
                    block.rd_count == 100,
                "Parse rd rotate <base> x <count>");
    TEST_ASSERT(bgp_ribout_parse_rt_set(&block, "rt-set [65551:1,65551:1001] x 100") == 0 &&
                    block.rt_set_count == 100 && bgp_ribout_rt_set_at(&block, 99).count == 2,
                "Parse rt-set <set> x <count>: 100 sets of two route targets");
    bgp_ribout_parse_label(&block, "label rotate 24001 x 100");
    TEST_ASSERT(bgp_ribout_parse_rotate_period(&block, "rotate-period 100") == 0 && block.rotate_period == 100,
                "Parse rotate-period");
    TEST_ASSERT(bgp_ribout_total_paths(&block) == 250, "Rotating RDs do not multiply the prefixes");
    TEST_ASSERT(bgp_ribout_generator_init(&gen, &block) == 0, "Lists of the rotate-period's length generate");
    while (bgp_ribout_generator_has_next(&gen) && bgp_ribout_generator_next(&gen, &path) == 0) {
        uint32_t k = (uint32_t)(generated % 100) + 1;

        in_step = in_step && path.has_rd && rd_assigned16(&path.rd) == k && path_rt_at(&path, 0) == k &&
                  path_rt_at(&path, 1) == 1000 + k && path.label == 24000 + k &&
                  ntohl(path.prefix_addr.ipv4.s_addr) == 0x0A140000u + ((uint32_t)generated << 8);
        generated++;
    }
    TEST_ASSERT(generated == 250 && in_step, "Path i carries RD, route targets and label of VRF i % 100 + 1");

    TEST_ASSERT(bgp_ribout_parse_rd(&block, "rd 65551:1 x 100") == 0 && !block.rd_rotate &&
                    bgp_ribout_total_paths(&block) == 25000,
                "A plain RD list multiplies the prefixes again");
    TEST_ASSERT(bgp_ribout_parse_rd(&block, "rd rotate 65551:7 65551:9") == 0 && block.rd_rotate &&
                    block.rd_count == 2,
                "Parse rd rotate with a value list");
    TEST_ASSERT(bgp_ribout_parse_rd(&block, "rd rotate") < 0, "rd rotate needs values");
    bgp_ribout_destroy(&block);
}

/*
 * rt-set sequences: appended to other sets, the local administrator's width checked per route target type.
 */
void test_rt_set_sequence_limits() {
    printf("\n=== rt-set sequences and their limits ===\n");
    bgp_ribout_config_t block;

    bgp_ribout_init(&block, "rt-seq");
    TEST_ASSERT(bgp_ribout_parse_rt_set(&block, "rt-set [65551:1] [65551:5] x 3") == 0 && block.rt_set_count == 4 &&
                    ((bgp_ribout_rt_set_at(&block, 3).values[0].bytes[6] << 8) |
                     bgp_ribout_rt_set_at(&block, 3).values[0].bytes[7]) == 7,
                "Sets and a sequence on one line: [1] [5] [6] [7]");
    TEST_ASSERT(bgp_ribout_parse_rt_set(&block, "rt-set [65000:4294967294] x 2") == 0 && block.rt_set_count == 6,
                "A two-octet AS route target counts in its four-octet local administrator");
    TEST_ASSERT(bgp_ribout_parse_rt_set(&block, "rt-set [65000:4294967295] x 2") < 0,
                "Reject a sequence past a four-octet local administrator");
    TEST_ASSERT(bgp_ribout_parse_rt_set(&block, "rt-set [65551:65535] x 2") < 0,
                "Reject a sequence past a four-octet AS route target's two-octet local administrator");
    TEST_ASSERT(bgp_ribout_parse_rt_set(&block, "rt-set [192.0.2.1:65534] x 2") == 0,
                "An IPv4-address route target counts in its two-octet local administrator");
    TEST_ASSERT(bgp_ribout_parse_rt_set(&block, "rt-set [192.0.2.1:65535] x 2") < 0,
                "Reject a sequence past an IPv4-address route target's local administrator");
    bgp_ribout_destroy(&block);
    bgp_ribout_init(&block, "rt-seq");
    TEST_ASSERT(bgp_ribout_parse_rt_set(&block, "rt-set [65551:1] x 2560") == 0 && block.rt_set_count == 2560 &&
                bgp_ribout_rt_set_at(&block, 2559).values[0].bytes[6] == 10 &&
                bgp_ribout_rt_set_at(&block, 2559).values[0].bytes[7] == 0,
                "Ten times the old RT-set inventory retains the final value");
    TEST_ASSERT(bgp_ribout_parse_rt_set(&block, "rt-set [65551:1] x 0") < 0 &&
                    bgp_ribout_parse_rt_set(&block, "rt-set [65551:1] x") < 0,
                "Reject a sequence without a count");
    bgp_ribout_destroy(&block);

    bgp_ribout_init(&block, "rt-million");
    TEST_ASSERT(bgp_ribout_parse_rt_set(&block, "rt-set [65000:1,65001:100] x 1000000 [65551:42] x 2") == 0 &&
                block.rt_set_count == 1000002 && block.rt_set_group_count == 2 &&
                bgp_ribout_config_bytes(&block) < 16384,
                "Million-set sequences mixed on a line occupy two compact groups");
    bgp_ribout_config_t *copy = bgp_ribout_config_clone(&block);
    bgp_ribout_destroy(&block);
    TEST_ASSERT(copy != NULL, "Compact RT groups deep-copy independently of their owner");
    if (copy) {
        bgp_rt_set_spec_t first = bgp_ribout_rt_set_at(copy, 0);
        bgp_rt_set_spec_t last = bgp_ribout_rt_set_at(copy, 999999);
        bgp_rt_set_spec_t next = bgp_ribout_rt_set_at(copy, 1000000);
        bgp_rt_set_spec_t end = bgp_ribout_rt_set_at(copy, 1000001);
        const uint8_t expected[] = {0x00, 0x02, 0xfd, 0xe8, 0x00, 0x0f, 0x42, 0x40};
        TEST_ASSERT(first.values[0].bytes[7] == 1 && last.count == 2 &&
                    memcmp(last.values[0].bytes, expected, sizeof(expected)) == 0 &&
                    next.values[0].bytes[7] == 42 && end.values[0].bytes[7] == 43,
                    "Lookup preserves exact first/last RT wire bytes and mixed-group boundary values");
        bgp_ribout_config_clone_free(copy);
    }
}

/*
 * rotate-every n: the attribute rotations and random values advance once every n paths, so blocks of n consecutive
 * prefixes share them (each VRF a contiguous block). NLRI keys still advance every path.
 */
void test_rotate_every_blocks() {
    printf("\n=== rotate-every: blocks of paths share their rotations ===\n");
    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;
    bgp_gen_path_t      paths[10];
    int                 blocked = 1;

    bgp_ribout_init(&block, "blocks");
    bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/24 x 10");
    bgp_ribout_parse_rd(&block, "rd rotate 65551:1 x 3");
    bgp_ribout_parse_label(&block, "label rotate 100 x 3");
    bgp_ribout_parse_next_hop(&block, "next-hop 192.0.2.1 x 2");
    bgp_ribout_parse_rt_set(&block, "rt-set [65551:1] x 3");
    bgp_ribout_parse_med(&block, "med range(1,3)");
    bgp_ribout_parse_localpref(&block, "localpref rand(100000)");
    TEST_ASSERT(bgp_ribout_parse_rotate_every(&block, "rotate-every 4") == 0 && block.rotate_every == 4,
                "Parse rotate-every");
    TEST_ASSERT(bgp_ribout_total_paths(&block) == 10, "rotate-every does not change the path count");
    TEST_ASSERT(bgp_ribout_generator_init(&gen, &block) == 0, "Generator initializes");
    for (int i = 0; i < 10; i++) {
        blocked = blocked && bgp_ribout_generator_next(&gen, &paths[i]) == 0;
    }
    for (int i = 0; i < 10; i++) {
        uint32_t step = (uint32_t)(i / 4);

        blocked = blocked && ntohl(paths[i].prefix_addr.ipv4.s_addr) == 0x0A000000u + ((uint32_t)i << 8) &&
                  rd_assigned16(&paths[i].rd) == 1 + step % 3 && paths[i].label == 100 + step % 3 &&
                  ntohl(paths[i].next_hop_addr.ipv4.s_addr) == 0xC0000201u + step % 2 &&
                  path_rt_at(&paths[i], 0) == 1 + step % 3 && paths[i].med == 1 + step % 3 &&
                  paths[i].local_pref == paths[i - i % 4].local_pref;
    }
    TEST_ASSERT(blocked, "Paths 0-3, 4-7 and 8-9 each share RD, label, next hop, RT, MED and random LOCAL_PREF");
    TEST_ASSERT(paths[0].local_pref != paths[4].local_pref || paths[4].local_pref != paths[8].local_pref,
                "Random values still change from block to block");
    TEST_ASSERT(bgp_ribout_parse_rotate_every(&block, "rotate-every 0") < 0 &&
                    bgp_ribout_parse_rotate_every(&block, "rotate-every") < 0,
                "Reject rotate-every 0 or without a value");
    bgp_ribout_destroy(&block);
}

/*
 * rotate-period n: every rotating list has n values or one; a list of another length is rejected at generation.
 */
void test_rotate_period_checks_lists() {
    printf("\n=== rotate-period: rotating lists stay in step ===\n");
    static const char *const k_mismatches[] = {
        "label rotate 24001 x 99",
        "next-hop 192.0.2.1 x 4",
        "rd rotate 65551:1 x 101",
        "soo 65551:1 65551:2",
    };
    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;

    for (size_t i = 0; i < sizeof(k_mismatches) / sizeof(k_mismatches[0]); i++) {
        int rejected;

        bgp_ribout_init(&block, "period");
        bgp_ribout_parse_prefix(&block, "prefix 10.20.0.0/24 x 100");
        bgp_ribout_parse_rd(&block, "rd 65551:1");
        bgp_ribout_parse_label(&block, "label rotate 24001 x 100");
        bgp_ribout_parse_next_hop(&block, "next-hop 192.0.2.1");
        bgp_ribout_parse_rt_set(&block, "rt-set [65551:1] x 100");
        bgp_ribout_parse_rotate_period(&block, "rotate-period 100");
        TEST_ASSERT(bgp_ribout_generator_init(&gen, &block) == 0, "Lists of period 100 (and of one) generate");
        if (strncmp(k_mismatches[i], "label", 5) == 0) {
            bgp_ribout_parse_label(&block, k_mismatches[i]);
        } else if (strncmp(k_mismatches[i], "next-hop", 8) == 0) {
            bgp_ribout_parse_next_hop(&block, k_mismatches[i]);
        } else if (strncmp(k_mismatches[i], "rd", 2) == 0) {
            bgp_ribout_parse_rd(&block, k_mismatches[i]);
        } else {
            bgp_ribout_parse_soo(&block, k_mismatches[i]);
        }
        rejected = bgp_ribout_generator_init(&gen, &block) < 0;
        printf("  (%s)\n", k_mismatches[i]);
        TEST_ASSERT(rejected, "A rotating list of another length is rejected");
        bgp_ribout_destroy(&block);
    }
}

/*
 * Dual-stack EVPN Type 2: an ip line per address family. With ip rotate MAC i gets IPv4 i and IPv6 i, two routes per
 * MAC; without, each MAC is generated with every IP of both families. rotate-every 2 keeps a host's two bindings on
 * one rotation step, so both carry the same route targets and labels.
 */
void test_dual_stack_type2() {
    printf("\n=== dual-stack EVPN Type 2 MAC/IP bindings ===\n");
    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;
    bgp_gen_path_t      path;
    int                 bound = 1;
    int                 generated = 0;

    bgp_ribout_init(&block, "dual");
    bgp_ribout_parse_rd(&block, "rd 65551:6");
    bgp_ribout_parse_mac(&block, "mac 02:00:00:00:00:01 x 6");
    bgp_ribout_parse_label(&block, "label 40001 x 3");
    bgp_ribout_parse_label2(&block, "label2 30001 x 3");
    bgp_ribout_parse_rt_set(&block, "rt-set [65551:1,65551:1001] x 3");
    bgp_ribout_parse_next_hop(&block, "next-hop 192.0.2.20");
    TEST_ASSERT(bgp_ribout_parse_ip(&block, "ip rotate 172.20.0.1 x 6") == 0 &&
                    bgp_ribout_parse_ip(&block, "ip rotate 2001:db8:20::1 x 6") == 0 && block.ip_spec.af == AF_INET &&
                    block.ip2_spec.af == AF_INET6 && block.ip_rotate && block.ip2_rotate,
                "An ip line per address family");
    bgp_ribout_parse_rotate_every(&block, "rotate-every 2");
    TEST_ASSERT(bgp_ribout_total_paths(&block) == 12, "6 MACs with an IPv4 and an IPv6 binding each: 12 routes");
    TEST_ASSERT(bgp_ribout_generator_init(&gen, &block) == 0, "Generator initializes");
    while (bgp_ribout_generator_has_next(&gen) && bgp_ribout_generator_next(&gen, &path) == 0) {
        uint32_t host = (uint32_t)generated / 2;
        int      ipv6 = generated % 2;

        bound = bound && path.mac_addr[5] == 1 + host && path.has_ip &&
                path.ip_af == (ipv6 ? AF_INET6 : AF_INET) &&
                (ipv6 ? path.ip_addr.ipv6.s6_addr[15] == 1 + host
                      : ntohl(path.ip_addr.ipv4.s_addr) == 0xAC140001u + host) &&
                path_rt_at(&path, 0) == 1 + host % 3 && path_rt_at(&path, 1) == 1001 + host % 3 &&
                path.label == 40001 + host % 3 && path.label2 == 30001 + host % 3;
        generated++;
    }
    TEST_ASSERT(generated == 12 && bound,
                "Host i: IPv4 i then IPv6 i, both with the route targets and labels of rotation step i");

    TEST_ASSERT(bgp_ribout_parse_ip(&block, "ip 172.20.0.1 x 2") == 0 && !block.ip_rotate && block.ip2_rotate &&
                    bgp_ribout_parse_ip(&block, "ip 2001:db8:20::1 x 3") == 0 && !block.ip2_rotate &&
                    bgp_ribout_total_paths(&block) == 6 * (2 + 3),
                "Without rotate each MAC goes with every IP of both families; a line replaces its family");
    TEST_ASSERT(bgp_ribout_edit(&block, "ip", "-", 1) == 0 && block.ip_spec.count == 0 && block.ip2_spec.count == 0,
                "no ip clears both families");
    bgp_ribout_destroy(&block);
}

/*
 * A 32-bit value in network byte order.
 */
static uint32_t be32_at(const uint8_t *c) {
    return ((uint32_t)c[0] << 24) | ((uint32_t)c[1] << 16) | ((uint32_t)c[2] << 8) | c[3];
}

/*
 * The n-th community of a path (4 octets) and the three words of its n-th large community (12 octets).
 */
static uint32_t path_community_at(const bgp_gen_path_t *path, int n) {
    return be32_at(path->community_data + 4 * n);
}

static int path_large_community_is(const bgp_gen_path_t *path, int n, uint32_t global, uint32_t data1, uint32_t data2) {
    const uint8_t *c = path->large_community_data + 12 * n;

    return be32_at(c) == global && be32_at(c + 4) == data1 && be32_at(c + 8) == data2;
}

/*
 * community and large-community: sets in the rt-set style, one set per rotation step. Sets as written and "x <count>"
 * sequences mix on a line and lines append; a sequence steps the low 16 bits of a community (well-known values stay)
 * and local data 2 of a large community. The sets do not multiply the paths.
 */
void test_community_sets_rotate() {
    printf("\n=== community / large-community sets rotate per path ===\n");
    // The expected sets, in rotation order: [65000:1,no-export] [65000:100] [65000:101] [blackhole,65001:7]
    static const uint32_t k_sets[4][2] = {
        {0xFDE80001u, 0xFFFFFF01u}, {0xFDE80064u, 0}, {0xFDE80065u, 0}, {0xFFFF029Au, 0xFDE90007u}};
    static const int k_lens[4] = {2, 1, 1, 2};
    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;
    bgp_gen_path_t      path;
    int                 rotated = 1;
    int                 generated = 0;

    bgp_ribout_init(&block, "comms");
    bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/24 x 13");
    bgp_ribout_parse_next_hop(&block, "next-hop 192.0.2.1");
    TEST_ASSERT(bgp_ribout_parse_community(&block, "community [65000:1,no-export] 65000:100 x 2") == 0 &&
                block.community_group_count == 2 &&
                bgp_ribout_community_sets(&block) == 3,
                "Parse a set and a bare-value sequence on one line: 3 sets");
    TEST_ASSERT(bgp_ribout_parse_community(&block, "community [blackhole,65001:7]") == 0 &&
                block.community_group_count == 3 &&
                bgp_ribout_community_sets(&block) == 4,
                "A second line appends a fourth set");
    TEST_ASSERT(bgp_ribout_parse_large_community(&block, "large-community [65000:1:10,4200000000:0:1] x 3") == 0 &&
                bgp_ribout_large_community_sets(&block) == 3,
                "Parse a large-community sequence of two values: 3 sets");
    TEST_ASSERT(bgp_ribout_total_paths(&block) == 13, "Community sets do not multiply the paths");
    TEST_ASSERT(bgp_ribout_generator_init(&gen, &block) == 0, "Generator initializes");
    while (bgp_ribout_generator_has_next(&gen) && bgp_ribout_generator_next(&gen, &path) == 0) {
        int      set = generated % 4;
        uint32_t step = (uint32_t)(generated % 3);

        rotated = rotated && path.community_len == 4 * k_lens[set] &&
                  path_community_at(&path, 0) == k_sets[set][0] &&
                  (k_lens[set] == 1 || path_community_at(&path, 1) == k_sets[set][1]) &&
                  path.large_community_len == 24 && path_large_community_is(&path, 0, 65000, 1, 10 + step) &&
                  path_large_community_is(&path, 1, 4200000000u, 0, 1 + step);
        generated++;
    }
    TEST_ASSERT(generated == 13 && rotated, "Path i carries community set i % 4 and large-community set i % 3");

    bgp_ribout_destroy(&block);
    bgp_ribout_init(&block, "comms");
    bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/24 x 6");
    TEST_ASSERT(bgp_ribout_parse_community(&block, "community [65000:1,no-export,65535:7] x 3") == 0,
                "Parse a sequence with well-known values");
    TEST_ASSERT(bgp_ribout_generator_init(&gen, &block) == 0, "Generator initializes");
    rotated = 1;
    for (int i = 0; i < 6 && bgp_ribout_generator_next(&gen, &path) == 0; i++) {
        rotated = rotated && path.community_len == 12 &&
                  path_community_at(&path, 0) == 0xFDE80001u + (uint32_t)(i % 3) &&
                  path_community_at(&path, 1) == 0xFFFFFF01u && path_community_at(&path, 2) == 0xFFFF0007u &&
                  path.large_community_len == 0;
    }
    TEST_ASSERT(rotated, "A sequence steps 65000:1 and leaves no-export and 65535:7 as they are");

    TEST_ASSERT(bgp_ribout_edit(&block, "community", "-", 1) == 0 && block.community_group_count == 0,
                "no community clears every set");
    TEST_ASSERT(bgp_ribout_generator_init(&gen, &block) == 0 &&
                bgp_ribout_generator_next(&gen, &path) == 0 &&
                path.community_len == 0,
                "Without sets a path carries no communities");
    bgp_ribout_destroy(&block);
}

/*
 * rotate-every and rotate-period apply to community and large-community sets as to the other rotating lists.
 */
void test_community_sets_rotation_options() {
    printf("\n=== community sets: rotate-every and rotate-period ===\n");
    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;
    bgp_gen_path_t      path;
    int                 in_step = 1;
    int                 generated = 0;

    bgp_ribout_init(&block, "comm-rot");
    bgp_ribout_parse_prefix(&block, "prefix 10.20.0.0/24 x 12");
    bgp_ribout_parse_rd(&block, "rd rotate 65551:1 x 3");
    bgp_ribout_parse_label(&block, "label 24001");
    bgp_ribout_parse_next_hop(&block, "next-hop 192.0.2.1");
    bgp_ribout_parse_rt_set(&block, "rt-set [65551:1] x 3");
    bgp_ribout_parse_community(&block, "community 65000:1 x 3");
    bgp_ribout_parse_large_community(&block, "large-community 65551:0:1 x 3");
    bgp_ribout_parse_rotate_every(&block, "rotate-every 2");
    TEST_ASSERT(bgp_ribout_parse_rotate_period(&block, "rotate-period 3") == 0 &&
                bgp_ribout_generator_init(&gen, &block) == 0,
                "Community lists of the rotate-period's length generate");
    while (bgp_ribout_generator_has_next(&gen) && bgp_ribout_generator_next(&gen, &path) == 0) {
        uint32_t vrf = (uint32_t)(generated / 2) % 3 + 1;

        in_step = in_step && rd_assigned16(&path.rd) == vrf && path_rt_at(&path, 0) == vrf &&
                  path.community_len == 4 && path_community_at(&path, 0) == (65000u << 16 | vrf) &&
                  path.large_community_len == 12 && path_large_community_is(&path, 0, 65551, 0, vrf);
        generated++;
    }
    TEST_ASSERT(generated == 12 && in_step,
                "rotate-every 2: paths 2k and 2k+1 carry the RD, route target, community and large community of "
                "VRF k % 3 + 1");

    bgp_ribout_parse_community(&block, "community 65000:9");
    TEST_ASSERT(bgp_ribout_community_sets(&block) == 4 && bgp_ribout_generator_init(&gen, &block) < 0,
                "rotate-period 3 rejects 4 community sets");
    bgp_ribout_edit(&block, "community", "-", 1);
    bgp_ribout_parse_community(&block, "community [65000:9,no-export]");
    TEST_ASSERT(bgp_ribout_generator_init(&gen, &block) == 0, "A single community set fits any rotate-period");
    bgp_ribout_parse_large_community(&block, "large-community 65551:0:9");
    TEST_ASSERT(bgp_ribout_generator_init(&gen, &block) < 0, "rotate-period 3 rejects 4 large-community sets");
    bgp_ribout_destroy(&block);
}

/*
 * What community and large-community lines reject; a rejected line adds none of its sets.
 */
void test_community_limits() {
    printf("\n=== community / large-community values and limits ===\n");
    static const char *const k_bad_communities[] = {
        "community",
        "community 65536:1",
        "community 1:65536",
        "community 65000",
        "community 1:2:3",
        "community no-such-name",
        "community -1:2",
        "community 1:",
        "community :1",
        "community [65000:1",
        "community []",
        "community [65000:1,]",
        "community [,65000:1]",
        "community [65000:1,,65000:2]",
        "community 65000:1 x",
        "community 65000:1 x 0",
        "community 65000:1 x two",
        "community 65000:65535 x 2",
        "community [65000:1,65000:1]",
        "community [no-export,65535:65281]",
        "community 65000:1 65000:2 x 0",
        "community 0x10:1",
    };
    static const char *const k_bad_large[] = {
        "large-community",
        "large-community 1:2",
        "large-community 1:2:3:4",
        "large-community 4294967296:1:1",
        "large-community 1:4294967296:1",
        "large-community 1:1:4294967296",
        "large-community no-export",
        "large-community [1:2:3",
        "large-community [1:2:3,]",
        "large-community 1:2:4294967295 x 2",
        "large-community [1:2:3,1:2:3]",
        "large-community 1:2:3 x 0",
    };
    bgp_ribout_config_t block;
    char                line[1024];
    int                 rejected = 1;
    int                 len;

    bgp_ribout_init(&block, "comm-limits");
    bgp_ribout_parse_community(&block, "community 65000:1");
    bgp_ribout_parse_large_community(&block, "large-community 1:2:3");
    for (size_t i = 0; i < sizeof(k_bad_communities) / sizeof(k_bad_communities[0]); i++) {
        int bad = bgp_ribout_parse_community(&block, k_bad_communities[i]) < 0;

        if (!bad) {
            printf("  accepted: %s\n", k_bad_communities[i]);
        }
        rejected = rejected && bad;
    }
    TEST_ASSERT(rejected && block.community_group_count == 1,
                "Reject bad community values, brackets, sequences, duplicates and overflow; the set before stays");
    rejected = 1;
    for (size_t i = 0; i < sizeof(k_bad_large) / sizeof(k_bad_large[0]); i++) {
        int bad = bgp_ribout_parse_large_community(&block, k_bad_large[i]) < 0;

        if (!bad) {
            printf("  accepted: %s\n", k_bad_large[i]);
        }
        rejected = rejected && bad;
    }
    TEST_ASSERT(rejected && block.large_community_group_count == 1,
                "Reject bad large-community values, sequences past 32 bits and duplicates (RFC 8092)");

    TEST_ASSERT(bgp_ribout_parse_community(&block, "community 65000:2 65000:3 65536:1") < 0 &&
                block.community_group_count == 1,
                "A line with one bad set adds none of its sets");
    TEST_ASSERT(bgp_ribout_parse_community(&block, "community 65000:65534 x 2 no-export x 100000") == 0 &&
                bgp_ribout_community_sets(&block) == 1 + 2 + 100000,
                "A sequence may end at 65535; a well-known value repeats any number of times");
    TEST_ASSERT(bgp_ribout_parse_large_community(&block, "large-community 1:2:4294967294 x 2") == 0,
                "A large-community sequence may end at local data 2 = 4294967295");
    TEST_ASSERT(bgp_ribout_parse_community(&block, "community [65000:1,65001:1]") == 0,
                "The same low half under another AS is not a duplicate");

    bgp_ribout_destroy(&block);
    bgp_ribout_init(&block, "comm-limits");
    len = snprintf(line, sizeof(line), "community [");
    for (int i = 0; i < MAX_COMMUNITIES_PER_SET; i++) {
        len += snprintf(line + len, sizeof(line) - (size_t)len, "%s65000:%d", i ? "," : "", i);
    }
    snprintf(line + len, sizeof(line) - (size_t)len, "]");
    TEST_ASSERT(bgp_ribout_parse_community(&block, line) == 0 &&
                block.community_groups[0].count == MAX_COMMUNITIES_PER_SET,
                "A set holds MAX_COMMUNITIES_PER_SET values");
    snprintf(line + len, sizeof(line) - (size_t)len, ",65000:99]");
    TEST_ASSERT(bgp_ribout_parse_community(&block, line) < 0, "Reject one value more");
    len = snprintf(line, sizeof(line), "large-community [");
    for (int i = 0; i <= MAX_LARGE_COMMUNITIES_PER_SET; i++) {
        len += snprintf(line + len, sizeof(line) - (size_t)len, "%s65000:0:%d", i ? "," : "", i);
    }
    snprintf(line + len, sizeof(line) - (size_t)len, "]");
    TEST_ASSERT(bgp_ribout_parse_large_community(&block, line) < 0,
                "Reject a large-community set of MAX_LARGE_COMMUNITIES_PER_SET + 1 values");

    bgp_ribout_destroy(&block);
    bgp_ribout_init(&block, "comm-limits");
    rejected = 0;
    for (int i = 0; i < 640; i++) {
        snprintf(line, sizeof(line), "community 65000:%d", i);
        rejected += bgp_ribout_parse_community(&block, line) < 0;
    }
    TEST_ASSERT(rejected == 0 && block.community_group_count == 640 &&
                block.community_groups[639].values[0] == ((65000U << 16) | 639),
                "Ten times the old community inventory retains the final value");
    TEST_ASSERT(bgp_ribout_edit(&block, "community", "-", 1) == 0 &&
                bgp_ribout_parse_community(&block, "community 1:0 x 65536 2:0 x 65536") == 0 &&
                bgp_ribout_community_sets(&block) == 131072,
                "A sequence counts as one set as written, however many sets it makes");
    bgp_ribout_destroy(&block);
    bgp_ribout_init(&block, "comm-limits");
    TEST_ASSERT(bgp_ribout_parse_large_community(&block, "large-community 1:1:0 x 4294967295") == 0 &&
                bgp_ribout_parse_large_community(&block, "large-community 2:2:2") < 0,
                "Reject more than 2^32 - 1 large-community sets in all");
    bgp_ribout_destroy(&block);
}

/*
 * Apply "keyword value" lines with bgp_ribout_edit(), as the CLI does; returns 0 when all of them apply.
 */
static int edit_lines(bgp_ribout_config_t *block, const char *const *lines) {
    for (; *lines; lines++) {
        char        keyword[32];
        const char *value = strchr(*lines, ' ');

        if (!value || (size_t)(value - *lines) >= sizeof(keyword)) {
            return -1;
        }
        snprintf(keyword, sizeof(keyword), "%.*s", (int)(value - *lines), *lines);
        if (bgp_ribout_edit(block, keyword, value + 1, 0) != 0) {
            printf("  (rejected: %s)\n", *lines);
            return -1;
        }
    }
    return 0;
}

// What an SR Policy ribout needs besides its keys.
#define SR_LIST "segment-list 1 weight 10 mpls 16001", "rt 192.0.2.1:100"

/*
 * SR Policy key rotation: color rotate, distinguisher rotate and endpoint rotate give each path one value in turn
 * (rotation step i: value i mod count) instead of one NLRI per value, so the key set shrinks to the other dimensions,
 * every key stays distinct, and rotate-every / rotate-period apply as to the attribute rotations.
 */
void test_srpolicy_key_rotation() {
    printf("\n=== SR Policy: color, distinguisher and endpoint rotate ===\n");
    static const char *const k_color[] = {
        "distinguisher 1 x 2",
        "color rotate 100 x 3",
        "endpoint 10.0.0.1 x 4",
        "path-id rotate 7 8",
        SR_LIST,
        NULL,
    };
    static const char *const k_all[] = {
        "distinguisher rotate 5 x 4",
        "color rotate 200 x 4",
        "endpoint 10.1.0.1 x 100",
        "rotate-period 4",
        SR_LIST,
        NULL,
    };
    static const char *const k_endpoint[] = {
        "distinguisher 1 x 10",
        "color 7",
        "endpoint rotate 10.2.0.1 x 5",
        SR_LIST,
        NULL,
    };
    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;
    bgp_gen_path_t      path;
    uint64_t            seen[100];
    int                 ok = 1, distinct = 1, n = 0;

    bgp_ribout_init(&block, "sr-rot");
    TEST_ASSERT(edit_lines(&block, k_color) == 0 &&
                block.color_rotate &&
                block.path_id_rotate &&
                bgp_ribout_total_paths(&block) == 8,
                "color rotate and path-id rotate do not multiply: 2 distinguishers x 4 endpoints = 8 policies");
    TEST_ASSERT(bgp_ribout_generator_init(&gen, &block) == 0, "Generator initializes");
    while (bgp_ribout_generator_has_next(&gen) && bgp_ribout_generator_next(&gen, &path) == 0) {
        ok = ok && path.distinguisher == 1u + (uint32_t)(n / 4) &&
             ntohl(path.endpoint_addr.ipv4.s_addr) == 0x0A000001u + (uint32_t)(n % 4) &&
             path.color == 100u + (uint32_t)(n % 3) && path.path_id == 7u + (uint32_t)(n % 2);
        seen[n] = (uint64_t)path.distinguisher << 40 | (uint64_t)path.color << 20 |
                  (ntohl(path.endpoint_addr.ipv4.s_addr) & 0xFFFFF);
        for (int k = 0; k < n; k++) {
            distinct = distinct && seen[k] != seen[n];
        }
        n++;
    }
    TEST_ASSERT(n == 8 && ok, "Path i: distinguisher and endpoint by position, color 100 + i % 3, path ID 7 + i % 2");
    TEST_ASSERT(distinct, "Every (distinguisher, color, endpoint) key is distinct");
    TEST_ASSERT(bgp_ribout_edit(&block, "rotate-every", "2", 0) == 0 && bgp_ribout_generator_init(&gen, &block) == 0,
                "rotate-every 2");
    ok = 1;
    for (n = 0; n < 8 && bgp_ribout_generator_next(&gen, &path) == 0; n++) {
        ok = ok && path.color == 100u + (uint32_t)(n / 2 % 3) && path.path_id == 7u + (uint32_t)(n / 2 % 2);
    }
    TEST_ASSERT(ok, "rotate-every 2: paths 2k and 2k+1 share color 100 + k % 3 and path ID 7 + k % 2");
    bgp_ribout_destroy(&block);

    bgp_ribout_init(&block, "sr-rot");
    TEST_ASSERT(edit_lines(&block, k_all) == 0 && bgp_ribout_total_paths(&block) == 100,
                "distinguisher rotate and color rotate: one policy per endpoint");
    TEST_ASSERT(bgp_ribout_generator_init(&gen, &block) == 0, "Lists of the rotate-period's length generate");
    ok = 1;
    for (n = 0; bgp_ribout_generator_has_next(&gen) && bgp_ribout_generator_next(&gen, &path) == 0; n++) {
        ok = ok && path.distinguisher == 5u + (uint32_t)(n % 4) && path.color == 200u + (uint32_t)(n % 4) &&
             ntohl(path.endpoint_addr.ipv4.s_addr) == 0x0A010001u + (uint32_t)n;
    }
    TEST_ASSERT(n == 100 && ok, "Path i: endpoint i with distinguisher 5 + i % 4 and color 200 + i % 4, in step");
    TEST_ASSERT(bgp_ribout_edit(&block, "color", "rotate 200 x 3", 0) == 0 &&
                bgp_ribout_generator_init(&gen, &block) < 0,
                "rotate-period 4 rejects 3 rotating colors");
    TEST_ASSERT(bgp_ribout_edit(&block, "color", "rotate 200 x 4", 0) == 0 &&
                bgp_ribout_edit(&block, "distinguisher", "rotate 5 x 5", 0) == 0 &&
                bgp_ribout_generator_init(&gen, &block) < 0,
                "rotate-period 4 rejects 5 rotating distinguishers");
    TEST_ASSERT(bgp_ribout_edit(&block, "distinguisher", "5 x 5", 0) == 0 &&
                !block.distinguisher_rotate &&
                bgp_ribout_generator_init(&gen, &block) == 0 &&
                bgp_ribout_total_paths(&block) == 500,
                "A plain distinguisher list is a key dimension again, outside rotate-period");
    bgp_ribout_destroy(&block);

    bgp_ribout_init(&block, "sr-rot");
    TEST_ASSERT(edit_lines(&block, k_endpoint) == 0 &&
                block.endpoint_rotate &&
                bgp_ribout_total_paths(&block) == 10,
                "endpoint rotate: one policy per distinguisher");
    TEST_ASSERT(bgp_ribout_generator_init(&gen, &block) == 0, "Generator initializes");
    ok = 1;
    for (n = 0; bgp_ribout_generator_has_next(&gen) && bgp_ribout_generator_next(&gen, &path) == 0; n++) {
        ok = ok && path.distinguisher == 1u + (uint32_t)n &&
             ntohl(path.endpoint_addr.ipv4.s_addr) == 0x0A020001u + (uint32_t)(n % 5) && path.color == 7;
    }
    TEST_ASSERT(n == 10 && ok, "Path i: distinguisher 1 + i, endpoint 10.2.0.1 + i % 5");
    TEST_ASSERT(bgp_ribout_edit(&block, "rotate-period", "4", 0) == 0 && bgp_ribout_generator_init(&gen, &block) < 0,
                "rotate-period 4 rejects 5 rotating endpoints");
    TEST_ASSERT(bgp_ribout_edit(&block, "endpoint", "-", 1) == 0 &&
                !block.endpoint_rotate &&
                bgp_ribout_edit(&block, "color", "-", 1) == 0 &&
                !block.color_rotate &&
                bgp_ribout_edit(&block, "distinguisher", "-", 1) == 0 &&
                !block.distinguisher_rotate,
                "no endpoint / color / distinguisher clear rotate");
    TEST_ASSERT(bgp_ribout_parse_color(&block, "color rotate") < 0 &&
                bgp_ribout_parse_endpoint(&block, "endpoint rotate") < 0 &&
                bgp_ribout_parse_distinguisher(&block, "distinguisher rotate") < 0,
                "rotate needs values");
    bgp_ribout_destroy(&block);
}

/*
 * Outside SR Policy colors are Color communities, which rotate anyway: color rotate generates the same paths.
 */
void test_color_rotate_outside_sr_policy() {
    printf("\n=== color rotate outside SR Policy ===\n");
    bgp_ribout_config_t plain, rotating;
    bgp_ribout_gen_t    gen_plain, gen_rotating;
    bgp_gen_path_t      a, b;
    int                 same = 1, n = 0;

    bgp_ribout_init(&plain, "colors");
    bgp_ribout_init(&rotating, "colors");
    bgp_ribout_parse_prefix(&plain, "prefix 10.1.0.0/24 x 7");
    bgp_ribout_parse_prefix(&rotating, "prefix 10.1.0.0/24 x 7");
    bgp_ribout_parse_next_hop(&plain, "next-hop 192.0.2.1");
    bgp_ribout_parse_next_hop(&rotating, "next-hop 192.0.2.1");
    bgp_ribout_parse_color(&plain, "color 1 x 3 co 01");
    TEST_ASSERT(bgp_ribout_parse_color(&rotating, "color rotate 1 x 3 co 01") == 0 && rotating.color_rotate,
                "Parse color rotate with co");
    TEST_ASSERT(bgp_ribout_total_paths(&plain) == 7 && bgp_ribout_total_paths(&rotating) == 7,
                "Colors never multiply unicast paths");
    TEST_ASSERT(bgp_ribout_generator_init(&gen_plain, &plain) == 0 &&
                bgp_ribout_generator_init(&gen_rotating, &rotating) == 0,
                "Both generate");
    while (bgp_ribout_generator_next(&gen_plain, &a) == 0 && bgp_ribout_generator_next(&gen_rotating, &b) == 0) {
        same = same && a.ext_comm_len == b.ext_comm_len &&
               memcmp(a.ext_comm_data, b.ext_comm_data, a.ext_comm_len) == 0;
        n++;
    }
    TEST_ASSERT(n == 7 && same, "The same Color community on every path");
    bgp_ribout_destroy(&plain);
    bgp_ribout_destroy(&rotating);
}

/*
 * ethernet-tag rotate: EVPN Type 5 gets one tag per path, in step with rd rotate (a VRF's RD and tag together); EVPN
 * Type 2 counts its MACs without the tag dimension, so ip rotate still binds MAC i to IP i.
 */
void test_ethernet_tag_rotation() {
    printf("\n=== EVPN ethernet-tag rotate ===\n");
    static const char *const k_type5[] = {
        "prefix 10.0.0.0/24 x 6",
        "rd rotate 65551:1 x 3",
        "ethernet-tag rotate 100 x 3",
        "label 10",
        "next-hop 192.0.2.1",
        NULL,
    };
    static const char *const k_type2[] = {
        "rd 65551:1",
        "mac 02:00:00:00:00:01 x 4",
        "ethernet-tag rotate 10 x 2",
        "ip rotate 10.1.0.1 x 4",
        "label 20",
        "next-hop 192.0.2.1",
        NULL,
    };
    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;
    bgp_gen_path_t      path;
    int                 ok = 1, n = 0;

    bgp_ribout_init(&block, "tags");
    TEST_ASSERT(edit_lines(&block, k_type5) == 0 &&
                block.ethernet_tag_rotate &&
                bgp_ribout_total_paths(&block) == 6,
                "Type 5: rotating RDs and tags do not multiply the prefixes");
    TEST_ASSERT(bgp_ribout_generator_init(&gen, &block) == 0, "Generator initializes");
    while (bgp_ribout_generator_has_next(&gen) && bgp_ribout_generator_next(&gen, &path) == 0) {
        ok = ok && path.has_ethernet_tag && path.ethernet_tag_id == 100u + (uint32_t)(n % 3) &&
             rd_assigned16(&path.rd) == 1u + (uint32_t)(n % 3) &&
             ntohl(path.prefix_addr.ipv4.s_addr) == 0x0A000000u + ((uint32_t)n << 8);
        n++;
    }
    TEST_ASSERT(n == 6 && ok, "Path i: prefix i with RD 65551:(1 + i % 3) and tag 100 + i % 3");
    TEST_ASSERT(bgp_ribout_edit(&block, "ethernet-tag", "100 x 3", 0) == 0 &&
                !block.ethernet_tag_rotate &&
                bgp_ribout_total_paths(&block) == 18,
                "A plain tag list multiplies the prefixes again");
    TEST_ASSERT(bgp_ribout_edit(&block, "ethernet-tag", "rotate 100 x 4", 0) == 0 &&
                bgp_ribout_edit(&block, "rotate-period", "3", 0) == 0 &&
                bgp_ribout_generator_init(&gen, &block) < 0,
                "rotate-period 3 rejects 4 rotating tags");
    TEST_ASSERT(bgp_ribout_edit(&block, "ethernet-tag", "-", 1) == 0 && !block.ethernet_tag_rotate,
                "no ethernet-tag clears rotate");
    bgp_ribout_destroy(&block);

    bgp_ribout_init(&block, "tags");
    TEST_ASSERT(edit_lines(&block, k_type2) == 0 && bgp_ribout_total_paths(&block) == 4,
                "Type 2: 4 MACs, the rotating tag adds no routes");
    TEST_ASSERT(bgp_ribout_generator_init(&gen, &block) == 0, "Generator initializes");
    ok = 1;
    for (n = 0; bgp_ribout_generator_has_next(&gen) && bgp_ribout_generator_next(&gen, &path) == 0; n++) {
        ok = ok && path.mac_addr[5] == 1 + n && path.ethernet_tag_id == 10u + (uint32_t)(n % 2) &&
             ntohl(path.ip_addr.ipv4.s_addr) == 0x0A010001u + (uint32_t)n;
    }
    TEST_ASSERT(n == 4 && ok, "MAC i: tag 10 + i % 2 and IP i (ip rotate counts MACs without the tag dimension)");
    TEST_ASSERT(bgp_ribout_edit(&block, "ethernet-tag", "10 11", 0) == 0 &&
                bgp_ribout_total_paths(&block) == 8 &&
                bgp_ribout_generator_init(&gen, &block) == 0,
                "Plain tags: each MAC under both tags");
    ok = 1;
    for (n = 0; bgp_ribout_generator_has_next(&gen) && bgp_ribout_generator_next(&gen, &path) == 0; n++) {
        ok = ok && path.ethernet_tag_id == 10u + (uint32_t)(n / 4) &&
             ntohl(path.ip_addr.ipv4.s_addr) == 0x0A010001u + (uint32_t)(n % 4);
    }
    TEST_ASSERT(n == 8 && ok, "Plain tags: MAC number (tag, MAC) binds IP number mod 4");
    bgp_ribout_destroy(&block);
}

/*
 * path-id rotate: one Add-Path ID per prefix in turn instead of each prefix once per ID.
 */
void test_path_id_rotation() {
    printf("\n=== path-id rotate ===\n");
    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;
    bgp_gen_path_t      path;
    int                 ok = 1, n = 0;

    bgp_ribout_init(&block, "ids");
    bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/24 x 5");
    bgp_ribout_parse_next_hop(&block, "next-hop 192.0.2.1");
    TEST_ASSERT(bgp_ribout_parse_path_ids(&block, "path-id rotate 1 x 3") == 0 &&
                block.path_id_rotate &&
                block.path_id_count == 3 &&
                bgp_ribout_total_paths(&block) == 5,
                "path-id rotate 1 x 3: 5 paths, not 15");
    TEST_ASSERT(bgp_ribout_generator_init(&gen, &block) == 0, "Generator initializes");
    while (bgp_ribout_generator_has_next(&gen) && bgp_ribout_generator_next(&gen, &path) == 0) {
        ok = ok && path.path_id == 1u + (uint32_t)(n % 3) &&
             ntohl(path.prefix_addr.ipv4.s_addr) == 0x0A000000u + ((uint32_t)n << 8);
        n++;
    }
    TEST_ASSERT(n == 5 && ok, "Prefix i carries path ID 1 + i % 3");
    TEST_ASSERT(bgp_ribout_parse_path_ids(&block, "path-id rotate range(4,5)") == 0 &&
                block.path_id_count == 2 &&
                bgp_ribout_total_paths(&block) == 5,
                "path-id rotate range(A,B)");
    TEST_ASSERT(bgp_ribout_parse_path_ids(&block, "path-id 1 x 3") == 0 &&
                !block.path_id_rotate &&
                bgp_ribout_total_paths(&block) == 15,
                "A plain list multiplies again");
    TEST_ASSERT(bgp_ribout_parse_path_ids(&block, "path-id rotate") < 0, "path-id rotate needs values");
    TEST_ASSERT(bgp_ribout_edit(&block, "path-id", "rotate 1 x 4", 0) == 0 &&
                bgp_ribout_edit(&block, "rotate-period", "3", 0) == 0 &&
                bgp_ribout_generator_init(&gen, &block) < 0,
                "rotate-period 3 rejects 4 rotating path IDs");
    bgp_ribout_destroy(&block);
}

/*
 * FlowSpec component rotate: a rotating component gives each rule one of its values in turn (rotation step i: value
 * i mod count) instead of one rule per value; the other components and the prefixes still make the rules. The
 * instance space (every component multiplied) must stay below 2^32.
 */
void test_flowspec_component_rotation() {
    printf("\n=== FlowSpec component rotate ===\n");
    static const char *const k_rules[] = {
        "address-family ipv4 flowspec",
        "prefix 10.0.0.0/24 x 2",
        "protocol rotate each(6, 17)",
        "dst-port rotate 80 x 3",
        "src-port each(1, 2)",
        NULL,
    };
    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;
    bgp_gen_path_t      path;
    char                text[256], want[256];
    int                 ok = 1, n = 0;

    bgp_ribout_init(&block, "fs-rot");
    TEST_ASSERT(edit_lines(&block, k_rules) == 0 &&
                block.flowspec->rotating &&
                bgp_ribout_total_paths(&block) == 4 &&
                bgp_ribout_flowspec_instances(&block) == 24,
                "2 prefixes x 2 source ports = 4 rules; 24 instances counting the rotating components");
    TEST_ASSERT(bgp_ribout_generator_init(&gen, &block) == 0, "Generator initializes");
    while (bgp_ribout_generator_has_next(&gen) && bgp_ribout_generator_next(&gen, &path) == 0) {
        bgp_ribout_flowspec_nlri_to_string(&block, path.flowspec_instance, text, sizeof(text));
        snprintf(want, sizeof(want), "prefix 10.0.%d.0/24 protocol %d dst-port %d src-port %d", n / 2,
                 n % 2 ? 17 : 6, 80 + n % 3, 1 + n % 2);
        if (strcmp(text, want) != 0) {
            printf("  rule %d: %s (want %s)\n", n, text, want);
            ok = 0;
        }
        n++;
    }
    TEST_ASSERT(n == 4 && ok, "Rule i: prefix i / 2, protocol and dst-port of rotation step i, src-port i % 2");

    TEST_ASSERT(bgp_ribout_edit(&block, "rotate-every", "2", 0) == 0 && bgp_ribout_generator_init(&gen, &block) == 0,
                "rotate-every 2");
    ok = 1;
    for (n = 0; n < 4 && bgp_ribout_generator_next(&gen, &path) == 0; n++) {
        bgp_ribout_flowspec_nlri_to_string(&block, path.flowspec_instance, text, sizeof(text));
        snprintf(want, sizeof(want), "prefix 10.0.%d.0/24 protocol %d dst-port %d src-port %d", n / 2,
                 n / 2 % 2 ? 17 : 6, 80 + n / 2 % 3, 1 + n % 2);
        ok = ok && strcmp(text, want) == 0;
    }
    TEST_ASSERT(ok, "rotate-every 2: rules 2k and 2k+1 share the rotating values of step k");

    TEST_ASSERT(bgp_ribout_edit(&block, "rotate-every", "-", 1) == 0 &&
                bgp_ribout_edit(&block, "rotate-period", "3", 0) == 0 &&
                bgp_ribout_generator_init(&gen, &block) < 0,
                "rotate-period 3 rejects the 2 rotating protocols");
    TEST_ASSERT(bgp_ribout_edit(&block, "protocol", "rotate each(6, 17, 1)", 0) == 0 &&
                bgp_ribout_generator_init(&gen, &block) == 0,
                "3 protocols and 3 ports fit rotate-period 3");
    TEST_ASSERT(bgp_ribout_edit(&block, "protocol", "each(6, 17, 1)", 0) == 0 &&
                !block.flowspec->components[3].rotate &&
                bgp_ribout_edit(&block, "dst-port", "80 x 3", 0) == 0 &&
                !block.flowspec->rotating &&
                bgp_ribout_total_paths(&block) == 2 * 3 * 3 * 2,
                "Plain components multiply the rules again");
    TEST_ASSERT(bgp_ribout_flowspec_parse_component(&block, "dst-port", "rotate") < 0 &&
                bgp_ribout_flowspec_parse_component(&block, "dst-port", "rotate   ") < 0,
                "rotate needs values");
    TEST_ASSERT(bgp_ribout_flowspec_parse_component(&block, "dst-port", "rotate 80") == 0 &&
                bgp_ribout_total_paths(&block) == 2 * 3 * 2,
                "A single rotating value is the value of every rule");
    bgp_ribout_destroy(&block);

    bgp_ribout_init(&block, "fs-rot");
    bgp_ribout_flowspec_parse_component(&block, "dst-port", "rotate 0 x 65536");
    bgp_ribout_flowspec_parse_component(&block, "src-port", "rotate 0 x 65536");
    bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/24");
    TEST_ASSERT(bgp_ribout_total_paths(&block) == 1 && bgp_ribout_generator_init(&gen, &block) < 0,
                "Reject an instance space of 2^32, though it generates one rule");
    bgp_ribout_destroy(&block);
}

int main(void) {
    test_compact_inventories();
    printf("===============================================\n");
    printf("BGP RIB-OUT Generator Tests\n");
    printf("===============================================\n");

    // Run all tests
    test_ipv4_prefix_parsing();
    test_ipv6_prefix_parsing();
    test_path_id_parsing();
    test_next_hop_single_ip();
    test_next_hop_wrapping();
    test_aspath_sequence();
    test_aspath_set();
    test_aspath_random();
    test_aspath_random_shorthand();
    test_aspath_mixed();
    test_localpref_fixed();
    test_localpref_random();
    test_localpref_range();
    test_localpref_randrange();
    test_full_width_random_range();
    test_label_rotate_follows_rt_set();
    test_ip_rotate_binds_macs();
    test_rd_rotate_and_rt_set_sequence();
    test_rt_set_sequence_limits();
    test_rotate_every_blocks();
    test_rotate_period_checks_lists();
    test_dual_stack_type2();
    test_origin_parsing();
    test_generator_init();
    test_generator_iteration();
    test_generator_path_id_cycling();
    test_generator_next_hop_wrapping();
    test_generator_reset();
    test_generator_randseed_is_deterministic();
    test_generator_default_seed_tracks_name();
    test_large_prefix_count();
    test_single_prefix_many_path_ids();
    test_full_integration();
    test_single_prefix_no_count();
    test_next_hop_ip_with_count_warning();
    test_next_hop_prefix_with_count();
    test_next_hop_prefix_no_count();
    test_multiple_ribouts_different_families();
    test_multiple_generators_same_block();
    test_ribout_modification_sequence();
    test_complex_aspath_all_types();
    test_generator_partial_generation();
    test_multiple_ribouts_independent();
    test_default_values();
    test_srpolicy_generator_total_paths();
    test_srpolicy_generator_order_and_attr_rotation();
    test_srpolicy_generator_default_next_hop();
    test_srpolicy_segment_lists_do_not_multiply_paths();
    test_srpolicy_extended_tunnel_knobs();
    test_evpn_type2_generator_total_paths();
    test_evpn_type2_generator_order_and_attr_rotation();
    test_evpn_type2_generator_default_next_hop();
    test_evpn_type2_secondary_fields_do_not_multiply_paths();
    test_evpn_type2_ext_community_rotators();
    test_evpn_type2_identifier_shorthand_generation();
    test_srpolicy_random_knobs_honor_randseed();
    test_flowspec_expression_parsing();
    test_flowspec_generator_order_and_totals();
    test_color_parsing_and_family();
    test_color_set_validation();
    test_color_community_rotation();
    test_community_sets_rotate();
    test_community_sets_rotation_options();
    test_community_limits();
    test_srpolicy_key_rotation();
    test_color_rotate_outside_sr_policy();
    test_ethernet_tag_rotation();
    test_path_id_rotation();
    test_flowspec_component_rotation();

    // Print summary
    printf("\n===============================================\n");
    printf("Test Summary\n");
    printf("===============================================\n");
    printf("Total tests:  %d\n", tests_passed + tests_failed);
    printf("Passed:       %d\n", tests_passed);
    printf("Failed:       %d\n", tests_failed);
    printf("===============================================\n");

    if (tests_failed == 0) {
        printf("%s %s\n", TEST_BADGE_PASS, "All tests passed!");
        return 0;
    } else {
        printf("%s %s\n", TEST_BADGE_FAIL, "Some tests failed");
        return 1;
    }
}
