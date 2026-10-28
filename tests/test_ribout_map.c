#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "test_case.h"
#include "bgp_ribout.h"
#include "bgp_ribout_config.h"

/*
 * Helper function to create AS path segments from simple AS array
 */
static bgp_aspath_segment_t* create_aspath_segments(const uint32_t *as_array,
                                                     uint32_t as_count,
                                                     uint32_t *out_segment_count) {
    if (as_count == 0) {
        *out_segment_count = 0;
        return NULL;
    }

    bgp_aspath_segment_t *segments = malloc(sizeof(bgp_aspath_segment_t));
    if (!segments) return NULL;

    segments[0].type = ASPATH_SEQUENCE;
    segments[0].value_count = as_count;
    for (uint32_t i = 0; i < as_count; i++) {
        segments[0].as_values[i] = as_array[i];
    }

    *out_segment_count = 1;
    return segments;
}

static void setup_basic_ribout(bgp_ribout_config_t *block) {
    bgp_ribout_init(block, "TEST");
    bgp_ribout_parse_prefix(block, "prefix 10.0.0.0/24 x 1");
    bgp_ribout_parse_path_ids(block, "path-id 0");
    bgp_ribout_parse_next_hop(block, "next-hop 192.168.1.1");
    bgp_ribout_parse_aspath(block, "as-path 100 200");
    bgp_ribout_parse_localpref(block, "localpref 100");
    bgp_ribout_parse_origin(block, "origin igp");
}

static void setup_diverse_ribout(bgp_ribout_config_t *block) {
    bgp_ribout_init(block, "DIVERSE");
    bgp_ribout_parse_prefix(block, "prefix 10.0.0.0/24 x 10");
    bgp_ribout_parse_path_ids(block, "path-id 1 2 3");
    bgp_ribout_parse_next_hop(block, "next-hop 192.168.1.1");
    bgp_ribout_parse_aspath(block, "as-path 100 200 300");
    bgp_ribout_parse_localpref(block, "localpref 150");
    bgp_ribout_parse_origin(block, "origin incomplete");
}

static void setup_consolidation_ribout(bgp_ribout_config_t *block, const char *name,
                                       const char *prefix_cmd, const char *next_hop_cmd,
                                       const char *as_path_cmd, const char *localpref_cmd,
                                       const char *origin_cmd) {
    bgp_ribout_init(block, name);
    bgp_ribout_parse_prefix(block, prefix_cmd);
    bgp_ribout_parse_path_ids(block, "path-id 1");
    bgp_ribout_parse_next_hop(block, next_hop_cmd);
    bgp_ribout_parse_aspath(block, as_path_cmd);
    bgp_ribout_parse_localpref(block, localpref_cmd);
    bgp_ribout_parse_origin(block, origin_cmd);
}

static size_t test_round_up_power_of_two(size_t value) {
    size_t rounded = 1;

    while (rounded < value) {
        if (rounded > (SIZE_MAX / 2)) {
            return 0;
        }
        rounded <<= 1;
    }

    return rounded;
}

static size_t test_expected_precompact_bucket_count(uint64_t total_paths) {
    uint64_t target;

    if (total_paths <= RIBOUT_HASHMAP_DEFAULT_SIZE) {
        return RIBOUT_HASHMAP_DEFAULT_SIZE;
    }

    target = total_paths * 2ULL;
    if (target < total_paths || target > (uint64_t)SIZE_MAX) {
        return 0;
    }

    return test_round_up_power_of_two((size_t)target);
}

// Test Functions

void test_create_destroy(void) {
    TEST("Create and destroy ribout");

    bgp_ribout_map_t *map = bgp_ribout_map_create(128);
    ASSERT(map != NULL, "Failed to create map");
    ASSERT(map->bucket_count == 128, "Wrong bucket count");
    ASSERT(map->entry_count == 0, "Initial entry count should be 0");
    ASSERT(map->total_nlri_count == 0, "Initial NLRI count should be 0");

    bgp_ribout_map_destroy(map);
    PASS();
}

void test_insert_single_nlri(void) {
    TEST("Insert single NLRI");

    bgp_ribout_map_t *map = bgp_ribout_map_create(0);
    ASSERT(map != NULL, "Failed to create map");

    // Convert string IPs to binary
    struct in_addr prefix_addr, next_hop_addr;
    inet_pton(AF_INET, "10.0.0.0", &prefix_addr);
    inet_pton(AF_INET, "192.168.1.1", &next_hop_addr);

    // Create AS path segments
    uint32_t aspath[] = {100, 200, 300};
    uint32_t              segment_count;
    bgp_aspath_segment_t *segments = create_aspath_segments(aspath, 3, &segment_count);

    bgp_path_attrs_t attrs = {
        .next_hop_addr       = &next_hop_addr,
        .next_hop_af         = AF_INET,
        .aspath_segments     = segments,
        .aspath_segment_count = segment_count,
        .local_pref          = 100,
        .origin              = 0,
    };
    int ret = bgp_ribout_map_insert(map, &prefix_addr, 24, AF_INET, 0, &attrs);
    ASSERT(ret == 0, "Insert failed");
    ASSERT(map->entry_count == 1, "Entry count should be 1");
    ASSERT(map->total_nlri_count == 1, "NLRI count should be 1");

    free(segments);
    bgp_ribout_map_destroy(map);
    PASS();
}

void test_insert_multiple_nlri_same_attrs(void) {
    TEST("Insert multiple NLRIs with same attributes");

    bgp_ribout_map_t *map = bgp_ribout_map_create(0);
    ASSERT(map != NULL, "Failed to create map");

    // Convert next_hop to binary
    struct in_addr next_hop_addr;
    inet_pton(AF_INET, "192.168.1.1", &next_hop_addr);

    // Create AS path segments
    uint32_t aspath[] = {100, 200};
    uint32_t              segment_count;
    bgp_aspath_segment_t *segments = create_aspath_segments(aspath, 2, &segment_count);

    bgp_path_attrs_t attrs = {
        .next_hop_addr       = &next_hop_addr,
        .next_hop_af         = AF_INET,
        .aspath_segments     = segments,
        .aspath_segment_count = segment_count,
        .local_pref          = 100,
        .origin              = 0,
    };

    // Insert first NLRI
    struct in_addr prefix1;
    inet_pton(AF_INET, "10.0.0.0", &prefix1);
    bgp_ribout_map_insert(map, &prefix1, 24, AF_INET, 0, &attrs);

    // Insert second NLRI with same attributes
    struct in_addr prefix2;
    inet_pton(AF_INET, "10.0.1.0", &prefix2);
    bgp_ribout_map_insert(map, &prefix2, 24, AF_INET, 0, &attrs);

    // Insert third NLRI with same attributes
    struct in_addr prefix3;
    inet_pton(AF_INET, "10.0.2.0", &prefix3);
    bgp_ribout_map_insert(map, &prefix3, 24, AF_INET, 0, &attrs);

    ASSERT(map->entry_count == 1, "Should have 1 entry (same attrs)");
    ASSERT(map->total_nlri_count == 3, "Should have 3 NLRIs");

    // Verify the entry has all 3 NLRIs
    path_attr_entry_t *entry = bgp_ribout_map_find(map, &attrs);
    ASSERT(entry != NULL, "Entry not found");
    ASSERT(entry->nlri_count == 3, "Entry should have 3 NLRIs");

    free(segments);
    bgp_ribout_map_destroy(map);
    PASS();
}

void test_insert_different_attrs(void) {
    TEST("Insert NLRIs with different attributes");

    bgp_ribout_map_t *map = bgp_ribout_map_create(0);
    ASSERT(map != NULL, "Failed to create map");

    // Create AS path segments
    uint32_t aspath1[] = {100, 200};
    uint32_t aspath2[] = {100, 300};
    uint32_t segment_count1, segment_count2;
    bgp_aspath_segment_t *segments1 = create_aspath_segments(aspath1, 2, &segment_count1);
    bgp_aspath_segment_t *segments2 = create_aspath_segments(aspath2, 2, &segment_count2);

    // Convert next_hops to binary
    struct in_addr next_hop1, next_hop2;
    inet_pton(AF_INET, "192.168.1.1", &next_hop1);
    inet_pton(AF_INET, "192.168.1.2", &next_hop2);

    // Insert with different AS paths
    struct in_addr prefix1, prefix2, prefix3, prefix4, prefix5;

    bgp_path_attrs_t attrs1 = {
        .next_hop_addr = &next_hop1, .next_hop_af = AF_INET,
        .aspath_segments = segments1, .aspath_segment_count = segment_count1,
        .local_pref = 100, .origin = 0,
    };
    inet_pton(AF_INET, "10.0.0.0", &prefix1);
    bgp_ribout_map_insert(map, &prefix1, 24, AF_INET, 0, &attrs1);

    bgp_path_attrs_t attrs2 = {
        .next_hop_addr = &next_hop1, .next_hop_af = AF_INET,
        .aspath_segments = segments2, .aspath_segment_count = segment_count2,
        .local_pref = 100, .origin = 0,
    };
    inet_pton(AF_INET, "10.0.1.0", &prefix2);
    bgp_ribout_map_insert(map, &prefix2, 24, AF_INET, 0, &attrs2);

    // Insert with different next_hop
    bgp_path_attrs_t attrs3 = {
        .next_hop_addr = &next_hop2, .next_hop_af = AF_INET,
        .aspath_segments = segments1, .aspath_segment_count = segment_count1,
        .local_pref = 100, .origin = 0,
    };
    inet_pton(AF_INET, "10.0.2.0", &prefix3);
    bgp_ribout_map_insert(map, &prefix3, 24, AF_INET, 0, &attrs3);

    // Insert with different local_pref
    bgp_path_attrs_t attrs4 = {
        .next_hop_addr = &next_hop1, .next_hop_af = AF_INET,
        .aspath_segments = segments1, .aspath_segment_count = segment_count1,
        .local_pref = 200, .origin = 0,
    };
    inet_pton(AF_INET, "10.0.3.0", &prefix4);
    bgp_ribout_map_insert(map, &prefix4, 24, AF_INET, 0, &attrs4);

    // Insert with different origin
    bgp_path_attrs_t attrs5 = {
        .next_hop_addr = &next_hop1, .next_hop_af = AF_INET,
        .aspath_segments = segments1, .aspath_segment_count = segment_count1,
        .local_pref = 100, .origin = 1,
    };
    inet_pton(AF_INET, "10.0.4.0", &prefix5);
    bgp_ribout_map_insert(map, &prefix5, 24, AF_INET, 0, &attrs5);

    ASSERT(map->entry_count == 5, "Should have 5 entries (all different)");
    ASSERT(map->total_nlri_count == 5, "Should have 5 NLRIs");

    free(segments1);
    free(segments2);
    bgp_ribout_map_destroy(map);
    PASS();
}

void test_find_existing(void) {
    TEST("Find existing path attributes");

    bgp_ribout_map_t *map = bgp_ribout_map_create(0);
    ASSERT(map != NULL, "Failed to create map");

    // Convert addresses to binary
    struct in_addr prefix_addr, next_hop_addr;
    inet_pton(AF_INET, "10.0.0.0", &prefix_addr);
    inet_pton(AF_INET, "192.168.1.1", &next_hop_addr);

    // Create AS path segments
    uint32_t aspath[] = {100, 200, 300};
    uint32_t              segment_count;
    bgp_aspath_segment_t *segments = create_aspath_segments(aspath, 3, &segment_count);

    bgp_path_attrs_t attrs = {
        .next_hop_addr       = &next_hop_addr,
        .next_hop_af         = AF_INET,
        .aspath_segments     = segments,
        .aspath_segment_count = segment_count,
        .local_pref          = 100,
        .origin              = 0,
    };
    bgp_ribout_map_insert(map, &prefix_addr, 24, AF_INET, 0, &attrs);

    path_attr_entry_t *entry = bgp_ribout_map_find(map, &attrs);
    ASSERT(entry != NULL, "Entry should be found");
    ASSERT(entry->local_pref == 100, "Wrong local_pref");
    ASSERT(entry->origin == 0, "Wrong origin");
    ASSERT(entry->next_hop_af == AF_INET, "Wrong next_hop address family");
    ASSERT(memcmp(&entry->next_hop.ipv4, &next_hop_addr, sizeof(struct in_addr)) == 0, "Wrong next_hop");
    ASSERT(entry->aspath_segment_count == 1, "Wrong AS path segment count");
    ASSERT(entry->aspath_data != NULL, "Compact AS path bytes should be present");
    ASSERT(entry->aspath_data_len > 0, "Compact AS path should have encoded data");

    free(segments);
    bgp_ribout_map_destroy(map);
    PASS();
}

void test_find_nonexistent(void) {
    TEST("Find non-existent path attributes");

    bgp_ribout_map_t *map = bgp_ribout_map_create(0);
    ASSERT(map != NULL, "Failed to create map");

    // Convert addresses to binary
    struct in_addr prefix_addr, next_hop_addr;
    inet_pton(AF_INET, "10.0.0.0", &prefix_addr);
    inet_pton(AF_INET, "192.168.1.1", &next_hop_addr);

    // Create AS path segments
    uint32_t aspath1[] = {100, 200};
    uint32_t aspath2[] = {100, 300};
    uint32_t segment_count1, segment_count2;
    bgp_aspath_segment_t *segments1 = create_aspath_segments(aspath1, 2, &segment_count1);
    bgp_aspath_segment_t *segments2 = create_aspath_segments(aspath2, 2, &segment_count2);

    bgp_path_attrs_t attrs1 = {
        .next_hop_addr       = &next_hop_addr,
        .next_hop_af         = AF_INET,
        .aspath_segments     = segments1,
        .aspath_segment_count = segment_count1,
        .local_pref          = 100,
        .origin              = 0,
    };
    bgp_ribout_map_insert(map, &prefix_addr, 24, AF_INET, 0, &attrs1);

    // Try to find with different AS path
    bgp_path_attrs_t attrs2 = {
        .next_hop_addr       = &next_hop_addr,
        .next_hop_af         = AF_INET,
        .aspath_segments     = segments2,
        .aspath_segment_count = segment_count2,
        .local_pref          = 100,
        .origin              = 0,
    };
    path_attr_entry_t *entry = bgp_ribout_map_find(map, &attrs2);
    ASSERT(entry == NULL, "Should not find entry with different AS path");

    free(segments1);
    free(segments2);
    bgp_ribout_map_destroy(map);
    PASS();
}

void test_clear_map(void) {
    TEST("Clear all entries from map");

    bgp_ribout_map_t *map = bgp_ribout_map_create(0);
    ASSERT(map != NULL, "Failed to create map");

    // Create AS path segments
    uint32_t aspath[] = {100, 200};
    uint32_t              segment_count;
    bgp_aspath_segment_t *segments = create_aspath_segments(aspath, 2, &segment_count);

    // Convert next_hops to binary
    struct in_addr next_hop1, next_hop2;
    inet_pton(AF_INET, "192.168.1.1", &next_hop1);
    inet_pton(AF_INET, "192.168.1.2", &next_hop2);

    // Insert multiple entries
    bgp_path_attrs_t attrs1 = {
        .next_hop_addr = &next_hop1, .next_hop_af = AF_INET,
        .aspath_segments = segments, .aspath_segment_count = segment_count,
        .local_pref = 100, .origin = 0,
    };
    bgp_path_attrs_t attrs2 = {
        .next_hop_addr = &next_hop2, .next_hop_af = AF_INET,
        .aspath_segments = segments, .aspath_segment_count = segment_count,
        .local_pref = 100, .origin = 0,
    };

    struct in_addr prefix1, prefix2, prefix3;
    inet_pton(AF_INET, "10.0.0.0", &prefix1);
    bgp_ribout_map_insert(map, &prefix1, 24, AF_INET, 0, &attrs1);

    inet_pton(AF_INET, "10.0.1.0", &prefix2);
    bgp_ribout_map_insert(map, &prefix2, 24, AF_INET, 0, &attrs1);

    inet_pton(AF_INET, "10.0.2.0", &prefix3);
    bgp_ribout_map_insert(map, &prefix3, 24, AF_INET, 0, &attrs2);

    ASSERT(map->entry_count > 0, "Should have entries");
    ASSERT(map->total_nlri_count > 0, "Should have NLRIs");

    // Clear the map
    bgp_ribout_map_clear(map);

    ASSERT(map->entry_count == 0, "Entry count should be 0 after clear");
    ASSERT(map->total_nlri_count == 0, "NLRI count should be 0 after clear");

    free(segments);
    bgp_ribout_map_destroy(map);
    PASS();
}

void test_add_path_support(void) {
    TEST("ADD-PATH support with path IDs");

    bgp_ribout_map_t *map = bgp_ribout_map_create(0);
    ASSERT(map != NULL, "Failed to create map");

    // Convert addresses to binary
    struct in_addr prefix_addr, next_hop_addr;
    inet_pton(AF_INET, "10.0.0.0", &prefix_addr);
    inet_pton(AF_INET, "192.168.1.1", &next_hop_addr);

    // Create AS path segments
    uint32_t aspath[] = {100, 200};
    uint32_t              segment_count;
    bgp_aspath_segment_t *segments = create_aspath_segments(aspath, 2, &segment_count);

    bgp_path_attrs_t attrs = {
        .next_hop_addr       = &next_hop_addr,
        .next_hop_af         = AF_INET,
        .aspath_segments     = segments,
        .aspath_segment_count = segment_count,
        .local_pref          = 100,
        .origin              = 0,
    };

    // Insert same prefix with different path IDs
    bgp_ribout_map_insert(map, &prefix_addr, 24, AF_INET, 1, &attrs);
    bgp_ribout_map_insert(map, &prefix_addr, 24, AF_INET, 2, &attrs);

    ASSERT(map->entry_count == 1, "Should have 1 entry (same attrs)");
    ASSERT(map->total_nlri_count == 2, "Should have 2 NLRIs (diff path IDs)");

    path_attr_entry_t *entry = bgp_ribout_map_find(map, &attrs);
    ASSERT(entry != NULL, "Entry not found");
    ASSERT(entry->nlri_count == 2, "Should have 2 NLRIs");

    free(segments);
    bgp_ribout_map_destroy(map);
    PASS();
}

void test_hash_collisions(void) {
    TEST("Handle hash collisions");

    // Use very small bucket count to force collisions
    bgp_ribout_map_t *map = bgp_ribout_map_create(4);
    ASSERT(map != NULL, "Failed to create map");

    // Create AS path segments
    uint32_t aspath1[] = {100};
    uint32_t aspath2[] = {200};
    uint32_t aspath3[] = {300};
    uint32_t segment_count1, segment_count2, segment_count3;
    bgp_aspath_segment_t *segments1 = create_aspath_segments(aspath1, 1, &segment_count1);
    bgp_aspath_segment_t *segments2 = create_aspath_segments(aspath2, 1, &segment_count2);
    bgp_aspath_segment_t *segments3 = create_aspath_segments(aspath3, 1, &segment_count3);

    // Convert next_hops to binary
    struct in_addr next_hop1, next_hop2, next_hop3;
    inet_pton(AF_INET, "192.168.1.1", &next_hop1);
    inet_pton(AF_INET, "192.168.1.2", &next_hop2);
    inet_pton(AF_INET, "192.168.1.3", &next_hop3);

    // Insert multiple different entries (likely to collide)
    bgp_path_attrs_t a1 = {
        .next_hop_addr = &next_hop1, .next_hop_af = AF_INET,
        .aspath_segments = segments1, .aspath_segment_count = segment_count1,
        .local_pref = 100, .origin = 0,
    };
    bgp_path_attrs_t a2 = {
        .next_hop_addr = &next_hop2, .next_hop_af = AF_INET,
        .aspath_segments = segments2, .aspath_segment_count = segment_count2,
        .local_pref = 100, .origin = 0,
    };
    bgp_path_attrs_t a3 = {
        .next_hop_addr = &next_hop3, .next_hop_af = AF_INET,
        .aspath_segments = segments3, .aspath_segment_count = segment_count3,
        .local_pref = 100, .origin = 0,
    };

    struct in_addr prefix1, prefix2, prefix3;
    inet_pton(AF_INET, "10.0.0.0", &prefix1);
    bgp_ribout_map_insert(map, &prefix1, 24, AF_INET, 0, &a1);

    inet_pton(AF_INET, "10.0.1.0", &prefix2);
    bgp_ribout_map_insert(map, &prefix2, 24, AF_INET, 0, &a2);

    inet_pton(AF_INET, "10.0.2.0", &prefix3);
    bgp_ribout_map_insert(map, &prefix3, 24, AF_INET, 0, &a3);

    ASSERT(map->entry_count == 3, "Should have 3 entries");
    ASSERT(map->total_nlri_count == 3, "Should have 3 NLRIs");

    // Verify all entries can still be found
    path_attr_entry_t *e1 = bgp_ribout_map_find(map, &a1);
    path_attr_entry_t *e2 = bgp_ribout_map_find(map, &a2);
    path_attr_entry_t *e3 = bgp_ribout_map_find(map, &a3);

    ASSERT(e1 != NULL, "Entry 1 not found");
    ASSERT(e2 != NULL, "Entry 2 not found");
    ASSERT(e3 != NULL, "Entry 3 not found");

    free(segments1);
    free(segments2);
    free(segments3);
    bgp_ribout_map_destroy(map);
    PASS();
}

void test_bucket_rounding(void) {
    TEST("Round bucket count to power of two");

    bgp_ribout_map_t *map = bgp_ribout_map_create(129);
    ASSERT(map != NULL, "Failed to create map");
    ASSERT(map->bucket_count == 256, "Bucket count should round up to 256");
    ASSERT(map->bucket_mask == 255, "Bucket mask should match rounded count");

    bgp_ribout_map_destroy(map);
    PASS();
}

void test_empty_aspath(void) {
    TEST("Insert with empty AS path");

    bgp_ribout_map_t *map = bgp_ribout_map_create(0);
    ASSERT(map != NULL, "Failed to create map");

    // Convert addresses to binary
    struct in_addr prefix_addr, next_hop_addr;
    inet_pton(AF_INET, "10.0.0.0", &prefix_addr);
    inet_pton(AF_INET, "192.168.1.1", &next_hop_addr);

    // Insert with NULL AS path (empty)
    bgp_path_attrs_t attrs = {
        .next_hop_addr       = &next_hop_addr,
        .next_hop_af         = AF_INET,
        .aspath_segments     = NULL,
        .aspath_segment_count = 0,
        .local_pref          = 100,
        .origin              = 0,
    };
    int ret = bgp_ribout_map_insert(map, &prefix_addr, 24, AF_INET, 0, &attrs);
    ASSERT(ret == 0, "Insert with empty AS path failed");
    ASSERT(map->entry_count == 1, "Entry count should be 1");

    // Find it
    path_attr_entry_t *entry = bgp_ribout_map_find(map, &attrs);
    ASSERT(entry != NULL, "Entry with empty AS path not found");
    ASSERT(entry->aspath_segment_count == 0, "AS path segment count should be 0");
    ASSERT(entry->aspath_data == NULL, "Compact AS path bytes should be NULL");

    bgp_ribout_map_destroy(map);
    PASS();
}

void test_get_stats(void) {
    TEST("Get map statistics");

    bgp_ribout_map_t *map = bgp_ribout_map_create(128);
    ASSERT(map != NULL, "Failed to create map");

    // Create AS path segments
    uint32_t aspath[] = {100, 200};
    uint32_t              segment_count;
    bgp_aspath_segment_t *segments = create_aspath_segments(aspath, 2, &segment_count);

    // Convert next_hops to binary
    struct in_addr next_hop1, next_hop2;
    inet_pton(AF_INET, "192.168.1.1", &next_hop1);
    inet_pton(AF_INET, "192.168.1.2", &next_hop2);

    // Insert entries
    bgp_path_attrs_t attrs1 = {
        .next_hop_addr = &next_hop1, .next_hop_af = AF_INET,
        .aspath_segments = segments, .aspath_segment_count = segment_count,
        .local_pref = 100, .origin = 0,
    };
    bgp_path_attrs_t attrs2 = {
        .next_hop_addr = &next_hop2, .next_hop_af = AF_INET,
        .aspath_segments = segments, .aspath_segment_count = segment_count,
        .local_pref = 100, .origin = 0,
    };

    struct in_addr prefix1, prefix2, prefix3;
    inet_pton(AF_INET, "10.0.0.0", &prefix1);
    bgp_ribout_map_insert(map, &prefix1, 24, AF_INET, 0, &attrs1);

    inet_pton(AF_INET, "10.0.1.0", &prefix2);
    bgp_ribout_map_insert(map, &prefix2, 24, AF_INET, 0, &attrs1);

    inet_pton(AF_INET, "10.0.2.0", &prefix3);
    bgp_ribout_map_insert(map, &prefix3, 24, AF_INET, 0, &attrs2);

    size_t entries, nlris, buckets;
    bgp_ribout_map_get_stats(map, &entries, &nlris, &buckets);

    ASSERT(entries == 2, "Wrong entry count in stats");
    ASSERT(nlris == 3, "Wrong NLRI count in stats");
    ASSERT(buckets == 128, "Wrong bucket count in stats");

    free(segments);
    bgp_ribout_map_destroy(map);
    PASS();
}

void test_generate_basic_map(void) {
    bgp_ribout_config_t block;
    size_t entries, nlris, buckets;
    int ret;

    TEST("Generate basic ribout map");
    setup_basic_ribout(&block);

    ret = bgp_ribout_generate_map(&block);
    ASSERT(ret == 0, "Generation failed");
    ASSERT(block.ribout != NULL, "Ribout map not created");

    bgp_ribout_map_get_stats(block.ribout, &entries, &nlris, &buckets);
    ASSERT(entries == 1, "Should have 1 path attr entry");
    ASSERT(nlris == 1, "Should have 1 NLRI");

    bgp_ribout_destroy(&block);
    PASS();
}

void test_generate_multiple_prefixes_same_attrs(void) {
    bgp_ribout_config_t block;
    size_t entries, nlris, buckets;
    int ret;

    TEST("Generate map with multiple prefixes sharing attributes");
    bgp_ribout_init(&block, "TEST");
    bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/24 x 10");
    bgp_ribout_parse_path_ids(&block, "path-id 0");
    bgp_ribout_parse_next_hop(&block, "next-hop 192.168.1.1");
    bgp_ribout_parse_aspath(&block, "as-path 100 200");
    bgp_ribout_parse_localpref(&block, "localpref 100");
    bgp_ribout_parse_origin(&block, "origin igp");

    ret = bgp_ribout_generate_map(&block);
    ASSERT(ret == 0, "Generation failed");

    bgp_ribout_map_get_stats(block.ribout, &entries, &nlris, &buckets);
    ASSERT(entries == 1, "Should have 1 entry (all same attrs)");
    ASSERT(nlris == 10, "Should have 10 NLRIs");

    bgp_ribout_destroy(&block);
    PASS();
}

void test_generate_multiple_pathids_same_prefix(void) {
    bgp_ribout_config_t block;
    size_t entries, nlris, buckets;
    int ret;

    TEST("Generate map with multiple path-ids for the same prefix");
    bgp_ribout_init(&block, "TEST");
    bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/24 x 1");
    bgp_ribout_parse_path_ids(&block, "path-id 1 2 3 4 5");
    bgp_ribout_parse_next_hop(&block, "next-hop 192.168.1.1");
    bgp_ribout_parse_aspath(&block, "as-path 100 200");
    bgp_ribout_parse_localpref(&block, "localpref 100");
    bgp_ribout_parse_origin(&block, "origin igp");

    ret = bgp_ribout_generate_map(&block);
    ASSERT(ret == 0, "Generation failed");

    bgp_ribout_map_get_stats(block.ribout, &entries, &nlris, &buckets);
    ASSERT(entries == 1, "Should have 1 entry (same attrs, different path-ids)");
    ASSERT(nlris == 5, "Should have 5 NLRIs");

    bgp_ribout_destroy(&block);
    PASS();
}

void test_generate_complex_diversity(void) {
    bgp_ribout_config_t block;
    size_t entries, nlris, buckets;
    int ret;

    TEST("Generate map with complex attribute diversity");
    setup_diverse_ribout(&block);

    ret = bgp_ribout_generate_map(&block);
    ASSERT(ret == 0, "Generation failed");

    bgp_ribout_map_get_stats(block.ribout, &entries, &nlris, &buckets);
    ASSERT(entries == 1, "Should have 1 entry (same next_hop)");
    ASSERT(nlris == 30, "Should have 30 NLRIs");

    bgp_ribout_destroy(&block);
    PASS();
}

void test_generate_regeneration_clears_old_map(void) {
    bgp_ribout_config_t block;
    size_t entries, nlris, buckets;

    TEST("Regeneration clears the previous ribout map");
    setup_basic_ribout(&block);

    bgp_ribout_generate_map(&block);
    bgp_ribout_parse_prefix(&block, "prefix 172.16.0.0/16 x 20");
    bgp_ribout_generate_map(&block);

    bgp_ribout_map_get_stats(block.ribout, &entries, &nlris, &buckets);
    ASSERT(nlris == 20, "Old ribout should be cleared");

    bgp_ribout_destroy(&block);
    PASS();
}

void test_generate_large_scale_map(void) {
    bgp_ribout_config_t block;
    size_t entries, nlris;
    int ret;

    TEST("Generate map at large scale");
    bgp_ribout_init(&block, "LARGE");
    bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/24 x 100");
    bgp_ribout_parse_path_ids(&block, "path-id 1 2 3 4 5");
    bgp_ribout_parse_next_hop(&block, "next-hop 192.168.1.1");
    bgp_ribout_parse_aspath(&block, "as-path 100 200 300 400");
    bgp_ribout_parse_localpref(&block, "localpref 150");
    bgp_ribout_parse_origin(&block, "origin igp");

    ret = bgp_ribout_generate_map(&block);
    ASSERT(ret == 0, "Large scale generation failed");

    bgp_ribout_map_get_stats(block.ribout, &entries, &nlris, NULL);
    ASSERT(entries == 1, "Should have 1 entry (all same attrs)");
    ASSERT(nlris == 500, "Should have 500 NLRIs (100 x 5)");

    bgp_ribout_destroy(&block);
    PASS();
}

void test_generate_map_compacts_bucket_table_after_grouping(void) {
    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;
    size_t              entries = 0;
    size_t              nlris = 0;
    size_t              buckets = 0;
    size_t              precompact_buckets = 0;

    TEST("Generate map compacts bucket table after grouping");

    bgp_ribout_init(&block, "COMPACT");
    bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/24 x 4096");
    bgp_ribout_parse_path_ids(&block, "path-id 1 2 3 4");
    bgp_ribout_parse_next_hop(&block, "next-hop 192.0.2.1");
    bgp_ribout_parse_aspath(&block, "as-path 65001 65002");
    bgp_ribout_parse_localpref(&block, "localpref 200");
    bgp_ribout_parse_origin(&block, "origin igp");

    ASSERT(bgp_ribout_generator_init(&gen, &block) == 0, "Failed to initialize generator for compaction test");
    precompact_buckets = test_expected_precompact_bucket_count(gen.total_paths);
    ASSERT(precompact_buckets > RIBOUT_HASHMAP_DEFAULT_SIZE,
           "Compaction test must start from an oversized insertion bucket table");

    ASSERT(bgp_ribout_generate_map(&block) == 0, "Compacted map generation failed");
    ASSERT(block.ribout != NULL, "Compacted map not created");

    bgp_ribout_map_get_stats(block.ribout, &entries, &nlris, &buckets);
    ASSERT(entries == 1, "Grouped workload should collapse into one attribute entry");
    ASSERT(nlris == (4096U * 4U), "Grouped workload should preserve every emitted NLRI");
    ASSERT(buckets < precompact_buckets, "Finished map should retain fewer buckets than the insertion hint");
    ASSERT(buckets == RIBOUT_HASHMAP_DEFAULT_SIZE, "One-group map should compact back to the default bucket table");

    bgp_ribout_destroy(&block);
    PASS();
}

void test_consolidate_multiple_ribouts_into_one_map(void) {
    static const struct {
        const char *name;
        const char *prefix_cmd;
        const char *next_hop_cmd;
        const char *as_path_cmd;
        const char *localpref_cmd;
        const char *origin_cmd;
    } cases[] = {
        {"high-prio", "prefix 10.1.0.0/24 x 5", "next-hop 192.168.1.1", "as-path 100 200",
         "localpref 200", "origin igp"},
        {"med-prio", "prefix 10.2.0.0/24 x 5", "next-hop 192.168.1.1", "as-path 100 200",
         "localpref 100", "origin igp"},
        {"low-prio", "prefix 10.3.0.0/24 x 5", "next-hop 192.168.2.1", "as-path 100 200",
         "localpref 50", "origin igp"},
        {"alt-path", "prefix 10.4.0.0/24 x 5", "next-hop 192.168.1.1", "as-path 100 300",
         "localpref 100", "origin igp"},
        {"incomplete", "prefix 10.5.0.0/24 x 5", "next-hop 192.168.1.1", "as-path 100 200",
         "localpref 100", "origin incomplete"},
    };
    bgp_ribout_config_t ribouts[sizeof(cases) / sizeof(cases[0])];
    bgp_ribout_map_t *consolidated = NULL;
    int               setup_ok = 1;
    size_t            entries = 0, nlris = 0, buckets = 0;

    TEST("Consolidate multiple ribouts into one map");
    consolidated = bgp_ribout_map_create(0);
    ASSERT(consolidated != NULL, "Failed to create consolidated map");

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        bgp_ribout_gen_t gen;
        bgp_gen_path_t   path;

        setup_consolidation_ribout(&ribouts[i], cases[i].name, cases[i].prefix_cmd, cases[i].next_hop_cmd,
                                   cases[i].as_path_cmd, cases[i].localpref_cmd, cases[i].origin_cmd);
        if (bgp_ribout_generate_map(&ribouts[i]) != 0 || bgp_ribout_generator_init(&gen, &ribouts[i]) != 0) {
            setup_ok = 0;
            break;
        }

        while (bgp_ribout_generator_has_next(&gen)) {
            const void      *prefix_ptr;
            const void      *next_hop_ptr;
            bgp_path_attrs_t attrs;

            if (bgp_ribout_generator_next(&gen, &path) != 0) {
                setup_ok = 0;
                break;
            }

            prefix_ptr = path.prefix_af == AF_INET ? (const void *)&path.prefix_addr.ipv4
                                                   : (const void *)&path.prefix_addr.ipv6;
            next_hop_ptr = path.next_hop_af == AF_INET ? (const void *)&path.next_hop_addr.ipv4
                                                       : (const void *)&path.next_hop_addr.ipv6;
            attrs = (bgp_path_attrs_t){
                .next_hop_addr = next_hop_ptr,
                .next_hop_af = path.next_hop_af,
                .aspath_segments = path.aspath_segments,
                .aspath_segment_count = path.aspath_segment_count,
                .local_pref = path.local_pref,
                .origin = (uint8_t)path.origin,
            };

            if (bgp_ribout_map_insert(consolidated, prefix_ptr, path.prefix_len, path.prefix_af, path.path_id,
                                      &attrs) != 0) {
                setup_ok = 0;
                break;
            }
        }
        if (!setup_ok) {
            break;
        }
    }

    ASSERT(setup_ok, "Multiple ribouts can be consolidated into one map");

    bgp_ribout_map_get_stats(consolidated, &entries, &nlris, &buckets);
    ASSERT(entries == 5, "Consolidation preserves distinct attribute groups");
    ASSERT(nlris == 25, "Consolidation preserves all generated NLRIs");
    ASSERT(buckets > 0, "Consolidated map reports bucket statistics");

    bgp_ribout_map_destroy(consolidated);
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        bgp_ribout_destroy(&ribouts[i]);
    }
    PASS();
}

void test_generate_srpolicy_map_groups_by_tunnel_attributes(void) {
    bgp_ribout_config_t block;
    size_t              bucket;
    int                 saw_first = 0;
    int                 saw_second = 0;

    TEST("Generate SR Policy map groups by tunnel attributes");

    bgp_ribout_init(&block, "SRPOL");
    bgp_ribout_parse_distinguisher(&block, "distinguisher 100 101");
    bgp_ribout_parse_color(&block, "color 200");
    bgp_ribout_parse_endpoint(&block, "endpoint 10.0.0.1 x 2");
    bgp_ribout_parse_path_ids(&block, "path-id 1");
    bgp_ribout_parse_next_hop(&block, "next-hop 192.0.2.1");
    bgp_ribout_parse_rt(&block, "rt 192.0.2.10:100");
    bgp_ribout_parse_enlp(&block, "enlp 3 4");
    bgp_ribout_parse_priority(&block, "priority 7 8");
    bgp_ribout_parse_preference(&block, "preference 300 400");
    bgp_ribout_parse_binding_sid(&block, "binding-sid mpls 16000 16001");
    bgp_ribout_parse_segment_list(&block, "segment-list 1 weight 10 mpls 16010 16011");
    bgp_ribout_parse_aspath(&block, "as-path 65001 65002");
    bgp_ribout_parse_localpref(&block, "localpref 200");
    bgp_ribout_parse_origin(&block, "origin igp");

    ASSERT(bgp_ribout_generate_map(&block) == 0, "SR Policy map generation failed");
    ASSERT(block.ribout != NULL, "SR Policy map not created");
    ASSERT(block.ribout->entry_count == 2, "Rotating SR preference/binding SID pairs split SR Policy map entries");
    ASSERT(block.ribout->total_nlri_count == 4, "SR Policy map preserves all generated NLRIs");

    for (bucket = 0; bucket < block.ribout->bucket_count; bucket++) {
        path_attr_entry_t *entry = block.ribout->buckets[bucket];

        while (entry) {
            if (entry->has_tunnel_encap &&
                entry->has_enlp &&
                entry->enlp == 3 &&
                entry->has_priority &&
                entry->priority == 7 &&
                entry->preference == 300 &&
                entry->binding_sid.type == SRPOLICY_BINDING_SID_MPLS &&
                entry->binding_sid.mpls_label == 16000) {
                ASSERT(entry->nlri_count == 2, "First SR tunnel-attribute group owns two NLRIs");
                saw_first = 1;
            } else if (entry->has_tunnel_encap &&
                       entry->has_enlp &&
                       entry->enlp == 4 &&
                       entry->has_priority &&
                       entry->priority == 8 &&
                       entry->preference == 400 &&
                       entry->binding_sid.type == SRPOLICY_BINDING_SID_MPLS &&
                       entry->binding_sid.mpls_label == 16001) {
                ASSERT(entry->nlri_count == 2, "Second SR tunnel-attribute group owns two NLRIs");
                saw_second = 1;
            }
            entry = entry->next;
        }
    }

    ASSERT(saw_first && saw_second, "SR Policy map retains both rotating tunnel-attribute groups");

    bgp_ribout_destroy(&block);
    PASS();
}

void test_generate_evpn_type2_map_keeps_encoded_field_variation_inside_one_group(void) {
    bgp_ribout_config_t block;
    path_attr_entry_t  *entry = NULL;
    int                 bucket_found = 0;

    TEST("Generate EVPN Type 2 map keeps encoded-field variation inside one attribute group");

    bgp_ribout_init(&block, "EVPN2");
    bgp_ribout_parse_rd(&block, "rd 65000:320");
    bgp_ribout_parse_ethernet_tag(&block, "ethernet-tag 10");
    bgp_ribout_parse_mac(&block, "mac 00:11:22:33:44:00 x 4");
    bgp_ribout_parse_ip(&block, "ip 192.0.2.1");
    bgp_ribout_parse_label(&block, "label 30000 30001");
    bgp_ribout_parse_label2(&block, "label2 40000 40001");
    bgp_ribout_parse_esi(&block, "esi 00:00:00:00:00:00:00:00:00:00 " "00:00:00:00:00:00:00:00:00:01");
    bgp_ribout_parse_next_hop(&block, "next-hop 192.0.2.10");
    bgp_ribout_parse_rt(&block, "rt 65000:320");
    bgp_ribout_parse_aspath(&block, "as-path 65001 65002");
    bgp_ribout_parse_localpref(&block, "localpref 200");
    bgp_ribout_parse_origin(&block, "origin igp");

    ASSERT(bgp_ribout_generate_map(&block) == 0, "EVPN Type 2 map generation failed");
    ASSERT(block.ribout != NULL, "EVPN Type 2 map not created");
    ASSERT(block.ribout->entry_count == 1,
           "EVPN Type 2 label, label2, and ESI variation do not split attribute groups");
    ASSERT(block.ribout->total_nlri_count == 4, "EVPN Type 2 map preserves all generated host-binding NLRIs");

    for (size_t bucket = 0; bucket < block.ribout->bucket_count; bucket++) {
        entry = block.ribout->buckets[bucket];
        if (!entry) {
            continue;
        }

        bucket_found = 1;
        ASSERT(entry->nlri_type == BGP_RIBOUT_NLRI_TYPE_EVPN_TYPE2,
               "EVPN Type 2 map entry keeps EVPN Type 2 NLRI type");
        ASSERT(entry->nlri_count == 4, "Single EVPN Type 2 attribute group owns all four MAC bindings");

        {
            const bgp_ribout_nlri_chunk_t *chunk = entry->nlri_chunks;
            uint32_t                       first_label1 = 0;
            uint32_t                       first_label2 = 0;
            int                            have_label1 = 0;
            int                            have_label2 = 0;
            int                            saw_label1_variation = 0;
            int                            saw_label2_variation = 0;

            ASSERT(chunk != NULL, "EVPN Type 2 map stores NLRI records in chunks");

            while (chunk) {
                size_t idx;

                for (idx = 0; idx < chunk->count; idx++) {
                    const bgp_ribout_nlri_evpn2_t *nlri =
                        (const bgp_ribout_nlri_evpn2_t *)(chunk->data + (idx * chunk->stride));

                    ASSERT(nlri->has_label2, "EVPN Type 2 label2 variation stays inside one attribute group");

                    if (!have_label1) {
                        first_label1 = nlri->label1;
                        have_label1 = 1;
                    } else if (nlri->label1 != first_label1) {
                        saw_label1_variation = 1;
                    }

                    if (!have_label2) {
                        first_label2 = nlri->label2;
                        have_label2 = 1;
                    } else if (nlri->label2 != first_label2) {
                        saw_label2_variation = 1;
                    }
                }

                chunk = chunk->next;
            }

            ASSERT(saw_label1_variation, "EVPN Type 2 primary label variation stays inside one attribute group");
            ASSERT(saw_label2_variation, "EVPN Type 2 label2 variation stays inside one attribute group");
        }

        break;
    }

    ASSERT(bucket_found, "EVPN Type 2 attribute group found in hash map");

    bgp_ribout_destroy(&block);
    PASS();
}

void test_generate_evpn_type2_map_groups_by_encap_and_router_mac(void) {
    bgp_ribout_config_t block;
    int                 groups_found = 0;

    TEST("Generate EVPN Type 2 map groups by encap and router-mac attrs");

    bgp_ribout_init(&block, "EVPN2-ATTRS");
    bgp_ribout_parse_rd(&block, "rd 65000:320");
    bgp_ribout_parse_ethernet_tag(&block, "ethernet-tag 10");
    bgp_ribout_parse_mac(&block, "mac 00:11:22:33:44:00 x 4");
    bgp_ribout_parse_ip(&block, "ip 192.0.2.1");
    bgp_ribout_parse_label(&block, "label 30000");
    bgp_ribout_parse_next_hop(&block, "next-hop 192.0.2.10");
    bgp_ribout_parse_rt(&block, "rt 65000:320");
    bgp_ribout_parse_encap(&block, "encap vxlan nvgre");
    bgp_ribout_parse_router_mac(&block, "router-mac 02:00:00:00:00:01 " "02:00:00:00:00:02");
    bgp_ribout_parse_aspath(&block, "as-path 65001 65002");
    bgp_ribout_parse_localpref(&block, "localpref 200");
    bgp_ribout_parse_origin(&block, "origin igp");

    ASSERT(bgp_ribout_generate_map(&block) == 0, "EVPN Type 2 attr-group map generation failed");
    ASSERT(block.ribout != NULL, "EVPN Type 2 attr-group map not created");
    ASSERT(block.ribout->entry_count == 2, "EVPN Type 2 encap/router-mac rotation splits attribute groups");
    ASSERT(block.ribout->total_nlri_count == 4, "EVPN Type 2 attr-group map preserves all generated host-bindings");

    for (size_t bucket = 0; bucket < block.ribout->bucket_count; bucket++) {
        path_attr_entry_t *entry = block.ribout->buckets[bucket];

        while (entry) {
            ASSERT(entry->nlri_type == BGP_RIBOUT_NLRI_TYPE_EVPN_TYPE2,
                   "EVPN Type 2 attr-group entry keeps EVPN Type 2 NLRI type");
            ASSERT(entry->nlri_count == 2, "Each EVPN Type 2 attr-group owns the paired MAC bindings");
            ASSERT(entry->ext_comm_len == 24, "Each EVPN Type 2 attr-group carries RT, encap, and router-mac");
            ASSERT(entry->ext_comm_data[8] == 0x03 && entry->ext_comm_data[9] == 0x0c,
                   "EVPN Type 2 attr-group keeps encap immediately after RT");
            ASSERT(entry->ext_comm_data[16] == 0x06 && entry->ext_comm_data[17] == 0x03,
                   "EVPN Type 2 attr-group keeps router-mac after encap");
            groups_found++;
            entry = entry->next;
        }
    }

    ASSERT(groups_found == 2, "EVPN Type 2 attr-group count matches hash buckets");

    bgp_ribout_destroy(&block);
    PASS();
}

// Main Test Runner

int main(void) {
    printf("BGP RIB-OUT Map Tests\n");
    printf("=====================\n\n");

    // Run all tests
    test_create_destroy();
    test_insert_single_nlri();
    test_insert_multiple_nlri_same_attrs();
    test_insert_different_attrs();
    test_find_existing();
    test_find_nonexistent();
    test_clear_map();
    test_add_path_support();
    test_hash_collisions();
    test_bucket_rounding();
    test_empty_aspath();
    test_get_stats();
    test_generate_basic_map();
    test_generate_multiple_prefixes_same_attrs();
    test_generate_multiple_pathids_same_prefix();
    test_generate_complex_diversity();
    test_generate_regeneration_clears_old_map();
    test_generate_large_scale_map();
    test_generate_map_compacts_bucket_table_after_grouping();
    test_consolidate_multiple_ribouts_into_one_map();
    test_generate_srpolicy_map_groups_by_tunnel_attributes();
    test_generate_evpn_type2_map_keeps_encoded_field_variation_inside_one_group();
    test_generate_evpn_type2_map_groups_by_encap_and_router_mac();

    // Print summary
    printf("\n=====================\n");
    printf("Tests run:    %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);
    printf("=====================\n");

    return (tests_failed == 0) ? 0 : 1;
}
