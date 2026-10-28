#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include "test_case.h"
#include "bgp_ribout.h"
#include "bgp_ribout_snapshot.h"

#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))

typedef struct {
    const char         *profile_name;
    const char         *prefix;
    const char         *rd;
    const char         *label;
    const char         *label2;
    const char         *ethernet_tag;
    const char         *mac;
    const char         *ip;
    const char         *path_id;
    const char         *next_hop;
    const char         *gateway_ip;
    const char         *esi;
    const char         *as_path;
    const char         *localpref;
    const char         *med;
    const char         *rt;
    const char         *rt_set;
    const char         *soo;
    const char         *origin;
    const char         *distinguisher;
    const char         *color;
    const char         *endpoint;
    const char         *enlp;
    const char         *priority;
    const char         *preference;
    const char         *binding_sid;
    const char         *segment_list_a;
    const char         *segment_list_b;
    bgp_ribout_family_t expected_family;
    uint64_t            expected_paths;
    size_t              expected_groups;
    size_t              expected_messages;
} stress_profile_t;

typedef struct {
    bgp_ribout_config_t     block;
    int                     initialized;
    const stress_profile_t *profile;
} stress_slot_t;

typedef struct {
    const char             *stable_name;
    const char             *replace_prefix;
    int                     replace_name_each_iteration;
    const stress_profile_t *variants[6];
    size_t                  variant_count;
} stress_slot_plan_t;

static int stress_parse_optional(bgp_ribout_config_t *block,
                                 const char *line,
                                 int (*parse_fn)(bgp_ribout_config_t *,
                                                 const char *)) {
    if (!line) {
        return 1;
    }

    return parse_fn(block, line) == 0;
}

static uint64_t stress_total_paths(const bgp_ribout_config_t *block) {
    if (block->endpoint_spec.count > 0) {
        return (uint64_t)bgp_ribout_effective_count(block->distinguisher_count) *
               (uint64_t)bgp_ribout_effective_count(block->color_count) *
               (uint64_t)block->endpoint_spec.count *
               (uint64_t)bgp_ribout_effective_count(block->path_id_count);
    }

    if (block->mac_spec.count > 0) {
        return (uint64_t)bgp_ribout_effective_count(block->rd_count) *
               (uint64_t)bgp_ribout_effective_count(block->ethernet_tag_count) *
               (uint64_t)block->mac_spec.count *
               (uint64_t)bgp_ribout_effective_count(block->ip_spec.count) *
               (uint64_t)bgp_ribout_effective_count(block->path_id_count);
    }

    return (uint64_t)block->prefix_spec.count *
           (uint64_t)bgp_ribout_effective_count(block->rd_count) *
           (uint64_t)bgp_ribout_effective_count(block->ethernet_tag_count) *
           (uint64_t)bgp_ribout_effective_count(block->gateway_ip_spec.count) *
           (uint64_t)bgp_ribout_effective_count(block->esi_count) *
           (uint64_t)bgp_ribout_effective_count(block->label_count) *
           (uint64_t)bgp_ribout_effective_count(block->path_id_count);
}

static size_t stress_count_messages(const bgp_msg_t *messages) {
    size_t count = 0;

    while (messages) {
        count++;
        messages = messages->next;
    }

    return count;
}

static size_t stress_sum_message_bytes(const bgp_msg_t *messages) {
    size_t total = 0;

    while (messages) {
        total += messages->length;
        messages = messages->next;
    }

    return total;
}

static int stress_setup_block(bgp_ribout_config_t *block, const char *name, const stress_profile_t *profile) {
    bgp_ribout_init(block, name);

    if (!stress_parse_optional(block, profile->prefix, bgp_ribout_parse_prefix) ||
        !stress_parse_optional(block, profile->rd, bgp_ribout_parse_rd) ||
        !stress_parse_optional(block, profile->label, bgp_ribout_parse_label) ||
        !stress_parse_optional(block, profile->label2, bgp_ribout_parse_label2) ||
        !stress_parse_optional(block, profile->ethernet_tag, bgp_ribout_parse_ethernet_tag) ||
        !stress_parse_optional(block, profile->mac, bgp_ribout_parse_mac) ||
        !stress_parse_optional(block, profile->ip, bgp_ribout_parse_ip) ||
        !stress_parse_optional(block, profile->path_id, bgp_ribout_parse_path_ids) ||
        !stress_parse_optional(block, profile->next_hop, bgp_ribout_parse_next_hop) ||
        !stress_parse_optional(block, profile->gateway_ip, bgp_ribout_parse_gateway_ip) ||
        !stress_parse_optional(block, profile->esi, bgp_ribout_parse_esi) ||
        !stress_parse_optional(block, profile->med, bgp_ribout_parse_med) ||
        !stress_parse_optional(block, profile->rt, bgp_ribout_parse_rt) ||
        !stress_parse_optional(block, profile->rt_set, bgp_ribout_parse_rt_set) ||
        !stress_parse_optional(block, profile->soo, bgp_ribout_parse_soo) ||
        !stress_parse_optional(block, profile->distinguisher, bgp_ribout_parse_distinguisher) ||
        !stress_parse_optional(block, profile->color, bgp_ribout_parse_color) ||
        !stress_parse_optional(block, profile->endpoint, bgp_ribout_parse_endpoint) ||
        !stress_parse_optional(block, profile->enlp, bgp_ribout_parse_enlp) ||
        !stress_parse_optional(block, profile->priority, bgp_ribout_parse_priority) ||
        !stress_parse_optional(block, profile->preference, bgp_ribout_parse_preference) ||
        !stress_parse_optional(block, profile->binding_sid, bgp_ribout_parse_binding_sid) ||
        !stress_parse_optional(block, profile->segment_list_a, bgp_ribout_parse_segment_list) ||
        !stress_parse_optional(block, profile->segment_list_b,
                               bgp_ribout_parse_segment_list)) {
        return 0;
    }

    if (profile->as_path) {
        if (bgp_ribout_parse_aspath(block, profile->as_path) != 0) {
            return 0;
        }
    } else if (bgp_ribout_parse_aspath(block, "as-path 65001 65002 65003") != 0) {
        return 0;
    }

    if (profile->localpref) {
        if (bgp_ribout_parse_localpref(block, profile->localpref) != 0) {
            return 0;
        }
    } else if (bgp_ribout_parse_localpref(block, "localpref 200") != 0) {
        return 0;
    }

    if (profile->origin) {
        return bgp_ribout_parse_origin(block, profile->origin) == 0;
    }

    return bgp_ribout_parse_origin(block, "origin igp") == 0;
}

static int stress_slot_configure(stress_slot_t *slot, const char *name, const stress_profile_t *profile) {
    if (slot->initialized) {
        bgp_ribout_destroy(&slot->block);
        slot->initialized = 0;
        slot->profile = NULL;
    }

    if (!stress_setup_block(&slot->block, name, profile)) {
        return 0;
    }

    slot->initialized = 1;
    slot->profile = profile;
    return 1;
}

static void stress_slot_cleanup(stress_slot_t *slot) {
    if (!slot || !slot->initialized) {
        return;
    }

    bgp_ribout_destroy(&slot->block);
    slot->initialized = 0;
    slot->profile = NULL;
}

static const stress_profile_t k_ipv4_profiles[2] = {
    {
        .profile_name = "ipv4-a",
        .prefix = "prefix 10.10.0.0/24 x 6144",
        .path_id = "path-id 0 1",
        .next_hop = "next-hop 192.0.2.1 x 1024",
        .expected_family = BGP_RIBOUT_FAMILY_IPV4_UNICAST,
        .expected_paths = 12288,
        .expected_groups = 1024,
        .expected_messages = 1024,
    },
    {
        .profile_name = "ipv4-b",
        .prefix = "prefix 10.20.0.0/24 x 4096",
        .path_id = "path-id 0 1 2",
        .next_hop = "next-hop 192.0.2.1 x 768",
        .expected_family = BGP_RIBOUT_FAMILY_IPV4_UNICAST,
        .expected_paths = 12288,
        .expected_groups = 768,
        .expected_messages = 768,
    },
};

static const stress_profile_t k_ipv6_profiles[2] = {
    {
        .profile_name = "ipv6-a",
        .prefix = "prefix 2001:db8:10::/64 x 6144",
        .path_id = "path-id 0 1",
        .next_hop = "next-hop 2001:db8:ffff::1 x 1024",
        .expected_family = BGP_RIBOUT_FAMILY_IPV6_UNICAST,
        .expected_paths = 12288,
        .expected_groups = 1024,
        .expected_messages = 1024,
    },
    {
        .profile_name = "ipv6-b",
        .prefix = "prefix 2001:db8:20::/64 x 4096",
        .path_id = "path-id 0 1 2",
        .next_hop = "next-hop 2001:db8:ffff::1 x 768",
        .expected_family = BGP_RIBOUT_FAMILY_IPV6_UNICAST,
        .expected_paths = 12288,
        .expected_groups = 768,
        .expected_messages = 768,
    },
};

static const stress_profile_t k_vpn4_profiles[2] = {
    {
        .profile_name = "vpn4-a",
        .prefix = "prefix 10.30.0.0/24 x 1536",
        .rd = "rd 65000:100 x 4",
        .label = "label 16000 16001",
        .next_hop = "next-hop 192.0.2.10 x 1024",
        .med = "med 50",
        .rt = "rt 65000:100 65000:101",
        .soo = "soo 65000:9",
        .expected_family = BGP_RIBOUT_FAMILY_VPNV4,
        .expected_paths = 12288,
        .expected_groups = 1024,
        .expected_messages = 1024,
    },
    {
        .profile_name = "vpn4-b",
        .prefix = "prefix 10.40.0.0/24 x 768",
        .rd = "rd 65000:200 x 4",
        .label = "label 24000 24001",
        .path_id = "path-id 7 8",
        .next_hop = "next-hop 192.0.2.10 x 768",
        .med = "med 75",
        .rt = "rt 65000:200 65000:201",
        .soo = "soo 65000:19",
        .expected_family = BGP_RIBOUT_FAMILY_VPNV4,
        .expected_paths = 12288,
        .expected_groups = 768,
        .expected_messages = 768,
    },
};

static const stress_profile_t k_evpn4_profiles[2] = {
    {
        .profile_name = "evpn4-a",
        .prefix = "prefix 192.168.10.0/24 x 768",
        .rd = "rd 65000:300 x 4",
        .label = "label 30000",
        .ethernet_tag = "ethernet-tag 10 11",
        .next_hop = "next-hop 192.0.2.20 x 1024",
        .gateway_ip = "gateway-ip 10.255.0.1 x 2",
        .med = "med 25",
        .rt = "rt 65000:300",
        .expected_family = BGP_RIBOUT_FAMILY_EVPN_TYPE5_IPV4,
        .expected_paths = 12288,
        .expected_groups = 1024,
        .expected_messages = 1024,
    },
    {
        .profile_name = "evpn4-b",
        .prefix = "prefix 192.168.20.0/24 x 256",
        .rd = "rd 65000:400 x 4",
        .label = "label 31000",
        .ethernet_tag = "ethernet-tag 20 21",
        .path_id = "path-id 7 8 9",
        .next_hop = "next-hop 192.0.2.20 x 768",
        .gateway_ip = "gateway-ip 10.255.1.1 x 2",
        .med = "med 35",
        .rt = "rt 65000:400",
        .expected_family = BGP_RIBOUT_FAMILY_EVPN_TYPE5_IPV4,
        .expected_paths = 12288,
        .expected_groups = 768,
        .expected_messages = 768,
    },
};

static const stress_profile_t k_sr4_profiles[2] = {
    {
        .profile_name = "sr4-a",
        .distinguisher = "distinguisher 100 x 4",
        .color = "color 500 x 8",
        .endpoint = "endpoint 10.50.0.1 x 384",
        .next_hop = "next-hop 192.0.2.30 x 1024",
        .rt = "rt 192.0.2.30:100",
        .enlp = "enlp 3",
        .priority = "priority 7",
        .preference = "preference 1000",
        .binding_sid = "binding-sid mpls 16000",
        .segment_list_a = "segment-list 1 weight 10 mpls 16010 16011 16012",
        .expected_family = BGP_RIBOUT_FAMILY_SR_POLICY_IPV4,
        .expected_paths = 12288,
        .expected_groups = 1024,
        .expected_messages = 1024,
    },
    {
        .profile_name = "sr4-b",
        .distinguisher = "distinguisher 200 x 6",
        .color = "color 700 701 702 703",
        .endpoint = "endpoint 10.60.0.1 x 256",
        .path_id = "path-id 7 8",
        .next_hop = "next-hop 192.0.2.30 x 768",
        .rt = "rt 192.0.2.30:200",
        .enlp = "enlp 4",
        .priority = "priority 9",
        .preference = "preference 2000",
        .binding_sid = "binding-sid mpls 26000",
        .segment_list_a = "segment-list 2 weight 20 mpls 26010 26011 26012",
        .expected_family = BGP_RIBOUT_FAMILY_SR_POLICY_IPV4,
        .expected_paths = 12288,
        .expected_groups = 768,
        .expected_messages = 768,
    },
};

static const stress_slot_plan_t k_slot_plans[] = {
    {.stable_name = "stmix0", .replace_prefix = NULL, .replace_name_each_iteration = 0,
     .variants = {
         &k_ipv4_profiles[0],
         &k_vpn4_profiles[0],
         &k_evpn4_profiles[0],
         &k_sr4_profiles[0],
         &k_ipv6_profiles[0],
         &k_vpn4_profiles[1],
     },
     .variant_count = 6},
    {.stable_name = "stmix1", .replace_prefix = NULL, .replace_name_each_iteration = 0,
     .variants = {
         &k_ipv6_profiles[1],
         &k_evpn4_profiles[1],
         &k_ipv4_profiles[1],
         &k_sr4_profiles[1],
         &k_vpn4_profiles[0],
         &k_evpn4_profiles[0],
     },
     .variant_count = 6},
    {.stable_name = "stmix2", .replace_prefix = NULL, .replace_name_each_iteration = 0,
     .variants = {
         &k_vpn4_profiles[1],
         &k_sr4_profiles[0],
         &k_ipv6_profiles[0],
         &k_evpn4_profiles[0],
         &k_ipv4_profiles[0],
         &k_sr4_profiles[1],
     },
     .variant_count = 6},
    {.stable_name = "stmix3", .replace_prefix = NULL, .replace_name_each_iteration = 0,
     .variants = {
         &k_evpn4_profiles[1],
         &k_ipv4_profiles[0],
         &k_sr4_profiles[1],
         &k_vpn4_profiles[0],
         &k_ipv6_profiles[1],
         &k_evpn4_profiles[0],
     },
     .variant_count = 6},
    {.stable_name = "streplace", .replace_prefix = "strep", .replace_name_each_iteration = 1,
     .variants = {
         &k_sr4_profiles[0],
         &k_ipv4_profiles[1],
         &k_vpn4_profiles[1],
         &k_evpn4_profiles[1],
         &k_ipv6_profiles[0],
         &k_sr4_profiles[1],
     },
     .variant_count = 6},
};

static int verify_cycle(stress_slot_t *slots, size_t slot_count, const char *phase, char *failure, size_t failure_len) {
    size_t slot_index;

    for (slot_index = 0; slot_index < slot_count; slot_index++) {
        stress_slot_t          *slot = &slots[slot_index];
        const stress_profile_t *profile = slot->profile;
        bgp_ribout_family_t     family;
        uint64_t                total_paths;
        size_t                  entries = 0;
        size_t                  nlris = 0;
        size_t                  message_bytes = 0;

        if (!slot->initialized || !profile) {
            snprintf(failure, failure_len, "%s: slot %zu is not configured", phase, slot_index);
            return 0;
        }

        family = bgp_ribout_resolve_family(&slot->block);
        if (family != profile->expected_family) {
            snprintf(failure, failure_len,
                     "%s/%s/%s: family %d != expected %d",
                     phase, slot->block.name, profile->profile_name,
                     family, profile->expected_family);
            return 0;
        }

        total_paths = stress_total_paths(&slot->block);
        if (total_paths != profile->expected_paths) {
            snprintf(failure, failure_len,
                     "%s/%s/%s: paths %"PRIu64" != expected %"PRIu64,
                     phase, slot->block.name, profile->profile_name,
                     total_paths, profile->expected_paths);
            return 0;
        }

        if (bgp_ribout_generate_map(&slot->block) != 0 || !slot->block.ribout) {
            snprintf(failure, failure_len,
                     "%s/%s/%s: map generation failed",
                     phase, slot->block.name, profile->profile_name);
            return 0;
        }

        bgp_ribout_map_get_stats(slot->block.ribout, &entries, &nlris, NULL);
        if (entries != profile->expected_groups) {
            snprintf(failure, failure_len,
                     "%s/%s/%s: groups %zu != expected %zu",
                     phase, slot->block.name, profile->profile_name,
                     entries, profile->expected_groups);
            return 0;
        }
        if (nlris != (size_t)profile->expected_paths) {
            snprintf(failure, failure_len,
                     "%s/%s/%s: nlris %zu != expected %"PRIu64,
                     phase, slot->block.name, profile->profile_name,
                     nlris, profile->expected_paths);
            return 0;
        }

        if (bgp_ribout_generate_messages(&slot->block) != 0) {
            snprintf(failure, failure_len,
                     "%s/%s/%s: message generation failed",
                     phase, slot->block.name, profile->profile_name);
            return 0;
        }

        if (slot->block.ribout != NULL) {
            snprintf(failure, failure_len,
                     "%s/%s/%s: ribout map should be consumed after message generation",
                     phase, slot->block.name, profile->profile_name);
            return 0;
        }
        if (slot->block.message_count != profile->expected_messages) {
            snprintf(failure, failure_len,
                     "%s/%s/%s: msgs %zu != expected %zu",
                     phase, slot->block.name, profile->profile_name,
                     slot->block.message_count, profile->expected_messages);
            return 0;
        }
        if (stress_count_messages(slot->block.messages) != profile->expected_messages) {
            snprintf(failure, failure_len,
                     "%s/%s/%s: linked-list message count mismatch",
                     phase, slot->block.name, profile->profile_name);
            return 0;
        }

        message_bytes = stress_sum_message_bytes(slot->block.messages);
        if (message_bytes == 0 || !slot->block.snapshot ||
            slot->block.snapshot->adv->msgs != slot->block.messages ||
            slot->block.snapshot->adv->count != slot->block.message_count ||
            slot->block.snapshot->adv->bytes != message_bytes) {
            snprintf(failure, failure_len,
                     "%s/%s/%s: message cache is empty or does not match the published snapshot",
                     phase, slot->block.name, profile->profile_name);
            return 0;
        }
    }

    return 1;
}

static void test_ribout_pipeline_stress_reconfiguration(void) {
    stress_slot_t slots[ARRAY_LEN(k_slot_plans)];
    size_t slot_index;
    int    iteration;
    char   failure[256];
    char   phase[64];
    char   name[32];

    memset(slots, 0, sizeof(slots));

    TEST("Ribout pipeline stress across repeated reconfiguration");

    for (slot_index = 0; slot_index < ARRAY_LEN(k_slot_plans); slot_index++) {
        const stress_slot_plan_t *plan = &k_slot_plans[slot_index];

        if (!stress_slot_configure(&slots[slot_index],
                                   plan->stable_name,
                                   plan->variants[0])) {
            snprintf(failure, sizeof(failure), "initial setup failed for %s", plan->stable_name);
            FAIL(failure);
            goto cleanup;
        }
    }

    if (!verify_cycle(slots, ARRAY_LEN(slots), "initial", failure, sizeof(failure))) {
        FAIL(failure);
        goto cleanup;
    }

    for (iteration = 1; iteration <= 5; iteration++) {
        for (slot_index = 0; slot_index < ARRAY_LEN(k_slot_plans); slot_index++) {
            const stress_slot_plan_t *plan = &k_slot_plans[slot_index];
            const stress_profile_t *profile =
                plan->variants[(size_t)iteration % plan->variant_count];
            const char *target_name = plan->stable_name;

            if (plan->replace_name_each_iteration) {
                snprintf(name, sizeof(name), "%s%d", plan->replace_prefix, iteration);
                target_name = name;
            }

            if (!stress_slot_configure(&slots[slot_index], target_name, profile)) {
                snprintf(failure, sizeof(failure), "iteration %d setup failed for %s", iteration, target_name);
                FAIL(failure);
                goto cleanup;
            }
        }

        snprintf(phase, sizeof(phase), "iteration-%d", iteration);
        if (!verify_cycle(slots, ARRAY_LEN(slots), phase, failure, sizeof(failure))) {
            FAIL(failure);
            goto cleanup;
        }
    }

    PASS();

cleanup:
    for (slot_index = 0; slot_index < ARRAY_LEN(slots); slot_index++) {
        stress_slot_cleanup(&slots[slot_index]);
    }
}

int main(void) {
    printf("BGP RIB-OUT Pipeline Stress Tests\n");
    printf("=================================\n\n");

    test_ribout_pipeline_stress_reconfiguration();

    printf("\nTests run: %d\n", tests_run);
    printf("Passed: %d\n", tests_passed);
    printf("Failed: %d\n", tests_failed);

    return tests_failed == 0 ? 0 : 1;
}
