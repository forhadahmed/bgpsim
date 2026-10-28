/*
 * Published ribout snapshots: lifetime under regeneration, removal and moves, the frozen configuration, and the wire
 * profile that a peer's negotiated session must accept.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include "bgp.h"
#include "test_case.h"
#include "bgp_ribout.h"
#include "bgp_ribout_snapshot.h"

/*
 * Apply "keyword value" lines to a fresh block; NULL ends the list.
 */
static int configure(bgp_ribout_config_t *block, const char *name, const char *const *lines) {
    if (bgp_ribout_init(block, name) != 0) {
        return -1;
    }
    for (; *lines; lines++) {
        char        keyword[32];
        const char *value = strchr(*lines, ' ');

        if (!value || (size_t)(value - *lines) >= sizeof(keyword)) {
            return -1;
        }
        snprintf(keyword, sizeof(keyword), "%.*s", (int)(value - *lines), *lines);
        if (bgp_ribout_edit(block, keyword, value + 1, 0) != 0) {
            return -1;
        }
    }
    return 0;
}

static const char *const k_ipv4[] = {"prefix 10.0.0.0/24 x 4", "next-hop 192.0.2.1", "as-path 65001", NULL};

static int copy_messages(const bgp_msg_t *msg, uint8_t *buf, size_t cap, size_t *len) {
    *len = 0;
    for (; msg; msg = msg->next) {
        if (*len + msg->length > cap) {
            return -1;
        }
        memcpy(buf + *len, msg->data, msg->length);
        *len += msg->length;
    }
    return 0;
}

static void test_reference_survives_regeneration(void) {
    bgp_ribout_config_t    block;
    bgp_ribout_snapshot_t *old;
    uint8_t before[8192], after[8192];
    size_t before_len, after_len;

    TEST("A held snapshot keeps its bytes and id across regeneration");
    ASSERT(configure(&block, "regen", k_ipv4) == 0, "configure");
    ASSERT(bgp_ribout_generate(&block) == BGP_RIBOUT_GENERATED, "first generation");
    old = bgp_ribout_snapshot_ref(block.snapshot);
    ASSERT(old->refs == 2 && old->adv->msgs == block.messages, "block and holder share the first snapshot");
    ASSERT(copy_messages(old->adv->msgs, before, sizeof(before), &before_len) == 0, "copy first bytes");

    ASSERT(bgp_ribout_edit(&block, "localpref", "300", 0) == 0, "edit");
    ASSERT(block.dirty == 1 && block.snapshot == old, "an edit keeps the snapshot and marks the block stale");
    ASSERT(bgp_ribout_generate(&block) == BGP_RIBOUT_GENERATED, "second generation");
    ASSERT(block.snapshot != old && block.snapshot->id > old->id, "regeneration publishes a newer snapshot");
    ASSERT(block.messages == block.snapshot->adv->msgs, "the block views the new snapshot");
    ASSERT(old->refs == 1, "the block dropped its reference to the old snapshot");
    ASSERT(copy_messages(old->adv->msgs, after, sizeof(after), &after_len) == 0, "copy old bytes again");
    ASSERT(before_len == after_len && memcmp(before, after, before_len) == 0, "old bytes unchanged");

    bgp_ribout_snapshot_unref(old);
    bgp_ribout_destroy(&block);
    PASS();
}

static void test_reference_survives_destroy(void) {
    bgp_ribout_config_t    block;
    bgp_ribout_snapshot_t *held;
    size_t                 count;
    uint64_t               bytes;

    TEST("A held snapshot outlives `no ribout`");
    ASSERT(configure(&block, "gone", k_ipv4) == 0, "configure");
    ASSERT(bgp_ribout_generate(&block) == BGP_RIBOUT_GENERATED, "generation");
    held = bgp_ribout_snapshot_ref(block.snapshot);
    count = block.message_count;
    bytes = held->adv->bytes;
    bgp_ribout_destroy(&block);
    ASSERT(held->refs == 1, "only the holder is left");
    ASSERT(held->adv->count == count && held->adv->bytes == bytes, "messages still there");
    ASSERT(strcmp(held->name, "gone") == 0 && strcmp(held->config->name, "gone") == 0, "names kept");
    bgp_ribout_snapshot_unref(held);
    PASS();
}

static void test_frozen_configuration(void) {
    static const char *const fs[] = {"address-family ipv4 flowspec", "prefix 10.0.0.0/24 x 2", "protocol 6",
                                     "as-path 65001", NULL};
    bgp_ribout_config_t          block;
    const bgp_ribout_snapshot_t *snapshot;

    TEST("A snapshot freezes the configuration it was built from");
    ASSERT(configure(&block, "frozen", fs) == 0, "configure");
    ASSERT(bgp_ribout_generate(&block) == BGP_RIBOUT_GENERATED, "generation");
    snapshot = block.snapshot;
    ASSERT(snapshot->config && snapshot->config->flowspec && snapshot->config->flowspec != block.flowspec,
           "FlowSpec part is a private copy");
    ASSERT(snapshot->config->ribout == NULL && snapshot->config->snapshot == NULL &&
           snapshot->config->messages == NULL, "the copy has no generated products");

    ASSERT(bgp_ribout_edit(&block, "prefix", "10.9.0.0/24 x 7", 0) == 0, "edit prefix");
    ASSERT(bgp_ribout_edit(&block, "protocol", "17", 0) == 0, "edit component");
    ASSERT(snapshot->config->prefix_spec.count == 2, "prefix count frozen");
    ASSERT(snapshot->config->flowspec->components[FLOWSPEC_IP_PROTOCOL].alternatives[0].values[0].value == 6,
           "FlowSpec component frozen");
    bgp_ribout_destroy(&block);
    PASS();
}

static void test_move_keeps_snapshot(void) {
    bgp_ribout_config_t    blocks[2];
    bgp_ribout_snapshot_t *snapshot;

    TEST("Moving a block (no ribout of an earlier block) keeps its snapshot");
    ASSERT(configure(&blocks[1], "moved", k_ipv4) == 0, "configure");
    ASSERT(bgp_ribout_generate(&blocks[1]) == BGP_RIBOUT_GENERATED, "generation");
    snapshot = blocks[1].snapshot;
    bgp_ribout_move(&blocks[0], &blocks[1]);
    ASSERT(blocks[0].snapshot == snapshot && snapshot->refs == 1, "snapshot moved with its reference");
    ASSERT(blocks[0].messages == snapshot->adv->msgs, "message view moved");
    ASSERT(blocks[1].snapshot == NULL && blocks[1].messages == NULL, "source cleared");
    bgp_ribout_destroy(&blocks[1]);
    bgp_ribout_destroy(&blocks[0]);
    PASS();
}

typedef struct {
    const char       *name;
    const char *const lines[10];
    uint16_t          afi;
    uint8_t           safi;
    uint8_t           add_path;
    uint8_t           classic;
    uint8_t           next_hop_af;
    uint8_t           needs_ext_nh;
} profile_case_t;

#define SR_COMMON "segment-list 1 weight 10 mpls 16001", "rt 192.0.2.1:100", "as-path 65001"

static const profile_case_t k_profiles[] = {
    {
        .name = "ipv4",
        .lines = {
            "prefix 10.0.0.0/24",
            "next-hop 192.0.2.1",
            NULL,
        },
        .afi = AFI_IPV4,
        .safi = SAFI_UNICAST,
        .add_path = 0,
        .classic = 1,
        .next_hop_af = AF_INET,
        .needs_ext_nh = 0,
    },
    {
        .name = "ipv4-pathid",
        .lines = {
            "prefix 10.0.0.0/24",
            "path-id 1 2",
            "next-hop 192.0.2.1",
            NULL,
        },
        .afi = AFI_IPV4,
        .safi = SAFI_UNICAST,
        .add_path = 1,
        .classic = 1,
        .next_hop_af = AF_INET,
        .needs_ext_nh = 0,
    },
    {
        .name = "ipv4-v6nh",
        .lines = {
            "prefix 10.0.0.0/24",
            "next-hop 2001:db8::1",
            NULL,
        },
        .afi = AFI_IPV4,
        .safi = SAFI_UNICAST,
        .add_path = 0,
        .classic = 0,
        .next_hop_af = AF_INET6,
        .needs_ext_nh = 1,
    },
    {
        .name = "ipv4-default-nh",
        .lines = {
            "prefix 10.0.0.0/24",
            NULL,
        },
        .afi = AFI_IPV4,
        .safi = SAFI_UNICAST,
        .add_path = 0,
        .classic = 1,
        .next_hop_af = AF_INET,
        .needs_ext_nh = 0,
    },
    {
        .name = "ipv6",
        .lines = {
            "prefix 2001:db8::/64",
            "next-hop 2001:db8::1",
            NULL,
        },
        .afi = AFI_IPV6,
        .safi = SAFI_UNICAST,
        .add_path = 0,
        .classic = 0,
        .next_hop_af = AF_INET6,
        .needs_ext_nh = 0,
    },
    {
        .name = "lu4",
        .lines = {
            "prefix 10.0.0.0/24",
            "label 100",
            "next-hop 192.0.2.1",
            NULL,
        },
        .afi = AFI_IPV4,
        .safi = SAFI_LABELED_UNICAST,
        .add_path = 0,
        .classic = 0,
        .next_hop_af = AF_INET,
        .needs_ext_nh = 0,
    },
    {
        .name = "lu4-v6nh",
        .lines = {
            "prefix 10.0.0.0/24",
            "label 100",
            "next-hop 2001:db8::1",
            NULL,
        },
        .afi = AFI_IPV4,
        .safi = SAFI_LABELED_UNICAST,
        .add_path = 0,
        .classic = 0,
        .next_hop_af = AF_INET6,
        .needs_ext_nh = 1,
    },
    {
        .name = "lu6",
        .lines = {
            "prefix 2001:db8::/64",
            "label 100",
            "next-hop 2001:db8::1",
            NULL,
        },
        .afi = AFI_IPV6,
        .safi = SAFI_LABELED_UNICAST,
        .add_path = 0,
        .classic = 0,
        .next_hop_af = AF_INET6,
        .needs_ext_nh = 0,
    },
    {
        .name = "vpn4",
        .lines = {
            "prefix 10.0.0.0/24",
            "rd 65000:1",
            "label 100",
            "next-hop 192.0.2.1",
            NULL,
        },
        .afi = AFI_IPV4,
        .safi = SAFI_MPLS_VPN,
        .add_path = 0,
        .classic = 0,
        .next_hop_af = AF_INET,
        .needs_ext_nh = 0,
    },
    {
        .name = "vpn4-v6nh",
        .lines = {
            "prefix 10.0.0.0/24",
            "rd 65000:1",
            "label 100",
            "next-hop 2001:db8::1",
            NULL,
        },
        .afi = AFI_IPV4,
        .safi = SAFI_MPLS_VPN,
        .add_path = 0,
        .classic = 0,
        .next_hop_af = AF_INET6,
        .needs_ext_nh = 1,
    },
    {
        .name = "vpn6-v4nh",
        .lines = {
            "prefix 2001:db8::/64",
            "rd 65000:1",
            "label 100",
            "next-hop 192.0.2.1",
            NULL,
        },
        .afi = AFI_IPV6,
        .safi = SAFI_MPLS_VPN,
        .add_path = 0,
        .classic = 0,
        .next_hop_af = AF_INET,
        .needs_ext_nh = 0,
    },
    {
        .name = "evpn5-v4",
        .lines = {
            "prefix 10.0.0.0/24",
            "rd 65000:1",
            "label 100",
            "ethernet-tag 0",
            "next-hop 192.0.2.1",
            NULL,
        },
        .afi = AFI_L2VPN,
        .safi = SAFI_EVPN,
        .add_path = 0,
        .classic = 0,
        .next_hop_af = AF_INET,
        .needs_ext_nh = 0,
    },
    {
        .name = "evpn5-v6",
        .lines = {
            "prefix 2001:db8::/64",
            "rd 65000:1",
            "label 100",
            "ethernet-tag 0",
            "next-hop 192.0.2.1",
            NULL,
        },
        .afi = AFI_L2VPN,
        .safi = SAFI_EVPN,
        .add_path = 0,
        .classic = 0,
        .next_hop_af = AF_INET,
        .needs_ext_nh = 0,
    },
    {
        .name = "evpn2",
        .lines = {
            "rd 65000:1",
            "mac 00:11:22:33:44:00 x 2",
            "label 100",
            NULL,
        },
        .afi = AFI_L2VPN,
        .safi = SAFI_EVPN,
        .add_path = 0,
        .classic = 0,
        .next_hop_af = AF_INET,
        .needs_ext_nh = 0,
    },
    {
        .name = "sr4",
        .lines = {
            "distinguisher 1",
            "color 100",
            "endpoint 10.0.0.1",
            SR_COMMON,
            NULL,
        },
        .afi = AFI_IPV4,
        .safi = SAFI_SR_POLICY,
        .add_path = 0,
        .classic = 0,
        .next_hop_af = AF_INET,
        .needs_ext_nh = 0,
    },
    {
        .name = "sr6-pathid",
        .lines = {
            "distinguisher 1",
            "color 100",
            "endpoint 2001:db8::1",
            "path-id 7",
            SR_COMMON,
            NULL,
        },
        .afi = AFI_IPV6,
        .safi = SAFI_SR_POLICY,
        .add_path = 1,
        .classic = 0,
        .next_hop_af = AF_INET,
        .needs_ext_nh = 0,
    },
    {
        .name = "fs4",
        .lines = {
            "address-family ipv4 flowspec",
            "prefix 10.0.0.0/24",
            "protocol 6",
            NULL,
        },
        .afi = AFI_IPV4,
        .safi = SAFI_FLOWSPEC,
        .add_path = 0,
        .classic = 0,
        .next_hop_af = 0,
        .needs_ext_nh = 0,
    },
    {
        .name = "fs6",
        .lines = {
            "address-family ipv6 flowspec",
            "prefix 2001:db8::/64",
            "protocol 6",
            NULL,
        },
        .afi = AFI_IPV6,
        .safi = SAFI_FLOWSPEC,
        .add_path = 0,
        .classic = 0,
        .next_hop_af = 0,
        .needs_ext_nh = 0,
    },
    {
        .name = "fsvpn4-nh",
        .lines = {
            "address-family ipv4 flowspec-vpn",
            "prefix 10.0.0.0/24",
            "rd 65000:1",
            "protocol 6",
            "next-hop 2001:db8::9",
            "action redirect-next-hop",
            NULL,
        },
        .afi = AFI_IPV4,
        .safi = SAFI_FLOWSPEC_VPN,
        .add_path = 0,
        .classic = 0,
        .next_hop_af = AF_INET6,
        .needs_ext_nh = 0,
    },
    {
        .name = "fsvpn6",
        .lines = {
            "address-family ipv6 flowspec-vpn",
            "prefix 2001:db8::/64",
            "rd 65000:1",
            "protocol 6",
            NULL,
        },
        .afi = AFI_IPV6,
        .safi = SAFI_FLOWSPEC_VPN,
        .add_path = 0,
        .classic = 0,
        .next_hop_af = 0,
        .needs_ext_nh = 0,
    },
};

static void test_profiles(void) {
    char failure[160];

    TEST("Snapshot wire profiles for every ribout family");
    for (size_t i = 0; i < sizeof(k_profiles) / sizeof(k_profiles[0]); i++) {
        const profile_case_t   *pc = &k_profiles[i];
        bgp_ribout_config_t     block;
        const bgp_tx_profile_t *p;

        snprintf(failure, sizeof(failure), "%s: configure/generate", pc->name);
        ASSERT(configure(&block, pc->name, pc->lines) == 0, failure);
        ASSERT(bgp_ribout_generate(&block) == BGP_RIBOUT_GENERATED, failure);
        p = &block.snapshot->profile;
        snprintf(failure, sizeof(failure),
                 "%s: afi %u safi %u add-path %u classic %u nh %u ext-nh %u", pc->name,
                 p->afi, p->safi, p->add_path, p->classic, p->next_hop_af, p->needs_ext_nh);
        ASSERT(p->afi == pc->afi && p->safi == pc->safi && p->add_path == pc->add_path &&
               p->classic == pc->classic && p->next_hop_af == pc->next_hop_af &&
               p->needs_ext_nh == pc->needs_ext_nh, failure);
        ASSERT(p->family == (uint8_t)bgp_ribout_resolve_family(&block), failure);
        bgp_ribout_destroy(&block);
    }
    PASS();
}

static void test_profile_text(void) {
    bgp_tx_profile_t profile = {.afi = AFI_IPV4, .safi = SAFI_LABELED_UNICAST,
                                .family = BGP_RIBOUT_FAMILY_LABELED_IPV4, .add_path = 1, .next_hop_af = AF_INET6,
                                .needs_ext_nh = 1};
    char text[96];

    TEST("Profile text for show ribout");
    bgp_tx_profile_to_string(&profile, text, sizeof(text));
    ASSERT(strcmp(text, "ipv4-labeled-unicast, add-path on, MP, ext-nh") == 0, text);
    PASS();
}

/*
 * ip rotate makes the keys of a Type 2 ribout MAC/IP pairs instead of every MAC with every IP: a different key set,
 * which must not compare equal to the cross product (or a regeneration would not withdraw the keys that went away),
 * while the two still overlap.
 */
static void test_type2_ip_rotate_keys(void) {
    static const char *const k_cross[] = {"rd 65551:7", "mac 02:00:00:00:00:01 x 4", "ip 10.0.0.1 x 4", "label 100",
                                          "next-hop 192.0.2.1", "as-path 65001", NULL};
    static const char *const k_pairs[] = {"rd 65551:7", "mac 02:00:00:00:00:01 x 4", "ip rotate 10.0.0.1 x 4",
                                          "label 100", "next-hop 192.0.2.1", "as-path 65001", NULL};
    bgp_ribout_config_t cross, pairs, again;
    int generated;

    TEST("ip rotate: Type 2 MAC/IP pairs are a different key set from the cross product");
    generated = configure(&cross, "cross", k_cross) == 0 && configure(&pairs, "pairs", k_pairs) == 0 &&
                configure(&again, "again", k_pairs) == 0 && bgp_ribout_generate(&cross) == BGP_RIBOUT_GENERATED &&
                bgp_ribout_generate(&pairs) == BGP_RIBOUT_GENERATED &&
                bgp_ribout_generate(&again) == BGP_RIBOUT_GENERATED;
    ASSERT(generated, "the three blocks generate");
    ASSERT(bgp_ribout_total_paths(&cross) == 16 && bgp_ribout_total_paths(&pairs) == 4,
           "4 MACs x 4 IPs make 16 routes, 4 rotating IPs make 4");
    ASSERT(!bgp_ribout_snapshot_same_keys(cross.snapshot, pairs.snapshot) &&
               !bgp_ribout_snapshot_same_keys(pairs.snapshot, cross.snapshot),
           "the pairs are not the cross product's key set");
    ASSERT(bgp_ribout_snapshot_same_keys(pairs.snapshot, again.snapshot), "the same pairs are the same key set");
    ASSERT(bgp_ribout_snapshot_keys_overlap(cross.snapshot, pairs.snapshot), "the pairs overlap the cross product");
    bgp_ribout_destroy(&cross);
    bgp_ribout_destroy(&pairs);
    bgp_ribout_destroy(&again);
    PASS();
}

/*
 * True when the two line lists generate and their snapshots have the same keys (same) or any key in common.
 */
static int keys_compare(const char *const *a_lines, const char *const *b_lines, int *same, int *overlap) {
    bgp_ribout_config_t a, b;
    int generated = configure(&a, "a", a_lines) == 0 && configure(&b, "b", b_lines) == 0 &&
                    bgp_ribout_generate(&a) == BGP_RIBOUT_GENERATED && bgp_ribout_generate(&b) == BGP_RIBOUT_GENERATED;

    if (generated) {
        *same = bgp_ribout_snapshot_same_keys(a.snapshot, b.snapshot);
        *overlap = bgp_ribout_snapshot_keys_overlap(a.snapshot, b.snapshot);
    }
    bgp_ribout_destroy(&a);
    bgp_ribout_destroy(&b);
    return generated;
}

/*
 * rd rotate pairs each prefix with one RD: not the key set of the RD cross product, and position-dependent, so
 * rotate-every or another rotating RD list changes the keys. Dual-stack Type 2 keys differ from one family's.
 */
static void test_rotation_keys(void) {
    static const char *const k_rd_cross[] = {"prefix 10.0.0.0/24 x 8", "rd 65551:1 x 4", "label 16", "next-hop 192.0.2.1",
                                             "as-path 65001", NULL};
    static const char *const k_rd_rotate[] = {"prefix 10.0.0.0/24 x 8", "rd rotate 65551:1 x 4", "label 16",
                                              "next-hop 192.0.2.1", "as-path 65001", NULL};
    static const char *const k_rd_blocks[] = {"prefix 10.0.0.0/24 x 8", "rd rotate 65551:1 x 4", "label 16",
                                              "rotate-every 2", "next-hop 192.0.2.1", "as-path 65001", NULL};
    static const char *const k_v4[] = {"rd 65551:6", "mac 02:00:00:00:00:01 x 4", "ip rotate 10.0.0.1 x 4", "label 1",
                                       "next-hop 192.0.2.1", "as-path 65001", NULL};
    static const char *const k_dual[] = {"rd 65551:6", "mac 02:00:00:00:00:01 x 4", "ip rotate 10.0.0.1 x 4",
                                         "ip rotate 2001:db8::1 x 4", "label 1", "next-hop 192.0.2.1", "as-path 65001",
                                         NULL};
    static const char *const k_v6[] = {"rd 65551:6", "mac 02:00:00:00:00:01 x 4", "ip rotate 2001:db8::1 x 4", "label 1",
                                       "next-hop 192.0.2.1", "as-path 65001", NULL};
    int same = -1, overlap = -1;

    TEST("rd rotate and dual-stack Type 2: key equality and overlap");
    ASSERT(keys_compare(k_rd_cross, k_rd_rotate, &same, &overlap) && !same && overlap,
           "Rotating RDs are a subset of the RD cross product: overlapping, not equal");
    ASSERT(keys_compare(k_rd_rotate, k_rd_rotate, &same, &overlap) && same && overlap, "The same rd rotate keys");
    ASSERT(keys_compare(k_rd_rotate, k_rd_blocks, &same, &overlap) && !same && overlap,
           "rotate-every pairs the RDs with other prefixes: different keys");
    ASSERT(keys_compare(k_v4, k_dual, &same, &overlap) && !same && overlap,
           "Dual-stack bindings add IPv6 keys to the IPv4 ones: overlapping, not equal");
    ASSERT(keys_compare(k_v4, k_v6, &same, &overlap) && !same && !overlap,
           "IPv4 and IPv6 bindings of the same MACs never overlap");
    ASSERT(keys_compare(k_v6, k_dual, &same, &overlap) && !same && overlap, "The IPv6 half overlaps too");
    PASS();
}

int main(void) {
    test_reference_survives_regeneration();
    test_reference_survives_destroy();
    test_frozen_configuration();
    test_move_keeps_snapshot();
    test_profiles();
    test_profile_text();
    test_type2_ip_rotate_keys();
    test_rotation_keys();
    printf("\nTests run: %d, passed: %d, failed: %d\n", tests_run, tests_passed, tests_failed);
    return tests_failed == 0 ? 0 : 1;
}
