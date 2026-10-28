/*
 * BGP RIB-OUT Constraint Tests
 * Covers invalid input rejection, limits, and boundary behavior.
 */

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "bgp.h"
#include "bgpsim.h"
#include "test_case.h"
#include "bgp_router.h"
#include "test_result.h"
#include "bgp_neighbor.h"
#include "test_helpers.h"
#include "bgp_ribout_config.h"
#include "bgp_ribout_snapshot.h"

// Invalid IP Address Tests

void test_invalid_ipv4_prefix_out_of_range() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test");

    int result = bgp_ribout_parse_prefix(&block, "prefix 999.999.999.999/24");
    test_result(result < 0, "Reject IPv4 prefix with out-of-range octets");
    bgp_ribout_destroy(&block);
}

void test_invalid_ipv4_prefix_incomplete() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test");

    int result = bgp_ribout_parse_prefix(&block, "prefix 10.0.0/24");
    test_result(result < 0, "Reject incomplete IPv4 prefix");
    bgp_ribout_destroy(&block);
}

void test_invalid_ipv4_prefix_length() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test");

    int result = bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/33");
    test_result(result < 0, "Reject IPv4 prefix length > 32");
    bgp_ribout_destroy(&block);
}

void test_invalid_ipv6_prefix_bad_hex() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test");

    int result = bgp_ribout_parse_prefix(&block, "prefix gggg::/64");
    test_result(result < 0, "Reject IPv6 prefix with invalid hex");
    bgp_ribout_destroy(&block);
}

void test_invalid_ipv6_prefix_length() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test");

    int result = bgp_ribout_parse_prefix(&block, "prefix 2001:db8::/129");
    test_result(result < 0, "Reject IPv6 prefix length > 128");
    bgp_ribout_destroy(&block);
}

void test_invalid_next_hop_out_of_range() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test");
    bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/24");

    int result = bgp_ribout_parse_next_hop(&block, "next-hop 256.256.256.256");
    test_result(result < 0, "Reject next_hop with out-of-range octets");
    bgp_ribout_destroy(&block);
}

void test_invalid_next_hop_extra_octets() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test");
    bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/24");

    int result = bgp_ribout_parse_next_hop(&block, "next-hop 10.0.0.0.1");
    test_result(result < 0, "Reject next_hop with extra octets");
    bgp_ribout_destroy(&block);
}

// Out of Range Values Tests

void test_invalid_aspath_negative() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test");

    int result = bgp_ribout_parse_aspath(&block, "as-path -100");
    test_result(result < 0, "Reject negative AS number");
    bgp_ribout_destroy(&block);
}

/*
 * Return 1 when "as-path 65001 [rand(64512) x count]" parses.
 */
static int aspath_random_count_accepted(int count) {
    bgp_ribout_config_t block;
    char                line[64];
    int                 accepted;

    bgp_ribout_init(&block, "aspath-random");
    snprintf(line, sizeof(line), "as-path 65001 [rand(64512) x %d]", count);
    accepted = bgp_ribout_parse_aspath(&block, line) == 0;
    bgp_ribout_destroy(&block);
    return accepted;
}

void test_aspath_random_count_at_segment_limit() {
    TEST("Accept a random AS-path segment of MAX_AS_VALUES_PER_SEGMENT ASNs");

    ASSERT(aspath_random_count_accepted(MAX_AS_VALUES_PER_SEGMENT),
           "A random segment of MAX_AS_VALUES_PER_SEGMENT ASNs is valid");
    PASS();
}

/*
 * A random AS-path segment holds at most MAX_AS_VALUES_PER_SEGMENT ASNs, like a SEQUENCE or SET: the generator writes
 * them into an array of that size. A larger repetition count must be rejected when the line is parsed.
 */
void test_invalid_aspath_random_count_over_segment_limit() {
    TEST("Reject a random AS-path segment longer than MAX_AS_VALUES_PER_SEGMENT");

    ASSERT(!aspath_random_count_accepted(MAX_AS_VALUES_PER_SEGMENT + 1),
           "A random segment holds at most MAX_AS_VALUES_PER_SEGMENT ASNs");
    PASS();
}

void test_invalid_localpref_negative() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test");

    int result = bgp_ribout_parse_localpref(&block, "localpref -50");
    test_result(result < 0, "Reject negative localpref");
    bgp_ribout_destroy(&block);
}

void test_invalid_path_id_negative() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test");

    int result = bgp_ribout_parse_path_ids(&block, "path-id -1");
    test_result(result < 0, "Reject negative path-id");
    bgp_ribout_destroy(&block);
}

void test_invalid_label_negative() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test");

    int result = bgp_ribout_parse_label(&block, "label -1");
    test_result(result < 0, "Reject negative MPLS label");
    bgp_ribout_destroy(&block);
}

void test_invalid_label_too_large() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test");

    // 21-24 bits parse (an EVPN VNI); generation decides whether the label is a VNI or an MPLS label.
    int result = bgp_ribout_parse_label(&block, "label 16777216");
    test_result(result < 0, "Reject label outside 24-bit range");
    bgp_ribout_destroy(&block);
}

void test_invalid_mac_integer_too_large() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test");

    int result = bgp_ribout_parse_mac(&block, "mac 281474976710656");
    test_result(result < 0, "Reject MAC decimal shorthand above 48-bit space");
    bgp_ribout_destroy(&block);
}

void test_invalid_router_mac_integer_multicast() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test");

    int result = bgp_ribout_parse_router_mac(&block, "router-mac 1099511627776");
    test_result(result < 0, "Reject router-mac decimal shorthand that expands to multicast MAC");
    bgp_ribout_destroy(&block);
}

void test_too_many_path_ids() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test");

    char cmd[2048] = "path-id";
    for (int i = 0; i < 101; i++) {
        char buf[32];
        snprintf(buf, sizeof(buf), " %d", i);
        strcat(cmd, buf);
    }

    int result = bgp_ribout_parse_path_ids(&block, cmd);
    test_result(result == 0 && block.path_id_count == 101 && bgp_ribout_path_ids_at(&block, 100) == 100,
                "Explicit path IDs grow past the old inventory limit without truncation");
    bgp_ribout_destroy(&block);
}

void test_too_many_labels() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test");

    char cmd[2048] = "label";
    for (int i = 0; i < 101; i++) {
        char buf[32];
        snprintf(buf, sizeof(buf), " %d", i);
        strcat(cmd, buf);
    }

    int result = bgp_ribout_parse_label(&block, cmd);
    test_result(result == 0 && block.label_count == 101 && bgp_ribout_labels_at(&block, 100) == 100,
                "Explicit labels grow past the old inventory limit without truncation");
    bgp_ribout_destroy(&block);
}

// Malformed Syntax Tests

void test_malformed_aspath_missing_closing_brace() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test");

    int result = bgp_ribout_parse_aspath(&block, "as-path { 100 200");
    test_result(result < 0, "Reject AS-path with missing closing brace");
    bgp_ribout_destroy(&block);
}

void test_malformed_aspath_empty_set() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test");

    int result = bgp_ribout_parse_aspath(&block, "as-path { }");
    test_result(result < 0, "Reject AS-path with empty set");
    bgp_ribout_destroy(&block);
}

void test_malformed_aspath_random_missing_count() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test");

    int result = bgp_ribout_parse_aspath(&block, "as-path [rand(100)]");
    test_result(result < 0, "Reject random AS-path without x count");
    bgp_ribout_destroy(&block);
}

void test_malformed_prefix_missing_count() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test");

    int result = bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/24 x");
    test_result(result < 0, "Reject prefix with 'x' but no count");
    bgp_ribout_destroy(&block);
}

void test_malformed_prefix_wrong_order() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test");

    int result = bgp_ribout_parse_prefix(&block, "prefix x 10 10.0.0.0/24");
    test_result(result < 0, "Reject prefix with wrong argument order");
    bgp_ribout_destroy(&block);
}

void test_malformed_label_missing_count() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test");

    int result = bgp_ribout_parse_label(&block, "label 16000 x");
    test_result(result < 0, "Reject label sequence with missing count");
    bgp_ribout_destroy(&block);
}

void test_invalid_origin_value() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test");

    int result = bgp_ribout_parse_origin(&block, "origin z");
    test_result(result < 0, "Reject invalid origin value");
    bgp_ribout_destroy(&block);
}

void test_invalid_esi_compact_hex_length() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test");

    int result = bgp_ribout_parse_esi(&block, "esi 001122334455667788a");
    test_result(result < 0, "Reject compact-hex ESI with wrong length");
    bgp_ribout_destroy(&block);
}

void test_invalid_esi_sequence_zero_count() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test");

    int result = bgp_ribout_parse_esi(&block, "esi 0 x 0");
    test_result(result < 0, "Reject ESI shorthand sequence with zero count");
    bgp_ribout_destroy(&block);
}

// Address Family Mismatch Tests

void test_ipv4_prefix_ipv6_next_hop() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test");

    bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/24");
    int result = bgp_ribout_parse_next_hop(&block, "next-hop 2001:db8::1");

    test_result(result == 0, "Allow IPv6 next_hop with IPv4 prefix (RFC 8950)");
    bgp_ribout_destroy(&block);
}

void test_ipv6_next_hop_with_link_local() {
    bgp_ribout_config_t block;
    struct in6_addr     expected_link_local;
    bgp_ribout_init(&block, "test");

    bgp_ribout_parse_prefix(&block, "prefix 2001:db8::/32");
    int result = bgp_ribout_parse_next_hop(&block, "next-hop 2001:db8::1 link-local fe80::1");
    inet_pton(AF_INET6, "fe80::1", &expected_link_local);

    test_result(result == 0 &&
                block.next_hop_spec.af == AF_INET6 &&
                block.next_hop_spec.has_link_local &&
                memcmp(&block.next_hop_spec.link_local, &expected_link_local, sizeof(expected_link_local)) == 0,
                "Allow IPv6 next_hop with IPv6 link-local companion");
    bgp_ribout_destroy(&block);
}

void test_ipv4_next_hop_with_link_local() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test");

    bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/24");
    int result = bgp_ribout_parse_next_hop(&block, "next-hop 192.0.2.1 link-local fe80::1");

    test_result(result < 0, "Reject link-local companion on IPv4 next_hop");
    bgp_ribout_destroy(&block);
}

void test_non_link_local_next_hop_companion() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test");

    bgp_ribout_parse_prefix(&block, "prefix 2001:db8::/32");
    int result = bgp_ribout_parse_next_hop(&block, "next-hop 2001:db8::1 link-local 2001:db8::2");

    test_result(result < 0, "Reject non-link-local IPv6 companion under link-local keyword");
    bgp_ribout_destroy(&block);
}

void test_ipv6_prefix_ipv4_next_hop() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test");

    bgp_ribout_parse_prefix(&block, "prefix 2001:db8::/32");
    int result = bgp_ribout_parse_next_hop(&block, "next-hop 192.168.1.1");

    test_result(result < 0, "Reject IPv4 next_hop with IPv6 prefix");
    bgp_ribout_destroy(&block);
}

void test_ipv4_prefix_ipv6_next_hop_reverse_order() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test");

    bgp_ribout_parse_next_hop(&block, "next-hop 2001:db8::1");
    int result = bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/24");

    test_result(result == 0, "Allow IPv6 next_hop with IPv4 prefix regardless of config order");
    bgp_ribout_destroy(&block);
}

void test_ipv6_prefix_ipv4_next_hop_reverse_order() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test");

    bgp_ribout_parse_next_hop(&block, "next-hop 192.168.1.1");
    int result = bgp_ribout_parse_prefix(&block, "prefix 2001:db8::/32");

    test_result(result < 0, "Reject IPv4 next_hop with IPv6 prefix regardless of config order");
    bgp_ribout_destroy(&block);
}

void test_vpnv6_prefix_ipv4_next_hop() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test");

    bgp_ribout_parse_prefix(&block, "prefix 2001:db8::/64");
    bgp_ribout_parse_rd(&block, "rd 65000:100");
    bgp_ribout_parse_label(&block, "label 24000");
    int result = bgp_ribout_parse_next_hop(&block, "next-hop 192.0.2.33");

    test_result(result == 0, "Allow IPv4 next-hop with VPNv6 ribout");
    bgp_ribout_destroy(&block);
}

void test_gateway_ip_family_mismatch() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test");

    bgp_ribout_parse_prefix(&block, "prefix 2001:db8::/64");
    int result = bgp_ribout_parse_gateway_ip(&block, "gateway-ip 10.255.0.1");

    test_result(result < 0, "Reject gateway-ip address family mismatch");
    bgp_ribout_destroy(&block);
}

// VPN / EVPN Token Validation Tests

void test_rt_and_rt_set_mutually_exclusive() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test");

    int result1 = bgp_ribout_parse_rt(&block, "rt 65000:100");
    int result2 = bgp_ribout_parse_rt_set(&block, "rt-set [65000:200]");

    test_result(result1 == 0 && result2 < 0, "Reject rt-set when fixed rt values are already configured");
    bgp_ribout_destroy(&block);
}

void test_rt_set_and_rt_mutually_exclusive() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test");

    int result1 = bgp_ribout_parse_rt_set(&block, "rt-set [65000:100]");
    int result2 = bgp_ribout_parse_rt(&block, "rt 65000:200");

    test_result(result1 == 0 && result2 < 0, "Reject fixed rt values when rt-set is already configured");
    bgp_ribout_destroy(&block);
}

void test_rt_set_parsing() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test");

    int result = bgp_ribout_parse_rt_set(&block, "rt-set [65000:100] [65000:200,65000:201]");

    test_result(result == 0 &&
                block.rt_set_count == 2 &&
                block.rt_sets[0].count == 1 &&
                block.rt_sets[1].count == 2,
                "Parse rotating route-target sets");
    bgp_ribout_destroy(&block);
}

void test_med_random_parsing() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test");

    int result = bgp_ribout_parse_med(&block, "med rand(25)");

    test_result(result == 0 &&
                block.med_spec.enabled == 1 &&
                block.med_spec.mode == BGP_U32_MODE_RANDOM &&
                block.med_spec.value == 25,
                "Parse random MED");
    bgp_ribout_destroy(&block);
}

void test_localpref_random_rejects_zero() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test");

    int result = bgp_ribout_parse_localpref(&block, "localpref rand(0)");

    test_result(result < 0, "Reject localpref rand(0)");
    bgp_ribout_destroy(&block);
}

void test_med_random_rejects_zero() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test");

    int result = bgp_ribout_parse_med(&block, "med rand(0)");

    test_result(result < 0, "Reject MED rand(0)");
    bgp_ribout_destroy(&block);
}

void test_aspath_random_rejects_zero() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test");

    int result = bgp_ribout_parse_aspath(&block, "as-path [rand(0) x 5]");

    test_result(result < 0, "Reject AS-path rand(0)");
    bgp_ribout_destroy(&block);
}

void test_srpolicy_preference_random_rejects_zero() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test");

    int result = bgp_ribout_parse_preference(&block, "preference rand(0)");

    test_result(result < 0, "Reject SR Policy preference rand(0)");
    bgp_ribout_destroy(&block);
}

void test_srpolicy_binding_sid_random_rejects_zero() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test");

    int result = bgp_ribout_parse_binding_sid(&block, "binding-sid mpls rand(0)");

    test_result(result < 0, "Reject SR Policy binding SID rand(0)");
    bgp_ribout_destroy(&block);
}

void test_localpref_range_rejects_reverse_bounds() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test");

    int result = bgp_ribout_parse_localpref(&block, "localpref range(300,200)");

    test_result(result < 0, "Reject localpref range() with start > end");
    bgp_ribout_destroy(&block);
}

void test_med_randrange_rejects_reverse_bounds() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test");

    int result = bgp_ribout_parse_med(&block, "med randrange(25,10)");

    test_result(result < 0, "Reject MED randrange() with start > end");
    bgp_ribout_destroy(&block);
}

void test_path_id_range_rejects_too_many_values() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test");

    int result = bgp_ribout_parse_path_ids(&block, "path-id range(0,4294967295)");

    test_result(result < 0, "Reject a range whose 2^32 values overflow the inventory count");
    bgp_ribout_destroy(&block);
}

void test_srpolicy_binding_sid_randrange_rejects_out_of_bounds() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test");

    int result = bgp_ribout_parse_binding_sid(&block, "binding-sid mpls randrange(16,1048576)");

    test_result(result < 0, "Reject SR Policy binding SID randrange() above 20-bit label space");
    bgp_ribout_destroy(&block);
}

static void setup_valid_srpolicy_block(bgp_ribout_config_t *block, const char *endpoint_line) {
    bgp_ribout_parse_distinguisher(block, "distinguisher 100 101");
    bgp_ribout_parse_color(block, "color 200 201");
    bgp_ribout_parse_endpoint(block, endpoint_line);
    bgp_ribout_parse_rt(block, "rt 192.0.2.10:100");
    bgp_ribout_parse_segment_list(block, "segment-list 1 weight 10 mpls 16010 16011");
}

static void setup_valid_evpn_type2_block(bgp_ribout_config_t *block, const char *ip_line) {
    bgp_ribout_parse_rd(block, "rd 65000:320");
    bgp_ribout_parse_ethernet_tag(block, "ethernet-tag 0 100");
    bgp_ribout_parse_mac(block, "mac 00:11:22:33:44:00 x 4");
    if (ip_line) {
        bgp_ribout_parse_ip(block, ip_line);
    }
    bgp_ribout_parse_label(block, "label 30000");
    bgp_ribout_parse_next_hop(block, "next-hop 192.0.2.10");
    bgp_ribout_parse_rt(block, "rt 65000:320");
}

void test_srpolicy_family_inference_ipv4() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "sr4");

    setup_valid_srpolicy_block(&block, "endpoint 10.0.0.1 x 4");

    test_result(bgp_ribout_resolve_family(&block) ==
                BGP_RIBOUT_FAMILY_SR_POLICY_IPV4,
                "Infer IPv4 SR Policy from endpoint token");
    bgp_ribout_destroy(&block);
}

void test_srpolicy_family_inference_ipv6() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "sr6");

    setup_valid_srpolicy_block(&block, "endpoint 2001:db8::1 x 4");

    test_result(bgp_ribout_resolve_family(&block) ==
                BGP_RIBOUT_FAMILY_SR_POLICY_IPV6,
                "Infer IPv6 SR Policy from endpoint token");
    bgp_ribout_destroy(&block);
}

void test_srpolicy_rejects_prefix_token_mix() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "sr-mixed");

    bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/24");
    bgp_ribout_parse_endpoint(&block, "endpoint 10.0.0.1");

    test_result(bgp_ribout_resolve_family(&block) == BGP_RIBOUT_FAMILY_NONE,
                "Reject mixed prefix and SR Policy token inference");
    bgp_ribout_destroy(&block);
}

void test_evpn_type2_family_inference_mac_only() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "evpn2-mac");

    setup_valid_evpn_type2_block(&block, NULL);

    test_result(bgp_ribout_resolve_family(&block) == BGP_RIBOUT_FAMILY_EVPN_TYPE2, "Infer EVPN Type 2 from MAC token");
    bgp_ribout_destroy(&block);
}

void test_evpn_type2_family_inference_ipv6_ip() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "evpn2-ipv6");

    setup_valid_evpn_type2_block(&block, "ip 2001:db8::1 x 2");

    test_result(bgp_ribout_resolve_family(&block) ==
                BGP_RIBOUT_FAMILY_EVPN_TYPE2,
                "Infer EVPN Type 2 when optional IPv6 IP binding is configured");
    bgp_ribout_destroy(&block);
}

void test_evpn_type2_rejects_prefix_token_mix() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "evpn2-mixed");

    bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/24");
    bgp_ribout_parse_mac(&block, "mac 00:11:22:33:44:00");
    bgp_ribout_parse_label(&block, "label 30000");
    bgp_ribout_parse_rd(&block, "rd 65000:320");

    test_result(bgp_ribout_resolve_family(&block) == BGP_RIBOUT_FAMILY_NONE,
                "Reject mixed prefix and EVPN Type 2 token inference");
    bgp_ribout_destroy(&block);
}

// Generator Initialization Failures

void test_generator_missing_prefix() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test");
    bgp_ribout_gen_t gen;

    // Set path-ids but no prefix
    bgp_ribout_parse_path_ids(&block, "path-id 0");

    int result = bgp_ribout_generator_init(&gen, &block);
    test_result(result < 0, "Reject generator init without prefix");
    bgp_ribout_destroy(&block);
}

void test_generator_missing_path_ids() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test");
    bgp_ribout_gen_t gen;

    // Set prefix but no path-ids
    bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/24");

    int result = bgp_ribout_generator_init(&gen, &block);
    test_result(result >= 0, "Generator works without path-ids (defaults to path-id 0)");
    bgp_ribout_destroy(&block);
}

void test_generator_label_sequence_multiplies_paths() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test");
    bgp_ribout_gen_t gen;

    bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/24 x 2");
    bgp_ribout_parse_label(&block, "label 16000 x 3");
    bgp_ribout_parse_path_ids(&block, "path-id 10 20");

    int result = bgp_ribout_generator_init(&gen, &block);
    test_result(result >= 0 && bgp_ribout_gen_total_paths(&gen) == 12,
                "Generator total paths includes labels and path-ids");
    bgp_ribout_destroy(&block);
}

void test_generator_zero_prefix_count() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test");
    bgp_ribout_gen_t gen;

    bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/24 x 0");
    bgp_ribout_parse_path_ids(&block, "path-id 0");

    int result = bgp_ribout_generator_init(&gen, &block);

    if (result >= 0) {
        // If init succeeds with zero count, verify total_paths is 0
        test_result(gen.total_paths == 0, "Generator with zero prefix count has zero total paths");
    } else {
        test_result(1, "Generator rejects zero prefix count");
    }
    bgp_ribout_destroy(&block);
}

void test_generator_vpn_requires_rd() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test");
    bgp_ribout_gen_t gen;

    bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/24");
    bgp_ribout_parse_label(&block, "label 16000");
    bgp_ribout_parse_rt(&block, "rt 65000:100");

    int result = bgp_ribout_generator_init(&gen, &block);
    test_result(result < 0, "Reject VPN/EVPN-specific tokens without RD");
    bgp_ribout_destroy(&block);
}

void test_generator_vpn_requires_label() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test");
    bgp_ribout_gen_t gen;

    bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/24");
    bgp_ribout_parse_rd(&block, "rd 65000:100");
    bgp_ribout_parse_rt(&block, "rt 65000:100");

    int result = bgp_ribout_generator_init(&gen, &block);
    test_result(result < 0, "Reject VPN ribout without label");
    bgp_ribout_destroy(&block);
}

void test_generator_evpn_dimensions_multiply_paths() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test");
    bgp_ribout_gen_t gen;

    bgp_ribout_parse_prefix(&block, "prefix 192.168.0.0/24 x 2");
    bgp_ribout_parse_rd(&block, "rd 65000:300");
    bgp_ribout_parse_label(&block, "label 30000");
    bgp_ribout_parse_ethernet_tag(&block, "ethernet-tag 0 100");
    bgp_ribout_parse_gateway_ip(&block, "gateway-ip 10.255.0.1 x 2");

    int result = bgp_ribout_generator_init(&gen, &block);
    test_result(result == 0 && bgp_ribout_gen_total_paths(&gen) == 8,
                "Generator total paths include EVPN Ethernet Tag and gateway IP dimensions");
    bgp_ribout_destroy(&block);
}

void test_generator_evpn_rejects_esi_and_gateway_ip() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test");
    bgp_ribout_gen_t gen;

    bgp_ribout_parse_prefix(&block, "prefix 192.168.0.0/24");
    bgp_ribout_parse_rd(&block, "rd 65000:300");
    bgp_ribout_parse_label(&block, "label 30000");
    bgp_ribout_parse_gateway_ip(&block, "gateway-ip 10.255.0.1");
    bgp_ribout_parse_esi(&block, "esi 00:00:00:00:00:00:00:00:00:01");

    int result = bgp_ribout_generator_init(&gen, &block);
    test_result(result < 0, "Reject EVPN type 5 ribout with both gateway IP and ESI configured");
    bgp_ribout_destroy(&block);
}

/*
 * Configure an EVPN Type 5 ribout with label 0 and this Overlay Index line (NULL for none). Returns 1 when the
 * generator rejects it, 0 when it accepts it, and -1 when the overlay line does not parse.
 */
static int evpn5_label_zero_rejected(const char *overlay_line) {
    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;
    bgp_gen_path_t      path;
    int                 result = 0;

    bgp_ribout_init(&block, "evpn5-label-zero");
    if (bgp_ribout_parse_prefix(&block, "prefix 192.168.0.0/24") != 0 ||
        bgp_ribout_parse_rd(&block, "rd 65000:300") != 0 ||
        bgp_ribout_parse_label(&block, "label 0") != 0 ||
        bgp_ribout_parse_ethernet_tag(&block, "ethernet-tag 0") != 0) {
        bgp_ribout_destroy(&block);
        return -1;
    }
    if (overlay_line != NULL) {
        if (strncmp(overlay_line, "esi", 3) == 0) {
            result = bgp_ribout_parse_esi(&block, overlay_line);
        } else if (strncmp(overlay_line, "gateway-ip", 10) == 0) {
            result = bgp_ribout_parse_gateway_ip(&block, overlay_line);
        } else {
            result = bgp_ribout_parse_router_mac(&block, overlay_line);
        }
    }
    result = result != 0 ? -1 : bgp_ribout_generator_init(&gen, &block) < 0;
    while (result == 0 && bgp_ribout_generator_has_next(&gen)) {
        result = bgp_ribout_generator_next(&gen, &path) < 0;
    }
    bgp_ribout_destroy(&block);
    return result;
}

/*
 * The Overlay Index is an ESI, a Gateway IP or the MAC of a Router's MAC Extended Community. Each form is a separate
 * case so rejection of one valid form cannot skip the others or the missing-index check.
 */
static void test_generator_evpn5_label_zero_with_overlay(const char *name, const char *overlay_line) {
    int result;

    TEST(name);
    result = evpn5_label_zero_rejected(overlay_line);
    ASSERT(result >= 0, "The EVPN Type 5 configuration parses");
    ASSERT(result == 0, "Label 0 with an Overlay Index is valid");
    PASS();
}

static void test_generator_evpn5_label_zero_rejects_zero_overlay(const char *name, const char *overlay_line) {
    int result;

    TEST(name);
    result = evpn5_label_zero_rejected(overlay_line);
    ASSERT(result >= 0, "The zero-valued Overlay Index configuration parses");
    ASSERT(result == 1, "A zero-valued Overlay Index cannot make a label-zero route valid");
    PASS();
}

/*
 * RFC 9136 section 3.1: "If the received label is zero and the route does not contain an Overlay Index, it MUST be
 * 'treat as withdraw'".
 */
void test_generator_evpn5_label_zero_requires_overlay_index() {
    int result;

    TEST("EVPN type 5 ribout with label 0 needs an Overlay Index");
    result = evpn5_label_zero_rejected(NULL);
    ASSERT(result >= 0, "The EVPN Type 5 configuration parses");
    ASSERT(result == 1, "RFC 9136 section 3.1: label 0 without an Overlay Index is treat-as-withdraw");
    PASS();
}

void test_generator_srpolicy_requires_distinguisher() {
    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;

    bgp_ribout_init(&block, "sr-missing-dist");
    bgp_ribout_parse_color(&block, "color 200");
    bgp_ribout_parse_endpoint(&block, "endpoint 10.0.0.1");
    bgp_ribout_parse_rt(&block, "rt 192.0.2.10:100");
    bgp_ribout_parse_segment_list(&block, "segment-list 1 weight 10 mpls 16010 16011");

    test_result(bgp_ribout_generator_init(&gen, &block) < 0, "Reject SR Policy ribout without distinguisher");
    bgp_ribout_destroy(&block);
}

void test_generator_srpolicy_requires_color() {
    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;

    bgp_ribout_init(&block, "sr-missing-color");
    bgp_ribout_parse_distinguisher(&block, "distinguisher 100");
    bgp_ribout_parse_endpoint(&block, "endpoint 10.0.0.1");
    bgp_ribout_parse_rt(&block, "rt 192.0.2.10:100");
    bgp_ribout_parse_segment_list(&block, "segment-list 1 weight 10 mpls 16010 16011");

    test_result(bgp_ribout_generator_init(&gen, &block) < 0, "Reject SR Policy ribout without color");
    bgp_ribout_destroy(&block);
}

void test_generator_srpolicy_requires_endpoint() {
    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;

    bgp_ribout_init(&block, "sr-missing-endpoint");
    bgp_ribout_parse_distinguisher(&block, "distinguisher 100");
    bgp_ribout_parse_color(&block, "color 200");
    bgp_ribout_parse_rt(&block, "rt 192.0.2.10:100");
    bgp_ribout_parse_segment_list(&block, "segment-list 1 weight 10 mpls 16010 16011");

    test_result(bgp_ribout_generator_init(&gen, &block) < 0, "Reject SR Policy ribout without endpoint");
    bgp_ribout_destroy(&block);
}

void test_generator_srpolicy_requires_segment_list() {
    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;

    bgp_ribout_init(&block, "sr-missing-sl");
    bgp_ribout_parse_distinguisher(&block, "distinguisher 100");
    bgp_ribout_parse_color(&block, "color 200");
    bgp_ribout_parse_endpoint(&block, "endpoint 10.0.0.1");
    bgp_ribout_parse_rt(&block, "rt 192.0.2.10:100");

    test_result(bgp_ribout_generator_init(&gen, &block) < 0, "Reject SR Policy ribout without segment-list");
    bgp_ribout_destroy(&block);
}

void test_generator_srpolicy_requires_route_target() {
    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;

    bgp_ribout_init(&block, "sr-missing-rt");
    bgp_ribout_parse_distinguisher(&block, "distinguisher 100");
    bgp_ribout_parse_color(&block, "color 200");
    bgp_ribout_parse_endpoint(&block, "endpoint 10.0.0.1");
    bgp_ribout_parse_segment_list(&block, "segment-list 1 weight 10 mpls 16010 16011");

    test_result(bgp_ribout_generator_init(&gen, &block) < 0, "Reject SR Policy ribout without route-target");
    bgp_ribout_destroy(&block);
}

void test_generator_srpolicy_rejects_non_ipv4_rt() {
    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;

    bgp_ribout_init(&block, "sr-bad-rt");
    bgp_ribout_parse_distinguisher(&block, "distinguisher 100");
    bgp_ribout_parse_color(&block, "color 200");
    bgp_ribout_parse_endpoint(&block, "endpoint 10.0.0.1");
    bgp_ribout_parse_rt(&block, "rt 65000:100");
    bgp_ribout_parse_segment_list(&block, "segment-list 1 weight 10 mpls 16010 16011");

    test_result(bgp_ribout_generator_init(&gen, &block) < 0,
                "Reject SR Policy ribout with non-IPv4-address route-target");
    bgp_ribout_destroy(&block);
}

void test_generator_evpn_type2_requires_rd() {
    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;

    bgp_ribout_init(&block, "evpn2-missing-rd");
    bgp_ribout_parse_mac(&block, "mac 00:11:22:33:44:00");
    bgp_ribout_parse_label(&block, "label 30000");
    bgp_ribout_parse_next_hop(&block, "next-hop 192.0.2.10");

    test_result(bgp_ribout_generator_init(&gen, &block) < 0, "Reject EVPN Type 2 ribout without RD");
    bgp_ribout_destroy(&block);
}

void test_generator_evpn_type2_requires_label() {
    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;

    bgp_ribout_init(&block, "evpn2-missing-label");
    bgp_ribout_parse_rd(&block, "rd 65000:320");
    bgp_ribout_parse_mac(&block, "mac 00:11:22:33:44:00");
    bgp_ribout_parse_next_hop(&block, "next-hop 192.0.2.10");

    test_result(bgp_ribout_generator_init(&gen, &block) < 0, "Reject EVPN Type 2 ribout without label");
    bgp_ribout_destroy(&block);
}

void test_generator_evpn_type2_requires_mac() {
    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;

    bgp_ribout_init(&block, "evpn2-missing-mac");
    bgp_ribout_parse_rd(&block, "rd 65000:320");
    bgp_ribout_parse_label(&block, "label 30000");
    bgp_ribout_parse_next_hop(&block, "next-hop 192.0.2.10");

    test_result(bgp_ribout_generator_init(&gen, &block) < 0, "Reject EVPN Type 2 ribout without MAC");
    bgp_ribout_destroy(&block);
}

void test_generator_evpn_type2_rejects_gateway_ip() {
    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;

    bgp_ribout_init(&block, "evpn2-gateway-ip");
    setup_valid_evpn_type2_block(&block, "ip 192.0.2.1");
    bgp_ribout_parse_gateway_ip(&block, "gateway-ip 10.255.0.1");

    test_result(bgp_ribout_generator_init(&gen, &block) < 0, "Reject EVPN Type 2 ribout with gateway-ip token");
    bgp_ribout_destroy(&block);
}

void test_generator_evpn_type2_rejects_link_local_next_hop() {
    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;

    bgp_ribout_init(&block, "evpn2-ll-nh");
    setup_valid_evpn_type2_block(&block, "ip 2001:db8::1");
    bgp_ribout_parse_next_hop(&block, "next-hop 2001:db8:320::10 link-local fe80::320");

    test_result(bgp_ribout_generator_init(&gen, &block) < 0,
                "Reject EVPN Type 2 ribout with IPv6 link-local next-hop companion");
    bgp_ribout_destroy(&block);
}

// Empty and Null Input Tests

void test_empty_prefix_string() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test");

    int result = bgp_ribout_parse_prefix(&block, "prefix");
    test_result(result < 0, "Reject empty prefix command");
    bgp_ribout_destroy(&block);
}

void test_empty_aspath() {
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "test");

    int result = bgp_ribout_parse_aspath(&block, "as-path");
    test_result(result < 0, "Reject empty AS-path command");
    bgp_ribout_destroy(&block);
}

// Boundary and Limit Tests

void test_max_ribouts() {
    bgp_sim_t           sim;

    bgp_init_simulator(&sim);
    int ok = 1;
    for (int i = 0; i < 500; i++) {
        char name[32];

        snprintf(name, sizeof(name), "ribout%d", i);
        if (!bgp_sim_add_ribout(&sim, name)) { ok = 0; break; }
    }

    test_result(ok && sim.ribout_count == 500, "Registry grows to 10x the former ribout limit");
    bgp_shutdown_sim(&sim);
}

void test_max_path_ids_boundary() {
    bgp_ribout_config_t block;
    char                cmd[4096] = "path-id";

    bgp_ribout_init(&block, "test");
    for (int i = 0; i < 100; i++) {
        char buf[32];

        snprintf(buf, sizeof(buf), " %d", i);
        strcat(cmd, buf);
    }

    test_result(bgp_ribout_parse_path_ids(&block, cmd) >= 0, "Parse 100 explicit path-ids");
    test_result(block.path_id_count == 100, "Explicit path-ID list retains every entry");
    bgp_ribout_destroy(&block);
}

void test_max_aspath_segments_boundary() {
    bgp_ribout_config_t block;
    char                cmd[4096] = "as-path";

    bgp_ribout_init(&block, "test");
    for (int i = 0; i < 30; i++) {
        char buf[32];

        snprintf(buf, sizeof(buf), " %d", 100 + i);
        strcat(cmd, buf);
    }

    test_result(bgp_ribout_parse_aspath(&block, cmd) >= 0, "Parse many AS-path segments");
    test_result(block.aspath_segment_count > 0, "AS-path segments created");
    bgp_ribout_destroy(&block);
}

void test_max_as_values_per_segment_boundary() {
    bgp_ribout_config_t block;
    char                cmd[4096] = "as-path {";

    bgp_ribout_init(&block, "test");
    for (int i = 0; i < 50; i++) {
        char buf[32];

        snprintf(buf, sizeof(buf), " %d", 100 + i);
        strcat(cmd, buf);
    }
    strcat(cmd, " }");

    test_result(bgp_ribout_parse_aspath(&block, cmd) >= 0, "Parse AS set with many values");
    if (block.aspath_segment_count > 0) {
        test_result(block.aspath_segments[0].value_count > 0, "AS set keeps parsed values");
    }
    bgp_ribout_destroy(&block);
}

void test_zero_prefix_count_boundary() {
    bgp_ribout_config_t block;

    bgp_ribout_init(&block, "test");
    bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/24 x 0");
    test_result(block.prefix_spec.count == 0, "Prefix count can be zero before generation");
    bgp_ribout_destroy(&block);
}

void test_minimal_valid_ribout_boundary() {
    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;
    int                 result;

    bgp_ribout_init(&block, "test");
    bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/24");
    bgp_ribout_parse_path_ids(&block, "path-id 0");
    result = bgp_ribout_generator_init(&gen, &block);

    test_result(result >= 0, "Minimal ribout (prefix + path-id) is valid");
    if (result >= 0) {
        test_result(gen.total_paths == 1, "Minimal ribout generates one path");
    }
    bgp_ribout_destroy(&block);
}

void test_large_path_id_count_boundary() {
    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;
    char                cmd[2048] = "path-id";
    int                 result;

    bgp_ribout_init(&block, "test");
    for (int i = 0; i < 50; i++) {
        char buf[32];

        snprintf(buf, sizeof(buf), " %d", i);
        strcat(cmd, buf);
    }

    bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/24 x 100");
    bgp_ribout_parse_path_ids(&block, cmd);
    result = bgp_ribout_generator_init(&gen, &block);

    test_result(result >= 0, "Handle 50 path-ids");
    if (result >= 0) {
        test_result(gen.total_paths == 5000, "Total paths scale with large path-id counts");
    }
    bgp_ribout_destroy(&block);
}

void test_very_large_total_paths_boundary() {
    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;
    int                 result;

    bgp_ribout_init(&block, "test");
    bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/24 x 100000");
    bgp_ribout_parse_path_ids(&block, "path-id 0 1 2 3 4 5 6 7 8 9");
    result = bgp_ribout_generator_init(&gen, &block);

    test_result(result >= 0, "Handle very large total path counts");
    if (result >= 0) {
        test_result(gen.total_paths == 1000000, "Very large total path count is correct");
    }
    bgp_ribout_destroy(&block);
}

void test_ipv4_zero_address_boundary() {
    bgp_ribout_config_t block;

    bgp_ribout_init(&block, "test");
    test_result(bgp_ribout_parse_prefix(&block, "prefix 0.0.0.0/0") >= 0, "Accept 0.0.0.0/0");
    bgp_ribout_destroy(&block);
}

void test_ipv4_loopback_boundary() {
    bgp_ribout_config_t block;

    bgp_ribout_init(&block, "test");
    test_result(bgp_ribout_parse_next_hop(&block, "next-hop 127.0.0.1") >= 0, "Accept 127.0.0.1 next-hop");
    bgp_ribout_destroy(&block);
}

void test_ipv4_broadcast_boundary() {
    bgp_ribout_config_t block;

    bgp_ribout_init(&block, "test");
    test_result(bgp_ribout_parse_next_hop(&block, "next-hop 255.255.255.255") >= 0, "Accept 255.255.255.255 next-hop");
    bgp_ribout_destroy(&block);
}

void test_ipv6_unspecified_boundary() {
    bgp_ribout_config_t block;

    bgp_ribout_init(&block, "test");
    test_result(bgp_ribout_parse_prefix(&block, "prefix ::/0") >= 0, "Accept ::/0 prefix");
    bgp_ribout_destroy(&block);
}

void test_ipv6_loopback_boundary() {
    bgp_ribout_config_t block;

    bgp_ribout_init(&block, "test");
    test_result(bgp_ribout_parse_next_hop(&block, "next-hop ::1") >= 0, "Accept ::1 next-hop");
    bgp_ribout_destroy(&block);
}

void test_ipv4_prefix_wrapping_boundary() {
    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;
    bgp_gen_path_t      path;
    char                prefix_str[64];
    int                 result;

    bgp_ribout_init(&block, "test");
    bgp_ribout_parse_prefix(&block, "prefix 10.255.255.255/32 x 3");
    bgp_ribout_parse_path_ids(&block, "path-id 0");
    result = bgp_ribout_generator_init(&gen, &block);
    test_result(result >= 0, "Initialize generator with boundary prefix");

    if (result >= 0) {
        bgp_ribout_generator_next(&gen, &path);
        test_path_prefix_to_string(&path, prefix_str, sizeof(prefix_str));
        test_result(strcmp(prefix_str, "10.255.255.255/32") == 0, "First boundary prefix is correct");
    }
    bgp_ribout_destroy(&block);
}

void test_empty_ribout_block_boundary() {
    bgp_ribout_config_t block;

    bgp_ribout_init(&block, "empty");
    test_result(block.prefix_spec.count == 0, "Empty block has zero prefix count");
    test_result(block.path_id_count == 0, "Empty block has zero path-id count");
    test_result(block.aspath_segment_count == 0, "Empty block has zero AS-path segments");
    bgp_ribout_destroy(&block);
}

void test_empty_simulator_boundary() {
    bgp_sim_t sim;

    bgp_init_simulator(&sim);
    test_result(sim.router_count == 0, "Empty simulator has no routers");
    test_result(sim.ribout_count == 0, "Empty simulator has no ribouts");
    bgp_shutdown_sim(&sim);
}

void test_rd_and_rt_value_bounds() {
    bgp_ribout_config_t block;
    int                 passed = 1;

    bgp_ribout_init(&block, "admin-bounds");
    passed &= (bgp_ribout_parse_rd(&block, "rd 65000:") < 0);            /* empty assigned       */
    passed &= (bgp_ribout_parse_rd(&block, "rd 65000:5000000000") < 0);  /* assigned > 2^32 - 1  */
    passed &= (bgp_ribout_parse_rd(&block, "rd 5000000000:1") < 0);      /* admin > 2^32 - 1     */
    passed &= (bgp_ribout_parse_rd(&block, "rd 4200000000:70000") < 0);  /* 4-octet AS: 2 octets */
    passed &= (bgp_ribout_parse_rd(&block, "rd 192.0.2.1:65536") < 0);   /* IPv4: 2 octets       */
    passed &= (bgp_ribout_parse_rd(&block, "rd 4200000000:65535") == 0) &&
              (block.rds[0].type == 2) &&
              (block.rds[0].value[4] == 0xff) && (block.rds[0].value[5] == 0xff);
    passed &= (bgp_ribout_parse_rd(&block, "rd 4200000000:65534 x 3") < 0); /* sequence past 65535 */
    passed &= (bgp_ribout_parse_rd(&block, "rd 65000:4294967294 x 2") == 0) && (block.rd_count == 2);
    passed &= (bgp_ribout_parse_rt(&block, "rt 65000:") < 0);
    passed &= (bgp_ribout_parse_soo(&block, "soo 192.0.2.1:70000") < 0);
    test_result(passed, "RD/RT/SoO admin:assigned bounds per form");
    bgp_ribout_destroy(&block);
}

// Strict Values

/*
 * Apply one "keyword value" line with bgp_ribout_edit(), as the CLI does; its result.
 */
static int edit_line(bgp_ribout_config_t *block, const char *line) {
    char        keyword[32];
    const char *value = strchr(line, ' ');

    if (!value || (size_t)(value - line) >= sizeof(keyword)) {
        return -1;
    }
    snprintf(keyword, sizeof(keyword), "%.*s", (int)(value - line), line);
    return bgp_ribout_edit(block, keyword, value + 1, 0);
}

/*
 * What the value parsers took before they were strict; each line must be rejected and change nothing.
 */
static const char *const k_malformed[] = {
    // a sign: %u wrapped "-1" to 4294967295, strtoul and %lld took "+"
    "next-hop 192.0.2.1 x -1",
    "endpoint 10.0.0.1 x -2",
    "mac 1 x -1",
    "gateway-ip 10.0.0.1 x -1",
    "ip 10.1.0.1 x -1",
    "binding-sid srv6 2001:db8::1 x -1",
    "label +100",
    "ethernet-tag +5",
    "path-id +1",
    "distinguisher +1",
    "color +1",
    "rotate-every +2",
    "rotate-period +2",
    "med +5",
    "localpref rand(+3)",
    "rd 65000:+1",
    "prefix 10.0.0.0/+24",
    "segment-list 1 weight +10 mpls 16001",
    "as-path +65001",
    "as-path [rand(-1) x 2]",
    "mac +1:2:3:4:5:6",
    "esi +0:00:00:00:00:00:00:00:00:01",
    // text after the value, which sscanf ignored
    "next-hop 192.0.2.1 x 3 junk",
    "next-hop 192.0.2.1 junk",
    "next-hop 192.0.2.1 link-local",
    "next-hop 192.0.2.1 link-local fe80::1 junk",
    "endpoint 10.0.0.1 junk",
    "mac 1 x 3 junk",
    "ip 10.1.0.1 junk",
    "gateway-ip 10.0.0.1 junk",
    "origin igp junk",
    "binding-sid srv6 2001:db8::1 junk",
    // Converted numbers alone do not prove that the expression is complete.
    "med range(1,2junk)",
    "med range(1,2",
    "med randrange(1,2",
    "med randrange(1,2) junk",
    "localpref rand(5junk)",
    "localpref rand(5", "localpref range(1,2))",
    "localpref rand(18446744073709551616)",
    "preference range(1,2junk)",
    "priority rand(5junk)",
    "enlp range(1,2",
    "binding-sid mpls randrange(16,20junk)",
    "path-id range(1,2junk)",
    "path-id rotate range(1,2",
    "label range(16,20junk)",
    "ethernet-tag range(1,2",
    "distinguisher range(1,2junk)",
    "color range(1,2junk)",
    // a count of 0, which unset the list
    "next-hop 192.0.2.1 x 0",
    "endpoint 10.0.0.1 x 0",
    "gateway-ip 10.0.0.1 x 0",
    "ip 10.1.0.1 x 0",
    // values past their field, truncated to 32 bits before
    "ethernet-tag 4294967296",
    "segment-list 1 weight 10 mpls 4294967297",
    "segment-list 4294967296 weight 10 mpls 16001",
    // as-path text that the scanner skipped
    "as-path 65001 junk",
    "as-path 65001 junk 65002",
    "as-path junk",
    "as-path 65001x",
    "as-path 65001 rand(5)x",
    "as-path [rand(5) x 2] junk",
    // hex and signed traffic rates that strtof took
    "action traffic-rate bytes +0",
    "action traffic-rate bytes 0x10",
};

/*
 * Every malformed line is rejected and leaves the block as it was: bgp_ribout_edit() works on a copy.
 */
void test_malformed_values_rejected() {
    bgp_ribout_config_t block;
    static uint8_t before[sizeof(bgp_ribout_config_t)];
    int rejected = 1;

    bgp_ribout_init(&block, "strict");
    edit_line(&block, "prefix 10.0.0.0/24 x 2");
    edit_line(&block, "next-hop 192.0.2.1 x 2");
    edit_line(&block, "as-path 65001");
    memcpy(before, &block, BGP_RIBOUT_CONFIG_SIZE);
    for (size_t i = 0; i < sizeof(k_malformed) / sizeof(k_malformed[0]); i++) {
        int ok = edit_line(&block, k_malformed[i]) != 0 && memcmp(before, &block, BGP_RIBOUT_CONFIG_SIZE) == 0;

        if (!ok) {
            printf("  accepted or changed the block: %s\n", k_malformed[i]);
        }
        rejected = rejected && ok;
    }
    test_result(rejected, "Reject signed, trailing, zero-count, oversized and unknown values; the block stays");
    bgp_ribout_destroy(&block);
}

void test_path_count_overflow() {
    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;

    bgp_ribout_init(&block, "path-count");
    test_result(edit_line(&block, "rd 65000:1") == 0 &&
                edit_line(&block, "label 16000") == 0 &&
                edit_line(&block, "mac 02:00:00:00:00:01") == 0 &&
                edit_line(&block, "ip 2001:db8::1") == 0 &&
                bgp_ribout_generate(&block) == BGP_RIBOUT_GENERATED,
                "A small Type 2 block has a published snapshot");
    bgp_ribout_snapshot_t *snapshot = block.snapshot;
    bgp_msg_t             *messages = block.messages;
    test_result(edit_line(&block, "rd 65000:1 x 4") == 0 &&
                edit_line(&block, "ethernet-tag 0 x 4") == 0 &&
                edit_line(&block, "mac 02:00:00:00:00:01 x 2147483648") == 0 &&
                edit_line(&block, "ip 2001:db8::1 x 2147483648") == 0,
                "Individual dimensions fit their address spaces");
    test_result(bgp_ribout_generator_init(&gen, &block) < 0 &&
                bgp_ribout_generate(&block) == BGP_RIBOUT_MAP_FAILED &&
                block.dirty && block.snapshot == snapshot && block.messages == messages,
                "A 2^66 path product is rejected without replacing the old snapshot");
    test_result(edit_line(&block, "rd 65000:1") == 0 &&
                edit_line(&block, "ethernet-tag 0") == 0 &&
                bgp_ribout_generator_init(&gen, &block) == 0 && gen.total_paths == (1ULL << 62),
                "Representable path products are counted in 64 bits without allocating the routes");
    test_result(edit_line(&block, "mac 02:00:00:00:00:01") == 0 &&
                edit_line(&block, "ip 0.0.0.0 x 2147483648") == 0 &&
                bgp_ribout_generator_init(&gen, &block) == 0 && gen.total_paths == (1ULL << 32),
                "The two IP-family counts are added in 64 bits before multiplying");
    bgp_ribout_destroy(&block);
}

/*
 * The strict parsers still take every valid form, with the values written.
 */
void test_strict_values_accepted() {
    static const char *const k_valid[] = {
        "next-hop 192.0.2.9 x 4",
        "mac 00:11:22:33:44:55 x 2",
        "mac 1",
        "ip rotate 10.1.0.1 x 4",
        "ip 2001:db8::1 x 3",
        "gateway-ip 10.0.0.1 x 2",
        "endpoint rotate 10.0.0.1 x 4",
        "label 100 x 2",
        "ethernet-tag 4294967295",
        "path-id rotate 1 x 2",
        "path-id range(1,4)",
        "rotate-every 2",
        "origin egp",
        "as-path 65001 {65002 65003} [rand(100) x 2] rand(5) 65004",
        "med range(1,5)",
        "med randrange ( 0 , 4294967295 )",
        "localpref rand ( 4294967295 )",
        "path-id range ( 0 , 2 )",
        "localpref rand(3)",
        "rd 65000:4294967295",
        "segment-list 1 weight 10 mpls 16001 16002",
        "binding-sid srv6 2001:db8::1 x 4",
        "esi 00:00:00:00:00:00:00:00:00:01",
        "community 65000:1",
        "action traffic-rate bytes 1e3",
        "as-path 4294967295",
    };
    bgp_ribout_config_t block;
    int                 accepted = 1;

    bgp_ribout_init(&block, "strict");
    edit_line(&block, "prefix 10.0.0.0/24 x 2");
    for (size_t i = 0; i < sizeof(k_valid) / sizeof(k_valid[0]); i++) {
        if (edit_line(&block, k_valid[i]) != 0) {
            printf("  rejected: %s\n", k_valid[i]);
            accepted = 0;
        }
    }
    test_result(accepted, "Accept every valid form of the strict parsers");
    test_result(block.next_hop_spec.count == 4 &&
                block.mac_spec.count == 1 &&
                bgp_ribout_ethernet_tags_at(&block, 0) == UINT32_MAX &&
                block.endpoint_rotate &&
                block.endpoint_spec.count == 4 &&
                block.aspath_segment_count == 1 &&
                block.aspath_segments[0].as_values[0] == UINT32_MAX &&
                block.binding_sid_srv6_spec.count == 4,
                "The values are the ones written, 2^32 - 1 included");
    bgp_ribout_destroy(&block);
}

int main(void) {
    printf("BGP RIB-OUT Constraint Tests\n");
    printf("===============================================\n\n");

    // Invalid IP addresses
    printf("=== Invalid IP Address Tests ===\n");
    test_invalid_ipv4_prefix_out_of_range();
    test_invalid_ipv4_prefix_incomplete();
    test_invalid_ipv4_prefix_length();
    test_invalid_ipv6_prefix_bad_hex();
    test_invalid_ipv6_prefix_length();
    test_invalid_next_hop_out_of_range();
    test_invalid_next_hop_extra_octets();
    printf("\n");

    // Out of range values
    printf("=== Out of Range Value Tests ===\n");
    test_invalid_aspath_negative();
    test_aspath_random_count_at_segment_limit();
    test_invalid_aspath_random_count_over_segment_limit();
    test_invalid_localpref_negative();
    test_invalid_path_id_negative();
    test_invalid_label_negative();
    test_invalid_label_too_large();
    test_invalid_mac_integer_too_large();
    test_invalid_router_mac_integer_multicast();
    test_too_many_path_ids();
    test_too_many_labels();
    printf("\n");

    // Malformed syntax
    printf("=== Malformed Syntax Tests ===\n");
    test_malformed_aspath_missing_closing_brace();
    test_malformed_aspath_empty_set();
    test_malformed_aspath_random_missing_count();
    test_malformed_prefix_missing_count();
    test_malformed_prefix_wrong_order();
    test_malformed_label_missing_count();
    test_invalid_origin_value();
    test_invalid_esi_compact_hex_length();
    test_invalid_esi_sequence_zero_count();
    printf("\n");

    // Address family mismatches
    printf("=== Address Family Mismatch Tests ===\n");
    test_ipv4_prefix_ipv6_next_hop();
    test_ipv6_next_hop_with_link_local();
    test_ipv4_next_hop_with_link_local();
    test_non_link_local_next_hop_companion();
    test_ipv6_prefix_ipv4_next_hop();
    test_ipv4_prefix_ipv6_next_hop_reverse_order();
    test_ipv6_prefix_ipv4_next_hop_reverse_order();
    test_vpnv6_prefix_ipv4_next_hop();
    test_gateway_ip_family_mismatch();
    printf("\n");

    // VPN / EVPN tokens
    printf("=== VPN / EVPN Token Tests ===\n");
    test_rt_and_rt_set_mutually_exclusive();
    test_rt_set_and_rt_mutually_exclusive();
    test_rt_set_parsing();
    test_med_random_parsing();
    test_localpref_random_rejects_zero();
    test_med_random_rejects_zero();
    test_aspath_random_rejects_zero();
    test_srpolicy_preference_random_rejects_zero();
    test_srpolicy_binding_sid_random_rejects_zero();
    test_localpref_range_rejects_reverse_bounds();
    test_med_randrange_rejects_reverse_bounds();
    test_path_id_range_rejects_too_many_values();
    test_srpolicy_binding_sid_randrange_rejects_out_of_bounds();
    test_rd_and_rt_value_bounds();
    test_srpolicy_family_inference_ipv4();
    test_srpolicy_family_inference_ipv6();
    test_srpolicy_rejects_prefix_token_mix();
    test_evpn_type2_family_inference_mac_only();
    test_evpn_type2_family_inference_ipv6_ip();
    test_evpn_type2_rejects_prefix_token_mix();
    printf("\n");

    // Generator initialization
    printf("=== Generator Initialization Tests ===\n");
    test_generator_missing_prefix();
    test_generator_missing_path_ids();
    test_generator_label_sequence_multiplies_paths();
    test_generator_zero_prefix_count();
    test_generator_vpn_requires_rd();
    test_generator_vpn_requires_label();
    test_generator_evpn_dimensions_multiply_paths();
    test_generator_evpn_rejects_esi_and_gateway_ip();
    test_generator_evpn5_label_zero_with_overlay(
        "EVPN type 5 label 0 with a Gateway IP Overlay Index",
        "gateway-ip 10.255.0.1");
    test_generator_evpn5_label_zero_with_overlay(
        "EVPN type 5 label 0 with an ESI Overlay Index",
        "esi 00:00:00:00:00:00:00:00:00:01");
    test_generator_evpn5_label_zero_with_overlay(
        "EVPN type 5 label 0 with a Router's MAC Overlay Index",
        "router-mac 00:11:22:33:44:55");
    test_generator_evpn5_label_zero_requires_overlay_index();
    test_generator_evpn5_label_zero_rejects_zero_overlay("EVPN type 5 label 0 rejects a zero Gateway IP",
                                                         "gateway-ip 0.0.0.0");
    test_generator_evpn5_label_zero_rejects_zero_overlay("EVPN type 5 label 0 rejects a zero ESI",
                                                         "esi 00:00:00:00:00:00:00:00:00:00");
    test_generator_evpn5_label_zero_rejects_zero_overlay("EVPN type 5 label 0 rejects a zero Router's MAC",
                                                         "router-mac 00:00:00:00:00:00");
    test_generator_srpolicy_requires_distinguisher();
    test_generator_srpolicy_requires_color();
    test_generator_srpolicy_requires_endpoint();
    test_generator_srpolicy_requires_segment_list();
    test_generator_srpolicy_requires_route_target();
    test_generator_srpolicy_rejects_non_ipv4_rt();
    test_generator_evpn_type2_requires_rd();
    test_generator_evpn_type2_requires_label();
    test_generator_evpn_type2_requires_mac();
    test_generator_evpn_type2_rejects_gateway_ip();
    test_generator_evpn_type2_rejects_link_local_next_hop();
    printf("\n");

    // Empty inputs
    printf("=== Empty Input Tests ===\n");
    test_empty_prefix_string();
    test_empty_aspath();
    printf("\n");

    // Strict values
    printf("=== Strict Value Tests ===\n");
    test_malformed_values_rejected();
    test_strict_values_accepted();
    printf("\n");

    // Boundary and limit behavior
    printf("=== Boundary And Limit Tests ===\n");
    test_max_ribouts();
    test_max_path_ids_boundary();
    test_max_aspath_segments_boundary();
    test_max_as_values_per_segment_boundary();
    test_zero_prefix_count_boundary();
    test_minimal_valid_ribout_boundary();
    test_large_path_id_count_boundary();
    test_very_large_total_paths_boundary();
    test_path_count_overflow();
    test_ipv4_zero_address_boundary();
    test_ipv4_loopback_boundary();
    test_ipv4_broadcast_boundary();
    test_ipv6_unspecified_boundary();
    test_ipv6_loopback_boundary();
    test_ipv4_prefix_wrapping_boundary();
    test_empty_ribout_block_boundary();
    test_empty_simulator_boundary();
    printf("\n");

    // Summary
    printf("===============================================\n");
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);
    printf("===============================================\n");

    return (tests_failed == 0) ? 0 : 1;
}
