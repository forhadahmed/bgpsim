// Unit tests for BGP FlowSpec UPDATE message generation (RFC 8955)

#include <math.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "bgp.h"
#include "test_wire.h"
#include "bgp_router.h"
#include "bgp_update.h"
#include "test_result.h"
#include "bgp_neighbor.h"

static int find_attr(const uint8_t *msg, size_t size, uint8_t type_code,
                     const uint8_t **value_out, uint16_t *length_out) {
    return test_wire_find_attr(msg, size, type_code, value_out, length_out, NULL);
}

static int has_attr(const uint8_t *msg, size_t size, uint8_t type_code) {
    return find_attr(msg, size, type_code, NULL, NULL);
}

// Helper: build a simple rule

/*
 * Smallest numeric_op length that holds a port value.
 */
static uint8_t port_op_len(uint16_t port) {
    return (port > 0xFF) ? FLOWSPEC_OP_LEN_2 : FLOWSPEC_OP_LEN_1;
}

/*
 * Build a simple FlowSpec rule: match destination prefix + single port.
 * Caller must free components[1].values and components array.
 */
static flowspec_rule_t make_simple_rule(const char *dest_prefix, uint8_t prefix_len, uint16_t port) {
    flowspec_rule_t       rule;
    flowspec_component_t *comps = malloc(2 * sizeof(flowspec_component_t));
    flowspec_op_value_t  *vals = malloc(sizeof(flowspec_op_value_t));

    assert(comps && vals);
    memset(comps, 0, 2 * sizeof(flowspec_component_t));

    // Component 1: Destination Prefix
    comps[0].type = FLOWSPEC_DEST_PREFIX;
    comps[0].prefix_len = prefix_len;
    inet_pton(AF_INET, dest_prefix, comps[0].prefix);
    comps[0].values = NULL;
    comps[0].num_values = 0;

    // Component 2: Destination Port
    vals[0].op = (uint8_t)(FLOWSPEC_OP_END | port_op_len(port) | FLOWSPEC_OP_EQ);
    vals[0].value = port;
    comps[1].type = FLOWSPEC_DEST_PORT;
    comps[1].prefix_len = 0;
    comps[1].values = vals;
    comps[1].num_values = 1;

    rule.components = comps;
    rule.num_components = 2;
    return rule;
}

/*
 * IPv6 version of make_simple_rule: a destination prefix with an RFC 8956 offset and one destination port. Free the
 * result with free_simple_rule.
 */
static flowspec_rule_t make_simple_rule_ipv6(const char *dest_prefix,
                                             uint8_t prefix_offset,
                                             uint8_t prefix_len,
                                             uint16_t port) {
    flowspec_rule_t       rule;
    flowspec_component_t *comps = malloc(2 * sizeof(flowspec_component_t));
    flowspec_op_value_t  *vals = malloc(sizeof(flowspec_op_value_t));

    assert(comps && vals);
    memset(comps, 0, 2 * sizeof(flowspec_component_t));

    comps[0].type = FLOWSPEC_DEST_PREFIX;
    comps[0].prefix_len = prefix_len;
    comps[0].prefix_offset = prefix_offset;
    inet_pton(AF_INET6, dest_prefix, comps[0].prefix);
    comps[0].values = NULL;
    comps[0].num_values = 0;

    vals[0].op = (uint8_t)(FLOWSPEC_OP_END | port_op_len(port) | FLOWSPEC_OP_EQ);
    vals[0].value = port;
    comps[1].type = FLOWSPEC_DEST_PORT;
    comps[1].values = vals;
    comps[1].num_values = 1;

    rule.components = comps;
    rule.num_components = 2;
    return rule;
}

static void free_simple_rule(flowspec_rule_t *rule) {
    int i;
    for (i = 0; i < rule->num_components; i++) {
        free(rule->components[i].values);
    }
    free(rule->components);
    rule->components = NULL;
    rule->num_components = 0;
}

// Test Cases

/*
 * Test 1: Rule validation - ascending type order
 */
void test_validate_ascending_order() {
    flowspec_rule_t      rule;
    flowspec_component_t comps[3];
    int                  passed;

    memset(comps, 0, sizeof(comps));

    // Valid: types 1 < 3 < 5
    comps[0].type = FLOWSPEC_DEST_PREFIX;
    comps[0].prefix_len = 24;
    inet_pton(AF_INET, "10.0.0.0", comps[0].prefix);
    comps[1].type = FLOWSPEC_IP_PROTOCOL;
    comps[1].values = &(flowspec_op_value_t){FLOWSPEC_OP_END | FLOWSPEC_OP_EQ, 6};
    comps[1].num_values = 1;
    comps[2].type = FLOWSPEC_DEST_PORT;
    comps[2].values = &(flowspec_op_value_t){FLOWSPEC_OP_END | FLOWSPEC_OP_EQ, 80};
    comps[2].num_values = 1;
    rule.components = comps;
    rule.num_components = 3;
    passed = (bgp_validate_flowspec_rule(&rule) == 0);

    // Invalid: types 5 > 3 (not ascending)
    comps[0].type = FLOWSPEC_DEST_PORT;
    comps[1].type = FLOWSPEC_IP_PROTOCOL;
    comps[2].type = FLOWSPEC_SRC_PORT;
    passed = passed && (bgp_validate_flowspec_rule(&rule) == -1);

    // Invalid: duplicate types
    comps[0].type = FLOWSPEC_DEST_PREFIX;
    comps[1].type = FLOWSPEC_DEST_PORT;
    comps[2].type = FLOWSPEC_DEST_PORT;
    passed = passed && (bgp_validate_flowspec_rule(&rule) == -1);

    test_result(passed, "Rule validation ascending type order");
}

/*
 * Test 2: Component encoding - destination prefix
 */
void test_encode_dest_prefix() {
    flowspec_component_t comp;
    uint8_t              buffer[64];
    int                  len;

    memset(&comp, 0, sizeof(comp));
    comp.type = FLOWSPEC_DEST_PREFIX;
    comp.prefix_len = 24;
    inet_pton(AF_INET, "10.1.2.0", comp.prefix);

    len = bgp_encode_flowspec_component(buffer, &comp);

    // type(1) + prefix_len(1) + 3 prefix bytes = 5
    test_result((len == 5) &&
                (buffer[0] == FLOWSPEC_DEST_PREFIX) &&
                (buffer[1] == 24) &&
                (buffer[2] == 10) &&
                (buffer[3] == 1) &&
                (buffer[4] == 2),
                "Component encoding: destination prefix");
}

/*
 * Test 3: Component encoding - source prefix
 */
void test_encode_src_prefix() {
    flowspec_component_t comp;
    uint8_t              buffer[64];
    int                  len;

    memset(&comp, 0, sizeof(comp));
    comp.type = FLOWSPEC_SRC_PREFIX;
    comp.prefix_len = 16;
    inet_pton(AF_INET, "192.168.0.0", comp.prefix);

    len = bgp_encode_flowspec_component(buffer, &comp);

    // type(1) + prefix_len(1) + 2 prefix bytes = 4
    test_result((len == 4) &&
                (buffer[0] == FLOWSPEC_SRC_PREFIX) &&
                (buffer[1] == 16) &&
                (buffer[2] == 192) &&
                (buffer[3] == 168),
                "Component encoding: source prefix");
}

/*
 * Test 3b: IPv6 destination prefix with offset encoding
 */
void test_encode_ipv6_dest_prefix_with_offset() {
    flowspec_component_t comp;
    uint8_t              buffer[64];
    int                  len;

    memset(&comp, 0, sizeof(comp));
    comp.type = FLOWSPEC_DEST_PREFIX;
    comp.prefix_len = 120;
    comp.prefix_offset = 96;
    inet_pton(AF_INET6, "::ffff:192.0.2.0", comp.prefix);

    len = bgp_encode_flowspec_component_afi(buffer, &comp, AFI_IPV6);

    test_result((len == 6) &&
                (buffer[0] == FLOWSPEC_DEST_PREFIX) &&
                (buffer[1] == 120) &&
                (buffer[2] == 96) &&
                (buffer[3] == 192) &&
                (buffer[4] == 0) &&
                (buffer[5] == 2),
                "IPv6 FlowSpec destination prefix offset encoding");
}

/*
 * Test 3c: every IPv6 offset/length pair against a bit-at-a-time reference
 * (RFC 8956 section 3.1: the pattern is bits offset..length-1, packed from
 * the first bit, trailing bits zero).
 */
void test_encode_ipv6_prefix_offset_all_bit_positions() {
    flowspec_component_t comp;
    uint8_t              buffer[64];
    uint8_t              expected[16];
    int                  mismatches = 0;

    memset(&comp, 0, sizeof(comp));
    comp.type = FLOWSPEC_SRC_PREFIX;
    for (int i = 0; i < 16; i++) {
        comp.prefix[i] = (uint8_t)(0xA5 ^ (i * 37));
    }

    for (int offset = 0; offset < 128; offset++) {
        for (int length = offset + 1; length <= 128; length++) {
            int pattern_bits = length - offset;
            int pattern_bytes = (pattern_bits + 7) / 8;
            int len;

            comp.prefix_offset = (uint8_t)offset;
            comp.prefix_len = (uint8_t)length;
            memset(expected, 0, sizeof(expected));
            for (int bit = 0; bit < pattern_bits; bit++) {
                int src = offset + bit;

                if ((comp.prefix[src / 8] >> (7 - src % 8)) & 1) {
                    expected[bit / 8] |= (uint8_t)(0x80 >> (bit % 8));
                }
            }

            len = bgp_encode_flowspec_component_afi(buffer, &comp, AFI_IPV6);
            if (len != 3 + pattern_bytes || buffer[1] != length || buffer[2] != offset ||
                memcmp(buffer + 3, expected, (size_t)pattern_bytes) != 0) {
                mismatches++;
            }
        }
    }

    test_result(mismatches == 0, "IPv6 FlowSpec prefix pattern for every offset/length pair");
}

/*
 * Test 4: Component encoding - numeric operator (1-byte value)
 */
void test_encode_numeric_op_1byte() {
    flowspec_component_t comp;
    flowspec_op_value_t  vals[1];
    uint8_t              buffer[64];
    int                  len;

    memset(&comp, 0, sizeof(comp));
    comp.type = FLOWSPEC_IP_PROTOCOL;
    vals[0].op = FLOWSPEC_OP_END | FLOWSPEC_OP_LEN_1 | FLOWSPEC_OP_EQ;
    vals[0].value = 6;  /* TCP */
    comp.values = vals;
    comp.num_values = 1;

    len = bgp_encode_flowspec_component(buffer, &comp);

    // type(1) + op(1) + value(1) = 3
    test_result((len == 3) &&
                (buffer[0] == FLOWSPEC_IP_PROTOCOL) &&
                (buffer[1] == (FLOWSPEC_OP_END | FLOWSPEC_OP_LEN_1 | FLOWSPEC_OP_EQ)) &&
                (buffer[2] == 6),
                "Component encoding: numeric 1-byte value");
}

/*
 * Test 5: Component encoding - numeric operator (2-byte value)
 */
void test_encode_numeric_op_2byte() {
    flowspec_component_t comp;
    flowspec_op_value_t  vals[1];
    uint8_t              buffer[64];
    int                  len;
    uint16_t             port_net;

    memset(&comp, 0, sizeof(comp));
    comp.type = FLOWSPEC_DEST_PORT;
    vals[0].op = FLOWSPEC_OP_END | FLOWSPEC_OP_LEN_2 | FLOWSPEC_OP_EQ;
    vals[0].value = 8080;
    comp.values = vals;
    comp.num_values = 1;

    len = bgp_encode_flowspec_component(buffer, &comp);

    // type(1) + op(1) + value(2) = 4
    memcpy(&port_net, buffer + 2, 2);
    port_net = ntohs(port_net);
    test_result((len == 4) &&
                (buffer[0] == FLOWSPEC_DEST_PORT) &&
                (buffer[1] == (FLOWSPEC_OP_END | FLOWSPEC_OP_LEN_2 | FLOWSPEC_OP_EQ)) &&
                (port_net == 8080),
                "Component encoding: numeric 2-byte value");
}

/*
 * Test 6: Component encoding - numeric operator (4-byte value)
 */
void test_encode_numeric_op_4byte() {
    flowspec_component_t comp;
    flowspec_op_value_t  vals[1];
    uint8_t              buffer[64];
    int                  len;
    uint32_t             val_net;

    memset(&comp, 0, sizeof(comp));
    comp.type = FLOWSPEC_PACKET_LEN;
    vals[0].op = FLOWSPEC_OP_END | FLOWSPEC_OP_LEN_4 | FLOWSPEC_OP_GT;
    vals[0].value = 100000;
    comp.values = vals;
    comp.num_values = 1;

    len = bgp_encode_flowspec_component(buffer, &comp);

    // type(1) + op(1) + value(4) = 6
    memcpy(&val_net, buffer + 2, 4);
    val_net = ntohl(val_net);
    test_result((len == 6) &&
                (buffer[0] == FLOWSPEC_PACKET_LEN) &&
                (val_net == 100000),
                "Component encoding: numeric 4-byte value");
}

/*
 * Test 7: Component encoding - multiple operator-value pairs (port range)
 */
void test_encode_port_range() {
    flowspec_component_t comp;
    flowspec_op_value_t  vals[2];
    uint8_t              buffer[64];
    int                  len;

    memset(&comp, 0, sizeof(comp));
    comp.type = FLOWSPEC_PORT;
    /*
     * port >= 80 AND port <= 443. The AND bit goes on the second operator:
     * it ANDs that pair with the result before it. RFC 8955 section 4.2.1.1
     * says the first operator MUST NOT carry it.
     */
    vals[0].op = FLOWSPEC_OP_LEN_1 | FLOWSPEC_OP_GT | FLOWSPEC_OP_EQ;
    vals[0].value = 80;
    vals[1].op = FLOWSPEC_OP_END | FLOWSPEC_OP_AND | FLOWSPEC_OP_LEN_2 |
                 FLOWSPEC_OP_LT | FLOWSPEC_OP_EQ;
    vals[1].value = 443;
    comp.values = vals;
    comp.num_values = 2;

    len = bgp_encode_flowspec_component(buffer, &comp);

    // type(1) + op(1)+val(1) + op(1)+val(2) = 6
    test_result((len == 6) &&
                (buffer[0] == FLOWSPEC_PORT) &&
                (buffer[1] == (FLOWSPEC_OP_LEN_1 | FLOWSPEC_OP_GT | FLOWSPEC_OP_EQ)) &&
                (buffer[2] == 80) &&
                (buffer[3] == (FLOWSPEC_OP_END | FLOWSPEC_OP_AND | FLOWSPEC_OP_LEN_2 |
                              FLOWSPEC_OP_LT | FLOWSPEC_OP_EQ)) &&
                (read_u16(buffer + 4) == 443),
                "Component encoding: port range (multi op-value)");
}

/*
 * Test 8: Component encoding - bitmask operator (TCP flags)
 */
void test_encode_bitmask_tcp_flags() {
    flowspec_component_t comp;
    flowspec_op_value_t  vals[1];
    uint8_t              buffer[64];
    int                  len;

    memset(&comp, 0, sizeof(comp));
    comp.type = FLOWSPEC_TCP_FLAGS;
    // Match SYN flag (0x02)
    vals[0].op = FLOWSPEC_OP_END | FLOWSPEC_OP_LEN_1 | FLOWSPEC_OP_MATCH;
    vals[0].value = 0x02;
    comp.values = vals;
    comp.num_values = 1;

    len = bgp_encode_flowspec_component(buffer, &comp);

    // type(1) + op(1) + value(1) = 3
    test_result((len == 3) &&
                (buffer[0] == FLOWSPEC_TCP_FLAGS) &&
                (buffer[1] == (FLOWSPEC_OP_END | FLOWSPEC_OP_LEN_1 | FLOWSPEC_OP_MATCH)) &&
                (buffer[2] == 0x02),
                "Component encoding: bitmask TCP flags");
}

/*
 * Test 9: Component encoding - bitmask operator (fragment)
 */
void test_encode_bitmask_fragment() {
    flowspec_component_t comp;
    flowspec_op_value_t  vals[1];
    uint8_t              buffer[64];
    int                  len;

    memset(&comp, 0, sizeof(comp));
    comp.type = FLOWSPEC_FRAGMENT;
    // Match "don't fragment" bit (0x01) AND NOT "is fragment" (0x02)
    vals[0].op = FLOWSPEC_OP_END | FLOWSPEC_OP_LEN_1 |
                 FLOWSPEC_OP_NOT | FLOWSPEC_OP_MATCH;
    vals[0].value = 0x02;
    comp.values = vals;
    comp.num_values = 1;

    len = bgp_encode_flowspec_component(buffer, &comp);

    test_result((len == 3) &&
                (buffer[0] == FLOWSPEC_FRAGMENT) &&
                (buffer[1] == (FLOWSPEC_OP_END | FLOWSPEC_OP_LEN_1 | FLOWSPEC_OP_NOT | FLOWSPEC_OP_MATCH)) &&
                (buffer[2] == 0x02),
                "Component encoding: bitmask fragment");
}

/*
 * Test 10: NLRI length encoding - short (< 240 bytes = 1-byte length)
 */
void test_nlri_length_short() {
    flowspec_rule_t rule = make_simple_rule("10.0.0.0", 24, 80);
    uint8_t         buffer[256];
    int             len;

    len = bgp_encode_flowspec_rule(buffer, &rule);

    /*
     * The length byte should be small (< 240) and encoded in 1 byte.
     * Component body:
     *   dest prefix: type(1) + plen(1) + 3 prefix bytes = 5
     *   dest port:   type(1) + op(1) + val(1) = 3 (1-byte value for port 80)
     * Total body = 8, so length byte = 8
     */
    test_result((len > 0) &&
                (buffer[0] < 240) &&
                (buffer[0] == (uint8_t)(len - 1)),
                "NLRI length encoding: short (1-byte length)");

    free_simple_rule(&rule);
}

/*
 * Test 11: NLRI length encoding threshold test (>= 240 = 2-byte length)
 */
void test_nlri_length_long() {
    flowspec_rule_t       rule;
    flowspec_component_t *comps;
    uint8_t               buffer[4096];
    int                   len;
    int                   i;
    /*
     * Numeric types that allow 4-octet values. TCP flags (9), DSCP (11),
     * and fragment (12) have MUST width limits (RFC 8955 section 4.2.2).
     */
    static const uint8_t types[] = {3, 4, 5, 6, 7, 8, 10};
    int num_comps = (int)(sizeof(types) / sizeof(types[0]));

    comps = calloc((size_t)num_comps, sizeof(flowspec_component_t));
    assert(comps != NULL);

    /*
     * Create many components with 4-byte values to push NLRI > 240 bytes.
     * Each numeric component with many op-value pairs uses lots of space.
     */
    for (i = 0; i < num_comps; i++) {
        int                  j;
        int                  nvals = 8;
        flowspec_op_value_t *vals = malloc((size_t)nvals * sizeof(flowspec_op_value_t));
        assert(vals != NULL);

        comps[i].type = types[i];
        for (j = 0; j < nvals; j++) {
            vals[j].op = FLOWSPEC_OP_LEN_4 | FLOWSPEC_OP_EQ;
            if (j == nvals - 1) {
                vals[j].op |= FLOWSPEC_OP_END;
            }
            vals[j].value = (uint32_t)(1000 + j);
        }
        comps[i].values = vals;
        comps[i].num_values = nvals;
    }

    rule.components = comps;
    rule.num_components = num_comps;

    len = bgp_encode_flowspec_rule(buffer, &rule);

    /*
     * With 7 components each having 8 x 5-byte (op+4-byte val) + 1 type byte:
     * each component = 1 + 8*5 = 41 bytes
     * Total body = 287 bytes > 240 => 2-byte length header 0xF11F
     */
    test_result((len == 2 + 287) &&
                (buffer[0] == 0xF1) && (buffer[1] == 0x1F),
                "NLRI length encoding: long (2-byte length >= 240)");

    for (i = 0; i < num_comps; i++) {
        free(comps[i].values);
    }
    free(comps);
}

/*
 * Test 12: Zero-length next-hop verification in generated UPDATE
 */
void test_zero_length_next_hop() {
    flowspec_rule_t            rule = make_simple_rule("10.0.0.0", 24, 80);
    flowspec_nlri_t           *nlri = flowspec_nlri_create(&rule);
    bgp_path_attr_t           *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t                   asns[] = {65001};
    as_path_segment_t          segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t           *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_update_result_t       *result;
    bgp_flowspec_update_opts_t opts = {.afi = AFI_IPV4, .safi = SAFI_FLOWSPEC};
    const uint8_t             *value = NULL;
    uint16_t                   length = 0;
    int                        passed;

    origin->next = as_path;
    result = bgp_generate_update_flowspec(nlri, origin, NULL, &opts);
    assert(result != NULL);

    // MP_REACH_NLRI: AFI(2) + SAFI(1) + NH_LEN(1) + ...
    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI, &value, &length) &&
             (value[0] == 0x00) && (value[1] == AFI_IPV4) &&
             (value[2] == SAFI_FLOWSPEC) &&
             (value[3] == 0);  /* NH_LEN = 0 */

    bgp_update_result_free(result);
    flowspec_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    free_simple_rule(&rule);
    test_result(passed, "FlowSpec zero-length next-hop in MP_REACH_NLRI");
}

/*
 * Test 13: Full UPDATE generation with correct AFI/SAFI
 */
void test_full_update_generation() {
    flowspec_rule_t            rule = make_simple_rule("192.168.0.0", 16, 443);
    flowspec_nlri_t           *nlri = flowspec_nlri_create(&rule);
    bgp_path_attr_t           *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t                   asns[] = {65001, 65002};
    as_path_segment_t          segment = {BGP_AS_SEQUENCE, 2, asns};
    bgp_path_attr_t           *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_update_result_t       *result;
    bgp_flowspec_update_opts_t opts = {.afi = AFI_IPV4, .safi = SAFI_FLOWSPEC};
    const uint8_t             *value = NULL;
    uint16_t                   length = 0;
    int                        passed;

    origin->next = as_path;
    result = bgp_generate_update_flowspec(nlri, origin, NULL, &opts);
    assert(result != NULL);

    passed = (result->num_messages == 1) &&
             find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI, &value, &length) &&
             has_attr(result->messages[0], result->message_lens[0], BGP_ATTR_ORIGIN) &&
             has_attr(result->messages[0], result->message_lens[0], BGP_ATTR_AS_PATH) &&
             // AFI = IPv4
             (read_u16(value) == AFI_IPV4) &&
             // SAFI = FlowSpec
             (value[2] == SAFI_FLOWSPEC);

    bgp_update_result_free(result);
    flowspec_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    free_simple_rule(&rule);
    test_result(passed, "Full FlowSpec UPDATE generation");
}

/*
 * Test 14: Traffic Rate extended community
 */
void test_traffic_rate_community() {
    bgp_path_attr_t *attr = bgp_attr_create_flowspec_rate(65001, 0.0f);
    uint16_t         as_net;
    uint32_t         rate_bits;
    float            rate;
    int              passed;

    assert(attr != NULL);
    passed = (attr->flags == (BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANSITIVE)) &&
             (attr->type_code == BGP_ATTR_EXT_COMM) &&
             (attr->length == 8) &&
             (attr->value[0] == 0x80) &&
             (attr->value[1] == 0x06);

    memcpy(&as_net, attr->value + 2, 2);
    as_net = ntohs(as_net);
    passed = passed && (as_net == 65001);

    // Rate = 0.0f means discard
    memcpy(&rate_bits, attr->value + 4, 4);
    rate_bits = ntohl(rate_bits);
    memcpy(&rate, &rate_bits, sizeof(rate));
    passed = passed && (rate == 0.0f);

    bgp_path_attr_free(attr);
    test_result(passed, "Traffic Rate extended community (discard)");
}

/*
 * Test 15: Traffic Rate extended community with non-zero rate
 */
void test_traffic_rate_nonzero() {
    float            input_rate = 1500.0f;
    bgp_path_attr_t *attr = bgp_attr_create_flowspec_rate(65000, input_rate);
    uint32_t         rate_bits;
    float            rate;
    int              passed;

    assert(attr != NULL);
    memcpy(&rate_bits, attr->value + 4, 4);
    rate_bits = ntohl(rate_bits);
    memcpy(&rate, &rate_bits, sizeof(rate));
    passed = (fabsf(rate - input_rate) < 0.01f);

    bgp_path_attr_free(attr);
    test_result(passed, "Traffic Rate extended community (1500 bytes/sec)");
}

void test_traffic_rate_packets_community() {
    float input_rate = 9000.0f;
    bgp_path_attr_t *attr =
        bgp_attr_create_flowspec_rate_pkts(64512, input_rate);
    uint16_t as_net;
    uint32_t rate_bits;
    float    rate;
    int      passed;

    assert(attr != NULL);
    passed = (attr->value[0] == 0x80) &&
             (attr->value[1] == 0x0c);

    memcpy(&as_net, attr->value + 2, 2);
    as_net = ntohs(as_net);
    memcpy(&rate_bits, attr->value + 4, 4);
    rate_bits = ntohl(rate_bits);
    memcpy(&rate, &rate_bits, sizeof(rate));
    passed = passed && (as_net == 64512) &&
             (fabsf(rate - input_rate) < 0.01f);

    bgp_path_attr_free(attr);
    test_result(passed, "Traffic-Rate-Packets extended community");
}

/*
 * Test 16: Traffic Action extended community
 */
void test_traffic_action_community() {
    bgp_path_attr_t *attr_both = bgp_attr_create_flowspec_action(1, 1);
    bgp_path_attr_t *attr_term = bgp_attr_create_flowspec_action(1, 0);
    bgp_path_attr_t *attr_samp = bgp_attr_create_flowspec_action(0, 1);
    bgp_path_attr_t *attr_none = bgp_attr_create_flowspec_action(0, 0);
    int              passed;

    assert(attr_both && attr_term && attr_samp && attr_none);

    passed = (attr_both->value[0] == 0x80) &&
             (attr_both->value[1] == 0x07) &&
             (attr_both->value[7] == 0x03) &&  /* terminal + sample */
             (attr_term->value[7] == 0x01) &&  /* terminal only     */
             (attr_samp->value[7] == 0x02) &&  /* sample only       */
             (attr_none->value[7] == 0x00);    /* no flags          */

    // Verify bytes 2-6 are zero
    passed = passed && (attr_both->value[2] == 0) &&
             (attr_both->value[3] == 0) &&
             (attr_both->value[4] == 0) &&
             (attr_both->value[5] == 0) &&
             (attr_both->value[6] == 0);

    bgp_path_attr_free(attr_both);
    bgp_path_attr_free(attr_term);
    bgp_path_attr_free(attr_samp);
    bgp_path_attr_free(attr_none);
    test_result(passed, "Traffic Action extended community");
}

/*
 * Test 17: Redirect Route Target extended community
 */
void test_redirect_rt_community() {
    bgp_path_attr_t *attr = bgp_attr_create_flowspec_redirect_rt(65001, 100);
    uint16_t         as_net;
    uint32_t         val_net;
    int              passed;

    assert(attr != NULL);
    passed = (attr->value[0] == 0x80) &&
             (attr->value[1] == 0x08);

    memcpy(&as_net, attr->value + 2, 2);
    as_net = ntohs(as_net);
    memcpy(&val_net, attr->value + 4, 4);
    val_net = ntohl(val_net);
    passed = passed && (as_net == 65001) && (val_net == 100);

    bgp_path_attr_free(attr);
    test_result(passed, "Redirect Route Target extended community");
}

void test_redirect_rt_ipv4_community() {
    bgp_path_attr_t *attr =
        bgp_attr_create_flowspec_redirect_rt_ip(0x0A000001, 1234);
    int passed;

    assert(attr != NULL);
    passed = (attr->value[0] == 0x81) &&
             (attr->value[1] == 0x08) &&
             (read_u32(attr->value + 2) == 0x0A000001) &&
             (read_u16(attr->value + 6) == 1234);

    bgp_path_attr_free(attr);
    test_result(passed, "Redirect Route Target IPv4 format");
}

void test_redirect_rt_as4_community() {
    bgp_path_attr_t *attr =
        bgp_attr_create_flowspec_redirect_rt_as4(4200000000U, 321);
    int passed;

    assert(attr != NULL);
    passed = (attr->value[0] == 0x82) &&
             (attr->value[1] == 0x08) &&
             (read_u32(attr->value + 2) == 4200000000U) &&
             (read_u16(attr->value + 6) == 321);

    bgp_path_attr_free(attr);
    test_result(passed, "Redirect Route Target AS4 format");
}

/*
 * Test 18: Traffic Marking extended community
 */
void test_traffic_marking_community() {
    bgp_path_attr_t *attr = bgp_attr_create_flowspec_marking(46);
    int              passed;

    assert(attr != NULL);
    passed = (attr->value[0] == 0x80) &&
             (attr->value[1] == 0x09) &&
             (attr->value[2] == 0) &&
             (attr->value[3] == 0) &&
             (attr->value[4] == 0) &&
             (attr->value[5] == 0) &&
             (attr->value[6] == 0) &&
             (attr->value[7] == 46);  /* DSCP = 46 (EF) */

    bgp_path_attr_free(attr);
    test_result(passed, "Traffic Marking extended community (DSCP=46)");
}

/*
 * Test 19: ADD-PATH support
 */
void test_flowspec_add_path() {
    flowspec_rule_t            rule = make_simple_rule("10.0.0.0", 24, 80);
    flowspec_nlri_t           *nlri = flowspec_nlri_create_path_id(&rule, 42);
    flowspec_nlri_t           *nlri_tail = nlri;
    flowspec_rule_t            rule2 = make_simple_rule("10.1.0.0", 24, 443);
    flowspec_nlri_t           *nlri2 = flowspec_nlri_create_path_id(&rule2, 43);
    bgp_path_attr_t           *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t                   asns[] = {65001};
    as_path_segment_t          segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t           *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_update_result_t       *result;
    bgp_flowspec_update_opts_t opts = {.afi = AFI_IPV4, .safi = SAFI_FLOWSPEC};
    const uint8_t             *value = NULL;
    uint16_t                   length = 0;
    int                        nlri_offset;
    int                        passed;

    flowspec_nlri_append(&nlri, &nlri_tail, nlri2);
    origin->next = as_path;
    result = bgp_generate_update_flowspec(nlri, origin, NULL, &opts);
    assert(result != NULL);

    // Find the NLRI section in MP_REACH
    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI, &value, &length);

    // Skip AFI(2) + SAFI(1) + NH_LEN(1) + NH(0) + reserved(1)
    nlri_offset = 5;

    // First 4 bytes should be path_id=42
    passed = passed && (read_u32(value + nlri_offset) == 42);

    bgp_update_result_free(result);
    flowspec_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    free_simple_rule(&rule);
    free_simple_rule(&rule2);
    test_result(passed, "FlowSpec ADD-PATH support");
}

/*
 * Test 20: Withdrawal generation
 */
void test_flowspec_withdrawal() {
    flowspec_rule_t            rule = make_simple_rule("10.0.0.0", 24, 80);
    flowspec_nlri_t           *withdrawn = flowspec_nlri_create(&rule);
    bgp_update_result_t       *result;
    bgp_flowspec_update_opts_t opts = {.afi = AFI_IPV4, .safi = SAFI_FLOWSPEC};
    int                        passed;

    result = bgp_generate_update_flowspec(NULL, NULL, withdrawn, &opts);
    assert(result != NULL);

    passed = (result->num_messages == 1) &&
             has_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_UNREACH_NLRI) &&
             !has_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI);

    bgp_update_result_free(result);
    flowspec_nlri_list_free(withdrawn);
    free_simple_rule(&rule);
    test_result(passed, "FlowSpec withdrawal generation");
}

/*
 * Test 21: Withdrawal with ADD-PATH
 */
void test_flowspec_withdrawal_add_path() {
    flowspec_rule_t            rule = make_simple_rule("10.0.0.0", 24, 80);
    flowspec_nlri_t           *withdrawn = flowspec_nlri_create_path_id(&rule, 99);
    bgp_update_result_t       *result;
    bgp_flowspec_update_opts_t opts = {.afi = AFI_IPV4, .safi = SAFI_FLOWSPEC};
    const uint8_t             *value = NULL;
    uint16_t                   length = 0;
    int                        offset;
    int                        passed;

    result = bgp_generate_update_flowspec(NULL, NULL, withdrawn, &opts);
    assert(result != NULL);

    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_UNREACH_NLRI, &value, &length);
    // Skip AFI(2) + SAFI(1) = 3 bytes to reach NLRI
    offset = 3;
    // First 4 bytes of NLRI should be path_id=99
    passed = passed && (read_u32(value + offset) == 99);

    bgp_update_result_free(result);
    flowspec_nlri_list_free(withdrawn);
    free_simple_rule(&rule);
    test_result(passed, "FlowSpec withdrawal with ADD-PATH");
}

/*
 * Test 22: IPv6 FlowSpec full UPDATE generation
 */
void test_flowspec_ipv6_update_generation() {
    flowspec_rule_t            rule = make_simple_rule_ipv6("2001:db8::", 0, 64, 80);
    flowspec_nlri_t           *nlri = flowspec_nlri_create(&rule);
    bgp_path_attr_t           *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t                   asns[] = {65001};
    as_path_segment_t          segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t           *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_update_result_t       *result;
    bgp_flowspec_update_opts_t opts = {.afi = AFI_IPV6, .safi = SAFI_FLOWSPEC};
    const uint8_t             *value = NULL;
    uint16_t                   length = 0;
    int                        passed;

    origin->next = as_path;
    result = bgp_generate_update_flowspec(nlri, origin, NULL, &opts);
    assert(result != NULL);

    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI, &value, &length) &&
             (read_u16(value) == AFI_IPV6) &&
             (value[2] == SAFI_FLOWSPEC) &&
             (value[3] == 0);

    bgp_update_result_free(result);
    flowspec_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    free_simple_rule(&rule);
    test_result(passed, "IPv6 FlowSpec UPDATE generation");
}

/*
 * Test 23: IPv6 FlowSpec ADD-PATH
 */
void test_flowspec_ipv6_add_path() {
    flowspec_rule_t            rule = make_simple_rule_ipv6("2001:db8::", 0, 64, 80);
    flowspec_nlri_t           *nlri = flowspec_nlri_create_path_id(&rule, 77);
    bgp_path_attr_t           *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t                   asns[] = {65001};
    as_path_segment_t          segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t           *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_update_result_t       *result;
    bgp_flowspec_update_opts_t opts = {.afi = AFI_IPV6, .safi = SAFI_FLOWSPEC};
    const uint8_t             *value = NULL;
    uint16_t                   length = 0;
    int                        nlri_offset;
    int                        passed;

    origin->next = as_path;
    result = bgp_generate_update_flowspec(nlri, origin, NULL, &opts);
    assert(result != NULL);

    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI, &value, &length) &&
             (read_u16(value) == AFI_IPV6) &&
             (value[2] == SAFI_FLOWSPEC);
    nlri_offset = 5;
    passed = passed && (read_u32(value + nlri_offset) == 77);

    bgp_update_result_free(result);
    flowspec_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    free_simple_rule(&rule);
    test_result(passed, "IPv6 FlowSpec ADD-PATH support");
}

/*
 * Test 22: NLRI create deep-copies rule
 */
void test_nlri_create_deep_copy() {
    flowspec_rule_t  rule = make_simple_rule("10.0.0.0", 24, 80);
    flowspec_nlri_t *nlri = flowspec_nlri_create(&rule);
    int              passed;

    assert(nlri != NULL);

    // Verify the NLRI rule is a deep copy (different pointers)
    passed = (nlri->rule.components != rule.components) &&
             (nlri->rule.num_components == rule.num_components) &&
             (nlri->rule.components[0].type == FLOWSPEC_DEST_PREFIX) &&
             (nlri->rule.components[1].type == FLOWSPEC_DEST_PORT) &&
             (nlri->rule.components[1].values != rule.components[1].values);

    flowspec_nlri_list_free(nlri);
    free_simple_rule(&rule);
    test_result(passed, "NLRI create deep-copies rule");
}

/*
 * Test 23: NLRI list operations
 */
void test_nlri_list_ops() {
    flowspec_rule_t  rule1 = make_simple_rule("10.0.0.0", 24, 80);
    flowspec_rule_t  rule2 = make_simple_rule("10.1.0.0", 24, 443);
    flowspec_rule_t  rule3 = make_simple_rule("10.2.0.0", 24, 8080);
    flowspec_nlri_t *nlri1 = flowspec_nlri_create(&rule1);
    flowspec_nlri_t *nlri2 = flowspec_nlri_create(&rule2);
    flowspec_nlri_t *nlri3 = flowspec_nlri_create(&rule3);
    flowspec_nlri_t *head = NULL;
    flowspec_nlri_t *tail = NULL;
    int              passed;

    flowspec_nlri_append(&head, &tail, nlri1);
    flowspec_nlri_append(&head, &tail, nlri2);
    flowspec_nlri_append(&head, &tail, nlri3);

    passed = (flowspec_nlri_count(head) == 3) &&
             (head == nlri1) &&
             (tail == nlri3) &&
             (head->next == nlri2) &&
             (head->next->next == nlri3);

    flowspec_nlri_list_free(head);
    free_simple_rule(&rule1);
    free_simple_rule(&rule2);
    free_simple_rule(&rule3);
    test_result(passed, "NLRI list operations (append/count)");
}

/*
 * Test 24: Validate empty/null rule is rejected
 */
void test_validate_empty_rule() {
    flowspec_rule_t empty_rule = { .components = NULL, .num_components = 0 };
    int             passed;

    passed = (bgp_validate_flowspec_rule(&empty_rule) == -1) &&
             (bgp_validate_flowspec_rule(NULL) == -1);

    test_result(passed, "Validate empty/null rule rejected");
}

/*
 * Test 25: Validate component type out of range
 */
void test_validate_component_type_range() {
    flowspec_component_t comp;
    flowspec_rule_t      rule;
    int                  passed;

    memset(&comp, 0, sizeof(comp));
    comp.type = 0;  /* Invalid: type must be 1-12 */
    comp.prefix_len = 24;
    inet_pton(AF_INET, "10.0.0.0", comp.prefix);
    rule.components = &comp;
    rule.num_components = 1;
    passed = (bgp_validate_flowspec_rule(&rule) == -1);

    comp.type = 13;  /* Invalid: type must be 1-12 */
    passed = passed && (bgp_validate_flowspec_rule(&rule) == -1);

    comp.type = 12;  /* Valid: max type */
    comp.values = &(flowspec_op_value_t){FLOWSPEC_OP_END | FLOWSPEC_OP_MATCH, 0x01};
    comp.num_values = 1;
    passed = passed && (bgp_validate_flowspec_rule(&rule) == 0);

    test_result(passed, "Validate component type range (1-12)");
}

/*
 * Test 26: Single-component rule encoding (dest prefix only)
 */
void test_single_component_rule() {
    flowspec_rule_t      rule;
    flowspec_component_t comp;
    uint8_t              buffer[64];
    int                  len;

    memset(&comp, 0, sizeof(comp));
    comp.type = FLOWSPEC_DEST_PREFIX;
    comp.prefix_len = 32;
    inet_pton(AF_INET, "192.168.1.1", comp.prefix);
    rule.components = &comp;
    rule.num_components = 1;

    len = bgp_encode_flowspec_rule(buffer, &rule);

    // length(1) + type(1) + plen(1) + 4 prefix bytes = 7
    test_result((len == 7) &&
                (buffer[0] == 6) &&  /* body = type(1)+plen(1)+prefix(4) = 6 */
                (buffer[1] == FLOWSPEC_DEST_PREFIX) &&
                (buffer[2] == 32),
                "Single-component rule encoding (dest /32)");
}

/*
 * Test 27: Op-value encoding - direct test
 */
void test_op_value_encoding() {
    flowspec_op_value_t ov;
    uint8_t             buffer[16];
    int                 len;

    // 1-byte value
    ov.op = FLOWSPEC_OP_END | FLOWSPEC_OP_LEN_1 | FLOWSPEC_OP_EQ;
    ov.value = 17;  /* UDP */
    len = bgp_encode_flowspec_op_value(buffer, &ov);
    test_result((len == 2) && (buffer[0] == ov.op) && (buffer[1] == 17), "Op-value encoding: 1-byte value");
}

/*
 * Test 28: Multiple rules in single UPDATE
 */
void test_multiple_rules_update() {
    flowspec_rule_t            rule1 = make_simple_rule("10.0.0.0", 8, 80);
    flowspec_rule_t            rule2 = make_simple_rule("172.16.0.0", 12, 443);
    flowspec_nlri_t           *nlri1 = flowspec_nlri_create(&rule1);
    flowspec_nlri_t           *nlri2 = flowspec_nlri_create(&rule2);
    flowspec_nlri_t           *head = nlri1;
    flowspec_nlri_t           *tail = nlri1;
    bgp_path_attr_t           *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t                   asns[] = {65001};
    as_path_segment_t          segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t           *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_update_result_t       *result;
    bgp_flowspec_update_opts_t opts = {.afi = AFI_IPV4, .safi = SAFI_FLOWSPEC};
    const uint8_t             *value = NULL;
    uint16_t                   length = 0;
    int                        passed;

    flowspec_nlri_append(&head, &tail, nlri2);
    origin->next = as_path;
    result = bgp_generate_update_flowspec(head, origin, NULL, &opts);
    assert(result != NULL);

    // Should produce a single UPDATE with both rules
    passed = (result->num_messages == 1) &&
             find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI, &value, &length) &&
             // NLRI section should contain both rules
             (length > 15);

    bgp_update_result_free(result);
    flowspec_nlri_list_free(head);
    bgp_path_attr_list_free(origin);
    free_simple_rule(&rule1);
    free_simple_rule(&rule2);
    test_result(passed, "Multiple rules in single UPDATE");
}

/*
 * Test 29: UPDATE with traffic filtering action attributes
 */
void test_update_with_traffic_actions() {
    flowspec_rule_t            rule = make_simple_rule("10.0.0.0", 24, 80);
    flowspec_nlri_t           *nlri = flowspec_nlri_create(&rule);
    bgp_path_attr_t           *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t                   asns[] = {65001};
    as_path_segment_t          segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t           *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_path_attr_t           *rate = bgp_attr_create_flowspec_rate(0, 0.0f);
    bgp_update_result_t       *result;
    bgp_flowspec_update_opts_t opts = {.afi = AFI_IPV4, .safi = SAFI_FLOWSPEC};
    int                        passed;

    origin->next = as_path;
    as_path->next = rate;

    result = bgp_generate_update_flowspec(nlri, origin, NULL, &opts);
    assert(result != NULL);

    // Should contain ORIGIN, AS_PATH, EXT_COMM, and MP_REACH
    passed = (result->num_messages == 1) &&
             has_attr(result->messages[0], result->message_lens[0], BGP_ATTR_ORIGIN) &&
             has_attr(result->messages[0], result->message_lens[0], BGP_ATTR_AS_PATH) &&
             has_attr(result->messages[0], result->message_lens[0], BGP_ATTR_EXT_COMM) &&
             has_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI);

    bgp_update_result_free(result);
    flowspec_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    free_simple_rule(&rule);
    test_result(passed, "UPDATE with traffic filtering actions");
}

/*
 * Test 30: DSCP component encoding
 */
void test_encode_dscp_component() {
    flowspec_component_t comp;
    flowspec_op_value_t  vals[1];
    uint8_t              buffer[64];
    int                  len;

    memset(&comp, 0, sizeof(comp));
    comp.type = FLOWSPEC_DSCP;
    vals[0].op = FLOWSPEC_OP_END | FLOWSPEC_OP_LEN_1 | FLOWSPEC_OP_EQ;
    vals[0].value = 46;  /* EF PHB */
    comp.values = vals;
    comp.num_values = 1;

    len = bgp_encode_flowspec_component(buffer, &comp);

    test_result((len == 3) && (buffer[0] == FLOWSPEC_DSCP) && (buffer[2] == 46), "Component encoding: DSCP value");
}

/*
 * Test 31: ICMP type component
 */
void test_encode_icmp_type() {
    flowspec_component_t comp;
    flowspec_op_value_t  vals[1];
    uint8_t              buffer[64];
    int                  len;

    memset(&comp, 0, sizeof(comp));
    comp.type = FLOWSPEC_ICMP_TYPE;
    vals[0].op = FLOWSPEC_OP_END | FLOWSPEC_OP_LEN_1 | FLOWSPEC_OP_EQ;
    vals[0].value = 8;  /* Echo Request */
    comp.values = vals;
    comp.num_values = 1;

    len = bgp_encode_flowspec_component(buffer, &comp);

    test_result((len == 3) && (buffer[0] == FLOWSPEC_ICMP_TYPE) && (buffer[2] == 8), "Component encoding: ICMP type");
}

/*
 * Test 32: ICMP code component
 */
void test_encode_icmp_code() {
    flowspec_component_t comp;
    flowspec_op_value_t  vals[1];
    uint8_t              buffer[64];
    int                  len;

    memset(&comp, 0, sizeof(comp));
    comp.type = FLOWSPEC_ICMP_CODE;
    vals[0].op = FLOWSPEC_OP_END | FLOWSPEC_OP_LEN_1 | FLOWSPEC_OP_EQ;
    vals[0].value = 0;  /* No code */
    comp.values = vals;
    comp.num_values = 1;

    len = bgp_encode_flowspec_component(buffer, &comp);

    test_result((len == 3) && (buffer[0] == FLOWSPEC_ICMP_CODE) && (buffer[2] == 0), "Component encoding: ICMP code");
}

/*
 * Test 33: Source port component
 */
void test_encode_src_port() {
    flowspec_component_t comp;
    flowspec_op_value_t  vals[1];
    uint8_t              buffer[64];
    int                  len;

    memset(&comp, 0, sizeof(comp));
    comp.type = FLOWSPEC_SRC_PORT;
    vals[0].op = FLOWSPEC_OP_END | FLOWSPEC_OP_LEN_2 | FLOWSPEC_OP_EQ;
    vals[0].value = 12345;
    comp.values = vals;
    comp.num_values = 1;

    len = bgp_encode_flowspec_component(buffer, &comp);

    // type(1) + op(1) + value(2) = 4
    test_result((len == 4) && (buffer[0] == FLOWSPEC_SRC_PORT), "Component encoding: source port");
}

/*
 * Test 34: Message splitting with many FlowSpec rules
 */
void test_flowspec_message_splitting() {
    flowspec_nlri_t           *head = NULL;
    flowspec_nlri_t           *tail = NULL;
    bgp_path_attr_t           *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t                   asns[] = {65001};
    as_path_segment_t          segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t           *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_update_result_t       *result;
    bgp_flowspec_update_opts_t opts = {.afi = AFI_IPV4, .safi = SAFI_FLOWSPEC, .max_pdu_size = 256};
    int                        passed;
    int                        i;

    for (i = 0; i < 50; i++) {
        char             prefix[32];
        flowspec_rule_t  rule;
        flowspec_nlri_t *new_nlri;

        snprintf(prefix, sizeof(prefix), "10.%d.0.0", i);
        rule = make_simple_rule(prefix, 16, (uint16_t)(80 + i));
        new_nlri = flowspec_nlri_create(&rule);
        flowspec_nlri_append(&head, &tail, new_nlri);
        free_simple_rule(&rule);
    }

    origin->next = as_path;
    result = bgp_generate_update_flowspec(head, origin, NULL, &opts);
    assert(result != NULL);

    // With 50 rules and max PDU 256, must split into multiple messages
    passed = (result->num_messages > 1);
    for (i = 0; i < result->num_messages; i++) {
        if (result->message_lens[i] > 256 ||
            test_wire_path_attr_len(result->messages[i], result->message_lens[i]) <= 0 ||
            !has_attr(result->messages[i], result->message_lens[i], BGP_ATTR_MP_REACH_NLRI)) {
            passed = 0;
        }
    }

    bgp_update_result_free(result);
    bgp_path_attr_list_free(origin);
    flowspec_nlri_list_free(head);
    test_result(passed, "FlowSpec message splitting");
}

/*
 * Test 35: Redirect RT boundary values
 */
void test_redirect_rt_boundary() {
    bgp_path_attr_t *attr_zero = bgp_attr_create_flowspec_redirect_rt(0, 0);
    bgp_path_attr_t *attr_max = bgp_attr_create_flowspec_redirect_rt(65535, 4294967295U);
    uint16_t         as_net;
    uint32_t         val_net;
    int              passed;

    assert(attr_zero && attr_max);

    // All-zero case
    memcpy(&as_net, attr_zero->value + 2, 2);
    memcpy(&val_net, attr_zero->value + 4, 4);
    passed = (ntohs(as_net) == 0) && (ntohl(val_net) == 0);

    // Max values
    memcpy(&as_net, attr_max->value + 2, 2);
    memcpy(&val_net, attr_max->value + 4, 4);
    passed = passed && (ntohs(as_net) == 65535) && (ntohl(val_net) == 4294967295U);

    bgp_path_attr_free(attr_zero);
    bgp_path_attr_free(attr_max);
    test_result(passed, "Redirect RT boundary values");
}

/*
 * Test 36: Traffic Marking DSCP boundary values
 */
void test_traffic_marking_boundary() {
    bgp_path_attr_t *attr_zero = bgp_attr_create_flowspec_marking(0);
    bgp_path_attr_t *attr_max = bgp_attr_create_flowspec_marking(63);
    int              passed;

    assert(attr_zero && attr_max);

    passed = (attr_zero->value[7] == 0) &&
             (attr_max->value[7] == 63);

    bgp_path_attr_free(attr_zero);
    bgp_path_attr_free(attr_max);
    test_result(passed, "Traffic Marking DSCP boundary (0 and 63)");
}

/*
 * Test 37: Complex multi-component rule
 */
void test_complex_rule() {
    flowspec_rule_t      rule;
    flowspec_component_t comps[4];
    flowspec_op_value_t  proto_vals[1];
    flowspec_op_value_t  port_vals[2];
    flowspec_op_value_t  flag_vals[1];
    uint8_t              buffer[256];
    int                  len;

    memset(comps, 0, sizeof(comps));

    // Dest prefix: 10.0.0.0/8
    comps[0].type = FLOWSPEC_DEST_PREFIX;
    comps[0].prefix_len = 8;
    inet_pton(AF_INET, "10.0.0.0", comps[0].prefix);

    // IP protocol: TCP (6)
    proto_vals[0].op = FLOWSPEC_OP_END | FLOWSPEC_OP_LEN_1 | FLOWSPEC_OP_EQ;
    proto_vals[0].value = 6;
    comps[1].type = FLOWSPEC_IP_PROTOCOL;
    comps[1].values = proto_vals;
    comps[1].num_values = 1;

    // Port range: 80-443
    port_vals[0].op = FLOWSPEC_OP_LEN_1 | FLOWSPEC_OP_GT | FLOWSPEC_OP_EQ;
    port_vals[0].value = 80;
    port_vals[1].op = FLOWSPEC_OP_END | FLOWSPEC_OP_AND | FLOWSPEC_OP_LEN_2 |
                      FLOWSPEC_OP_LT | FLOWSPEC_OP_EQ;
    port_vals[1].value = 443;
    comps[2].type = FLOWSPEC_PORT;
    comps[2].values = port_vals;
    comps[2].num_values = 2;

    // TCP flags: match SYN
    flag_vals[0].op = FLOWSPEC_OP_END | FLOWSPEC_OP_LEN_1 | FLOWSPEC_OP_MATCH;
    flag_vals[0].value = 0x02;
    comps[3].type = FLOWSPEC_TCP_FLAGS;
    comps[3].values = flag_vals;
    comps[3].num_values = 1;

    rule.components = comps;
    rule.num_components = 4;

    len = bgp_encode_flowspec_rule(buffer, &rule);

    /*
     * Body:
     *   dest prefix: 1+1+1 = 3 (type + plen + 1 prefix byte for /8)
     *   ip proto:    1+1+1 = 3 (type + op + value)
     *   port:        1+1+1+1+2 = 6 (type + op+val + op+val)
     *   tcp flags:   1+1+1 = 3 (type + op + value)
     * Total body = 15
     * Length prefix: 1 byte (< 240)
     * Total = 16
     */
    test_result((len == 16) && (buffer[0] == 15), "Complex multi-component rule encoding");
}

/*
 * Test 38: Packet length component with GT operator
 */
void test_encode_packet_len_gt() {
    flowspec_component_t comp;
    flowspec_op_value_t  vals[1];
    uint8_t              buffer[64];
    int                  len;

    memset(&comp, 0, sizeof(comp));
    comp.type = FLOWSPEC_PACKET_LEN;
    vals[0].op = FLOWSPEC_OP_END | FLOWSPEC_OP_LEN_2 | FLOWSPEC_OP_GT;
    vals[0].value = 1500;
    comp.values = vals;
    comp.num_values = 1;

    len = bgp_encode_flowspec_component(buffer, &comp);

    // type(1) + op(1) + value(2) = 4
    test_result((len == 4) && (buffer[0] == FLOWSPEC_PACKET_LEN), "Component encoding: packet length > 1500");
}

/*
 * Test 39: Rejection of pre-existing MP attributes
 */
void test_reject_preexisting_mp_attrs() {
    flowspec_rule_t            rule = make_simple_rule("10.0.0.0", 24, 80);
    flowspec_nlri_t           *nlri = flowspec_nlri_create(&rule);
    bgp_path_attr_t           *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    bgp_path_attr_t           *mp_reach = bgp_attr_create_mp_reach_raw(AFI_IPV4, SAFI_FLOWSPEC, NULL, 0, NULL, 0);
    bgp_update_result_t       *result;
    bgp_flowspec_update_opts_t opts = {.afi = AFI_IPV4, .safi = SAFI_FLOWSPEC};

    origin->next = mp_reach;
    result = bgp_generate_update_flowspec(nlri, origin, NULL, &opts);

    // Should reject because caller already supplied MP_REACH_NLRI
    test_result(result == NULL, "Reject pre-existing MP_REACH_NLRI in attrs");

    flowspec_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    free_simple_rule(&rule);
}

/*
 * Test 40: Dest prefix /0 (default route)
 */
void test_dest_prefix_default() {
    flowspec_component_t comp;
    uint8_t              buffer[64];
    int                  len;

    memset(&comp, 0, sizeof(comp));
    comp.type = FLOWSPEC_DEST_PREFIX;
    comp.prefix_len = 0;

    len = bgp_encode_flowspec_component(buffer, &comp);

    // type(1) + prefix_len(1) + 0 prefix bytes = 2
    test_result((len == 2) &&
                (buffer[0] == FLOWSPEC_DEST_PREFIX) &&
                (buffer[1] == 0),
                "Component encoding: dest prefix /0 (default)");
}

// RFC 8955 / RFC 8956 operator and length rules

/*
 * Encode a rule of one port component and return the rule encoder result.
 */
static int encode_port_list(const flowspec_op_value_t *vals, int num_values, uint8_t type) {
    uint8_t              buffer[8192];
    flowspec_component_t comp;
    flowspec_rule_t      rule = { &comp, 1 };

    memset(&comp, 0, sizeof(comp));
    comp.type = type;
    comp.values = (flowspec_op_value_t *)vals;
    comp.num_values = num_values;
    return bgp_encode_flowspec_rule_afi(buffer, &rule, AFI_IPV4);
}

/*
 * Test 41: Reject malformed operator lists: no end bit, an early end bit, AND on the first pair, a reserved bit,
 * a value wider than its length, an empty list
 */
void test_reject_bad_operator_lists() {
    flowspec_op_value_t no_end[1] = {{FLOWSPEC_OP_EQ, 80}};
    flowspec_op_value_t early_end[2] = {{FLOWSPEC_OP_END | FLOWSPEC_OP_EQ, 80},
                                        {FLOWSPEC_OP_END | FLOWSPEC_OP_EQ, 81}};
    flowspec_op_value_t first_and[2] = {{FLOWSPEC_OP_AND | FLOWSPEC_OP_GT, 80},
                                        {FLOWSPEC_OP_END | FLOWSPEC_OP_LT, 90}};
    flowspec_op_value_t num_reserved[1] = {{FLOWSPEC_OP_END | FLOWSPEC_NUMERIC_OP_RESERVED | FLOWSPEC_OP_EQ, 80}};
    flowspec_op_value_t too_wide[1] = {{FLOWSPEC_OP_END | FLOWSPEC_OP_LEN_1 | FLOWSPEC_OP_EQ, 443}};
    flowspec_op_value_t good[2] = {{FLOWSPEC_OP_GT | FLOWSPEC_OP_EQ, 80},
                                   {FLOWSPEC_OP_END | FLOWSPEC_OP_AND | FLOWSPEC_OP_LEN_2 | FLOWSPEC_OP_LT, 1024}};
    int passed = 1;

    passed &= (encode_port_list(no_end, 1, FLOWSPEC_DEST_PORT) == -1);
    passed &= (encode_port_list(early_end, 2, FLOWSPEC_DEST_PORT) == -1);
    passed &= (encode_port_list(first_and, 2, FLOWSPEC_DEST_PORT) == -1);
    passed &= (encode_port_list(num_reserved, 1, FLOWSPEC_DEST_PORT) == -1);
    passed &= (encode_port_list(too_wide, 1, FLOWSPEC_DEST_PORT) == -1);
    passed &= (encode_port_list(good, 0, FLOWSPEC_DEST_PORT) == -1);  /* empty list */
    passed &= (encode_port_list(good, 2, FLOWSPEC_DEST_PORT) == 1 + 1 + 2 + 3);
    test_result(passed, "Reject malformed operator lists (end bit, first AND, reserved, width, empty)");
}

/*
 * Test 42: Bitmask, DSCP and fragment widths and bits follow the RFC 8955 MUST rules
 */
void test_reject_bad_bitmask_widths() {
    flowspec_op_value_t tcp4[1] = {{FLOWSPEC_OP_END | FLOWSPEC_OP_LEN_4 | FLOWSPEC_OP_MATCH, FLOWSPEC_TCP_SYN}};
    flowspec_op_value_t tcp2[1] = {{FLOWSPEC_OP_END | FLOWSPEC_OP_LEN_2 | FLOWSPEC_OP_MATCH, FLOWSPEC_TCP_SYN}};
    flowspec_op_value_t bm_reserved[1] = {{FLOWSPEC_OP_END | 0x04 | FLOWSPEC_OP_MATCH, FLOWSPEC_TCP_SYN}};
    flowspec_op_value_t dscp2[1] = {{FLOWSPEC_OP_END | FLOWSPEC_OP_LEN_2 | FLOWSPEC_OP_EQ, 46}};
    flowspec_op_value_t frag_df[1] = {{FLOWSPEC_OP_END | FLOWSPEC_OP_MATCH, FLOWSPEC_FRAG_DF}};
    flowspec_op_value_t frag_bit4[1] = {{FLOWSPEC_OP_END | FLOWSPEC_OP_MATCH, 0x10}};
    int                 passed = 1;

    passed &= (encode_port_list(tcp4, 1, FLOWSPEC_TCP_FLAGS) == -1);
    passed &= (encode_port_list(tcp2, 1, FLOWSPEC_TCP_FLAGS) == 1 + 1 + 1 + 2);
    passed &= (encode_port_list(bm_reserved, 1, FLOWSPEC_TCP_FLAGS) == -1);
    passed &= (encode_port_list(dscp2, 1, FLOWSPEC_DSCP) == -1);
    passed &= (encode_port_list(frag_df, 1, FLOWSPEC_FRAGMENT) == 1 + 1 + 1 + 1);
    passed &= (encode_port_list(frag_bit4, 1, FLOWSPEC_FRAGMENT) == -1);
    test_result(passed, "Bitmask and DSCP widths follow RFC 8955 MUST rules");
}

/*
 * Test 43: IPv6 fragment bits and the Flow Label component (RFC 8956 sections 3.6 and 3.7)
 */
void test_ipv6_fragment_and_flow_label() {
    uint8_t              buffer[64];
    flowspec_component_t comps[2];
    flowspec_rule_t      rule = { comps, 2 };
    flowspec_op_value_t  frag = {FLOWSPEC_OP_END | FLOWSPEC_OP_MATCH, FLOWSPEC_FRAG_DF};
    flowspec_op_value_t  label = {FLOWSPEC_OP_END | FLOWSPEC_OP_LEN_4 | FLOWSPEC_OP_EQ, 0x12345};
    int                  passed;
    int                  len;

    memset(comps, 0, sizeof(comps));
    comps[0].type = FLOWSPEC_FRAGMENT;
    comps[0].values = &frag;
    comps[0].num_values = 1;
    comps[1].type = FLOWSPEC_FLOW_LABEL;
    comps[1].values = &label;
    comps[1].num_values = 1;

    // RFC 8956 section 3.6: no DF bit for IPv6.
    passed = (bgp_encode_flowspec_rule_afi(buffer, &rule, AFI_IPV6) == -1);

    frag.value = FLOWSPEC_FRAG_ISF;
    len = bgp_encode_flowspec_rule_afi(buffer, &rule, AFI_IPV6);
    passed = passed && (len == 1 + 3 + 6) &&
             (buffer[0] == 9) &&
             (buffer[1] == FLOWSPEC_FRAGMENT) && (buffer[2] == 0x81) && (buffer[3] == FLOWSPEC_FRAG_ISF) &&
             (buffer[4] == FLOWSPEC_FLOW_LABEL) && (buffer[5] == 0xA1) &&
             (read_u32(buffer + 6) == 0x12345);

    // Type 13 is IPv6 only.
    passed = passed && (bgp_encode_flowspec_rule_afi(buffer, &rule, AFI_IPV4) == -1);
    test_result(passed, "IPv6 fragment bits and Flow Label component (RFC 8956 3.6, 3.7)");
}

/*
 * One rule: dest prefix /24 plus a port list of n 2-octet values.
 */
static int encode_long_rule(int num_values, uint8_t op_len, uint8_t *buffer) {
    flowspec_component_t comps[2];
    flowspec_rule_t      rule = { comps, 2 };
    flowspec_op_value_t *vals = calloc((size_t)num_values, sizeof(*vals));
    int                  len;
    int                  i;

    assert(vals);
    memset(comps, 0, sizeof(comps));
    comps[0].type = FLOWSPEC_DEST_PREFIX;
    comps[0].prefix_len = 24;
    inet_pton(AF_INET, "10.0.0.0", comps[0].prefix);
    for (i = 0; i < num_values; i++) {
        vals[i].op = (uint8_t)(op_len | FLOWSPEC_OP_EQ | (i == num_values - 1 ? FLOWSPEC_OP_END : 0));
        vals[i].value = (uint32_t)(1000 + i);
    }
    comps[1].type = FLOWSPEC_PORT;
    comps[1].values = vals;
    comps[1].num_values = num_values;
    len = bgp_encode_flowspec_rule_afi(buffer, &rule, AFI_IPV4);
    free(vals);
    return len;
}

/*
 * Test 44: The NLRI value limit is 4095 octets; a longer rule fails without a length wrap or an overflow
 */
void test_nlri_length_limit() {
    static uint8_t buffer[16384];
    int passed;
    int len;

    // 5 (prefix) + 1 (type) + 1363 * 3 = 4095: the largest legal value.
    len = encode_long_rule(1363, FLOWSPEC_OP_LEN_2, buffer);
    passed = (len == 2 + FLOWSPEC_MAX_NLRI_LEN) && (buffer[0] == 0xFF) && (buffer[1] == 0xFF);

    // 4098 octets: the old encoder wrote length 0xf000 (= 0).
    passed = passed && (encode_long_rule(1364, FLOWSPEC_OP_LEN_2, buffer) == -1);

    // 5006 octets: the old encoder overflowed its stack buffer.
    passed = passed && (encode_long_rule(1000, FLOWSPEC_OP_LEN_4, buffer) == -1);
    test_result(passed, "NLRI value limit 4095 octets; no length wrap or overflow");
}

// Extended Communities

/*
 * Test 45: Color community CO types 00/01/10/11 in flag bits 0-1 (RFC 9830 section 3)
 */
void test_color_community_co_bits() {
    static const uint16_t flags[] = {0x0000, 0x4000, 0x8000, 0xC000};
    int     passed = 1;
    uint8_t co;

    for (co = 0; co <= BGP_COLOR_CO_RESERVED; co++) {
        bgp_path_attr_t *attr = bgp_attr_create_ext_comm_color(0x01020304, co);

        passed &= (attr != NULL) && (attr->type_code == BGP_ATTR_EXT_COMM) &&
                  (attr->flags == (BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANSITIVE)) &&
                  (attr->length == 8) &&
                  (attr->value[0] == 0x03) && (attr->value[1] == 0x0b) &&
                  (read_u16(attr->value + 2) == flags[co]) &&
                  (read_u32(attr->value + 4) == 0x01020304);
        bgp_path_attr_free(attr);
    }
    passed &= (bgp_attr_create_ext_comm_color(100, 4) == NULL);
    test_result(passed, "Color community: CO types 00/01/10/11 in flag bits 0-1 (RFC 9830 3)");
}

/*
 * Test 46: Color community keeps the unassigned flag bits that the caller sets
 */
void test_color_community_raw_flags() {
    bgp_path_attr_t *attr = bgp_attr_create_ext_comm_color_flags(0xFFFFFFFFu, 0x3FFF);
    int passed = (attr != NULL) && (read_u16(attr->value + 2) == 0x3FFF) &&
                 (read_u32(attr->value + 4) == 0xFFFFFFFFu);

    bgp_path_attr_free(attr);
    test_result(passed, "Color community: caller-set flags (unassigned bits)");
}

/*
 * Test 47: Redirect-to-IPv4 community 0x010c with the C bit
 */
void test_redirect_ipv4_community() {
    bgp_path_attr_t *attr = bgp_attr_create_flowspec_redirect_ipv4(0xC0000201, 0);
    bgp_path_attr_t *copy = bgp_attr_create_flowspec_redirect_ipv4(0xC0000201, 1);
    static const uint8_t want[8] = {0x01, 0x0c, 0xc0, 0x00, 0x02, 0x01, 0x00, 0x00};
    int passed = (attr != NULL) && (copy != NULL) &&
                 (attr->type_code == BGP_ATTR_EXT_COMM) && (attr->length == 8) &&
                 (memcmp(attr->value, want, 8) == 0) &&
                 (memcmp(copy->value, want, 7) == 0) && (copy->value[7] == 0x01);

    bgp_path_attr_free(attr);
    bgp_path_attr_free(copy);
    test_result(passed, "Redirect-to-IPv4 community 0x010c with C bit");
}

/*
 * Test 48: Redirect-to-IPv6 community 0x000c in attribute 25
 */
void test_redirect_ipv6_community() {
    struct in6_addr  addr;
    bgp_path_attr_t *attr;
    bgp_path_attr_t *copy;
    int              passed;

    inet_pton(AF_INET6, "2001:db8::1", &addr);
    attr = bgp_attr_create_flowspec_redirect_ipv6(&addr, 0);
    copy = bgp_attr_create_flowspec_redirect_ipv6(&addr, 1);
    passed = (attr != NULL) && (copy != NULL) &&
             (attr->type_code == BGP_ATTR_IPV6_EXT_COMM) &&
             (attr->flags == (BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANSITIVE)) &&
             (attr->length == 20) &&
             (attr->value[0] == 0x00) && (attr->value[1] == 0x0c) &&
             (memcmp(attr->value + 2, &addr, 16) == 0) &&
             (read_u16(attr->value + 18) == 0x0000) &&
             (read_u16(copy->value + 18) == 0x0001);
    bgp_path_attr_free(attr);
    bgp_path_attr_free(copy);
    test_result(passed, "Redirect-to-IPv6 community 0x000c in attribute 25");
}

/*
 * Test 49: Redirect-to-next-hop community 0x0800 with the C bit
 */
void test_redirect_nexthop_community() {
    bgp_path_attr_t *attr = bgp_attr_create_flowspec_redirect_nexthop(0);
    bgp_path_attr_t *copy = bgp_attr_create_flowspec_redirect_nexthop(1);
    static const uint8_t want[8] = {0x08, 0x00, 0, 0, 0, 0, 0, 0};
    int passed = (attr != NULL) && (copy != NULL) &&
                 (memcmp(attr->value, want, 8) == 0) &&
                 (memcmp(copy->value, want, 7) == 0) && (copy->value[7] == 0x01);

    bgp_path_attr_free(attr);
    bgp_path_attr_free(copy);
    test_result(passed, "Redirect-to-next-hop community 0x0800 with C bit");
}

/*
 * Test 50: rt-redirect-ipv6 community 0x000d (RFC 8956 section 6.1)
 */
void test_redirect_rt_ipv6_community() {
    struct in6_addr  addr;
    bgp_path_attr_t *attr;
    int              passed;

    inet_pton(AF_INET6, "2001:db8:ffff::9", &addr);
    attr = bgp_attr_create_flowspec_redirect_rt_ipv6(&addr, 0x1234);
    passed = (attr != NULL) && (attr->type_code == BGP_ATTR_IPV6_EXT_COMM) &&
             (attr->value[0] == 0x00) && (attr->value[1] == 0x0d) &&
             (memcmp(attr->value + 2, &addr, 16) == 0) &&
             (read_u16(attr->value + 18) == 0x1234);
    bgp_path_attr_free(attr);
    test_result(passed, "rt-redirect-ipv6 community 0x000d (RFC 8956 6.1)");
}

/*
 * Test 51: Append to an attribute 25 community list; an attribute of a different type is rejected
 */
void test_ipv6_ext_comm_append() {
    struct in6_addr  a;
    struct in6_addr  b;
    bgp_path_attr_t *first;
    bgp_path_attr_t *second;
    bgp_path_attr_t *v4 = bgp_attr_create_flowspec_redirect_nexthop(0);
    int              passed;

    inet_pton(AF_INET6, "2001:db8::1", &a);
    inet_pton(AF_INET6, "2001:db8::2", &b);
    first = bgp_attr_create_flowspec_redirect_ipv6(&a, 0);
    second = bgp_attr_create_flowspec_redirect_rt_ipv6(&b, 7);
    passed = (bgp_attr_ipv6_ext_comm_append_attr(first, second) == 0) &&
             (first->length == 40) &&
             (first->value[21] == 0x0d) &&
             (memcmp(first->value + 22, &b, 16) == 0) &&
             (bgp_attr_ipv6_ext_comm_append_attr(first, v4) == -1);
    bgp_path_attr_free(first);
    bgp_path_attr_free(second);
    bgp_path_attr_free(v4);
    test_result(passed, "IPv6 Address Specific community list append");
}

/*
 * Test 52: Interface-set community 0x0702/0x4702 (O and I bits, group ID range)
 */
void test_interface_set_community() {
    bgp_path_attr_t *both = bgp_attr_create_flowspec_interface_set(4200000000u, 0x3FFF, 1, 1, 1);
    bgp_path_attr_t *in_nt = bgp_attr_create_flowspec_interface_set(65000, 5, 1, 0, 0);
    int passed = (both != NULL) && (in_nt != NULL) &&
                 (both->value[0] == 0x07) && (both->value[1] == 0x02) &&
                 (read_u32(both->value + 2) == 4200000000u) &&
                 (read_u16(both->value + 6) == 0xFFFF) &&
                 (in_nt->value[0] == 0x47) &&
                 (read_u16(in_nt->value + 6) == 0x4005) &&
                 (bgp_attr_create_flowspec_interface_set(1, 1, 0, 0, 1) == NULL) &&
                 (bgp_attr_create_flowspec_interface_set(1, 0x4000, 1, 0, 1) == NULL);

    bgp_path_attr_free(both);
    bgp_path_attr_free(in_nt);
    test_result(passed, "Interface-set community 0x0702/0x4702 (O, I, group)");
}

/*
 * Test 53: Traffic marking rejects a DSCP above 63 (reserved bits, RFC 8955 section 7.5)
 */
void test_traffic_marking_reserved_bits() {
    test_result(bgp_attr_create_flowspec_marking(64) == NULL,
                "Traffic marking rejects DSCP > 63 (reserved bits, RFC 8955 7.5)");
}

// SR-TE steering

/*
 * Test 54: SR-TE steering to an IPv4 endpoint: redirect and two Colors in one attribute 16
 */
void test_srte_ipv4_endpoint() {
    bgp_color_spec_t colors[] = {{100, BGP_COLOR_CO_SPECIFIC}, {200, BGP_COLOR_CO_NULL}};
    bgp_flowspec_srte_t steer;
    bgp_path_attr_t    *attrs;
    static const uint8_t want[24] = {
        0x01, 0x0c, 0xc0, 0x00, 0x02, 0x01, 0x00, 0x01,  /* redirect, C=1 */
        0x03, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64,  /* color 100, 00 */
        0x03, 0x0b, 0x40, 0x00, 0x00, 0x00, 0x00, 0xc8,  /* color 200, 01 */
    };
    int passed;

    memset(&steer, 0, sizeof(steer));
    steer.endpoint.af = AF_INET;
    inet_pton(AF_INET, "192.0.2.1", &steer.endpoint.address.ipv4);
    steer.colors = colors;
    steer.num_colors = 2;
    steer.copy = 1;
    attrs = bgp_attr_create_flowspec_srte(&steer);
    passed = (attrs != NULL) && (attrs->type_code == BGP_ATTR_EXT_COMM) &&
             (attrs->length == 24) && (memcmp(attrs->value, want, 24) == 0) &&
             (attrs->next == NULL);
    bgp_path_attr_list_free(attrs);
    test_result(passed, "SR-TE steering: IPv4 endpoint, two Colors, one attribute 16");
}

/*
 * Test 55: SR-TE steering to an IPv6 endpoint: redirect in attribute 25, the Color in attribute 16
 */
void test_srte_ipv6_endpoint() {
    bgp_color_spec_t colors[] = {{7, BGP_COLOR_CO_ANY}};
    bgp_flowspec_srte_t steer;
    bgp_path_attr_t    *attrs;
    int                 passed;

    memset(&steer, 0, sizeof(steer));
    steer.endpoint.af = AF_INET6;
    inet_pton(AF_INET6, "2001:db8::7", &steer.endpoint.address.ipv6);
    steer.colors = colors;
    steer.num_colors = 1;
    attrs = bgp_attr_create_flowspec_srte(&steer);
    passed = (attrs != NULL) && (attrs->type_code == BGP_ATTR_EXT_COMM) &&
             (attrs->length == 8) && (attrs->value[0] == 0x03) &&
             (read_u16(attrs->value + 2) == 0x8000) && (read_u32(attrs->value + 4) == 7) &&
             (attrs->next != NULL) && (attrs->next->type_code == BGP_ATTR_IPV6_EXT_COMM) &&
             (attrs->next->length == 20) && (attrs->next->value[1] == 0x0c) &&
             (memcmp(attrs->next->value + 2, &steer.endpoint.address.ipv6, 16) == 0) &&
             (attrs->next->next == NULL);
    bgp_path_attr_list_free(attrs);
    test_result(passed, "SR-TE steering: IPv6 endpoint, redirect in attribute 25");
}

/*
 * Test 56: SR-TE steering rejects a missing Color, a bad CO type and a bad endpoint
 */
void test_srte_invalid_input() {
    bgp_color_spec_t bad_co[] = {{100, 4}};
    bgp_color_spec_t ok[] = {{100, BGP_COLOR_CO_SPECIFIC}};
    bgp_flowspec_srte_t steer;
    int                 passed;

    memset(&steer, 0, sizeof(steer));
    steer.endpoint.af = AF_INET;
    steer.colors = ok;
    steer.num_colors = 0;
    passed = (bgp_attr_create_flowspec_srte(&steer) == NULL);       /* no Color */
    steer.num_colors = 1;
    steer.colors = bad_co;
    passed = passed && (bgp_attr_create_flowspec_srte(&steer) == NULL);
    steer.colors = ok;
    steer.endpoint.af = 0;
    passed = passed && (bgp_attr_create_flowspec_srte(&steer) == NULL);
    passed = passed && (bgp_attr_create_flowspec_srte(NULL) == NULL);
    test_result(passed, "SR-TE steering: reject missing Color, bad CO type, bad endpoint");
}

/*
 * Locate the MP_REACH NLRI value and return its next-hop length.
 */
static int mp_reach_parts(const uint8_t *msg, size_t size, const uint8_t **mp, uint16_t *mp_len) {
    if (!find_attr(msg, size, BGP_ATTR_MP_REACH_NLRI, mp, mp_len)) {
        return -1;
    }
    return (*mp)[3];
}

/*
 * Test 57: SR-TE steering UPDATE with redirect-to-IP and Colors: zero-length next hop
 */
void test_srte_full_update() {
    flowspec_rule_t            rule = make_simple_rule("10.1.0.0", 24, 443);
    flowspec_nlri_t           *nlri = flowspec_nlri_create(&rule);
    bgp_color_spec_t           colors[] = {{100, BGP_COLOR_CO_SPECIFIC}, {300, BGP_COLOR_CO_RESERVED}};
    bgp_flowspec_srte_t        steer;
    bgp_path_attr_t           *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t                   asns[] = {65001};
    as_path_segment_t          segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t           *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_update_result_t       *result;
    bgp_flowspec_update_opts_t opts = {.afi = AFI_IPV4, .safi = SAFI_FLOWSPEC};
    const uint8_t             *value = NULL;
    const uint8_t             *mp = NULL;
    uint16_t                   length = 0;
    uint16_t                   mp_len = 0;
    int                        passed;

    memset(&steer, 0, sizeof(steer));
    steer.endpoint.af = AF_INET;
    inet_pton(AF_INET, "192.0.2.1", &steer.endpoint.address.ipv4);
    steer.colors = colors;
    steer.num_colors = 2;
    origin->next = as_path;
    as_path->next = bgp_attr_create_flowspec_srte(&steer);
    assert(as_path->next != NULL);

    result = bgp_generate_update_flowspec(nlri, origin, NULL, &opts);
    passed = (result != NULL) && (result->num_messages == 1) &&
             (mp_reach_parts(result->messages[0], result->message_lens[0], &mp, &mp_len) == 0) &&
             find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_EXT_COMM, &value, &length) &&
             (length == 24) &&
             (value[0] == 0x01) && (value[1] == 0x0c) && (read_u32(value + 2) == 0xC0000201) &&
             (read_u32(value + 12) == 100) &&
             (read_u16(value + 18) == 0xC000) && (read_u32(value + 20) == 300) &&
             // NLRI: len 9 | 01 18 0a 01 00 | 05 91 01 bb  (port 443 is 2 octets)
             (mp[5] == 9) && (mp[11] == FLOWSPEC_DEST_PORT) && (mp[12] == 0x91) &&
             (read_u16(mp + 13) == 443);

    bgp_update_result_free(result);
    flowspec_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    free_simple_rule(&rule);
    test_result(passed, "SR-TE steering UPDATE: redirect + Colors, zero-length next hop");
}

/*
 * Test 58: SR-TE steering UPDATE through the next hop: 0x0800 and a 4-octet MP_REACH next hop
 */
void test_srte_via_next_hop_update() {
    flowspec_rule_t  rule = make_simple_rule("10.1.0.0", 24, 80);
    flowspec_nlri_t *nlri = flowspec_nlri_create(&rule);
    bgp_color_spec_t colors[] = {{100, BGP_COLOR_CO_SPECIFIC}};
    bgp_flowspec_srte_t        steer;
    bgp_flowspec_update_opts_t opts;
    bgp_path_attr_t           *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_update_result_t *result;
    const uint8_t       *value = NULL;
    const uint8_t       *mp = NULL;
    uint16_t             length = 0;
    uint16_t             mp_len = 0;
    int                  passed;

    memset(&steer, 0, sizeof(steer));
    steer.endpoint.af = AF_INET;
    inet_pton(AF_INET, "192.0.2.1", &steer.endpoint.address.ipv4);
    steer.colors = colors;
    steer.num_colors = 1;
    steer.via_next_hop = 1;
    origin->next = as_path;
    as_path->next = bgp_attr_create_flowspec_srte(&steer);
    assert(as_path->next != NULL);

    memset(&opts, 0, sizeof(opts));
    opts.afi = AFI_IPV4;
    opts.safi = SAFI_FLOWSPEC;
    opts.next_hop = &steer.endpoint;
    result = bgp_generate_update_flowspec(nlri, origin, NULL, &opts);
    passed = (result != NULL) &&
             (mp_reach_parts(result->messages[0], result->message_lens[0], &mp, &mp_len) == 4) &&
             (read_u32(mp + 4) == 0xC0000201) && (mp[8] == 0) &&
             find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_EXT_COMM, &value, &length) &&
             (length == 16) && (value[0] == 0x08) && (value[1] == 0x00) &&
             (value[8] == 0x03) && (value[9] == 0x0b);

    bgp_update_result_free(result);
    flowspec_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    free_simple_rule(&rule);
    test_result(passed, "SR-TE steering via next hop: 0x0800 + 4-octet MP_REACH next hop");
}

/*
 * Test 59: FlowSpec next hop with an IPv6 global and a link-local address (32 octets)
 */
void test_flowspec_ipv6_next_hop_link_local() {
    flowspec_rule_t            rule = make_simple_rule_ipv6("2001:db8::", 0, 64, 80);
    flowspec_nlri_t           *nlri = flowspec_nlri_create(&rule);
    bgp_flowspec_update_opts_t opts;
    bgp_next_hop_t             nh;
    bgp_path_attr_t           *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_update_result_t *result;
    const uint8_t       *mp = NULL;
    uint16_t             mp_len = 0;
    int                  passed;

    memset(&nh, 0, sizeof(nh));
    nh.af = AF_INET6;
    inet_pton(AF_INET6, "2001:db8::1", &nh.address.ipv6);
    nh.has_link_local = 1;
    inet_pton(AF_INET6, "fe80::1", &nh.link_local);
    memset(&opts, 0, sizeof(opts));
    opts.afi = AFI_IPV6;
    opts.safi = SAFI_FLOWSPEC;
    opts.next_hop = &nh;
    origin->next = as_path;

    result = bgp_generate_update_flowspec(nlri, origin, NULL, &opts);
    passed = (result != NULL) &&
             (mp_reach_parts(result->messages[0], result->message_lens[0], &mp, &mp_len) == 32) &&
             (read_u16(mp) == AFI_IPV6) &&
             (memcmp(mp + 4, &nh.address.ipv6, 16) == 0) &&
             (memcmp(mp + 20, &nh.link_local, 16) == 0) &&
             (mp[36] == 0);

    nh.af = 0;
    passed = passed && (bgp_generate_update_flowspec(nlri, origin, NULL, &opts) == NULL);

    bgp_update_result_free(result);
    flowspec_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    free_simple_rule(&rule);
    test_result(passed, "FlowSpec next-hop option: IPv6 global + link-local (32 octets)");
}

// VPN FlowSpec (SAFI 134)

/*
 * Test 60: VPN FlowSpec (SAFI 134): the RD comes before the rule and the NLRI length includes it
 */
void test_flowspec_vpn_update() {
    flowspec_rule_t            rule = make_simple_rule("10.0.0.0", 24, 80);
    route_distinguisher_t      rd = rd_create_type0(65000, 100);
    flowspec_nlri_t           *vpn = flowspec_nlri_create_vpn(&rule, rd);
    flowspec_nlri_t           *plain = flowspec_nlri_create(&rule);
    bgp_flowspec_update_opts_t opts;
    bgp_path_attr_t           *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_update_result_t *result;
    bgp_update_result_t *withdraw;
    const uint8_t       *mp = NULL;
    uint16_t             mp_len = 0;
    static const uint8_t want[] = {
        16,                                              /* 8 (RD) + 8 (rule) */
        0x00, 0x00, 0xfd, 0xe8, 0x00, 0x00, 0x00, 0x64,  /* RD 65000:100      */
        0x01, 0x18, 0x0a, 0x00, 0x00,                    /* dest 10.0.0.0/24  */
        0x05, 0x81, 0x50,                                /* dst-port =80      */
    };
    int passed;

    memset(&opts, 0, sizeof(opts));
    opts.afi = AFI_IPV4;
    opts.safi = SAFI_FLOWSPEC_VPN;
    origin->next = as_path;

    result = bgp_generate_update_flowspec(vpn, origin, NULL, &opts);
    passed = (result != NULL) &&
             (mp_reach_parts(result->messages[0], result->message_lens[0], &mp, &mp_len) == 0) &&
             (mp[2] == SAFI_FLOWSPEC_VPN) &&
             (mp_len == 5 + sizeof(want)) &&
             (memcmp(mp + 5, want, sizeof(want)) == 0);

    withdraw = bgp_generate_update_flowspec(NULL, NULL, vpn, &opts);
    passed = passed && (withdraw != NULL) &&
             find_attr(withdraw->messages[0], withdraw->message_lens[0], BGP_ATTR_MP_UNREACH_NLRI, &mp, &mp_len) &&
             (mp[2] == SAFI_FLOWSPEC_VPN) && (memcmp(mp + 3, want, sizeof(want)) == 0);

    // An entry without an RD cannot go in SAFI 134, and the reverse.
    passed = passed && (bgp_generate_update_flowspec(plain, origin, NULL, &opts) == NULL);
    opts.safi = SAFI_FLOWSPEC;
    passed = passed && (bgp_generate_update_flowspec(vpn, origin, NULL, &opts) == NULL);

    bgp_update_result_free(result);
    bgp_update_result_free(withdraw);
    flowspec_nlri_list_free(vpn);
    flowspec_nlri_list_free(plain);
    bgp_path_attr_list_free(origin);
    free_simple_rule(&rule);
    test_result(passed, "VPN FlowSpec (SAFI 134): RD before the rule, length covers RD");
}

// RFC example vectors

static flowspec_component_t prefix_comp(uint8_t type, int af, const char *addr, uint8_t len, uint8_t offset) {
    flowspec_component_t comp;

    memset(&comp, 0, sizeof(comp));
    comp.type = type;
    comp.prefix_len = len;
    comp.prefix_offset = offset;
    inet_pton(af, addr, comp.prefix);
    return comp;
}

/*
 * A component of one type with the operator/value list vals.
 */
static flowspec_component_t op_comp(uint8_t type, flowspec_op_value_t *vals, int num_values) {
    flowspec_component_t comp;

    memset(&comp, 0, sizeof(comp));
    comp.type = type;
    comp.values = vals;
    comp.num_values = num_values;
    return comp;
}

/*
 * Test 61: RFC 8955 section 4.3 examples 1-3 and RFC 8956 section 3.8.1 example 1
 */
void test_rfc_example_vectors() {
    uint8_t buffer[64];
    int     passed = 1;

    {   /* RFC 8955 4.3.1: to 192.0.2.0/24, TCP, port 25 */
        static const uint8_t want[] = {0x0b, 0x01, 0x18, 0xc0, 0x00, 0x02,
                                       0x03, 0x81, 0x06, 0x04, 0x81, 0x19};
        flowspec_op_value_t proto = {0x81, 6};
        flowspec_op_value_t port = {0x81, 25};
        flowspec_component_t c[3] = {
            prefix_comp(FLOWSPEC_DEST_PREFIX, AF_INET, "192.0.2.0", 24, 0),
            op_comp(FLOWSPEC_IP_PROTOCOL, &proto, 1),
            op_comp(FLOWSPEC_PORT, &port, 1),
        };
        flowspec_rule_t rule = {c, 3};

        passed &= (bgp_encode_flowspec_rule_afi(buffer, &rule, AFI_IPV4) == (int)sizeof(want)) &&
                  (memcmp(buffer, want, sizeof(want)) == 0);
    }
    {   /* RFC 8955 4.3.2: ports (>=137 AND <=139) OR 8080 */
        static const uint8_t want[] = {0x12, 0x01, 0x18, 0xc0, 0x00, 0x02,
                                       0x02, 0x18, 0xcb, 0x00, 0x71,
                                       0x04, 0x03, 0x89, 0x45, 0x8b, 0x91, 0x1f, 0x90};
        flowspec_op_value_t ports[3] = {{0x03, 137}, {0x45, 139}, {0x91, 8080}};
        flowspec_component_t c[3] = {
            prefix_comp(FLOWSPEC_DEST_PREFIX, AF_INET, "192.0.2.0", 24, 0),
            prefix_comp(FLOWSPEC_SRC_PREFIX, AF_INET, "203.0.113.0", 24, 0),
            op_comp(FLOWSPEC_PORT, ports, 3),
        };
        flowspec_rule_t rule = {c, 3};

        passed &= (bgp_encode_flowspec_rule_afi(buffer, &rule, AFI_IPV4) == (int)sizeof(want)) &&
                  (memcmp(buffer, want, sizeof(want)) == 0);
    }
    {   /* RFC 8955 4.3.3: to 192.0.2.1, fragment DF or FF */
        static const uint8_t want[] = {0x09, 0x01, 0x20, 0xc0, 0x00, 0x02, 0x01,
                                       0x0c, 0x80, 0x05};
        flowspec_op_value_t frag = {0x80, FLOWSPEC_FRAG_DF | FLOWSPEC_FRAG_FF};
        flowspec_component_t c[2] = {
            prefix_comp(FLOWSPEC_DEST_PREFIX, AF_INET, "192.0.2.1", 32, 0),
            op_comp(FLOWSPEC_FRAGMENT, &frag, 1),
        };
        flowspec_rule_t rule = {c, 2};

        passed &= (bgp_encode_flowspec_rule_afi(buffer, &rule, AFI_IPV4) == (int)sizeof(want)) &&
                  (memcmp(buffer, want, sizeof(want)) == 0);
    }
    {   /*
         * RFC 8956 3.8.1: from ::1234:5678:9a00:0/64-104 to 2001:db8::/32,
         * TCP. Table 1 of the RFC prints "0d bb"; the decoded table and the
         * address give 0d b8, which is used here.
         */
        static const uint8_t want[] = {0x12, 0x01, 0x20, 0x00, 0x20, 0x01, 0x0d, 0xb8,
                                       0x02, 0x68, 0x40, 0x12, 0x34, 0x56, 0x78, 0x9a,
                                       0x03, 0x81, 0x06};
        flowspec_op_value_t proto = {0x81, 6};
        flowspec_component_t c[3] = {
            prefix_comp(FLOWSPEC_DEST_PREFIX, AF_INET6, "2001:db8::", 32, 0),
            prefix_comp(FLOWSPEC_SRC_PREFIX, AF_INET6, "::1234:5678:9a00:0", 104, 64),
            op_comp(FLOWSPEC_IP_PROTOCOL, &proto, 1),
        };
        flowspec_rule_t rule = {c, 3};

        passed &= (bgp_encode_flowspec_rule_afi(buffer, &rule, AFI_IPV6) == (int)sizeof(want)) &&
                  (memcmp(buffer, want, sizeof(want)) == 0);
    }
    test_result(passed, "RFC 8955 4.3 and RFC 8956 3.8.1 example encodings");
}

int main() {
    printf("========================================\n");
    printf("BGP FlowSpec UPDATE Message Tests\n");
    printf("========================================\n\n");

    // Rule validation
    test_validate_ascending_order();

    // Component encoding - prefix types
    test_encode_dest_prefix();
    test_encode_src_prefix();
    test_encode_ipv6_dest_prefix_with_offset();
    test_encode_ipv6_prefix_offset_all_bit_positions();

    // Component encoding - numeric operators
    test_encode_numeric_op_1byte();
    test_encode_numeric_op_2byte();
    test_encode_numeric_op_4byte();
    test_encode_port_range();

    // Component encoding - bitmask operators
    test_encode_bitmask_tcp_flags();
    test_encode_bitmask_fragment();

    // NLRI length encoding
    test_nlri_length_short();
    test_nlri_length_long();

    // UPDATE generation
    test_zero_length_next_hop();
    test_full_update_generation();

    // Traffic filtering extended communities
    test_traffic_rate_community();
    test_traffic_rate_nonzero();
    test_traffic_rate_packets_community();
    test_traffic_action_community();
    test_redirect_rt_community();
    test_redirect_rt_ipv4_community();
    test_redirect_rt_as4_community();
    test_traffic_marking_community();

    // ADD-PATH and withdrawals
    test_flowspec_add_path();
    test_flowspec_withdrawal();
    test_flowspec_withdrawal_add_path();
    test_flowspec_ipv6_update_generation();
    test_flowspec_ipv6_add_path();

    // NLRI operations
    test_nlri_create_deep_copy();
    test_nlri_list_ops();

    // Boundary / validation tests
    test_validate_empty_rule();
    test_validate_component_type_range();
    test_single_component_rule();
    test_op_value_encoding();
    test_multiple_rules_update();
    test_update_with_traffic_actions();

    // Additional component types
    test_encode_dscp_component();
    test_encode_icmp_type();
    test_encode_icmp_code();
    test_encode_src_port();

    // Splitting and boundaries
    test_flowspec_message_splitting();
    test_redirect_rt_boundary();
    test_traffic_marking_boundary();
    test_complex_rule();
    test_encode_packet_len_gt();
    test_reject_preexisting_mp_attrs();
    test_dest_prefix_default();

    // RFC 8955 / RFC 8956 rules
    test_rfc_example_vectors();
    test_reject_bad_operator_lists();
    test_reject_bad_bitmask_widths();
    test_ipv6_fragment_and_flow_label();
    test_nlri_length_limit();

    // Redirect, Color, and interface-set communities
    test_color_community_co_bits();
    test_color_community_raw_flags();
    test_redirect_ipv4_community();
    test_redirect_ipv6_community();
    test_redirect_nexthop_community();
    test_redirect_rt_ipv6_community();
    test_ipv6_ext_comm_append();
    test_interface_set_community();
    test_traffic_marking_reserved_bits();

    // SR-TE steering and next hop
    test_srte_ipv4_endpoint();
    test_srte_ipv6_endpoint();
    test_srte_invalid_input();
    test_srte_full_update();
    test_srte_via_next_hop_update();
    test_flowspec_ipv6_next_hop_link_local();

    // VPN FlowSpec
    test_flowspec_vpn_update();

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
    } else {
        printf("%s %s\n\n", TEST_BADGE_FAIL, "Some tests failed");
        return 1;
    }
}
