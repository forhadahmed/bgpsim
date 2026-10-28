/*
 * Unit tests for BGP VPN UPDATE message generation
 * Tests VPNv4, VPNv6, and EVPN Type 5
 */

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <arpa/inet.h>
#include "bgp.h"
#include "test_wire.h"
#include "bgp_router.h"
#include "bgp_update.h"
#include "test_result.h"
#include "bgp_neighbor.h"
#include "test_helpers.h"

#define TEST_FIND_TAIL(tail, head)       \
    do {                                 \
        (tail) = (head);                 \
        while ((tail) && (tail)->next) { \
            (tail) = (tail)->next;       \
        }                                \
    } while (0)

static int find_attr(const uint8_t *msg, size_t size, uint8_t type_code,
                     const uint8_t **value_out, uint16_t *length_out) {
    return test_wire_find_attr(msg, size, type_code, value_out, length_out, NULL);
}

static int has_attr(const uint8_t *msg, size_t size, uint8_t type_code) {
    return find_attr(msg, size, type_code, NULL, NULL);
}

static evpn_esi_t make_esi(uint8_t type, uint8_t fill) {
    evpn_esi_t esi;

    esi.type = type;
    memset(esi.value, fill, sizeof(esi.value));
    return esi;
}

/*
 * Test 1: Route Distinguisher creation
 */
void test_rd_creation() {
    route_distinguisher_t rd0 = rd_create_type0(65000, 100);
    route_distinguisher_t rd1 = rd_create_type1(0x0A000001, 200);
    route_distinguisher_t rd2 = rd_create_type2(65001, 300);

    test_result((rd0.type == 0) && (rd1.type == 1) && (rd2.type == 2), "RD creation");
}

/*
 * Test 2: VPNv4 NLRI creation
 */
void test_vpnv4_nlri_creation() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    vpnv4_nlri_list_t    *list = vpnv4_nlri_create("10.1.0.0", 16, 1000, rd);
    vpnv4_nlri_list_t    *tail;

    assert(list != NULL);
    TEST_FIND_TAIL(tail, list);
    vpnv4_nlri_add_tail(&list, &tail, "10.2.0.0", 16, 2000, rd);
    vpnv4_nlri_add_tail(&list, &tail, "10.3.0.0", 16, 3000, rd);

    test_result(vpnv4_nlri_count(list) == 3, "VPNv4 NLRI creation");
    vpnv4_nlri_list_free(list);
}

/*
 * Test 3: VPNv6 NLRI creation
 */
void test_vpnv6_nlri_creation() {
    route_distinguisher_t rd = rd_create_type1(0x0A000001, 100);
    vpnv6_nlri_list_t    *list = vpnv6_nlri_create("2001:db8:100::", 48, 5000, rd);
    vpnv6_nlri_list_t    *tail;

    assert(list != NULL);
    TEST_FIND_TAIL(tail, list);
    vpnv6_nlri_add_tail(&list, &tail, "2001:db8:200::", 48, 6000, rd);

    test_result(vpnv6_nlri_count(list) == 2, "VPNv6 NLRI creation");
    vpnv6_nlri_list_free(list);
}

/*
 * Test 4: EVPN Type 5 IPv4 creation
 */
void test_evpn_type5_ipv4_creation() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_type5_nlri_t    *list = evpn_type5_nlri_create_ipv4("192.168.1.0", 24, rd, 100, "10.0.0.1", 10000);

    assert(list != NULL);
    test_result((list->prefix.route_type == EVPN_RT_IP_PREFIX) &&
                (list->prefix.ip_prefix_len == 24) &&
                (list->prefix.ethernet_tag_id == 100),
                "EVPN Type 5 IPv4");
    evpn_type5_nlri_list_free(list);
}

/*
 * Test 5: EVPN Type 5 IPv6 creation
 */
void test_evpn_type5_ipv6_creation() {
    route_distinguisher_t rd = rd_create_type2(65001, 200);
    evpn_type5_nlri_t    *list = evpn_type5_nlri_create_ipv6("2001:db8:100::", 48, rd, 200, "2001:db8::1", 20000);

    assert(list != NULL);
    test_result((list->prefix.route_type == EVPN_RT_IP_PREFIX) &&
                (list->prefix.ip_prefix_len == 48),
                "EVPN Type 5 IPv6");
    evpn_type5_nlri_list_free(list);
}

/*
 * Test 6: VPNv4 prefix encoding
 */
void test_vpnv4_prefix_encoding() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    vpnv4_prefix_t        prefix;
    uint8_t               buffer[256];

    prefix.prefix_len = 24 + 64 + 24;
    prefix.label.label = 100;
    prefix.label.tc = 0;
    prefix.label.s = 1;
    prefix.label.ttl = 0;
    prefix.rd = rd;
    inet_pton(AF_INET, "10.1.1.0", &prefix.prefix);

    test_result((bgp_encode_vpnv4_prefix(buffer, &prefix) == 15) && (buffer[0] == prefix.prefix_len), "VPNv4 encoding");
}

/*
 * Test 7: VPNv6 prefix encoding
 */
void test_vpnv6_prefix_encoding() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    vpnv6_prefix_t        prefix;
    uint8_t               buffer[256];

    prefix.prefix_len = 24 + 64 + 48;
    prefix.label.label = 200;
    prefix.label.tc = 0;
    prefix.label.s = 1;
    prefix.label.ttl = 0;
    prefix.rd = rd;
    inet_pton(AF_INET6, "2001:db8:100::", prefix.prefix);

    test_result((bgp_encode_vpnv6_prefix(buffer, &prefix) == 18) && (buffer[0] == prefix.prefix_len), "VPNv6 encoding");
}

/*
 * Test 8: EVPN Type 5 encoding
 */
void test_evpn_type5_encoding() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_type5_nlri_t    *list = evpn_type5_nlri_create_ipv4("192.168.1.0", 24, rd, 100, "10.0.0.1", 10000);
    uint8_t               buffer[256];

    assert(list != NULL);
    test_result((bgp_encode_evpn_type5_prefix(buffer, &list->prefix) > 0) &&
                (buffer[0] == EVPN_RT_IP_PREFIX),
                "EVPN Type 5 encoding");
    evpn_type5_nlri_list_free(list);
}

/*
 * Test 9: VPNv4 UPDATE uses a 12-byte VPN next hop
 */
void test_vpnv4_update_next_hop_length() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    vpnv4_nlri_list_t    *nlri = vpnv4_nlri_create("10.1.0.0", 16, 1000, rd);
    bgp_path_attr_t      *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_next_hop_t       next_hop = make_ipv4_next_hop("192.0.2.1");
    bgp_update_result_t *result;
    const uint8_t       *value = NULL;
    uint16_t             length = 0;
    int                  passed;

    origin->next = as_path;
    result = bgp_generate_update_vpnv4(nlri, origin, NULL, 0, BGP_VPN_TRANSPORT_IPV4, &next_hop);
    assert(result != NULL);

    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI, &value, &length) &&
             (value[0] == 0x00) && (value[1] == AFI_IPV4) &&
             (value[2] == SAFI_MPLS_VPN) &&
             (value[3] == 12) &&
             (memcmp(value + 4, "\x00\x00\x00\x00\x00\x00\x00\x00", 8) == 0) &&
             (value[12] == 192) && (value[13] == 0) &&
             (value[14] == 2) && (value[15] == 1);

    bgp_update_result_free(result);
    vpnv4_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    test_result(passed, "VPNv4 next-hop length");
}

/*
 * Test 10: VPNv6 default next hop uses VPN-IPv6 encoding
 */
void test_vpnv6_default_next_hop() {
    route_distinguisher_t rd = rd_create_type1(0x0A000001, 100);
    vpnv6_nlri_list_t    *nlri = vpnv6_nlri_create("2001:db8:100::", 48, 5000, rd);
    bgp_path_attr_t      *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_update_result_t *result;
    const uint8_t       *value = NULL;
    uint16_t             length = 0;
    int                  passed;

    origin->next = as_path;
    result = bgp_generate_update_vpnv6(nlri, origin, NULL, 0, BGP_VPN_TRANSPORT_IPV6, NULL);
    assert(result != NULL);

    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI, &value, &length) &&
             (value[0] == 0x00) && (value[1] == AFI_IPV6) &&
             (value[2] == SAFI_MPLS_VPN) &&
             (value[3] == 24);

    bgp_update_result_free(result);
    vpnv6_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    test_result(passed, "VPNv6 default next hop");
}

/*
 * Test 11: VPNv6 over IPv4 transport uses an IPv4-mapped VPN-IPv6 next hop
 */
void test_vpnv6_ipv4_transport() {
    route_distinguisher_t rd = rd_create_type1(0x0A000001, 100);
    vpnv6_nlri_list_t    *nlri = vpnv6_nlri_create("2001:db8:100::", 48, 5000, rd);
    bgp_path_attr_t      *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_next_hop_t       next_hop = make_ipv4_next_hop("192.0.2.33");
    bgp_update_result_t *result;
    const uint8_t       *value = NULL;
    uint16_t             length = 0;
    int                  passed;

    origin->next = as_path;
    result = bgp_generate_update_vpnv6(nlri, origin, NULL, 0, BGP_VPN_TRANSPORT_IPV4, &next_hop);
    assert(result != NULL);

    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI, &value, &length) &&
             (value[3] == 24) &&
             (memcmp(value + 4, "\x00\x00\x00\x00\x00\x00\x00\x00", 8) == 0) &&
             (memcmp(value + 12, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF", 12) == 0) &&
             (value[24] == 192) && (value[25] == 0) &&
             (value[26] == 2) && (value[27] == 33);

    bgp_update_result_free(result);
    vpnv6_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    test_result(passed, "VPNv6 over IPv4 transport");
}

/*
 * Test 12: VPNv6 over IPv6 transport uses a VPN-IPv6 next hop
 */
void test_vpnv6_ipv6_transport() {
    route_distinguisher_t rd = rd_create_type1(0x0A000001, 100);
    vpnv6_nlri_list_t    *nlri = vpnv6_nlri_create("2001:db8:100::", 48, 5000, rd);
    bgp_path_attr_t      *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_next_hop_t       next_hop = make_ipv6_next_hop("2001:db8::1");
    bgp_update_result_t *result;
    const uint8_t       *value = NULL;
    uint16_t             length = 0;
    uint8_t              expected_ipv6[16];
    int                  passed;

    inet_pton(AF_INET6, "2001:db8::1", expected_ipv6);
    origin->next = as_path;
    result = bgp_generate_update_vpnv6(nlri, origin, NULL, 0, BGP_VPN_TRANSPORT_IPV6, &next_hop);
    assert(result != NULL);

    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI, &value, &length) &&
             (value[3] == 24) &&
             (memcmp(value + 4, "\x00\x00\x00\x00\x00\x00\x00\x00", 8) == 0) &&
             (memcmp(value + 12, expected_ipv6, 16) == 0);

    bgp_update_result_free(result);
    vpnv6_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    test_result(passed, "VPNv6 over IPv6 transport");
}

/*
 * Test 13: VPNv4 withdrawals use MP_UNREACH_NLRI
 */
void test_vpnv4_withdrawals() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    vpnv4_nlri_list_t    *withdrawn = vpnv4_nlri_create("10.1.0.0", 16, 1000, rd);
    bgp_update_result_t  *result = bgp_generate_update_vpnv4(NULL, NULL, withdrawn, 0, BGP_VPN_TRANSPORT_IPV4, NULL);
    int passed = (result != NULL) &&
                 (result->num_messages == 1) &&
                 find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_UNREACH_NLRI, NULL, NULL);

    bgp_update_result_free(result);
    vpnv4_nlri_list_free(withdrawn);
    test_result(passed, "VPNv4 withdrawals");
}

/*
 * Test 14: VPNv4 ADD-PATH encodes path IDs ahead of NLRI payloads
 */
void test_vpnv4_add_path_update() {
    route_distinguisher_t rd = rd_create_type0(65000, 7);
    vpnv4_nlri_list_t    *nlri = vpnv4_nlri_create_path_id("10.10.0.0", 16, 1000, rd, 101);
    vpnv4_nlri_list_t    *nlri_tail;
    bgp_path_attr_t      *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_update_result_t *result;
    bgp_next_hop_t       next_hop = make_ipv4_next_hop("192.0.2.1");
    const uint8_t       *value = NULL;
    uint16_t             length = 0;
    uint8_t              first_nlri[64];
    int                  first_len;
    int                  offset = 0;
    int                  passed;

    TEST_FIND_TAIL(nlri_tail, nlri);
    vpnv4_nlri_add_tail_path_id(&nlri, &nlri_tail, "10.11.0.0", 16, 2000, rd, 202);
    origin->next = as_path;
    result = bgp_generate_update_vpnv4(nlri, origin, NULL, 0, BGP_VPN_TRANSPORT_IPV4, &next_hop);
    assert(result != NULL);

    first_len = bgp_encode_vpnv4_prefix(first_nlri, &nlri->prefix);
    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI, &value, &length) &&
             mp_reach_nlri_offset(value, length, &offset) &&
             (read_u32(value + offset) == 101) &&
             (memcmp(value + offset + 4, first_nlri, (size_t)first_len) == 0) &&
             (read_u32(value + offset + 4 + first_len) == 202);

    bgp_update_result_free(result);
    vpnv4_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    test_result(passed, "VPNv4 ADD-PATH UPDATE");
}

/*
 * Test 15: VPNv4 ADD-PATH withdrawals carry path IDs in MP_UNREACH_NLRI
 */
void test_vpnv4_add_path_withdrawals() {
    route_distinguisher_t rd = rd_create_type0(65000, 8);
    vpnv4_nlri_list_t    *withdrawn = vpnv4_nlri_create_path_id("10.20.0.0", 16, 3000, rd, 333);
    vpnv4_nlri_list_t    *withdrawn_tail;
    bgp_update_result_t  *result;
    const uint8_t        *value = NULL;
    uint16_t              length = 0;
    uint8_t               first_nlri[64];
    int                   first_len;
    int                   offset = 0;
    int                   passed;

    TEST_FIND_TAIL(withdrawn_tail, withdrawn);
    vpnv4_nlri_add_tail_path_id(&withdrawn, &withdrawn_tail, "10.21.0.0", 16, 4000, rd, 444);
    result = bgp_generate_update_vpnv4(NULL, NULL, withdrawn, 0, BGP_VPN_TRANSPORT_IPV4, NULL);
    assert(result != NULL);

    first_len = bgp_encode_vpnv4_prefix(first_nlri, &withdrawn->prefix);
    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_UNREACH_NLRI, &value, &length) &&
             mp_unreach_nlri_offset(value, length, &offset) &&
             (read_u32(value + offset) == 333) &&
             (memcmp(value + offset + 4, first_nlri, (size_t)first_len) == 0) &&
             (read_u32(value + offset + 4 + first_len) == 444);

    bgp_update_result_free(result);
    vpnv4_nlri_list_free(withdrawn);
    test_result(passed, "VPNv4 ADD-PATH withdrawals");
}

/*
 * Test 16: EVPN can encode an IPv4 next hop
 */
void test_evpn_ipv4_next_hop() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_type5_nlri_t    *nlri = evpn_type5_nlri_create_ipv4("192.168.1.0", 24, rd, 100, "10.0.0.1", 10000);
    bgp_path_attr_t      *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_next_hop_t       next_hop = make_ipv4_next_hop("10.0.0.9");
    bgp_update_result_t *result;
    const uint8_t       *value = NULL;
    uint16_t             length = 0;
    int                  passed;

    origin->next = as_path;
    result = bgp_generate_update_evpn_type5(nlri, origin, NULL, 0, &next_hop);
    assert(result != NULL);

    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI, &value, &length) &&
             (value[0] == 0x00) && (value[1] == AFI_L2VPN) &&
             (value[2] == SAFI_EVPN) &&
             (value[3] == 4) &&
             (value[4] == 10) && (value[5] == 0) &&
             (value[6] == 0) && (value[7] == 9);

    bgp_update_result_free(result);
    evpn_type5_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    test_result(passed, "EVPN IPv4 next hop");
}

void test_evpn_type5_update_with_encap_and_router_mac_ext_comms() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    uint8_t router_mac[] = {0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee};
    evpn_type5_nlri_t *nlri = evpn_type5_nlri_create_ipv4("192.168.1.0", 24, rd, 0, NULL, 10000);
    bgp_path_attr_t   *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_path_attr_t     *encap = bgp_attr_create_ext_comm_encap(8);  /* VXLAN */
    bgp_path_attr_t     *router = bgp_attr_create_ext_comm_router_mac(router_mac);
    bgp_next_hop_t       next_hop = make_ipv4_next_hop("10.0.0.9");
    bgp_update_result_t *result;
    const uint8_t       *value = NULL;
    uint16_t             length = 0;
    int                  passed;

    assert(nlri != NULL);
    assert(origin != NULL);
    assert(as_path != NULL);
    assert(encap != NULL);
    assert(router != NULL);

    passed = (bgp_attr_ext_comm_append_attr(encap, router) == 0);
    bgp_path_attr_free(router);
    origin->next = as_path;
    as_path->next = encap;

    result = bgp_generate_update_evpn_type5(nlri, origin, NULL, 0, &next_hop);
    assert(result != NULL);

    passed = passed &&
             find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_EXT_COMM, &value, &length) &&
             (length == 16) &&
             (value[0] == 0x03) && (value[1] == 0x0c) &&
             (value[6] == 0x00) && (value[7] == 0x08) &&
             (value[8] == 0x06) && (value[9] == 0x03) &&
             (memcmp(value + 10, router_mac, 6) == 0);

    bgp_update_result_free(result);
    evpn_type5_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    test_result(passed, "EVPN Type 5 UPDATE carries Encapsulation + Router MAC ECs");
}

/*
 * Test 17: VPNv6 ADD-PATH encodes path IDs ahead of NLRI payloads
 */
void test_vpnv6_add_path_update() {
    route_distinguisher_t rd = rd_create_type1(0x0A000001, 100);
    vpnv6_nlri_list_t    *nlri = vpnv6_nlri_create_path_id("2001:db8:100::", 48, 5000, rd, 909);
    vpnv6_nlri_list_t    *nlri_tail;
    bgp_path_attr_t      *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_next_hop_t       next_hop = make_ipv6_next_hop("2001:db8::1");
    bgp_update_result_t *result;
    const uint8_t       *value = NULL;
    uint16_t             length = 0;
    uint8_t              first_nlri[64];
    int                  first_len;
    int                  offset = 0;
    int                  passed;

    TEST_FIND_TAIL(nlri_tail, nlri);
    vpnv6_nlri_add_tail_path_id(&nlri, &nlri_tail, "2001:db8:200::", 48, 6000, rd, 1001);
    origin->next = as_path;
    result = bgp_generate_update_vpnv6(nlri, origin, NULL, 0, BGP_VPN_TRANSPORT_IPV6, &next_hop);
    assert(result != NULL);

    first_len = bgp_encode_vpnv6_prefix(first_nlri, &nlri->prefix);
    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI, &value, &length) &&
             mp_reach_nlri_offset(value, length, &offset) &&
             (read_u32(value + offset) == 909) &&
             (memcmp(value + offset + 4, first_nlri, (size_t)first_len) == 0) &&
             (read_u32(value + offset + 4 + first_len) == 1001);

    bgp_update_result_free(result);
    vpnv6_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    test_result(passed, "VPNv6 ADD-PATH UPDATE");
}

/*
 * Test 18: EVPN Type 5 ADD-PATH encodes path IDs ahead of route-type NLRI
 */
void test_evpn_type5_add_path_update() {
    route_distinguisher_t rd = rd_create_type0(65000, 9);
    evpn_type5_nlri_t    *nlri = evpn_type5_nlri_create_ipv4_path_id("192.168.1.0", 24, rd, 100, "10.0.0.1", 10000, 1234);
    bgp_path_attr_t      *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_next_hop_t       next_hop = make_ipv4_next_hop("10.0.0.9");
    bgp_update_result_t *result;
    const uint8_t       *value = NULL;
    uint16_t             length = 0;
    uint8_t              first_nlri[80];
    int                  first_len;
    int                  offset = 0;
    int                  passed;

    evpn_type5_nlri_t *second = evpn_type5_nlri_create_ipv4_path_id(
        "192.168.2.0", 24, rd, 101, "10.0.0.1", 10001, 5678
    );
    evpn_type5_nlri_t *tail = nlri;

    while (tail->next) {
        tail = tail->next;
    }
    evpn_type5_nlri_append(&nlri, &tail, second);

    origin->next = as_path;
    result = bgp_generate_update_evpn_type5(nlri, origin, NULL, 0, &next_hop);
    assert(result != NULL);

    first_len = bgp_encode_evpn_type5_prefix(first_nlri, &nlri->prefix);
    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI, &value, &length) &&
             mp_reach_nlri_offset(value, length, &offset) &&
             (read_u32(value + offset) == 1234) &&
             (memcmp(value + offset + 4, first_nlri, (size_t)first_len) == 0) &&
             (read_u32(value + offset + 4 + first_len) == 5678);

    bgp_update_result_free(result);
    evpn_type5_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    test_result(passed, "EVPN Type 5 ADD-PATH UPDATE");
}

/*
 * Test 19: Large VPNv4 NLRI list
 */
void test_large_vpnv4_list() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    vpnv4_nlri_list_t    *nlri = NULL;
    vpnv4_nlri_list_t    *nlri_tail = NULL;
    bgp_path_attr_t      *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_update_result_t *result;
    int                  i;

    for (i = 0; i < 100; i++) {
        char prefix[32];
        snprintf(prefix, sizeof(prefix), "10.%d.0.0", i);
        vpnv4_nlri_add_tail(&nlri, &nlri_tail, prefix, 16, 1000 + i, rd);
    }

    origin->next = as_path;
    result = bgp_generate_update_vpnv4(nlri, origin, NULL, 0, BGP_VPN_TRANSPORT_IPV4, NULL);

    test_result((vpnv4_nlri_count(nlri) == 100) && (result != NULL) && (result->num_messages >= 1), "Large VPNv4 list");

    bgp_update_result_free(result);
    vpnv4_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
}

/*
 * Test 20: RD type verification
 */
void test_rd_types() {
    route_distinguisher_t rd0 = rd_create_type0(100, 200);
    route_distinguisher_t rd1 = rd_create_type1(0xC0A80101, 300);
    route_distinguisher_t rd2 = rd_create_type2(4200000000UL, 400);

    test_result((rd0.type == 0) && (rd1.type == 1) && (rd2.type == 2), "RD types");
}

/*
 * Test 21: MPLS label encoding
 */
void test_mpls_label_encoding() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    uint32_t labels[] = {100, 1000, 10000, 100000, 1048575};
    int passed = 1;
    int i;

    for (i = 0; i < 5; i++) {
        vpnv4_nlri_list_t *nlri = vpnv4_nlri_create("10.0.0.0", 8, labels[i], rd);
        passed = passed && (nlri->prefix.label.label == labels[i]);
        vpnv4_nlri_list_free(nlri);
    }

    test_result(passed, "MPLS label encoding");
}

/*
 * Test 22: EVPN Type 5 encoding size validation per RFC 9136
 */
void test_evpn_type5_encoding_size() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_type5_nlri_t    *v4 = evpn_type5_nlri_create_ipv4("192.168.1.0", 24, rd, 100, "10.0.0.1", 10000);
    evpn_type5_nlri_t    *v6 = evpn_type5_nlri_create_ipv6("2001:db8::", 48, rd, 200, "2001:db8::1", 20000);
    uint8_t               buf[256];
    int                   v4_len = bgp_encode_evpn_type5_prefix(buf, &v4->prefix);
    int                   v6_len = bgp_encode_evpn_type5_prefix(buf, &v6->prefix);

    test_result((v4_len == 36) && (v6_len == 60), "EVPN Type 5 RFC 9136 encoding size");

    evpn_type5_nlri_list_free(v4);
    evpn_type5_nlri_list_free(v6);
}

/*
 * Test 23: Extended Community Route Target creation
 */
void test_ext_comm_rt() {
    bgp_path_attr_t *rt = bgp_attr_create_ext_comm_rt(65001, 100);
    int passed = (rt != NULL) &&
                 (rt->flags == (BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANSITIVE)) &&
                 (rt->type_code == BGP_ATTR_EXT_COMM) &&
                 (rt->length == 8) &&
                 (rt->value[0] == 0x00) && (rt->value[1] == 0x02);

    bgp_path_attr_free(rt);
    test_result(passed, "Extended Community RT");
}

/*
 * Test 24: Extended Community Route Target (4-byte AS specific)
 */
void test_ext_comm_rt_as4() {
    bgp_path_attr_t *rt = bgp_attr_create_ext_comm_rt_as4(4200000000UL, 100);
    int passed = (rt != NULL) &&
                 (rt->value[0] == 0x02) &&
                 (rt->value[1] == 0x02) &&
                 (rt->length == 8);

    bgp_path_attr_free(rt);
    test_result(passed, "Extended Community RT AS4");
}

/*
 * Test 25: Extended Community Route Target (IPv4 specific)
 */
void test_ext_comm_rt_ip() {
    bgp_path_attr_t *rt = bgp_attr_create_ext_comm_rt_ip(0x0A000001U, 100);
    int passed = (rt != NULL) &&
                 (rt->value[0] == 0x01) &&
                 (rt->value[1] == 0x02) &&
                 (rt->value[2] == 0x0A) &&
                 (rt->value[3] == 0x00) &&
                 (rt->value[4] == 0x00) &&
                 (rt->value[5] == 0x01);

    bgp_path_attr_free(rt);
    test_result(passed, "Extended Community RT IPv4");
}

/*
 * Test 26: RD wire format validation (2-byte type per RFC 4364)
 */
void test_rd_wire_format() {
    route_distinguisher_t rd = rd_create_type1(0x0A000001, 100);
    vpnv4_prefix_t        prefix;
    uint8_t               buffer[256];

    prefix.prefix_len = 24 + 64 + 24;
    prefix.label.label = 100;
    prefix.label.tc = 0;
    prefix.label.s = 1;
    prefix.label.ttl = 0;
    prefix.rd = rd;
    inet_pton(AF_INET, "10.1.1.0", &prefix.prefix);

    bgp_encode_vpnv4_prefix(buffer, &prefix);

    test_result((buffer[4] == 0x00) && (buffer[5] == 0x01) &&
                (buffer[6] == 0x0A) && (buffer[7] == 0x00) &&
                (buffer[8] == 0x00) && (buffer[9] == 0x01) &&
                (buffer[10] == 0x00) && (buffer[11] == 0x64),
                "RD wire format (2-byte type)");
}

void test_vpnv4_message_splitting() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    vpnv4_nlri_list_t    *nlri = NULL;
    vpnv4_nlri_list_t    *nlri_tail = NULL;
    bgp_path_attr_t      *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001, 65002};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 2, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_next_hop_t       next_hop = make_ipv4_next_hop("192.0.2.1");
    bgp_update_result_t *result;
    int                  passed;

    for (int i = 0; i < 50; i++) {
        char prefix[32];

        snprintf(prefix, sizeof(prefix), "10.%d.0.0", i);
        vpnv4_nlri_add_tail(&nlri, &nlri_tail, prefix, 16, 1000 + i, rd);
    }

    origin->next = as_path;
    result = bgp_generate_update_vpnv4(nlri, origin, NULL, 512, BGP_VPN_TRANSPORT_IPV4, &next_hop);
    assert(result != NULL);

    passed = (result->num_messages > 1);
    for (int i = 0; i < result->num_messages; i++) {
        if (result->message_lens[i] > 512 ||
            test_wire_path_attr_len(result->messages[i], result->message_lens[i]) <= 0 ||
            !has_attr(result->messages[i], result->message_lens[i], BGP_ATTR_MP_REACH_NLRI)) {
            passed = 0;
        }
    }

    bgp_update_result_free(result);
    bgp_path_attr_list_free(origin);
    vpnv4_nlri_list_free(nlri);
    test_result(passed, "VPNv4 message splitting");
}

void test_vpnv6_message_splitting() {
    route_distinguisher_t rd = rd_create_type1(0x0A000001, 100);
    vpnv6_nlri_list_t    *nlri = NULL;
    vpnv6_nlri_list_t    *nlri_tail = NULL;
    bgp_path_attr_t      *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_next_hop_t       next_hop = make_ipv6_next_hop("2001:db8::1");
    bgp_update_result_t *result;
    int                  passed;

    for (int i = 0; i < 30; i++) {
        char prefix[64];

        snprintf(prefix, sizeof(prefix), "2001:db8:%x::", i);
        vpnv6_nlri_add_tail(&nlri, &nlri_tail, prefix, 48, 2000 + i, rd);
    }

    origin->next = as_path;
    result = bgp_generate_update_vpnv6(nlri, origin, NULL, 400, BGP_VPN_TRANSPORT_IPV6, &next_hop);
    assert(result != NULL);

    passed = (result->num_messages > 1);
    for (int i = 0; i < result->num_messages; i++) {
        if (result->message_lens[i] > 400 ||
            test_wire_path_attr_len(result->messages[i], result->message_lens[i]) <= 0 ||
            !has_attr(result->messages[i], result->message_lens[i], BGP_ATTR_MP_REACH_NLRI)) {
            passed = 0;
        }
    }

    bgp_update_result_free(result);
    bgp_path_attr_list_free(origin);
    vpnv6_nlri_list_free(nlri);
    test_result(passed, "VPNv6 message splitting");
}

void test_evpn_large_list() {
    route_distinguisher_t rd = rd_create_type2(65001, 500);
    evpn_type5_nlri_t    *nlri = NULL;
    evpn_type5_nlri_t    *nlri_tail = NULL;
    bgp_path_attr_t      *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001, 65002, 65003};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 3, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_next_hop_t       next_hop = make_ipv4_next_hop("10.0.0.9");
    bgp_update_result_t *result;
    int                  passed;

    for (int i = 0; i < 20; i++) {
        char               prefix[32];
        evpn_type5_nlri_t *new_nlri;

        snprintf(prefix, sizeof(prefix), "192.168.%d.0", i);
        new_nlri = evpn_type5_nlri_create_ipv4(prefix, 24, rd, 100 + i, "10.0.0.1", 10000 + i);
        evpn_type5_nlri_append(&nlri, &nlri_tail, new_nlri);
    }

    origin->next = as_path;
    result = bgp_generate_update_evpn_type5(nlri, origin, NULL, 0, &next_hop);
    assert(result != NULL);

    passed = (result->num_messages >= 1);
    for (int i = 0; i < result->num_messages; i++) {
        if (test_wire_path_attr_len(result->messages[i], result->message_lens[i]) <= 0 ||
            !has_attr(result->messages[i], result->message_lens[i], BGP_ATTR_MP_REACH_NLRI)) {
            passed = 0;
        }
    }

    bgp_update_result_free(result);
    bgp_path_attr_list_free(origin);
    evpn_type5_nlri_list_free(nlri);
    test_result(passed, "EVPN large list");
}

void test_vpnv4_extreme_splitting() {
    route_distinguisher_t rd = rd_create_type0(65000, 999);
    vpnv4_nlri_list_t    *nlri = NULL;
    vpnv4_nlri_list_t    *nlri_tail = NULL;
    bgp_path_attr_t      *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_next_hop_t       next_hop = make_ipv4_next_hop("198.51.100.2");
    bgp_update_result_t *result;
    int                  passed;

    for (int i = 0; i < 200; i++) {
        char prefix[32];

        snprintf(prefix, sizeof(prefix), "172.%d.%d.0", i / 256, i % 256);
        vpnv4_nlri_add_tail(&nlri, &nlri_tail, prefix, 24, 5000 + i, rd);
    }

    origin->next = as_path;
    result = bgp_generate_update_vpnv4(nlri, origin, NULL, 256, BGP_VPN_TRANSPORT_IPV4, &next_hop);
    assert(result != NULL);

    passed = (result->num_messages > 10);
    for (int i = 0; i < result->num_messages; i++) {
        if (result->message_lens[i] > 256 ||
            test_wire_path_attr_len(result->messages[i], result->message_lens[i]) <= 0 ||
            !has_attr(result->messages[i], result->message_lens[i], BGP_ATTR_MP_REACH_NLRI)) {
            passed = 0;
        }
    }

    bgp_update_result_free(result);
    bgp_path_attr_list_free(origin);
    vpnv4_nlri_list_free(nlri);
    test_result(passed, "VPNv4 extreme splitting");
}

void test_vpnv4_add_path_message_splitting() {
    route_distinguisher_t rd = rd_create_type0(65000, 77);
    vpnv4_nlri_list_t    *nlri = NULL;
    vpnv4_nlri_list_t    *nlri_tail = NULL;
    bgp_path_attr_t      *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_next_hop_t       next_hop = make_ipv4_next_hop("198.51.100.9");
    bgp_update_result_t *result;
    const uint8_t       *value = NULL;
    uint16_t             length = 0;
    int                  offset = 0;
    int                  passed = 1;

    for (int i = 0; i < 80; i++) {
        char prefix[32];

        snprintf(prefix, sizeof(prefix), "10.%d.0.0", i);
        vpnv4_nlri_add_tail_path_id(&nlri, &nlri_tail, prefix, 16, 7000 + i, rd, 1000 + i);
    }

    origin->next = as_path;
    result = bgp_generate_update_vpnv4(nlri, origin, NULL, 256, BGP_VPN_TRANSPORT_IPV4, &next_hop);
    assert(result != NULL);

    passed = (result->num_messages > 1);
    for (int i = 0; i < result->num_messages; i++) {
        if (result->message_lens[i] > 256 ||
            test_wire_path_attr_len(result->messages[i], result->message_lens[i]) <= 0 ||
            !has_attr(result->messages[i], result->message_lens[i], BGP_ATTR_MP_REACH_NLRI)) {
            passed = 0;
        }
    }

    if (!find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI, &value, &length) || length < 5) {
        passed = 0;
    } else {
        offset = 5 + value[3];
        if (offset + 4 > length || read_u32(value + offset) != 1000) {
            passed = 0;
        }
    }

    bgp_update_result_free(result);
    bgp_path_attr_list_free(origin);
    vpnv4_nlri_list_free(nlri);
    test_result(passed, "VPNv4 ADD-PATH message splitting");
}

// Adversarial / boundary tests

/*
 * Test 31: EVPN Type 5 rejects non-zero ESI + non-zero gateway-ip (RFC 9136)
 */
void test_evpn_type5_esi_gw_both_nonzero() {
    evpn_type5_prefix_t prefix;
    evpn_esi_t          esi = make_esi(1, 0xAA);
    uint8_t             buffer[256];
    int                 result;

    memset(&prefix, 0, sizeof(prefix));
    prefix.route_type = EVPN_RT_IP_PREFIX;
    prefix.af = AF_INET;
    prefix.rd = rd_create_type0(65000, 1);
    prefix.ethernet_tag_id = 100;
    prefix.ip_prefix_len = 24;
    inet_pton(AF_INET, "10.0.0.0", prefix.ip_prefix);

    evpn_type5_prefix_set_esi(&prefix, esi);

    // Set non-zero gateway IP
    inet_pton(AF_INET, "10.0.0.1", prefix.gateway_ip);

    prefix.label.label = 1000;
    prefix.label.tc = 0;
    prefix.label.s = 1;
    prefix.label.ttl = 0;

    result = bgp_encode_evpn_type5_prefix(buffer, &prefix);
    test_result(result == -1, "EVPN Type 5 ESI+GW both non-zero rejected (RFC 9136)");
}

/*
 * Test 32: EVPN Type 5 allows non-zero ESI with zero gateway-ip
 */
void test_evpn_type5_esi_nonzero_gw_zero() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_esi_t            esi = make_esi(3, 0x42);
    evpn_type5_nlri_t    *nlri = evpn_type5_nlri_create_ipv4("10.0.0.0", 24, rd, 0, NULL, 5000);
    uint8_t               buffer[256];
    int                   result;

    assert(nlri != NULL);
    evpn_type5_nlri_set_esi(nlri, esi);
    result = bgp_encode_evpn_type5_prefix(buffer, &nlri->prefix);
    test_result(result > 0, "EVPN Type 5 non-zero ESI + zero GW allowed");
    evpn_type5_nlri_list_free(nlri);
}

/*
 * Test 33: EVPN Type 5 allows non-zero gateway-ip with zero ESI
 */
void test_evpn_type5_gw_nonzero_esi_zero() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_type5_nlri_t    *nlri = evpn_type5_nlri_create_ipv4("192.168.1.0", 24, rd, 100, "10.0.0.1", 10000);
    uint8_t               buffer[256];
    int                   result;

    assert(nlri != NULL);
    // ESI should be zero from create function
    result = bgp_encode_evpn_type5_prefix(buffer, &nlri->prefix);
    test_result(result > 0, "EVPN Type 5 zero ESI + non-zero GW allowed");
    evpn_type5_nlri_list_free(nlri);
}

/*
 * Test 34: EVPN Type 5 ethernet_tag_id = 0
 */
void test_evpn_type5_etag_zero() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_type5_nlri_t    *nlri = evpn_type5_nlri_create_ipv4("10.0.0.0", 8, rd, 0, "10.0.0.1", 1000);
    uint8_t               buffer[256];
    int                   len;

    assert(nlri != NULL);
    len = bgp_encode_evpn_type5_prefix(buffer, &nlri->prefix);

    // Ethernet Tag ID at offset: 1(rt) + 1(len) + 8(RD) + 10(ESI) = 20
    test_result((len > 0) &&
                (buffer[20] == 0) && (buffer[21] == 0) &&
                (buffer[22] == 0) && (buffer[23] == 0),
                "EVPN Type 5 ethernet_tag_id=0");
    evpn_type5_nlri_list_free(nlri);
}

/*
 * Test 35: EVPN Type 5 ethernet_tag_id = UINT32_MAX
 */
void test_evpn_type5_etag_max() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_type5_nlri_t    *nlri = evpn_type5_nlri_create_ipv4("10.0.0.0", 8, rd, 4294967295U, "10.0.0.1", 1000);
    uint8_t               buffer[256];
    int                   len;

    assert(nlri != NULL);
    len = bgp_encode_evpn_type5_prefix(buffer, &nlri->prefix);

    test_result((len > 0) &&
                (buffer[20] == 0xFF) && (buffer[21] == 0xFF) &&
                (buffer[22] == 0xFF) && (buffer[23] == 0xFF),
                "EVPN Type 5 ethernet_tag_id=UINT32_MAX");
    evpn_type5_nlri_list_free(nlri);
}

/*
 * Test 36: EVPN Type 5 IPv6 encoding size is exactly 60 bytes
 */
void test_evpn_type5_ipv6_size_exact() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_type5_nlri_t    *nlri = evpn_type5_nlri_create_ipv6("2001:db8::", 32, rd, 0, NULL, 1000);
    uint8_t               buffer[256];
    int                   len;

    assert(nlri != NULL);
    len = bgp_encode_evpn_type5_prefix(buffer, &nlri->prefix);

    // rt(1) + len(1) + RD(8) + ESI(10) + ETag(4) + PL(1) + IP(16) + GW(16) + label(3) = 60
    test_result(len == 60, "EVPN Type 5 IPv6 encoding is exactly 60 bytes");
    evpn_type5_nlri_list_free(nlri);
}

/*
 * Test 37: EVPN Type 5 IPv4 encoding size is exactly 36 bytes
 */
void test_evpn_type5_ipv4_size_exact() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_type5_nlri_t    *nlri = evpn_type5_nlri_create_ipv4("10.0.0.0", 8, rd, 0, NULL, 1000);
    uint8_t               buffer[256];
    int                   len;

    assert(nlri != NULL);
    len = bgp_encode_evpn_type5_prefix(buffer, &nlri->prefix);

    // rt(1) + len(1) + RD(8) + ESI(10) + ETag(4) + PL(1) + IP(4) + GW(4) + label(3) = 36
    test_result(len == 36, "EVPN Type 5 IPv4 encoding is exactly 36 bytes");
    evpn_type5_nlri_list_free(nlri);
}

/*
 * Test 38: VPNv4 prefix_len minimum = 88 (24 label + 64 RD + 0 IP)
 */
void test_vpnv4_prefix_len_minimum() {
    vpnv4_prefix_t prefix;
    uint8_t        buffer[256];
    int            len;

    prefix.prefix_len = 88;  /* 24 + 64 + 0 */
    prefix.label.label = 100;
    prefix.label.tc = 0;
    prefix.label.s = 1;
    prefix.label.ttl = 0;
    prefix.rd = rd_create_type0(65000, 1);
    prefix.prefix = 0;

    len = bgp_encode_vpnv4_prefix(buffer, &prefix);

    // 1(plen) + 3(label) + 8(RD) + 0(IP) = 12
    test_result((len == 12) && (buffer[0] == 88), "VPNv4 prefix_len=88 (default route)");
}

/*
 * Test 39: VPNv4 /32 host = prefix_len 120 (24 + 64 + 32)
 */
void test_vpnv4_host_route() {
    vpnv4_prefix_t prefix;
    uint8_t        buffer[256];
    int            len;

    prefix.prefix_len = 120;  /* 24 + 64 + 32 */
    prefix.label.label = 500;
    prefix.label.tc = 0;
    prefix.label.s = 1;
    prefix.label.ttl = 0;
    prefix.rd = rd_create_type0(65000, 1);
    inet_pton(AF_INET, "10.0.0.1", &prefix.prefix);

    len = bgp_encode_vpnv4_prefix(buffer, &prefix);

    // 1(plen) + 3(label) + 8(RD) + 4(IP) = 16
    test_result((len == 16) && (buffer[0] == 120), "VPNv4 /32 host route (prefix_len=120)");
}

/*
 * Test 40: VPNv6 /128 host = prefix_len 216 (24 + 64 + 128)
 */
void test_vpnv6_host_route() {
    vpnv6_prefix_t prefix;
    uint8_t        buffer[256];
    int            len;

    prefix.prefix_len = 216;  /* 24 + 64 + 128 */
    prefix.label.label = 700;
    prefix.label.tc = 0;
    prefix.label.s = 1;
    prefix.label.ttl = 0;
    prefix.rd = rd_create_type1(0x0A000001, 1);
    inet_pton(AF_INET6, "2001:db8::1", prefix.prefix);

    len = bgp_encode_vpnv6_prefix(buffer, &prefix);

    // 1(plen) + 3(label) + 8(RD) + 16(IP) = 28
    test_result((len == 28) && (buffer[0] == 216), "VPNv6 /128 host route (prefix_len=216)");
}

/*
 * Test 41: MPLS max label in VPN context round-trips correctly
 */
void test_vpnv4_mpls_label_max() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    vpnv4_nlri_list_t    *nlri = vpnv4_nlri_create("10.0.0.0", 8, 1048575, rd);
    uint8_t               buffer[256];

    assert(nlri != NULL);
    bgp_encode_vpnv4_prefix(buffer, &nlri->prefix);

    // Label is at bytes 1-3; decode and verify
    uint32_t wire_label = ((uint32_t)buffer[1] << 12) |
                          ((uint32_t)buffer[2] << 4) |
                          ((uint32_t)buffer[3] >> 4);
    test_result((wire_label == 1048575) && ((buffer[3] & 0x01) == 1), "VPNv4 MPLS max label (1048575)");
    vpnv4_nlri_list_free(nlri);
}

/*
 * Test 42: Extended Community RT boundary - AS=0, value=0
 */
void test_ext_comm_rt_zeros() {
    bgp_path_attr_t *rt = bgp_attr_create_ext_comm_rt(0, 0);
    int passed = (rt != NULL) && (rt->length == 8) &&
                 (rt->value[0] == 0x00) && (rt->value[1] == 0x02) &&
                 (rt->value[2] == 0x00) && (rt->value[3] == 0x00) &&
                 (rt->value[4] == 0x00) && (rt->value[5] == 0x00) &&
                 (rt->value[6] == 0x00) && (rt->value[7] == 0x00);

    bgp_path_attr_free(rt);
    test_result(passed, "Extended Community RT (AS=0, value=0)");
}

/*
 * Test 43: Extended Community RT AS4 boundary - max AS
 */
void test_ext_comm_rt_as4_max() {
    bgp_path_attr_t *rt = bgp_attr_create_ext_comm_rt_as4(4294967295U, 65535);
    int passed = (rt != NULL) && (rt->length == 8) &&
                 (rt->value[0] == 0x02) && (rt->value[1] == 0x02) &&
                 (rt->value[2] == 0xFF) && (rt->value[3] == 0xFF) &&
                 (rt->value[4] == 0xFF) && (rt->value[5] == 0xFF) &&
                 (rt->value[6] == 0xFF) && (rt->value[7] == 0xFF);

    bgp_path_attr_free(rt);
    test_result(passed, "Extended Community RT AS4 max values");
}

/*
 * Test 44: VPNv4 UPDATE with EVPN IPv6 next-hop carries correct nh_len
 */
void test_vpnv4_ipv6_transport_next_hop() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    vpnv4_nlri_list_t    *nlri = vpnv4_nlri_create("10.1.0.0", 16, 1000, rd);
    bgp_path_attr_t      *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_next_hop_t       next_hop = make_ipv6_next_hop("2001:db8::1");
    bgp_update_result_t *result;
    const uint8_t       *value = NULL;
    uint16_t             length = 0;
    int                  passed;

    origin->next = as_path;
    result = bgp_generate_update_vpnv4(nlri, origin, NULL, 0, BGP_VPN_TRANSPORT_IPV6, &next_hop);
    assert(result != NULL);

    // VPN IPv6 next-hop: 8 bytes reserved + 16 bytes IPv6 = 24
    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI, &value, &length) &&
             (value[3] == 24);

    bgp_update_result_free(result);
    vpnv4_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    test_result(passed, "VPNv4 over IPv6 transport next-hop (24 bytes)");
}

/*
 * Test 45: EVPN IPv6 next-hop carries correct nh_len
 */
void test_evpn_ipv6_next_hop() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_type5_nlri_t    *nlri = evpn_type5_nlri_create_ipv4("192.168.1.0", 24, rd, 100, "10.0.0.1", 10000);
    bgp_path_attr_t      *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_next_hop_t       next_hop = make_ipv6_next_hop("2001:db8::9");
    bgp_update_result_t *result;
    const uint8_t       *value = NULL;
    uint16_t             length = 0;
    int                  passed;

    origin->next = as_path;
    result = bgp_generate_update_evpn_type5(nlri, origin, NULL, 0, &next_hop);
    assert(result != NULL);

    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI, &value, &length) &&
             (value[3] == 16);  /* EVPN next-hop: 16 bytes for IPv6 */

    bgp_update_result_free(result);
    evpn_type5_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    test_result(passed, "EVPN IPv6 next-hop (16 bytes)");
}

/*
 * Test 46: EVPN Type 5 withdrawal
 */
void test_evpn_type5_withdrawal() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_type5_nlri_t    *withdrawn = evpn_type5_nlri_create_ipv4("192.168.1.0", 24, rd, 100, NULL, 0);
    bgp_update_result_t  *result;
    int                   passed;

    result = bgp_generate_update_evpn_type5(NULL, NULL, withdrawn, 0, NULL);
    assert(result != NULL);

    passed = (result->num_messages == 1) &&
             has_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_UNREACH_NLRI);

    bgp_update_result_free(result);
    evpn_type5_nlri_list_free(withdrawn);
    test_result(passed, "EVPN Type 5 withdrawal");
}

/*
 * Test 47: RD type 2 wire format (4-byte AS)
 */
void test_rd_type2_wire_format() {
    route_distinguisher_t rd = rd_create_type2(4200000000UL, 500);
    vpnv4_prefix_t        prefix;
    uint8_t               buffer[256];

    prefix.prefix_len = 24 + 64 + 24;
    prefix.label.label = 100;
    prefix.label.tc = 0;
    prefix.label.s = 1;
    prefix.label.ttl = 0;
    prefix.rd = rd;
    inet_pton(AF_INET, "10.1.1.0", &prefix.prefix);

    bgp_encode_vpnv4_prefix(buffer, &prefix);

    // RD type 2: type field = 0x0002 at bytes 4-5
    test_result((buffer[4] == 0x00) && (buffer[5] == 0x02), "RD type 2 wire format");
}

static void test_invalid_vpn_inputs(void) {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    int passed = vpnv4_nlri_create("bad", 24, 100, rd) == NULL &&
                 vpnv4_nlri_create(NULL, 24, 100, rd) == NULL &&
                 vpnv4_nlri_create("10.0.0.0", 33, 100, rd) == NULL &&
                 vpnv6_nlri_create("bad", 64, 100, rd) == NULL &&
                 vpnv6_nlri_create("2001:db8::", 129, 100, rd) == NULL;
    uint8_t            wire[64];
    vpnv4_nlri_list_t *v4 = vpnv4_nlri_create_path_id("10.0.0.0", 24, 100, rd, 7);
    vpnv6_nlri_list_t *v6 = vpnv6_nlri_create_path_id("2001:db8::", 64, 100, rd, 7);
    assert(v4 && v6);
    v4->prefix.prefix_len = 87;
    v6->prefix.prefix_len = 217;
    passed &= bgp_encode_vpnv4_prefix(wire, &v4->prefix) < 0 &&
              bgp_encode_vpnv6_prefix(wire, &v6->prefix) < 0;
    bgp_update_result_t *r4 = bgp_generate_update_vpnv4(NULL, NULL, v4, 4096, BGP_VPN_TRANSPORT_IPV4, NULL);
    bgp_update_result_t *r6 = bgp_generate_update_vpnv6(NULL, NULL, v6, 4096, BGP_VPN_TRANSPORT_IPV6, NULL);
    passed &= !r4 && !r6;
    bgp_update_result_free(r4);
    bgp_update_result_free(r6);
    vpnv4_nlri_list_free(v4);
    vpnv6_nlri_list_free(v6);
    test_result(passed, "VPN malformed prefixes rejected through ADD-PATH chunking");
}

int main() {
    test_invalid_vpn_inputs();
    printf("========================================\n");
    printf("BGP VPN UPDATE Message Generation Tests\n");
    printf("========================================\n\n");

    test_rd_creation();
    test_vpnv4_nlri_creation();
    test_vpnv6_nlri_creation();
    test_evpn_type5_ipv4_creation();
    test_evpn_type5_ipv6_creation();
    test_vpnv4_prefix_encoding();
    test_vpnv6_prefix_encoding();
    test_evpn_type5_encoding();
    test_vpnv4_update_next_hop_length();
    test_vpnv6_default_next_hop();
    test_vpnv6_ipv4_transport();
    test_vpnv6_ipv6_transport();
    test_vpnv4_withdrawals();
    test_vpnv4_add_path_update();
    test_vpnv4_add_path_withdrawals();
    test_evpn_ipv4_next_hop();
    test_evpn_type5_update_with_encap_and_router_mac_ext_comms();
    test_vpnv6_add_path_update();
    test_evpn_type5_add_path_update();
    test_large_vpnv4_list();
    test_rd_types();
    test_mpls_label_encoding();
    test_evpn_type5_encoding_size();
    test_ext_comm_rt();
    test_ext_comm_rt_as4();
    test_ext_comm_rt_ip();
    test_rd_wire_format();
    test_vpnv4_message_splitting();
    test_vpnv6_message_splitting();
    test_evpn_large_list();
    test_vpnv4_extreme_splitting();
    test_vpnv4_add_path_message_splitting();

    // Adversarial / boundary tests
    test_evpn_type5_esi_gw_both_nonzero();
    test_evpn_type5_esi_nonzero_gw_zero();
    test_evpn_type5_gw_nonzero_esi_zero();
    test_evpn_type5_etag_zero();
    test_evpn_type5_etag_max();
    test_evpn_type5_ipv6_size_exact();
    test_evpn_type5_ipv4_size_exact();
    test_vpnv4_prefix_len_minimum();
    test_vpnv4_host_route();
    test_vpnv6_host_route();
    test_vpnv4_mpls_label_max();
    test_ext_comm_rt_zeros();
    test_ext_comm_rt_as4_max();
    test_vpnv4_ipv6_transport_next_hop();
    test_evpn_ipv6_next_hop();
    test_evpn_type5_withdrawal();
    test_rd_type2_wire_format();

    printf("========================================\n");
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
