// Unit tests for BGP EVPN Types 1-4 UPDATE message generation

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
    memset(esi.value, fill, 9);
    return esi;
}

static evpn_esi_t make_zero_esi(void) {
    evpn_esi_t esi;

    esi.type = 0;
    memset(esi.value, 0, 9);
    return esi;
}

// Type 1 Tests

void test_type1_nlri_creation() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_esi_t            esi = make_esi(1, 0xAA);
    evpn_type1_nlri_t    *nlri = evpn_type1_nlri_create(rd, esi, 100, 5000);

    assert(nlri != NULL);
    test_result((nlri->prefix.route_type == EVPN_RT_ETHERNET_AUTO_DISCOVERY) &&
                (nlri->prefix.ethernet_tag_id == 100) &&
                (nlri->prefix.esi.type == 1) &&
                (nlri->prefix.label.label == 5000),
                "Type 1 NLRI creation");
    evpn_type1_nlri_list_free(nlri);
}

void test_type1_prefix_encoding() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_esi_t            esi = make_esi(1, 0xBB);
    evpn_type1_nlri_t    *nlri = evpn_type1_nlri_create(rd, esi, 200, 1000);
    uint8_t               buffer[256];
    int                   len;

    assert(nlri != NULL);
    len = bgp_encode_evpn_type1_prefix(buffer, &nlri->prefix);

    // rt(1) + len(1) + RD(8) + ESI(10) + ETag(4) + Label(3) = 27
    test_result((len == 27) &&
                (buffer[0] == EVPN_RT_ETHERNET_AUTO_DISCOVERY) &&
                (buffer[1] == 25),  /* length = 27 - 2 */
                "Type 1 prefix encoding size");
    evpn_type1_nlri_list_free(nlri);
}

void test_type1_wire_format() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_esi_t            esi = make_esi(3, 0x42);
    evpn_type1_nlri_t    *nlri = evpn_type1_nlri_create(rd, esi, 0, 100);
    uint8_t               buffer[256];

    assert(nlri != NULL);
    bgp_encode_evpn_type1_prefix(buffer, &nlri->prefix);

    // Check route type at offset 0
    int passed = (buffer[0] == 1);

    // ESI type at offset 10 (after rt + len + RD)
    passed = passed && (buffer[10] == 3);

    // ESI value at offsets 11-19 (9 bytes of 0x42)
    for (int i = 0; i < 9; i++) {
        passed = passed && (buffer[11 + i] == 0x42);
    }

    // Ethernet Tag ID at offset 20 (all zeros)
    passed = passed && (buffer[20] == 0) && (buffer[21] == 0) &&
             (buffer[22] == 0) && (buffer[23] == 0);

    // RD at offset 2 (after rt + len)
    passed = passed && test_wire_rd_is(buffer + 2, 0, 65000, 1);

    test_result(passed, "Type 1 wire format");
    evpn_type1_nlri_list_free(nlri);
}

void test_type1_update_generation() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_esi_t            esi = make_esi(0, 0x11);
    evpn_type1_nlri_t    *nlri = evpn_type1_nlri_create(rd, esi, 0, 1000);
    bgp_path_attr_t      *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_next_hop_t       next_hop = make_ipv4_next_hop("10.0.0.1");
    bgp_update_result_t *result;
    const uint8_t       *value = NULL;
    uint16_t             length = 0;
    int                  passed;

    origin->next = as_path;
    result = bgp_generate_update_evpn_type1(nlri, origin, NULL, 0, &next_hop);
    assert(result != NULL);

    passed = (result->num_messages == 1) &&
             find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI, &value, &length) &&
             (value[0] == 0x00) && (value[1] == AFI_L2VPN) &&
             (value[2] == SAFI_EVPN) &&
             (value[3] == 4);  /* IPv4 next-hop = 4 bytes */

    bgp_update_result_free(result);
    evpn_type1_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    test_result(passed, "Type 1 UPDATE generation");
}

void test_type1_add_path() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_esi_t            esi = make_zero_esi();
    evpn_type1_nlri_t    *nlri = evpn_type1_nlri_create_path_id(rd, esi, 0, 1000, 42);
    bgp_path_attr_t      *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_next_hop_t       next_hop = make_ipv4_next_hop("10.0.0.1");
    bgp_update_result_t *result;
    const uint8_t       *value = NULL;
    uint16_t             length = 0;
    int                  offset = 0;
    int                  passed;

    origin->next = as_path;
    result = bgp_generate_update_evpn_type1(nlri, origin, NULL, 0, &next_hop);
    assert(result != NULL);

    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI, &value, &length) &&
             mp_reach_nlri_offset(value, length, &offset) &&
             (read_u32(value + offset) == 42) &&
             (value[offset + 4] == EVPN_RT_ETHERNET_AUTO_DISCOVERY);

    bgp_update_result_free(result);
    evpn_type1_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    test_result(passed, "Type 1 ADD-PATH");
}

void test_type1_withdrawal() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_esi_t            esi = make_zero_esi();
    evpn_type1_nlri_t    *withdrawn = evpn_type1_nlri_create(rd, esi, 0, 0);
    bgp_update_result_t  *result;
    int                   passed;

    result = bgp_generate_update_evpn_type1(NULL, NULL, withdrawn, 0, NULL);
    assert(result != NULL);

    passed = (result->num_messages == 1) &&
             has_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_UNREACH_NLRI);

    bgp_update_result_free(result);
    evpn_type1_nlri_list_free(withdrawn);
    test_result(passed, "Type 1 withdrawal");
}

// Type 2 Tests

void test_type2_mac_ipv4_creation() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_esi_t            esi = make_zero_esi();
    uint8_t mac[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    evpn_type2_nlri_t *nlri = evpn_type2_nlri_create_ipv4(rd, esi, 100, mac, "192.168.1.1", 5000);

    assert(nlri != NULL);
    test_result((nlri->prefix.route_type == EVPN_RT_MAC_IP_ADVERTISEMENT) &&
                (nlri->prefix.ip_addr_len == 32) &&
                (nlri->prefix.has_label2 == 0) &&
                (memcmp(nlri->prefix.mac_addr, mac, 6) == 0),
                "Type 2 MAC+IPv4 creation");
    evpn_type2_nlri_list_free(nlri);
}

void test_type2_invalid_ipv4_text_rejected() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_esi_t            esi = make_zero_esi();
    uint8_t mac[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};

    test_result(evpn_type2_nlri_create_ipv4(rd, esi, 100, mac,
                                            "not-an-ipv4-address", 5000) == NULL,
                "Type 2 invalid IPv4 text rejected");
}

void test_type2_mac_ipv6_creation() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_esi_t            esi = make_zero_esi();
    uint8_t mac[] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    evpn_type2_nlri_t *nlri = evpn_type2_nlri_create_ipv6(rd, esi, 200, mac, "2001:db8::1", 6000);

    assert(nlri != NULL);
    test_result((nlri->prefix.route_type == EVPN_RT_MAC_IP_ADVERTISEMENT) &&
                (nlri->prefix.ip_addr_len == 128),
                "Type 2 MAC+IPv6 creation");
    evpn_type2_nlri_list_free(nlri);
}

void test_type2_invalid_ipv6_text_rejected() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_esi_t            esi = make_zero_esi();
    uint8_t mac[] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

    test_result(evpn_type2_nlri_create_ipv6(rd, esi, 200, mac,
                                            "not-an-ipv6-address", 6000) == NULL,
                "Type 2 invalid IPv6 text rejected");
}

void test_type2_mac_only_creation() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_esi_t            esi = make_zero_esi();
    uint8_t mac[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    evpn_type2_nlri_t *nlri = evpn_type2_nlri_create_mac_only(rd, esi, 0, mac, 1000);

    assert(nlri != NULL);
    test_result((nlri->prefix.route_type == EVPN_RT_MAC_IP_ADVERTISEMENT) &&
                (nlri->prefix.ip_addr_len == 0),
                "Type 2 MAC-only creation");
    evpn_type2_nlri_list_free(nlri);
}

void test_type2_encoding_mac_ipv4() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_esi_t            esi = make_zero_esi();
    uint8_t mac[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    evpn_type2_nlri_t *nlri = evpn_type2_nlri_create_ipv4(rd, esi, 0, mac, "192.168.1.1", 1000);
    uint8_t            buffer[256];
    int                len;

    assert(nlri != NULL);
    len = bgp_encode_evpn_type2_prefix(buffer, &nlri->prefix);

    /*
     * rt(1) + len(1) + RD(8) + ESI(10) + ETag(4) + MAC_LEN(1) + MAC(6)
     * + IP_LEN(1) + IP(4) + Label1(3) = 39
     */
    test_result((len == 39) && (buffer[0] == EVPN_RT_MAC_IP_ADVERTISEMENT), "Type 2 MAC+IPv4 encoding size");
    evpn_type2_nlri_list_free(nlri);
}

void test_type2_encoding_mac_ipv6() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_esi_t            esi = make_zero_esi();
    uint8_t mac[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    evpn_type2_nlri_t *nlri = evpn_type2_nlri_create_ipv6(rd, esi, 0, mac, "2001:db8::1", 1000);
    uint8_t            buffer[256];
    int                len;

    assert(nlri != NULL);
    len = bgp_encode_evpn_type2_prefix(buffer, &nlri->prefix);

    /*
     * rt(1) + len(1) + RD(8) + ESI(10) + ETag(4) + MAC_LEN(1) + MAC(6)
     * + IP_LEN(1) + IP(16) + Label1(3) = 51
     */
    test_result((len == 51) && (buffer[0] == EVPN_RT_MAC_IP_ADVERTISEMENT), "Type 2 MAC+IPv6 encoding size");
    evpn_type2_nlri_list_free(nlri);
}

void test_type2_encoding_mac_only() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_esi_t            esi = make_zero_esi();
    uint8_t mac[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    evpn_type2_nlri_t *nlri = evpn_type2_nlri_create_mac_only(rd, esi, 0, mac, 1000);
    uint8_t            buffer[256];
    int                len;

    assert(nlri != NULL);
    len = bgp_encode_evpn_type2_prefix(buffer, &nlri->prefix);

    /*
     * rt(1) + len(1) + RD(8) + ESI(10) + ETag(4) + MAC_LEN(1) + MAC(6)
     * + IP_LEN(1) + IP(0) + Label1(3) = 35
     */
    test_result((len == 35) && (buffer[0] == EVPN_RT_MAC_IP_ADVERTISEMENT), "Type 2 MAC-only encoding size");
    evpn_type2_nlri_list_free(nlri);
}

void test_type2_encoding_two_labels() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_esi_t            esi = make_zero_esi();
    uint8_t mac[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    evpn_type2_nlri_t *nlri = evpn_type2_nlri_create_ipv4(rd, esi, 0, mac, "10.0.0.1", 1000);
    uint8_t            buffer[256];
    int                len;

    assert(nlri != NULL);
    evpn_type2_nlri_set_label2(nlri, 2000);
    len = bgp_encode_evpn_type2_prefix(buffer, &nlri->prefix);

    // Same as IPv4 (39) + Label2(3) = 42
    test_result((len == 42) && (buffer[0] == EVPN_RT_MAC_IP_ADVERTISEMENT), "Type 2 two-label encoding size");
    evpn_type2_nlri_list_free(nlri);
}

void test_type2_wire_format_mac() {
    route_distinguisher_t rd = rd_create_type1(0x0A000001, 100);
    evpn_esi_t            esi = make_zero_esi();
    uint8_t mac[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE};
    evpn_type2_nlri_t *nlri = evpn_type2_nlri_create_mac_only(rd, esi, 0, mac, 100);
    uint8_t            buffer[256];

    assert(nlri != NULL);
    bgp_encode_evpn_type2_prefix(buffer, &nlri->prefix);

    // MAC addr length at offset 24 (rt + len + RD + ESI + ETag)
    int passed = (buffer[24] == 48);

    // MAC at offset 25-30
    passed = passed && (buffer[25] == 0xDE) && (buffer[26] == 0xAD) &&
             (buffer[27] == 0xBE) && (buffer[28] == 0xEF) &&
             (buffer[29] == 0xCA) && (buffer[30] == 0xFE);

    // IP addr length at offset 31
    passed = passed && (buffer[31] == 0);

    // RD at offset 2 (after rt + len), type 1: 10.0.0.1:100
    passed = passed && test_wire_rd_is(buffer + 2, 1, 0x0A000001, 100);

    test_result(passed, "Type 2 wire format MAC");
    evpn_type2_nlri_list_free(nlri);
}

void test_type2_invalid_ip_length_rejected() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_esi_t            esi = make_zero_esi();
    uint8_t mac[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    evpn_type2_nlri_t *nlri = evpn_type2_nlri_create_mac_only(rd, esi, 0, mac, 100);
    uint8_t            buffer[256];

    assert(nlri != NULL);

    // Only 0, 32, and 128 are valid in RFC 7432 strict mode.
    nlri->prefix.ip_addr_len = 24;

    test_result(bgp_encode_evpn_type2_prefix(buffer, &nlri->prefix) < 0, "Type 2 invalid IP length rejected");
    evpn_type2_nlri_list_free(nlri);
}

void test_type2_label_overflow_rejected() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_esi_t            esi = make_zero_esi();
    uint8_t mac[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    evpn_type2_nlri_t *nlri = evpn_type2_nlri_create_mac_only(rd, esi, 0, mac, 100);
    uint8_t            buffer[256];

    assert(nlri != NULL);

    /*
     * The generic MPLS encoder masks oversized values, but the strict EVPN
     * Type 2 path should reject them before any on-wire truncation happens.
     */
    nlri->prefix.label1.label = 0x100000;

    test_result(bgp_encode_evpn_type2_prefix(buffer, &nlri->prefix) < 0, "Type 2 Label1 overflow rejected");
    evpn_type2_nlri_list_free(nlri);
}

/*
 * The 3-byte label field at buffer + offset holds b0 b1 b2.
 */
static int label_field_is(const uint8_t *buffer, int offset, uint8_t b0, uint8_t b1, uint8_t b2) {
    return buffer[offset] == b0 && buffer[offset + 1] == b1 && buffer[offset + 2] == b2;
}

/*
 * EVPN label fields hold an MPLS label (RFC 7432): 30000 is 30000 << 4 with the bottom-of-stack bit, 07 53 01. With
 * VXLAN, NVGRE and the other IP encapsulations they hold the 24-bit VNI itself (RFC 8365 section 5.1.3): 00 75 30.
 */
void test_label_mpls_and_vni_forms() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_esi_t            esi = make_zero_esi();
    uint8_t mac[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    evpn_type1_nlri_t *type1 = evpn_type1_nlri_create(rd, esi, 7, 30000);
    evpn_type2_nlri_t *type2 = evpn_type2_nlri_create_mac_only(rd, esi, 0, mac, 30000);
    evpn_type5_nlri_t *type5 = evpn_type5_nlri_create_ipv4("172.16.0.0", 24, rd, 0, NULL, 30000);
    uint8_t            buffer[256];
    int                ok;

    assert(type1 != NULL && type2 != NULL && type5 != NULL);

    // Type 1: route type, length, RD (8), ESI (10), Ethernet tag (4), then the label at 24.
    ok = bgp_encode_evpn_type1_prefix(buffer, &type1->prefix) == 27 && label_field_is(buffer, 24, 0x07, 0x53, 0x01);
    type1->prefix.label_vni = 1;
    ok = ok && bgp_encode_evpn_type1_prefix(buffer, &type1->prefix) == 27 &&
         label_field_is(buffer, 24, 0x00, 0x75, 0x30);
    test_result(ok, "Type 1 label: MPLS 30000 is 07 53 01, VNI 30000 is 00 75 30");

    // Type 2 MAC only: ... Ethernet tag, MAC length, MAC (6), IP length (0), then Label1 at 32 and Label2 at 35.
    ok = bgp_encode_evpn_type2_prefix(buffer, &type2->prefix) == 35 && label_field_is(buffer, 32, 0x07, 0x53, 0x01);
    evpn_type2_nlri_set_label2(type2, 40000);
    ok = ok && bgp_encode_evpn_type2_prefix(buffer, &type2->prefix) == 38 &&
         label_field_is(buffer, 35, 0x09, 0xC4, 0x01);
    type2->prefix.label_vni = 1;
    ok = ok && bgp_encode_evpn_type2_prefix(buffer, &type2->prefix) == 38 &&
         label_field_is(buffer, 32, 0x00, 0x75, 0x30) && label_field_is(buffer, 35, 0x00, 0x9C, 0x40);
    test_result(ok, "Type 2 Label1 and Label2: MPLS form, or both VNIs with label_vni");

    // Type 5 IPv4: ... Ethernet tag, prefix length, prefix (4), gateway (4), then the label at 33.
    ok = bgp_encode_evpn_type5_prefix(buffer, &type5->prefix) == 36 && label_field_is(buffer, 33, 0x07, 0x53, 0x01);
    type5->prefix.label_vni = 1;
    ok = ok && bgp_encode_evpn_type5_prefix(buffer, &type5->prefix) == 36 &&
         label_field_is(buffer, 33, 0x00, 0x75, 0x30);
    type5->prefix.label.label = 0xFFFFFF;
    ok = ok && bgp_encode_evpn_type5_prefix(buffer, &type5->prefix) == 36 &&
         label_field_is(buffer, 33, 0xFF, 0xFF, 0xFF);
    test_result(ok, "Type 5 label: MPLS 07 53 01, VNI 00 75 30, largest VNI FF FF FF");

    evpn_type1_nlri_list_free(type1);
    evpn_type2_nlri_list_free(type2);
    evpn_type5_nlri_list_free(type5);
}

/*
 * A VNI has 24 bits and an MPLS label 20: Type 2 rejects values past the form's range rather than truncating them.
 */
void test_type2_label_ranges_follow_form() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_esi_t            esi = make_zero_esi();
    uint8_t mac[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    evpn_type2_nlri_t *nlri = evpn_type2_nlri_create_mac_only(rd, esi, 0, mac, 0xFFFFF);
    uint8_t            buffer[256];
    int                ok;

    assert(nlri != NULL);
    evpn_type2_nlri_set_label2(nlri, 0xFFFFF);
    ok = bgp_encode_evpn_type2_prefix(buffer, &nlri->prefix) == 38 && label_field_is(buffer, 32, 0xFF, 0xFF, 0xF1);
    nlri->prefix.label1.label = 0x100000;
    ok = ok && bgp_encode_evpn_type2_prefix(buffer, &nlri->prefix) < 0;
    nlri->prefix.label_vni = 1;
    nlri->prefix.label1.label = 0xFFFFFF;
    nlri->prefix.label2.label = 0xFFFFFF;
    ok = ok && bgp_encode_evpn_type2_prefix(buffer, &nlri->prefix) == 38 &&
         label_field_is(buffer, 32, 0xFF, 0xFF, 0xFF) && label_field_is(buffer, 35, 0xFF, 0xFF, 0xFF);
    nlri->prefix.label1.label = 0x1000000;
    ok = ok && bgp_encode_evpn_type2_prefix(buffer, &nlri->prefix) < 0;
    nlri->prefix.label1.label = 1;
    nlri->prefix.label2.label = 0x1000000;
    ok = ok && bgp_encode_evpn_type2_prefix(buffer, &nlri->prefix) < 0;
    test_result(ok, "Type 2 labels: MPLS up to 1048575, VNI up to 16777215, larger rejected");
    evpn_type2_nlri_list_free(nlri);
}

void test_type2_update_generation() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_esi_t            esi = make_zero_esi();
    uint8_t mac[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    evpn_type2_nlri_t *nlri = evpn_type2_nlri_create_ipv4(rd, esi, 0, mac, "10.0.0.1", 1000);
    bgp_path_attr_t   *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_next_hop_t       next_hop = make_ipv4_next_hop("10.0.0.9");
    bgp_update_result_t *result;
    const uint8_t       *value = NULL;
    uint16_t             length = 0;
    int                  passed;

    origin->next = as_path;
    result = bgp_generate_update_evpn_type2(nlri, origin, NULL, 0, &next_hop);
    assert(result != NULL);

    passed = (result->num_messages == 1) &&
             find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI, &value, &length) &&
             (value[0] == 0x00) && (value[1] == AFI_L2VPN) &&
             (value[2] == SAFI_EVPN);

    bgp_update_result_free(result);
    evpn_type2_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    test_result(passed, "Type 2 UPDATE generation");
}

void test_type2_update_with_encap_and_router_mac_ext_comms() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_esi_t            esi = make_zero_esi();
    uint8_t mac[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t router_mac[] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    evpn_type2_nlri_t *nlri = evpn_type2_nlri_create_ipv4(rd, esi, 0, mac, "10.0.0.1", 1000);
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

    result = bgp_generate_update_evpn_type2(nlri, origin, NULL, 0, &next_hop);
    assert(result != NULL);

    passed = passed &&
             find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_EXT_COMM, &value, &length) &&
             (length == 16) &&
             (value[0] == 0x03) && (value[1] == 0x0c) &&
             (value[6] == 0x00) && (value[7] == 0x08) &&
             (value[8] == 0x06) && (value[9] == 0x03) &&
             (memcmp(value + 10, router_mac, 6) == 0);

    bgp_update_result_free(result);
    evpn_type2_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    test_result(passed, "Type 2 UPDATE carries Encapsulation + Router MAC ECs");
}

void test_type2_add_path() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_esi_t            esi = make_zero_esi();
    uint8_t mac[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    evpn_type2_nlri_t *nlri = evpn_type2_nlri_create_ipv4_path_id(rd, esi, 0, mac, "10.0.0.1", 1000, 99);
    bgp_path_attr_t   *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_next_hop_t       next_hop = make_ipv4_next_hop("10.0.0.9");
    bgp_update_result_t *result;
    const uint8_t       *value = NULL;
    uint16_t             length = 0;
    int                  offset = 0;
    int                  passed;

    origin->next = as_path;
    result = bgp_generate_update_evpn_type2(nlri, origin, NULL, 0, &next_hop);
    assert(result != NULL);

    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI, &value, &length) &&
             mp_reach_nlri_offset(value, length, &offset) &&
             (read_u32(value + offset) == 99) &&
             (value[offset + 4] == EVPN_RT_MAC_IP_ADVERTISEMENT);

    bgp_update_result_free(result);
    evpn_type2_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    test_result(passed, "Type 2 ADD-PATH");
}

void test_type2_withdrawal() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_esi_t            esi = make_zero_esi();
    uint8_t mac[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    evpn_type2_nlri_t   *withdrawn = evpn_type2_nlri_create_mac_only(rd, esi, 0, mac, 0);
    bgp_update_result_t *result;
    int                  passed;

    result = bgp_generate_update_evpn_type2(NULL, NULL, withdrawn, 0, NULL);
    assert(result != NULL);

    passed = (result->num_messages == 1) &&
             has_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_UNREACH_NLRI);

    bgp_update_result_free(result);
    evpn_type2_nlri_list_free(withdrawn);
    test_result(passed, "Type 2 withdrawal");
}

void test_type2_ipv6_next_hop() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_esi_t            esi = make_zero_esi();
    uint8_t mac[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    evpn_type2_nlri_t *nlri = evpn_type2_nlri_create_ipv4(rd, esi, 0, mac, "10.0.0.1", 1000);
    bgp_path_attr_t   *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_next_hop_t       next_hop = make_ipv6_next_hop("2001:db8::1");
    bgp_update_result_t *result;
    const uint8_t       *value = NULL;
    uint16_t             length = 0;
    int                  passed;

    origin->next = as_path;
    result = bgp_generate_update_evpn_type2(nlri, origin, NULL, 0, &next_hop);
    assert(result != NULL);

    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI, &value, &length) &&
             (value[3] == 16);  /* IPv6 next-hop = 16 bytes */

    bgp_update_result_free(result);
    evpn_type2_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    test_result(passed, "Type 2 IPv6 next-hop");
}

void test_type2_ipv6_link_local_next_hop_rejected() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_esi_t            esi = make_zero_esi();
    uint8_t mac[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    evpn_type2_nlri_t   *nlri = evpn_type2_nlri_create_ipv4(rd, esi, 0, mac, "10.0.0.1", 1000);
    bgp_path_attr_t     *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    bgp_next_hop_t       next_hop = make_ipv6_next_hop_with_link_local("2001:db8::1", "fe80::1");
    bgp_update_result_t *result;

    assert(nlri != NULL);

    /*
     * RFC 7432 requires the EVPN MP_REACH next hop to be the advertising
     * PE's IPv4 or IPv6 address, so the strict helper keeps Type 2 on the
     * 4-byte or 16-byte next-hop forms.
     */
    result = bgp_generate_update_evpn_type2(nlri, origin, NULL, 0, &next_hop);

    test_result(result == NULL, "Type 2 IPv6 link-local next-hop rejected");
    bgp_update_result_free(result);
    evpn_type2_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
}

// Type 3 Tests

void test_type3_ipv4_creation() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_type3_nlri_t    *nlri = evpn_type3_nlri_create_ipv4(rd, 100, "10.0.0.1");

    assert(nlri != NULL);
    test_result((nlri->prefix.route_type == EVPN_RT_INCLUSIVE_MULTICAST) &&
                (nlri->prefix.ethernet_tag_id == 100) &&
                (nlri->prefix.ip_addr_len == 32),
                "Type 3 IPv4 creation");
    evpn_type3_nlri_list_free(nlri);
}

void test_type3_ipv6_creation() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_type3_nlri_t    *nlri = evpn_type3_nlri_create_ipv6(rd, 200, "2001:db8::1");

    assert(nlri != NULL);
    test_result((nlri->prefix.route_type == EVPN_RT_INCLUSIVE_MULTICAST) &&
                (nlri->prefix.ip_addr_len == 128),
                "Type 3 IPv6 creation");
    evpn_type3_nlri_list_free(nlri);
}

void test_type3_encoding_ipv4() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_type3_nlri_t    *nlri = evpn_type3_nlri_create_ipv4(rd, 0, "10.0.0.1");
    uint8_t               buffer[256];
    int                   len;

    assert(nlri != NULL);
    len = bgp_encode_evpn_type3_prefix(buffer, &nlri->prefix);

    // rt(1) + len(1) + RD(8) + ETag(4) + IP_LEN(1) + IP(4) = 19
    test_result((len == 19) && (buffer[0] == EVPN_RT_INCLUSIVE_MULTICAST), "Type 3 IPv4 encoding size");
    evpn_type3_nlri_list_free(nlri);
}

void test_type3_encoding_ipv6() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_type3_nlri_t    *nlri = evpn_type3_nlri_create_ipv6(rd, 0, "2001:db8::1");
    uint8_t               buffer[256];
    int                   len;

    assert(nlri != NULL);
    len = bgp_encode_evpn_type3_prefix(buffer, &nlri->prefix);

    // rt(1) + len(1) + RD(8) + ETag(4) + IP_LEN(1) + IP(16) = 31
    test_result((len == 31) && (buffer[0] == EVPN_RT_INCLUSIVE_MULTICAST), "Type 3 IPv6 encoding size");
    evpn_type3_nlri_list_free(nlri);
}

void test_type3_wire_format() {
    route_distinguisher_t rd = rd_create_type2(4200000000u, 7);
    evpn_type3_nlri_t    *nlri = evpn_type3_nlri_create_ipv4(rd, 500, "10.1.2.3");
    uint8_t               buffer[256];

    assert(nlri != NULL);
    bgp_encode_evpn_type3_prefix(buffer, &nlri->prefix);

    // Ethernet Tag ID at offset 10 (rt + len + RD)
    uint32_t etag = read_u32(buffer + 10);
    int      passed = (etag == 500);

    // IP addr length at offset 14
    passed = passed && (buffer[14] == 32);

    // IP addr at offset 15
    passed = passed && (buffer[15] == 10) && (buffer[16] == 1) &&
             (buffer[17] == 2) && (buffer[18] == 3);

    // RD at offset 2 (after rt + len), type 2: 4200000000:7
    passed = passed && test_wire_rd_is(buffer + 2, 2, 4200000000u, 7);

    test_result(passed, "Type 3 wire format");
    evpn_type3_nlri_list_free(nlri);
}

void test_type3_update_generation() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_type3_nlri_t    *nlri = evpn_type3_nlri_create_ipv4(rd, 0, "10.0.0.1");
    bgp_path_attr_t      *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_next_hop_t       next_hop = make_ipv4_next_hop("10.0.0.9");
    bgp_update_result_t *result;
    int                  passed;

    origin->next = as_path;
    result = bgp_generate_update_evpn_type3(nlri, origin, NULL, 0, &next_hop);
    assert(result != NULL);

    passed = (result->num_messages == 1) &&
             has_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI);

    bgp_update_result_free(result);
    evpn_type3_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    test_result(passed, "Type 3 UPDATE generation");
}

void test_type3_add_path() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_type3_nlri_t    *nlri = evpn_type3_nlri_create_ipv4_path_id(rd, 0, "10.0.0.1", 77);
    bgp_path_attr_t      *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_next_hop_t       next_hop = make_ipv4_next_hop("10.0.0.9");
    bgp_update_result_t *result;
    const uint8_t       *value = NULL;
    uint16_t             length = 0;
    int                  offset = 0;
    int                  passed;

    origin->next = as_path;
    result = bgp_generate_update_evpn_type3(nlri, origin, NULL, 0, &next_hop);
    assert(result != NULL);

    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI, &value, &length) &&
             mp_reach_nlri_offset(value, length, &offset) &&
             (read_u32(value + offset) == 77) &&
             (value[offset + 4] == EVPN_RT_INCLUSIVE_MULTICAST);

    bgp_update_result_free(result);
    evpn_type3_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    test_result(passed, "Type 3 ADD-PATH");
}

void test_type3_withdrawal() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_type3_nlri_t    *withdrawn = evpn_type3_nlri_create_ipv4(rd, 0, "10.0.0.1");
    bgp_update_result_t  *result;
    int                   passed;

    result = bgp_generate_update_evpn_type3(NULL, NULL, withdrawn, 0, NULL);
    assert(result != NULL);

    passed = (result->num_messages == 1) &&
             has_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_UNREACH_NLRI);

    bgp_update_result_free(result);
    evpn_type3_nlri_list_free(withdrawn);
    test_result(passed, "Type 3 withdrawal");
}

// Type 4 Tests

void test_type4_ipv4_creation() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_esi_t            esi = make_esi(2, 0x55);
    evpn_type4_nlri_t    *nlri = evpn_type4_nlri_create_ipv4(rd, esi, "10.0.0.1");

    assert(nlri != NULL);
    test_result((nlri->prefix.route_type == EVPN_RT_ETHERNET_SEGMENT) &&
                (nlri->prefix.esi.type == 2) &&
                (nlri->prefix.ip_addr_len == 32),
                "Type 4 IPv4 creation");
    evpn_type4_nlri_list_free(nlri);
}

void test_type4_ipv6_creation() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_esi_t            esi = make_esi(5, 0x77);
    evpn_type4_nlri_t    *nlri = evpn_type4_nlri_create_ipv6(rd, esi, "2001:db8::1");

    assert(nlri != NULL);
    test_result((nlri->prefix.route_type == EVPN_RT_ETHERNET_SEGMENT) &&
                (nlri->prefix.ip_addr_len == 128),
                "Type 4 IPv6 creation");
    evpn_type4_nlri_list_free(nlri);
}

void test_type4_encoding_ipv4() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_esi_t            esi = make_esi(1, 0x33);
    evpn_type4_nlri_t    *nlri = evpn_type4_nlri_create_ipv4(rd, esi, "10.0.0.1");
    uint8_t               buffer[256];
    int                   len;

    assert(nlri != NULL);
    len = bgp_encode_evpn_type4_prefix(buffer, &nlri->prefix);

    // rt(1) + len(1) + RD(8) + ESI(10) + IP_LEN(1) + IP(4) = 25
    test_result((len == 25) && (buffer[0] == EVPN_RT_ETHERNET_SEGMENT), "Type 4 IPv4 encoding size");
    evpn_type4_nlri_list_free(nlri);
}

void test_type4_encoding_ipv6() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_esi_t            esi = make_esi(1, 0x33);
    evpn_type4_nlri_t    *nlri = evpn_type4_nlri_create_ipv6(rd, esi, "2001:db8::1");
    uint8_t               buffer[256];
    int                   len;

    assert(nlri != NULL);
    len = bgp_encode_evpn_type4_prefix(buffer, &nlri->prefix);

    // rt(1) + len(1) + RD(8) + ESI(10) + IP_LEN(1) + IP(16) = 37
    test_result((len == 37) && (buffer[0] == EVPN_RT_ETHERNET_SEGMENT), "Type 4 IPv6 encoding size");
    evpn_type4_nlri_list_free(nlri);
}

void test_type4_wire_format() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_esi_t            esi = make_esi(4, 0x99);
    evpn_type4_nlri_t    *nlri = evpn_type4_nlri_create_ipv4(rd, esi, "10.1.2.3");
    uint8_t               buffer[256];

    assert(nlri != NULL);
    bgp_encode_evpn_type4_prefix(buffer, &nlri->prefix);

    // ESI type at offset 10
    int passed = (buffer[10] == 4);

    // ESI value at offsets 11-19
    for (int i = 0; i < 9; i++) {
        passed = passed && (buffer[11 + i] == 0x99);
    }

    // IP addr length at offset 20
    passed = passed && (buffer[20] == 32);

    // IP addr at offset 21
    passed = passed && (buffer[21] == 10) && (buffer[22] == 1) &&
             (buffer[23] == 2) && (buffer[24] == 3);

    // RD at offset 2 (after rt + len)
    passed = passed && test_wire_rd_is(buffer + 2, 0, 65000, 1);

    test_result(passed, "Type 4 wire format");
    evpn_type4_nlri_list_free(nlri);
}

void test_type4_update_generation() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_esi_t            esi = make_esi(1, 0x11);
    evpn_type4_nlri_t    *nlri = evpn_type4_nlri_create_ipv4(rd, esi, "10.0.0.1");
    bgp_path_attr_t      *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_next_hop_t       next_hop = make_ipv4_next_hop("10.0.0.9");
    bgp_update_result_t *result;
    int                  passed;

    origin->next = as_path;
    result = bgp_generate_update_evpn_type4(nlri, origin, NULL, 0, &next_hop);
    assert(result != NULL);

    passed = (result->num_messages == 1) &&
             has_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI);

    bgp_update_result_free(result);
    evpn_type4_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    test_result(passed, "Type 4 UPDATE generation");
}

void test_type4_add_path() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_esi_t            esi = make_esi(1, 0x11);
    evpn_type4_nlri_t    *nlri = evpn_type4_nlri_create_ipv4_path_id(rd, esi, "10.0.0.1", 555);
    bgp_path_attr_t      *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_next_hop_t       next_hop = make_ipv4_next_hop("10.0.0.9");
    bgp_update_result_t *result;
    const uint8_t       *value = NULL;
    uint16_t             length = 0;
    int                  offset = 0;
    int                  passed;

    origin->next = as_path;
    result = bgp_generate_update_evpn_type4(nlri, origin, NULL, 0, &next_hop);
    assert(result != NULL);

    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI, &value, &length) &&
             mp_reach_nlri_offset(value, length, &offset) &&
             (read_u32(value + offset) == 555) &&
             (value[offset + 4] == EVPN_RT_ETHERNET_SEGMENT);

    bgp_update_result_free(result);
    evpn_type4_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    test_result(passed, "Type 4 ADD-PATH");
}

void test_type4_withdrawal() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_esi_t            esi = make_zero_esi();
    evpn_type4_nlri_t    *withdrawn = evpn_type4_nlri_create_ipv4(rd, esi, "10.0.0.1");
    bgp_update_result_t  *result;
    int                   passed;

    result = bgp_generate_update_evpn_type4(NULL, NULL, withdrawn, 0, NULL);
    assert(result != NULL);

    passed = (result->num_messages == 1) &&
             has_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_UNREACH_NLRI);

    bgp_update_result_free(result);
    evpn_type4_nlri_list_free(withdrawn);
    test_result(passed, "Type 4 withdrawal");
}

void test_type5_wire_format() {
    route_distinguisher_t rd = rd_create_type1(0x0A000001, 100);
    evpn_type5_nlri_t    *nlri = evpn_type5_nlri_create_ipv4("172.16.0.0", 24, rd, 0, NULL, 30000);
    uint8_t               buffer[256];
    int                   len;

    assert(nlri != NULL);
    len = bgp_encode_evpn_type5_prefix(buffer, &nlri->prefix);

    // rt(1) + len(1) + RD(8) + ESI(10) + ETag(4) + IP len(1) + IP(4) + GW(4) + Label(3) = 36
    int passed = (len == 36) && (buffer[0] == EVPN_RT_IP_PREFIX) && (buffer[1] == 34);

    // RD at offset 2 (after rt + len), type 1: 10.0.0.1:100
    passed = passed && test_wire_rd_is(buffer + 2, 1, 0x0A000001, 100);

    // IP prefix length at offset 24, prefix 172.16.0.0 at 25-28, gateway zero at 29-32
    passed = passed && (buffer[24] == 24) && (buffer[25] == 172) && (buffer[26] == 16) &&
             (buffer[27] == 0) && (buffer[28] == 0) && (read_u32(buffer + 29) == 0);

    test_result(passed, "Type 5 wire format");
    evpn_type5_nlri_list_free(nlri);
}

// Extended Community Tests

void test_mac_mobility_ext_comm() {
    bgp_path_attr_t *attr = bgp_attr_create_ext_comm_mac_mobility(0x01, 42);
    int passed = (attr != NULL) &&
                 (attr->length == 8) &&
                 (attr->value[0] == 0x06) && (attr->value[1] == 0x00) &&
                 (attr->value[2] == 0x01) &&
                 (read_u32(attr->value + 4) == 42);

    bgp_path_attr_free(attr);
    test_result(passed, "MAC Mobility extended community");
}

void test_mac_mobility_ext_comm_invalid_flags() {
    bgp_path_attr_t *attr = bgp_attr_create_ext_comm_mac_mobility(0x02, 42);

    test_result(attr == NULL, "MAC Mobility reserved flag bits rejected");
}

void test_esi_label_ext_comm() {
    bgp_path_attr_t *attr = bgp_attr_create_ext_comm_esi_label(0x00, 100);
    int passed = (attr != NULL) &&
                 (attr->length == 8) &&
                 (attr->value[0] == 0x06) && (attr->value[1] == 0x01) &&
                 (attr->value[2] == 0x00);

    bgp_path_attr_free(attr);
    test_result(passed, "ESI Label extended community");
}

void test_esi_label_ext_comm_invalid_flags() {
    bgp_path_attr_t *attr = bgp_attr_create_ext_comm_esi_label(0x02, 100);

    test_result(attr == NULL, "ESI Label reserved flag bits rejected");
}

void test_esi_label_ext_comm_large_label() {
    bgp_path_attr_t *attr = bgp_attr_create_ext_comm_esi_label(0x00, 0x100000);

    test_result(attr == NULL, "ESI Label values above 20 bits rejected");
}

void test_default_gateway_ext_comm() {
    bgp_path_attr_t *attr = bgp_attr_create_ext_comm_default_gateway();
    int passed = (attr != NULL) &&
                 (attr->flags == (BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANSITIVE)) &&
                 (attr->type_code == BGP_ATTR_EXT_COMM) &&
                 (attr->length == 8) &&
                 (attr->value[0] == 0x03) &&
                 (attr->value[1] == 0x0d) &&
                 (attr->value[2] == 0) &&
                 (attr->value[3] == 0) &&
                 (attr->value[4] == 0) &&
                 (attr->value[5] == 0) &&
                 (attr->value[6] == 0) &&
                 (attr->value[7] == 0);

    bgp_path_attr_free(attr);
    test_result(passed, "Default Gateway extended community");
}

void test_encap_ext_comm() {
    bgp_path_attr_t *attr = bgp_attr_create_ext_comm_encap(8); /* VXLAN */
    int passed = (attr != NULL) &&
                 (attr->flags == (BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANSITIVE)) &&
                 (attr->type_code == BGP_ATTR_EXT_COMM) &&
                 (attr->length == 8) &&
                 (attr->value[0] == 0x03) &&
                 (attr->value[1] == 0x0c) &&
                 (attr->value[2] == 0) &&
                 (attr->value[3] == 0) &&
                 (attr->value[4] == 0) &&
                 (attr->value[5] == 0) &&
                 (attr->value[6] == 0x00) &&
                 (attr->value[7] == 0x08);

    bgp_path_attr_free(attr);
    test_result(passed, "Encapsulation extended community");
}

void test_router_mac_ext_comm() {
    uint8_t router_mac[] = {0x02, 0x10, 0x20, 0x30, 0x40, 0x50};
    bgp_path_attr_t *attr = bgp_attr_create_ext_comm_router_mac(router_mac);
    int passed = (attr != NULL) &&
                 (attr->flags == (BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANSITIVE)) &&
                 (attr->type_code == BGP_ATTR_EXT_COMM) &&
                 (attr->length == 8) &&
                 (attr->value[0] == 0x06) &&
                 (attr->value[1] == 0x03) &&
                 (memcmp(attr->value + 2, router_mac, 6) == 0);

    bgp_path_attr_free(attr);
    test_result(passed, "Router MAC extended community");
}

void test_router_mac_ext_comm_invalid_multicast() {
    uint8_t multicast_mac[] = {0x01, 0x00, 0x5e, 0x00, 0x00, 0x01};
    bgp_path_attr_t *attr = bgp_attr_create_ext_comm_router_mac(multicast_mac);

    test_result(attr == NULL, "Router MAC multicast/broadcast MACs rejected");
}

// NLRI list utility tests

void test_type1_nlri_list_count() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_esi_t            esi = make_zero_esi();
    evpn_type1_nlri_t    *head = NULL;
    evpn_type1_nlri_t    *tail = NULL;

    for (int i = 0; i < 5; i++) {
        evpn_type1_nlri_t *n = evpn_type1_nlri_create(rd, esi, i, 1000 + i);

        evpn_type1_nlri_append(&head, &tail, n);
    }

    test_result(evpn_type1_nlri_count(head) == 5, "Type 1 NLRI list count");
    evpn_type1_nlri_list_free(head);
}

void test_type2_nlri_list_count() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_esi_t            esi = make_zero_esi();
    uint8_t mac[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    evpn_type2_nlri_t *head = NULL;
    evpn_type2_nlri_t *tail = NULL;

    for (int i = 0; i < 3; i++) {
        evpn_type2_nlri_t *n = evpn_type2_nlri_create_mac_only(rd, esi, 0, mac, 1000 + i);

        evpn_type2_nlri_append(&head, &tail, n);
    }

    test_result(evpn_type2_nlri_count(head) == 3, "Type 2 NLRI list count");
    evpn_type2_nlri_list_free(head);
}

// Withdrawal wire format tests

void test_type1_withdrawal_wire_format() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_esi_t            esi = make_esi(1, 0xAA);
    evpn_type1_nlri_t    *withdrawn = evpn_type1_nlri_create(rd, esi, 0, 0);
    bgp_update_result_t  *result;
    const uint8_t        *value = NULL;
    uint16_t              length = 0;
    int                   offset = 0;
    int                   passed;

    result = bgp_generate_update_evpn_type1(NULL, NULL, withdrawn, 0, NULL);
    assert(result != NULL);

    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_UNREACH_NLRI, &value, &length) &&
             mp_unreach_nlri_offset(value, length, &offset) &&
             (value[0] == 0x00) && (value[1] == AFI_L2VPN) &&
             (value[2] == SAFI_EVPN) &&
             (value[offset] == EVPN_RT_ETHERNET_AUTO_DISCOVERY);

    bgp_update_result_free(result);
    evpn_type1_nlri_list_free(withdrawn);
    test_result(passed, "Type 1 withdrawal wire format");
}

void test_type3_add_path_withdrawal() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_type3_nlri_t    *withdrawn = evpn_type3_nlri_create_ipv4_path_id(rd, 0, "10.0.0.1", 888);
    bgp_update_result_t  *result;
    const uint8_t        *value = NULL;
    uint16_t              length = 0;
    int                   offset = 0;
    int                   passed;

    result = bgp_generate_update_evpn_type3(NULL, NULL, withdrawn, 0, NULL);
    assert(result != NULL);

    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_UNREACH_NLRI, &value, &length) &&
             mp_unreach_nlri_offset(value, length, &offset) &&
             (read_u32(value + offset) == 888) &&
             (value[offset + 4] == EVPN_RT_INCLUSIVE_MULTICAST);

    bgp_update_result_free(result);
    evpn_type3_nlri_list_free(withdrawn);
    test_result(passed, "Type 3 ADD-PATH withdrawal");
}

// Message splitting tests

void test_type2_message_splitting() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_esi_t            esi = make_zero_esi();
    uint8_t mac[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    evpn_type2_nlri_t *head = NULL;
    evpn_type2_nlri_t *tail = NULL;
    bgp_path_attr_t   *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_next_hop_t       next_hop = make_ipv4_next_hop("10.0.0.1");
    bgp_update_result_t *result;
    int                  passed;

    for (int i = 0; i < 50; i++) {
        char               ip[32];
        evpn_type2_nlri_t *n;

        snprintf(ip, sizeof(ip), "10.0.%d.%d", i / 256, i % 256);
        n = evpn_type2_nlri_create_ipv4(rd, esi, 0, mac, ip, 1000 + i);
        evpn_type2_nlri_append(&head, &tail, n);
    }

    origin->next = as_path;
    result = bgp_generate_update_evpn_type2(head, origin, NULL, 512, &next_hop);
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
    evpn_type2_nlri_list_free(head);
    test_result(passed, "Type 2 message splitting");
}

static void test_router_nlri_validation(void) {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    evpn_esi_t            esi = {0};
    evpn_type3_nlri_t    *bad3 = evpn_type3_nlri_create_ipv4(rd, 0, "invalid");
    evpn_type4_nlri_t    *bad4 = evpn_type4_nlri_create_ipv6(rd, esi, "invalid");
    test_result(!bad3 && !bad4, "EVPN router constructors reject invalid IP text");
    evpn_type3_nlri_list_free(bad3);
    evpn_type4_nlri_list_free(bad4);
    evpn_type3_prefix_t p3 = {.route_type = 3, .ip_addr_len = 31};
    evpn_type4_prefix_t p4 = {.route_type = 4, .ip_addr_len = 127};
    uint8_t             buffer[64];
    test_result(bgp_encode_evpn_type3_prefix(buffer, &p3) < 0 &&
                bgp_encode_evpn_type4_prefix(buffer, &p4) < 0,
                "EVPN router NLRIs reject inconsistent address lengths");
}

int main() {
    printf("========================================\n");
    printf("BGP EVPN Types 1-4 UPDATE Tests\n");
    printf("========================================\n\n");

    // Type 1 tests
    test_type1_nlri_creation();
    test_type1_prefix_encoding();
    test_type1_wire_format();
    test_type1_update_generation();
    test_type1_add_path();
    test_type1_withdrawal();

    // Type 2 tests
    test_type2_mac_ipv4_creation();
    test_type2_invalid_ipv4_text_rejected();
    test_type2_mac_ipv6_creation();
    test_type2_invalid_ipv6_text_rejected();
    test_type2_mac_only_creation();
    test_type2_encoding_mac_ipv4();
    test_type2_encoding_mac_ipv6();
    test_type2_encoding_mac_only();
    test_type2_encoding_two_labels();
    test_type2_wire_format_mac();
    test_type2_invalid_ip_length_rejected();
    test_type2_label_overflow_rejected();
    test_type2_update_generation();
    test_type2_update_with_encap_and_router_mac_ext_comms();
    test_type2_add_path();
    test_type2_withdrawal();
    test_type2_ipv6_next_hop();
    test_type2_ipv6_link_local_next_hop_rejected();

    // Type 3 tests
    test_type3_ipv4_creation();
    test_type3_ipv6_creation();
    test_type3_encoding_ipv4();
    test_type3_encoding_ipv6();
    test_type3_wire_format();
    test_type3_update_generation();
    test_type3_add_path();
    test_type3_withdrawal();

    // Type 4 tests
    test_type4_ipv4_creation();
    test_type4_ipv6_creation();
    test_type4_encoding_ipv4();
    test_type4_encoding_ipv6();
    test_type4_wire_format();
    test_type4_update_generation();
    test_type4_add_path();
    test_type4_withdrawal();

    // Type 5 tests
    test_type5_wire_format();

    // Extended community tests
    test_mac_mobility_ext_comm();
    test_mac_mobility_ext_comm_invalid_flags();
    test_esi_label_ext_comm();
    test_esi_label_ext_comm_invalid_flags();
    test_esi_label_ext_comm_large_label();
    test_default_gateway_ext_comm();
    test_encap_ext_comm();
    test_router_mac_ext_comm();
    test_router_mac_ext_comm_invalid_multicast();

    // NLRI list utility tests
    test_type1_nlri_list_count();
    test_type2_nlri_list_count();

    // Withdrawal wire format tests
    test_type1_withdrawal_wire_format();
    test_type3_add_path_withdrawal();

    // Message splitting tests
    test_type2_message_splitting();
    test_label_mpls_and_vni_forms();
    test_type2_label_ranges_follow_form();
    test_router_nlri_validation();

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
