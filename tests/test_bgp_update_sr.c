/*
 * Unit tests for BGP SR Policy UPDATE message generation
 * Tests SR Policy NLRI (AFI 1/2, SAFI 73) encoding per RFC 9830
 */

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include "bgp.h"
#include "test_case.h"
#include "test_wire.h"
#include "bgp_router.h"
#include "bgp_update.h"
#include "test_result.h"
#include "bgp_neighbor.h"
#include "test_helpers.h"

// RFC 9830 flag bits. The figures number bit 0 as the most significant bit of the octet.
#define RFC9830_BSID_FLAG_S      0x80  /* Binding SID and SRv6 Binding SID, Figures 5 and 8 */
#define RFC9830_BSID_FLAG_I      0x40
#define RFC9830_SRV6_BSID_FLAG_B 0x20  /* SRv6 Binding SID, Figure 8                        */
#define RFC9830_SEGMENT_FLAG_V   0x80  /* Segment Flags, Figure 13                          */
#define RFC9830_SEGMENT_FLAG_B   0x10

#define TEST_FIND_TAIL(tail, head)       \
    do {                                 \
        (tail) = (head);                 \
        while ((tail) && (tail)->next) { \
            (tail) = (tail)->next;       \
        }                                \
    } while (0)

static uint32_t read_mpls_label20(const uint8_t *ptr) {
    return ((uint32_t)ptr[0] << 12) |
           ((uint32_t)ptr[1] << 4) |
           ((uint32_t)ptr[2] >> 4);
}

static int find_attr(const uint8_t *msg, size_t size, uint8_t type_code,
                     const uint8_t **value_out, uint16_t *length_out) {
    return test_wire_find_attr(msg, size, type_code, value_out, length_out, NULL);
}

static int has_attr(const uint8_t *msg, size_t size, uint8_t type_code) {
    return find_attr(msg, size, type_code, NULL, NULL);
}

/*
 * Test 1: SR Policy NLRI creation (IPv4 endpoint)
 */
void test_srpolicy_nlri_creation_ipv4() {
    srpolicy_nlri_list_t *nlri = srpolicy_nlri_create(100, 200, AFI_IPV4, "10.0.0.1");
    srpolicy_nlri_list_t *tail;

    assert(nlri != NULL);
    TEST_FIND_TAIL(tail, nlri);

    srpolicy_nlri_list_t *second = srpolicy_nlri_create(101, 201, AFI_IPV4, "10.0.0.2");
    srpolicy_nlri_append(&nlri, &tail, second);

    test_result(srpolicy_nlri_count(nlri) == 2 &&
                nlri->prefix.distinguisher == 100 &&
                nlri->prefix.color == 200 &&
                nlri->prefix.endpoint_af == AFI_IPV4,
                "SR Policy NLRI creation (IPv4)");
    srpolicy_nlri_list_free(nlri);
}

/*
 * Test 2: SR Policy NLRI creation (IPv6 endpoint)
 */
void test_srpolicy_nlri_creation_ipv6() {
    srpolicy_nlri_list_t *nlri = srpolicy_nlri_create(300, 400, AFI_IPV6, "2001:db8::1");

    assert(nlri != NULL);
    test_result(nlri->prefix.distinguisher == 300 &&
                nlri->prefix.color == 400 &&
                nlri->prefix.endpoint_af == AFI_IPV6,
                "SR Policy NLRI creation (IPv6)");
    srpolicy_nlri_list_free(nlri);
}

/*
 * Test 3: SR Policy prefix encoding (IPv4 endpoint) wire format
 */
void test_srpolicy_prefix_encoding_ipv4() {
    srpolicy_prefix_t prefix;
    uint8_t           buffer[256];
    int               len;

    prefix.distinguisher = 100;
    prefix.color = 200;
    prefix.endpoint_af = AFI_IPV4;
    memset(prefix.endpoint, 0, 16);
    inet_pton(AF_INET, "10.0.0.1", prefix.endpoint);

    len = bgp_encode_srpolicy_prefix(buffer, &prefix);

    // 1(nlri_len) + 4(dist) + 4(color) + 4(endpoint) = 13
    test_result(len == 13 &&
                buffer[0] == 96 &&              /* (4+4+4)*8 = 96 bits */
                read_u32(buffer + 1) == 100 &&  /* distinguisher       */
                read_u32(buffer + 5) == 200 &&  /* color               */
                buffer[9] == 10 && buffer[10] == 0 &&
                buffer[11] == 0 && buffer[12] == 1,
                "SR Policy prefix encoding (IPv4)");
}

/*
 * Test 4: SR Policy prefix encoding (IPv6 endpoint) wire format
 */
void test_srpolicy_prefix_encoding_ipv6() {
    srpolicy_prefix_t prefix;
    uint8_t           buffer[256];
    uint8_t           expected_ipv6[16];
    int               len;

    prefix.distinguisher = 500;
    prefix.color = 600;
    prefix.endpoint_af = AFI_IPV6;
    memset(prefix.endpoint, 0, 16);
    inet_pton(AF_INET6, "2001:db8::1", prefix.endpoint);
    inet_pton(AF_INET6, "2001:db8::1", expected_ipv6);

    len = bgp_encode_srpolicy_prefix(buffer, &prefix);

    // 1(nlri_len) + 4(dist) + 4(color) + 16(endpoint) = 25
    test_result(len == 25 &&
                buffer[0] == 192 &&             /* (4+4+16)*8 = 192 bits */
                read_u32(buffer + 1) == 500 &&  /* distinguisher         */
                read_u32(buffer + 5) == 600 &&  /* color                 */
                memcmp(buffer + 9, expected_ipv6, 16) == 0,
                "SR Policy prefix encoding (IPv6)");
}

/*
 * Test 5: IPv4 NLRI with IPv6 next-hop (AFI-independent next hop)
 */
void test_srpolicy_next_hop_independence() {
    srpolicy_nlri_list_t *nlri = srpolicy_nlri_create(100, 200, AFI_IPV4, "10.0.0.1");
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

    // IPv4 NLRI AFI with IPv6 next hop -- this must work
    result = bgp_generate_update_srpolicy(nlri, origin, NULL, 0, AFI_IPV4, &next_hop);
    assert(result != NULL);

    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI, &value, &length) &&
             (value[0] == 0x00) && (value[1] == AFI_IPV4) &&
             (value[2] == SAFI_SR_POLICY) &&
             (value[3] == 16) &&  /* IPv6 next-hop = 16 bytes */
             (memcmp(value + 4, expected_ipv6, 16) == 0);

    bgp_update_result_free(result);
    srpolicy_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    test_result(passed, "SR Policy IPv4 NLRI with IPv6 next-hop");
}

/*
 * Test 6: IPv4 next-hop with IPv4 NLRI
 */
void test_srpolicy_ipv4_next_hop() {
    srpolicy_nlri_list_t *nlri = srpolicy_nlri_create(100, 200, AFI_IPV4, "10.0.0.1");
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
    result = bgp_generate_update_srpolicy(nlri, origin, NULL, 0, AFI_IPV4, &next_hop);
    assert(result != NULL);

    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI, &value, &length) &&
             (value[0] == 0x00) && (value[1] == AFI_IPV4) &&
             (value[2] == SAFI_SR_POLICY) &&
             (value[3] == 4) &&  /* IPv4 next-hop = 4 bytes */
             (value[4] == 192) && (value[5] == 0) &&
             (value[6] == 2) && (value[7] == 1);

    bgp_update_result_free(result);
    srpolicy_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    test_result(passed, "SR Policy IPv4 next-hop");
}

/*
 * Test 7: IPv6 NLRI with IPv6 next-hop
 */
void test_srpolicy_ipv6_nlri() {
    srpolicy_nlri_list_t *nlri = srpolicy_nlri_create(100, 200, AFI_IPV6, "2001:db8::1");
    bgp_path_attr_t      *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_next_hop_t       next_hop = make_ipv6_next_hop("2001:db8::99");
    bgp_update_result_t *result;
    const uint8_t       *value = NULL;
    uint16_t             length = 0;
    int                  nlri_off = 0;
    int                  passed;

    origin->next = as_path;
    result = bgp_generate_update_srpolicy(nlri, origin, NULL, 0, AFI_IPV6, &next_hop);
    assert(result != NULL);

    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI, &value, &length) &&
             (value[0] == 0x00) && (value[1] == AFI_IPV6) &&
             (value[2] == SAFI_SR_POLICY) &&
             (value[3] == 16) &&        /* IPv6 next-hop                      */
             mp_reach_nlri_offset(value, length, &nlri_off) &&
             (value[nlri_off] == 192);  /* NLRI bit length = (4+4+16)*8 = 192 */

    bgp_update_result_free(result);
    srpolicy_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    test_result(passed, "SR Policy IPv6 NLRI with IPv6 next-hop");
}

/*
 * Test 8: Tunnel Encapsulation attribute encoding
 */
void test_tunnel_encap_attribute() {
    srpolicy_segment_t      segments[2] = {{.type = SR_SEGMENT_TYPE_MPLS}, {.type = SR_SEGMENT_TYPE_MPLS}};
    srpolicy_segment_list_t seg_list = {.weight = 100, .segments = segments, .num_segments = 2};
    srpolicy_tunnel_encap_t    spec = {.has_preference = 1, .preference = 150, .has_binding_sid = 1,
                                       .binding_sid = {.type = SRPOLICY_BINDING_SID_MPLS, .mpls_label = 16000},
                                       .segment_lists = &seg_list, .num_segment_lists = 1};
    bgp_path_attr_t           *attr;
    const uint8_t             *p;

    // Set up MPLS segments
    uint32_t label1 = htonl(16001);
    memcpy(segments[0].sid, &label1, 4);
    uint32_t label2 = htonl(16002);
    memcpy(segments[1].sid, &label2, 4);

    attr = bgp_attr_create_tunnel_encap_srpolicy(&spec);
    assert(attr != NULL);

    test_result(attr->type_code == BGP_ATTR_TUNNEL_ENCAP &&
                (attr->flags & BGP_ATTR_FLAG_OPTIONAL) &&
                (attr->flags & BGP_ATTR_FLAG_TRANSITIVE),
                "Tunnel Encapsulation attribute flags");

    p = attr->value;

    /*
     * RFC 9830 uses 1-octet Type/Length for the standard SR Policy
     * sub-TLVs and a 2-octet Length only for the Segment List (type 128).
     */

    // Tunnel Type = 15 (SR Policy)
    int passed = (read_u16(p) == 15);
    p += 2;

    // Tunnel Length
    uint16_t tunnel_len = read_u16(p);
    passed = passed && (tunnel_len == 44);
    p += 2;

    // Preference sub-TLV (type 12)
    passed = passed && (p[0] == 12) && (p[1] == 6);
    p += 2;
    passed = passed && (p[0] == 0) && (p[1] == 0);
    p += 2;
    passed = passed && (read_u32(p) == 150);
    p += 4;

    // Binding SID sub-TLV (type 13)
    passed = passed && (p[0] == 13) && (p[1] == 6);
    p += 2;
    passed = passed && (p[0] == 0);  /* flags    */
    passed = passed && (p[1] == 0);  /* reserved */
    // Binding SID uses the full 4-octet MPLS label field with TC/S/TTL zero.
    passed = passed && (read_mpls_label20(p + 2) == 16000);
    passed = passed && ((p[4] & 0x0F) == 0);
    passed = passed && (p[5] == 0);
    p += 6;

    // Segment List sub-TLV (type 128)
    passed = passed && (p[0] == 128);
    p += 1;
    uint16_t sl_len = read_u16(p);
    passed = passed && (sl_len == 25);
    p += 2;
    passed = passed && (p[0] == 0);  /* reserved */
    p += 1;

    // Weight sub-TLV (sub-type 9)
    passed = passed && (p[0] == 9) && (p[1] == 6);
    p += 2;
    passed = passed && (p[0] == 0) && (p[1] == 0);
    p += 2;
    passed = passed && (read_u32(p) == 100);
    p += 4;

    // First segment sub-TLV: Type A (SR-MPLS label).
    passed = passed && (p[0] == 1) && (p[1] == 6);
    p += 2;
    passed = passed && (p[0] == 0);           /* flags                       */
    passed = passed && (p[1] == 0);           /* reserved                    */
    passed = passed && (read_mpls_label20(p + 2) == 16001);
    passed = passed && ((p[4] & 0x0F) == 0);  /* TC=0, S=0                   */
    passed = passed && (p[5] == 255);         /* TTL=255 => receiver chooses */
    p += 6;

    // Second segment sub-TLV: another Type A segment.
    passed = passed && (p[0] == 1) && (p[1] == 6);
    p += 2;
    passed = passed && (p[0] == 0) && (p[1] == 0);
    passed = passed && (read_mpls_label20(p + 2) == 16002);
    passed = passed && ((p[4] & 0x0F) == 0);
    passed = passed && (p[5] == 255);

    bgp_path_attr_free(attr);
    test_result(passed, "Tunnel Encapsulation SR Policy encoding");
}

/*
 * Test 8b: Optional SR Policy sub-TLVs beyond Preference / Binding SID
 */
void test_tunnel_encap_optional_subtlvs() {
    srpolicy_tunnel_encap_t spec = {0};
    bgp_path_attr_t        *attr;
    const uint8_t          *p;
    int                     passed;

    spec.has_enlp = 1;
    spec.enlp = 3;
    spec.has_priority = 1;
    spec.priority = 7;
    spec.candidate_path_name = "cp-a";
    spec.policy_name = "sp-a";

    attr = bgp_attr_create_tunnel_encap_srpolicy(&spec);
    assert(attr != NULL);

    p = attr->value;
    passed = (read_u16(p) == 15);
    p += 2;
    passed = passed && (read_u16(p) == 25);
    p += 2;

    // ENLP sub-TLV (type 14, length 3).
    passed = passed && (p[0] == 14) && (p[1] == 3) &&
             (p[2] == 0) && (p[3] == 0) && (p[4] == 3);
    p += 5;

    // Priority sub-TLV (type 15, length 2).
    passed = passed && (p[0] == 15) && (p[1] == 2) &&
             (p[2] == 7) && (p[3] == 0);
    p += 4;

    // Candidate Path Name sub-TLV (type 129, 2-byte length).
    passed = passed && (p[0] == 129);
    p += 1;
    passed = passed && (read_u16(p) == 5);
    p += 2;
    passed = passed && (p[0] == 0) && (memcmp(p + 1, "cp-a", 4) == 0);
    p += 5;

    // Policy Name sub-TLV (type 130, 2-byte length).
    passed = passed && (p[0] == 130);
    p += 1;
    passed = passed && (read_u16(p) == 5);
    p += 2;
    passed = passed && (p[0] == 0) && (memcmp(p + 1, "sp-a", 4) == 0);

    bgp_path_attr_free(attr);
    test_result(passed, "Tunnel Encapsulation optional SR sub-TLVs");
}

/*
 * Test 8c: Legacy Binding SID sub-TLV carrying an SRv6 BSID
 */
void test_tunnel_encap_legacy_srv6_binding_sid() {
    srpolicy_tunnel_encap_t spec = {0};
    bgp_path_attr_t        *attr;
    const uint8_t          *p;
    uint8_t                 expected_sid[16];
    int                     passed;

    spec.has_preference = 1;
    spec.preference = 99;
    spec.has_binding_sid = 1;
    spec.binding_sid.flags = RFC9830_BSID_FLAG_S | RFC9830_BSID_FLAG_I;
    spec.binding_sid.type = SRPOLICY_BINDING_SID_SRV6;
    inet_pton(AF_INET6, "fc00:0:64::1", spec.binding_sid.srv6_sid);
    inet_pton(AF_INET6, "fc00:0:64::1", expected_sid);

    attr = bgp_attr_create_tunnel_encap_srpolicy(&spec);
    if (attr == NULL) {
        test_result(0, "Tunnel Encap legacy SRv6 Binding SID (S and I flags accepted)");
        return;
    }

    p = attr->value;
    passed = (read_u16(p) == 15);
    p += 2;
    passed = passed && (read_u16(p) == 28);
    p += 2;

    // Skip Preference sub-TLV.
    passed = passed && (p[0] == 12) && (p[1] == 6);
    p += 8;

    // Binding SID sub-TLV (type 13, legacy SRv6 BSID form), S and I at the RFC 9830 bits.
    passed = passed && (p[0] == 13) && (p[1] == 18) &&
             (p[2] == 0xC0) && (p[3] == 0) &&
             (memcmp(p + 4, expected_sid, 16) == 0);

    bgp_path_attr_free(attr);
    test_result(passed, "Tunnel Encap legacy SRv6 Binding SID");
}

/*
 * Test 8d: RFC 9830 SRv6 Binding SID sub-TLV with optional behavior block
 */
void test_tunnel_encap_srv6_binding_sid_subtlv() {
    srpolicy_tunnel_encap_t     spec = {0};
    srpolicy_srv6_binding_sid_t binding_sid = {0};
    bgp_path_attr_t            *attr;
    const uint8_t              *p;
    uint8_t                     expected_sid[16];
    int                         passed;

    binding_sid.flags = RFC9830_BSID_FLAG_S | RFC9830_BSID_FLAG_I;
    binding_sid.has_behavior = 1;
    binding_sid.behavior.endpoint_behavior = 0x1234;
    binding_sid.behavior.locator_block_len = 48;
    binding_sid.behavior.locator_node_len = 16;
    binding_sid.behavior.function_len = 16;
    binding_sid.behavior.argument_len = 48;
    inet_pton(AF_INET6, "fc00:0:77::1", binding_sid.sid);
    inet_pton(AF_INET6, "fc00:0:77::1", expected_sid);

    spec.srv6_binding_sids = &binding_sid;
    spec.num_srv6_binding_sids = 1;

    attr = bgp_attr_create_tunnel_encap_srpolicy(&spec);
    if (attr == NULL) {
        test_result(0, "Tunnel Encap SRv6 Binding SID sub-TLV (S and I flags accepted)");
        return;
    }

    p = attr->value;
    passed = (read_u16(p) == 15);
    p += 2;
    passed = passed && (read_u16(p) == 28);
    p += 2;

    // S + I + B (B because the behavior block is present): 0xE0.
    passed = passed && (p[0] == 20) && (p[1] == 26) &&
             (p[2] == (RFC9830_BSID_FLAG_S | RFC9830_BSID_FLAG_I | RFC9830_SRV6_BSID_FLAG_B)) &&
             (p[3] == 0) &&
             (memcmp(p + 4, expected_sid, 16) == 0);
    p += 20;
    passed = passed && (read_u16(p) == 0x1234) &&
             (read_u16(p + 2) == 0) &&
             (p[4] == 48) && (p[5] == 16) &&
             (p[6] == 16) && (p[7] == 48);

    bgp_path_attr_free(attr);
    test_result(passed, "Tunnel Encap SRv6 Binding SID sub-TLV");
}

/*
 * Test 9: Full UPDATE generation with attributes
 */
void test_srpolicy_full_update() {
    srpolicy_nlri_list_t *nlri = srpolicy_nlri_create(100, 200, AFI_IPV4, "10.0.0.1");
    bgp_path_attr_t      *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001, 65002};
    as_path_segment_t segment = {BGP_AS_SEQUENCE, 2, asns};
    bgp_path_attr_t  *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_path_attr_t  *local_pref = bgp_attr_create_local_pref(100);

    // Build tunnel encapsulation attribute
    srpolicy_segment_t segs[1] = {{.type = SR_SEGMENT_TYPE_MPLS}};
    uint32_t           sid_val = htonl(16001);
    memcpy(segs[0].sid, &sid_val, 4);

    srpolicy_segment_list_t seg_list = {.weight = 1, .segments = segs, .num_segments = 1};
    srpolicy_tunnel_encap_t    spec = {.has_preference = 1, .preference = 100, .has_binding_sid = 1,
                                       .binding_sid = {.type = SRPOLICY_BINDING_SID_MPLS, .mpls_label = 16000},
                                       .segment_lists = &seg_list, .num_segment_lists = 1};
    bgp_path_attr_t           *tunnel = bgp_attr_create_tunnel_encap_srpolicy(&spec);

    bgp_next_hop_t       next_hop = make_ipv4_next_hop("192.0.2.1");
    bgp_update_result_t *result;
    int                  passed;

    origin->next = as_path;
    as_path->next = local_pref;
    local_pref->next = tunnel;

    result = bgp_generate_update_srpolicy(nlri, origin, NULL, 0, AFI_IPV4, &next_hop);
    assert(result != NULL);

    passed = (result->num_messages == 1) &&
             has_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI) &&
             has_attr(result->messages[0], result->message_lens[0], BGP_ATTR_ORIGIN) &&
             has_attr(result->messages[0], result->message_lens[0], BGP_ATTR_AS_PATH) &&
             has_attr(result->messages[0], result->message_lens[0], BGP_ATTR_LOCAL_PREF) &&
             has_attr(result->messages[0], result->message_lens[0], BGP_ATTR_TUNNEL_ENCAP);

    bgp_update_result_free(result);
    srpolicy_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    test_result(passed, "SR Policy full UPDATE generation");
}

/*
 * Test 10: SR Policy ADD-PATH encoding
 */
void test_srpolicy_add_path() {
    srpolicy_nlri_list_t *nlri = srpolicy_nlri_create_path_id(100, 200, AFI_IPV4, "10.0.0.1", 42);
    srpolicy_nlri_list_t *tail;
    bgp_path_attr_t      *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_next_hop_t       next_hop = make_ipv4_next_hop("192.0.2.1");
    bgp_update_result_t *result;
    const uint8_t       *value = NULL;
    uint16_t             length = 0;
    uint8_t              first_nlri[64];
    int                  first_len;
    int                  offset = 0;
    int                  passed;

    TEST_FIND_TAIL(tail, nlri);
    srpolicy_nlri_list_t *second = srpolicy_nlri_create_path_id(101, 201, AFI_IPV4, "10.0.0.2", 99);
    srpolicy_nlri_append(&nlri, &tail, second);

    origin->next = as_path;
    result = bgp_generate_update_srpolicy(nlri, origin, NULL, 0, AFI_IPV4, &next_hop);
    assert(result != NULL);

    first_len = bgp_encode_srpolicy_prefix(first_nlri, &nlri->prefix);
    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI, &value, &length) &&
             mp_reach_nlri_offset(value, length, &offset) &&
             (read_u32(value + offset) == 42) &&
             (memcmp(value + offset + 4, first_nlri, (size_t)first_len) == 0) &&
             (read_u32(value + offset + 4 + first_len) == 99);

    bgp_update_result_free(result);
    srpolicy_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    test_result(passed, "SR Policy ADD-PATH encoding");
}

/*
 * Test 11: SR Policy withdrawals use MP_UNREACH_NLRI
 */
void test_srpolicy_withdrawals() {
    srpolicy_nlri_list_t *withdrawn = srpolicy_nlri_create(100, 200, AFI_IPV4, "10.0.0.1");
    bgp_update_result_t  *result = bgp_generate_update_srpolicy(NULL, NULL, withdrawn, 0, AFI_IPV4, NULL);
    int passed = (result != NULL) &&
                 (result->num_messages == 1) &&
                 find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_UNREACH_NLRI, NULL, NULL);

    bgp_update_result_free(result);
    srpolicy_nlri_list_free(withdrawn);
    test_result(passed, "SR Policy withdrawals");
}

/*
 * Test 12: SR Policy ADD-PATH withdrawals
 */
void test_srpolicy_add_path_withdrawals() {
    srpolicy_nlri_list_t *withdrawn = srpolicy_nlri_create_path_id(100, 200, AFI_IPV4, "10.0.0.1", 777);
    srpolicy_nlri_list_t *withdrawn_tail;
    bgp_update_result_t  *result;
    const uint8_t        *value = NULL;
    uint16_t              length = 0;
    uint8_t               first_nlri[64];
    int                   first_len;
    int                   offset = 0;
    int                   passed;

    TEST_FIND_TAIL(withdrawn_tail, withdrawn);
    srpolicy_nlri_list_t *second = srpolicy_nlri_create_path_id(101, 201, AFI_IPV4, "10.0.0.2", 888);
    srpolicy_nlri_append(&withdrawn, &withdrawn_tail, second);

    result = bgp_generate_update_srpolicy(NULL, NULL, withdrawn, 0, AFI_IPV4, NULL);
    assert(result != NULL);

    first_len = bgp_encode_srpolicy_prefix(first_nlri, &withdrawn->prefix);
    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_UNREACH_NLRI, &value, &length) &&
             mp_unreach_nlri_offset(value, length, &offset) &&
             (read_u32(value + offset) == 777) &&
             (memcmp(value + offset + 4, first_nlri, (size_t)first_len) == 0) &&
             (read_u32(value + offset + 4 + first_len) == 888);

    bgp_update_result_free(result);
    srpolicy_nlri_list_free(withdrawn);
    test_result(passed, "SR Policy ADD-PATH withdrawals");
}

/*
 * Test 13: SR Policy message splitting with many NLRIs
 */
void test_srpolicy_message_splitting() {
    srpolicy_nlri_list_t *nlri = NULL;
    srpolicy_nlri_list_t *nlri_tail = NULL;
    bgp_path_attr_t      *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_next_hop_t       next_hop = make_ipv4_next_hop("192.0.2.1");
    bgp_update_result_t *result;
    int                  passed;

    for (int i = 0; i < 100; i++) {
        char                  endpoint[32];
        srpolicy_nlri_list_t *new_nlri;

        snprintf(endpoint, sizeof(endpoint), "10.%d.0.%d", i / 256, i % 256);
        new_nlri = srpolicy_nlri_create((uint32_t)i, 200 + i, AFI_IPV4, endpoint);
        srpolicy_nlri_append(&nlri, &nlri_tail, new_nlri);
    }

    origin->next = as_path;
    result = bgp_generate_update_srpolicy(nlri, origin, NULL, 256, AFI_IPV4, &next_hop);
    assert(result != NULL);

    passed = (result->num_messages > 1);
    for (int i = 0; i < result->num_messages; i++) {
        if (result->message_lens[i] > 256 ||
            test_wire_path_attr_len(result->messages[i], result->message_lens[i]) <= 0 ||
            !has_attr(result->messages[i], result->message_lens[i], BGP_ATTR_MP_REACH_NLRI)) {
            passed = 0;
        }
    }

    bgp_update_result_free(result);
    bgp_path_attr_list_free(origin);
    srpolicy_nlri_list_free(nlri);
    test_result(passed, "SR Policy message splitting");
}

/*
 * Test 14: IPv6 endpoint NLRI encoding size
 */
void test_srpolicy_ipv6_encoding_size() {
    srpolicy_prefix_t prefix;
    uint8_t           buffer[256];
    int               len;

    prefix.distinguisher = 1;
    prefix.color = 2;
    prefix.endpoint_af = AFI_IPV6;
    memset(prefix.endpoint, 0, 16);
    inet_pton(AF_INET6, "2001:db8::1", prefix.endpoint);

    len = bgp_encode_srpolicy_prefix(buffer, &prefix);

    // 1(nlri_len) + 4(dist) + 4(color) + 16(endpoint) = 25
    test_result(len == 25, "SR Policy IPv6 NLRI encoding size is 25 bytes");
}

/*
 * Test 15: IPv4 endpoint NLRI encoding size
 */
void test_srpolicy_ipv4_encoding_size() {
    srpolicy_prefix_t prefix;
    uint8_t           buffer[256];
    int               len;

    prefix.distinguisher = 1;
    prefix.color = 2;
    prefix.endpoint_af = AFI_IPV4;
    memset(prefix.endpoint, 0, 16);
    inet_pton(AF_INET, "10.0.0.1", prefix.endpoint);

    len = bgp_encode_srpolicy_prefix(buffer, &prefix);

    // 1(nlri_len) + 4(dist) + 4(color) + 4(endpoint) = 13
    test_result(len == 13, "SR Policy IPv4 NLRI encoding size is 13 bytes");
}

/*
 * Test 16: Tunnel Encapsulation with SRv6 segment
 */
void test_tunnel_encap_srv6_segment() {
    srpolicy_segment_t      segments[1] = {{.type = SR_SEGMENT_TYPE_SRV6}};
    srpolicy_segment_list_t seg_list = {.weight = 50, .segments = segments, .num_segments = 1};
    // A Binding SID sub-TLV with no SID: flags and reserved octets only.
    srpolicy_tunnel_encap_t    spec = {.has_preference = 1, .preference = 200, .has_binding_sid = 1,
                                       .binding_sid = {.type = SRPOLICY_BINDING_SID_NONE},
                                       .segment_lists = &seg_list, .num_segment_lists = 1};
    bgp_path_attr_t           *attr;
    const uint8_t             *p;

    inet_pton(AF_INET6, "fc00:0:1::1", segments[0].sid);

    attr = bgp_attr_create_tunnel_encap_srpolicy(&spec);
    assert(attr != NULL);

    p = attr->value;
    p += 4;  /* Skip tunnel type + tunnel length */

    // Skip preference sub-TLV (type+len+flags+reserved+value = 8 bytes)
    p += 8;

    // Binding SID sub-TLV with no BSID is only flags+reserved in the value.
    p += 4;

    // Segment List
    int passed = (p[0] == 128);  /* type = 128 */
    p += 1;
    passed = passed && (read_u16(p) == 29);
    p += 2;
    passed = passed && (p[0] == 0);
    p += 1;

    // Weight sub-TLV
    passed = passed && (p[0] == 9) && (p[1] == 6);
    p += 2;
    passed = passed && (p[0] == 0) && (p[1] == 0);
    p += 2;
    passed = passed && (read_u32(p) == 50);
    p += 4;

    // Segment sub-TLV: Type B (SRv6 SID), no optional behavior block.
    passed = passed && (p[0] == 13) && (p[1] == 18);
    p += 2;
    passed = passed && (p[0] == 0) && (p[1] == 0);
    p += 2;

    uint8_t expected_srv6[16];
    inet_pton(AF_INET6, "fc00:0:1::1", expected_srv6);
    passed = passed && (memcmp(p, expected_srv6, 16) == 0);

    bgp_path_attr_free(attr);
    test_result(passed, "Tunnel Encapsulation SRv6 segment");
}

/*
 * Test 16b: Type B Segment sub-TLV with optional behavior / SID structure
 */
void test_tunnel_encap_srv6_segment_with_behavior() {
    srpolicy_tunnel_encap_t spec = {0};
    srpolicy_segment_t      segment = {0};
    srpolicy_segment_list_t seg_list = {0};
    bgp_path_attr_t        *attr;
    const uint8_t          *p;
    uint8_t                 expected_srv6[16];
    int                     passed;

    spec.has_preference = 1;
    spec.preference = 200;

    segment.type = SR_SEGMENT_TYPE_SRV6;
    segment.flags = RFC9830_SEGMENT_FLAG_V;
    segment.has_srv6_behavior = 1;
    segment.srv6_behavior.endpoint_behavior = 0x1234;
    segment.srv6_behavior.locator_block_len = 48;
    segment.srv6_behavior.locator_node_len = 16;
    segment.srv6_behavior.function_len = 16;
    segment.srv6_behavior.argument_len = 48;
    inet_pton(AF_INET6, "fc00:0:1::99", segment.sid);
    inet_pton(AF_INET6, "fc00:0:1::99", expected_srv6);

    seg_list.weight = 50;
    seg_list.segments = &segment;
    seg_list.num_segments = 1;
    spec.segment_lists = &seg_list;
    spec.num_segment_lists = 1;

    attr = bgp_attr_create_tunnel_encap_srpolicy(&spec);
    if (attr == NULL) {
        test_result(0, "Tunnel Encap SRv6 segment with behavior (V flag accepted)");
        return;
    }

    p = attr->value;
    passed = (read_u16(p) == 15);
    p += 2;
    passed = passed && (read_u16(p) == 48);
    p += 2;

    // Skip Preference sub-TLV.
    passed = passed && (p[0] == 12) && (p[1] == 6);
    p += 8;

    // Segment List type 128 with value len 37 = reserved(1)+weight(8)+segment(28).
    passed = passed && (p[0] == 128);
    p += 1;
    passed = passed && (read_u16(p) == 37);
    p += 2;
    passed = passed && (p[0] == 0);
    p += 1;

    // Weight sub-TLV
    passed = passed && (p[0] == 9) && (p[1] == 6);
    p += 8;

    // Type B segment: V + derived B = 0x90.
    passed = passed && (p[0] == 13) && (p[1] == 26) &&
             (p[2] == (RFC9830_SEGMENT_FLAG_V | RFC9830_SEGMENT_FLAG_B)) && (p[3] == 0) &&
             (memcmp(p + 4, expected_srv6, 16) == 0);
    p += 20;
    passed = passed && (read_u16(p) == 0x1234) &&
             (read_u16(p + 2) == 0) &&
             (p[4] == 48) && (p[5] == 16) &&
             (p[6] == 16) && (p[7] == 48);

    bgp_path_attr_free(attr);
    test_result(passed, "Tunnel Encap SRv6 segment with behavior");
}

/*
 * Test 16c: Strict helper rejects invalid new SRv6/ENLP forms
 */
void test_tunnel_encap_extended_validation() {
    srpolicy_tunnel_encap_t     bad_enlp = {0};
    srpolicy_tunnel_encap_t     bad_bsid = {0};
    srpolicy_srv6_binding_sid_t srv6_bsid = {0};
    srpolicy_segment_t          bad_segment = {0};
    srpolicy_segment_list_t     bad_seg_list = {0};
    srpolicy_tunnel_encap_t     bad_segment_spec = {0};
    int                         passed;

    bad_enlp.has_enlp = 1;
    bad_enlp.enlp = 5;

    srv6_bsid.has_behavior = 1;
    srv6_bsid.behavior.locator_block_len = 80;
    srv6_bsid.behavior.locator_node_len = 32;
    srv6_bsid.behavior.function_len = 32;
    srv6_bsid.behavior.argument_len = 32; /* total 176 > 128 */
    bad_bsid.srv6_binding_sids = &srv6_bsid;
    bad_bsid.num_srv6_binding_sids = 1;

    bad_segment.type = SR_SEGMENT_TYPE_SRV6;
    bad_segment.has_srv6_behavior = 1;
    bad_segment.srv6_behavior.locator_block_len = 64;
    bad_segment.srv6_behavior.locator_node_len = 32;
    bad_segment.srv6_behavior.function_len = 32;
    bad_segment.srv6_behavior.argument_len = 32; /* total 160 > 128 */
    bad_seg_list.weight = 1;
    bad_seg_list.segments = &bad_segment;
    bad_seg_list.num_segments = 1;
    bad_segment_spec.segment_lists = &bad_seg_list;
    bad_segment_spec.num_segment_lists = 1;

    passed = (bgp_attr_create_tunnel_encap_srpolicy(&bad_enlp) == NULL) &&
             (bgp_attr_create_tunnel_encap_srpolicy(&bad_bsid) == NULL) &&
             (bgp_attr_create_tunnel_encap_srpolicy(&bad_segment_spec) == NULL);

    test_result(passed, "Tunnel Encap extended validation");
}

/*
 * Test 17: Reject invalid AFI
 */
void test_srpolicy_invalid_afi() {
    srpolicy_nlri_list_t *nlri = srpolicy_nlri_create(100, 200, AFI_IPV4, "10.0.0.1");
    bgp_path_attr_t      *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_next_hop_t       next_hop = make_ipv4_next_hop("192.0.2.1");
    bgp_update_result_t *result;

    origin->next = as_path;
    // AFI_L2VPN is invalid for SR Policy
    result = bgp_generate_update_srpolicy(nlri, origin, NULL, 0, AFI_L2VPN, &next_hop);

    test_result(result == NULL, "SR Policy rejects invalid AFI");

    srpolicy_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
}

/*
 * This is currently a strict-mode rejection: the outer MP attribute AFI
 * must match the endpoint AF carried by the SR Policy NLRI payload.
 * Later protocol-fuzz support may deliberately bypass this check.
 */
void test_srpolicy_endpoint_afi_mismatch() {
    srpolicy_nlri_list_t *nlri = srpolicy_nlri_create(100, 200, AFI_IPV6, "2001:db8::1");
    bgp_path_attr_t      *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_next_hop_t       next_hop = make_ipv6_next_hop("2001:db8::99");
    bgp_update_result_t *result;

    origin->next = as_path;
    result = bgp_generate_update_srpolicy(nlri, origin, NULL, 0, AFI_IPV4, &next_hop);

    test_result(result == NULL, "SR Policy rejects endpoint AFI mismatch");

    srpolicy_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
}

/*
 * Test 18: Default next-hop (NULL) encodes 4-byte all-zero
 */
void test_srpolicy_default_next_hop() {
    srpolicy_nlri_list_t *nlri = srpolicy_nlri_create(100, 200, AFI_IPV4, "10.0.0.1");
    bgp_path_attr_t      *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_update_result_t *result;
    const uint8_t       *value = NULL;
    uint16_t             length = 0;
    int                  passed;

    origin->next = as_path;
    result = bgp_generate_update_srpolicy(nlri, origin, NULL, 0, AFI_IPV4, NULL);
    assert(result != NULL);

    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI, &value, &length) &&
             (value[3] == 4) &&  /* Default 4-byte next-hop */
             (value[4] == 0) && (value[5] == 0) &&
             (value[6] == 0) && (value[7] == 0);

    bgp_update_result_free(result);
    srpolicy_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    test_result(passed, "SR Policy default next-hop (all zeros)");
}

/*
 * Test 19: Multiple segment lists in Tunnel Encapsulation
 */
void test_tunnel_encap_multiple_segment_lists() {
    srpolicy_segment_t segs1[1] = {{.type = SR_SEGMENT_TYPE_MPLS}};
    srpolicy_segment_t segs2[1] = {{.type = SR_SEGMENT_TYPE_MPLS}};
    srpolicy_segment_list_t seg_lists[2] = {{.weight = 10, .segments = segs1, .num_segments = 1},
                                               {.weight = 20, .segments = segs2, .num_segments = 1}};
    srpolicy_tunnel_encap_t    spec = {.has_preference = 1, .preference = 100, .has_binding_sid = 1,
                                       .binding_sid = {.type = SRPOLICY_BINDING_SID_MPLS, .mpls_label = 16000},
                                       .segment_lists = seg_lists, .num_segment_lists = 2};
    bgp_path_attr_t           *attr;
    const uint8_t             *p;

    uint32_t label1 = htonl(16001);
    memcpy(segs1[0].sid, &label1, 4);
    uint32_t label2 = htonl(16002);
    memcpy(segs2[0].sid, &label2, 4);

    attr = bgp_attr_create_tunnel_encap_srpolicy(&spec);
    assert(attr != NULL);

    p = attr->value;

    // Tunnel type
    int passed = (read_u16(p) == 15);
    p += 4;  /* type + length */

    // Skip preference (8) + binding SID with MPLS BSID (8).
    p += 16;

    // First segment list
    passed = passed && (p[0] == 128);
    p += 1;
    passed = passed && (read_u16(p) == 17);
    p += 2;
    passed = passed && (p[0] == 0);
    p += 1;

    // Weight of first segment list
    passed = passed && (p[0] == 9) && (p[1] == 6);
    p += 2;
    passed = passed && (p[0] == 0) && (p[1] == 0);
    p += 2;
    passed = passed && (read_u32(p) == 10);
    p += 4;

    // Skip first MPLS segment: type+len+flags+reserved+label(4) = 8.
    p += 8;

    // Second segment list
    passed = passed && (p[0] == 128);
    p += 1;
    passed = passed && (read_u16(p) == 17);
    p += 2;
    passed = passed && (p[0] == 0);
    p += 1;

    // Weight of second segment list
    passed = passed && (p[0] == 9) && (p[1] == 6);
    p += 2;
    passed = passed && (p[0] == 0) && (p[1] == 0);
    p += 2;
    passed = passed && (read_u32(p) == 20);

    bgp_path_attr_free(attr);
    test_result(passed, "Tunnel Encap multiple segment lists");
}

/*
 * Test 20: SR Policy IPv6 NLRI with IPv4 next-hop (reverse independence)
 */
void test_srpolicy_ipv6_nlri_ipv4_nh() {
    srpolicy_nlri_list_t *nlri = srpolicy_nlri_create(100, 200, AFI_IPV6, "2001:db8::1");
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
    result = bgp_generate_update_srpolicy(nlri, origin, NULL, 0, AFI_IPV6, &next_hop);
    assert(result != NULL);

    // IPv6 NLRI AFI but IPv4 next-hop
    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI, &value, &length) &&
             (value[0] == 0x00) && (value[1] == AFI_IPV6) &&
             (value[2] == SAFI_SR_POLICY) &&
             (value[3] == 4) &&  /* IPv4 next-hop = 4 bytes */
             (value[4] == 192) && (value[5] == 0) &&
             (value[6] == 2) && (value[7] == 1);

    bgp_update_result_free(result);
    srpolicy_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    test_result(passed, "SR Policy IPv6 NLRI with IPv4 next-hop");
}

/*
 * Test: bgp_serialize_tunnel_encap_srpolicy_attr() writes the bytes of bgp_attr_create_tunnel_encap_srpolicy()
 * for a spec with every sub-TLV kind and a value longer than 255 octets (Extended Length header), and for a short
 * spec (3-octet header). It writes nothing when the attribute is one octet longer than the capacity, and it rejects
 * the specs that the create function rejects.
 */
void test_tunnel_encap_serialize_matches_create() {
    srpolicy_tunnel_encap_t        full = {0};
    srpolicy_tunnel_encap_t        short_spec = {0};
    srpolicy_tunnel_encap_t        bad_enlp = {0};
    srpolicy_srv6_binding_sid_t    srv6_bsid = {0};
    srpolicy_segment_t             mpls_segments[2] = {{0}};
    srpolicy_segment_t             srv6_segments[12];
    srpolicy_segment_list_t        lists[2] = {{0}};
    const srpolicy_tunnel_encap_t *specs[] = {&full, &short_spec};
    uint8_t                        want[1024];
    uint8_t                        got[1024];
    int                            passed = 1;

    for (int i = 0; i < 2; i++) {
        uint32_t label_net = htonl(16001u + (uint32_t)i);

        mpls_segments[i].type = SR_SEGMENT_TYPE_MPLS;
        memcpy(mpls_segments[i].sid, &label_net, sizeof(label_net));
    }
    memset(srv6_segments, 0, sizeof(srv6_segments));
    for (int i = 0; i < 12; i++) {
        srv6_segments[i].type = SR_SEGMENT_TYPE_SRV6;
        srv6_segments[i].has_srv6_behavior = 1;
        srv6_segments[i].srv6_behavior.endpoint_behavior = 0x0030;
        srv6_segments[i].srv6_behavior.locator_block_len = 32;
        srv6_segments[i].srv6_behavior.locator_node_len = 16;
        srv6_segments[i].srv6_behavior.function_len = 16;
        inet_pton(AF_INET6, "fc00:0:1::", srv6_segments[i].sid);
        srv6_segments[i].sid[15] = (uint8_t)(i + 1);
    }
    lists[0].weight = 10;
    lists[0].segments = mpls_segments;
    lists[0].num_segments = 2;
    lists[1].weight = 20;
    lists[1].segments = srv6_segments;
    lists[1].num_segments = 12;

    inet_pton(AF_INET6, "fc00:0:99::1", srv6_bsid.sid);

    full.has_preference = 1;
    full.preference = 300;
    full.has_binding_sid = 1;
    full.binding_sid.type = SRPOLICY_BINDING_SID_MPLS;
    full.binding_sid.mpls_label = 24000;
    full.has_enlp = 1;
    full.enlp = 2;
    full.has_priority = 1;
    full.priority = 7;
    full.candidate_path_name = "cp-green";
    full.policy_name = "policy-green";
    full.srv6_binding_sids = &srv6_bsid;
    full.num_srv6_binding_sids = 1;
    full.segment_lists = lists;
    full.num_segment_lists = 2;

    short_spec.has_preference = 1;
    short_spec.preference = 100;

    for (size_t s = 0; s < sizeof(specs) / sizeof(specs[0]); s++) {
        bgp_path_attr_t *attr = bgp_attr_create_tunnel_encap_srpolicy(specs[s]);
        int              want_len;

        assert(attr != NULL);
        want_len = bgp_serialize_raw_path_attr(want, attr->flags, attr->type_code, attr->length, attr->value);

        memset(got, 0xAA, sizeof(got));
        passed = passed && (bgp_serialize_tunnel_encap_srpolicy_attr(got, (size_t)want_len, specs[s]) == want_len) &&
                 (memcmp(got, want, (size_t)want_len) == 0) && (got[want_len] == 0xAA);

        // The full spec needs the 4-octet header; the short one the 3-octet header.
        if (specs[s] == &full) {
            passed = passed && (attr->length > 255) && ((got[0] & BGP_ATTR_FLAG_EXTENDED_LEN) != 0) &&
                     (read_u16(got + 2) == attr->length);
        } else {
            passed = passed && ((got[0] & BGP_ATTR_FLAG_EXTENDED_LEN) == 0) && (got[2] == attr->length);
        }

        memset(got, 0xAA, sizeof(got));
        passed = passed && (bgp_serialize_tunnel_encap_srpolicy_attr(got, (size_t)want_len - 1, specs[s]) == -1) &&
                 (got[0] == 0xAA);
        bgp_path_attr_free(attr);
    }

    // The checks of the create function apply: ENLP must be 1 to 4.
    bad_enlp.has_enlp = 1;
    bad_enlp.enlp = 5;
    passed = passed && (bgp_attr_create_tunnel_encap_srpolicy(&bad_enlp) == NULL) &&
             (bgp_serialize_tunnel_encap_srpolicy_attr(got, sizeof(got), &bad_enlp) == -1) &&
             (bgp_serialize_tunnel_encap_srpolicy_attr(got, sizeof(got), NULL) == -1);

    test_result(passed, "Tunnel Encap buffer writer matches the attribute path");
}

/*
 * Return 1 when bgp_attr_create_tunnel_encap_srpolicy() rejects spec (an attribute it makes is freed).
 */
static int tunnel_encap_rejected(const srpolicy_tunnel_encap_t *spec) {
    bgp_path_attr_t *attr = bgp_attr_create_tunnel_encap_srpolicy(spec);

    bgp_path_attr_free(attr);
    return attr == NULL;
}

/*
 * RFC 9830 unassigned flag bits "MUST be set to zero upon transmission". Each sub-TLV is checked independently.
 */
void test_tunnel_encap_rejects_unassigned_bsid_flag() {
    srpolicy_tunnel_encap_t     bsid_spec = {0};

    TEST("Tunnel Encap rejects an unassigned Binding SID flag");

    bsid_spec.has_binding_sid = 1;
    bsid_spec.binding_sid.type = SRPOLICY_BINDING_SID_MPLS;
    bsid_spec.binding_sid.mpls_label = 24000;
    bsid_spec.binding_sid.flags = 0x01;

    ASSERT(tunnel_encap_rejected(&bsid_spec), "RFC 9830 section 2.4.2: Binding SID flag 0x01 is unassigned");
    PASS();
}

void test_tunnel_encap_rejects_unassigned_srv6_bsid_flag() {
    srpolicy_tunnel_encap_t     srv6_spec = {0};
    srpolicy_srv6_binding_sid_t srv6_bsid = {0};

    TEST("Tunnel Encap rejects an unassigned SRv6 Binding SID flag");

    srv6_bsid.flags = 0x01;
    inet_pton(AF_INET6, "fc00:0:99::1", srv6_bsid.sid);
    srv6_spec.srv6_binding_sids = &srv6_bsid;
    srv6_spec.num_srv6_binding_sids = 1;

    ASSERT(tunnel_encap_rejected(&srv6_spec), "RFC 9830 section 2.4.3: SRv6 Binding SID flag 0x01 is unassigned");
    PASS();
}

void test_tunnel_encap_rejects_unassigned_segment_flag() {
    srpolicy_tunnel_encap_t segment_spec = {0};
    srpolicy_segment_t      segment = {0};
    srpolicy_segment_list_t list = {0};
    uint32_t                label_net = htonl(16001);

    TEST("Tunnel Encap rejects an unassigned segment flag");

    segment.type = SR_SEGMENT_TYPE_MPLS;
    segment.flags = 0x01;
    memcpy(segment.sid, &label_net, sizeof(label_net));
    list.weight = 1;
    list.segments = &segment;
    list.num_segments = 1;
    segment_spec.segment_lists = &list;
    segment_spec.num_segment_lists = 1;

    ASSERT(tunnel_encap_rejected(&segment_spec), "RFC 9830 section 2.4.4.2.3: Segment flag 0x01 is unassigned");
    PASS();
}

/*
 * Run the allocating encoder in a child: a length that wraps makes a short buffer, and the writer runs past it.
 * Return 1 only when the child exits normally with the expected acceptance/rejection result. A crash, fork failure or
 * allocation failure fails both the valid-name and oversized-name cases.
 */
static int tunnel_encap_name_matches_in_child(size_t name_len, int expect_rejection) {
    pid_t pid = fork();
    int   status = 0;

    if (pid == 0) {
        srpolicy_tunnel_encap_t spec = {0};
        bgp_path_attr_t        *attr;
        char                   *name = malloc(name_len + 1);
        int                     rejected;

        if (name == NULL) {
            _exit(2);
        }
        memset(name, 'a', name_len);
        name[name_len] = '\0';
        spec.has_preference = 1;
        spec.preference = 1;
        spec.candidate_path_name = name;
        attr = bgp_attr_create_tunnel_encap_srpolicy(&spec);
        rejected = attr == NULL;
        bgp_path_attr_free(attr);
        free(name);
        _exit(rejected == expect_rejection ? 0 : 1);
    }

    return pid > 0 && waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

void test_tunnel_encap_accepts_value_under_64k() {
    TEST("Tunnel Encap accepts a 60000-octet Candidate Path Name");

    ASSERT(tunnel_encap_name_matches_in_child(60000, 0), "A 60000-octet Candidate Path Name fits in the attribute");
    PASS();
}

/*
 * The attribute length field has 16 bits, so a value longer than 65,535 octets cannot be encoded.
 */
void test_tunnel_encap_rejects_value_over_64k() {
    TEST("Tunnel Encap rejects a value longer than 65535 octets");

    ASSERT(tunnel_encap_name_matches_in_child(65530, 1),
           "A 65530-octet Candidate Path Name needs more than 65535 value octets");
    PASS();
}

void test_tunnel_encap_accepts_maximum_value() {
    TEST("Tunnel Encap accepts an exactly 65535-octet value");

    ASSERT(tunnel_encap_name_matches_in_child(65519, 0), "The 65519-octet name and 16 octets of framing fit exactly");
    PASS();
}

void test_tunnel_encap_rejects_first_oversized_value() {
    TEST("Tunnel Encap rejects an exactly 65536-octet value");

    ASSERT(tunnel_encap_name_matches_in_child(65520, 1),
           "The first unrepresentable value is rejected before allocation and writing");
    PASS();
}

static void test_invalid_srpolicy_inputs(void) {
    uint8_t           wire[32];
    srpolicy_prefix_t prefix = {.endpoint_af = 99};
    int passed = srpolicy_nlri_create(1, 100, 99, "192.0.2.1") == NULL &&
                 srpolicy_nlri_create(1, 100, AFI_IPV4, "bad") == NULL &&
                 srpolicy_nlri_create(1, 100, AFI_IPV6, "192.0.2.1") == NULL &&
                 bgp_encode_srpolicy_prefix(wire, &prefix) < 0 &&
                 bgp_encode_srpolicy_prefix(wire, NULL) < 0;
    test_result(passed, "SR Policy rejects invalid AFI and malformed endpoints");
}

int main() {
    test_invalid_srpolicy_inputs();
    printf("==============================================\n");
    printf("BGP SR Policy UPDATE Message Generation Tests\n");
    printf("==============================================\n\n");

    test_srpolicy_nlri_creation_ipv4();
    test_srpolicy_nlri_creation_ipv6();
    test_srpolicy_prefix_encoding_ipv4();
    test_srpolicy_prefix_encoding_ipv6();
    test_srpolicy_next_hop_independence();
    test_srpolicy_ipv4_next_hop();
    test_srpolicy_ipv6_nlri();
    test_tunnel_encap_attribute();
    test_tunnel_encap_optional_subtlvs();
    test_tunnel_encap_legacy_srv6_binding_sid();
    test_tunnel_encap_srv6_binding_sid_subtlv();
    test_srpolicy_full_update();
    test_srpolicy_add_path();
    test_srpolicy_withdrawals();
    test_srpolicy_add_path_withdrawals();
    test_srpolicy_message_splitting();
    test_srpolicy_ipv6_encoding_size();
    test_srpolicy_ipv4_encoding_size();
    test_tunnel_encap_srv6_segment();
    test_tunnel_encap_srv6_segment_with_behavior();
    test_tunnel_encap_extended_validation();
    test_srpolicy_invalid_afi();
    test_srpolicy_endpoint_afi_mismatch();
    test_srpolicy_default_next_hop();
    test_tunnel_encap_multiple_segment_lists();
    test_srpolicy_ipv6_nlri_ipv4_nh();
    test_tunnel_encap_serialize_matches_create();
    test_tunnel_encap_rejects_unassigned_bsid_flag();
    test_tunnel_encap_rejects_unassigned_srv6_bsid_flag();
    test_tunnel_encap_rejects_unassigned_segment_flag();
    test_tunnel_encap_accepts_value_under_64k();
    test_tunnel_encap_rejects_value_over_64k();
    test_tunnel_encap_accepts_maximum_value();
    test_tunnel_encap_rejects_first_oversized_value();

    printf("==============================================\n");
    printf("Test Summary\n");
    printf("==============================================\n");
    printf("Total tests run:    %d\n", tests_passed + tests_failed);
    printf("Tests passed:       %d\n", tests_passed);
    printf("Tests failed:       %d\n", tests_failed);
    printf("==============================================\n\n");

    if (tests_failed == 0) {
        printf("%s %s\n\n", TEST_BADGE_PASS, "All tests passed!");
        return 0;
    } else {
        printf("%s %s\n\n", TEST_BADGE_FAIL, "Some tests failed");
        return 1;
    }
}
