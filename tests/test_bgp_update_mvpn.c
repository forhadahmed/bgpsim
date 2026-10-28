// Unit tests for BGP MVPN UPDATE message generation

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "bgp.h"
#include "test_case.h"
#include "test_wire.h"
#include "bgp_router.h"
#include "bgp_update.h"
#include "test_result.h"
#include "bgp_neighbor.h"
#include "test_helpers.h"

/*
 * RFC 6514 section 19: the MCAST-VPN NLRI "has been assigned SAFI 5". SAFI 129 is a different family ("Multicast for
 * BGP/MPLS IP VPNs"). The tests compare with the number, not with SAFI_MVPN, so a wrong SAFI_MVPN fails them.
 */
#define RFC6514_MCAST_VPN_SAFI 5

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

// MVPN Type 1 Tests

/*
 * Test 1: MVPN Type 1 IPv4 NLRI creation
 */
void test_mvpn_type1_ipv4_creation() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    mvpn_type1_nlri_t    *list = mvpn_type1_nlri_create_ipv4(rd, "10.0.0.1");
    mvpn_type1_nlri_t    *tail;

    assert(list != NULL);
    TEST_FIND_TAIL(tail, list);

    mvpn_type1_nlri_t *second = mvpn_type1_nlri_create_ipv4(rd, "10.0.0.2");
    mvpn_type1_nlri_append(&list, &tail, second);

    test_result((mvpn_type1_nlri_count(list) == 2) &&
                (list->prefix.route_type == MVPN_RT_INTRA_AS_IPMSI_AD) &&
                (list->prefix.af == AF_INET),
                "MVPN Type 1 IPv4 creation");
    mvpn_type1_nlri_list_free(list);
}

/*
 * Test 2: MVPN Type 1 prefix encoding
 */
void test_mvpn_type1_prefix_encoding() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    mvpn_type1_nlri_t    *nlri = mvpn_type1_nlri_create_ipv4(rd, "10.0.0.1");
    uint8_t               buffer[64];
    int                   len;

    assert(nlri != NULL);
    len = bgp_encode_mvpn_type1_prefix(buffer, &nlri->prefix);

    // route_type(1) + length(1) + RD(8) + IP(4) = 14
    test_result((len == 14) &&
                (buffer[0] == MVPN_RT_INTRA_AS_IPMSI_AD) &&
                (buffer[1] == 12) &&  /* length: RD(8) + IP(4) */
                test_wire_rd_is(buffer + 2, 0, 65000, 1),
                "MVPN Type 1 IPv4 prefix encoding");
    mvpn_type1_nlri_list_free(nlri);
}

/*
 * Test 3: MVPN Type 1 IPv6 prefix encoding
 */
void test_mvpn_type1_ipv6_prefix_encoding() {
    route_distinguisher_t rd = rd_create_type1(0x0A000001, 100);
    mvpn_type1_nlri_t    *nlri = mvpn_type1_nlri_create_ipv6(rd, "2001:db8::1");
    uint8_t               buffer[64];
    int                   len;

    assert(nlri != NULL);
    len = bgp_encode_mvpn_type1_prefix(buffer, &nlri->prefix);

    // route_type(1) + length(1) + RD(8) + IP(16) = 26
    test_result((len == 26) &&
                (buffer[0] == MVPN_RT_INTRA_AS_IPMSI_AD) &&
                (buffer[1] == 24) &&  /* length: RD(8) + IP(16) */
                test_wire_rd_is(buffer + 2, 1, 0x0A000001, 100),
                "MVPN Type 1 IPv6 prefix encoding");
    mvpn_type1_nlri_list_free(nlri);
}

/*
 * Test 4: MVPN Type 1 full UPDATE generation
 */
void test_mvpn_type1_update_generation() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    mvpn_type1_nlri_t    *nlri = mvpn_type1_nlri_create_ipv4(rd, "10.0.0.1");
    bgp_path_attr_t      *attrs = make_test_attrs();
    bgp_next_hop_t        next_hop = make_ipv4_next_hop("192.0.2.1");
    bgp_update_result_t  *result;
    const uint8_t        *value = NULL;
    uint16_t              length = 0;
    int                   passed;

    result = bgp_generate_update_mvpn_type1(nlri, attrs, NULL, 0, AFI_IPV4, &next_hop);
    assert(result != NULL);

    // Verify MP_REACH_NLRI with AFI=1, SAFI=5
    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI, &value, &length) &&
             (read_u16(value) == AFI_IPV4) &&
             (value[2] == RFC6514_MCAST_VPN_SAFI) &&
             (value[3] == 4);  /* IPv4 next-hop */

    bgp_update_result_free(result);
    mvpn_type1_nlri_list_free(nlri);
    bgp_path_attr_list_free(attrs);
    test_result(passed, "MVPN Type 1 UPDATE generation");
}

/*
 * Test 5: MVPN Type 1 ADD-PATH
 */
void test_mvpn_type1_add_path() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    mvpn_type1_nlri_t    *nlri = mvpn_type1_nlri_create_ipv4_path_id(rd, "10.0.0.1", 777);
    mvpn_type1_nlri_t    *tail;
    bgp_path_attr_t      *attrs = make_test_attrs();
    bgp_next_hop_t        next_hop = make_ipv4_next_hop("192.0.2.1");
    bgp_update_result_t  *result;
    const uint8_t        *value = NULL;
    uint16_t              length = 0;
    int                   offset = 0;
    int                   passed;

    TEST_FIND_TAIL(tail, nlri);
    mvpn_type1_nlri_t *second = mvpn_type1_nlri_create_ipv4_path_id(rd, "10.0.0.2", 888);
    mvpn_type1_nlri_append(&nlri, &tail, second);

    result = bgp_generate_update_mvpn_type1(nlri, attrs, NULL, 0, AFI_IPV4, &next_hop);
    assert(result != NULL);

    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI, &value, &length) &&
             mp_reach_nlri_offset(value, length, &offset) &&
             (read_u32(value + offset) == 777);

    bgp_update_result_free(result);
    mvpn_type1_nlri_list_free(nlri);
    bgp_path_attr_list_free(attrs);
    test_result(passed, "MVPN Type 1 ADD-PATH");
}

/*
 * Test 6: MVPN Type 1 withdrawal
 */
void test_mvpn_type1_withdrawal() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    mvpn_type1_nlri_t    *withdrawn = mvpn_type1_nlri_create_ipv4(rd, "10.0.0.1");
    bgp_update_result_t  *result;
    int                   passed;

    result = bgp_generate_update_mvpn_type1(NULL, NULL, withdrawn, 0, AFI_IPV4, NULL);
    assert(result != NULL);

    passed = (result->num_messages == 1) &&
             has_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_UNREACH_NLRI);

    bgp_update_result_free(result);
    mvpn_type1_nlri_list_free(withdrawn);
    test_result(passed, "MVPN Type 1 withdrawal");
}

// MVPN Type 3 Tests

/*
 * Test 7: MVPN Type 3 IPv4 NLRI creation
 */
void test_mvpn_type3_ipv4_creation() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    mvpn_type3_nlri_t    *nlri = mvpn_type3_nlri_create_ipv4(rd, "10.1.1.1", "239.1.1.1", "10.0.0.1");

    assert(nlri != NULL);
    test_result((nlri->prefix.route_type == MVPN_RT_SPMSI_AD) &&
                (nlri->prefix.af == AF_INET) &&
                (nlri->prefix.mcast_src_len == 32) &&
                (nlri->prefix.mcast_grp_len == 32),
                "MVPN Type 3 IPv4 creation");
    mvpn_type3_nlri_list_free(nlri);
}

/*
 * Test 8: MVPN Type 3 prefix encoding
 */
void test_mvpn_type3_prefix_encoding() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    mvpn_type3_nlri_t    *nlri = mvpn_type3_nlri_create_ipv4(rd, "10.1.1.1", "239.1.1.1", "10.0.0.1");
    uint8_t               buffer[128];
    int                   len;

    assert(nlri != NULL);
    len = bgp_encode_mvpn_type3_prefix(buffer, &nlri->prefix);

    /*
     * route_type(1) + length(1) + RD(8) + src_len(1) + src(4) +
     * grp_len(1) + grp(4) + orig_ip(4) = 24
     */
    test_result((len == 24) &&
                (buffer[0] == MVPN_RT_SPMSI_AD) &&
                (buffer[1] == 22) &&   /* length: 8+1+4+1+4+4 */
                (buffer[10] == 32) &&  /* mcast_src_len       */
                (buffer[15] == 32) &&  /* mcast_grp_len       */
                test_wire_rd_is(buffer + 2, 0, 65000, 1),
                "MVPN Type 3 IPv4 prefix encoding");
    mvpn_type3_nlri_list_free(nlri);
}

/*
 * Test 9: MVPN Type 3 IPv6 prefix encoding
 */
void test_mvpn_type3_ipv6_prefix_encoding() {
    route_distinguisher_t rd = rd_create_type2(4200000000u, 7);
    mvpn_type3_nlri_t    *nlri = mvpn_type3_nlri_create_ipv6(rd, "2001:db8::1", "ff3e::1", "2001:db8::99");
    uint8_t               buffer[128];
    int                   len;

    assert(nlri != NULL);
    len = bgp_encode_mvpn_type3_prefix(buffer, &nlri->prefix);

    /*
     * route_type(1) + length(1) + RD(8) + src_len(1) + src(16) +
     * grp_len(1) + grp(16) + orig_ip(16) = 60
     */
    test_result((len == 60) &&
                (buffer[0] == MVPN_RT_SPMSI_AD) &&
                (buffer[1] == 58) &&    /* length: 8+1+16+1+16+16 */
                (buffer[10] == 128) &&  /* mcast_src_len          */
                (buffer[27] == 128) &&  /* mcast_grp_len          */
                test_wire_rd_is(buffer + 2, 2, 4200000000u, 7),
                "MVPN Type 3 IPv6 prefix encoding");
    mvpn_type3_nlri_list_free(nlri);
}

/*
 * Test 10: MVPN Type 3 full UPDATE generation
 */
void test_mvpn_type3_update_generation() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    mvpn_type3_nlri_t    *nlri = mvpn_type3_nlri_create_ipv4(rd, "10.1.1.1", "239.1.1.1", "10.0.0.1");
    bgp_path_attr_t      *attrs = make_test_attrs();
    bgp_next_hop_t        next_hop = make_ipv4_next_hop("192.0.2.1");
    bgp_update_result_t  *result;
    const uint8_t        *value = NULL;
    uint16_t              length = 0;
    int                   passed;

    result = bgp_generate_update_mvpn_type3(nlri, attrs, NULL, 0, AFI_IPV4, &next_hop);
    assert(result != NULL);

    // Verify MP_REACH_NLRI with AFI=1, SAFI=5
    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI, &value, &length) &&
             (read_u16(value) == AFI_IPV4) &&
             (value[2] == RFC6514_MCAST_VPN_SAFI) &&
             (value[3] == 4);

    bgp_update_result_free(result);
    mvpn_type3_nlri_list_free(nlri);
    bgp_path_attr_list_free(attrs);
    test_result(passed, "MVPN Type 3 UPDATE generation");
}

/*
 * Test 11: MVPN Type 3 ADD-PATH
 */
void test_mvpn_type3_add_path() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    mvpn_type3_nlri_t    *nlri = mvpn_type3_nlri_create_ipv4_path_id(rd, "10.1.1.1", "239.1.1.1", "10.0.0.1", 1234);
    mvpn_type3_nlri_t    *tail;
    bgp_path_attr_t      *attrs = make_test_attrs();
    bgp_next_hop_t        next_hop = make_ipv4_next_hop("192.0.2.1");
    bgp_update_result_t  *result;
    const uint8_t        *value = NULL;
    uint16_t              length = 0;
    int                   offset = 0;
    int                   passed;

    TEST_FIND_TAIL(tail, nlri);
    mvpn_type3_nlri_t *second = mvpn_type3_nlri_create_ipv4_path_id(rd, "10.2.2.2", "239.2.2.2", "10.0.0.2", 5678);
    mvpn_type3_nlri_append(&nlri, &tail, second);

    result = bgp_generate_update_mvpn_type3(nlri, attrs, NULL, 0, AFI_IPV4, &next_hop);
    assert(result != NULL);

    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI, &value, &length) &&
             mp_reach_nlri_offset(value, length, &offset) &&
             (read_u32(value + offset) == 1234);

    bgp_update_result_free(result);
    mvpn_type3_nlri_list_free(nlri);
    bgp_path_attr_list_free(attrs);
    test_result(passed, "MVPN Type 3 ADD-PATH");
}

/*
 * Test 12: MVPN Type 3 withdrawal
 */
void test_mvpn_type3_withdrawal() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    mvpn_type3_nlri_t    *withdrawn = mvpn_type3_nlri_create_ipv4(rd, "10.1.1.1", "239.1.1.1", "10.0.0.1");
    bgp_update_result_t  *result;
    int                   passed;

    result = bgp_generate_update_mvpn_type3(NULL, NULL, withdrawn, 0, AFI_IPV4, NULL);
    assert(result != NULL);

    passed = (result->num_messages == 1) &&
             has_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_UNREACH_NLRI);

    bgp_update_result_free(result);
    mvpn_type3_nlri_list_free(withdrawn);
    test_result(passed, "MVPN Type 3 withdrawal");
}

// MVPN Type 2/4/5/6/7 Tests

void test_mvpn_type2_prefix_encoding() {
    route_distinguisher_t rd = rd_create_type0(65000, 2);
    mvpn_type2_nlri_t    *nlri = mvpn_type2_nlri_create(rd, 65123);
    uint8_t               buffer[64];
    int                   len;

    assert(nlri != NULL);
    len = bgp_encode_mvpn_type2_prefix(buffer, &nlri->prefix);

    test_result((len == 14) &&
                (buffer[0] == MVPN_RT_INTER_AS_IPMSI_AD) &&
                (buffer[1] == 12) &&
                test_wire_rd_is(buffer + 2, 0, 65000, 2) &&
                (read_u32(buffer + 10) == 65123),
                "MVPN Type 2 prefix encoding");
    mvpn_type2_nlri_list_free(nlri);
}

void test_mvpn_type2_update_generation() {
    route_distinguisher_t rd = rd_create_type0(65000, 2);
    mvpn_type2_nlri_t    *nlri = mvpn_type2_nlri_create_path_id(rd, 65123, 222);
    bgp_path_attr_t      *attrs = make_test_attrs();
    bgp_next_hop_t        next_hop = make_ipv4_next_hop("192.0.2.1");
    bgp_update_result_t  *result;
    const uint8_t        *value = NULL;
    uint16_t              length = 0;
    int                   offset = 0;
    int                   passed;

    result = bgp_generate_update_mvpn_type2(nlri, attrs, NULL, 0, AFI_IPV4, &next_hop);
    assert(result != NULL);

    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI, &value, &length) &&
             (read_u16(value) == AFI_IPV4) &&
             (value[2] == RFC6514_MCAST_VPN_SAFI) &&
             mp_reach_nlri_offset(value, length, &offset) &&
             (read_u32(value + offset) == 222);

    bgp_update_result_free(result);
    mvpn_type2_nlri_list_free(nlri);
    bgp_path_attr_list_free(attrs);
    test_result(passed, "MVPN Type 2 UPDATE generation");
}

void test_mvpn_type4_prefix_encoding() {
    route_distinguisher_t rd = rd_create_type0(65000, 2);
    uint8_t               route_key[32];
    mvpn_type2_prefix_t route_key_prefix = {
        .route_type = MVPN_RT_INTER_AS_IPMSI_AD,
        .rd = rd,
        .source_as = htonl(65123)
    };
    mvpn_type4_nlri_t *nlri;
    uint8_t            buffer[64];
    int                route_key_len;
    int                len;

    route_key_len = bgp_encode_mvpn_type2_prefix(route_key, &route_key_prefix);
    nlri = mvpn_type4_nlri_create_ipv4(rd, route_key, (uint8_t)route_key_len, "10.0.0.9");
    assert(nlri != NULL);
    len = bgp_encode_mvpn_type4_prefix(buffer, &nlri->prefix);

    test_result((len == 20) &&
                (buffer[0] == MVPN_RT_LEAF_AD) &&
                (buffer[1] == 18) &&
                (buffer[2] == MVPN_RT_INTER_AS_IPMSI_AD) &&
                test_wire_rd_is(buffer + 4, 0, 65000, 2),  /* RD of the embedded route key */
                "MVPN Type 4 prefix encoding");
    mvpn_type4_nlri_list_free(nlri);
}

void test_mvpn_type4_update_generation() {
    route_distinguisher_t rd = rd_create_type0(65000, 2);
    uint8_t               route_key[32];
    mvpn_type2_prefix_t route_key_prefix = {
        .route_type = MVPN_RT_INTER_AS_IPMSI_AD,
        .rd = rd,
        .source_as = htonl(65123)
    };
    int route_key_len = bgp_encode_mvpn_type2_prefix(route_key, &route_key_prefix);
    mvpn_type4_nlri_t *nlri = mvpn_type4_nlri_create_ipv4_path_id(
        rd, route_key, (uint8_t)route_key_len, "10.0.0.9", 333);
    bgp_path_attr_t     *attrs = make_test_attrs();
    bgp_next_hop_t       next_hop = make_ipv4_next_hop("192.0.2.1");
    bgp_update_result_t *result;
    const uint8_t       *value = NULL;
    uint16_t             length = 0;
    int                  offset = 0;
    int                  passed;

    result = bgp_generate_update_mvpn_type4(nlri, attrs, NULL, 0, AFI_IPV4, &next_hop);
    assert(result != NULL);

    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI, &value, &length) &&
             (read_u16(value) == AFI_IPV4) &&
             (value[2] == RFC6514_MCAST_VPN_SAFI) &&
             mp_reach_nlri_offset(value, length, &offset) &&
             (read_u32(value + offset) == 333);

    bgp_update_result_free(result);
    mvpn_type4_nlri_list_free(nlri);
    bgp_path_attr_list_free(attrs);
    test_result(passed, "MVPN Type 4 UPDATE generation");
}

void test_mvpn_type5_update_generation() {
    route_distinguisher_t rd = rd_create_type0(65000, 3);
    mvpn_type5_nlri_t    *nlri = mvpn_type5_nlri_create_ipv4_path_id(rd, "10.1.1.1", "239.1.1.1", 444);
    bgp_path_attr_t      *attrs = make_test_attrs();
    bgp_next_hop_t        next_hop = make_ipv4_next_hop("192.0.2.1");
    bgp_update_result_t  *result;
    const uint8_t        *value = NULL;
    uint16_t              length = 0;
    int                   offset = 0;
    int                   passed;

    result = bgp_generate_update_mvpn_type5(nlri, attrs, NULL, 0, AFI_IPV4, &next_hop);
    assert(result != NULL);

    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI, &value, &length) &&
             (read_u16(value) == AFI_IPV4) &&
             (value[2] == RFC6514_MCAST_VPN_SAFI) &&
             mp_reach_nlri_offset(value, length, &offset) &&
             (read_u32(value + offset) == 444) &&
             test_wire_rd_is(value + offset + 6, 0, 65000, 3);  /* after path-id, rt and len */

    bgp_update_result_free(result);
    mvpn_type5_nlri_list_free(nlri);
    bgp_path_attr_list_free(attrs);
    test_result(passed, "MVPN Type 5 UPDATE generation");
}

void test_mvpn_type6_update_generation() {
    route_distinguisher_t rd = rd_create_type0(65000, 4);
    mvpn_type6_nlri_t    *nlri = mvpn_type6_nlri_create_ipv4_path_id(rd, 65123, "10.2.2.2", "239.2.2.2", 555);
    bgp_path_attr_t      *attrs = make_test_attrs();
    bgp_next_hop_t        next_hop = make_ipv4_next_hop("192.0.2.1");
    bgp_update_result_t  *result;
    const uint8_t        *value = NULL;
    uint16_t              length = 0;
    int                   offset = 0;
    int                   passed;

    result = bgp_generate_update_mvpn_type6(nlri, attrs, NULL, 0, AFI_IPV4, &next_hop);
    assert(result != NULL);

    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI, &value, &length) &&
             (read_u16(value) == AFI_IPV4) &&
             (value[2] == RFC6514_MCAST_VPN_SAFI) &&
             mp_reach_nlri_offset(value, length, &offset) &&
             (read_u32(value + offset) == 555) &&
             test_wire_rd_is(value + offset + 6, 0, 65000, 4);  /* after path-id, rt and len */

    bgp_update_result_free(result);
    mvpn_type6_nlri_list_free(nlri);
    bgp_path_attr_list_free(attrs);
    test_result(passed, "MVPN Type 6 UPDATE generation");
}

void test_mvpn_type7_update_generation() {
    route_distinguisher_t rd = rd_create_type0(65000, 5);
    mvpn_type7_nlri_t    *nlri = mvpn_type7_nlri_create_ipv4_path_id(rd, 65123, "10.3.3.3", "239.3.3.3", 666);
    bgp_path_attr_t      *attrs = make_test_attrs();
    bgp_next_hop_t        next_hop = make_ipv4_next_hop("192.0.2.1");
    bgp_update_result_t  *result;
    const uint8_t        *value = NULL;
    uint16_t              length = 0;
    int                   offset = 0;
    int                   passed;

    result = bgp_generate_update_mvpn_type7(nlri, attrs, NULL, 0, AFI_IPV4, &next_hop);
    assert(result != NULL);

    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI, &value, &length) &&
             (read_u16(value) == AFI_IPV4) &&
             (value[2] == RFC6514_MCAST_VPN_SAFI) &&
             mp_reach_nlri_offset(value, length, &offset) &&
             (read_u32(value + offset) == 666) &&
             test_wire_rd_is(value + offset + 6, 0, 65000, 5);  /* after path-id, rt and len */

    bgp_update_result_free(result);
    mvpn_type7_nlri_list_free(nlri);
    bgp_path_attr_list_free(attrs);
    test_result(passed, "MVPN Type 7 UPDATE generation");
}

// PMSI Tunnel Attribute Tests

/*
 * Test 13: PMSI Tunnel attribute creation
 */
void test_pmsi_tunnel_creation() {
    uint8_t tunnel_id[] = {10, 0, 0, 1};  /* Ingress Replication to 10.0.0.1 */
    bgp_path_attr_t *attr = bgp_attr_create_pmsi_tunnel(
        0x01,  /* flags: leaf-info-required        */
        6,     /* tunnel type: Ingress Replication */
        5000,  /* label                            */
        tunnel_id, 4);
    int passed;

    assert(attr != NULL);
    passed = (attr->flags == (BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANSITIVE)) &&
             (attr->type_code == BGP_ATTR_PMSI_TUNNEL) &&
             (attr->length == 9) &&       /* 5 + 4 bytes tunnel_id */
             (attr->value[0] == 0x01) &&  /* flags                 */
             (attr->value[1] == 6) &&     /* tunnel type           */
             (attr->value[5] == 10) &&    /* tunnel ID starts      */
             (attr->value[6] == 0) &&
             (attr->value[7] == 0) &&
             (attr->value[8] == 1);

    bgp_path_attr_free(attr);
    test_result(passed, "PMSI Tunnel attribute creation");
}

/*
 * The label value of a PMSI Tunnel attribute: the high-order 20 bits of its 3-octet MPLS Label field.
 */
static uint32_t pmsi_label_value(const bgp_path_attr_t *attr) {
    return ((uint32_t)attr->value[2] << 12) | ((uint32_t)attr->value[3] << 4) | (attr->value[4] >> 4);
}

void test_pmsi_tunnel_nonzero_label_value() {
    uint8_t         tunnel_id[] = {10, 0, 0, 1};
    bgp_path_attr_t *label = bgp_attr_create_pmsi_tunnel(0, 6, 5000, tunnel_id, 4);
    uint32_t         value = label != NULL ? pmsi_label_value(label) : 0;

    TEST("PMSI Tunnel nonzero label keeps its value");
    bgp_path_attr_free(label);

    ASSERT(value == 5000, "A label keeps its value in the high-order 20 bits");
    PASS();
}

/*
 * RFC 6514 section 5: "Absence of an MPLS Label is indicated by setting the MPLS Label field to zero".
 */
void test_pmsi_tunnel_no_label_is_zero() {
    uint8_t         tunnel_id[] = {10, 0, 0, 1};
    bgp_path_attr_t *no_label = bgp_attr_create_pmsi_tunnel(0, 6, 0, tunnel_id, 4);
    int              created = no_label != NULL;
    int              all_zero = created && no_label->value[2] == 0 && no_label->value[3] == 0 && no_label->value[4] == 0;

    TEST("PMSI Tunnel label 0 is encoded as an all-zero field");
    bgp_path_attr_free(no_label);

    ASSERT(created, "The PMSI Tunnel attribute builds");
    ASSERT(all_zero, "RFC 6514 section 5: an absent MPLS Label is an all-zero field");
    PASS();
}

// Additional boundary tests

/*
 * Test 14: MVPN Type 1 with AFI_IPV6 UPDATE uses the MCAST-VPN SAFI in MP_REACH
 */
void test_mvpn_type1_ipv6_update() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    mvpn_type1_nlri_t    *nlri = mvpn_type1_nlri_create_ipv6(rd, "2001:db8::1");
    bgp_path_attr_t      *attrs = make_test_attrs();
    bgp_next_hop_t        next_hop = make_ipv6_next_hop("2001:db8::99");
    bgp_update_result_t  *result;
    const uint8_t        *value = NULL;
    uint16_t              length = 0;
    int                   passed;

    result = bgp_generate_update_mvpn_type1(nlri, attrs, NULL, 0, AFI_IPV6, &next_hop);
    assert(result != NULL);

    // Verify AFI=2, SAFI=5, nh_len=16
    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI, &value, &length) &&
             (read_u16(value) == AFI_IPV6) &&
             (value[2] == RFC6514_MCAST_VPN_SAFI) &&
             (value[3] == 16);

    bgp_update_result_free(result);
    mvpn_type1_nlri_list_free(nlri);
    bgp_path_attr_list_free(attrs);
    test_result(passed, "MVPN Type 1 IPv6 UPDATE (AFI=2, SAFI=5)");
}

/*
 * Test 15: MVPN Type 3 IPv6 UPDATE
 */
void test_mvpn_type3_ipv6_update() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    mvpn_type3_nlri_t    *nlri = mvpn_type3_nlri_create_ipv6(rd, "2001:db8::1", "ff3e::1", "2001:db8::99");
    bgp_path_attr_t      *attrs = make_test_attrs();
    bgp_next_hop_t        next_hop = make_ipv6_next_hop("2001:db8::99");
    bgp_update_result_t  *result;
    const uint8_t        *value = NULL;
    uint16_t              length = 0;
    int                   passed;

    result = bgp_generate_update_mvpn_type3(nlri, attrs, NULL, 0, AFI_IPV6, &next_hop);
    assert(result != NULL);

    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI, &value, &length) &&
             (read_u16(value) == AFI_IPV6) &&
             (value[2] == RFC6514_MCAST_VPN_SAFI) &&
             (value[3] == 16);

    bgp_update_result_free(result);
    mvpn_type3_nlri_list_free(nlri);
    bgp_path_attr_list_free(attrs);
    test_result(passed, "MVPN Type 3 IPv6 UPDATE (AFI=2, SAFI=5)");
}

/*
 * Test 16: MVPN Type 1 ADD-PATH withdrawal
 */
void test_mvpn_type1_add_path_withdrawal() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    mvpn_type1_nlri_t    *withdrawn = mvpn_type1_nlri_create_ipv4_path_id(rd, "10.0.0.1", 444);
    bgp_update_result_t  *result;
    const uint8_t        *value = NULL;
    uint16_t              length = 0;
    int                   offset = 0;
    int                   passed;

    result = bgp_generate_update_mvpn_type1(NULL, NULL, withdrawn, 0, AFI_IPV4, NULL);
    assert(result != NULL);

    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_UNREACH_NLRI, &value, &length) &&
             mp_unreach_nlri_offset(value, length, &offset) &&
             (read_u32(value + offset) == 444);

    bgp_update_result_free(result);
    mvpn_type1_nlri_list_free(withdrawn);
    test_result(passed, "MVPN Type 1 ADD-PATH withdrawal");
}

/*
 * Test 17: MVPN Type 3 ADD-PATH withdrawal
 */
void test_mvpn_type3_add_path_withdrawal() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    mvpn_type3_nlri_t    *withdrawn = mvpn_type3_nlri_create_ipv4_path_id(rd, "10.1.1.1", "239.1.1.1", "10.0.0.1", 555);
    bgp_update_result_t  *result;
    const uint8_t        *value = NULL;
    uint16_t              length = 0;
    int                   offset = 0;
    int                   passed;

    result = bgp_generate_update_mvpn_type3(NULL, NULL, withdrawn, 0, AFI_IPV4, NULL);
    assert(result != NULL);

    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_UNREACH_NLRI, &value, &length) &&
             mp_unreach_nlri_offset(value, length, &offset) &&
             (read_u32(value + offset) == 555);

    bgp_update_result_free(result);
    mvpn_type3_nlri_list_free(withdrawn);
    test_result(passed, "MVPN Type 3 ADD-PATH withdrawal");
}

/*
 * Test 18: PMSI Tunnel with no tunnel ID
 */
void test_pmsi_tunnel_no_tunnel_id() {
    bgp_path_attr_t *attr = bgp_attr_create_pmsi_tunnel(0, 0, 0, NULL, 0);
    int              passed;

    assert(attr != NULL);
    passed = (attr->length == 5) &&
             (attr->value[0] == 0) &&
             (attr->value[1] == 0);

    bgp_path_attr_free(attr);
    test_result(passed, "PMSI Tunnel with no tunnel ID");
}

/*
 * Test 19: MVPN rejects invalid AFI
 */
void test_mvpn_invalid_afi() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    mvpn_type1_nlri_t    *nlri = mvpn_type1_nlri_create_ipv4(rd, "10.0.0.1");
    bgp_path_attr_t      *attrs = make_test_attrs();
    bgp_next_hop_t        next_hop = make_ipv4_next_hop("192.0.2.1");
    bgp_update_result_t  *result;

    // AFI_L2VPN is not valid for MVPN
    result = bgp_generate_update_mvpn_type1(nlri, attrs, NULL, 0, AFI_L2VPN, &next_hop);
    test_result(result == NULL, "MVPN rejects invalid AFI");

    mvpn_type1_nlri_list_free(nlri);
    bgp_path_attr_list_free(attrs);
}

static void test_mvpn_validation(void) {
    uint8_t               bytes[300] = {1};
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    mvpn_type4_nlri_t    *leaf = mvpn_type4_nlri_create_ipv6_path_id(rd, bytes, 240, "2001:db8::1", 7);
    test_result(leaf == NULL, "MVPN Leaf A-D rejects overflowing one-octet length");
    mvpn_type4_nlri_list_free(leaf);
    const uint8_t short_key[] = {2, 0};
    leaf = mvpn_type4_nlri_create_ipv4(rd, short_key, sizeof(short_key), "192.0.2.1");
    test_result(leaf == NULL, "MVPN Leaf A-D rejects a truncated embedded Route Key");
    mvpn_type4_nlri_list_free(leaf);
    mvpn_type1_nlri_t *nlri = mvpn_type1_nlri_create_ipv4(rd, "not-an-ip");
    test_result(nlri == NULL, "MVPN rejects invalid originating router addresses");
    mvpn_type1_nlri_list_free(nlri);
    uint8_t *large_id = calloc(UINT16_MAX, 1);
    assert(large_id);
    large_id[65529] = 0xab;
    bgp_path_attr_t *attr = bgp_attr_create_pmsi_tunnel(0, 6, 0, large_id, 65530);
    test_result(attr && attr->length == UINT16_MAX && attr->value[65534] == 0xab,
                "PMSI preserves payload at the exact attribute-value boundary");
    bgp_path_attr_list_free(attr);
    attr = bgp_attr_create_pmsi_tunnel(0, 6, 0, large_id, 65531);
    test_result(attr == NULL, "PMSI rejects overflowing attribute length");
    bgp_path_attr_list_free(attr);
    free(large_id);
    attr = bgp_attr_create_pmsi_tunnel(0, 6, 0x100000, bytes, 4);
    test_result(attr == NULL, "PMSI rejects overflowing MPLS label");
    bgp_path_attr_list_free(attr);
    attr = bgp_attr_create_pmsi_tunnel(0, 6, 0, NULL, 4);
    test_result(attr == NULL, "PMSI rejects a missing tunnel identifier payload");
    bgp_path_attr_list_free(attr);
}

int main() {
    printf("============================================\n");
    printf("BGP MVPN UPDATE Generation Tests\n");
    printf("============================================\n\n");

    // MVPN Type 1 tests
    test_mvpn_type1_ipv4_creation();
    test_mvpn_type1_prefix_encoding();
    test_mvpn_type1_ipv6_prefix_encoding();
    test_mvpn_type1_update_generation();
    test_mvpn_type1_add_path();
    test_mvpn_type1_withdrawal();

    // MVPN Type 3 tests
    test_mvpn_type3_ipv4_creation();
    test_mvpn_type3_prefix_encoding();
    test_mvpn_type3_ipv6_prefix_encoding();
    test_mvpn_type3_update_generation();
    test_mvpn_type3_add_path();
    test_mvpn_type3_withdrawal();

    // Additional MVPN route types
    test_mvpn_type2_prefix_encoding();
    test_mvpn_type2_update_generation();
    test_mvpn_type4_prefix_encoding();
    test_mvpn_type4_update_generation();
    test_mvpn_type5_update_generation();
    test_mvpn_type6_update_generation();
    test_mvpn_type7_update_generation();

    // Attribute helpers
    test_pmsi_tunnel_creation();
    test_pmsi_tunnel_nonzero_label_value();
    test_pmsi_tunnel_no_label_is_zero();

    // Boundary / additional tests
    test_mvpn_type1_ipv6_update();
    test_mvpn_type3_ipv6_update();
    test_mvpn_type1_add_path_withdrawal();
    test_mvpn_type3_add_path_withdrawal();
    test_pmsi_tunnel_no_tunnel_id();
    test_mvpn_invalid_afi();
    test_mvpn_validation();

    printf("============================================\n");
    printf("Test Summary\n");
    printf("============================================\n");
    printf("Total tests run:    %d\n", tests_passed + tests_failed);
    printf("Tests passed:       %d\n", tests_passed);
    printf("Tests failed:       %d\n", tests_failed);
    printf("============================================\n\n");

    if (tests_failed == 0) {
        printf("%s %s\n\n", TEST_BADGE_PASS, "All tests passed!");
        return 0;
    } else {
        printf("%s %s\n\n", TEST_BADGE_FAIL, "Some tests failed");
        return 1;
    }
}
