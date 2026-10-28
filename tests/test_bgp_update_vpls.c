// Unit tests for BGP VPLS UPDATE message generation

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

// VPLS Tests

/*
 * Test 1: VPLS NLRI creation
 */
void test_vpls_nlri_creation() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    vpls_nlri_list_t     *list = vpls_nlri_create(rd, 1, 0, 8, 1000);
    vpls_nlri_list_t     *tail;

    assert(list != NULL);
    TEST_FIND_TAIL(tail, list);

    vpls_nlri_list_t *second = vpls_nlri_create(rd, 2, 0, 8, 2000);
    vpls_nlri_append(&list, &tail, second);

    test_result(vpls_nlri_count(list) == 2, "VPLS NLRI creation");
    vpls_nlri_list_free(list);
}

/*
 * Test 2: VPLS prefix encoding
 */
void test_vpls_prefix_encoding() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    vpls_nlri_list_t     *nlri = vpls_nlri_create(rd, 10, 0, 16, 5000);
    uint8_t               buffer[64];
    int                   len;

    assert(nlri != NULL);
    len = bgp_encode_vpls_prefix(buffer, &nlri->prefix);

    // length(2) + RD(8) + VE_ID(2) + offset(2) + size(2) + label(3) = 19
    test_result((len == 19) &&
                (read_u16(buffer) == 17) &&       /* NLRI length field = 17 */
                (read_u16(buffer + 10) == 10) &&  /* VE ID = 10             */
                (read_u16(buffer + 12) == 0) &&   /* VE Block Offset = 0    */
                (read_u16(buffer + 14) == 16) &&  /* VE Block Size = 16     */
                test_wire_rd_is(buffer + 2, 0, 65000, 1),
                "VPLS prefix encoding");
    vpls_nlri_list_free(nlri);
}

/*
 * Test 3: VPLS full UPDATE generation
 */
void test_vpls_update_generation() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    vpls_nlri_list_t     *nlri = vpls_nlri_create(rd, 1, 0, 8, 1000);
    bgp_path_attr_t      *attrs = make_test_attrs();
    bgp_next_hop_t        next_hop = make_ipv4_next_hop("10.0.0.1");
    bgp_update_result_t  *result;
    const uint8_t        *value = NULL;
    uint16_t              length = 0;
    int                   passed;

    result = bgp_generate_update_vpls(nlri, attrs, NULL, 0, &next_hop);
    assert(result != NULL);

    // Verify MP_REACH_NLRI with AFI=25, SAFI=65
    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI, &value, &length) &&
             (read_u16(value) == AFI_L2VPN) &&
             (value[2] == SAFI_VPLS) &&
             (value[3] == 4);  /* IPv4 next-hop = 4 bytes */

    bgp_update_result_free(result);
    vpls_nlri_list_free(nlri);
    bgp_path_attr_list_free(attrs);
    test_result(passed, "VPLS UPDATE generation");
}

/*
 * Test 4: VPLS Layer2 Info Extended Community
 */
void test_vpls_l2info_ext_comm() {
    bgp_path_attr_t *attr = bgp_attr_create_ext_comm_l2info(19, 0x04, 1500);
    int              passed;

    assert(attr != NULL);
    passed = (attr->flags == (BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANSITIVE)) &&
             (attr->type_code == BGP_ATTR_EXT_COMM) &&
             (attr->length == 8) &&
             (attr->value[0] == 0x80) &&           /* Extended type high        */
             (attr->value[1] == 0x0A) &&           /* Extended type low         */
             (attr->value[2] == 19) &&             /* Encapsulation type (VPLS) */
             (attr->value[3] == 0x04) &&           /* Control flags             */
             (read_u16(attr->value + 4) == 1500);  /* MTU                       */

    bgp_path_attr_free(attr);
    test_result(passed, "VPLS Layer2 Info ext community");
}

/*
 * Test 5: VPLS ADD-PATH
 */
void test_vpls_add_path() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    vpls_nlri_list_t     *nlri = vpls_nlri_create_path_id(rd, 1, 0, 8, 1000, 555);
    vpls_nlri_list_t     *tail;
    bgp_path_attr_t      *attrs = make_test_attrs();
    bgp_next_hop_t        next_hop = make_ipv4_next_hop("10.0.0.1");
    bgp_update_result_t  *result;
    const uint8_t        *value = NULL;
    uint16_t              length = 0;
    int                   offset = 0;
    int                   passed;

    TEST_FIND_TAIL(tail, nlri);
    vpls_nlri_list_t *second = vpls_nlri_create_path_id(rd, 2, 0, 8, 2000, 666);
    vpls_nlri_append(&nlri, &tail, second);

    result = bgp_generate_update_vpls(nlri, attrs, NULL, 0, &next_hop);
    assert(result != NULL);

    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI, &value, &length) &&
             mp_reach_nlri_offset(value, length, &offset) &&
             (read_u32(value + offset) == 555);

    bgp_update_result_free(result);
    vpls_nlri_list_free(nlri);
    bgp_path_attr_list_free(attrs);
    test_result(passed, "VPLS ADD-PATH");
}

/*
 * Test 6: VPLS withdrawal
 */
void test_vpls_withdrawal() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    vpls_nlri_list_t     *withdrawn = vpls_nlri_create(rd, 1, 0, 8, 1000);
    bgp_update_result_t  *result;
    int                   passed;

    result = bgp_generate_update_vpls(NULL, NULL, withdrawn, 0, NULL);
    assert(result != NULL);

    passed = (result->num_messages == 1) &&
             has_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_UNREACH_NLRI);

    bgp_update_result_free(result);
    vpls_nlri_list_free(withdrawn);
    test_result(passed, "VPLS withdrawal");
}

/*
 * Test 7: VPLS fixed NLRI size
 */
void test_vpls_nlri_fixed_size() {
    route_distinguisher_t rd = rd_create_type1(0xC0A80101, 300);
    vpls_nlri_list_t     *nlri = vpls_nlri_create(rd, 100, 50, 32, 99999);
    uint8_t               buffer[64];
    int                   len;

    assert(nlri != NULL);
    len = bgp_encode_vpls_prefix(buffer, &nlri->prefix);

    // Always 19 bytes regardless of field values
    test_result(len == 19, "VPLS fixed NLRI size (19 bytes)");
    test_result(test_wire_rd_is(buffer + 2, 1, 0xC0A80101, 300), "VPLS type 1 RD 192.168.1.1:300");
    vpls_nlri_list_free(nlri);
}

/*
 * Test 8: VPLS ADD-PATH withdrawal
 */
void test_vpls_add_path_withdrawal() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    vpls_nlri_list_t     *withdrawn = vpls_nlri_create_path_id(rd, 1, 0, 8, 1000, 333);
    bgp_update_result_t  *result;
    const uint8_t        *value = NULL;
    uint16_t              length = 0;
    int                   offset = 0;
    int                   passed;

    result = bgp_generate_update_vpls(NULL, NULL, withdrawn, 0, NULL);
    assert(result != NULL);

    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_UNREACH_NLRI, &value, &length) &&
             mp_unreach_nlri_offset(value, length, &offset) &&
             (read_u32(value + offset) == 333);

    bgp_update_result_free(result);
    vpls_nlri_list_free(withdrawn);
    test_result(passed, "VPLS ADD-PATH withdrawal");
}

/*
 * VPLS also keeps the stricter 4/16-byte next-hop interpretation from
 * RFC 4761. A later fuzz feature can relax this condition
 * intentionally, but the default encoder path should stay conformant.
 */
void test_vpls_reject_ipv6_link_local_next_hop() {
    route_distinguisher_t rd = rd_create_type0(65000, 1);
    vpls_nlri_list_t     *nlri = vpls_nlri_create(rd, 1, 0, 8, 1000);
    bgp_path_attr_t      *attrs = make_test_attrs();
    bgp_next_hop_t        next_hop = make_ipv6_next_hop_with_link_local("2001:db8::1", "fe80::1");
    bgp_update_result_t  *result;

    result = bgp_generate_update_vpls(nlri, attrs, NULL, 0, &next_hop);

    test_result(result == NULL, "VPLS rejects IPv6 global+link-local next-hop");

    vpls_nlri_list_free(nlri);
    bgp_path_attr_list_free(attrs);
}

static void test_vpls_invalid_payload(void) {
    vpls_nlri_list_t *nlri = vpls_nlri_create_path_id(rd_create_type0(65000, 1), 1, 0, 8, 1000, 7);
    uint8_t           buffer[32];
    nlri->prefix.length = 16;
    test_result(bgp_encode_vpls_prefix(buffer, &nlri->prefix) < 0, "VPLS rejects inconsistent NLRI length");
    bgp_update_result_t *result = bgp_generate_update_vpls(NULL, NULL, nlri, 0, NULL);
    test_result(result == NULL, "VPLS propagates encoder rejection with ADD-PATH");
    bgp_update_result_free(result);
    nlri->prefix.length = 17;
    nlri->prefix.label_base.label = 0x100000;
    test_result(bgp_encode_vpls_prefix(buffer, &nlri->prefix) < 0, "VPLS rejects overflowing label base");
    vpls_nlri_list_free(nlri);
}

int main() {
    printf("============================================\n");
    printf("BGP VPLS UPDATE Generation Tests\n");
    printf("============================================\n\n");

    test_vpls_nlri_creation();
    test_vpls_prefix_encoding();
    test_vpls_update_generation();
    test_vpls_l2info_ext_comm();
    test_vpls_add_path();
    test_vpls_withdrawal();
    test_vpls_nlri_fixed_size();
    test_vpls_add_path_withdrawal();
    test_vpls_reject_ipv6_link_local_next_hop();
    test_vpls_invalid_payload();

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
