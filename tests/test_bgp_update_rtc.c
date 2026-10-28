// Unit tests for BGP RTC UPDATE message generation

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

// RTC Tests

/*
 * Test 1: RTC NLRI creation
 */
void test_rtc_nlri_creation() {
    uint8_t rt[] = {0x00, 0x02, 0xFD, 0xE9, 0x00, 0x00, 0x00, 0x64};
    rtc_nlri_list_t *list = rtc_nlri_create(65001, rt, 8);
    rtc_nlri_list_t *tail;

    assert(list != NULL);
    TEST_FIND_TAIL(tail, list);

    uint8_t rt2[] = {0x00, 0x02, 0xFD, 0xEA, 0x00, 0x00, 0x00, 0xC8};
    rtc_nlri_list_t *second = rtc_nlri_create(65002, rt2, 8);
    rtc_nlri_append(&list, &tail, second);

    test_result(rtc_nlri_count(list) == 2, "RTC NLRI creation");
    rtc_nlri_list_free(list);
}

/*
 * Test 2: RTC prefix encoding
 */
void test_rtc_prefix_encoding() {
    uint8_t rt[] = {0x00, 0x02, 0xFD, 0xE9, 0x00, 0x00, 0x00, 0x64};
    rtc_nlri_list_t *nlri = rtc_nlri_create(65001, rt, 8);
    uint8_t          buffer[64];
    int              len;

    assert(nlri != NULL);
    len = bgp_encode_rtc_prefix(buffer, &nlri->prefix);

    // prefix_len(1) + origin_as(4) + RT(8) = 13
    test_result((len == 13) &&
                (buffer[0] == 96) &&   /* 32 + 64 = 96 bits */
                (read_u32(buffer + 1) == 65001),
                "RTC prefix encoding");
    rtc_nlri_list_free(nlri);
}

/*
 * Test 3: RTC default route (zero length)
 */
void test_rtc_default_route() {
    rtc_nlri_list_t *nlri = rtc_nlri_create_default();
    uint8_t          buffer[64];
    int              len;

    assert(nlri != NULL);
    len = bgp_encode_rtc_prefix(buffer, &nlri->prefix);

    // Default route: just prefix_len byte (value 0)
    test_result((len == 1) && (buffer[0] == 0), "RTC default route (zero-length)");
    rtc_nlri_list_free(nlri);
}

/*
 * Test 4: RTC full UPDATE generation
 */
void test_rtc_update_generation() {
    uint8_t rt[] = {0x00, 0x02, 0xFD, 0xE9, 0x00, 0x00, 0x00, 0x64};
    rtc_nlri_list_t     *nlri = rtc_nlri_create(65001, rt, 8);
    bgp_path_attr_t     *attrs = make_test_attrs();
    bgp_next_hop_t       next_hop = make_ipv4_next_hop("10.0.0.1");
    bgp_update_result_t *result;
    const uint8_t       *value = NULL;
    uint16_t             length = 0;
    int                  passed;

    result = bgp_generate_update_rtc(nlri, attrs, NULL, 0, &next_hop);
    assert(result != NULL);

    // Verify MP_REACH_NLRI with AFI=1, SAFI=132, nh_len=4
    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI, &value, &length) &&
             (read_u16(value) == AFI_IPV4) &&
             (value[2] == SAFI_RTC) &&
             (value[3] == 4);  /* IPv4 next-hop = 4 bytes */

    bgp_update_result_free(result);
    rtc_nlri_list_free(nlri);
    bgp_path_attr_list_free(attrs);
    test_result(passed, "RTC UPDATE generation");
}

/*
 * Test 5: RTC ADD-PATH
 */
void test_rtc_add_path() {
    uint8_t rt[] = {0x00, 0x02, 0xFD, 0xE9, 0x00, 0x00, 0x00, 0x64};
    rtc_nlri_list_t     *nlri = rtc_nlri_create_path_id(65001, rt, 8, 42);
    rtc_nlri_list_t     *tail;
    bgp_path_attr_t     *attrs = make_test_attrs();
    bgp_next_hop_t       next_hop = make_ipv4_next_hop("10.0.0.1");
    bgp_update_result_t *result;
    const uint8_t       *value = NULL;
    uint16_t             length = 0;
    int                  offset = 0;
    int                  passed;

    TEST_FIND_TAIL(tail, nlri);
    uint8_t rt2[] = {0x00, 0x02, 0xFD, 0xEA, 0x00, 0x00, 0x00, 0xC8};
    rtc_nlri_list_t *second = rtc_nlri_create_path_id(65002, rt2, 8, 99);
    rtc_nlri_append(&nlri, &tail, second);

    result = bgp_generate_update_rtc(nlri, attrs, NULL, 0, &next_hop);
    assert(result != NULL);

    // Verify path IDs appear before NLRI
    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI, &value, &length) &&
             mp_reach_nlri_offset(value, length, &offset) &&
             (read_u32(value + offset) == 42);

    bgp_update_result_free(result);
    rtc_nlri_list_free(nlri);
    bgp_path_attr_list_free(attrs);
    test_result(passed, "RTC ADD-PATH");
}

/*
 * Test 6: RTC withdrawal
 */
void test_rtc_withdrawal() {
    uint8_t rt[] = {0x00, 0x02, 0xFD, 0xE9, 0x00, 0x00, 0x00, 0x64};
    rtc_nlri_list_t     *withdrawn = rtc_nlri_create(65001, rt, 8);
    bgp_update_result_t *result;
    int                  passed;

    result = bgp_generate_update_rtc(NULL, NULL, withdrawn, 0, NULL);
    assert(result != NULL);

    passed = (result->num_messages == 1) &&
             has_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_UNREACH_NLRI);

    bgp_update_result_free(result);
    rtc_nlri_list_free(withdrawn);
    test_result(passed, "RTC withdrawal");
}

/*
 * Test 7: RTC with IPv6 next hop
 */
void test_rtc_ipv6_next_hop() {
    uint8_t rt[] = {0x00, 0x02, 0xFD, 0xE9, 0x00, 0x00, 0x00, 0x64};
    rtc_nlri_list_t     *nlri = rtc_nlri_create(65001, rt, 8);
    bgp_path_attr_t     *attrs = make_test_attrs();
    bgp_next_hop_t       next_hop = make_ipv6_next_hop("2001:db8::1");
    bgp_update_result_t *result;
    const uint8_t       *value = NULL;
    uint16_t             length = 0;
    int                  passed;

    result = bgp_generate_update_rtc(nlri, attrs, NULL, 0, &next_hop);
    assert(result != NULL);

    // IPv6 next-hop = 16 bytes
    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI, &value, &length) &&
             (value[3] == 16);

    bgp_update_result_free(result);
    rtc_nlri_list_free(nlri);
    bgp_path_attr_list_free(attrs);
    test_result(passed, "RTC IPv6 next-hop");
}

/*
 * Test 8: RTC with partial RT (less than 8 bytes)
 */
void test_rtc_partial_rt() {
    // 4-byte RT (e.g., just the type and global admin)
    uint8_t rt[] = {0x00, 0x02, 0xFD, 0xE9};
    rtc_nlri_list_t *nlri = rtc_nlri_create(65001, rt, 4);
    uint8_t          buffer[64];
    int              len;

    assert(nlri != NULL);
    len = bgp_encode_rtc_prefix(buffer, &nlri->prefix);

    // prefix_len = 32 + 32 = 64 bits, wire = 1 + 4 + 4 = 9
    test_result((len == 9) && (buffer[0] == 64), "RTC partial RT (4 bytes)");
    rtc_nlri_list_free(nlri);
}

/*
 * Test 9: RTC ADD-PATH withdrawal
 */
void test_rtc_add_path_withdrawal() {
    uint8_t rt[] = {0x00, 0x02, 0xFD, 0xE9, 0x00, 0x00, 0x00, 0x64};
    rtc_nlri_list_t     *withdrawn = rtc_nlri_create_path_id(65001, rt, 8, 42);
    bgp_update_result_t *result;
    const uint8_t       *value = NULL;
    uint16_t             length = 0;
    int                  offset = 0;
    int                  passed;

    result = bgp_generate_update_rtc(NULL, NULL, withdrawn, 0, NULL);
    assert(result != NULL);

    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_UNREACH_NLRI, &value, &length) &&
             mp_unreach_nlri_offset(value, length, &offset) &&
             (read_u32(value + offset) == 42);

    bgp_update_result_free(result);
    rtc_nlri_list_free(withdrawn);
    test_result(passed, "RTC ADD-PATH withdrawal");
}

/*
 * RTC keeps the RFC 4684 next-hop restriction in strict mode even
 * though the shared helper can encode a 32-byte IPv6 global+link-local
 * next hop for other families. That check is a good future fuzz-mode
 * escape hatch, so keep it covered explicitly.
 */
void test_rtc_reject_ipv6_link_local_next_hop() {
    uint8_t rt[] = {0x00, 0x02, 0xFD, 0xE9, 0x00, 0x00, 0x00, 0x64};
    rtc_nlri_list_t     *nlri = rtc_nlri_create(65001, rt, 8);
    bgp_path_attr_t     *attrs = make_test_attrs();
    bgp_next_hop_t       next_hop = make_ipv6_next_hop_with_link_local("2001:db8::1", "fe80::1");
    bgp_update_result_t *result;

    result = bgp_generate_update_rtc(nlri, attrs, NULL, 0, &next_hop);

    test_result(result == NULL, "RTC rejects IPv6 global+link-local next-hop");

    rtc_nlri_list_free(nlri);
    bgp_path_attr_list_free(attrs);
}

static void test_rtc_length_boundaries(void) {
    rtc_prefix_t prefix = {.prefix_len = 33, .origin_as = htonl(65000), .route_target = {0xFF}};
    uint8_t      buffer[32];
    memset(buffer, 0xAA, sizeof(buffer));
    int len = bgp_encode_rtc_prefix(buffer, &prefix);
    test_result(len == 6 && buffer[5] == 0x80 && buffer[6] == 0xAA,
                "RTC masks partial RT bits without writing past the prefix");
    prefix.prefix_len = 97;
    test_result(bgp_encode_rtc_prefix(buffer, &prefix) < 0, "RTC rejects prefix lengths above 96");
    int short_prefixes_rejected = 1, short_withdrawals_rejected = 1;
    for (uint8_t bits = 1; bits < 32; bits++) {
        prefix.prefix_len = bits;
        memset(buffer, 0xAA, sizeof(buffer));
        if (bgp_encode_rtc_prefix(buffer, &prefix) >= 0 || buffer[0] != 0xAA) short_prefixes_rejected = 0;
        rtc_nlri_list_t      invalid = {.prefix = prefix, .add_path = 1, .path_id = 7};
        bgp_update_result_t *rejected = bgp_generate_update_rtc(NULL, NULL, &invalid, 4096, NULL);
        if (rejected) short_withdrawals_rejected = 0;
        bgp_update_result_free(rejected);
    }
    test_result(short_prefixes_rejected, "RTC rejects lengths 1-31 before writing; origin AS cannot be a prefix");
    test_result(short_withdrawals_rejected, "RTC rejects lengths 1-31 through ADD-PATH withdrawal generation");
    rtc_nlri_list_t *bad = rtc_nlri_create(65000, NULL, 8);
    test_result(bad == NULL, "RTC rejects a missing RT payload");
    rtc_nlri_list_free(bad);

    // The shared MP budget reserves one header octet; RT worst-case sizing must not reject this short route.
    rtc_nlri_list_t     *short_route = rtc_nlri_create(65000, NULL, 0);
    bgp_update_result_t *result = bgp_generate_update_rtc(NULL, NULL, short_route, 35, NULL);
    test_result(result && result->num_messages == 1 && result->message_lens[0] == 34,
                "RTC packs short withdrawals with their exact wire length");
    bgp_update_result_free(result);
    rtc_nlri_list_free(short_route);
}

int main() {
    printf("============================================\n");
    printf("BGP RTC UPDATE Generation Tests\n");
    printf("============================================\n\n");

    test_rtc_nlri_creation();
    test_rtc_prefix_encoding();
    test_rtc_default_route();
    test_rtc_update_generation();
    test_rtc_add_path();
    test_rtc_withdrawal();
    test_rtc_ipv6_next_hop();
    test_rtc_partial_rt();
    test_rtc_add_path_withdrawal();
    test_rtc_reject_ipv6_link_local_next_hop();
    test_rtc_length_boundaries();

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
