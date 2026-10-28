// Unit tests for BGP UPDATE message generation

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
#include "test_helpers.h"

#define TEST_FIND_TAIL(tail, head)       \
    do {                                 \
        (tail) = (head);                 \
        while ((tail) && (tail)->next) { \
            (tail) = (tail)->next;       \
        }                                \
    } while (0)

static int find_attr(const uint8_t *msg, uint16_t msg_len, uint8_t type_code,
                     const uint8_t **value_out, uint16_t *length_out, uint8_t *flags_out) {
    return test_wire_find_attr(msg, msg_len, type_code, value_out, length_out, flags_out);
}

static int validate_ipv4_mapped_ipv6_next_hop(const uint8_t *data, const char *expected_ipv4) {
    struct in_addr addr;

    inet_pton(AF_INET, expected_ipv4, &addr);
    return memcmp(data, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF", 12) == 0 &&
           memcmp(data + 12, &addr, 4) == 0;
}

static int validate_ipv4_add_path_nlri(const uint8_t *data,
                                      uint16_t length,
                                      const uint32_t *expected_path_ids,
                                      const char *const *expected_prefixes,
                                      const uint8_t *expected_prefix_lens,
                                      int expected_count) {
    int i;
    int offset = 0;

    for (i = 0; i < expected_count; i++) {
        struct in_addr addr;
        int            prefix_bytes;

        if (offset + 5 > length) {
            return 0;
        }
        if (read_u32(data + offset) != expected_path_ids[i]) {
            return 0;
        }
        offset += 4;

        if (data[offset++] != expected_prefix_lens[i]) {
            return 0;
        }

        prefix_bytes = (expected_prefix_lens[i] + 7) / 8;
        if (offset + prefix_bytes > length) {
            return 0;
        }

        inet_pton(AF_INET, expected_prefixes[i], &addr);
        if (memcmp(data + offset, &addr, (size_t)prefix_bytes) != 0) {
            return 0;
        }

        offset += prefix_bytes;
    }

    return offset == length;
}

static int validate_ipv6_add_path_nlri(const uint8_t *data,
                                      uint16_t length,
                                      const uint32_t *expected_path_ids,
                                      const char *const *expected_prefixes,
                                      const uint8_t *expected_prefix_lens,
                                      int expected_count) {
    int i;
    int offset = 0;

    for (i = 0; i < expected_count; i++) {
        uint8_t prefix[16];
        int     prefix_bytes;

        if (offset + 5 > length) {
            return 0;
        }
        if (read_u32(data + offset) != expected_path_ids[i]) {
            return 0;
        }
        offset += 4;

        if (data[offset++] != expected_prefix_lens[i]) {
            return 0;
        }

        prefix_bytes = (expected_prefix_lens[i] + 7) / 8;
        if (offset + prefix_bytes > length) {
            return 0;
        }

        inet_pton(AF_INET6, expected_prefixes[i], prefix);
        if (memcmp(data + offset, prefix, (size_t)prefix_bytes) != 0) {
            return 0;
        }

        offset += prefix_bytes;
    }

    return offset == length;
}

static int validate_labeled_ipv4_nlri(const uint8_t *data,
                                      uint16_t length,
                                      const uint32_t *expected_path_ids,
                                      const uint32_t *expected_labels,
                                      const char *const *expected_prefixes,
                                      const uint8_t *expected_prefix_lens,
                                      int expected_count,
                                      int withdraw_mode) {
    int offset = 0;

    for (int i = 0; i < expected_count; i++) {
        struct in_addr addr;
        int            prefix_bytes;
        uint8_t        expected_nlri_len = (uint8_t)(24 + expected_prefix_lens[i]);

        if (expected_path_ids) {
            if (offset + 4 > length || read_u32(data + offset) != expected_path_ids[i]) {
                return 0;
            }
            offset += 4;
        }

        if (offset + 4 > length || data[offset++] != expected_nlri_len) {
            return 0;
        }

        if (withdraw_mode) {
            if (data[offset] != 0x80 || data[offset + 1] != 0x00 || data[offset + 2] != 0x00) {
                return 0;
            }
        } else {
            if (decode_wire_label(data + offset) != expected_labels[i] ||
                (data[offset + 2] & 0x01) != 1) {
                return 0;
            }
        }
        offset += 3;

        prefix_bytes = (expected_prefix_lens[i] + 7) / 8;
        if (offset + prefix_bytes > length) {
            return 0;
        }

        inet_pton(AF_INET, expected_prefixes[i], &addr);
        if (memcmp(data + offset, &addr, (size_t)prefix_bytes) != 0) {
            return 0;
        }
        offset += prefix_bytes;
    }

    return offset == length;
}

static int validate_labeled_ipv6_nlri(const uint8_t *data,
                                      uint16_t length,
                                      const uint32_t *expected_path_ids,
                                      const uint32_t *expected_labels,
                                      const char *const *expected_prefixes,
                                      const uint8_t *expected_prefix_lens,
                                      int expected_count,
                                      int withdraw_mode) {
    int offset = 0;

    for (int i = 0; i < expected_count; i++) {
        uint8_t prefix[16];
        int     prefix_bytes;
        uint8_t expected_nlri_len = (uint8_t)(24 + expected_prefix_lens[i]);

        if (expected_path_ids) {
            if (offset + 4 > length || read_u32(data + offset) != expected_path_ids[i]) {
                return 0;
            }
            offset += 4;
        }

        if (offset + 4 > length || data[offset++] != expected_nlri_len) {
            return 0;
        }

        if (withdraw_mode) {
            if (data[offset] != 0x80 || data[offset + 1] != 0x00 || data[offset + 2] != 0x00) {
                return 0;
            }
        } else {
            if (decode_wire_label(data + offset) != expected_labels[i] ||
                (data[offset + 2] & 0x01) != 1) {
                return 0;
            }
        }
        offset += 3;

        prefix_bytes = (expected_prefix_lens[i] + 7) / 8;
        if (offset + prefix_bytes > length) {
            return 0;
        }

        inet_pton(AF_INET6, expected_prefixes[i], prefix);
        if (memcmp(data + offset, prefix, (size_t)prefix_bytes) != 0) {
            return 0;
        }
        offset += prefix_bytes;
    }

    return offset == length;
}

static int extract_mp_reach_afi(const uint8_t *msg,
                                uint16_t msg_len,
                                uint16_t expected_afi,
                                uint8_t expected_safi,
                                const uint8_t **value_out,
                                uint16_t *length_out,
                                const uint8_t **nlri_out,
                                uint16_t *nlri_len_out) {
    const uint8_t *value = NULL;
    uint16_t       length = 0;
    uint16_t       afi;
    uint8_t        nh_len;
    int            base_len;

    if (!find_attr(msg,
                   msg_len,
                   BGP_ATTR_MP_REACH_NLRI,
                   &value,
                   &length,
                   NULL) ||
        length < 5) {
        return 0;
    }

    afi = read_u16(value);
    if (afi != expected_afi || value[2] != expected_safi) {
        return 0;
    }

    nh_len = value[3];
    base_len = 2 + 1 + 1 + nh_len + 1;
    if ((uint16_t)base_len > length || value[4 + nh_len] != 0) {
        return 0;
    }

    if (value_out) {
        *value_out = value;
    }
    if (length_out) {
        *length_out = length;
    }
    if (nlri_out) {
        *nlri_out = value + base_len;
    }
    if (nlri_len_out) {
        *nlri_len_out = (uint16_t)(length - base_len);
    }

    return 1;
}

/*
 * Test 1: IPv4 NLRI creation and counting
 */
void test_ipv4_nlri_creation() {
    ipv4_nlri_list_t *list = ipv4_nlri_create("192.168.1.0", 24);
    ipv4_nlri_list_t *tail;
    assert(list != NULL);

    TEST_FIND_TAIL(tail, list);
    ipv4_nlri_add_tail(&list, &tail, "10.0.0.0", 8);
    ipv4_nlri_add_tail(&list, &tail, "172.16.0.0", 12);

    test_result(ipv4_nlri_count(list) == 3, "IPv4 NLRI creation");
    ipv4_nlri_list_free(list);
}

/*
 * Test 2: IPv6 NLRI creation and counting
 */
void test_ipv6_nlri_creation() {
    ipv6_nlri_list_t *list = ipv6_nlri_create("2001:db8::", 32);
    ipv6_nlri_list_t *tail;
    assert(list != NULL);

    TEST_FIND_TAIL(tail, list);
    ipv6_nlri_add_tail(&list, &tail, "2001:db8:1::", 48);
    ipv6_nlri_add_tail(&list, &tail, "2001:db8:2::", 48);

    test_result(ipv6_nlri_count(list) == 3, "IPv6 NLRI creation");
    ipv6_nlri_list_free(list);
}

/*
 * Test 3: ORIGIN attribute creation
 */
void test_origin_attribute() {
    bgp_path_attr_t *attr = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    int passed = (attr != NULL) &&
                 (attr->type_code == BGP_ATTR_ORIGIN) &&
                 (attr->length == 1) &&
                 (attr->value[0] == BGP_ORIGIN_IGP) &&
                 (attr->flags == BGP_ATTR_FLAG_TRANSITIVE);

    bgp_path_attr_free(attr);
    test_result(passed, "ORIGIN attribute");
}

/*
 * Test 4: AS_PATH attribute creation
 */
void test_as_path_attribute() {
    uint32_t asns[] = {100, 200, 300};
    as_path_segment_t segment = {
        .type = BGP_AS_SEQUENCE,
        .length = 3,
        .as_numbers = asns
    };
    bgp_path_attr_t *attr = bgp_attr_create_as_path(&segment, 1);
    int passed = (attr != NULL) &&
                 (attr->type_code == BGP_ATTR_AS_PATH) &&
                 (attr->flags == BGP_ATTR_FLAG_TRANSITIVE) &&
                 (attr->length == 14);

    bgp_path_attr_free(attr);
    test_result(passed, "AS_PATH attribute");
}

/*
 * Test 5: AS_PATH transition encoding
 */
void test_as_path_transition_attribute() {
    uint32_t asns[] = {65001, 4200000000UL};
    as_path_segment_t segment = {BGP_AS_SEQUENCE, 2, asns};
    bgp_path_attr_t  *as4_path = NULL;
    bgp_path_attr_t  *as_path = bgp_attr_create_as_path_transition(&segment, 1, &as4_path);
    int passed = (as_path != NULL) &&
                 (as4_path != NULL) &&
                 (as_path->length == 6) &&
                 (as4_path->type_code == BGP_ATTR_AS4_PATH) &&
                 (as4_path->length == 10) &&
                 (as_path->value[2] == 0xFD) && (as_path->value[3] == 0xE9) &&
                 (as_path->value[4] == 0x5B) && (as_path->value[5] == 0xA0);

    bgp_path_attr_free(as_path);
    bgp_path_attr_free(as4_path);
    test_result(passed, "AS_PATH transition");
}

/*
 * Test 6: NEXT_HOP attribute creation
 */
void test_next_hop_attribute() {
    bgp_next_hop_t   next_hop = make_ipv4_next_hop("192.168.1.1");
    bgp_path_attr_t *attr = bgp_attr_create_next_hop(&next_hop);
    int passed = (attr != NULL) &&
                 (attr->type_code == BGP_ATTR_NEXT_HOP) &&
                 (attr->length == 4) &&
                 (attr->flags == BGP_ATTR_FLAG_TRANSITIVE);

    bgp_path_attr_free(attr);
    test_result(passed, "NEXT_HOP attribute");
}

/*
 * Test 7: MED attribute creation
 */
void test_med_attribute() {
    bgp_path_attr_t *attr = bgp_attr_create_med(100);
    int passed = (attr != NULL) &&
                 (attr->type_code == BGP_ATTR_MULTI_EXIT_DISC) &&
                 (attr->length == 4) &&
                 (attr->flags == BGP_ATTR_FLAG_OPTIONAL);

    bgp_path_attr_free(attr);
    test_result(passed, "MED attribute");
}

/*
 * Test 8: LOCAL_PREF attribute creation
 */
void test_local_pref_attribute() {
    bgp_path_attr_t *attr = bgp_attr_create_local_pref(200);
    int passed = (attr != NULL) &&
                 (attr->type_code == BGP_ATTR_LOCAL_PREF) &&
                 (attr->length == 4) &&
                 (attr->flags == BGP_ATTR_FLAG_TRANSITIVE);

    bgp_path_attr_free(attr);
    test_result(passed, "LOCAL_PREF attribute");
}

/*
 * Test 9: MP_REACH_NLRI attribute for IPv6
 */
void test_mp_reach_nlri_ipv6() {
    const uint8_t    *value = NULL;
    uint16_t          length = 0;
    uint8_t           flags = 0;
    bgp_next_hop_t    next_hop = make_ipv6_next_hop_with_link_local("2001:db8::1", "fe80::1");
    ipv6_nlri_list_t *nlri = ipv6_nlri_create("2001:db8:100::", 48);
    ipv6_nlri_list_t *nlri_tail;
    bgp_path_attr_t  *attr;
    uint8_t           buffer[1024];

    TEST_FIND_TAIL(nlri_tail, nlri);
    ipv6_nlri_add_tail(&nlri, &nlri_tail, "2001:db8:200::", 48);
    attr = bgp_attr_create_mp_reach_ipv6(&next_hop, nlri);
    assert(attr != NULL);

    bgp_serialize_path_attributes(buffer, attr);

    flags = buffer[0];
    value = buffer + ((flags & BGP_ATTR_FLAG_EXTENDED_LEN) ? 4 : 3);
    length = (flags & BGP_ATTR_FLAG_EXTENDED_LEN) ? read_u16(buffer + 2) : buffer[2];

    test_result(attr->type_code == BGP_ATTR_MP_REACH_NLRI &&
                length > 0 &&
                (flags & BGP_ATTR_FLAG_OPTIONAL) &&
                value[0] == 0x00 && value[1] == 0x02 &&
                value[2] == SAFI_UNICAST &&
                value[3] == 32,
                "MP_REACH_NLRI attribute");

    bgp_path_attr_free(attr);
    ipv6_nlri_list_free(nlri);
}

/*
 * Test 10: MP_UNREACH_NLRI attribute for IPv6
 */
void test_mp_unreach_nlri_ipv6() {
    ipv6_nlri_list_t *withdrawn = ipv6_nlri_create("2001:db8:300::", 48);
    bgp_path_attr_t  *attr = bgp_attr_create_mp_unreach_ipv6(withdrawn);
    uint8_t           buffer[256];
    int               passed;

    assert(attr != NULL);
    bgp_serialize_path_attributes(buffer, attr);

    passed = (attr->type_code == BGP_ATTR_MP_UNREACH_NLRI) &&
             (buffer[0] == BGP_ATTR_FLAG_OPTIONAL) &&
             (buffer[1] == BGP_ATTR_MP_UNREACH_NLRI) &&
             (buffer[3] == 0x00) && (buffer[4] == 0x02) &&
             (buffer[5] == SAFI_UNICAST);

    bgp_path_attr_free(attr);
    ipv6_nlri_list_free(withdrawn);
    test_result(passed, "MP_UNREACH_NLRI attribute");
}

/*
 * Test 11: Extended-length path attribute serialization
 */
void test_extended_length_serialization() {
    bgp_next_hop_t    next_hop = make_ipv6_next_hop("2001:db8::1");
    ipv6_nlri_list_t *nlri = NULL;
    ipv6_nlri_list_t *nlri_tail = NULL;
    bgp_path_attr_t  *attr;
    uint8_t           buffer[2048];
    int               passed;
    int               i;

    for (i = 0; i < 40; i++) {
        char prefix[64];
        snprintf(prefix, sizeof(prefix), "2001:db8:%x::", i);
        ipv6_nlri_add_tail(&nlri, &nlri_tail, prefix, 64);
    }

    attr = bgp_attr_create_mp_reach_ipv6(&next_hop, nlri);
    assert(attr != NULL);
    bgp_serialize_path_attributes(buffer, attr);

    passed = (buffer[0] & BGP_ATTR_FLAG_EXTENDED_LEN) &&
             (read_u16(buffer + 2) == attr->length);

    bgp_path_attr_free(attr);
    ipv6_nlri_list_free(nlri);
    test_result(passed, "Extended-length serialization");
}

/*
 * Test 12: Simple IPv4 UPDATE generation
 */
void test_simple_ipv4_update() {
    ipv4_nlri_list_t *nlri = ipv4_nlri_create("192.168.1.0", 24);
    ipv4_nlri_list_t *nlri_tail;
    bgp_path_attr_t  *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_next_hop_t       next_hop = make_ipv4_next_hop("10.0.0.1");
    bgp_path_attr_t     *next_hop_attr;
    bgp_update_result_t *result;
    int                  passed;

    TEST_FIND_TAIL(nlri_tail, nlri);
    ipv4_nlri_add_tail(&nlri, &nlri_tail, "192.168.2.0", 24);
    next_hop_attr = bgp_attr_create_next_hop(&next_hop);

    origin->next = as_path;
    as_path->next = next_hop_attr;

    result = bgp_generate_update_ipv4(nlri, origin, NULL, 0);
    assert(result != NULL);

    passed = (result->num_messages == 1) &&
             (((bgp_header_t *)result->messages[0])->type == BGP_MSG_UPDATE) &&
             (test_wire_withdrawn_len(result->messages[0], result->message_lens[0]) == 0) &&
             (test_wire_path_attr_len(result->messages[0], result->message_lens[0]) > 0);

    bgp_update_result_free(result);
    ipv4_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    test_result(passed, "Simple IPv4 UPDATE");
}

/*
 * Test 13: IPv4 UPDATE with withdrawn routes
 */
void test_ipv4_update_with_withdrawn() {
    ipv4_nlri_list_t *nlri = ipv4_nlri_create("192.168.1.0", 24);
    ipv4_nlri_list_t *withdrawn = ipv4_nlri_create("10.0.0.0", 8);
    bgp_path_attr_t  *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_next_hop_t       next_hop = make_ipv4_next_hop("10.0.0.1");
    bgp_path_attr_t     *next_hop_attr;
    bgp_update_result_t *result;
    int                  passed;

    next_hop_attr = bgp_attr_create_next_hop(&next_hop);

    origin->next = as_path;
    as_path->next = next_hop_attr;

    result = bgp_generate_update_ipv4(nlri, origin, withdrawn, 0);
    assert(result != NULL);

    passed = (result->num_messages == 2) &&
             (test_wire_withdrawn_len(result->messages[0], result->message_lens[0]) > 0) &&
             (test_wire_path_attr_len(result->messages[0], result->message_lens[0]) == 0) &&
             (test_wire_withdrawn_len(result->messages[1], result->message_lens[1]) == 0) &&
             (test_wire_path_attr_len(result->messages[1], result->message_lens[1]) > 0);

    bgp_update_result_free(result);
    ipv4_nlri_list_free(nlri);
    ipv4_nlri_list_free(withdrawn);
    bgp_path_attr_list_free(origin);
    test_result(passed, "IPv4 UPDATE with withdrawn");
}

/*
 * Test 14: IPv4 UPDATE message splitting repeats path attributes
 */
void test_ipv4_update_splitting() {
    ipv4_nlri_list_t *nlri = NULL;
    ipv4_nlri_list_t *nlri_tail = NULL;
    bgp_path_attr_t  *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_next_hop_t       next_hop = make_ipv4_next_hop("10.0.0.1");
    bgp_path_attr_t     *next_hop_attr;
    bgp_update_result_t *result;
    int                  passed = 1;
    int                  i;

    for (i = 0; i < 100; i++) {
        char prefix[32];
        snprintf(prefix, sizeof(prefix), "10.%d.0.0", i);
        ipv4_nlri_add_tail(&nlri, &nlri_tail, prefix, 16);
    }

    next_hop_attr = bgp_attr_create_next_hop(&next_hop);

    origin->next = as_path;
    as_path->next = next_hop_attr;

    result = bgp_generate_update_ipv4(nlri, origin, NULL, 200);
    assert(result != NULL);

    passed = (result->num_messages > 1);
    for (i = 0; i < result->num_messages; i++) {
        if (test_wire_path_attr_len(result->messages[i], result->message_lens[i]) == 0) {
            passed = 0;
        }
    }

    bgp_update_result_free(result);
    ipv4_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    test_result(passed, "IPv4 UPDATE splitting");
}

/*
 * Test 15: Simple IPv6 UPDATE generation
 */
void test_simple_ipv6_update() {
    ipv6_nlri_list_t *nlri = ipv6_nlri_create("2001:db8:100::", 48);
    ipv6_nlri_list_t *nlri_tail;
    bgp_next_hop_t    next_hop = make_ipv6_next_hop("2001:db8::1");
    bgp_path_attr_t  *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_update_result_t *result;
    const uint8_t       *value = NULL;
    uint16_t             length = 0;
    int                  passed;

    TEST_FIND_TAIL(nlri_tail, nlri);
    ipv6_nlri_add_tail(&nlri, &nlri_tail, "2001:db8:200::", 48);
    origin->next = as_path;

    result = bgp_generate_update_ipv6(nlri, origin, NULL, 0, &next_hop);
    assert(result != NULL);

    passed = (result->num_messages == 1) &&
             find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI, &value, &length, NULL) &&
             (value[3] == 16) &&
             !find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_UNREACH_NLRI, NULL, NULL, NULL);

    bgp_update_result_free(result);
    ipv6_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    test_result(passed, "Simple IPv6 UPDATE");
}

void test_ipv6_update_ipv4_next_hop() {
    static const char *expected_next_hop = "192.0.2.9";
    ipv6_nlri_list_t *nlri = ipv6_nlri_create("2001:db8:100::", 48);
    ipv6_nlri_list_t *nlri_tail;
    bgp_next_hop_t    next_hop = make_ipv4_next_hop(expected_next_hop);
    bgp_path_attr_t  *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_update_result_t *result;
    const uint8_t       *value = NULL;
    uint16_t             length = 0;
    int                  passed;

    TEST_FIND_TAIL(nlri_tail, nlri);
    ipv6_nlri_add_tail(&nlri, &nlri_tail, "2001:db8:200::", 48);
    origin->next = as_path;

    result = bgp_generate_update_ipv6(nlri, origin, NULL, 0, &next_hop);
    assert(result != NULL);

    passed = (result->num_messages == 1) &&
             extract_mp_reach_afi(result->messages[0],
                                  result->message_lens[0],
                                  AFI_IPV6,
                                  SAFI_UNICAST,
                                  &value,
                                  &length,
                                  NULL,
                                  NULL) &&
             (value[3] == 16) &&
             validate_ipv4_mapped_ipv6_next_hop(value + 4, expected_next_hop);

    bgp_update_result_free(result);
    ipv6_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    test_result(passed, "IPv6 UPDATE with IPv4 next hop");
}

void test_simple_labeled_ipv4_update() {
    static const uint32_t expected_labels[] = {100, 200};
    static const char *expected_prefixes[] = {"192.0.2.0", "198.51.100.0"};
    static const uint8_t expected_prefix_lens[] = {24, 24};
    labeled_ipv4_nlri_t *nlri = labeled_ipv4_nlri_create("192.0.2.0", 24, 100);
    labeled_ipv4_nlri_t *nlri_tail;
    bgp_next_hop_t       next_hop = make_ipv4_next_hop("10.0.0.1");
    bgp_path_attr_t     *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_update_result_t *result;
    const uint8_t       *value = NULL;
    const uint8_t       *nlri_data = NULL;
    uint16_t             length = 0;
    uint16_t             nlri_len = 0;
    int                  passed;

    TEST_FIND_TAIL(nlri_tail, nlri);
    labeled_ipv4_nlri_add_tail(&nlri, &nlri_tail, "198.51.100.0", 24, 200);
    origin->next = as_path;

    result = bgp_generate_update_labeled_ipv4(nlri, origin, NULL, 0, &next_hop);
    assert(result != NULL);

    passed = (result->num_messages == 1) &&
             extract_mp_reach_afi(result->messages[0],
                                  result->message_lens[0],
                                  AFI_IPV4,
                                  SAFI_LABELED_UNICAST,
                                  &value,
                                  &length,
                                  &nlri_data,
                                  &nlri_len) &&
             (value[3] == 4) &&
             validate_labeled_ipv4_nlri(nlri_data,
                                        nlri_len,
                                        NULL,
                                        expected_labels,
                                        expected_prefixes,
                                        expected_prefix_lens,
                                        2,
                                        0);

    bgp_update_result_free(result);
    labeled_ipv4_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    test_result(passed, "Simple IPv4 labeled-unicast UPDATE");
}

void test_labeled_ipv4_rfc8950_update() {
    static const uint32_t expected_labels[] = {16000};
    static const char *expected_prefixes[] = {"203.0.113.0"};
    static const uint8_t expected_prefix_lens[] = {24};
    labeled_ipv4_nlri_t *nlri =
        labeled_ipv4_nlri_create("203.0.113.0", 24, 16000);
    bgp_next_hop_t   next_hop = make_ipv6_next_hop("2001:db8::1");
    bgp_path_attr_t *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_update_result_t *result;
    const uint8_t       *value = NULL;
    const uint8_t       *nlri_data = NULL;
    uint16_t             length = 0;
    uint16_t             nlri_len = 0;
    int                  passed;

    origin->next = as_path;
    result = bgp_generate_update_labeled_ipv4(nlri, origin, NULL, 0, &next_hop);
    assert(result != NULL);

    passed = (result->num_messages == 1) &&
             extract_mp_reach_afi(result->messages[0],
                                  result->message_lens[0],
                                  AFI_IPV4,
                                  SAFI_LABELED_UNICAST,
                                  &value,
                                  &length,
                                  &nlri_data,
                                  &nlri_len) &&
             (value[3] == 16) &&
             validate_labeled_ipv4_nlri(nlri_data,
                                        nlri_len,
                                        NULL,
                                        expected_labels,
                                        expected_prefixes,
                                        expected_prefix_lens,
                                        1,
                                        0);

    bgp_update_result_free(result);
    labeled_ipv4_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    test_result(passed, "IPv4 labeled-unicast RFC 8950 UPDATE");
}

void test_labeled_ipv4_add_path_update() {
    static const uint32_t expected_path_ids[] = {10, 11};
    static const uint32_t expected_labels[] = {300, 301};
    static const char *expected_prefixes[] = {"192.0.2.0", "192.0.3.0"};
    static const uint8_t expected_prefix_lens[] = {24, 24};
    labeled_ipv4_nlri_t *nlri =
        labeled_ipv4_nlri_create_path_id("192.0.2.0", 24, 300, 10);
    labeled_ipv4_nlri_t *nlri_tail;
    bgp_next_hop_t       next_hop = make_ipv4_next_hop("10.0.0.1");
    bgp_path_attr_t     *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_update_result_t *result;
    const uint8_t       *nlri_data = NULL;
    uint16_t             nlri_len = 0;
    int                  passed;

    TEST_FIND_TAIL(nlri_tail, nlri);
    labeled_ipv4_nlri_add_tail_path_id(&nlri, &nlri_tail, "192.0.3.0", 24, 301, 11);
    origin->next = as_path;
    result = bgp_generate_update_labeled_ipv4(nlri, origin, NULL, 0, &next_hop);
    assert(result != NULL);

    passed = extract_mp_reach_afi(result->messages[0],
                                  result->message_lens[0],
                                  AFI_IPV4,
                                  SAFI_LABELED_UNICAST,
                                  NULL,
                                  NULL,
                                  &nlri_data,
                                  &nlri_len) &&
             validate_labeled_ipv4_nlri(nlri_data,
                                        nlri_len,
                                        expected_path_ids,
                                        expected_labels,
                                        expected_prefixes,
                                        expected_prefix_lens,
                                        2,
                                        0);

    bgp_update_result_free(result);
    labeled_ipv4_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    test_result(passed, "IPv4 labeled-unicast ADD-PATH UPDATE");
}

void test_labeled_ipv4_withdrawn() {
    static const uint32_t expected_path_ids[] = {55};
    static const uint32_t expected_labels[] = {0};
    static const char *expected_prefixes[] = {"10.0.0.0"};
    static const uint8_t expected_prefix_lens[] = {8};
    labeled_ipv4_nlri_t *withdrawn =
        labeled_ipv4_nlri_create_path_id("10.0.0.0", 8, 999, 55);
    bgp_update_result_t *result;
    const uint8_t       *value = NULL;
    uint16_t             length = 0;
    int                  passed;

    result = bgp_generate_update_labeled_ipv4(NULL, NULL, withdrawn, 0, NULL);
    assert(result != NULL);

    passed = (result->num_messages == 1) &&
             find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_UNREACH_NLRI, &value, &length, NULL) &&
             validate_labeled_ipv4_nlri(value + 3,
                                        (uint16_t)(length - 3),
                                        expected_path_ids,
                                        expected_labels,
                                        expected_prefixes,
                                        expected_prefix_lens,
                                        1,
                                        1);

    bgp_update_result_free(result);
    labeled_ipv4_nlri_list_free(withdrawn);
    test_result(passed, "IPv4 labeled-unicast withdrawn");
}

void test_simple_labeled_ipv6_update() {
    static const uint32_t expected_labels[] = {5000, 5001};
    static const char *expected_prefixes[] = {"2001:db8:100::", "2001:db8:200::"};
    static const uint8_t expected_prefix_lens[] = {48, 48};
    labeled_ipv6_nlri_t *nlri =
        labeled_ipv6_nlri_create("2001:db8:100::", 48, 5000);
    labeled_ipv6_nlri_t *nlri_tail;
    bgp_next_hop_t       next_hop = make_ipv6_next_hop("2001:db8::1");
    bgp_path_attr_t     *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_update_result_t *result;
    const uint8_t       *value = NULL;
    const uint8_t       *nlri_data = NULL;
    uint16_t             length = 0;
    uint16_t             nlri_len = 0;
    int                  passed;

    TEST_FIND_TAIL(nlri_tail, nlri);
    labeled_ipv6_nlri_add_tail(&nlri, &nlri_tail, "2001:db8:200::", 48, 5001);
    origin->next = as_path;
    result = bgp_generate_update_labeled_ipv6(nlri, origin, NULL, 0, &next_hop);
    assert(result != NULL);

    passed = (result->num_messages == 1) &&
             extract_mp_reach_afi(result->messages[0],
                                  result->message_lens[0],
                                  AFI_IPV6,
                                  SAFI_LABELED_UNICAST,
                                  &value,
                                  &length,
                                  &nlri_data,
                                  &nlri_len) &&
             (value[3] == 16) &&
             validate_labeled_ipv6_nlri(nlri_data,
                                        nlri_len,
                                        NULL,
                                        expected_labels,
                                        expected_prefixes,
                                        expected_prefix_lens,
                                        2,
                                        0);

    bgp_update_result_free(result);
    labeled_ipv6_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    test_result(passed, "Simple IPv6 labeled-unicast UPDATE");
}

void test_labeled_ipv6_ipv4_next_hop_update() {
    static const char *expected_next_hop = "198.51.100.7";
    static const uint32_t expected_labels[] = {5100, 5101};
    static const char *expected_prefixes[] = {"2001:db8:300::", "2001:db8:400::"};
    static const uint8_t expected_prefix_lens[] = {48, 48};
    labeled_ipv6_nlri_t *nlri =
        labeled_ipv6_nlri_create("2001:db8:300::", 48, 5100);
    labeled_ipv6_nlri_t *nlri_tail;
    bgp_next_hop_t       next_hop = make_ipv4_next_hop(expected_next_hop);
    bgp_path_attr_t     *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_update_result_t *result;
    const uint8_t       *value = NULL;
    const uint8_t       *nlri_data = NULL;
    uint16_t             length = 0;
    uint16_t             nlri_len = 0;
    int                  passed;

    TEST_FIND_TAIL(nlri_tail, nlri);
    labeled_ipv6_nlri_add_tail(&nlri, &nlri_tail, "2001:db8:400::", 48, 5101);
    origin->next = as_path;
    result = bgp_generate_update_labeled_ipv6(nlri, origin, NULL, 0, &next_hop);
    assert(result != NULL);

    passed = (result->num_messages == 1) &&
             extract_mp_reach_afi(result->messages[0],
                                  result->message_lens[0],
                                  AFI_IPV6,
                                  SAFI_LABELED_UNICAST,
                                  &value,
                                  &length,
                                  &nlri_data,
                                  &nlri_len) &&
             (value[3] == 16) &&
             validate_ipv4_mapped_ipv6_next_hop(value + 4, expected_next_hop) &&
             validate_labeled_ipv6_nlri(nlri_data,
                                        nlri_len,
                                        NULL,
                                        expected_labels,
                                        expected_prefixes,
                                        expected_prefix_lens,
                                        2,
                                        0);

    bgp_update_result_free(result);
    labeled_ipv6_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    test_result(passed, "IPv6 labeled-unicast UPDATE with IPv4 next hop");
}

void test_labeled_ipv6_add_path_update() {
    static const uint32_t expected_path_ids[] = {1000, 1001};
    static const uint32_t expected_labels[] = {6000, 6001};
    static const char *expected_prefixes[] = {"2001:db8:10::", "2001:db8:20::"};
    static const uint8_t expected_prefix_lens[] = {48, 48};
    labeled_ipv6_nlri_t *nlri =
        labeled_ipv6_nlri_create_path_id("2001:db8:10::", 48, 6000, 1000);
    labeled_ipv6_nlri_t *nlri_tail;
    bgp_next_hop_t       next_hop = make_ipv6_next_hop("2001:db8::1");
    bgp_path_attr_t     *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_update_result_t *result;
    const uint8_t       *nlri_data = NULL;
    uint16_t             nlri_len = 0;
    int                  passed;

    TEST_FIND_TAIL(nlri_tail, nlri);
    labeled_ipv6_nlri_add_tail_path_id(&nlri, &nlri_tail, "2001:db8:20::", 48, 6001, 1001);
    origin->next = as_path;
    result = bgp_generate_update_labeled_ipv6(nlri, origin, NULL, 0, &next_hop);
    assert(result != NULL);

    passed = extract_mp_reach_afi(result->messages[0],
                                  result->message_lens[0],
                                  AFI_IPV6,
                                  SAFI_LABELED_UNICAST,
                                  NULL,
                                  NULL,
                                  &nlri_data,
                                  &nlri_len) &&
             validate_labeled_ipv6_nlri(nlri_data,
                                        nlri_len,
                                        expected_path_ids,
                                        expected_labels,
                                        expected_prefixes,
                                        expected_prefix_lens,
                                        2,
                                        0);

    bgp_update_result_free(result);
    labeled_ipv6_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    test_result(passed, "IPv6 labeled-unicast ADD-PATH UPDATE");
}

void test_labeled_ipv6_withdrawn() {
    static const uint32_t expected_labels[] = {0};
    static const char *expected_prefixes[] = {"2001:db8:dead::"};
    static const uint8_t expected_prefix_lens[] = {48};
    labeled_ipv6_nlri_t *withdrawn =
        labeled_ipv6_nlri_create("2001:db8:dead::", 48, 7000);
    bgp_update_result_t *result;
    const uint8_t       *value = NULL;
    uint16_t             length = 0;
    int                  passed;

    result = bgp_generate_update_labeled_ipv6(NULL, NULL, withdrawn, 0, NULL);
    assert(result != NULL);

    passed = (result->num_messages == 1) &&
             find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_UNREACH_NLRI, &value, &length, NULL) &&
             validate_labeled_ipv6_nlri(value + 3,
                                        (uint16_t)(length - 3),
                                        NULL,
                                        expected_labels,
                                        expected_prefixes,
                                        expected_prefix_lens,
                                        1,
                                        1);

    bgp_update_result_free(result);
    labeled_ipv6_nlri_list_free(withdrawn);
    test_result(passed, "IPv6 labeled-unicast withdrawn");
}

/*
 * Test 16: IPv4 ADD-PATH announcement encoding
 */
void test_simple_ipv4_rfc8950_update() {
    ipv4_nlri_list_t *nlri = ipv4_nlri_create("192.168.1.0", 24);
    ipv4_nlri_list_t *nlri_tail;
    bgp_next_hop_t    next_hop = make_ipv6_next_hop("2001:db8::1");
    bgp_path_attr_t  *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_update_result_t *result;
    const uint8_t       *value = NULL;
    uint16_t             length = 0;
    const uint8_t       *nlri_data = NULL;
    uint16_t             nlri_len = 0;
    int                  passed;

    TEST_FIND_TAIL(nlri_tail, nlri);
    ipv4_nlri_add_tail(&nlri, &nlri_tail, "192.168.2.0", 24);
    origin->next = as_path;

    result = bgp_generate_update_ipv4_mp(nlri, origin, NULL, 0, &next_hop);
    assert(result != NULL);

    passed = (result->num_messages == 1) &&
             !find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_NEXT_HOP, NULL, NULL, NULL) &&
             extract_mp_reach_afi(result->messages[0],
                                  result->message_lens[0],
                                  AFI_IPV4,
                                  SAFI_UNICAST,
                                  &value,
                                  &length,
                                  &nlri_data,
                                  &nlri_len) &&
             (value[3] == 16) &&
             (nlri_len > 0);

    bgp_update_result_free(result);
    ipv4_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    test_result(passed, "Simple IPv4 RFC 8950 UPDATE");
}

void test_ipv4_rfc8950_add_path_update() {
    static const uint32_t expected_path_ids[] = {100, 200};
    static const char *expected_prefixes[] = {"192.0.2.0", "192.0.3.0"};
    static const uint8_t expected_prefix_lens[] = {24, 24};
    ipv4_nlri_list_t *nlri = ipv4_nlri_create_path_id("192.0.2.0", 24, 100);
    ipv4_nlri_list_t *nlri_tail;
    bgp_next_hop_t    next_hop = make_ipv6_next_hop("2001:db8::1");
    bgp_path_attr_t  *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_update_result_t *result;
    const uint8_t       *nlri_data = NULL;
    uint16_t             nlri_len = 0;
    int                  passed;

    TEST_FIND_TAIL(nlri_tail, nlri);
    ipv4_nlri_add_tail_path_id(&nlri, &nlri_tail, "192.0.3.0", 24, 200);
    origin->next = as_path;

    result = bgp_generate_update_ipv4_mp(nlri, origin, NULL, 0, &next_hop);
    assert(result != NULL);

    passed = (result->num_messages == 1) &&
             extract_mp_reach_afi(result->messages[0],
                                  result->message_lens[0],
                                  AFI_IPV4,
                                  SAFI_UNICAST,
                                  NULL,
                                  NULL,
                                  &nlri_data,
                                  &nlri_len) &&
             validate_ipv4_add_path_nlri(nlri_data, nlri_len,
                                        expected_path_ids,
                                        expected_prefixes,
                                        expected_prefix_lens,
                                        2);

    bgp_update_result_free(result);
    ipv4_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    test_result(passed, "IPv4 RFC 8950 ADD-PATH UPDATE");
}

void test_ipv4_rfc8950_update_with_withdrawn() {
    ipv4_nlri_list_t *nlri = ipv4_nlri_create("192.168.1.0", 24);
    ipv4_nlri_list_t *withdrawn = ipv4_nlri_create("10.0.0.0", 8);
    bgp_next_hop_t    next_hop = make_ipv6_next_hop("2001:db8::1");
    bgp_path_attr_t  *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_update_result_t *result;
    const uint8_t       *value = NULL;
    uint16_t             length = 0;
    int                  passed;

    origin->next = as_path;
    result = bgp_generate_update_ipv4_mp(nlri, origin, withdrawn, 0, &next_hop);
    assert(result != NULL);

    passed = (result->num_messages == 2) &&
             find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_UNREACH_NLRI, &value, &length, NULL) &&
             (read_u16(value) == AFI_IPV4) &&
             (value[2] == SAFI_UNICAST) &&
             find_attr(result->messages[1], result->message_lens[1], BGP_ATTR_MP_REACH_NLRI, NULL, NULL, NULL);

    bgp_update_result_free(result);
    ipv4_nlri_list_free(nlri);
    ipv4_nlri_list_free(withdrawn);
    bgp_path_attr_list_free(origin);
    test_result(passed, "IPv4 RFC 8950 UPDATE with withdrawn");
}

/*
 * Test 16: IPv4 ADD-PATH announcement encoding
 */
void test_ipv4_add_path_update() {
    static const uint32_t expected_path_ids[] = {0, 55};
    static const char *expected_prefixes[] = {"192.0.2.0", "192.0.3.0"};
    static const uint8_t expected_prefix_lens[] = {24, 24};
    ipv4_nlri_list_t *nlri = ipv4_nlri_create_path_id("192.0.2.0", 24, 0);
    ipv4_nlri_list_t *nlri_tail;
    bgp_path_attr_t  *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_next_hop_t       next_hop = make_ipv4_next_hop("10.0.0.1");
    bgp_path_attr_t     *next_hop_attr = bgp_attr_create_next_hop(&next_hop);
    bgp_update_result_t *result;
    test_wire_update_t   view;
    int                  passed;

    TEST_FIND_TAIL(nlri_tail, nlri);
    ipv4_nlri_add_tail_path_id(&nlri, &nlri_tail, "192.0.3.0", 24, 55);
    origin->next = as_path;
    as_path->next = next_hop_attr;

    result = bgp_generate_update_ipv4(nlri, origin, NULL, 0);
    assert(result != NULL);

    passed = (result->num_messages == 1) &&
             test_wire_update_view(result->messages[0], result->message_lens[0], &view) &&
             validate_ipv4_add_path_nlri(view.nlri, (uint16_t)view.nlri_len,
                                        expected_path_ids,
                                        expected_prefixes,
                                        expected_prefix_lens,
                                        2);

    bgp_update_result_free(result);
    ipv4_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    test_result(passed, "IPv4 ADD-PATH UPDATE");
}

/*
 * Test 17: IPv4 ADD-PATH withdrawn encoding
 */
void test_ipv4_add_path_withdrawn() {
    static const uint32_t expected_path_ids[] = {77};
    static const char *expected_prefixes[] = {"10.0.0.0"};
    static const uint8_t expected_prefix_lens[] = {8};
    ipv4_nlri_list_t    *withdrawn = ipv4_nlri_create_path_id("10.0.0.0", 8, 77);
    bgp_update_result_t *result = bgp_generate_update_ipv4(NULL, NULL, withdrawn, 0);
    uint16_t             withdrawn_len;
    int                  passed;

    assert(result != NULL);
    withdrawn_len = test_wire_withdrawn_len(result->messages[0], result->message_lens[0]);
    passed = (result->num_messages == 1) &&
             (test_wire_path_attr_len(result->messages[0], result->message_lens[0]) == 0) &&
             validate_ipv4_add_path_nlri(result->messages[0] + BGP_HEADER_SIZE + 2,
                                        withdrawn_len,
                                        expected_path_ids,
                                        expected_prefixes,
                                        expected_prefix_lens,
                                        1);

    bgp_update_result_free(result);
    ipv4_nlri_list_free(withdrawn);
    test_result(passed, "IPv4 ADD-PATH withdrawn");
}

/*
 * Test 18: IPv6 UPDATE with withdrawals
 */
void test_ipv6_update_with_withdrawn() {
    ipv6_nlri_list_t *nlri = ipv6_nlri_create("2001:db8:100::", 48);
    ipv6_nlri_list_t *withdrawn = ipv6_nlri_create("2001:db8:dead::", 48);
    bgp_next_hop_t    next_hop = make_ipv6_next_hop("2001:db8::1");
    bgp_path_attr_t  *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_update_result_t *result;
    int                  passed;

    origin->next = as_path;
    result = bgp_generate_update_ipv6(nlri, origin, withdrawn, 0, &next_hop);
    assert(result != NULL);

    passed = (result->num_messages == 2) &&
             find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_UNREACH_NLRI, NULL, NULL, NULL) &&
             find_attr(result->messages[1], result->message_lens[1], BGP_ATTR_MP_REACH_NLRI, NULL, NULL, NULL);

    bgp_update_result_free(result);
    ipv6_nlri_list_free(nlri);
    ipv6_nlri_list_free(withdrawn);
    bgp_path_attr_list_free(origin);
    test_result(passed, "IPv6 UPDATE with withdrawn");
}

/*
 * Test 19: IPv6 ADD-PATH MP_REACH encoding
 */
void test_ipv6_add_path_update() {
    static const uint32_t expected_path_ids[] = {100, 200};
    static const char *expected_prefixes[] = {"2001:db8:100::", "2001:db8:200::"};
    static const uint8_t expected_prefix_lens[] = {48, 48};
    ipv6_nlri_list_t *nlri = ipv6_nlri_create_path_id("2001:db8:100::", 48, 100);
    ipv6_nlri_list_t *nlri_tail;
    bgp_next_hop_t    next_hop = make_ipv6_next_hop("2001:db8::1");
    bgp_path_attr_t  *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_update_result_t *result;
    const uint8_t       *value = NULL;
    uint16_t             length = 0;
    const uint8_t       *nlri_data;
    uint16_t             nlri_len;
    int                  passed;

    TEST_FIND_TAIL(nlri_tail, nlri);
    ipv6_nlri_add_tail_path_id(&nlri, &nlri_tail, "2001:db8:200::", 48, 200);
    origin->next = as_path;

    result = bgp_generate_update_ipv6(nlri, origin, NULL, 0, &next_hop);
    assert(result != NULL);

    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI, &value, &length, NULL);
    nlri_data = value + 2 + 1 + 1 + value[3] + 1;
    nlri_len = (uint16_t)(length - (2 + 1 + 1 + value[3] + 1));
    passed = passed &&
             validate_ipv6_add_path_nlri(nlri_data,
                                        nlri_len,
                                        expected_path_ids,
                                        expected_prefixes,
                                        expected_prefix_lens,
                                        2);

    bgp_update_result_free(result);
    ipv6_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    test_result(passed, "IPv6 ADD-PATH UPDATE");
}

/*
 * Test 20: IPv6 ADD-PATH MP_UNREACH encoding
 */
void test_ipv6_add_path_withdrawn() {
    static const uint32_t expected_path_ids[] = {4096};
    static const char *expected_prefixes[] = {"2001:db8:dead::"};
    static const uint8_t expected_prefix_lens[] = {48};
    ipv6_nlri_list_t *withdrawn =
        ipv6_nlri_create_path_id("2001:db8:dead::", 48, 4096);
    bgp_path_attr_t *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_update_result_t *result;
    const uint8_t       *value = NULL;
    uint16_t             length = 0;
    int                  passed;

    origin->next = as_path;
    result = bgp_generate_update_ipv6(NULL, origin, withdrawn, 0, NULL);
    assert(result != NULL);

    passed = (result->num_messages == 1) &&
             find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_UNREACH_NLRI, &value, &length, NULL) &&
             validate_ipv6_add_path_nlri(value + 3,
                                        (uint16_t)(length - 3),
                                        expected_path_ids,
                                        expected_prefixes,
                                        expected_prefix_lens,
                                        1);

    bgp_update_result_free(result);
    ipv6_nlri_list_free(withdrawn);
    bgp_path_attr_list_free(origin);
    test_result(passed, "IPv6 ADD-PATH withdrawn");
}

/*
 * Test 21: Mixed ADD-PATH list is rejected
 */
void test_mixed_add_path_rejected() {
    ipv4_nlri_list_t *nlri = ipv4_nlri_create("192.0.2.0", 24);
    ipv4_nlri_list_t *nlri_tail;
    bgp_path_attr_t  *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_next_hop_t       next_hop = make_ipv4_next_hop("10.0.0.1");
    bgp_path_attr_t     *next_hop_attr = bgp_attr_create_next_hop(&next_hop);
    bgp_update_result_t *result;

    TEST_FIND_TAIL(nlri_tail, nlri);
    ipv4_nlri_add_tail_path_id(&nlri, &nlri_tail, "192.0.3.0", 24, 7);
    origin->next = as_path;
    as_path->next = next_hop_attr;

    result = bgp_generate_update_ipv4(nlri, origin, NULL, 0);
    test_result(result == NULL, "Mixed ADD-PATH list rejected");

    bgp_update_result_free(result);
    ipv4_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
}

/*
 * Test 22: IPv4 prefix encoding
 */
void test_ipv4_prefix_encoding() {
    ipv4_prefix_t prefix;
    uint8_t       buffer[32];
    int           len;

    prefix.prefix_len = 24;
    inet_pton(AF_INET, "192.168.1.0", &prefix.prefix);
    len = bgp_encode_ipv4_prefix(buffer, &prefix);

    test_result((len == 4) && (buffer[0] == 24), "IPv4 prefix encoding");
}

/*
 * Test 23: IPv6 prefix encoding
 */
void test_ipv6_prefix_encoding() {
    ipv6_prefix_t prefix;
    uint8_t       buffer[32];
    int           len;

    prefix.prefix_len = 48;
    inet_pton(AF_INET6, "2001:db8:100::", prefix.prefix);
    len = bgp_encode_ipv6_prefix(buffer, &prefix);

    test_result((len == 7) && (buffer[0] == 48), "IPv6 prefix encoding");
}

/*
 * Test 24: Large IPv4 NLRI list
 */
void test_large_ipv4_nlri() {
    ipv4_nlri_list_t *nlri = NULL;
    ipv4_nlri_list_t *nlri_tail = NULL;
    bgp_path_attr_t  *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_next_hop_t       next_hop = make_ipv4_next_hop("10.0.0.1");
    bgp_path_attr_t     *next_hop_attr;
    bgp_update_result_t *result;
    int                  i;
    int                  passed;

    for (i = 0; i < 1000; i++) {
        char prefix[32];
        snprintf(prefix, sizeof(prefix), "10.%d.%d.0", i / 256, i % 256);
        ipv4_nlri_add_tail(&nlri, &nlri_tail, prefix, 24);
    }

    next_hop_attr = bgp_attr_create_next_hop(&next_hop);
    origin->next = as_path;
    as_path->next = next_hop_attr;

    result = bgp_generate_update_ipv4(nlri, origin, NULL, 4096);
    assert(result != NULL);

    passed = (ipv4_nlri_count(nlri) == 1000) && (result->num_messages >= 1);

    bgp_update_result_free(result);
    ipv4_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    test_result(passed, "Large IPv4 NLRI list");
}

/*
 * Test 25: Multiple AS_PATH segments
 */
void test_multiple_as_path_segments() {
    uint32_t asns1[] = {100, 200};
    uint32_t asns2[] = {300, 400, 500};
    as_path_segment_t segments[] = {
        {BGP_AS_SEQUENCE, 2, asns1},
        {BGP_AS_SEQUENCE, 3, asns2}
    };
    bgp_path_attr_t *attr = bgp_attr_create_as_path(segments, 2);
    int              passed = (attr != NULL) && (attr->length == 24);

    bgp_path_attr_free(attr);
    test_result(passed, "Multiple AS_PATH segments");
}

/*
 * Test 26: Missing required IPv4 attributes
 */
void test_missing_required_ipv4_attrs() {
    ipv4_nlri_list_t    *nlri = ipv4_nlri_create("192.168.1.0", 24);
    bgp_path_attr_t     *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    bgp_update_result_t *result = bgp_generate_update_ipv4(nlri, origin, NULL, 0);

    test_result(result == NULL, "Missing required IPv4 attributes");

    bgp_update_result_free(result);
    ipv4_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
}

/*
 * Test 27: Edge case - withdrawn-only update
 */
void test_empty_nlri() {
    ipv4_nlri_list_t    *withdrawn = ipv4_nlri_create("10.0.0.0", 8);
    bgp_update_result_t *result = bgp_generate_update_ipv4(NULL, NULL, withdrawn, 0);
    int passed = (result != NULL) &&
                 (result->num_messages == 1) &&
                 (test_wire_withdrawn_len(result->messages[0], result->message_lens[0]) > 0) &&
                 (test_wire_path_attr_len(result->messages[0], result->message_lens[0]) == 0);

    bgp_update_result_free(result);
    ipv4_nlri_list_free(withdrawn);
    test_result(passed, "Withdrawn-only UPDATE");
}

// Adversarial / boundary tests

/*
 * Test 28: IPv4 /0 prefix (default route) encodes as 1 byte (just prefix_len)
 */
void test_ipv4_prefix_len_zero() {
    ipv4_prefix_t prefix;
    uint8_t       buffer[32];
    int           len;

    prefix.prefix_len = 0;
    prefix.prefix = 0;
    len = bgp_encode_ipv4_prefix(buffer, &prefix);

    test_result((len == 1) && (buffer[0] == 0), "IPv4 /0 prefix encoding");
}

/*
 * Test 29: IPv4 /32 host route encodes all 4 prefix bytes
 */
void test_ipv4_prefix_len_32() {
    ipv4_prefix_t prefix;
    uint8_t       buffer[32];
    int           len;

    prefix.prefix_len = 32;
    inet_pton(AF_INET, "192.0.2.1", &prefix.prefix);
    len = bgp_encode_ipv4_prefix(buffer, &prefix);

    test_result((len == 5) && (buffer[0] == 32), "IPv4 /32 host route encoding");
}

/*
 * Test 30: IPv6 /0 prefix (default route)
 */
void test_ipv6_prefix_len_zero() {
    ipv6_prefix_t prefix;
    uint8_t       buffer[32];
    int           len;

    prefix.prefix_len = 0;
    memset(prefix.prefix, 0, 16);
    len = bgp_encode_ipv6_prefix(buffer, &prefix);

    test_result((len == 1) && (buffer[0] == 0), "IPv6 /0 prefix encoding");
}

/*
 * Test 31: IPv6 /128 host route encodes all 16 bytes
 */
void test_ipv6_prefix_len_128() {
    ipv6_prefix_t prefix;
    uint8_t       buffer[32];
    int           len;

    prefix.prefix_len = 128;
    inet_pton(AF_INET6, "2001:db8::1", prefix.prefix);
    len = bgp_encode_ipv6_prefix(buffer, &prefix);

    test_result((len == 17) && (buffer[0] == 128), "IPv6 /128 host route encoding");
}

/*
 * Test 32: MPLS label 0 (explicit null) encodes correctly
 */
void test_mpls_label_zero() {
    mpls_label_t label = {0, 0, 1, 0};
    uint8_t      buffer[3];

    bgp_encode_mpls_label(buffer, &label);

    test_result((decode_wire_label(buffer) == 0) && (buffer[2] & 0x01) == 1, "MPLS label 0 (explicit null)");
}

/*
 * Test 33: MPLS max label (1048575 = 0xFFFFF) encodes correctly
 */
void test_mpls_label_max() {
    mpls_label_t label = {1048575, 0, 1, 0};
    uint8_t      buffer[3];

    bgp_encode_mpls_label(buffer, &label);

    test_result((decode_wire_label(buffer) == 1048575) &&
                (buffer[0] == 0xFF) && (buffer[1] == 0xFF) &&
                ((buffer[2] & 0xF0) == 0xF0),
                "MPLS max label (1048575)");
}

/*
 * Test 34: MPLS label overflow (> 20 bits) is silently masked
 */
void test_mpls_label_overflow_masked() {
    mpls_label_t label = {0x100000, 0, 1, 0};  /* 2^20, one beyond max */
    uint8_t      buffer[3];

    bgp_encode_mpls_label(buffer, &label);

    // Label should be masked to 20 bits: 0x100000 & 0xFFFFF = 0
    test_result(decode_wire_label(buffer) == 0, "MPLS label overflow masked to 20 bits");
}

/*
 * Test 35: Labeled IPv4 prefix_len < 24 returns -1
 */
void test_labeled_ipv4_prefix_len_too_short() {
    labeled_ipv4_prefix_t prefix;
    uint8_t               buffer[32];

    prefix.prefix_len = 23;
    prefix.label.label = 100;
    prefix.label.tc = 0;
    prefix.label.s = 1;
    prefix.label.ttl = 0;
    inet_pton(AF_INET, "10.0.0.0", &prefix.prefix);

    test_result(bgp_encode_labeled_ipv4_prefix(buffer, &prefix) == -1, "Labeled IPv4 prefix_len < 24 rejected");
}

/*
 * Test 36: Labeled IPv6 prefix_len < 24 returns -1
 */
void test_labeled_ipv6_prefix_len_too_short() {
    labeled_ipv6_prefix_t prefix;
    uint8_t               buffer[32];

    prefix.prefix_len = 20;
    prefix.label.label = 100;
    prefix.label.tc = 0;
    prefix.label.s = 1;
    prefix.label.ttl = 0;
    memset(prefix.prefix, 0, 16);

    test_result(bgp_encode_labeled_ipv6_prefix(buffer, &prefix) == -1, "Labeled IPv6 prefix_len < 24 rejected");
}

/*
 * Test 37: Labeled IPv4 prefix_len == 24 means /0 IP prefix (label only)
 */
void test_labeled_ipv4_prefix_len_exactly_24() {
    labeled_ipv4_prefix_t prefix;
    uint8_t               buffer[32];
    int                   len;

    prefix.prefix_len = 24;  /* 24 label bits + 0 IP bits */
    prefix.label.label = 500;
    prefix.label.tc = 0;
    prefix.label.s = 1;
    prefix.label.ttl = 0;
    prefix.prefix = 0;

    len = bgp_encode_labeled_ipv4_prefix(buffer, &prefix);

    // 1 byte prefix_len + 3 bytes label + 0 bytes IP = 4
    test_result((len == 4) && (buffer[0] == 24) &&
                (decode_wire_label(buffer + 1) == 500),
                "Labeled IPv4 prefix_len == 24 (default route)");
}

/*
 * Test 38: Labeled IPv4 /32 = prefix_len 56 (24 + 32)
 */
void test_labeled_ipv4_host_route() {
    labeled_ipv4_prefix_t prefix;
    uint8_t               buffer[32];
    int                   len;

    prefix.prefix_len = 56;  /* 24 + 32 */
    prefix.label.label = 999;
    prefix.label.tc = 0;
    prefix.label.s = 1;
    prefix.label.ttl = 0;
    inet_pton(AF_INET, "10.0.0.1", &prefix.prefix);

    len = bgp_encode_labeled_ipv4_prefix(buffer, &prefix);

    // 1 + 3 + 4 = 8 bytes
    test_result((len == 8) && (buffer[0] == 56), "Labeled IPv4 /32 host route (prefix_len=56)");
}

/*
 * Test 39: ADD-PATH with path_id = 0 is valid when add_path flag set
 */
void test_add_path_id_zero() {
    static const uint32_t expected_path_ids[] = {0};
    static const char *expected_prefixes[] = {"10.0.0.0"};
    static const uint8_t expected_prefix_lens[] = {8};
    ipv4_nlri_list_t *nlri = ipv4_nlri_create_path_id("10.0.0.0", 8, 0);
    bgp_path_attr_t  *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_next_hop_t       next_hop = make_ipv4_next_hop("10.0.0.1");
    bgp_path_attr_t     *next_hop_attr = bgp_attr_create_next_hop(&next_hop);
    bgp_update_result_t *result;
    test_wire_update_t   view;
    int                  passed;

    origin->next = as_path;
    as_path->next = next_hop_attr;
    result = bgp_generate_update_ipv4(nlri, origin, NULL, 0);
    assert(result != NULL);

    passed = (result->num_messages == 1) &&
             test_wire_update_view(result->messages[0], result->message_lens[0], &view) &&
             validate_ipv4_add_path_nlri(view.nlri, (uint16_t)view.nlri_len,
                                         expected_path_ids,
                                         expected_prefixes,
                                         expected_prefix_lens, 1);

    bgp_update_result_free(result);
    ipv4_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    test_result(passed, "ADD-PATH with path_id=0");
}

/*
 * Test 40: ADD-PATH with path_id = UINT32_MAX
 */
void test_add_path_id_max() {
    static const uint32_t expected_path_ids[] = {4294967295U};
    static const char *expected_prefixes[] = {"10.0.0.0"};
    static const uint8_t expected_prefix_lens[] = {8};
    ipv4_nlri_list_t *nlri = ipv4_nlri_create_path_id("10.0.0.0", 8, 4294967295U);
    bgp_path_attr_t  *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_next_hop_t       next_hop = make_ipv4_next_hop("10.0.0.1");
    bgp_path_attr_t     *next_hop_attr = bgp_attr_create_next_hop(&next_hop);
    bgp_update_result_t *result;
    test_wire_update_t   view;
    int                  passed;

    origin->next = as_path;
    as_path->next = next_hop_attr;
    result = bgp_generate_update_ipv4(nlri, origin, NULL, 0);
    assert(result != NULL);

    passed = (result->num_messages == 1) &&
             test_wire_update_view(result->messages[0], result->message_lens[0], &view) &&
             validate_ipv4_add_path_nlri(view.nlri, (uint16_t)view.nlri_len,
                                         expected_path_ids,
                                         expected_prefixes,
                                         expected_prefix_lens, 1);

    bgp_update_result_free(result);
    ipv4_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    test_result(passed, "ADD-PATH with path_id=UINT32_MAX");
}

/*
 * Test 41: Extended-length flag at boundary (255 vs 256 byte value)
 */
void test_extended_length_boundary() {
    int size_255 = bgp_marshaled_attr_size(BGP_ATTR_FLAG_OPTIONAL, 255);
    int size_256 = bgp_marshaled_attr_size(BGP_ATTR_FLAG_OPTIONAL, 256);

    // 255: flags(1) + type(1) + len(1) + value(255) = 258
    // 256: flags(1) + type(1) + len(2) + value(256) = 260
    test_result((size_255 == 258) && (size_256 == 260), "Extended-length flag boundary (255 vs 256)");
}

/*
 * Test 42: IPv6 next-hop without link-local is 16 bytes
 */
void test_ipv6_next_hop_global_only() {
    ipv6_nlri_list_t *nlri = ipv6_nlri_create("2001:db8:100::", 48);
    bgp_next_hop_t    next_hop = make_ipv6_next_hop("2001:db8::1");
    bgp_path_attr_t  *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_update_result_t *result;
    const uint8_t       *value = NULL;
    uint16_t             length = 0;
    int                  passed;

    origin->next = as_path;
    result = bgp_generate_update_ipv6(nlri, origin, NULL, 0, &next_hop);
    assert(result != NULL);

    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI, &value, &length, NULL) &&
             (value[3] == 16);  /* nh_len = 16 (global only) */

    bgp_update_result_free(result);
    ipv6_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    test_result(passed, "IPv6 next-hop global only (16 bytes)");
}

/*
 * Test 43: IPv6 next-hop with link-local is 32 bytes
 */
void test_ipv6_next_hop_with_link_local() {
    ipv6_nlri_list_t *nlri = ipv6_nlri_create("2001:db8:100::", 48);
    bgp_next_hop_t    next_hop = make_ipv6_next_hop_with_link_local("2001:db8::1", "fe80::1");
    bgp_path_attr_t  *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_update_result_t *result;
    const uint8_t       *value = NULL;
    uint16_t             length = 0;
    int                  passed;

    origin->next = as_path;
    result = bgp_generate_update_ipv6(nlri, origin, NULL, 0, &next_hop);
    assert(result != NULL);

    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI, &value, &length, NULL) &&
             (value[3] == 32);  /* nh_len = 32 (global + link-local) */

    bgp_update_result_free(result);
    ipv6_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    test_result(passed, "IPv6 next-hop with link-local (32 bytes)");
}

/*
 * Test 44: MED and LOCAL_PREF boundary values (0 and UINT32_MAX)
 */
void test_med_and_local_pref_boundaries() {
    bgp_path_attr_t *med_zero = bgp_attr_create_med(0);
    bgp_path_attr_t *med_max = bgp_attr_create_med(4294967295U);
    bgp_path_attr_t *lp_zero = bgp_attr_create_local_pref(0);
    bgp_path_attr_t *lp_max = bgp_attr_create_local_pref(4294967295U);
    int              passed;

    passed = (med_zero != NULL) && (med_zero->length == 4) &&
             (med_max != NULL) && (med_max->length == 4) &&
             (lp_zero != NULL) && (lp_zero->length == 4) &&
             (lp_max != NULL) && (lp_max->length == 4);

    // Verify MED=0 wire encoding
    if (med_zero) {
        passed = passed && (med_zero->value[0] == 0) &&
                 (med_zero->value[1] == 0) && (med_zero->value[2] == 0) &&
                 (med_zero->value[3] == 0);
    }
    // Verify MED=UINT32_MAX wire encoding
    if (med_max) {
        passed = passed && (med_max->value[0] == 0xFF) &&
                 (med_max->value[1] == 0xFF) && (med_max->value[2] == 0xFF) &&
                 (med_max->value[3] == 0xFF);
    }

    bgp_path_attr_free(med_zero);
    bgp_path_attr_free(med_max);
    bgp_path_attr_free(lp_zero);
    bgp_path_attr_free(lp_max);
    test_result(passed, "MED and LOCAL_PREF boundary values");
}

/*
 * Test 45: ORIGIN attribute with all valid values
 */
void test_origin_all_values() {
    bgp_path_attr_t *igp = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    bgp_path_attr_t *egp = bgp_attr_create_origin(BGP_ORIGIN_EGP);
    bgp_path_attr_t *incomplete = bgp_attr_create_origin(BGP_ORIGIN_INCOMPLETE);

    int passed = (igp && igp->value[0] == 0) &&
                 (egp && egp->value[0] == 1) &&
                 (incomplete && incomplete->value[0] == 2);

    bgp_path_attr_free(igp);
    bgp_path_attr_free(egp);
    bgp_path_attr_free(incomplete);
    test_result(passed, "ORIGIN all valid values (IGP/EGP/INCOMPLETE)");
}

/*
 * Test 46: IPv4 /0 default route through full UPDATE pipeline
 */
void test_ipv4_default_route_update() {
    ipv4_nlri_list_t *nlri = ipv4_nlri_create("0.0.0.0", 0);
    bgp_path_attr_t  *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_next_hop_t       next_hop = make_ipv4_next_hop("10.0.0.1");
    bgp_path_attr_t     *next_hop_attr = bgp_attr_create_next_hop(&next_hop);
    bgp_update_result_t *result;
    int                  passed;

    origin->next = as_path;
    as_path->next = next_hop_attr;
    result = bgp_generate_update_ipv4(nlri, origin, NULL, 0);
    assert(result != NULL);

    // NLRI for /0: just 1 byte (0x00 prefix_len), no prefix bytes
    passed = (result->num_messages == 1) &&
             (test_wire_path_attr_len(result->messages[0], result->message_lens[0]) > 0);

    bgp_update_result_free(result);
    ipv4_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    test_result(passed, "IPv4 /0 default route UPDATE");
}

/*
 * Test 47: IPv6 /128 host route through full UPDATE pipeline
 */
void test_ipv6_host_route_update() {
    ipv6_nlri_list_t *nlri = ipv6_nlri_create("2001:db8::1", 128);
    bgp_next_hop_t    next_hop = make_ipv6_next_hop("2001:db8::fe");
    bgp_path_attr_t  *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_update_result_t *result;
    const uint8_t       *nlri_data = NULL;
    uint16_t             nlri_len = 0;
    int                  passed;

    origin->next = as_path;
    result = bgp_generate_update_ipv6(nlri, origin, NULL, 0, &next_hop);
    assert(result != NULL);

    passed = (result->num_messages == 1) &&
             extract_mp_reach_afi(result->messages[0],
                                  result->message_lens[0],
                                  AFI_IPV6, SAFI_UNICAST,
                                  NULL, NULL, &nlri_data, &nlri_len) &&
             (nlri_len == 17) &&  /* 1 byte prefix_len(128) + 16 bytes prefix */
             (nlri_data[0] == 128);

    bgp_update_result_free(result);
    ipv6_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    test_result(passed, "IPv6 /128 host route UPDATE");
}

/*
 * Test 48: AS_SET segment type
 */
void test_as_set_segment() {
    uint32_t asns[] = {100, 200, 300};
    as_path_segment_t segment = {
        .type = BGP_AS_SET,
        .length = 3,
        .as_numbers = asns
    };
    bgp_path_attr_t *attr = bgp_attr_create_as_path(&segment, 1);

    // AS_SET: type(1) + count(1) + 3*4 = 14 bytes
    int passed = (attr != NULL) && (attr->length == 14) &&
                 (attr->value[0] == BGP_AS_SET) &&
                 (attr->value[1] == 3);

    bgp_path_attr_free(attr);
    test_result(passed, "AS_SET segment type encoding");
}

/*
 * Test 49: Empty AS_PATH (zero segments)
 */
void test_empty_as_path() {
    bgp_path_attr_t *attr = bgp_attr_create_as_path(NULL, 0);

    test_result((attr != NULL) && (attr->length == 0), "Empty AS_PATH (iBGP)");

    bgp_path_attr_free(attr);
}

/*
 * RFC 4271 section 5: one attribute of each type per UPDATE.
 */
void test_reject_repeated_attribute_types() {
    ipv4_nlri_list_t *nlri = ipv4_nlri_create("192.168.1.0", 24);
    bgp_path_attr_t  *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_next_hop_t       next_hop = make_ipv4_next_hop("10.0.0.1");
    bgp_path_attr_t     *rt_a = bgp_attr_create_ext_comm_rt(65000, 1);
    bgp_path_attr_t     *rt_b = bgp_attr_create_ext_comm_rt(65000, 2);
    bgp_update_result_t *result;
    int                  passed;

    origin->next = as_path;
    as_path->next = bgp_attr_create_next_hop(&next_hop);
    as_path->next->next = rt_a;
    rt_a->next = rt_b;

    /*
     * Two Extended Communities attributes: a receiver would keep only the
     * first (RFC 7606 section 3 (g)), so the strict encoder refuses.
     */
    result = bgp_generate_update_ipv4(nlri, origin, NULL, 0);
    passed = (result == NULL);

    // Merged into one attribute, the same communities are accepted.
    rt_a->next = NULL;
    passed = passed && (bgp_attr_ext_comm_append_attr(rt_a, rt_b) == 0);
    result = bgp_generate_update_ipv4(nlri, origin, NULL, 0);
    passed = passed && (result != NULL) && (result->num_messages == 1);

    bgp_update_result_free(result);
    bgp_path_attr_free(rt_b);
    ipv4_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    test_result(passed, "Reject repeated attribute types; accept the merged list");
}

/*
 * The RFC 4360 admin layout builders own the byte order for RT, SoO, and
 * FlowSpec redirect communities.
 */
void test_ext_comm_admin_layouts() {
    static const uint8_t want_g2[8] = {0x80, 0x08, 0xfd, 0xe8, 0x00, 0x01, 0x86, 0xa0};
    static const uint8_t want_g4[8] = {0x02, 0x03, 0xfa, 0x56, 0xea, 0x00, 0x01, 0x2c};
    bgp_path_attr_t *g2 = bgp_attr_create_ext_comm_global2(0x80, 0x08, 65000, 100000);
    bgp_path_attr_t *g4 = bgp_attr_create_ext_comm_global4(0x02, 0x03, 4200000000u, 300);
    bgp_path_attr_t *rt = bgp_attr_create_ext_comm_rt(65000, 100000);
    bgp_path_attr_t *redirect = bgp_attr_create_flowspec_redirect_rt(65000, 100000);
    int passed = g2 && g4 && rt && redirect &&
                 (memcmp(g2->value, want_g2, 8) == 0) &&
                 (memcmp(g4->value, want_g4, 8) == 0) &&
                 (rt->value[0] == 0x00) && (rt->value[1] == 0x02) &&
                 (memcmp(rt->value + 2, want_g2 + 2, 6) == 0) &&
                 (memcmp(redirect->value, want_g2, 8) == 0);

    bgp_path_attr_free(g2);
    bgp_path_attr_free(g4);
    bgp_path_attr_free(rt);
    bgp_path_attr_free(redirect);
    test_result(passed, "RFC 4360 admin layouts (2+4 and 4+2 octets)");
}

/*
 * Test: bgp_serialize_as_path_attr() writes the bytes of bgp_attr_create_as_path() for an empty path, a SEQUENCE plus
 * a SET with a 4-octet ASN, and a 282-octet value (Extended Length header). It writes nothing past its capacity and
 * nothing at all when the attribute is one octet longer than the capacity.
 */
void test_serialize_as_path_attr() {
    uint32_t          sequence_asns[] = {65001, 4200000000u};
    uint32_t          set_asns[] = {100, 200, 300};
    uint32_t          long_asns[70];
    as_path_segment_t two_segments[] = {{BGP_AS_SEQUENCE, 2, sequence_asns}, {BGP_AS_SET, 3, set_asns}};
    as_path_segment_t long_segment = {BGP_AS_SEQUENCE, 70, long_asns};
    struct {
        as_path_segment_t *segments;
        int                count;
    } cases[] = {{NULL, 0}, {two_segments, 2}, {&long_segment, 1}};
    uint8_t want[400];
    uint8_t got[400];
    int     passed = 1;

    for (int i = 0; i < 70; i++) {
        long_asns[i] = 64512u + (uint32_t)i;
    }

    for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
        bgp_path_attr_t *attr = bgp_attr_create_as_path(cases[c].segments, cases[c].count);
        int              want_len;

        assert(attr != NULL);
        want_len = bgp_serialize_raw_path_attr(want, attr->flags, attr->type_code, attr->length, attr->value);

        // Exact capacity: the same bytes, and the octet after them is not touched.
        memset(got, 0xAA, sizeof(got));
        passed = passed &&
                 (bgp_serialize_as_path_attr(got, (size_t)want_len, cases[c].segments, cases[c].count) == want_len) &&
                 (memcmp(got, want, (size_t)want_len) == 0) && (got[want_len] == 0xAA);

        // One octet less: -1, and buffer unchanged.
        memset(got, 0xAA, sizeof(got));
        passed = passed &&
                 (bgp_serialize_as_path_attr(got, (size_t)want_len - 1, cases[c].segments, cases[c].count) == -1) &&
                 (got[0] == 0xAA);
        bgp_path_attr_free(attr);
    }

    // 70 ASNs: a 2-octet segment header and 280 octets of ASNs, so the attribute header has 4 octets.
    passed = passed && (bgp_serialize_as_path_attr(got, sizeof(got), &long_segment, 1) == 4 + 282) &&
             ((got[0] & BGP_ATTR_FLAG_EXTENDED_LEN) != 0) && (got[1] == BGP_ATTR_AS_PATH) &&
             (read_u16(got + 2) == 282) && (got[4] == BGP_AS_SEQUENCE) && (got[5] == 70) &&
             (read_u32(got + 6) == 64512u);

    test_result(passed, "AS_PATH buffer writer matches the attribute list path");
}

/*
 * Test: bgp_builder_clear() frees the messages that the builder still holds, leaves a message that a caller took
 * (slot set to NULL), and keeps the result and arrays, so the next appends use the same arrays. valgrind checks the
 * frees.
 */
void test_builder_clear_keeps_arrays() {
    const uint8_t attrs[] = {BGP_ATTR_FLAG_TRANSITIVE, BGP_ATTR_ORIGIN, 1, BGP_ORIGIN_IGP};
    bgp_builder_t builder;
    uint8_t      *taken;
    uint8_t     **arrays;
    int           passed;

    assert(bgp_builder_init(&builder) == 0);
    for (int i = 0; i < 3; i++) {
        assert(bgp_builder_append_attrs_only(&builder, attrs, sizeof(attrs)) == 0);
    }
    taken = builder.result->messages[1];
    builder.result->messages[1] = NULL;
    arrays = builder.result->messages;

    bgp_builder_clear(&builder);
    passed = (builder.result != NULL) && (builder.result->num_messages == 0) && (builder.capacity >= 3) &&
             (builder.result->messages == arrays);

    // The builder works again on the same arrays.
    passed = passed && (bgp_builder_append_attrs_only(&builder, attrs, sizeof(attrs)) == 0) &&
             (builder.result->num_messages == 1) && (builder.result->messages == arrays) &&
             (builder.result->message_lens[0] == BGP_HEADER_SIZE + 2 + 2 + sizeof(attrs));

    // The taken message is still a valid UPDATE.
    passed = passed && (taken[BGP_MARKER_SIZE + 2] == BGP_MSG_UPDATE);

    free(taken);
    bgp_builder_release(&builder);
    bgp_builder_clear(&builder);  /* No result: nothing to do */
    test_result(passed, "Builder clear frees held messages and keeps its arrays");
}

static void test_builder_bounds(void) {
    uint8_t      *payload = calloc(UINT16_MAX, 1);
    bgp_builder_t builder;
    int           passed = payload && bgp_builder_init(&builder) == 0;
    assert(passed);
    // The 16-bit outer length includes the 23-byte UPDATE framing.
    passed = bgp_builder_append(&builder, NULL, 0, NULL, 0, payload, UINT16_MAX - 23) == 0 &&
             builder.result->message_lens[0] == UINT16_MAX;
    bgp_builder_clear(&builder);
    passed &= bgp_builder_append(&builder, NULL, 0, NULL, 0, payload, UINT16_MAX - 22) < 0;
    passed &= bgp_builder_append(&builder, payload, 32768, payload, 32768, NULL, 0) < 0;
    passed &= bgp_builder_append(&builder, NULL, 1, NULL, 0, NULL, 0) < 0;
    passed &= bgp_builder_append(&builder, NULL, 0, NULL, 1, NULL, 0) < 0;
    passed &= bgp_builder_append(&builder, NULL, 0, NULL, 0, NULL, 1) < 0;
    bgp_mp_args_t args = {.afi = AFI_IPV4, .safi = SAFI_UNICAST, .mp_nlri = payload,
                          .mp_nlri_len = UINT16_MAX - 30};
    passed &= bgp_builder_append_mp(&builder, &args) == 0 &&
              builder.result->message_lens[0] == UINT16_MAX;
    bgp_builder_clear(&builder);
    args.mp_nlri_len++;
    passed &= bgp_builder_append_mp(&builder, &args) < 0;
    args.mp_nlri_len = UINT16_MAX;
    passed &= bgp_builder_append_mp(&builder, &args) < 0;
    args.mp_nlri_len = 32768;
    args.attrs = payload;
    args.attrs_len = 32768;
    passed &= bgp_builder_append_mp(&builder, &args) < 0;
    args = (bgp_mp_args_t){.is_reach = 1, .nh_len = 4};
    passed &= bgp_builder_append_mp(&builder, &args) < 0;
    args = (bgp_mp_args_t){.mp_nlri_len = 1};
    passed &= bgp_builder_append_mp(&builder, &args) < 0;
    passed &= bgp_builder_append_mp(&builder, NULL) < 0 && builder.result->num_messages == 0;
    bgp_builder_release(&builder);
    free(payload);
    test_result(passed, "Builder rejects overflow and missing payloads without appending messages");
}

static void test_core_encoder_bounds(void) {
    uint8_t               wire[64] = {0}, *serialized = NULL;
    uint16_t              len = 0;
    ipv4_prefix_t         v4 = {.prefix_len = 33};
    ipv6_prefix_t         v6 = {.prefix_len = 129};
    labeled_ipv4_prefix_t l4 = {.prefix_len = 57};
    labeled_ipv6_prefix_t l6 = {.prefix_len = 153};
    int passed = bgp_encode_ipv4_prefix(wire, &v4) < 0 && bgp_encode_ipv6_prefix(wire, &v6) < 0 &&
                 bgp_encode_labeled_ipv4_prefix(wire, &l4) < 0 &&
                 bgp_encode_labeled_ipv6_prefix(wire, &l6) < 0;
    passed &= ipv4_nlri_create("bad", 24) == NULL && ipv6_nlri_create("192.0.2.1", 64) == NULL &&
              labeled_ipv4_nlri_create("10.0.0.0", 33, 100) == NULL &&
              labeled_ipv6_nlri_create("2001:db8::", 129, 100) == NULL;
    passed &= bgp_serialize_mp_reach_attr_alloc(1, 1, wire, 4, wire, UINT16_MAX, &serialized, &len) < 0;
    passed &= bgp_serialize_mp_unreach_attr_alloc(1, 1, wire, UINT16_MAX, &serialized, &len) < 0;
    passed &= bgp_serialize_mp_reach_attr(wire, 1, 1, wire, 4, wire, UINT16_MAX) < 0;
    passed &= bgp_serialize_mp_unreach_attr(wire, 1, 1, wire, UINT16_MAX) < 0;
    passed &= serialized == NULL && wire[0] == 0;
    ipv6_nlri_list_t *head = NULL, *tail = NULL;
    for (int i = 0; i < 4000; i++) ipv6_nlri_add_tail(&head, &tail, "2001:db8::1", 128);
    assert(ipv6_nlri_count(head) == 4000);
    bgp_path_attr_t *reach = bgp_attr_create_mp_reach_ipv6(NULL, head);
    bgp_path_attr_t *unreach = bgp_attr_create_mp_unreach_ipv6(head);
    passed &= !reach && !unreach;
    bgp_path_attr_free(reach);
    bgp_path_attr_free(unreach);
    ipv6_nlri_list_free(head);
    test_result(passed, "Core prefix and MP attribute encoders reject oversized input before writes");
}

int main() {
    printf("========================================\n");
    printf("BGP UPDATE Message Generation Tests\n");
    printf("========================================\n\n");

    test_ipv4_nlri_creation();
    test_ipv6_nlri_creation();
    test_origin_attribute();
    test_as_path_attribute();
    test_as_path_transition_attribute();
    test_next_hop_attribute();
    test_med_attribute();
    test_local_pref_attribute();
    test_mp_reach_nlri_ipv6();
    test_mp_unreach_nlri_ipv6();
    test_extended_length_serialization();
    test_simple_ipv4_update();
    test_ipv4_update_with_withdrawn();
    test_ipv4_update_splitting();
    test_simple_ipv6_update();
    test_ipv6_update_ipv4_next_hop();
    test_simple_labeled_ipv4_update();
    test_labeled_ipv4_rfc8950_update();
    test_labeled_ipv4_add_path_update();
    test_labeled_ipv4_withdrawn();
    test_simple_labeled_ipv6_update();
    test_labeled_ipv6_ipv4_next_hop_update();
    test_labeled_ipv6_add_path_update();
    test_labeled_ipv6_withdrawn();
    test_simple_ipv4_rfc8950_update();
    test_ipv4_rfc8950_add_path_update();
    test_ipv4_rfc8950_update_with_withdrawn();
    test_ipv4_add_path_update();
    test_ipv4_add_path_withdrawn();
    test_ipv6_update_with_withdrawn();
    test_ipv6_add_path_update();
    test_ipv6_add_path_withdrawn();
    test_mixed_add_path_rejected();
    test_ipv4_prefix_encoding();
    test_ipv6_prefix_encoding();
    test_large_ipv4_nlri();
    test_multiple_as_path_segments();
    test_missing_required_ipv4_attrs();
    test_empty_nlri();

    // Adversarial / boundary tests
    test_ipv4_prefix_len_zero();
    test_ipv4_prefix_len_32();
    test_ipv6_prefix_len_zero();
    test_ipv6_prefix_len_128();
    test_mpls_label_zero();
    test_mpls_label_max();
    test_mpls_label_overflow_masked();
    test_labeled_ipv4_prefix_len_too_short();
    test_labeled_ipv6_prefix_len_too_short();
    test_labeled_ipv4_prefix_len_exactly_24();
    test_labeled_ipv4_host_route();
    test_add_path_id_zero();
    test_add_path_id_max();
    test_extended_length_boundary();
    test_ipv6_next_hop_global_only();
    test_ipv6_next_hop_with_link_local();
    test_med_and_local_pref_boundaries();
    test_origin_all_values();
    test_ipv4_default_route_update();
    test_ipv6_host_route_update();
    test_as_set_segment();
    test_empty_as_path();
    test_reject_repeated_attribute_types();
    test_ext_comm_admin_layouts();
    test_serialize_as_path_attr();
    test_builder_clear_keeps_arrays();
    test_builder_bounds();
    test_core_encoder_bounds();

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
    }

    printf("%s %s\n\n", TEST_BADGE_FAIL, "Some tests failed");
    return 1;
}
