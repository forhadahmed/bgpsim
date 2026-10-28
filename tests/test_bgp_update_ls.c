/*
 * Unit tests for BGP-LS UPDATE message generation
 * Tests BGP Link-State (RFC 9552) encoder
 */

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

static uint64_t read_u64(const uint8_t *ptr) {
    uint64_t value;
    memcpy(&value, ptr, sizeof(value));
    return be64toh(value);
}

static int find_attr(const uint8_t *msg, size_t size, uint8_t type_code,
                     const uint8_t **value_out, uint16_t *length_out) {
    return test_wire_find_attr(msg, size, type_code, value_out, length_out, NULL);
}

static int has_attr(const uint8_t *msg, size_t size, uint8_t type_code) {
    return find_attr(msg, size, type_code, NULL, NULL);
}

/*
 * Test 1: TLV creation and encoding
 */
void test_tlv_create_and_encode() {
    uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
    bgpls_tlv_t *tlv = bgpls_tlv_create(512, 4, data);
    uint8_t      buffer[64];
    int          len;

    assert(tlv != NULL);
    len = bgpls_encode_tlv(buffer, tlv);

    test_result((len == 8) &&
                (read_u16(buffer) == 512) &&
                (read_u16(buffer + 2) == 4) &&
                (memcmp(buffer + 4, data, 4) == 0),
                "TLV create and encode");
    bgpls_tlv_list_free(tlv);
}

/*
 * Test 2: TLV chain encoding
 */
void test_tlv_chain_encode() {
    bgpls_tlv_t *as_tlv = bgpls_tlv_create_as(65001);
    bgpls_tlv_t *id_data;
    uint8_t router_id[] = {10, 0, 0, 1};
    uint8_t buffer[64];
    int     len;

    assert(as_tlv != NULL);
    id_data = bgpls_tlv_create_igp_router_id(router_id, 4);
    assert(id_data != NULL);
    as_tlv->next = id_data;

    len = bgpls_encode_tlv_chain(buffer, as_tlv);

    /*
     * AS TLV: type(2) + len(2) + value(4) = 8
     * IGP Router ID TLV: type(2) + len(2) + value(4) = 8
     * Total = 16
     */
    test_result((len == 16) &&
                (read_u16(buffer) == BGPLS_TLV_AS) &&
                (read_u16(buffer + 2) == 4) &&
                (read_u32(buffer + 4) == 65001) &&
                (read_u16(buffer + 8) == BGPLS_TLV_IGP_ROUTER_ID) &&
                (read_u16(buffer + 10) == 4),
                "TLV chain encode");
    bgpls_tlv_list_free(as_tlv);
}

/*
 * Test 3: TLV chain wire length
 */
void test_tlv_chain_wire_len() {
    bgpls_tlv_t *as_tlv = bgpls_tlv_create_as(65001);
    bgpls_tlv_t *id_tlv = bgpls_tlv_create_bgpls_id(1);
    int          wire_len;

    assert(as_tlv != NULL);
    assert(id_tlv != NULL);
    as_tlv->next = id_tlv;

    wire_len = bgpls_tlv_chain_wire_len(as_tlv);

    // AS: 4+4=8, BGPLS_ID: 4+4=8, total=16
    test_result(wire_len == 16, "TLV chain wire length");
    bgpls_tlv_list_free(as_tlv);
}

/*
 * Test 4: Convenience TLV creators
 */
void test_convenience_tlv_creators() {
    bgpls_tlv_t *as_tlv = bgpls_tlv_create_as(65001);
    bgpls_tlv_t *id_tlv = bgpls_tlv_create_bgpls_id(42);
    bgpls_tlv_t *area_tlv = bgpls_tlv_create_ospf_area(0);
    bgpls_tlv_t *iface_tlv = bgpls_tlv_create_ipv4_iface(0x0A000001);
    bgpls_tlv_t *neighbor_tlv = bgpls_tlv_create_ipv4_neighbor(0x0A000002);
    uint8_t ipv6_iface[] = {
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 1
    };
    uint8_t ipv6_neighbor[] = {
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 2
    };
    bgpls_tlv_t *iface6_tlv = bgpls_tlv_create_ipv6_iface(ipv6_iface);
    bgpls_tlv_t *neighbor6_tlv = bgpls_tlv_create_ipv6_neighbor(ipv6_neighbor);
    bgpls_tlv_t *llr_tlv = bgpls_tlv_create_link_local_remote(100, 200);
    uint8_t      buffer[64];
    int          passed = 1;

    passed = passed && (as_tlv != NULL) && (as_tlv->type == BGPLS_TLV_AS);
    passed = passed && (id_tlv != NULL) && (id_tlv->type == BGPLS_TLV_BGPLS_ID);
    passed = passed && (area_tlv != NULL) && (area_tlv->type == BGPLS_TLV_OSPF_AREA);
    passed = passed && (iface_tlv != NULL) && (iface_tlv->type == BGPLS_TLV_IPV4_IFACE_ADDR);
    passed = passed && (neighbor_tlv != NULL) && (neighbor_tlv->type == BGPLS_TLV_IPV4_NEIGHBOR_ADDR);
    passed = passed && (iface6_tlv != NULL) && (iface6_tlv->type == BGPLS_TLV_IPV6_IFACE_ADDR) &&
             (iface6_tlv->length == 16) &&
             (memcmp(iface6_tlv->value, ipv6_iface, 16) == 0);
    passed = passed && (neighbor6_tlv != NULL) &&
             (neighbor6_tlv->type == BGPLS_TLV_IPV6_NEIGHBOR_ADDR) &&
             (neighbor6_tlv->length == 16) &&
             (memcmp(neighbor6_tlv->value, ipv6_neighbor, 16) == 0);
    passed = passed && (llr_tlv != NULL) && (llr_tlv->type == BGPLS_TLV_LINK_LOCAL_REMOTE) &&
             (llr_tlv->length == 8);

    // Verify link local/remote values
    if (passed) {
        bgpls_encode_tlv(buffer, llr_tlv);
        passed = passed && (read_u32(buffer + 4) == 100) &&
                 (read_u32(buffer + 8) == 200);
    }

    bgpls_tlv_list_free(as_tlv);
    bgpls_tlv_list_free(id_tlv);
    bgpls_tlv_list_free(area_tlv);
    bgpls_tlv_list_free(iface_tlv);
    bgpls_tlv_list_free(neighbor_tlv);
    bgpls_tlv_list_free(iface6_tlv);
    bgpls_tlv_list_free(neighbor6_tlv);
    bgpls_tlv_list_free(llr_tlv);
    test_result(passed, "Convenience TLV creators");
}

/*
 * Test 5: IGP Router ID with various lengths
 */
void test_igp_router_id_lengths() {
    uint8_t id4[] = {10, 0, 0, 1};
    uint8_t id6[] = {0x00, 0x00, 0x00, 0x01, 0x00, 0x00};
    uint8_t id7[] = {0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x02};
    uint8_t id8[] = {0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02};
    uint8_t id16[] = {
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 1
    };
    bgpls_tlv_t *tlv4 = bgpls_tlv_create_igp_router_id(id4, 4);
    bgpls_tlv_t *tlv6 = bgpls_tlv_create_igp_router_id(id6, 6);
    bgpls_tlv_t *tlv7 = bgpls_tlv_create_igp_router_id(id7, 7);
    bgpls_tlv_t *tlv8 = bgpls_tlv_create_igp_router_id(id8, 8);
    bgpls_tlv_t *tlv16 = bgpls_tlv_create_igp_router_id(id16, 16);
    bgpls_tlv_t *tlv0 = bgpls_tlv_create_igp_router_id(id4, 0);
    bgpls_tlv_t *tlv5 = bgpls_tlv_create_igp_router_id(id4, 5);
    bgpls_tlv_t *tlv9 = bgpls_tlv_create_igp_router_id(id16, 9);

    test_result((tlv4 != NULL) && (tlv4->length == 4) &&
                (tlv6 != NULL) && (tlv6->length == 6) &&
                (tlv7 != NULL) && (tlv7->length == 7) &&
                (tlv8 != NULL) && (tlv8->length == 8) &&
                (tlv16 != NULL) && (tlv16->length == 16) &&
                (tlv0 == NULL) && (tlv5 == NULL) && (tlv9 == NULL),
                "IGP Router ID lengths (4, 6, 7, 8, 16 ok; 0, 5, 9 rejected)");

    bgpls_tlv_list_free(tlv4);
    bgpls_tlv_list_free(tlv6);
    bgpls_tlv_list_free(tlv7);
    bgpls_tlv_list_free(tlv8);
    bgpls_tlv_list_free(tlv16);
}

/*
 * Test 6: Node descriptor builder
 */
void test_node_desc_create() {
    uint8_t router_id[] = {10, 0, 0, 1};
    bgpls_tlv_t *desc = bgpls_node_desc_create(65001, router_id, 4);
    uint8_t      buffer[128];
    int          len;

    assert(desc != NULL);
    len = bgpls_encode_tlv(buffer, desc);

    /*
     * Container TLV: type(2) + len(2) + sub-TLVs
     * Sub-TLVs: AS(8) + IGP Router ID(8) = 16
     * Total: 4 + 16 = 20
     */
    test_result((len == 20) &&
                (read_u16(buffer) == BGPLS_TLV_LOCAL_NODE_DESC) &&
                (read_u16(buffer + 2) == 16),
                "Node descriptor builder");
    bgpls_tlv_list_free(desc);
}

/*
 * Test 7: Node NLRI creation
 */
void test_node_nlri_creation() {
    uint8_t router_id[] = {10, 0, 0, 1};
    bgpls_tlv_t  *desc = bgpls_node_desc_create(65001, router_id, 4);
    bgpls_nlri_t *nlri = bgpls_nlri_create_node(BGPLS_PROTO_OSPFV2, 100, desc);

    assert(nlri != NULL);
    test_result((nlri->prefix.nlri_type == BGPLS_NLRI_NODE) &&
                (nlri->prefix.protocol_id == BGPLS_PROTO_OSPFV2) &&
                (nlri->prefix.identifier == 100) &&
                (nlri->prefix.local_node_descriptors != NULL) &&
                (nlri->add_path == 0),
                "Node NLRI creation");
    bgpls_nlri_list_free(nlri);
}

/*
 * Test 8: Node NLRI encoding
 */
void test_node_nlri_encoding() {
    uint8_t router_id[] = {10, 0, 0, 1};
    bgpls_tlv_t  *desc = bgpls_node_desc_create(65001, router_id, 4);
    bgpls_nlri_t *nlri = bgpls_nlri_create_node(BGPLS_PROTO_OSPFV2, 100, desc);
    uint8_t       buffer[256];
    int           len;

    assert(nlri != NULL);
    len = bgp_encode_bgpls_prefix(buffer, &nlri->prefix);

    // type(2) + length(2) + proto(1) + id(8) + local_desc_tlv(20) = 33
    test_result((len == 33) &&
                (read_u16(buffer) == BGPLS_NLRI_NODE) &&
                (read_u16(buffer + 2) == 29) &&    /* body length: 1+8+20 */
                (buffer[4] == BGPLS_PROTO_OSPFV2) &&
                (read_u64(buffer + 5) == 100),
                "Node NLRI encoding");
    bgpls_nlri_list_free(nlri);
}

/*
 * Test 9: Link NLRI creation and encoding
 */
void test_link_nlri_creation() {
    uint8_t local_id[] = {10, 0, 0, 1};
    uint8_t remote_id[] = {10, 0, 0, 2};
    bgpls_tlv_t  *local_desc = bgpls_node_desc_create(65001, local_id, 4);
    bgpls_tlv_t  *remote_desc_raw;
    bgpls_tlv_t  *link_desc;
    bgpls_tlv_t  *link_neighbor;
    bgpls_nlri_t *nlri;
    uint8_t       buffer[512];
    int           len;

    // Build remote node descriptor as a container TLV (type 257)
    {
        bgpls_tlv_t *as_tlv = bgpls_tlv_create_as(65002);
        bgpls_tlv_t *id_tlv = bgpls_tlv_create_igp_router_id(remote_id, 4);
        int          sub_len;
        uint8_t     *sub_buf;

        as_tlv->next = id_tlv;
        sub_len = bgpls_tlv_chain_wire_len(as_tlv);
        sub_buf = malloc((size_t)sub_len);
        bgpls_encode_tlv_chain(sub_buf, as_tlv);
        bgpls_tlv_list_free(as_tlv);
        remote_desc_raw = bgpls_tlv_create(BGPLS_TLV_REMOTE_NODE_DESC, (uint16_t)sub_len, sub_buf);
        free(sub_buf);
    }

    link_desc = bgpls_tlv_create_ipv4_iface(0x0A000001);
    link_neighbor = bgpls_tlv_create_ipv4_neighbor(0x0A000002);
    assert(link_desc != NULL);
    assert(link_neighbor != NULL);
    link_desc->next = link_neighbor;

    nlri = bgpls_nlri_create_link(BGPLS_PROTO_OSPFV2, 200, local_desc, remote_desc_raw, link_desc);
    assert(nlri != NULL);

    len = bgp_encode_bgpls_prefix(buffer, &nlri->prefix);

    test_result((len > 0) &&
                (read_u16(buffer) == BGPLS_NLRI_LINK) &&
                (buffer[4] == BGPLS_PROTO_OSPFV2) &&
                (read_u64(buffer + 5) == 200) &&
                (nlri->prefix.local_node_descriptors != NULL) &&
                (nlri->prefix.remote_node_descriptors != NULL) &&
                (nlri->prefix.link_descriptors != NULL),
                "Link NLRI creation and encoding");
    bgpls_nlri_list_free(nlri);
}

/*
 * Test 10: IPv4 Prefix NLRI creation
 */
void test_prefix_ipv4_nlri_creation() {
    uint8_t router_id[] = {10, 0, 0, 1};
    bgpls_tlv_t *desc = bgpls_node_desc_create(65001, router_id, 4);
    uint8_t prefix_data[] = {24, 192, 168, 1};
    bgpls_tlv_t  *prefix_desc = bgpls_tlv_create(BGPLS_TLV_IP_REACH_INFO, 4, prefix_data);
    bgpls_nlri_t *nlri;
    uint8_t       buffer[256];
    int           len;

    nlri = bgpls_nlri_create_prefix_ipv4(BGPLS_PROTO_OSPFV2, 300, desc, prefix_desc);
    assert(nlri != NULL);

    len = bgp_encode_bgpls_prefix(buffer, &nlri->prefix);

    test_result((len > 0) &&
                (read_u16(buffer) == BGPLS_NLRI_IPV4_PREFIX) &&
                (nlri->prefix.prefix_descriptors != NULL),
                "IPv4 Prefix NLRI creation");
    bgpls_nlri_list_free(nlri);
}

/*
 * Test 11: IPv6 Prefix NLRI creation
 */
void test_prefix_ipv6_nlri_creation() {
    uint8_t router_id[] = {0x19, 0x20, 0x00, 0x00, 0x20, 0x01};
    bgpls_tlv_t *desc = bgpls_node_desc_create(65001, router_id, 6);
    uint8_t prefix_data[] = {48, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01};
    bgpls_tlv_t  *prefix_desc = bgpls_tlv_create(BGPLS_TLV_IP_REACH_INFO, 7, prefix_data);
    bgpls_nlri_t *nlri;
    uint8_t       buffer[256];
    int           len;

    nlri = bgpls_nlri_create_prefix_ipv6(BGPLS_PROTO_ISIS_L2, 400, desc, prefix_desc);
    assert(nlri != NULL);

    len = bgp_encode_bgpls_prefix(buffer, &nlri->prefix);

    test_result((len > 0) && (read_u16(buffer) == BGPLS_NLRI_IPV6_PREFIX), "IPv6 Prefix NLRI creation");
    bgpls_nlri_list_free(nlri);
}

/*
 * Test 12: BGP-LS attribute (type 29)
 */
void test_bgpls_attribute() {
    uint8_t metric_data[] = {0x00, 0x00, 0x00, 0x0A};               /* metric = 10            */
    bgpls_tlv_t     *tlv = bgpls_tlv_create(1095, 4, metric_data);  /* type 1095 = IGP metric */
    bgp_path_attr_t *attr;

    assert(tlv != NULL);
    attr = bgp_attr_create_bgpls(tlv);
    assert(attr != NULL);

    // BGP-LS attr is optional, non-transitive
    test_result((attr->type_code == BGP_ATTR_BGP_LS) &&
                (attr->flags == BGP_ATTR_FLAG_OPTIONAL) &&
                (attr->length == 8) &&      /* type(2) + len(2) + value(4) */
                (read_u16(attr->value) == 1095) &&
                (read_u16(attr->value + 2) == 4) &&
                (read_u32(attr->value + 4) == 10),
                "BGP-LS attribute (type 29)");
    bgp_path_attr_free(attr);
    bgpls_tlv_list_free(tlv);
}

/*
 * Test 13: Full Node NLRI UPDATE with MP_REACH_NLRI
 */
void test_node_update_generation() {
    uint8_t router_id[] = {10, 0, 0, 1};
    bgpls_tlv_t     *desc = bgpls_node_desc_create(65001, router_id, 4);
    bgpls_nlri_t    *nlri = bgpls_nlri_create_node(BGPLS_PROTO_OSPFV2, 100, desc);
    bgp_path_attr_t *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_next_hop_t       next_hop = make_ipv4_next_hop("192.0.2.1");
    bgp_update_result_t *result;
    const uint8_t       *value = NULL;
    uint16_t             length = 0;
    int                  passed;

    origin->next = as_path;
    result = bgp_generate_update_bgpls(nlri, origin, NULL, 0, &next_hop);
    assert(result != NULL);

    // Verify MP_REACH_NLRI with AFI=16388, SAFI=71
    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI, &value, &length) &&
             (read_u16(value) == AFI_BGP_LS) &&
             (value[2] == SAFI_BGP_LS) &&
             (value[3] == 4);  /* IPv4 next-hop length */

    bgp_update_result_free(result);
    bgpls_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    test_result(passed, "Node UPDATE with MP_REACH_NLRI (AFI=16388, SAFI=71)");
}

/*
 * Test 14: UPDATE with IPv6 next-hop
 */
void test_bgpls_ipv6_next_hop() {
    uint8_t router_id[] = {10, 0, 0, 1};
    bgpls_tlv_t     *desc = bgpls_node_desc_create(65001, router_id, 4);
    bgpls_nlri_t    *nlri = bgpls_nlri_create_node(BGPLS_PROTO_OSPFV2, 100, desc);
    bgp_path_attr_t *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_next_hop_t       next_hop = make_ipv6_next_hop("2001:db8::1");
    bgp_update_result_t *result;
    const uint8_t       *value = NULL;
    uint16_t             length = 0;
    int                  passed;

    origin->next = as_path;
    result = bgp_generate_update_bgpls(nlri, origin, NULL, 0, &next_hop);
    assert(result != NULL);

    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI, &value, &length) &&
             (read_u16(value) == AFI_BGP_LS) &&
             (value[2] == SAFI_BGP_LS) &&
             (value[3] == 16);  /* IPv6 next-hop length */

    bgp_update_result_free(result);
    bgpls_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    test_result(passed, "BGP-LS IPv6 next-hop (16 bytes)");
}

/*
 * Test 15: Withdrawal uses MP_UNREACH_NLRI
 */
void test_bgpls_withdrawal() {
    uint8_t router_id[] = {10, 0, 0, 1};
    bgpls_tlv_t         *desc = bgpls_node_desc_create(65001, router_id, 4);
    bgpls_nlri_t        *withdrawn = bgpls_nlri_create_node(BGPLS_PROTO_OSPFV2, 100, desc);
    bgp_update_result_t *result;
    const uint8_t       *value = NULL;
    uint16_t             length = 0;
    int                  passed;

    result = bgp_generate_update_bgpls(NULL, NULL, withdrawn, 0, NULL);
    assert(result != NULL);

    passed = (result->num_messages == 1) &&
             find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_UNREACH_NLRI, &value, &length) &&
             (read_u16(value) == AFI_BGP_LS) &&
             (value[2] == SAFI_BGP_LS);

    bgp_update_result_free(result);
    bgpls_nlri_list_free(withdrawn);
    test_result(passed, "BGP-LS withdrawal (MP_UNREACH_NLRI)");
}

/*
 * Test 16: ADD-PATH support
 */
void test_bgpls_add_path() {
    uint8_t router_id[] = {10, 0, 0, 1};
    bgpls_tlv_t  *desc1 = bgpls_node_desc_create(65001, router_id, 4);
    bgpls_nlri_t *nlri1 = bgpls_nlri_create_node_path_id(BGPLS_PROTO_OSPFV2, 100, desc1, 42);
    uint8_t router_id2[] = {10, 0, 0, 2};
    bgpls_tlv_t     *desc2 = bgpls_node_desc_create(65002, router_id2, 4);
    bgpls_nlri_t    *nlri2 = bgpls_nlri_create_node_path_id(BGPLS_PROTO_OSPFV2, 100, desc2, 43);
    bgpls_nlri_t    *tail = nlri1;
    bgp_path_attr_t *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_next_hop_t       next_hop = make_ipv4_next_hop("192.0.2.1");
    bgp_update_result_t *result;
    const uint8_t       *value = NULL;
    uint16_t             length = 0;
    int                  offset = 0;
    int                  passed;

    bgpls_nlri_append(&nlri1, &tail, nlri2);
    origin->next = as_path;

    result = bgp_generate_update_bgpls(nlri1, origin, NULL, 0, &next_hop);
    assert(result != NULL);

    // First NLRI should have path_id=42
    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI, &value, &length) &&
             mp_reach_nlri_offset(value, length, &offset) &&
             (read_u32(value + offset) == 42);

    bgp_update_result_free(result);
    bgpls_nlri_list_free(nlri1);
    bgp_path_attr_list_free(origin);
    test_result(passed, "BGP-LS ADD-PATH");
}

/*
 * Test 17: NLRI list count and free
 */
void test_nlri_list_operations() {
    uint8_t id1[] = {10, 0, 0, 1};
    uint8_t id2[] = {10, 0, 0, 2};
    uint8_t id3[] = {10, 0, 0, 3};
    bgpls_nlri_t *list = NULL;
    bgpls_nlri_t *tail = NULL;
    bgpls_nlri_t *n1, *n2, *n3;

    n1 = bgpls_nlri_create_node(BGPLS_PROTO_OSPFV2, 1, bgpls_node_desc_create(65001, id1, 4));
    n2 = bgpls_nlri_create_node(BGPLS_PROTO_OSPFV2, 2, bgpls_node_desc_create(65002, id2, 4));
    n3 = bgpls_nlri_create_node(BGPLS_PROTO_OSPFV2, 3, bgpls_node_desc_create(65003, id3, 4));

    bgpls_nlri_append(&list, &tail, n1);
    bgpls_nlri_append(&list, &tail, n2);
    bgpls_nlri_append(&list, &tail, n3);

    test_result(bgpls_nlri_count(list) == 3, "NLRI list count");
    bgpls_nlri_list_free(list);
}

/*
 * Test 18: Wire format: NLRI type/length/protocol/identifier
 */
void test_wire_format_header() {
    uint8_t router_id[] = {0x19, 0x20, 0x00, 0x00, 0x20, 0x01};
    bgpls_tlv_t  *desc = bgpls_node_desc_create(65001, router_id, 6);
    bgpls_nlri_t *nlri = bgpls_nlri_create_node(BGPLS_PROTO_ISIS_L1, 0x0102030405060708ULL, desc);
    uint8_t       buffer[256];

    assert(nlri != NULL);
    bgp_encode_bgpls_prefix(buffer, &nlri->prefix);

    test_result((read_u16(buffer) == 1) &&                        /* NLRI type = Node */
                (buffer[4] == BGPLS_PROTO_ISIS_L1) &&             /* Protocol ID      */
                (read_u64(buffer + 5) == 0x0102030405060708ULL),  /* Identifier       */
                "Wire format header (type/proto/id)");
    bgpls_nlri_list_free(nlri);
}

/*
 * Test 19: Multiple NLRI in one UPDATE
 */
void test_multiple_nlri_update() {
    bgpls_nlri_t    *list = NULL;
    bgpls_nlri_t    *tail = NULL;
    bgp_path_attr_t *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_next_hop_t       next_hop = make_ipv4_next_hop("192.0.2.1");
    bgp_update_result_t *result;
    int                  passed;
    int                  i;

    for (i = 0; i < 5; i++) {
        uint8_t       rid[4];
        bgpls_tlv_t  *desc;
        bgpls_nlri_t *n;

        rid[0] = 10; rid[1] = 0; rid[2] = 0; rid[3] = (uint8_t)(i + 1);
        desc = bgpls_node_desc_create(65001 + (uint32_t)i, rid, 4);
        n = bgpls_nlri_create_node(BGPLS_PROTO_OSPFV2, (uint64_t)i, desc);
        bgpls_nlri_append(&list, &tail, n);
    }

    origin->next = as_path;
    result = bgp_generate_update_bgpls(list, origin, NULL, 0, &next_hop);
    assert(result != NULL);

    passed = (result->num_messages >= 1) &&
             has_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI);

    bgp_update_result_free(result);
    bgpls_nlri_list_free(list);
    bgp_path_attr_list_free(origin);
    test_result(passed, "Multiple NLRI in one UPDATE");
}

/*
 * Test 20: Message splitting with small PDU size
 */
void test_message_splitting() {
    bgpls_nlri_t    *list = NULL;
    bgpls_nlri_t    *tail = NULL;
    bgp_path_attr_t *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_next_hop_t       next_hop = make_ipv4_next_hop("192.0.2.1");
    bgp_update_result_t *result;
    int                  passed;
    int                  i;

    for (i = 0; i < 30; i++) {
        uint8_t       rid[4];
        bgpls_tlv_t  *desc;
        bgpls_nlri_t *n;

        rid[0] = 10; rid[1] = 0; rid[2] = (uint8_t)(i / 256);
        rid[3] = (uint8_t)(i % 256);
        desc = bgpls_node_desc_create(65001 + (uint32_t)i, rid, 4);
        n = bgpls_nlri_create_node(BGPLS_PROTO_OSPFV2, (uint64_t)i, desc);
        bgpls_nlri_append(&list, &tail, n);
    }

    origin->next = as_path;
    result = bgp_generate_update_bgpls(list, origin, NULL, 256, &next_hop);
    assert(result != NULL);

    passed = (result->num_messages > 1);
    for (i = 0; i < result->num_messages; i++) {
        if (result->message_lens[i] > 256 ||
            test_wire_path_attr_len(result->messages[i], result->message_lens[i]) <= 0 ||
            !has_attr(result->messages[i], result->message_lens[i], BGP_ATTR_MP_REACH_NLRI)) {
            passed = 0;
        }
    }

    bgp_update_result_free(result);
    bgpls_nlri_list_free(list);
    bgp_path_attr_list_free(origin);
    test_result(passed, "BGP-LS message splitting");
}

/*
 * Test 21: Link NLRI UPDATE generation
 */
void test_link_update_generation() {
    uint8_t local_id[] = {10, 0, 0, 1};
    uint8_t remote_id[] = {10, 0, 0, 2};
    bgpls_tlv_t *local_desc = bgpls_node_desc_create(65001, local_id, 4);
    bgpls_tlv_t *as_tlv, *id_tlv;
    int              sub_len;
    uint8_t         *sub_buf;
    bgpls_tlv_t     *remote_desc;
    bgpls_tlv_t     *link_desc = bgpls_tlv_create_link_local_remote(1, 2);
    bgpls_nlri_t    *nlri;
    bgp_path_attr_t *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_next_hop_t       next_hop = make_ipv4_next_hop("192.0.2.1");
    bgp_update_result_t *result;
    const uint8_t       *value = NULL;
    uint16_t             length = 0;
    int                  nlri_offset = 0;
    int                  passed;

    as_tlv = bgpls_tlv_create_as(65002);
    id_tlv = bgpls_tlv_create_igp_router_id(remote_id, 4);
    as_tlv->next = id_tlv;
    sub_len = bgpls_tlv_chain_wire_len(as_tlv);
    sub_buf = malloc((size_t)sub_len);
    bgpls_encode_tlv_chain(sub_buf, as_tlv);
    bgpls_tlv_list_free(as_tlv);
    remote_desc = bgpls_tlv_create(BGPLS_TLV_REMOTE_NODE_DESC, (uint16_t)sub_len, sub_buf);
    free(sub_buf);

    nlri = bgpls_nlri_create_link(BGPLS_PROTO_OSPFV2, 500, local_desc, remote_desc, link_desc);
    origin->next = as_path;

    result = bgp_generate_update_bgpls(nlri, origin, NULL, 0, &next_hop);
    assert(result != NULL);

    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_REACH_NLRI, &value, &length) &&
             mp_reach_nlri_offset(value, length, &nlri_offset);

    // Verify NLRI type = 2 (Link) at start of NLRI data
    if (passed) {
        passed = (read_u16(value + nlri_offset) == BGPLS_NLRI_LINK);
    }

    bgp_update_result_free(result);
    bgpls_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
    test_result(passed, "Link NLRI UPDATE generation");
}

/*
 * Test 22: Protocol ID encoding for all types
 */
void test_protocol_id_encoding() {
    uint8_t rid_isis[] = {0x19, 0x20, 0x00, 0x00, 0x20, 0x01};
    uint8_t rid_ospf[] = {10, 0, 0, 1};
    uint8_t protocols[] = {
        BGPLS_PROTO_ISIS_L1, BGPLS_PROTO_ISIS_L2, BGPLS_PROTO_OSPFV2,
        BGPLS_PROTO_DIRECT, BGPLS_PROTO_STATIC, BGPLS_PROTO_OSPFV3
    };
    uint8_t buffer[256];
    int     passed = 1;
    int     i;

    for (i = 0; i < 6; i++) {
        const uint8_t *rid = rid_ospf;
        uint16_t       rid_len = 4;
        bgpls_tlv_t   *desc;
        bgpls_nlri_t  *nlri;

        if (protocols[i] == BGPLS_PROTO_ISIS_L1 ||
            protocols[i] == BGPLS_PROTO_ISIS_L2) {
            rid = rid_isis;
            rid_len = 6;
        }

        desc = bgpls_node_desc_create(65001, rid, rid_len);
        nlri = bgpls_nlri_create_node(protocols[i], 0, desc);

        bgp_encode_bgpls_prefix(buffer, &nlri->prefix);
        if (buffer[4] != protocols[i]) {
            passed = 0;
        }
        bgpls_nlri_list_free(nlri);
    }

    test_result(passed, "Protocol ID encoding (all 6 types)");
}

/*
 * Test 23: BGP-LS attribute with empty TLV chain
 */
void test_bgpls_attr_empty() {
    bgp_path_attr_t *attr = bgp_attr_create_bgpls(NULL);

    assert(attr != NULL);
    test_result((attr->type_code == BGP_ATTR_BGP_LS) && (attr->length == 0), "BGP-LS attribute with empty TLV chain");
    bgp_path_attr_free(attr);
}

/*
 * Test 24: TLV append
 */
void test_tlv_append() {
    bgpls_tlv_t *head = NULL;
    bgpls_tlv_t *tail = NULL;

    bgpls_tlv_append(&head, &tail, bgpls_tlv_create_as(1));
    bgpls_tlv_append(&head, &tail, bgpls_tlv_create_as(2));
    bgpls_tlv_append(&head, &tail, bgpls_tlv_create_as(3));

    test_result((head != NULL) && (tail != NULL) &&
                (head != tail) &&
                (head->next != NULL) &&
                (head->next->next == tail),
                "TLV append");
    bgpls_tlv_list_free(head);
}

/*
 * Test 25: Withdrawal NLRI wire format verification
 */
void test_withdrawal_wire_format() {
    uint8_t router_id[] = {10, 0, 0, 1};
    bgpls_tlv_t         *desc = bgpls_node_desc_create(65001, router_id, 4);
    bgpls_nlri_t        *withdrawn = bgpls_nlri_create_node(BGPLS_PROTO_OSPFV2, 100, desc);
    bgp_update_result_t *result;
    const uint8_t       *value = NULL;
    uint16_t             length = 0;
    int                  offset = 0;
    int                  passed;

    result = bgp_generate_update_bgpls(NULL, NULL, withdrawn, 0, NULL);
    assert(result != NULL);

    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_UNREACH_NLRI, &value, &length) &&
             mp_unreach_nlri_offset(value, length, &offset);

    // Verify NLRI starts at offset and has Node type
    if (passed) {
        passed = (read_u16(value + offset) == BGPLS_NLRI_NODE);
    }

    bgp_update_result_free(result);
    bgpls_nlri_list_free(withdrawn);
    test_result(passed, "Withdrawal wire format");
}

/*
 * Test 26: ADD-PATH withdrawal
 */
void test_add_path_withdrawal() {
    uint8_t router_id[] = {10, 0, 0, 1};
    bgpls_tlv_t         *desc = bgpls_node_desc_create(65001, router_id, 4);
    bgpls_nlri_t        *withdrawn = bgpls_nlri_create_node_path_id(BGPLS_PROTO_OSPFV2, 100, desc, 999);
    bgp_update_result_t *result;
    const uint8_t       *value = NULL;
    uint16_t             length = 0;
    int                  offset = 0;
    int                  passed;

    result = bgp_generate_update_bgpls(NULL, NULL, withdrawn, 0, NULL);
    assert(result != NULL);

    passed = find_attr(result->messages[0], result->message_lens[0], BGP_ATTR_MP_UNREACH_NLRI, &value, &length) &&
             mp_unreach_nlri_offset(value, length, &offset) &&
             (read_u32(value + offset) == 999);

    bgp_update_result_free(result);
    bgpls_nlri_list_free(withdrawn);
    test_result(passed, "ADD-PATH withdrawal (path_id=999)");
}

/*
 * Test 27: Empty Node NLRI is rejected because Local Node Descriptors are
 * mandatory for all currently supported BGP-LS NLRI types.
 */
void test_empty_node_nlri_rejected() {
    bgpls_nlri_t *nlri = bgpls_nlri_create_node(BGPLS_PROTO_OSPFV2, 0, NULL);
    uint8_t       buffer[256];

    assert(nlri != NULL);
    test_result(bgp_encode_bgpls_prefix(buffer, &nlri->prefix) < 0, "Empty Node NLRI rejected");
    bgpls_nlri_list_free(nlri);
}

/*
 * Test 28: Node Descriptor sub-TLVs must be in ascending order.
 */
void test_unsorted_node_descriptor_rejected() {
    uint8_t router_id[] = {10, 0, 0, 1};
    bgpls_tlv_t  *router = bgpls_tlv_create_igp_router_id(router_id, 4);
    bgpls_tlv_t  *as = bgpls_tlv_create_as(65001);
    bgpls_tlv_t  *desc;
    uint8_t      *sub_buf;
    int           sub_len;
    bgpls_nlri_t *nlri;
    uint8_t       buffer[256];

    assert(router != NULL);
    assert(as != NULL);

    /*
     * Build the serialized Node Descriptor in reverse order on purpose:
     * IGP Router-ID (515) before AS (512).  RFC 9552 requires ascending
     * sub-TLV ordering, so strict mode must reject this.
     */
    router->next = as;
    sub_len = bgpls_tlv_chain_wire_len(router);
    sub_buf = malloc((size_t)sub_len);
    assert(sub_buf != NULL);
    bgpls_encode_tlv_chain(sub_buf, router);
    bgpls_tlv_list_free(router);

    desc = bgpls_tlv_create(BGPLS_TLV_LOCAL_NODE_DESC, (uint16_t)sub_len, sub_buf);
    free(sub_buf);
    assert(desc != NULL);

    nlri = bgpls_nlri_create_node(BGPLS_PROTO_OSPFV2, 100, desc);
    assert(nlri != NULL);

    test_result(bgp_encode_bgpls_prefix(buffer, &nlri->prefix) < 0, "Unsorted Node Descriptor rejected");
    bgpls_nlri_list_free(nlri);
}

/*
 * Test 29: Prefix NLRIs need the mandatory IP Reachability Information TLV.
 */
void test_prefix_without_reachability_rejected() {
    uint8_t router_id[] = {10, 0, 0, 1};
    bgpls_tlv_t  *desc = bgpls_node_desc_create(65001, router_id, 4);
    bgpls_tlv_t  *prefix_desc = bgpls_tlv_create(BGPLS_TLV_MT_ID, 2, (const uint8_t[]){0x00, 0x00});
    bgpls_nlri_t *nlri;
    uint8_t       buffer[256];

    assert(desc != NULL);
    assert(prefix_desc != NULL);
    nlri = bgpls_nlri_create_prefix_ipv4(BGPLS_PROTO_OSPFV2, 300, desc, prefix_desc);
    assert(nlri != NULL);

    test_result(bgp_encode_bgpls_prefix(buffer, &nlri->prefix) < 0, "Prefix NLRI without reachability rejected");
    bgpls_nlri_list_free(nlri);
}

/*
 * Test 30: Link descriptors cannot mix local/remote identifiers with
 * interface+neighbor address pairs in strict RFC 9552 mode.
 */
void test_link_descriptor_mix_rejected() {
    uint8_t local_id[] = {10, 0, 0, 1};
    uint8_t remote_id[] = {10, 0, 0, 2};
    bgpls_tlv_t  *local_desc = bgpls_node_desc_create(65001, local_id, 4);
    bgpls_tlv_t  *remote_desc_raw;
    bgpls_tlv_t  *link_desc = bgpls_tlv_create_link_local_remote(1, 2);
    bgpls_tlv_t  *neighbor = bgpls_tlv_create_ipv4_neighbor(0x0A000002);
    bgpls_nlri_t *nlri;
    uint8_t       buffer[512];

    assert(local_desc != NULL);
    assert(link_desc != NULL);
    assert(neighbor != NULL);

    link_desc->next = neighbor;

    {
        bgpls_tlv_t *as_tlv = bgpls_tlv_create_as(65002);
        bgpls_tlv_t *id_tlv = bgpls_tlv_create_igp_router_id(remote_id, 4);
        int          sub_len;
        uint8_t     *sub_buf;

        assert(as_tlv != NULL);
        assert(id_tlv != NULL);
        as_tlv->next = id_tlv;
        sub_len = bgpls_tlv_chain_wire_len(as_tlv);
        sub_buf = malloc((size_t)sub_len);
        assert(sub_buf != NULL);
        bgpls_encode_tlv_chain(sub_buf, as_tlv);
        bgpls_tlv_list_free(as_tlv);
        remote_desc_raw = bgpls_tlv_create(BGPLS_TLV_REMOTE_NODE_DESC, (uint16_t)sub_len, sub_buf);
        free(sub_buf);
    }

    assert(remote_desc_raw != NULL);
    nlri = bgpls_nlri_create_link(BGPLS_PROTO_OSPFV2, 200, local_desc, remote_desc_raw, link_desc);
    assert(nlri != NULL);

    test_result(bgp_encode_bgpls_prefix(buffer, &nlri->prefix) < 0,
                "Link Descriptor local/remote + address mix rejected");
    bgpls_nlri_list_free(nlri);
}

/*
 * Test 31: BGP-LS uses a single global IPv6 next-hop, not the 32-byte
 * global+link-local form used by some other AFI/SAFIs.
 */
void test_bgpls_ipv6_link_local_next_hop_rejected() {
    uint8_t router_id[] = {10, 0, 0, 1};
    bgpls_tlv_t     *desc = bgpls_node_desc_create(65001, router_id, 4);
    bgpls_nlri_t    *nlri = bgpls_nlri_create_node(BGPLS_PROTO_OSPFV2, 100, desc);
    bgp_path_attr_t *origin = bgp_attr_create_origin(BGP_ORIGIN_IGP);
    uint32_t asns[] = {65001};
    as_path_segment_t    segment = {BGP_AS_SEQUENCE, 1, asns};
    bgp_path_attr_t     *as_path = bgp_attr_create_as_path(&segment, 1);
    bgp_next_hop_t       next_hop = make_ipv6_next_hop("2001:db8::1");
    bgp_update_result_t *result;

    origin->next = as_path;
    next_hop.has_link_local = 1;
    inet_pton(AF_INET6, "fe80::1", &next_hop.link_local);

    result = bgp_generate_update_bgpls(nlri, origin, NULL, 0, &next_hop);

    test_result(result == NULL, "BGP-LS IPv6 global+link-local next-hop rejected");
    bgpls_nlri_list_free(nlri);
    bgp_path_attr_list_free(origin);
}

static void test_invalid_nlri_update_rejected(void) {
    uint8_t       router_id[4] = {1, 2, 3, 4};
    bgpls_nlri_t *nlri = bgpls_nlri_create_node(BGPLS_PROTO_OSPFV2, 0, bgpls_node_desc_create(65000, router_id, 4));
    assert(nlri);
    nlri->prefix.protocol_id = 255;
    bgp_update_result_t *result = bgp_generate_update_bgpls(NULL, NULL, nlri, 0, NULL);
    test_result(result == NULL, "BGP-LS propagates invalid NLRI rejection before building UPDATEs");
    bgp_update_result_free(result);
    bgpls_nlri_list_free(nlri);
    bgpls_tlv_t *bad = bgpls_tlv_create(1234, 8, NULL);
    test_result(bad == NULL, "BGP-LS rejects absent nonempty TLV payload");
    bgpls_tlv_list_free(bad);
    // Valid Node Descriptor sub-TLVs whose aggregate body cannot fit its two-octet length.
    bgpls_tlv_t *local = bgpls_node_desc_create(65000, router_id, 4);
    assert(local && local->length == 16);
    uint8_t *large = calloc(UINT16_MAX, 1), *wire = malloc(70000);
    assert(large && wire);
    memcpy(large, local->value, 16);
    large[16] = 3;
    large[17] = 0xe8;  /* Unknown descriptor sub-TLV 1000 sorts after the router ID. */
    large[18] = 0xff;
    large[19] = 0xeb;  /* 65515 bytes complete the 65535-byte container.             */
    free(local->value);
    local->value = large;
    local->length = UINT16_MAX;
    bgpls_prefix_t prefix = {.nlri_type = BGPLS_NLRI_NODE, .protocol_id = BGPLS_PROTO_OSPFV2,
                             .local_node_descriptors = local};
    wire[0] = 0xaa;
    test_result(bgp_encode_bgpls_prefix(wire, &prefix) < 0 && wire[0] == 0xaa,
                "BGP-LS rejects aggregate NLRI length overflow before writing");
    bgpls_tlv_list_free(local);
    free(wire);
}

int main() {
    printf("========================================\n");
    printf("BGP-LS UPDATE Message Generation Tests\n");
    printf("========================================\n\n");

    test_tlv_create_and_encode();
    test_tlv_chain_encode();
    test_tlv_chain_wire_len();
    test_convenience_tlv_creators();
    test_igp_router_id_lengths();
    test_node_desc_create();
    test_node_nlri_creation();
    test_node_nlri_encoding();
    test_link_nlri_creation();
    test_prefix_ipv4_nlri_creation();
    test_prefix_ipv6_nlri_creation();
    test_bgpls_attribute();
    test_node_update_generation();
    test_bgpls_ipv6_next_hop();
    test_bgpls_withdrawal();
    test_bgpls_add_path();
    test_nlri_list_operations();
    test_wire_format_header();
    test_multiple_nlri_update();
    test_message_splitting();
    test_link_update_generation();
    test_protocol_id_encoding();
    test_bgpls_attr_empty();
    test_tlv_append();
    test_withdrawal_wire_format();
    test_add_path_withdrawal();
    test_empty_node_nlri_rejected();
    test_unsorted_node_descriptor_rejected();
    test_prefix_without_reachability_rejected();
    test_link_descriptor_mix_rejected();
    test_bgpls_ipv6_link_local_next_hop_rejected();
    test_invalid_nlri_update_rejected();

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
