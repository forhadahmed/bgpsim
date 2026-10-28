/*
 * BGP UPDATE Message Generation - BGP-LS Extensions
 * Implements BGP Link-State (RFC 9552) support
 */

#define OUTPUT_STDIO_REMAP

#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "bgp.h"
#include "output.h"
#include "bgp_update.h"

// TLV Helper Functions

bgpls_tlv_t* bgpls_tlv_create(uint16_t type, uint16_t length, const uint8_t *value) {
    if (length && !value) return NULL;
    bgpls_tlv_t *tlv = calloc(1, sizeof(bgpls_tlv_t));

    if (!tlv) {
        return NULL;
    }

    tlv->type = type;
    tlv->length = length;
    tlv->next = NULL;

    if (length > 0 && value) {
        tlv->value = malloc(length);
        if (!tlv->value) {
            free(tlv);
            return NULL;
        }
        memcpy(tlv->value, value, length);
    } else {
        tlv->value = NULL;
        tlv->length = 0;
    }

    return tlv;
}

bgpls_tlv_t* bgpls_tlv_create_u32(uint16_t type, uint32_t value) {
    uint32_t net_value = htonl(value);

    return bgpls_tlv_create(type, 4, (const uint8_t *)&net_value);
}

bgpls_tlv_t* bgpls_tlv_create_as(uint32_t as_number) {
    return bgpls_tlv_create_u32(BGPLS_TLV_AS, as_number);
}

bgpls_tlv_t* bgpls_tlv_create_bgpls_id(uint32_t bgpls_id) {
    return bgpls_tlv_create_u32(BGPLS_TLV_BGPLS_ID, bgpls_id);
}

bgpls_tlv_t* bgpls_tlv_create_ospf_area(uint32_t area_id) {
    return bgpls_tlv_create_u32(BGPLS_TLV_OSPF_AREA, area_id);
}

static int bgpls_igp_router_id_length_valid(uint16_t id_len) {
    return id_len == 4 || id_len == 6 || id_len == 7 || id_len == 8 ||
           id_len == 16;
}

bgpls_tlv_t* bgpls_tlv_create_igp_router_id(const uint8_t *id, uint16_t id_len) {
    if (!id || !bgpls_igp_router_id_length_valid(id_len)) {
        return NULL;
    }

    return bgpls_tlv_create(BGPLS_TLV_IGP_ROUTER_ID, id_len, id);
}

bgpls_tlv_t* bgpls_tlv_create_ipv4_iface(uint32_t addr) {
    uint32_t net_addr = htonl(addr);

    return bgpls_tlv_create(BGPLS_TLV_IPV4_IFACE_ADDR, 4, (const uint8_t *)&net_addr);
}

bgpls_tlv_t* bgpls_tlv_create_ipv4_neighbor(uint32_t addr) {
    uint32_t net_addr = htonl(addr);

    return bgpls_tlv_create(BGPLS_TLV_IPV4_NEIGHBOR_ADDR, 4, (const uint8_t *)&net_addr);
}

bgpls_tlv_t* bgpls_tlv_create_ipv6_iface(const uint8_t *addr) {
    if (!addr) {
        return NULL;
    }

    return bgpls_tlv_create(BGPLS_TLV_IPV6_IFACE_ADDR, 16, addr);
}

bgpls_tlv_t* bgpls_tlv_create_ipv6_neighbor(const uint8_t *addr) {
    if (!addr) {
        return NULL;
    }

    return bgpls_tlv_create(BGPLS_TLV_IPV6_NEIGHBOR_ADDR, 16, addr);
}

bgpls_tlv_t* bgpls_tlv_create_link_local_remote(uint32_t local_id, uint32_t remote_id) {
    uint8_t  buf[8];
    uint32_t net_local = htonl(local_id);
    uint32_t net_remote = htonl(remote_id);

    memcpy(buf, &net_local, 4);
    memcpy(buf + 4, &net_remote, 4);

    return bgpls_tlv_create(BGPLS_TLV_LINK_LOCAL_REMOTE, 8, buf);
}

void bgpls_tlv_append(bgpls_tlv_t **head, bgpls_tlv_t **tail, bgpls_tlv_t *tlv) {
    if (!tlv) {
        return;
    }

    if (*tail) {
        (*tail)->next = tlv;
        *tail = tlv;
    } else {
        *head = tlv;
        *tail = tlv;
    }
}

void bgpls_tlv_list_free(bgpls_tlv_t *list) {
    while (list) {
        bgpls_tlv_t *next = list->next;

        free(list->value);
        free(list);
        list = next;
    }
}

int bgpls_encode_tlv(uint8_t *buffer, const bgpls_tlv_t *tlv) {
    if (!buffer || !tlv || (tlv->length && !tlv->value)) return -1;
    int      offset = 0;
    uint16_t type_net = htons(tlv->type);
    uint16_t len_net = htons(tlv->length);

    /*
     * TODO(WIRE_MUTATION): Corrupt the 2-byte BGP-LS TLV type.
     *
     * RFC 9552 section 5.1 specifies TLVs as [Type(2) | Length(2) |
     * Value(variable)]. Unknown types MUST be preserved and
     * propagated (section 5.1), so corrupting type to an unknown
     * value tests whether the peer correctly passes it through or
     * incorrectly drops/rejects it.
     *
     * Additional framing-adjacent hazard: RFC 9552 section 5.1
     * REQUIRES NLRI TLVs to be in ascending order by Type. Mutating
     * one type value out of order makes the NLRI "malformed by a
     * BGP-LS Propagator" per the RFC, testing whether the peer
     * detects the ordering violation.
     *
     * Useful mutations:
     *   - Unknown type (e.g. 0xFFFF): tests unknown-TLV propagation
     *   - Type=0: reserved/invalid
     *   - Swap two adjacent TLV types to break ordering: tests
     *     "NLRI with out-of-order TLVs is malformed" enforcement
     *   - Duplicate an existing type: tests dup detection
     */
    memcpy(buffer + offset, &type_net, 2);
    offset += 2;
    /*
     * TODO(WIRE_MUTATION): Corrupt the 2-byte BGP-LS TLV length.
     *
     * HIGHEST FRAMING VALUE in the BGP-LS encoder
     *
     * BGP-LS is deeply nested: outer Link-State NLRI contains
     * descriptor TLVs (Node/Link/Prefix), each of which contains
     * sub-TLVs, some of which contain sub-sub-TLVs. Every level uses
     * this same 2-byte Length field.
     *
     * A wrong length at any level cascades to every sibling TLV at
     * that level AND to the parent's remaining value. Example:
     * corrupting the length of the Node Descriptor TLV inside a
     * Link NLRI causes the decoder to read the Remote Node
     * Descriptors TLV as part of the local Node Descriptors' value,
     * and then the Link descriptor TLVs get parsed starting inside
     * what was supposed to be a remote-node sub-TLV.
     *
     * Useful mutations:
     *
     *   - Shrink by 1 or 2 bytes:
     *       Tail of this TLV's value becomes the start of the next
     *       TLV's header. Next TLV's type byte is actually the last
     *       two bytes of value; every subsequent TLV at this level
     *       is misaligned.
     *
     *   - Grow by 1 or 2 bytes:
     *       Absorbs first bytes of next TLV header into this TLV's
     *       value. Next TLV walk hits a truncated type/length pair.
     *
     *   - Set to 0 (empty value):
     *       RFC 9552 says "a TLV with no value portion would have a
     *       length of zero". Legal for some types, malformed for
     *       types that require value. Tests type-specific length
     *       enforcement.
     *
     *   - Set to 0xFFFF:
     *       Claims value extends past parent TLV boundary / NLRI
     *       end / attribute end. Classic "length larger than
     *       container" bug class.
     *
     *   - Shrink below minimum for the declared type:
     *       e.g. Local Node Descriptors TLV with length < 4 when
     *       the smallest sub-TLV is 4 bytes. Decoder may walk into
     *       infinite loop trying to find the first valid sub-TLV.
     *
     * For any BGP-LS parser fuzz run, length-field mutation at
     * every nesting level is the primary target.
     */
    memcpy(buffer + offset, &len_net, 2);
    offset += 2;

    if (tlv->length > 0 && tlv->value) {
        memcpy(buffer + offset, tlv->value, tlv->length);
        offset += tlv->length;
        /*
         * TODO(WIRE_MUTATION): Corrupt BGP-LS TLV payload bytes.
         *
         * Value-level. Since each TLV value is opaque to the outer
         * framing (the length field bounds it), corrupting payload
         * bytes doesn't cascade to sibling TLVs. Interesting only
         * for per-type semantic validation (e.g. corrupting an
         * IPv4 address TLV to have odd byte count).
         */
    }

    return offset;
}

int bgpls_encode_tlv_chain(uint8_t *buffer, const bgpls_tlv_t *chain) {
    int offset = 0;

    while (chain) {
        int len = bgpls_encode_tlv(buffer + offset, chain);
        if (len < 0 || len > INT_MAX - offset) return -1;
        offset += len;
        chain = chain->next;
    }

    return offset;
}

int bgpls_tlv_chain_wire_len(const bgpls_tlv_t *chain) {
    int len = 0;

    while (chain) {
        if ((chain->length && !chain->value) || 4 + chain->length > INT_MAX - len) return -1;
        len += 4 + chain->length;  /* type(2) + length(2) + value */
        chain = chain->next;
    }

    return len;
}

static uint16_t bgpls_read_u16(const uint8_t *ptr) {
    uint16_t value;

    memcpy(&value, ptr, sizeof(value));
    return ntohs(value);
}

static int bgpls_protocol_id_supported(uint8_t protocol_id) {
    switch (protocol_id) {
        case BGPLS_PROTO_ISIS_L1:
        case BGPLS_PROTO_ISIS_L2:
        case BGPLS_PROTO_OSPFV2:
        case BGPLS_PROTO_DIRECT:
        case BGPLS_PROTO_STATIC:
        case BGPLS_PROTO_OSPFV3:
        case BGPLS_PROTO_BGP:
        case BGPLS_PROTO_SR:
            return 1;
        default:
            return 0;
    }
}

// BGP-LS Attribute TLV Layouts

#define REQ    BGPLS_FIELD_REQUIRED
#define STEP   (BGPLS_FIELD_REQUIRED | BGPLS_FIELD_STEP)
#define FLAGS   {"flags", BGPLS_FIELD_FLAGS8, 0}
#define ALGO    {"algorithm", BGPLS_FIELD_U8, 0}
#define WEIGHT  {"weight", BGPLS_FIELD_U8, 0}
#define ZERO8   {NULL, BGPLS_FIELD_ZERO8, 0}
#define ZERO16  {NULL, BGPLS_FIELD_ZERO16, 0}
#define SUBS    {"sub", BGPLS_FIELD_SUB_TLVS, 0}
#define NODE    BGPLS_ON_NODE
#define LINK    BGPLS_ON_LINK
#define PFX     BGPLS_ON_PREFIX
#define SID6    BGPLS_ON_SRV6_SID
#define CP      BGPLS_ON_SR_POLICY
#define FLAGS16 {"flags", BGPLS_FIELD_FLAGS16, 0}
#define U32(key, flags) {key, BGPLS_FIELD_U32, flags}
#define BW     {NULL, BGPLS_FIELD_BANDWIDTH, REQ}

// Flag layouts: IS-IS (RFC 8667) and, where it differs, OSPFv2/OSPFv3 (RFC 8665, RFC 8666).
#define ADJ_FLAGS    {"f,b,v,l,s,p", "b,v,l,g,p"}
#define PREFIX_FLAGS {"r,n,p,e,v,l", "-,np,m,e,v,l"}
#define SRV6_FLAGS   {"b,s,p", NULL}
#define PEER_FLAGS   {"v,l,b,p", NULL}

/*
 * RFC 9552 (base and TE), RFC 8571 (performance metrics), RFC 8814 (MSD), RFC 9085 (SR-MPLS), RFC 9104 (extended
 * administrative group), RFC 9514 (SRv6), RFC 9351 (Flexible Algorithm), RFC 9086 (BGP peering segments) and
 * RFC 9857 (SR Policy candidate path state). Fields
 * are in wire order. Sub-TLVs are fields of the TLV that carries them; a TLV that no NLRI type carries by itself
 * (mask 0) is valid only after `sub`.
 */
static const bgpls_attr_def_t bgpls_attr_defs[] = {
    {"raw", 0, NODE | LINK | PFX | SID6 | CP, {{"type", BGPLS_FIELD_U16, REQ}, {"value", BGPLS_FIELD_HEX, 0}}, {0}},
    {"mt-id", 263, NODE | LINK | PFX, {{NULL, BGPLS_FIELD_U16_LIST, REQ}}, {0}},
    {"node-msd", 266, NODE, {{NULL, BGPLS_FIELD_U8_LIST, REQ}}, {0}},
    {"link-msd", 267, LINK, {{NULL, BGPLS_FIELD_U8_LIST, REQ}}, {0}},
    {"node-flags", 1024, NODE, {{NULL, BGPLS_FIELD_FLAGS8, REQ}}, {"o,a,e,b,r,v", NULL}},
    {"node-opaque", 1025, NODE, {{NULL, BGPLS_FIELD_HEX, REQ}}, {0}},
    {"node-name", 1026, NODE, {{NULL, BGPLS_FIELD_TEXT, REQ}}, {0}},
    {"isis-area", 1027, NODE, {{NULL, BGPLS_FIELD_HEX, REQ}}, {0}},
    {"ipv4-router-id", 1028, NODE | LINK, {{NULL, BGPLS_FIELD_IPV4, STEP}}, {0}},
    {"ipv6-router-id", 1029, NODE | LINK, {{NULL, BGPLS_FIELD_IPV6, STEP}}, {0}},
    {"remote-ipv4-router-id", 1030, LINK, {{NULL, BGPLS_FIELD_IPV4, STEP}}, {0}},
    {"remote-ipv6-router-id", 1031, LINK, {{NULL, BGPLS_FIELD_IPV6, STEP}}, {0}},
    {"sr-capabilities", 1034, NODE, {FLAGS, ZERO8, {NULL, BGPLS_FIELD_RANGES, REQ}}, {"i,v", "-"}},
    {"sr-algorithm", 1035, NODE, {{NULL, BGPLS_FIELD_U8_LIST, REQ}}, {0}},
    {"sr-local-block", 1036, NODE, {FLAGS, ZERO8, {NULL, BGPLS_FIELD_RANGES, REQ}}, {0}},
    {"srms-preference", 1037, NODE, {{NULL, BGPLS_FIELD_U8, REQ}}, {0}},
    {"srv6-capabilities", 1038, NODE, {{"flags", BGPLS_FIELD_FLAGS16, 0}, ZERO16}, {"-,o", NULL}},
    // RFC 9351: the definition on a node with its sub-TLVs, and the per-algorithm metric of a prefix.
    {"flex-algo", 1039, NODE,
     {{NULL, BGPLS_FIELD_U8, REQ}, {"metric-type", BGPLS_FIELD_U8, 0}, {"calc-type", BGPLS_FIELD_U8, 0},
      {"priority", BGPLS_FIELD_U8, 0}, SUBS},
     {0}},
    {"exclude-any", 1040, 0, {{NULL, BGPLS_FIELD_U32_LIST, REQ}}, {0}},
    {"include-any", 1041, 0, {{NULL, BGPLS_FIELD_U32_LIST, REQ}}, {0}},
    {"include-all", 1042, 0, {{NULL, BGPLS_FIELD_U32_LIST, REQ}}, {0}},
    {"fad-flags", 1043, 0, {{NULL, BGPLS_FIELD_U32_LIST, REQ}}, {0}},
    {"flex-algo-prefix-metric", 1044, PFX,
     {{NULL, BGPLS_FIELD_U8, REQ}, FLAGS, ZERO16, {"metric", BGPLS_FIELD_U32, STEP}}, {0}},
    {"exclude-srlg", 1045, 0, {{NULL, BGPLS_FIELD_U32_LIST, REQ}}, {0}},
    {"fad-unsupported", 1046, 0, {{NULL, BGPLS_FIELD_U8, REQ}, {"types", BGPLS_FIELD_HEX, 0}}, {0}},
    {"admin-group", 1088, LINK, {{NULL, BGPLS_FIELD_U32, REQ}}, {0}},
    {"max-bandwidth", 1089, LINK, {BW}, {0}},
    {"max-reservable-bandwidth", 1090, LINK, {BW}, {0}},
    {"unreserved-bandwidth", 1091, LINK, {BW, BW, BW, BW, BW, BW, BW, BW}, {0}},
    {"te-metric", 1092, LINK, {{NULL, BGPLS_FIELD_U32, STEP}}, {0}},
    {"link-protection", 1093, LINK, {{NULL, BGPLS_FIELD_U16, REQ}}, {0}},
    {"mpls-protocols", 1094, LINK, {{NULL, BGPLS_FIELD_FLAGS8, REQ}}, {"l,r", NULL}},
    {"igp-metric", 1095, LINK | PFX, {{NULL, BGPLS_FIELD_METRIC, STEP}}, {0}},
    {"srlg", 1096, LINK, {{NULL, BGPLS_FIELD_U32_LIST, REQ}}, {0}},
    {"link-opaque", 1097, LINK, {{NULL, BGPLS_FIELD_HEX, REQ}}, {0}},
    {"link-name", 1098, LINK, {{NULL, BGPLS_FIELD_TEXT, REQ}}, {0}},
    {"adj-sid", 1099, LINK, {FLAGS, WEIGHT, ZERO16, {NULL, BGPLS_FIELD_SID, STEP}}, ADJ_FLAGS},
    {"lan-adj-sid", 1100, LINK,
     {FLAGS, WEIGHT, ZERO16, {"neighbor", BGPLS_FIELD_NEIGHBOR, REQ}, {NULL, BGPLS_FIELD_SID, STEP}}, ADJ_FLAGS},
    // RFC 9086 section 5: one layout for the three BGP peering SIDs.
    {"peer-node-sid", 1101, LINK, {FLAGS, WEIGHT, ZERO16, {NULL, BGPLS_FIELD_SID, STEP}}, PEER_FLAGS},
    {"peer-adj-sid", 1102, LINK, {FLAGS, WEIGHT, ZERO16, {NULL, BGPLS_FIELD_SID, STEP}}, PEER_FLAGS},
    {"peer-set-sid", 1103, LINK, {FLAGS, WEIGHT, ZERO16, {NULL, BGPLS_FIELD_SID, STEP}}, PEER_FLAGS},
    {"srv6-endx-sid", 1106, LINK,
     {{"behavior", BGPLS_FIELD_BEHAVIOR, REQ}, FLAGS, ALGO, WEIGHT, ZERO8, {NULL, BGPLS_FIELD_SRV6_SID, STEP},
      {"structure", BGPLS_FIELD_STRUCTURE, 0}},
     SRV6_FLAGS},
    {"isis-srv6-lan-endx-sid", 1107, LINK,
     {{"behavior", BGPLS_FIELD_BEHAVIOR, REQ}, FLAGS, ALGO, WEIGHT, ZERO8, {"neighbor", BGPLS_FIELD_NEIGHBOR, REQ},
      {NULL, BGPLS_FIELD_SRV6_SID, STEP}, {"structure", BGPLS_FIELD_STRUCTURE, 0}},
     SRV6_FLAGS},
    {"ospfv3-srv6-lan-endx-sid", 1108, LINK,
     {{"behavior", BGPLS_FIELD_BEHAVIOR, REQ}, FLAGS, ALGO, WEIGHT, ZERO8, {"neighbor", BGPLS_FIELD_NEIGHBOR, REQ},
      {NULL, BGPLS_FIELD_SRV6_SID, STEP}, {"structure", BGPLS_FIELD_STRUCTURE, 0}},
     SRV6_FLAGS},
    // RFC 8571: the A (anomalous) flag is the high bit of the first octet.
    {"link-delay", 1114, LINK, {FLAGS, {NULL, BGPLS_FIELD_U24, STEP}}, {"a", NULL}},
    {"min-max-link-delay", 1115, LINK,
     {FLAGS, {NULL, BGPLS_FIELD_U24, REQ}, ZERO8, {NULL, BGPLS_FIELD_U24, REQ}}, {"a", NULL}},
    {"delay-variation", 1116, LINK, {ZERO8, {NULL, BGPLS_FIELD_U24, STEP}}, {0}},
    {"link-loss", 1117, LINK, {FLAGS, {NULL, BGPLS_FIELD_U24, STEP}}, {"a", NULL}},
    {"residual-bandwidth", 1118, LINK, {BW}, {0}},
    {"available-bandwidth", 1119, LINK, {BW}, {0}},
    {"utilized-bandwidth", 1120, LINK, {BW}, {0}},
    {"igp-flags", 1152, PFX, {{NULL, BGPLS_FIELD_FLAGS8, REQ}}, {"d,n,l,p", NULL}},
    {"route-tag", 1153, PFX, {{NULL, BGPLS_FIELD_U32_LIST, REQ}}, {0}},
    {"extended-route-tag", 1154, PFX, {{NULL, BGPLS_FIELD_U64_LIST, REQ}}, {0}},
    {"prefix-metric", 1155, PFX, {{NULL, BGPLS_FIELD_U32, STEP}}, {0}},
    {"ospf-forwarding-address", 1156, PFX, {{NULL, BGPLS_FIELD_IP, REQ}}, {0}},
    {"prefix-opaque", 1157, PFX, {{NULL, BGPLS_FIELD_HEX, REQ}}, {0}},
    {"prefix-sid", 1158, PFX, {FLAGS, ALGO, ZERO16, {NULL, BGPLS_FIELD_SID, STEP}}, PREFIX_FLAGS},
    {"range", 1159, PFX, {FLAGS, ZERO8, {"size", BGPLS_FIELD_U16, REQ}, SUBS}, {"f,m,s,d,a", "ia"}},
    {"srv6-locator", 1162, PFX, {FLAGS, ALGO, ZERO16, {"metric", BGPLS_FIELD_U32, STEP}, SUBS}, {"d", NULL}},
    {"prefix-attr-flags", 1170, PFX, {{NULL, BGPLS_FIELD_U8_LIST, REQ}}, {0}},
    {"source-router-id", 1171, PFX, {{NULL, BGPLS_FIELD_IP, REQ}}, {0}},
    {"l2-bundle-member", 1172, LINK, {{NULL, BGPLS_FIELD_U32, REQ}, SUBS}, {0}},
    {"extended-admin-group", 1173, LINK, {{NULL, BGPLS_FIELD_U32_LIST, REQ}}, {0}},
    {"source-ospf-router-id", 1174, PFX, {{NULL, BGPLS_FIELD_IPV4, REQ}}, {0}},
    // RFC 9857 section 5: the state of an SR Policy candidate path. A label is a 4-octet label stack entry.
    {"sr-binding-sid", 1201, CP,
     {FLAGS16, ZERO16, {"label", BGPLS_FIELD_MPLS, STEP}, {"specified", BGPLS_FIELD_MPLS, 0}}, {"d,b,u,l,f", NULL}},
    {"cp-state", 1202, CP,
     {{"priority", BGPLS_FIELD_U8, 0}, ZERO8, FLAGS16, U32("preference", STEP)}, {"s,a,b,e,v,o,d,c,i,t,u", NULL}},
    {"cp-name", 1203, CP, {{NULL, BGPLS_FIELD_TEXT, REQ}}, {0}},
    {"cp-constraints", 1204, CP, {FLAGS16, ZERO16, {"mt-id", BGPLS_FIELD_U16, 0}, ALGO, ZERO8, SUBS},
     {"d,p,u,a,t,s,f,h", NULL}},
    {"segment-list", 1205, CP,
     {FLAGS16, ZERO16, {"mt-id", BGPLS_FIELD_U16, 0}, ALGO, ZERO8, U32("weight", 0), SUBS}, {"d,e,c,v,r,f,a,t,m", NULL}},
    // A segment: its type (1 is an SR-MPLS label, 2 an SRv6 SID, ...), the SID, then the descriptor of that type.
    {"segment", 1206, 0,
     {{NULL, BGPLS_FIELD_U8, REQ}, ZERO8, FLAGS16, {"label", BGPLS_FIELD_MPLS, STEP}, {"descriptor", BGPLS_FIELD_HEX, 0}},
     {"s,e,v,r,a", NULL}},
    {"srv6-segment", 1206, 0,
     {{NULL, BGPLS_FIELD_U8, REQ}, ZERO8, FLAGS16, {"sid", BGPLS_FIELD_IPV6, STEP}, {"descriptor", BGPLS_FIELD_HEX, 0}},
     {"s,e,v,r,a", NULL}},
    {"segment-list-metric", 1207, 0,
     {{NULL, BGPLS_FIELD_U8, REQ}, FLAGS, ZERO16, U32("margin", 0), U32("bound", 0), U32("value", 0)}, {"m,a,b,v", NULL}},
    {"cp-srlg", 1209, 0, {{NULL, BGPLS_FIELD_U32_LIST, REQ}}, {0}},
    {"cp-bandwidth", 1210, 0, {BW}, {0}},
    {"disjoint-group", 1211, 0,
     {{"request", BGPLS_FIELD_FLAGS8, 0}, {"status", BGPLS_FIELD_FLAGS8, 0}, ZERO16, {NULL, BGPLS_FIELD_U32, STEP}},
     {"s,n,l,f,i,x", NULL}},
    {"srv6-binding-sid", 1212, CP,
     {FLAGS16, ZERO16, {NULL, BGPLS_FIELD_IPV6, STEP}, {"specified", BGPLS_FIELD_IPV6, REQ}, SUBS}, {"b,u,f", NULL}},
    {"policy-name", 1213, CP, {{NULL, BGPLS_FIELD_TEXT, REQ}}, {0}},
    {"bidirectional-group", 1214, 0, {FLAGS16, ZERO16, {NULL, BGPLS_FIELD_U32, STEP}}, {"r,c", NULL}},
    {"cp-metric", 1215, 0, {{NULL, BGPLS_FIELD_U8, REQ}, FLAGS, ZERO16, U32("margin", 0), U32("bound", 0)},
     {"o,m,a,b", NULL}},
    {"segment-list-bandwidth", 1216, 0, {BW}, {0}},
    {"segment-list-id", 1217, 0, {{NULL, BGPLS_FIELD_U32, STEP}}, {0}},
    {"srv6-endpoint-behavior", 1250, SID6, {{NULL, BGPLS_FIELD_BEHAVIOR, REQ}, FLAGS, ALGO}, {0}},
    {"srv6-bgp-peer-node-sid", 1251, SID6,
     {FLAGS, WEIGHT, ZERO16, {"peer-as", BGPLS_FIELD_U32, REQ}, {"peer-id", BGPLS_FIELD_IPV4, REQ}}, SRV6_FLAGS},
    {"srv6-sid-structure", 1252, SID6,
     {{NULL, BGPLS_FIELD_U8, REQ}, {NULL, BGPLS_FIELD_U8, REQ}, {NULL, BGPLS_FIELD_U8, REQ},
      {NULL, BGPLS_FIELD_U8, REQ}},
     {0}},
};

#define PATH      BGP_ON_PATH_ATTR
#define CONST8(v) {NULL, BGPLS_FIELD_CONST8, (v) << 8}

/*
 * Path attribute lines. They use the field layouts of the table above. A row with the PATH mask is an attribute of
 * its own, named by its ribout keyword. The other rows are the TLVs of a container attribute or TLVs nested in
 * those; such a TLV has a 1-octet type and a 2-octet length (RFC 8669 section 3, RFC 9252 sections 2 and 3).
 * Fields are in wire order.
 */
static const bgpls_attr_def_t bgp_path_attr_defs[] = {
    // attribute type <code> value <hex> [flags <hex>]: any attribute. The value starts after the two octets.
    {"attribute", 0, PATH, {{"type", BGPLS_FIELD_U8, REQ}, {"flags", BGPLS_FIELD_U8, 0}, {"value", BGPLS_FIELD_HEX, 0}}, {0}},
    {"atomic-aggregate", 6, PATH, {{0}}, {0}},
    // RFC 6793: the AS number of an AGGREGATOR is four octets on a session with 4-octet AS numbers.
    {"aggregator", 7, PATH, {{NULL, BGPLS_FIELD_U32, STEP}, {NULL, BGPLS_FIELD_IPV4, REQ}}, {0}},
    {"originator-id", 9, PATH, {{NULL, BGPLS_FIELD_IPV4, STEP}}, {0}},
    {"cluster-list", 10, PATH, {{NULL, BGPLS_FIELD_IPV4_LIST, REQ}}, {0}},
    // RFC 7311 section 3: one AIGP TLV, type 1, length 11 (with its own header), an 8-octet metric.
    {"aigp", 26, PATH, {CONST8(1), CONST8(0), CONST8(11), {NULL, BGPLS_FIELD_U64, STEP}}, {0}},
    {"otc", 35, PATH, {{NULL, BGPLS_FIELD_U32, STEP}}, {0}},
    // prefix-sid <tlv>: RFC 8669 section 3. `index` is the Label-Index TLV: a reserved octet, flags, the index.
    // `srgb` is the Originator SRGB TLV: flags, then pairs of first label and size, three octets each. The
    // keywords are those of the BGP-LS lines (`ls prefix-sid ... index`, `ls sr-capabilities ... range`).
    {"index", 1, 0, {ZERO8, ZERO16, {NULL, BGPLS_FIELD_U32, STEP}}, {0}},
    {"srgb", 3, 0, {ZERO16, {"range", BGPLS_FIELD_U24_LIST, REQ}}, {0}},
    // RFC 9252 section 2: the L3 and L2 Service TLVs, each with one SRv6 SID Information sub-TLV (section 3.1):
    // a reserved octet, the SID, flags, the endpoint behavior, a reserved octet, then the SID Structure.
    {"srv6-l3", 5, 0, {ZERO8, {"srv6-sid-information", BGPLS_FIELD_EMBED8, 0}}, {0}},
    {"srv6-l2", 6, 0, {ZERO8, {"srv6-sid-information", BGPLS_FIELD_EMBED8, 0}}, {0}},
    {"srv6-sid-information", 1, 0,
     {ZERO8, {NULL, BGPLS_FIELD_SRV6_SID, STEP}, FLAGS, {"behavior", BGPLS_FIELD_BEHAVIOR, REQ}, ZERO8,
      {"structure", BGPLS_FIELD_SID_STRUCTURE6, 0}},
     {0}},
};

/*
 * The ribout keywords: type code, flags, and whether the lines of the keyword are TLVs of one attribute.
 */
static const struct {
    const char *line;
    uint8_t     type, flags, container;
} bgp_path_attr_lines[] = {
    {"attribute", 0, BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANSITIVE, 0},
    {"atomic-aggregate", 6, BGP_ATTR_FLAG_TRANSITIVE, 0},
    {"aggregator", 7, BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANSITIVE, 0},
    {"originator-id", 9, BGP_ATTR_FLAG_OPTIONAL, 0},
    {"cluster-list", 10, BGP_ATTR_FLAG_OPTIONAL, 0},
    {"aigp", 26, BGP_ATTR_FLAG_OPTIONAL, 0},
    {"otc", 35, BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANSITIVE, 0},
    {"prefix-sid", 40, BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANSITIVE, 1},
};

uint8_t bgp_path_attr_line(const char *line, uint8_t *flags, int *container) {
    for (size_t i = 0; line && i < sizeof(bgp_path_attr_lines) / sizeof(bgp_path_attr_lines[0]); i++) {
        if (strcmp(line, bgp_path_attr_lines[i].line) == 0) {
            *flags = bgp_path_attr_lines[i].flags;
            *container = bgp_path_attr_lines[i].container;
            return bgp_path_attr_lines[i].type ? bgp_path_attr_lines[i].type : 255;
        }
    }
    return 0;
}

const bgpls_attr_def_t *bgp_path_attr_def_find(const char *line, const char *name) {
    // A container line names a TLV row; any other line is its own row.
    const char *wanted = name ? name : line;
    for (size_t i = 0; wanted && i < sizeof(bgp_path_attr_defs) / sizeof(bgp_path_attr_defs[0]); i++) {
        if (strcmp(wanted, bgp_path_attr_defs[i].name) == 0 && !(bgp_path_attr_defs[i].nlri_mask & PATH) == (name != NULL)) {
            return &bgp_path_attr_defs[i];
        }
    }
    return NULL;
}

#undef REQ
#undef STEP
#undef FLAGS
#undef ALGO
#undef WEIGHT
#undef ZERO8
#undef ZERO16
#undef SUBS
#undef NODE
#undef LINK
#undef PFX
#undef SID6
#undef BW
#undef ADJ_FLAGS
#undef PREFIX_FLAGS
#undef SRV6_FLAGS
#undef PATH
#undef CONST8

const bgpls_attr_def_t *bgpls_attr_def_find(const char *name) {
    for (size_t i = 0; name && i < sizeof(bgpls_attr_defs) / sizeof(bgpls_attr_defs[0]); i++) {
        if (strcmp(name, bgpls_attr_defs[i].name) == 0) {
            return &bgpls_attr_defs[i];
        }
    }
    return NULL;
}

static int bgpls_tlv_order_ok(const bgpls_tlv_t *prev, const bgpls_tlv_t *curr, int unique_types) {
    if (curr->type < prev->type) {
        return 0;
    }
    if (curr->type > prev->type) {
        return 1;
    }
    if (unique_types) {
        return 0;
    }
    if (curr->length < prev->length) {
        return 0;
    }
    if (curr->length > prev->length) {
        return 1;
    }
    if (curr->length == 0) {
        return 1;
    }
    if (!prev->value || !curr->value) {
        return 0;
    }
    return memcmp(prev->value, curr->value, curr->length) <= 0;
}

static int bgpls_tlv_chain_sorted(const bgpls_tlv_t *chain, int unique_types) {
    const bgpls_tlv_t *prev = NULL;

    while (chain) {
        if (prev && !bgpls_tlv_order_ok(prev, chain, unique_types)) {
            return 0;
        }
        prev = chain;
        chain = chain->next;
    }

    return 1;
}

static int bgpls_node_router_id_length_valid(uint8_t protocol_id, uint16_t length) {
    switch (protocol_id) {
        case BGPLS_PROTO_ISIS_L1:
        case BGPLS_PROTO_ISIS_L2:
            return length == 6 || length == 7;
        case BGPLS_PROTO_OSPFV2:
        case BGPLS_PROTO_OSPFV3:
            return length == 4 || length == 8;
        case BGPLS_PROTO_DIRECT:
        case BGPLS_PROTO_STATIC:
            return length == 4 || length == 16;
        default:
            return bgpls_igp_router_id_length_valid(length);
    }
}

static int bgpls_validate_node_desc_tlv(const bgpls_tlv_t *tlv, uint16_t expected_type, uint8_t protocol_id) {
    uint16_t offset = 0;
    uint16_t prev_type = 0;
    int      first = 1;
    int      saw_router_id = 0;
    int      saw_bgp_id = 0;
    int      saw_te_id = 0;
    int      saw_as = 0;

    if (!tlv || tlv->next || tlv->type != expected_type ||
        tlv->length == 0 || !tlv->value) {
        // TODO(FUZZ_GATE): Allow missing or malformed BGP-LS Node Descriptor containers.
        return 0;
    }

    while (offset < tlv->length) {
        uint16_t type;
        uint16_t length;

        if ((uint16_t)(tlv->length - offset) < 4) {
            return 0;
        }
        type = bgpls_read_u16(tlv->value + offset);
        length = bgpls_read_u16(tlv->value + offset + 2);
        offset = (uint16_t)(offset + 4);
        if ((uint16_t)(tlv->length - offset) < length) {
            return 0;
        }
        if (!first && type <= prev_type) {
            /*
             * TODO(FUZZ_GATE): Allow unordered or duplicate BGP-LS Node
             * Descriptor sub-TLVs.
             *
             * RFC 9552 section 5.1 REQUIRES all TLVs within an NLRI
             * to be in ascending order by Type, and for multiple
             * TLVs of the same type, further ordered by Length then
             * Value. The RFC is explicit: "NLRIs having TLVs that
             * do not follow the above ordering rules MUST be
             * considered as malformed by a BGP-LS Propagator."
             *
             * Fuzz use case: send an NLRI with TLVs out of ascending
             * order and observe peer behavior:
             *
             *   - Correctly detects malformed NLRI and applies
             *     "treat as withdraw" (RFC 7606)
             *   - Silently accepts and propagates with original
             *     ordering (violating canonical form)
             *   - Re-sorts before propagation (hides the input bug)
             *   - Crashes or resets session
             *
             * This is a genuinely subtle conformance check because
             * the TLV bytes themselves are all well-formed at the
             * framing level — only their ORDER violates the spec.
             * Parsers often implement the framing check but skip
             * the ordering check because it's semantically separate
             * from parse correctness.
             *
             * Proposed allow key: "bgpls.tlv-unordered"
             */
            return 0;
        }

        switch (type) {
            case BGPLS_TLV_AS:
            case BGPLS_TLV_BGPLS_ID:
            case BGPLS_TLV_OSPF_AREA:
                if (length != 4) {
                    return 0;
                }
                saw_as |= type == BGPLS_TLV_AS;
                break;
            case BGPLS_TLV_IGP_ROUTER_ID:
                if (!bgpls_node_router_id_length_valid(protocol_id, length)) {
                    return 0;
                }
                saw_router_id = 1;
                break;
            case BGPLS_TLV_BGP_ROUTER_ID:
            case BGPLS_TLV_MEMBER_ASN:
                // RFC 9086 section 4.1: four octets, not zero.
                if (length != 4 || !memcmp(tlv->value + offset, "\0\0\0", 4)) {
                    return 0;
                }
                saw_bgp_id |= type == BGPLS_TLV_BGP_ROUTER_ID;
                break;
            case BGPLS_TLV_IPV4_ROUTER_ID:
            case BGPLS_TLV_IPV6_ROUTER_ID:
                if (length != (type == BGPLS_TLV_IPV4_ROUTER_ID ? 4 : 16)) {
                    return 0;
                }
                saw_te_id = 1;
                break;
            default:
                break;
        }

        prev_type = type;
        first = 0;
        offset = (uint16_t)(offset + length);
    }

    // RFC 9086 section 4.2: a BGP node is its AS number and BGP Router-ID. An IGP node needs its IGP Router-ID.
    // RFC 9857 section 3: the headend of an SR Policy is named by its IPv4 or IPv6 Router-ID (TLV 1028 or 1029).
    if (protocol_id == BGPLS_PROTO_SR) {
        return offset == tlv->length && saw_te_id;
    }
    return offset == tlv->length && (protocol_id == BGPLS_PROTO_BGP ? saw_as && saw_bgp_id : saw_router_id);
}

static int bgpls_validate_link_desc_chain(const bgpls_tlv_t *chain, uint8_t protocol_id) {
    int saw_llr = 0;
    int saw_v4_iface = 0;
    int saw_v4_neighbor = 0;
    int saw_v6_iface = 0;
    int saw_v6_neighbor = 0;
    int mt_id_count = 0;

    if (chain && !bgpls_tlv_chain_sorted(chain, 0)) {
        // TODO(FUZZ_GATE): Allow unordered BGP-LS Link Descriptor TLVs.
        return 0;
    }

    while (chain) {
        switch (chain->type) {
            case BGPLS_TLV_LINK_LOCAL_REMOTE:
                if (chain->length != 8) {
                    return 0;
                }
                saw_llr = 1;
                break;
            case BGPLS_TLV_IPV4_IFACE_ADDR:
                if (chain->length != 4) {
                    return 0;
                }
                saw_v4_iface = 1;
                break;
            case BGPLS_TLV_IPV4_NEIGHBOR_ADDR:
                if (chain->length != 4) {
                    return 0;
                }
                saw_v4_neighbor = 1;
                break;
            case BGPLS_TLV_IPV6_IFACE_ADDR:
                if (chain->length != 16) {
                    return 0;
                }
                saw_v6_iface = 1;
                break;
            case BGPLS_TLV_IPV6_NEIGHBOR_ADDR:
                if (chain->length != 16) {
                    return 0;
                }
                saw_v6_neighbor = 1;
                break;
            case BGPLS_TLV_MT_ID:
                if (chain->length != 2) {
                    return 0;
                }
                mt_id_count++;
                break;
            default:
                break;
        }
        chain = chain->next;
    }

    if (mt_id_count > 1) {
        return 0;
    }
    if ((saw_v4_iface ^ saw_v4_neighbor) || (saw_v6_iface ^ saw_v6_neighbor)) {
        // TODO(FUZZ_GATE): Allow incomplete BGP-LS interface/neighbor address pairs.
        return 0;
    }
    // A BGP peering link may carry both: RFC 9086 section 5.2 names a PeerAdj link by its identifiers and lets it
    // add the session addresses.
    if (protocol_id != BGPLS_PROTO_BGP && saw_llr &&
        (saw_v4_iface || saw_v4_neighbor || saw_v6_iface || saw_v6_neighbor)) {
        // TODO(FUZZ_GATE): Allow conflicting BGP-LS link-local/remote and address descriptors.
        return 0;
    }

    return 1;
}

static int bgpls_ip_reach_tlv_valid(const bgpls_tlv_t *tlv, uint16_t nlri_type) {
    uint8_t  prefix_len;
    uint16_t expected_len;
    uint16_t max_prefix_len;

    if (!tlv || tlv->type != BGPLS_TLV_IP_REACH_INFO ||
        tlv->length == 0 || !tlv->value) {
        // TODO(FUZZ_GATE): Allow malformed or missing BGP-LS IP Reachability TLVs.
        return 0;
    }

    prefix_len = tlv->value[0];
    max_prefix_len = (nlri_type == BGPLS_NLRI_IPV4_PREFIX) ? 32 : 128;
    if (prefix_len > max_prefix_len) {
        return 0;
    }

    expected_len = (uint16_t)(1 + ((prefix_len + 7) / 8));
    if (tlv->length != expected_len) {
        // TODO(FUZZ_GATE): Allow BGP-LS reachability TLVs whose length does not match prefix bits.
        return 0;
    }
    if (prefix_len > 0 && (prefix_len % 8) != 0) {
        uint8_t trailing_mask = (uint8_t)((1u << (8 - (prefix_len % 8))) - 1u);

        if (tlv->value[tlv->length - 1] & trailing_mask) {
            // TODO(FUZZ_GATE): Allow non-zero trailing bits in BGP-LS IP prefixes.
            return 0;
        }
    }

    return 1;
}

static int bgpls_validate_prefix_desc_chain(const bgpls_tlv_t *chain, uint16_t nlri_type) {
    int mt_id_count = 0;
    int ospf_route_type_count = 0;
    int reach_count = 0;

    if (!chain || !bgpls_tlv_chain_sorted(chain, 0)) {
        return 0;
    }

    while (chain) {
        switch (chain->type) {
            case BGPLS_TLV_MT_ID:
                if (chain->length != 2) {
                    return 0;
                }
                mt_id_count++;
                break;
            case BGPLS_TLV_OSPF_ROUTE_TYPE:
                if (chain->length != 1 || !chain->value ||
                    chain->value[0] < 1 || chain->value[0] > 6) {
                    return 0;
                }
                ospf_route_type_count++;
                break;
            case BGPLS_TLV_IP_REACH_INFO:
                if (!bgpls_ip_reach_tlv_valid(chain, nlri_type)) {
                    return 0;
                }
                reach_count++;
                break;
            default:
                break;
        }
        chain = chain->next;
    }

    return mt_id_count <= 1 && ospf_route_type_count <= 1 && reach_count == 1;
}

/*
 * RFC 9514 section 6.1: exactly one SRv6 SID Information TLV of 16 octets, and at most one Multi-Topology ID.
 */
static int bgpls_validate_srv6_sid_desc_chain(const bgpls_tlv_t *chain) {
    int mt_id_count = 0;
    int sid_count = 0;

    if (!chain || !bgpls_tlv_chain_sorted(chain, 0)) {
        return 0;
    }
    for (; chain; chain = chain->next) {
        if (chain->type == BGPLS_TLV_MT_ID) {
            if (chain->length != 2) {
                return 0;
            }
            mt_id_count++;
        } else if (chain->type == BGPLS_TLV_SRV6_SID_INFO) {
            if (chain->length != 16) {
                return 0;
            }
            sid_count++;
        }
    }
    return mt_id_count <= 1 && sid_count == 1;
}

/*
 * RFC 9857 section 4: one SR Policy Candidate Path Descriptor. Its E and O flags give the sizes of the endpoint and
 * of the originator address, so the length is 24, 36 or 48 octets.
 */
static int bgpls_validate_sr_policy_desc(const bgpls_tlv_t *tlv) {
    if (!tlv || tlv->next || tlv->type != BGPLS_TLV_SR_POLICY_CP || tlv->length < 24 || !tlv->value) {
        return 0;
    }
    return tlv->length == 16 + ((tlv->value[1] & 0x80) ? 16 : 4) + ((tlv->value[1] & 0x40) ? 16 : 4) &&
           !(tlv->value[1] & 0x3F) && !tlv->value[2] && !tlv->value[3];
}

static int bgpls_prefix_valid(const bgpls_prefix_t *prefix) {
    if (!prefix) return 0;
    if (!bgpls_protocol_id_supported(prefix->protocol_id)) {
        // TODO(FUZZ_GATE): Allow non-standard BGP-LS Protocol-ID values.
        return 0;
    }
    // RFC 9857 section 3: the SR Policy Candidate Path NLRI, and only it, has Protocol-ID Segment Routing.
    if ((prefix->nlri_type == BGPLS_NLRI_SR_POLICY) != (prefix->protocol_id == BGPLS_PROTO_SR) ||
        (prefix->nlri_type != BGPLS_NLRI_SR_POLICY && prefix->sr_policy_descriptors)) {
        return 0;
    }

    switch (prefix->nlri_type) {
        case BGPLS_NLRI_NODE:
            // TODO(FUZZ_GATE): Allow malformed Node NLRI descriptor layout.
            return bgpls_validate_node_desc_tlv(prefix->local_node_descriptors,
                                                BGPLS_TLV_LOCAL_NODE_DESC,
                                                prefix->protocol_id) &&
                   !prefix->remote_node_descriptors &&
                   !prefix->link_descriptors &&
                   !prefix->prefix_descriptors && !prefix->srv6_sid_descriptors;
        case BGPLS_NLRI_LINK:
            // TODO(FUZZ_GATE): Allow malformed Link NLRI descriptor layout.
            return bgpls_validate_node_desc_tlv(prefix->local_node_descriptors,
                                                BGPLS_TLV_LOCAL_NODE_DESC,
                                                prefix->protocol_id) &&
                   bgpls_validate_node_desc_tlv(prefix->remote_node_descriptors,
                                                BGPLS_TLV_REMOTE_NODE_DESC,
                                                prefix->protocol_id) &&
                   !prefix->prefix_descriptors && !prefix->srv6_sid_descriptors &&
                   bgpls_validate_link_desc_chain(prefix->link_descriptors, prefix->protocol_id);
        case BGPLS_NLRI_IPV4_PREFIX:
        case BGPLS_NLRI_IPV6_PREFIX:
            // TODO(FUZZ_GATE): Allow malformed Prefix NLRI descriptor layout.
            return bgpls_validate_node_desc_tlv(prefix->local_node_descriptors,
                                                BGPLS_TLV_LOCAL_NODE_DESC,
                                                prefix->protocol_id) &&
                   !prefix->remote_node_descriptors &&
                   !prefix->link_descriptors && !prefix->srv6_sid_descriptors &&
                   bgpls_validate_prefix_desc_chain(prefix->prefix_descriptors, prefix->nlri_type);
        case BGPLS_NLRI_SR_POLICY:
            return bgpls_validate_node_desc_tlv(prefix->local_node_descriptors,
                                                BGPLS_TLV_LOCAL_NODE_DESC,
                                                prefix->protocol_id) &&
                   !prefix->remote_node_descriptors &&
                   !prefix->link_descriptors && !prefix->prefix_descriptors &&
                   !prefix->srv6_sid_descriptors &&
                   bgpls_validate_sr_policy_desc(prefix->sr_policy_descriptors);
        case BGPLS_NLRI_SRV6_SID:
            return bgpls_validate_node_desc_tlv(prefix->local_node_descriptors,
                                                BGPLS_TLV_LOCAL_NODE_DESC,
                                                prefix->protocol_id) &&
                   !prefix->remote_node_descriptors &&
                   !prefix->link_descriptors && !prefix->prefix_descriptors &&
                   bgpls_validate_srv6_sid_desc_chain(prefix->srv6_sid_descriptors);
        default:
            // TODO(FUZZ_GATE): Allow unsupported or experimental BGP-LS NLRI types.
            return 0;
    }
}

// Node Descriptor Builder

bgpls_tlv_t* bgpls_node_desc_create(uint32_t as_number, const uint8_t *router_id, uint16_t router_id_len) {
    bgpls_tlv_t *as_tlv = bgpls_tlv_create_as(as_number);
    bgpls_tlv_t *id_tlv = bgpls_tlv_create_igp_router_id(router_id, router_id_len);
    int          sub_len;
    uint8_t     *sub_buf;
    bgpls_tlv_t *desc;

    if (!as_tlv || !id_tlv) {
        bgpls_tlv_list_free(as_tlv);
        bgpls_tlv_list_free(id_tlv);
        return NULL;
    }

    as_tlv->next = id_tlv;
    sub_len = bgpls_tlv_chain_wire_len(as_tlv);

    sub_buf = malloc((size_t)sub_len);
    if (!sub_buf) {
        bgpls_tlv_list_free(as_tlv);
        return NULL;
    }

    bgpls_encode_tlv_chain(sub_buf, as_tlv);
    bgpls_tlv_list_free(as_tlv);

    desc = bgpls_tlv_create(BGPLS_TLV_LOCAL_NODE_DESC, (uint16_t)sub_len, sub_buf);
    free(sub_buf);

    return desc;
}

// NLRI Creation Functions

static bgpls_nlri_t* bgpls_nlri_alloc(uint16_t nlri_type,
                                       uint8_t protocol_id,
                                       uint64_t identifier,
                                       int add_path,
                                       uint32_t path_id) {
    bgpls_nlri_t *nlri = calloc(1, sizeof(bgpls_nlri_t));

    if (!nlri) {
        return NULL;
    }

    memset(&nlri->prefix, 0, sizeof(nlri->prefix));
    nlri->prefix.nlri_type = nlri_type;
    nlri->prefix.protocol_id = protocol_id;
    nlri->prefix.identifier = identifier;
    nlri->path_id = path_id;
    nlri->add_path = (uint8_t)(add_path ? 1 : 0);
    nlri->next = NULL;

    return nlri;
}

bgpls_nlri_t* bgpls_nlri_create_node(uint8_t protocol_id, uint64_t identifier, bgpls_tlv_t *local_desc) {
    bgpls_nlri_t *nlri = bgpls_nlri_alloc(BGPLS_NLRI_NODE, protocol_id, identifier, 0, 0);

    if (nlri) {
        nlri->prefix.local_node_descriptors = local_desc;
    }

    return nlri;
}

bgpls_nlri_t* bgpls_nlri_create_node_path_id(uint8_t protocol_id,
                                              uint64_t identifier,
                                              bgpls_tlv_t *local_desc,
                                              uint32_t path_id) {
    bgpls_nlri_t *nlri = bgpls_nlri_alloc(BGPLS_NLRI_NODE, protocol_id, identifier, 1, path_id);

    if (nlri) {
        nlri->prefix.local_node_descriptors = local_desc;
    }

    return nlri;
}

bgpls_nlri_t* bgpls_nlri_create_link(uint8_t protocol_id,
                                     uint64_t identifier,
                                     bgpls_tlv_t *local_desc,
                                     bgpls_tlv_t *remote_desc,
                                     bgpls_tlv_t *link_desc) {
    bgpls_nlri_t *nlri = bgpls_nlri_alloc(BGPLS_NLRI_LINK, protocol_id, identifier, 0, 0);

    if (nlri) {
        nlri->prefix.local_node_descriptors = local_desc;
        nlri->prefix.remote_node_descriptors = remote_desc;
        nlri->prefix.link_descriptors = link_desc;
    }

    return nlri;
}

bgpls_nlri_t* bgpls_nlri_create_link_path_id(uint8_t protocol_id,
                                              uint64_t identifier,
                                              bgpls_tlv_t *local_desc,
                                              bgpls_tlv_t *remote_desc,
                                              bgpls_tlv_t *link_desc,
                                              uint32_t path_id) {
    bgpls_nlri_t *nlri = bgpls_nlri_alloc(BGPLS_NLRI_LINK, protocol_id, identifier, 1, path_id);

    if (nlri) {
        nlri->prefix.local_node_descriptors = local_desc;
        nlri->prefix.remote_node_descriptors = remote_desc;
        nlri->prefix.link_descriptors = link_desc;
    }

    return nlri;
}

bgpls_nlri_t* bgpls_nlri_create_prefix_ipv4(uint8_t protocol_id,
                                             uint64_t identifier,
                                             bgpls_tlv_t *local_desc,
                                             bgpls_tlv_t *prefix_desc) {
    bgpls_nlri_t *nlri = bgpls_nlri_alloc(BGPLS_NLRI_IPV4_PREFIX, protocol_id, identifier, 0, 0);

    if (nlri) {
        nlri->prefix.local_node_descriptors = local_desc;
        nlri->prefix.prefix_descriptors = prefix_desc;
    }

    return nlri;
}

bgpls_nlri_t* bgpls_nlri_create_prefix_ipv4_path_id(
    uint8_t protocol_id, uint64_t identifier,
    bgpls_tlv_t *local_desc, bgpls_tlv_t *prefix_desc,
    uint32_t path_id) {
    bgpls_nlri_t *nlri = bgpls_nlri_alloc(BGPLS_NLRI_IPV4_PREFIX, protocol_id, identifier, 1, path_id);

    if (nlri) {
        nlri->prefix.local_node_descriptors = local_desc;
        nlri->prefix.prefix_descriptors = prefix_desc;
    }

    return nlri;
}

bgpls_nlri_t* bgpls_nlri_create_prefix_ipv6(uint8_t protocol_id,
                                             uint64_t identifier,
                                             bgpls_tlv_t *local_desc,
                                             bgpls_tlv_t *prefix_desc) {
    bgpls_nlri_t *nlri = bgpls_nlri_alloc(BGPLS_NLRI_IPV6_PREFIX, protocol_id, identifier, 0, 0);

    if (nlri) {
        nlri->prefix.local_node_descriptors = local_desc;
        nlri->prefix.prefix_descriptors = prefix_desc;
    }

    return nlri;
}

bgpls_nlri_t* bgpls_nlri_create_prefix_ipv6_path_id(
    uint8_t protocol_id, uint64_t identifier,
    bgpls_tlv_t *local_desc, bgpls_tlv_t *prefix_desc,
    uint32_t path_id) {
    bgpls_nlri_t *nlri = bgpls_nlri_alloc(BGPLS_NLRI_IPV6_PREFIX, protocol_id, identifier, 1, path_id);

    if (nlri) {
        nlri->prefix.local_node_descriptors = local_desc;
        nlri->prefix.prefix_descriptors = prefix_desc;
    }

    return nlri;
}

// NLRI List Utilities (manual, not macro)

/*
 * BGP-LS NLRI nodes own TLV chains that need deep-freeing, so the
 * standard DEFINE_NLRI_LIST_UTILS macro cannot be used here.
 */

void bgpls_nlri_append(bgpls_nlri_t **head, bgpls_nlri_t **tail, bgpls_nlri_t *nlri) {
    if (!nlri) {
        return;
    }

    if (*tail) {
        (*tail)->next = nlri;
        *tail = nlri;
    } else {
        *head = nlri;
        *tail = nlri;
    }
}

int bgpls_nlri_count(bgpls_nlri_t *list) {
    int count = 0;

    while (list) {
        count++;
        list = list->next;
    }

    return count;
}

void bgpls_nlri_list_free(bgpls_nlri_t *list) {
    while (list) {
        bgpls_nlri_t *next = list->next;

        bgpls_tlv_list_free(list->prefix.local_node_descriptors);
        bgpls_tlv_list_free(list->prefix.remote_node_descriptors);
        bgpls_tlv_list_free(list->prefix.link_descriptors);
        bgpls_tlv_list_free(list->prefix.prefix_descriptors);
        bgpls_tlv_list_free(list->prefix.srv6_sid_descriptors);
        bgpls_tlv_list_free(list->prefix.sr_policy_descriptors);
        free(list);
        list = next;
    }
}

// NLRI Encoding

/*
 * Encode one BGP-LS NLRI into the buffer.
 *
 * Wire format (RFC 9552 Section 5.2):
 *   NLRI Type      (2 bytes)
 *   Total NLRI Len (2 bytes)
 *   Protocol-ID    (1 byte)
 *   Identifier     (8 bytes)
 *   Descriptor TLVs (variable)
 */
int bgp_encode_bgpls_prefix(uint8_t *buffer, bgpls_prefix_t *prefix) {
    if (!buffer || !bgpls_prefix_valid(prefix)) {
        return -1;
    }
    const bgpls_tlv_t *chains[] = {prefix->local_node_descriptors, prefix->remote_node_descriptors,
                                    prefix->link_descriptors, prefix->prefix_descriptors,
                                    prefix->srv6_sid_descriptors, prefix->sr_policy_descriptors};
    int body_size = 9;
    for (size_t i = 0; i < sizeof(chains) / sizeof(*chains); i++) {
        int len = bgpls_tlv_chain_wire_len(chains[i]);
        if (len < 0 || len > UINT16_MAX - body_size) return -1;
        body_size += len;
    }
    return bgp_encode_bgpls_prefix_unchecked(buffer, prefix);
}

int bgp_encode_bgpls_prefix_unchecked(uint8_t *buffer, const bgpls_prefix_t *prefix) {
    int      offset = 0;
    int      body_start;
    uint16_t type_net;
    uint64_t id_net;
    uint16_t body_len;

    // NLRI Type
    type_net = htons(prefix->nlri_type);
    // TODO(WIRE_MUTATION): Corrupt BGP-LS NLRI type after encode.
    memcpy(buffer + offset, &type_net, 2);
    offset += 2;

    // Total NLRI Length placeholder
    offset += 2;
    body_start = offset;

    // Protocol-ID
    // TODO(WIRE_MUTATION): Corrupt BGP-LS Protocol-ID after encode.
    buffer[offset++] = prefix->protocol_id;

    // Identifier (8 bytes, big-endian)
    id_net = htobe64(prefix->identifier);
    // TODO(WIRE_MUTATION): Corrupt BGP-LS Identifier after encode.
    memcpy(buffer + offset, &id_net, 8);
    offset += 8;

    // Local Node Descriptors
    if (prefix->local_node_descriptors) {
        offset += bgpls_encode_tlv_chain(buffer + offset, prefix->local_node_descriptors);
    }

    // Remote Node Descriptors (Link NLRI only)
    if (prefix->remote_node_descriptors) {
        offset += bgpls_encode_tlv_chain(buffer + offset, prefix->remote_node_descriptors);
    }

    // Link Descriptors (Link NLRI only)
    if (prefix->link_descriptors) {
        offset += bgpls_encode_tlv_chain(buffer + offset, prefix->link_descriptors);
    }

    // Prefix Descriptors (Prefix NLRI only)
    if (prefix->prefix_descriptors) {
        offset += bgpls_encode_tlv_chain(buffer + offset, prefix->prefix_descriptors);
    }

    // SRv6 SID Descriptors (SRv6 SID NLRI only)
    if (prefix->srv6_sid_descriptors) {
        offset += bgpls_encode_tlv_chain(buffer + offset, prefix->srv6_sid_descriptors);
    }

    // SR Policy Candidate Path Descriptor (SR Policy Candidate Path NLRI only)
    if (prefix->sr_policy_descriptors) {
        offset += bgpls_encode_tlv_chain(buffer + offset, prefix->sr_policy_descriptors);
    }

    // Fill in Total NLRI Length
    body_len = htons((uint16_t)(offset - body_start));
    // TODO(WIRE_MUTATION): Corrupt BGP-LS Total NLRI Length after encode.
    memcpy(buffer + 2, &body_len, 2);

    return offset;
}

// BGP-LS Attribute (type 29)

bgp_path_attr_t* bgp_attr_create_bgpls(bgpls_tlv_t *tlv_chain) {
    int              total_len = bgpls_tlv_chain_wire_len(tlv_chain);
    bgp_path_attr_t *attr;

    if (total_len < 0 || total_len > 65535) {
        return NULL;
    }

    /*
     * The BGP-LS Attribute (type 29) is optional and non-transitive. It is
     * distinct from the BGP-LS NLRI itself, which still rides in MP_REACH or
     * MP_UNREACH for AFI 16388 / SAFI 71.
     */
    attr = bgp_attr_alloc(BGP_ATTR_FLAG_OPTIONAL, BGP_ATTR_BGP_LS, (uint16_t)total_len);
    if (!attr) {
        return NULL;
    }

    if (total_len > 0) {
        bgpls_encode_tlv_chain(attr->value, tlv_chain);
        // TODO(WIRE_MUTATION): Corrupt serialized BGP-LS Attribute TLV bytes after encode.
    }

    return attr;
}

// Next-Hop Encoding

/*
 * BGP-LS uses standard IPv4 (4 bytes) or IPv6 (16 bytes) next-hop
 * encoding, with no RD padding.  This is the same logic as EVPN.
 */
int bgp_encode_bgpls_next_hop(const bgp_next_hop_t *next_hop, uint8_t *buffer, uint8_t *nh_len_out) {
    bgp_next_hop_t        default_next_hop;
    const bgp_next_hop_t *effective = next_hop;

    if (!effective) {
        memset(&default_next_hop, 0, sizeof(default_next_hop));
        default_next_hop.af = AF_INET;
        effective = &default_next_hop;
    }

    if (effective->af == AF_INET) {
        memcpy(buffer, &effective->address.ipv4, 4);
        *nh_len_out = 4;
        // TODO(WIRE_MUTATION): Corrupt BGP-LS IPv4 next-hop bytes after encode.
        return 0;
    }

    if (effective->af == AF_INET6) {
        if (effective->has_link_local) {
            // TODO(FUZZ_GATE): Allow non-standard BGP-LS IPv6 next-hops with link-local bytes.
            return -1;
        }
        memcpy(buffer, &effective->address.ipv6, 16);
        *nh_len_out = 16;
        // TODO(WIRE_MUTATION): Corrupt BGP-LS IPv6 next-hop bytes after encode.
        return 0;
    }

    // TODO(FUZZ_GATE): Allow unsupported BGP-LS next-hop address families.
    return -1;
}

// ADD-PATH Detection

static int bgp_detect_bgpls_add_path(const bgpls_nlri_t *list, int *add_path_out) {
    int add_path = -1;

    while (list) {
        if (add_path == -1) {
            add_path = list->add_path ? 1 : 0;
        } else if ((list->add_path ? 1 : 0) != add_path) {
            return -1;
        }

        if (!list->add_path && list->path_id != 0) {
            return -1;
        }

        list = list->next;
    }

    *add_path_out = (add_path < 0) ? 0 : add_path;
    return 0;
}

// NLRI + Path-ID Encoding

static int bgp_encode_bgpls_nlri(uint8_t *buffer, const bgpls_nlri_t *nlri, int add_path) {
    int offset = 0;
    int len;

    if (add_path) {
        uint32_t path_id_net = htonl(nlri->path_id);

        memcpy(buffer + offset, &path_id_net, sizeof(path_id_net));
        offset += sizeof(path_id_net);
    }

    len = bgp_encode_bgpls_prefix(buffer + offset, (bgpls_prefix_t *)&nlri->prefix);
    return (len < 0) ? -1 : offset + len;
}

// Chunking

/*
 * Estimate the wire size of one BGP-LS NLRI entry.
 * type(2) + length(2) + proto(1) + id(8) + descriptors
 */
static int bgpls_nlri_wire_size(const bgpls_nlri_t *nlri) {
    int size = 2 + 2 + 1 + 8;  /* header + proto + id */

    const bgpls_tlv_t *chains[] = {nlri->prefix.local_node_descriptors, nlri->prefix.remote_node_descriptors,
                                    nlri->prefix.link_descriptors, nlri->prefix.prefix_descriptors,
                                    nlri->prefix.srv6_sid_descriptors, nlri->prefix.sr_policy_descriptors};
    for (size_t i = 0; i < sizeof(chains) / sizeof(*chains); i++) {
        int len = bgpls_tlv_chain_wire_len(chains[i]);
        if (len < 0 || len > UINT16_MAX + 4 - size) return -1;
        size += len;
    }

    return size;
}

static int encode_bgpls_chunk(bgpls_nlri_t **cursor, uint8_t *buffer, int max_bytes, int add_path) {
    int written = 0;

    while (*cursor) {
        int needed = bgpls_nlri_wire_size(*cursor);
        if (needed < 0) return -1;

        if ((int)(*cursor)->add_path != add_path) {
            return -1;
        }
        if (add_path) {
            needed += 4;
        }

        if (written + needed > max_bytes) {
            return (written > 0) ? written : -1;
        }

        int encoded = bgp_encode_bgpls_nlri(buffer + written, *cursor, add_path);
        if (encoded < 0) return -1;
        written += encoded;
        *cursor = (*cursor)->next;
    }

    return written;
}

// MESSAGE GENERATION

bgp_update_result_t* bgp_generate_update_bgpls(
    bgpls_nlri_t *nlri_list,
    bgp_path_attr_t *attributes,
    bgpls_nlri_t *withdrawn_list,
    uint16_t max_pdu_size,
    const bgp_next_hop_t *next_hop)
{
    bgp_builder_t builder = {0};
    uint8_t      *base_attr_data = NULL;
    uint16_t      base_attr_len = 0;
    uint8_t      *nlri_buffer = NULL;
    uint8_t       nh_buf[BGP_STANDARD_NEXT_HOP_BUF_SIZE];
    uint8_t       nh_len = 0;
    int           available_space;
    int           nlri_add_path = 0;
    int           withdrawn_add_path = 0;
    bgpls_nlri_t *curr;

    if (max_pdu_size == 0) {
        max_pdu_size = BGP_MAX_PDU_SIZE;
    }
    if (max_pdu_size < BGP_UPDATE_MIN_SIZE) {
        return NULL;
    }

    if (bgp_attr_list_contains_type(attributes, BGP_ATTR_MP_REACH_NLRI) ||
        bgp_attr_list_contains_type(attributes, BGP_ATTR_MP_UNREACH_NLRI)) {
        return NULL;
    }

    if (bgp_detect_bgpls_add_path(nlri_list, &nlri_add_path) < 0 ||
        bgp_detect_bgpls_add_path(withdrawn_list, &withdrawn_add_path) < 0) {
        return NULL;
    }

    if (bgp_serialize_path_attributes_alloc(attributes,
                                            &base_attr_data,
                                            &base_attr_len) < 0) {
        return NULL;
    }

    if (nlri_list) {
        if (!bgp_validate_mp_attrs(attributes) ||
            bgp_encode_bgpls_next_hop(next_hop, nh_buf, &nh_len) < 0) {
            goto fail;
        }
    }

    if (bgp_builder_init(&builder) < 0) {
        goto fail;
    }

    nlri_buffer = malloc(max_pdu_size);
    if (!nlri_buffer) {
        goto fail;
    }

    if (withdrawn_list) {
        available_space = bgp_mp_unreach_payload_budget(max_pdu_size);
        if (available_space <= 0) {
            goto fail;
        }

        curr = withdrawn_list;
        while (curr) {
            int nlri_len = encode_bgpls_chunk(&curr, nlri_buffer, available_space, withdrawn_add_path);
            if (nlri_len <= 0 ||
                bgp_builder_append_mp(&builder, &(bgp_mp_args_t){
                    .afi         = AFI_BGP_LS,
                    .safi        = SAFI_BGP_LS,
                    .mp_nlri     = nlri_buffer,
                    .mp_nlri_len = (uint16_t)nlri_len,
                }) < 0) {
                goto fail;
            }
        }
    }

    if (nlri_list) {
        available_space = bgp_mp_reach_payload_budget(max_pdu_size, base_attr_len, nh_len);
        if (available_space <= 0) {
            goto fail;
        }

        curr = nlri_list;
        while (curr) {
            int nlri_len = encode_bgpls_chunk(&curr, nlri_buffer, available_space, nlri_add_path);
            if (nlri_len <= 0 ||
                bgp_builder_append_mp(&builder, &(bgp_mp_args_t){
                    .attrs       = base_attr_data,
                    .attrs_len   = base_attr_len,
                    .is_reach    = 1,
                    .afi         = AFI_BGP_LS,
                    .safi        = SAFI_BGP_LS,
                    .next_hop    = nh_buf,
                    .nh_len      = nh_len,
                    .mp_nlri     = nlri_buffer,
                    .mp_nlri_len = (uint16_t)nlri_len,
                }) < 0) {
                goto fail;
            }
        }
    } else if (!withdrawn_list) {
        if (bgp_builder_append_attrs_only(&builder,
                                          base_attr_data,
                                          base_attr_len) < 0) {
            goto fail;
        }
    }

    free(base_attr_data);
    free(nlri_buffer);
    return bgp_builder_take(&builder);

fail:
    free(base_attr_data);
    free(nlri_buffer);
    bgp_builder_release(&builder);
    return NULL;
}
