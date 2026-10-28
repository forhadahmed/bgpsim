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
            return 1;
        default:
            return 0;
    }
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
                break;
            case BGPLS_TLV_IGP_ROUTER_ID:
                if (!bgpls_node_router_id_length_valid(protocol_id, length)) {
                    return 0;
                }
                saw_router_id = 1;
                break;
            default:
                break;
        }

        prev_type = type;
        first = 0;
        offset = (uint16_t)(offset + length);
    }

    return offset == tlv->length && saw_router_id;
}

static int bgpls_validate_link_desc_chain(const bgpls_tlv_t *chain) {
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
    if (saw_llr && (saw_v4_iface || saw_v4_neighbor || saw_v6_iface || saw_v6_neighbor)) {
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

static int bgpls_prefix_valid(const bgpls_prefix_t *prefix) {
    if (!prefix) return 0;
    if (!bgpls_protocol_id_supported(prefix->protocol_id)) {
        // TODO(FUZZ_GATE): Allow non-standard BGP-LS Protocol-ID values.
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
                   !prefix->prefix_descriptors;
        case BGPLS_NLRI_LINK:
            // TODO(FUZZ_GATE): Allow malformed Link NLRI descriptor layout.
            return bgpls_validate_node_desc_tlv(prefix->local_node_descriptors,
                                                BGPLS_TLV_LOCAL_NODE_DESC,
                                                prefix->protocol_id) &&
                   bgpls_validate_node_desc_tlv(prefix->remote_node_descriptors,
                                                BGPLS_TLV_REMOTE_NODE_DESC,
                                                prefix->protocol_id) &&
                   !prefix->prefix_descriptors &&
                   bgpls_validate_link_desc_chain(prefix->link_descriptors);
        case BGPLS_NLRI_IPV4_PREFIX:
        case BGPLS_NLRI_IPV6_PREFIX:
            // TODO(FUZZ_GATE): Allow malformed Prefix NLRI descriptor layout.
            return bgpls_validate_node_desc_tlv(prefix->local_node_descriptors,
                                                BGPLS_TLV_LOCAL_NODE_DESC,
                                                prefix->protocol_id) &&
                   !prefix->remote_node_descriptors &&
                   !prefix->link_descriptors &&
                   bgpls_validate_prefix_desc_chain(prefix->prefix_descriptors, prefix->nlri_type);
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
    int      offset = 0;
    int      body_start;
    uint16_t type_net;
    uint64_t id_net;
    uint16_t body_len;

    if (!buffer || !bgpls_prefix_valid(prefix)) {
        return -1;
    }
    const bgpls_tlv_t *chains[] = {prefix->local_node_descriptors, prefix->remote_node_descriptors,
                                    prefix->link_descriptors, prefix->prefix_descriptors};
    int body_size = 9;
    for (size_t i = 0; i < sizeof(chains) / sizeof(*chains); i++) {
        int len = bgpls_tlv_chain_wire_len(chains[i]);
        if (len < 0 || len > UINT16_MAX - body_size) return -1;
        body_size += len;
    }

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
                                    nlri->prefix.link_descriptors, nlri->prefix.prefix_descriptors};
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
