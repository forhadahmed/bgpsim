/*
 * BGP UPDATE Message Generation - FlowSpec Extensions
 * Implements IPv4 FlowSpec (RFC 8955), IPv6 FlowSpec (RFC 8956), VPN FlowSpec
 * (RFC 8955 section 8), the redirect-to-IP actions, and the action set for
 * steering into an SR Policy (draft-ietf-idr-ts-flowspec-srv6-policy).
 */

#define OUTPUT_STDIO_REMAP

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "bgp.h"
#include "output.h"
#include "bgp_update.h"

// FlowSpec Rule Helper Functions

/*
 * Deep-copy a flowspec_rule_t.  The caller owns the returned rule's
 * heap-allocated arrays (components[].values and components itself).
 */
static int flowspec_rule_deep_copy(flowspec_rule_t *dst, const flowspec_rule_t *src) {
    int i;

    dst->num_components = src->num_components;
    if (src->num_components == 0) {
        dst->components = NULL;
        return 0;
    }

    dst->components = malloc((size_t)src->num_components * sizeof(flowspec_component_t));
    if (!dst->components) {
        return -1;
    }

    for (i = 0; i < src->num_components; i++) {
        dst->components[i].type = src->components[i].type;
        dst->components[i].prefix_len = src->components[i].prefix_len;
        dst->components[i].prefix_offset = src->components[i].prefix_offset;
        memcpy(dst->components[i].prefix, src->components[i].prefix, 16);
        dst->components[i].num_values = src->components[i].num_values;

        if (src->components[i].num_values > 0 && src->components[i].values) {
            dst->components[i].values =
                malloc((size_t)src->components[i].num_values * sizeof(flowspec_op_value_t));
            if (!dst->components[i].values) {
                // Clean up already-copied entries
                int j;
                for (j = 0; j < i; j++) {
                    free(dst->components[j].values);
                }
                free(dst->components);
                dst->components = NULL;
                return -1;
            }
            memcpy(dst->components[i].values,
                   src->components[i].values,
                   (size_t)src->components[i].num_values *
                       sizeof(flowspec_op_value_t));
        } else {
            dst->components[i].values = NULL;
        }
    }

    return 0;
}

static void flowspec_rule_cleanup(flowspec_rule_t *rule) {
    int i;

    if (!rule->components) {
        return;
    }

    for (i = 0; i < rule->num_components; i++) {
        free(rule->components[i].values);
    }
    free(rule->components);
    rule->components = NULL;
    rule->num_components = 0;
}

// FlowSpec NLRI Functions

static flowspec_nlri_t* flowspec_nlri_create_internal(const flowspec_rule_t *rule,
                                                      int add_path,
                                                      uint32_t path_id,
                                                      const route_distinguisher_t *rd) {
    flowspec_nlri_t *nlri = calloc(1, sizeof(flowspec_nlri_t));

    if (!nlri) {
        return NULL;
    }

    if (flowspec_rule_deep_copy(&nlri->rule, rule) < 0) {
        free(nlri);
        return NULL;
    }

    nlri->path_id = path_id;
    nlri->add_path = (uint8_t)(add_path ? 1 : 0);
    if (rd) {
        nlri->has_rd = 1;
        nlri->rd = *rd;
    }
    nlri->next = NULL;
    return nlri;
}

/*
 * New SAFI 133 NLRI entry with a deep copy of rule; free the list with flowspec_nlri_list_free().
 */
flowspec_nlri_t* flowspec_nlri_create(const flowspec_rule_t *rule) {
    return flowspec_nlri_create_internal(rule, 0, 0, NULL);
}

/*
 * As flowspec_nlri_create(), with an ADD-PATH path ID.
 */
flowspec_nlri_t* flowspec_nlri_create_path_id(const flowspec_rule_t *rule, uint32_t path_id) {
    return flowspec_nlri_create_internal(rule, 1, path_id, NULL);
}

/*
 * New SAFI 134 (VPN FlowSpec) entry: the rule plus its RD.
 */
flowspec_nlri_t* flowspec_nlri_create_vpn(const flowspec_rule_t *rule, route_distinguisher_t rd) {
    return flowspec_nlri_create_internal(rule, 0, 0, &rd);
}

/*
 * As flowspec_nlri_create_vpn(), with an ADD-PATH path ID.
 */
flowspec_nlri_t* flowspec_nlri_create_vpn_path_id(const flowspec_rule_t *rule,
                                                  route_distinguisher_t rd,
                                                  uint32_t path_id) {
    return flowspec_nlri_create_internal(rule, 1, path_id, &rd);
}

/*
 * Custom list utilities -- cannot use DEFINE_NLRI_LIST_UTILS because
 * flowspec_nlri_t owns heap memory inside the rule.
 */

void flowspec_nlri_append(flowspec_nlri_t **list_head, flowspec_nlri_t **list_tail, flowspec_nlri_t *new_nlri) {
    if (!new_nlri) {
        return;
    }

    if (*list_tail) {
        (*list_tail)->next = new_nlri;
        *list_tail = new_nlri;
    } else {
        *list_head = new_nlri;
        *list_tail = new_nlri;
    }
}

int flowspec_nlri_count(flowspec_nlri_t *list) {
    int count = 0;

    while (list) {
        count++;
        list = list->next;
    }

    return count;
}

void flowspec_nlri_list_free(flowspec_nlri_t *list) {
    while (list) {
        flowspec_nlri_t *next = list->next;
        flowspec_rule_cleanup(&list->rule);
        free(list);
        list = next;
    }
}

// FlowSpec Encoding Functions

static int flowspec_op_value_len(uint8_t op) {
    return 1 << ((op >> 4) & 0x03);
}

/*
 * Encode a single operator-value pair into the buffer.
 * Returns the number of bytes written.
 */
int bgp_encode_flowspec_op_value(uint8_t *buffer, const flowspec_op_value_t *ov) {
    int offset = 0;
    int value_len = flowspec_op_value_len(ov->op);

    // Write operator byte
    buffer[offset++] = ov->op;
    // TODO(WIRE_MUTATION): Flip the end-of-list, AND, length, or reserved operator bits.

    // Write value in network byte order
    switch (value_len) {
    case 1:
        buffer[offset++] = (uint8_t)(ov->value & 0xFF);
        break;
    case 2: {
        uint16_t net = htons((uint16_t)(ov->value & 0xFFFF));
        memcpy(buffer + offset, &net, 2);
        offset += 2;
        break;
    }
    case 4: {
        uint32_t net = htonl(ov->value);
        memcpy(buffer + offset, &net, 4);
        offset += 4;
        break;
    }
    case 8:
        /*
         * For 8-byte values, write high 4 bytes as zero + low 4 bytes.
         * Our value field is uint32_t, so the top 4 bytes are always zero.
         */
        memset(buffer + offset, 0, 4);
        offset += 4;
        {
            uint32_t net = htonl(ov->value);
            memcpy(buffer + offset, &net, 4);
            offset += 4;
        }
        break;
    }

    return offset;
}

/*
 * Types 1 and 2 are prefixes; the others are operator lists.
 */
static int flowspec_component_is_prefix(uint8_t type) {
    return type == FLOWSPEC_DEST_PREFIX || type == FLOWSPEC_SRC_PREFIX;
}

/*
 * Types 9 (TCP flags) and 12 (fragment) use bitmask_op; the others use
 * numeric_op (RFC 8955 section 4.2.1).
 */
static int flowspec_component_is_bitmask(uint8_t type) {
    return type == FLOWSPEC_TCP_FLAGS || type == FLOWSPEC_FRAGMENT;
}

/*
 * Type 13 (Flow Label) exists only for IPv6 (RFC 8956 section 3.7).
 */
static int flowspec_max_component_type(uint16_t afi) {
    return (afi == AFI_IPV6) ? FLOWSPEC_FLOW_LABEL : FLOWSPEC_FRAGMENT;
}

/*
 * Check a prefix component: IPv4 has no offset and a length up to 32; IPv6 needs offset < length <= 128, or both 0
 * (RFC 8956 section 3.1).
 */
static int flowspec_validate_prefix_component(const flowspec_component_t *comp, uint16_t afi) {
    // TODO(FUZZ_GATE): Allow IPv6 offset >= length and lengths past the address size.
    if (afi == AFI_IPV4) {
        return (comp->prefix_offset == 0 && comp->prefix_len <= 32) ? 0 : -1;
    }

    if (afi == AFI_IPV6) {
        if (comp->prefix_len > 128 || comp->prefix_offset > 128) {
            return -1;
        }
        if (comp->prefix_len == 0) {
            return (comp->prefix_offset == 0) ? 0 : -1;
        }
        return (comp->prefix_offset < comp->prefix_len) ? 0 : -1;
    }

    return -1;
}

/*
 * Check one {operator, value} list.
 *
 * RFC 8955 section 4.2.1: the end-of-list bit is set on the last pair only,
 * the AND bit MUST be unset on the first pair, and the reserved operator bits
 * MUST be zero. A list without its end bit makes the receiver read the next
 * component as more operators, so the NLRI is malformed.
 *
 * Per-type value widths that are MUST rules: TCP flags 1 or 2 octets
 * (4.2.2.9), DSCP 1 octet (4.2.2.11), fragment 1 octet (4.2.2.12, RFC 8956
 * 3.6). The fragment bits that are not defined MUST be zero; for IPv6 that
 * includes DF (RFC 8956 section 3.6). SHOULD widths are not enforced.
 */
static int flowspec_validate_op_list(const flowspec_component_t *comp, uint16_t afi) {
    int      bitmask = flowspec_component_is_bitmask(comp->type);
    uint8_t  reserved = bitmask ? FLOWSPEC_BITMASK_OP_RESERVED : FLOWSPEC_NUMERIC_OP_RESERVED;
    uint32_t frag_zero_bits = (afi == AFI_IPV6) ? 0xF1u : 0xF0u;
    int      i;

    // TODO(FUZZ_GATE): Allow a component with an empty {operator, value} list.
    if (comp->num_values <= 0 || !comp->values) {
        return -1;
    }

    for (i = 0; i < comp->num_values; i++) {
        uint8_t  op = comp->values[i].op;
        uint32_t value = comp->values[i].value;
        int      value_len = flowspec_op_value_len(op);
        int      last = (i == comp->num_values - 1);

        // TODO(FUZZ_GATE): Allow a missing, early, or repeated end-of-list bit.
        if (((op & FLOWSPEC_OP_END) != 0) != last) {
            return -1;
        }
        // TODO(FUZZ_GATE): Allow the AND bit on the first operator.
        if (i == 0 && (op & FLOWSPEC_OP_AND)) {
            return -1;
        }
        // TODO(FUZZ_GATE): Allow nonzero reserved operator bits.
        if (op & reserved) {
            return -1;
        }
        // TODO(FUZZ_GATE): Allow a value wider than its operator length (the encoder truncates it).
        if (value_len < 4 && (value >> (8 * value_len)) != 0) {
            return -1;
        }
        // TODO(FUZZ_GATE): Allow value widths that RFC 8955 / RFC 8956 forbid for the type.
        if (comp->type == FLOWSPEC_TCP_FLAGS && value_len > 2) {
            return -1;
        }
        if ((comp->type == FLOWSPEC_DSCP || comp->type == FLOWSPEC_FRAGMENT) && value_len != 1) {
            return -1;
        }
        if (comp->type == FLOWSPEC_FRAGMENT && (value & frag_zero_bits) != 0) {
            return -1;
        }
    }

    return 0;
}

/*
 * Check one component for afi: a known type (13 is IPv6 only) and a valid prefix or operator list.
 */
static int flowspec_validate_component(const flowspec_component_t *comp, uint16_t afi) {
    if (afi != AFI_IPV4 && afi != AFI_IPV6) {
        return -1;
    }
    // TODO(FUZZ_GATE): Allow unknown component types and Flow Label (13) in IPv4 rules.
    if (comp->type < 1 || comp->type > flowspec_max_component_type(afi)) {
        return -1;
    }
    if (flowspec_component_is_prefix(comp->type)) {
        return flowspec_validate_prefix_component(comp, afi);
    }
    return flowspec_validate_op_list(comp, afi);
}

/*
 * Encoded size of one valid component. Stops counting once the size passes
 * FLOWSPEC_MAX_NLRI_LEN, so a huge value list cannot overflow the int.
 */
static int flowspec_component_size(const flowspec_component_t *comp, uint16_t afi) {
    int size = 1;
    int i;

    if (flowspec_component_is_prefix(comp->type)) {
        int start_bit = (afi == AFI_IPV6) ? comp->prefix_offset : 0;

        size += (afi == AFI_IPV6) ? 2 : 1;
        return size + bgp_prefix_bytes_needed((uint8_t)(comp->prefix_len - start_bit));
    }

    for (i = 0; i < comp->num_values && size <= FLOWSPEC_MAX_NLRI_LEN; i++) {
        size += 1 + flowspec_op_value_len(comp->values[i].op);
    }
    return size;
}

/*
 * Write the prefix pattern of a component: bits offset to length - 1 of the address, packed from the first bit, with
 * the bits after the length zero (RFC 8956 section 3.1; IPv4 has no offset). Returns the bytes written.
 */
static int flowspec_extract_prefix_pattern(uint8_t *buffer, const flowspec_component_t *comp, uint16_t afi) {
    int start_bit = (afi == AFI_IPV6) ? comp->prefix_offset : 0;
    int pattern_bits = comp->prefix_len - start_bit;
    int pattern_bytes = bgp_prefix_bytes_needed(pattern_bits);
    int first = start_bit / 8;
    int shift = start_bit % 8;
    int i;

    // Bits start_bit..prefix_len-1, moved to the front a byte at a time.
    for (i = 0; i < pattern_bytes; i++) {
        uint8_t next = (shift && first + i + 1 < (int)sizeof(comp->prefix)) ? comp->prefix[first + i + 1] : 0;

        buffer[i] = (uint8_t)((comp->prefix[first + i] << shift) | (shift ? next >> (8 - shift) : 0));
    }
    // Bits past the prefix length are zero on the wire.
    if (pattern_bits % 8) {
        buffer[pattern_bytes - 1] &= (uint8_t)(0xFF << (8 - pattern_bits % 8));
    }

    return pattern_bytes;
}

/*
 * Write one component that flowspec_validate_component() accepted. The buffer
 * must hold flowspec_component_size() octets. Returns the bytes written.
 */
static int flowspec_write_component(uint8_t *buffer, const flowspec_component_t *comp, uint16_t afi) {
    int offset = 0;

    // Write component type
    buffer[offset++] = comp->type;
    // TODO(WIRE_MUTATION): Corrupt the component type (unknown type, or break the ascending order).

    if (flowspec_component_is_prefix(comp->type)) {
        // Prefix component: IPv4 uses <type,len,prefix>; IPv6 adds offset.
        buffer[offset++] = comp->prefix_len;
        if (afi == AFI_IPV6) {
            buffer[offset++] = comp->prefix_offset;
        }

        int bytes = flowspec_extract_prefix_pattern(buffer + offset, comp, afi);
        offset += bytes;
    } else {
        // Operator-value component: type(1) | [op(1) | value(variable)]+
        int i;
        for (i = 0; i < comp->num_values; i++) {
            offset += bgp_encode_flowspec_op_value(buffer + offset, &comp->values[i]);
        }
    }

    return offset;
}

/*
 * Encode a single FlowSpec component into the buffer. The buffer must hold
 * the encoded component; bgp_encode_flowspec_rule_afi() checks this.
 * Returns the number of bytes written, or -1 on error.
 */
int bgp_encode_flowspec_component_afi(uint8_t *buffer, const flowspec_component_t *comp, uint16_t afi) {
    if (flowspec_validate_component(comp, afi) < 0) {
        return -1;
    }
    return flowspec_write_component(buffer, comp, afi);
}

int bgp_encode_flowspec_component(uint8_t *buffer, const flowspec_component_t *comp) {
    return bgp_encode_flowspec_component_afi(buffer, comp, AFI_IPV4);
}

/*
 * Validate a FlowSpec rule: components must be in ascending type order, and
 * each component must be valid for the AFI.
 * Returns 0 on success, -1 on validation failure.
 */
static int bgp_validate_flowspec_rule_internal(const flowspec_rule_t *rule, uint16_t afi) {
    int i;

    if (!rule || rule->num_components <= 0 || !rule->components) {
        return -1;
    }

    for (i = 0; i < rule->num_components; i++) {
        // TODO(FUZZ_GATE): Allow unordered or repeated component types (RFC 8955 section 4.2).
        if (i > 0 && rule->components[i].type <= rule->components[i - 1].type) {
            return -1;
        }
        if (flowspec_validate_component(&rule->components[i], afi) < 0) {
            return -1;
        }
    }

    return 0;
}

int bgp_validate_flowspec_rule(const flowspec_rule_t *rule) {
    return bgp_validate_flowspec_rule_internal(rule, AFI_IPV4);
}

/*
 * Check one rule and return the encoded length of its components, or -1 when
 * the rule is invalid or the components need more than capacity octets. The
 * components are checked once here; flowspec_write_rule_body() writes them.
 */
static int flowspec_rule_body_len(const flowspec_rule_t *rule, int capacity, uint16_t afi) {
    int body_len = 0;
    int i;

    if (bgp_validate_flowspec_rule_internal(rule, afi) < 0) {
        return -1;
    }

    for (i = 0; i < rule->num_components; i++) {
        int comp_len = flowspec_component_size(&rule->components[i], afi);

        // TODO(FUZZ_GATE): Allow NLRI values longer than the 4095-octet length field.
        if (comp_len > capacity - body_len) {
            return -1;
        }
        body_len += comp_len;
    }

    return body_len;
}

/*
 * Write the components of a rule that flowspec_rule_body_len() accepted. Returns the bytes written.
 */
static int flowspec_write_rule_body(uint8_t *body, const flowspec_rule_t *rule, uint16_t afi) {
    int body_len = 0;

    for (int i = 0; i < rule->num_components; i++) {
        body_len += flowspec_write_component(body + body_len, &rule->components[i], afi);
    }
    return body_len;
}

/*
 * RFC 8955 section 4.1: a value shorter than 240 octets uses a 1-octet
 * length. A longer value uses 2 octets: 0xf in the high nibble and a 12-bit
 * length, so the largest value is 4095 octets. Returns the bytes written.
 */
static int flowspec_write_nlri_length(uint8_t *buffer, int value_len) {
    if (value_len < 240) {
        buffer[0] = (uint8_t)value_len;
        // TODO(WIRE_MUTATION): Corrupt the 1-octet FlowSpec NLRI length.
        return 1;
    }

    buffer[0] = (uint8_t)(0xF0 | ((value_len >> 8) & 0x0F));
    buffer[1] = (uint8_t)(value_len & 0xFF);
    // TODO(WIRE_MUTATION): Corrupt the 2-octet FlowSpec NLRI length or clear its 0xf nibble.
    return 2;
}

/*
 * Encode a complete FlowSpec rule (one NLRI entry) into the buffer.
 * Writes the NLRI length prefix (1 byte if < 240, 2 bytes otherwise)
 * followed by the component data.
 * Returns the total number of bytes written, or -1 on error.
 */
int bgp_encode_flowspec_rule_afi(uint8_t *buffer, const flowspec_rule_t *rule, uint16_t afi) {
    int body_len = flowspec_rule_body_len(rule, FLOWSPEC_MAX_NLRI_LEN, afi);
    int offset;

    if (body_len < 0) {
        return -1;
    }

    // The length is known first, so the components go straight after it.
    offset = flowspec_write_nlri_length(buffer, body_len);
    return offset + flowspec_write_rule_body(buffer + offset, rule, afi);
}

int bgp_encode_flowspec_rule(uint8_t *buffer, const flowspec_rule_t *rule) {
    return bgp_encode_flowspec_rule_afi(buffer, rule, AFI_IPV4);
}

// FlowSpec NLRI Encoding

/*
 * One NLRI entry: [path-id] length value. With an RD (SAFI 134) the value
 * starts with the 8-octet Route Distinguisher, and the length covers it, as
 * RFC 8955 section 8 requires. Returns the bytes written, or -1.
 */
int bgp_encode_flowspec_nlri_entry(uint8_t *buffer,
                                   const flowspec_rule_t *rule,
                                   const route_distinguisher_t *rd,
                                   uint16_t afi,
                                   int add_path,
                                   uint32_t path_id) {
    int rd_len = rd ? 8 : 0;
    int body_len = flowspec_rule_body_len(rule, FLOWSPEC_MAX_NLRI_LEN - rd_len, afi);
    int offset = 0;

    // The rule is checked before the first octet is written, so an invalid rule leaves buffer unchanged.
    if (body_len < 0) {
        return -1;
    }

    if (add_path) {
        uint32_t path_id_net = htonl(path_id);
        memcpy(buffer + offset, &path_id_net, sizeof(path_id_net));
        offset += sizeof(path_id_net);
    }

    // The length is known first, so the RD and the components go straight after it.
    offset += flowspec_write_nlri_length(buffer + offset, rd_len + body_len);
    if (rd) {
        bgp_encode_rd(buffer + offset, rd);
        offset += 8;
    }
    return offset + flowspec_write_rule_body(buffer + offset, rule, afi);
}

/*
 * Encode one list entry. The entry must have an RD exactly when safi is SAFI_FLOWSPEC_VPN.
 */
static int bgp_encode_flowspec_nlri(uint8_t *buffer,
                                    const flowspec_nlri_t *nlri,
                                    int add_path,
                                    uint16_t afi,
                                    uint8_t safi) {
    if ((nlri->has_rd != 0) != (safi == SAFI_FLOWSPEC_VPN)) {
        return -1;
    }

    return bgp_encode_flowspec_nlri_entry(buffer, &nlri->rule, nlri->has_rd ? &nlri->rd : NULL,
                                          afi, add_path, nlri->path_id);
}

// ADD-PATH Detection

DEFINE_ADD_PATH_DETECTOR(bgp_detect_flowspec_add_path, flowspec_nlri_t, do { } while (0))

// Chunking

static int encode_flowspec_chunk(flowspec_nlri_t **cursor,
                                 uint8_t *buffer,
                                 int max_bytes,
                                 int add_path,
                                 uint16_t afi,
                                 uint8_t safi) {
    int written = 0;

    while (*cursor) {
        uint8_t scratch[FLOWSPEC_MAX_NLRI_ENTRY_LEN];
        int     needed = bgp_encode_flowspec_nlri(scratch, *cursor, add_path, afi, safi);

        if (needed <= 0) {
            return -1;
        }

        if ((int)(*cursor)->add_path != add_path) {
            return -1;
        }

        if (written + needed > max_bytes) {
            return (written > 0) ? written : -1;
        }

        memcpy(buffer + written, scratch, (size_t)needed);
        written += needed;
        *cursor = (*cursor)->next;
    }

    return written;
}

/*
 * MP_REACH next hop for FlowSpec. RFC 8955 section 4 says the length MUST be
 * 0, which is the result for a NULL next_hop. The redirect-to-next-hop
 * community (type 0x08, draft-simpson-idr-flowspec-redirect) is the only user
 * of a non-zero next hop: 4 octets (IPv4), 16 (IPv6), or 32 (IPv6 with
 * link-local). Either address family can go with either AFI.
 */
static int flowspec_encode_next_hop(const bgp_next_hop_t *next_hop, uint8_t *buffer, uint8_t *nh_len) {
    *nh_len = 0;
    if (!next_hop) {
        return 0;
    }

    // TODO(FUZZ_GATE): Allow next-hop lengths other than 4, 16, or 32 octets.
    return bgp_encode_standard_next_hop(next_hop, buffer, nh_len);
}

// Traffic Filtering Extended Communities

/*
 * Traffic Rate (type 0x8006): rate-limit matching traffic.
 * Value: 2-byte informational AS + 4-byte IEEE 754 float rate (bytes/sec).
 * A rate of 0.0 means discard (drop).
 */
bgp_path_attr_t* bgp_attr_create_flowspec_rate(uint16_t as, float rate) {
    bgp_path_attr_t *attr = bgp_attr_alloc_ext_comm(0x80, 0x06);
    uint16_t         as_net = htons(as);
    uint32_t         rate_bits;

    if (!attr) {
        return NULL;
    }

    memcpy(attr->value + 2, &as_net, 2);
    memcpy(&rate_bits, &rate, sizeof(rate_bits));
    rate_bits = htonl(rate_bits);
    memcpy(attr->value + 4, &rate_bits, 4);
    return attr;
}

/*
 * Traffic-Rate-Packets (type 0x800c): packet-rate limit matching traffic.
 * Value: 2-byte informational AS + 4-byte IEEE 754 float rate (packets/sec).
 */
bgp_path_attr_t* bgp_attr_create_flowspec_rate_pkts(uint16_t as, float rate) {
    bgp_path_attr_t *attr = bgp_attr_alloc_ext_comm(0x80, 0x0c);
    uint16_t         as_net = htons(as);
    uint32_t         rate_bits;

    if (!attr) {
        return NULL;
    }

    memcpy(attr->value + 2, &as_net, 2);
    memcpy(&rate_bits, &rate, sizeof(rate_bits));
    rate_bits = htonl(rate_bits);
    memcpy(attr->value + 4, &rate_bits, 4);
    return attr;
}

/*
 * Traffic Action (type 0x8007): action flags for matching traffic.
 * Bit 0 (LSB) = terminal action, bit 1 = sample.
 */
bgp_path_attr_t* bgp_attr_create_flowspec_action(int terminal, int sample) {
    bgp_path_attr_t *attr = bgp_attr_alloc_ext_comm(0x80, 0x07);

    if (!attr) {
        return NULL;
    }

    attr->value[7] = (uint8_t)((terminal ? 0x01 : 0x00) | (sample ? 0x02 : 0x00));
    return attr;
}

/*
 * Redirect Route Target (type 0x8008): redirect matching traffic to a VRF.
 * Uses the original 2-byte-AS specific route-target format. Separate helpers
 * cover the IPv4-address-specific and 4-byte-AS formats.
 */
bgp_path_attr_t* bgp_attr_create_flowspec_redirect_rt(uint16_t as, uint32_t value) {
    return bgp_attr_create_ext_comm_global2(0x80, 0x08, as, value);
}

/*
 * Redirect Route Target (type 0x8108): IPv4-address-specific format.
 * Value: 4-byte IPv4 address + 2-byte local administrator.
 */
bgp_path_attr_t* bgp_attr_create_flowspec_redirect_rt_ip(uint32_t ipv4_address, uint16_t local_admin) {
    return bgp_attr_create_ext_comm_global4(0x81, 0x08, ipv4_address, local_admin);
}

/*
 * Redirect Route Target (type 0x8208): 4-byte-AS specific format.
 * Value: 4-byte AS + 2-byte local administrator.
 */
bgp_path_attr_t* bgp_attr_create_flowspec_redirect_rt_as4(uint32_t asn, uint16_t local_admin) {
    return bgp_attr_create_ext_comm_global4(0x82, 0x08, asn, local_admin);
}

/*
 * Traffic Marking (type 0x8009): set DSCP value on matching traffic.
 * The two high-order bits of the last octet are reserved and MUST be zero
 * (RFC 8955 section 7.5), so the DSCP value is at most 63.
 */
bgp_path_attr_t* bgp_attr_create_flowspec_marking(uint8_t dscp) {
    bgp_path_attr_t *attr;

    // TODO(FUZZ_GATE): Allow DSCP values above 63 (reserved bits set).
    if (dscp > 63) {
        return NULL;
    }

    attr = bgp_attr_alloc_ext_comm(0x80, 0x09);
    if (!attr) {
        return NULL;
    }

    attr->value[7] = dscp;
    return attr;
}

// Redirect and Interface-Set Extended Communities

/*
 * Redirect-to-IPv4 (draft-ietf-idr-flowspec-redirect-ip section 2): IPv4
 * Address Specific community, Type=0x01 Sub-Type=0x0c. The Global
 * Administrator is the target address. In the Local Administrator only the
 * low-order bit is defined, C (copy); the other bits MUST be zero on send and
 * are ignored on receipt.
 */
bgp_path_attr_t* bgp_attr_create_flowspec_redirect_ipv4(uint32_t ipv4_address, int copy) {
    // TODO(WIRE_MUTATION): Set reserved Local Administrator bits; the receiver must ignore them.
    return bgp_attr_create_ext_comm_global4(0x01, 0x0c, ipv4_address, (uint16_t)(copy ? 0x0001 : 0x0000));
}

/*
 * Redirect-to-IPv6 (same draft): IPv6 Address Specific community (attribute
 * 25), Type=0x00 Sub-Type=0x0c, with the same Local Administrator layout.
 */
bgp_path_attr_t* bgp_attr_create_flowspec_redirect_ipv6(const struct in6_addr *ipv6_address, int copy) {
    return bgp_attr_create_ipv6_ext_comm(0x00, 0x0c, ipv6_address, (uint16_t)(copy ? 0x0001 : 0x0000));
}

/*
 * Redirect/mirror to IP next-hop (draft-simpson-idr-flowspec-redirect,
 * IANA type 0x08 sub-type 0x00). The target is the MP_REACH next hop, so the
 * UPDATE needs bgp_flowspec_update_opts_t.next_hop. The low-order bit of the
 * 6-octet value is C (copy); the other bits are zero.
 */
bgp_path_attr_t* bgp_attr_create_flowspec_redirect_nexthop(int copy) {
    bgp_path_attr_t *attr = bgp_attr_alloc_ext_comm(0x08, 0x00);

    if (!attr) {
        return NULL;
    }

    attr->value[7] = (uint8_t)(copy ? 0x01 : 0x00);
    return attr;
}

/*
 * rt-redirect-ipv6 (RFC 8956 section 6.1): redirect to the VRF that imports
 * this IPv6 Address Specific Route Target. Type 0x000d in attribute 25.
 */
bgp_path_attr_t* bgp_attr_create_flowspec_redirect_rt_ipv6(const struct in6_addr *ipv6_address, uint16_t local_admin) {
    return bgp_attr_create_ipv6_ext_comm(0x00, 0x0d, ipv6_address, local_admin);
}

/*
 * Interface-set (draft-ietf-idr-flowspec-interfaceset section 3):
 *   Type=0x07 (transitive) or 0x47 (non-transitive) | Sub-Type=0x02 |
 *   AS(4) | O(1 bit) | I(1 bit) | Group Identifier(14 bits)
 * A community with both direction flags clear MUST make the receiver discard
 * the update.
 */
bgp_path_attr_t* bgp_attr_create_flowspec_interface_set(uint32_t asn,
                                                        uint16_t group_id,
                                                        int inbound,
                                                        int outbound,
                                                        int transitive) {
    uint16_t flags_group;

    // TODO(FUZZ_GATE): Allow both direction flags clear and group IDs above 14 bits.
    if ((!inbound && !outbound) || group_id > 0x3FFF) {
        return NULL;
    }

    flags_group = (uint16_t)((outbound ? 0x8000 : 0) | (inbound ? 0x4000 : 0) | group_id);
    return bgp_attr_create_ext_comm_global4((uint8_t)(transitive ? 0x07 : 0x47), 0x02, asn, flags_group);
}

// SR-TE Steering

/*
 * Mode 1 of draft-ietf-idr-ts-flowspec-srv6-policy (section 3.1.1): a
 * Redirect-to-IP community names the SR Policy endpoint and the Color
 * communities name the Colors, so (endpoint, Color) selects the policy.
 *
 * The communities are merged into one Extended Communities attribute (and
 * one IPv6 Address Specific attribute for an IPv6 redirect). Two separate
 * copies of attribute 16 would lose all but the first at the receiver
 * (RFC 7606 section 3 (g)).
 */
bgp_path_attr_t* bgp_attr_create_flowspec_srte(const bgp_flowspec_srte_t *steer) {
    bgp_path_attr_t *ext = NULL;
    bgp_path_attr_t *ext6 = NULL;
    int              i;

    if (!steer || !steer->colors || steer->num_colors <= 0 ||
        (steer->endpoint.af != AF_INET && steer->endpoint.af != AF_INET6)) {
        return NULL;
    }

    if (steer->via_next_hop) {
        ext = bgp_attr_create_flowspec_redirect_nexthop(steer->copy);
        if (!ext) {
            goto fail;
        }
    } else if (steer->endpoint.af == AF_INET) {
        ext = bgp_attr_create_flowspec_redirect_ipv4(ntohl(steer->endpoint.address.ipv4.s_addr), steer->copy);
        if (!ext) {
            goto fail;
        }
    } else {
        ext6 = bgp_attr_create_flowspec_redirect_ipv6(&steer->endpoint.address.ipv6, steer->copy);
        if (!ext6) {
            goto fail;
        }
    }

    for (i = 0; i < steer->num_colors; i++) {
        bgp_path_attr_t *color = bgp_attr_create_ext_comm_color(steer->colors[i].color, steer->colors[i].co_type);
        int              rc;

        if (!color) {
            goto fail;
        }
        if (!ext) {
            ext = color;
            continue;
        }
        rc = bgp_attr_ext_comm_append_attr(ext, color);
        bgp_path_attr_free(color);
        if (rc < 0) {
            goto fail;
        }
    }

    ext->next = ext6;
    return ext;

fail:
    bgp_path_attr_free(ext);
    bgp_path_attr_free(ext6);
    return NULL;
}

// MESSAGE GENERATION with splitting support

bgp_update_result_t* bgp_generate_update_flowspec(
    flowspec_nlri_t *nlri_list,
    bgp_path_attr_t *attributes,
    flowspec_nlri_t *withdrawn_list,
    const bgp_flowspec_update_opts_t *opts)
{
    bgp_builder_t    builder = {0};
    uint8_t         *base_attr_data = NULL;
    uint16_t         base_attr_len = 0;
    uint8_t         *nlri_buffer = NULL;
    uint8_t          next_hop[BGP_STANDARD_NEXT_HOP_BUF_SIZE];
    uint8_t          nh_len = 0;
    int              available_space;
    int              nlri_add_path = 0;
    int              withdrawn_add_path = 0;
    uint16_t         afi = opts ? opts->afi : 0;
    uint8_t          safi = opts ? opts->safi : 0;
    uint16_t         max_pdu_size = opts ? opts->max_pdu_size : 0;
    flowspec_nlri_t *curr;

    if (!opts) {
        return NULL;
    }

    if (afi != AFI_IPV4 && afi != AFI_IPV6) {
        return NULL;
    }
    if (safi != SAFI_FLOWSPEC && safi != SAFI_FLOWSPEC_VPN) {
        return NULL;
    }

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

    if (flowspec_encode_next_hop(opts->next_hop, next_hop, &nh_len) < 0) {
        return NULL;
    }

    if (bgp_detect_flowspec_add_path(nlri_list, &nlri_add_path) < 0 ||
        bgp_detect_flowspec_add_path(withdrawn_list, &withdrawn_add_path) < 0) {
        return NULL;
    }

    if (bgp_serialize_path_attributes_alloc(attributes,
                                            &base_attr_data,
                                            &base_attr_len) < 0) {
        return NULL;
    }

    if (nlri_list) {
        if (!bgp_validate_mp_attrs(attributes)) {
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
            int nlri_len = encode_flowspec_chunk(&curr, nlri_buffer, available_space, withdrawn_add_path, afi, safi);
            if (nlri_len <= 0 ||
                bgp_builder_append_mp(&builder, &(bgp_mp_args_t){
                    .afi         = afi,
                    .safi        = safi,
                    .mp_nlri     = nlri_buffer,
                    .mp_nlri_len = (uint16_t)nlri_len,
                }) < 0) {
                goto fail;
            }
        }
    }

    if (nlri_list) {
        /*
         * The per-message budget is AFI/SAFI + NH_LEN + next hop + reserved
         * octet + encoded NLRI. The next hop is empty unless opts set one.
         */
        available_space = bgp_mp_reach_payload_budget(max_pdu_size, base_attr_len, nh_len);
        if (available_space <= 0) {
            goto fail;
        }

        curr = nlri_list;
        while (curr) {
            int nlri_len = encode_flowspec_chunk(&curr, nlri_buffer, available_space, nlri_add_path, afi, safi);
            if (nlri_len <= 0 ||
                bgp_builder_append_mp(&builder, &(bgp_mp_args_t){
                    .attrs       = base_attr_data,
                    .attrs_len   = base_attr_len,
                    .is_reach    = 1,
                    .afi         = afi,
                    .safi        = safi,
                    .next_hop    = nh_len ? next_hop : NULL,
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

