#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "bgp.h"
#include "bgp_update.h"

int bgp_prefix_bytes_needed(uint8_t prefix_len) {
    return (prefix_len + 7) / 8;
}

bgp_path_attr_t* bgp_attr_alloc(uint8_t flags, uint8_t type_code, uint16_t length) {
    bgp_path_attr_t *attr = calloc(1, sizeof(bgp_path_attr_t));

    if (!attr) {
        return NULL;
    }

    attr->flags = flags;
    attr->type_code = type_code;
    attr->length = length;
    attr->next = NULL;
    attr->value = NULL;

    if (length > 0) {
        attr->value = malloc(length);
        if (!attr->value) {
            free(attr);
            return NULL;
        }
    }

    return attr;
}

uint8_t bgp_attr_wire_flags(const bgp_path_attr_t *attr) {
    uint8_t flags = attr->flags;

    if (attr->length > 255) {
        flags |= BGP_ATTR_FLAG_EXTENDED_LEN;
    } else {
        flags &= (uint8_t)~BGP_ATTR_FLAG_EXTENDED_LEN;
    }

    return flags;
}

int bgp_marshaled_attr_size(uint8_t flags, uint16_t value_len) {
    if (value_len > 255) {
        flags |= BGP_ATTR_FLAG_EXTENDED_LEN;
    } else {
        flags &= (uint8_t)~BGP_ATTR_FLAG_EXTENDED_LEN;
    }

    return 2 + ((flags & BGP_ATTR_FLAG_EXTENDED_LEN) ? 2 : 1) + value_len;
}

int bgp_attr_list_contains_type(const bgp_path_attr_t *attr_list, uint8_t type_code) {
    const bgp_path_attr_t *curr = attr_list;

    while (curr) {
        if (curr->type_code == type_code) {
            return 1;
        }
        curr = curr->next;
    }

    return 0;
}

/*
 * Check the attribute list of a classic IPv4 unicast UPDATE. Returns 0 when it is valid, else -1.
 */
int bgp_validate_ipv4_attrs(const bgp_path_attr_t *attr_list) {
    /*
     * Classic UPDATE-format IPv4 unicast still uses the base RFC 4271
     * withdrawn-routes / path-attributes / NLRI layout rather than MP_REACH.
     * In strict mode that means ORIGIN, AS_PATH, and NEXT_HOP must already
     * exist before the encoder can legally place trailing IPv4 NLRI on the
     * wire.
     */
    /*
     * TODO(FUZZ_GATE): Allow classic IPv4 UPDATEs missing mandatory attrs.
     *
     * RFC 4271 section 5 declares ORIGIN, AS_PATH, and NEXT_HOP as
     * "well-known mandatory" for any UPDATE that carries NLRI. RFC 4271
     * section 6.3 answers a missing one with a NOTIFICATION (Missing
     * Well-known Attribute). RFC 7606 section 3 (d) replaces that with
     * "treat-as-withdraw" for every missing mandatory attribute; the
     * receiver does not choose between the two.
     *
     * Fuzz use case: generate an UPDATE with NLRI but missing one
     * of the three mandatory attrs. Useful for testing:
     *
     *   - Missing ORIGIN: per RFC 7606, treat-as-withdraw.
     *     Target: verify the receiver withdraws cleanly without
     *     leaking previously-installed routes.
     *
     *   - Missing AS_PATH: per RFC 7606, treat-as-withdraw.
     *     Target: same as ORIGIN, plus loop detection edge cases.
     *
     *   - Missing NEXT_HOP: per RFC 7606, treat-as-withdraw.
     *     Target: whether the receiver correctly rejects the NLRI
     *     without attempting to install a route with no next-hop
     *     (historical "route with zero next-hop" bugs).
     *
     * This gate is symmetric with bgp_validate_mp_attrs() which
     * enforces only ORIGIN and AS_PATH (NEXT_HOP is in the
     * MP_REACH attribute itself for MP families).
     *
     * Proposed allow key: "mandatory.ipv4-missing-attr"
     */
    return bgp_attr_list_contains_type(attr_list, BGP_ATTR_ORIGIN) &&
           bgp_attr_list_contains_type(attr_list, BGP_ATTR_AS_PATH) &&
           bgp_attr_list_contains_type(attr_list, BGP_ATTR_NEXT_HOP);
}

int bgp_validate_mp_attrs(const bgp_path_attr_t *attr_list) {
    return bgp_attr_list_contains_type(attr_list, BGP_ATTR_ORIGIN) &&
           bgp_attr_list_contains_type(attr_list, BGP_ATTR_AS_PATH);
}

static int bgp_write_raw_attr_header(uint8_t *buffer, uint8_t flags, uint8_t type_code, uint16_t value_len) {
    uint8_t wire_flags = flags;
    int     offset = 0;

    if (value_len > 255) {
        wire_flags |= BGP_ATTR_FLAG_EXTENDED_LEN;
    } else {
        wire_flags &= (uint8_t)~BGP_ATTR_FLAG_EXTENDED_LEN;
    }
    /*
     * TODO(WIRE_MUTATION): Corrupt path attribute header (flags / type / length).
     *
     * Each path attribute is [flags(1) | type(1) | length(1 or 2)].
     * The extended-length bit in flags selects between a 1-byte and
     * 2-byte length field, so THREE logical fields live here with
     * different fuzz profiles.
     *
     * Useful mutations (listed in decreasing framing-cascade severity):
     *
     *   - Flip BGP_ATTR_FLAG_EXTENDED_LEN in flags:
     *       Decoder now reads 1 byte where 2 were written (or vice
     *       versa). EVERY subsequent path attribute in the same UPDATE
     *       shifts. This usually pushes the NLRI boundary into the
     *       middle of a real attribute. Highest-value framing corruption
     *       at the attribute level.
     *
     *   - Shrink length by N (keep extended-length consistent):
     *       Peer treats last N bytes of this attr's value as the start
     *       of the next attr header. Next attr's flags/type/length
     *       become garbage, cascading further.
     *
     *   - Grow length by N:
     *       Peer reads into the next attr's bytes as value of this one.
     *       Next-attr parse hits wrong offset.
     *
     *   - Set to 0xFF / 0xFFFF:
     *       Claims value extends beyond total_path_attribute_length.
     *       Tests cross-check between attr-header length and the
     *       containing attrs-region length.
     *
     *   - Corrupt type:
     *       Value-level. Not a framing hazard (length is still honored),
     *       but useful for testing unknown-type handling and the
     *       "transitive unknown attr must be passed through" rule.
     *
     *   - Flip other flags bits (Optional / Transitive / Partial):
     *       Mostly value-level, but the Optional bit interacts with
     *       the "unknown optional attr" rule in RFC 4271 section 5.
     *
     * This is the highest-value framing hook INSIDE the attributes
     * region. For a fuzz run targeting parser framing bugs, the
     * extended-length bit toggle is the first thing to try.
     */

    if (buffer) {
        buffer[offset] = wire_flags;
    }
    offset++;

    if (buffer) {
        buffer[offset] = type_code;
    }
    offset++;

    if (wire_flags & BGP_ATTR_FLAG_EXTENDED_LEN) {
        uint16_t length_net = htons(value_len);

        if (buffer) {
            memcpy(buffer + offset, &length_net, sizeof(length_net));
        }
        offset += 2;
    } else {
        if (buffer) {
            buffer[offset] = (uint8_t)value_len;
        }
        offset++;
    }

    return offset;
}

int bgp_serialize_raw_path_attr(uint8_t *buffer,
                                uint8_t flags,
                                uint8_t type_code,
                                uint16_t value_len,
                                const uint8_t *value) {
    int offset = bgp_write_raw_attr_header(buffer, flags, type_code, value_len);

    if (buffer && value_len > 0 && value) {
        memcpy(buffer + offset, value, value_len);
    }

    return offset + value_len;
}

static int bgp_mp_value_length(int reach, uint8_t nh_len, uint16_t nlri_len) {
    int len = (reach ? 5 + nh_len : 3) + (int)nlri_len;
    return len <= UINT16_MAX ? len : -1;
}

int bgp_serialize_mp_reach_attr(uint8_t *buffer,
                                uint16_t afi,
                                uint8_t safi,
                                const uint8_t *next_hop,
                                uint8_t nh_len,
                                const uint8_t *nlri_data,
                                uint16_t nlri_len) {
    uint16_t afi_net = htons(afi);
    int      value_len = bgp_mp_value_length(1, nh_len, nlri_len);
    if (value_len < 0 || (buffer && ((nh_len && !next_hop) || (nlri_len && !nlri_data)))) return -1;
    int offset = bgp_write_raw_attr_header(buffer, BGP_ATTR_FLAG_OPTIONAL, BGP_ATTR_MP_REACH_NLRI, value_len);

    if (buffer) {
        memcpy(buffer + offset, &afi_net, sizeof(afi_net));
    }
    offset += 2;
    if (buffer) {
        buffer[offset] = safi;
    }
    offset++;
    if (buffer) {
        buffer[offset] = nh_len;
    }
    offset++;
    /*
     * RFC 4760 MP_REACH value is:
     *   AFI(2) | SAFI(1) | NH_LEN(1) | NEXT_HOP | SNPAs(1=0) | NLRI...
     * The final reserved octet must stay zero in the strict encoder.
     */
    /*
     * TODO(WIRE_MUTATION): Corrupt MP_REACH internal header fields.
     *
     * Four distinct fields live in this header area; each has a
     * different fuzz profile and should be targeted individually:
     *
     *   - AFI (2 bytes):
     *       Value-level. Corrupting the AFI causes decoder/NLRI
     *       disagreement: the decoder expects IPv6 NLRI but sees
     *       IPv4-shaped bytes, etc. Most vendors reject the attribute
     *       or treat it as unreachable.
     *
     *   - SAFI (1 byte):
     *       Value-level. Toggling between UNICAST and MPLS_VPN
     *       shifts the decoder's expectation of whether RD/label
     *       fields are present, but since the NLRI bytes were encoded
     *       for the original SAFI this quickly produces parse errors.
     *       Useful for testing AFI/SAFI consistency validation.
     *
     *   - NH_LEN (1 byte):  *** HIGHEST FRAMING VALUE ***
     *       FRAMING HAZARD. NH_LEN controls how many bytes the
     *       decoder consumes as next-hop before reading the reserved
     *       octet and then the NLRI. A wrong value shifts where NLRI
     *       starts WITHIN the MP_REACH attribute value. Useful
     *       mutations:
     *         * shrink by N: N bytes of real next-hop are parsed as
     *           the reserved octet / NLRI, next NLRI walk starts
     *           inside the next-hop bytes
     *         * grow by N: N bytes of reserved/NLRI are absorbed as
     *           next-hop suffix, NLRI walk starts N bytes later
     *         * set to 0: no next-hop; tests minimum-encoding logic
     *         * set to 255: claims next-hop is 255 bytes, likely
     *           overrunning the attribute
     *
     *   - Reserved octet (1 byte, SNPA count = 0):
     *       RFC 4760 mandates zero. Nonzero values test whether the
     *       peer enforces the invariant or silently skips the field.
     *
     * For framing fuzz the NH_LEN mutation is the high-value target;
     * the other three fields are value-level or semantic-level.
     */
    if (nh_len > 0) {
        if (buffer && next_hop) {
            memcpy(buffer + offset, next_hop, nh_len);
        }
        offset += nh_len;
        // TODO(WIRE_MUTATION): Corrupt MP_REACH next-hop payload bytes.
    }
    if (buffer) {
        buffer[offset] = 0;
    }
    offset++;
    if (nlri_len > 0) {
        if (buffer && nlri_data) {
            memcpy(buffer + offset, nlri_data, nlri_len);
        }
        offset += nlri_len;
    }

    return offset;
}

int bgp_serialize_mp_unreach_attr(uint8_t *buffer,
                                  uint16_t afi,
                                  uint8_t safi,
                                  const uint8_t *nlri_data,
                                  uint16_t nlri_len) {
    uint16_t afi_net = htons(afi);
    int      value_len = bgp_mp_value_length(0, 0, nlri_len);
    if (value_len < 0 || (buffer && nlri_len && !nlri_data)) return -1;
    int offset = bgp_write_raw_attr_header(buffer, BGP_ATTR_FLAG_OPTIONAL, BGP_ATTR_MP_UNREACH_NLRI, value_len);

    if (buffer) {
        memcpy(buffer + offset, &afi_net, sizeof(afi_net));
    }
    offset += 2;
    if (buffer) {
        buffer[offset] = safi;
    }
    offset++;
    // RFC 4760 MP_UNREACH value is simply AFI(2) | SAFI(1) | withdrawn NLRI...
    /*
     * TODO(WIRE_MUTATION): Corrupt MP_UNREACH AFI / SAFI.
     *
     * Only two fields, and neither is a length: the withdrawn NLRI
     * region extends implicitly to the end of the attribute value
     * (bounded by the outer path-attribute length). So MP_UNREACH
     * has no per-attribute framing hazard beyond whatever the outer
     * attribute-length corruption already provides.
     *
     * Useful mutations are therefore value-level:
     *
     *   - AFI / SAFI mismatch with the NLRI format:
     *       Peer decodes NLRI with a different grammar than was
     *       used to encode, producing parse errors or treating the
     *       NLRI bytes as a different route type.
     *
     *   - AFI=0 / SAFI=0:
     *       Reserved values; tests per-AFI/SAFI reject logic.
     *
     * Framing-wise this is a lower-value target than MP_REACH (no
     * NH_LEN, no reserved byte). Most fuzz runs can skip this site
     * and focus on MP_REACH.
     */
    if (nlri_len > 0) {
        if (buffer && nlri_data) {
            memcpy(buffer + offset, nlri_data, nlri_len);
        }
        offset += nlri_len;
    }

    return offset;
}

int bgp_serialize_path_attributes(uint8_t *buffer, bgp_path_attr_t *attr_list) {
    int              offset = 0;
    bgp_path_attr_t *curr = attr_list;

    while (curr) {
        offset += bgp_serialize_raw_path_attr(buffer ? buffer + offset : NULL,
                                              curr->flags, curr->type_code,
                                              curr->length, curr->value);
        curr = curr->next;
    }

    return offset;
}

/*
 * RFC 4271 section 5: "The same attribute (attribute with the same type)
 * cannot appear more than once within the Path Attributes field of a
 * particular UPDATE message." A receiver keeps only the first copy (RFC 7606
 * section 3 (g)), or resets the session for MP_REACH / MP_UNREACH, so a
 * repeated type is almost always a caller that forgot to merge a list.
 */
static int bgp_attr_list_has_duplicate_type(const bgp_path_attr_t *attr_list) {
    uint8_t seen[256 / 8] = {0};
    const bgp_path_attr_t *curr;

    for (curr = attr_list; curr; curr = curr->next) {
        uint8_t mask = (uint8_t)(1u << (curr->type_code % 8));

        if (seen[curr->type_code / 8] & mask) {
            return 1;
        }
        seen[curr->type_code / 8] |= mask;
    }
    return 0;
}

/*
 * Serialize attr_list into a new buffer (*data_out, caller frees). An empty list gives NULL and 0. Returns -1 when the
 * list has two attributes of one type (RFC 4271 section 5) or on an encode error.
 */
int bgp_serialize_path_attributes_alloc(bgp_path_attr_t *attr_list, uint8_t **data_out, uint16_t *len_out) {
    int      serialized_len;
    uint8_t *data = NULL;

    *data_out = NULL;
    *len_out = 0;

    if (!attr_list) {
        return 0;
    }

    // TODO(FUZZ_GATE): Allow repeated attribute types (RFC 7606 section 3 (g) receiver tests).
    if (bgp_attr_list_has_duplicate_type(attr_list)) {
        return -1;
    }

    serialized_len = bgp_serialize_path_attributes(NULL, attr_list);
    if (serialized_len < 0) {
        return -1;
    }
    if (serialized_len == 0) {
        return 0;
    }

    data = malloc((size_t)serialized_len);
    if (!data) {
        return -1;
    }

    bgp_serialize_path_attributes(data, attr_list);
    *data_out = data;
    *len_out = (uint16_t)serialized_len;
    return 0;
}

static int bgp_alloc_marshaled_attr(uint8_t flags,
                                    uint8_t type_code,
                                    uint16_t value_len,
                                    uint8_t **data_out,
                                    uint16_t *len_out) {
    int attr_len = bgp_marshaled_attr_size(flags, value_len);
    if (!data_out || !len_out || attr_len > UINT16_MAX) return -1;
    uint8_t *data = malloc((size_t)attr_len);

    if (!data) {
        return -1;
    }

    bgp_write_raw_attr_header(data, flags, type_code, value_len);
    *data_out = data;
    *len_out = (uint16_t)attr_len;
    return 0;
}

int bgp_serialize_mp_reach_attr_alloc(uint16_t afi,
                                      uint8_t safi,
                                      const uint8_t *next_hop,
                                      uint8_t nh_len,
                                      const uint8_t *nlri_data,
                                      uint16_t nlri_len,
                                      uint8_t **data_out,
                                      uint16_t *len_out) {
    int value_len = bgp_mp_value_length(1, nh_len, nlri_len);
    if (value_len < 0 || (nh_len && !next_hop) || (nlri_len && !nlri_data)) return -1;

    if (bgp_alloc_marshaled_attr(BGP_ATTR_FLAG_OPTIONAL, BGP_ATTR_MP_REACH_NLRI,
                                 value_len, data_out, len_out) < 0) {
        return -1;
    }

    bgp_serialize_mp_reach_attr(*data_out, afi, safi, next_hop, nh_len, nlri_data, nlri_len);
    return 0;
}

int bgp_serialize_mp_unreach_attr_alloc(uint16_t afi,
                                        uint8_t safi,
                                        const uint8_t *nlri_data,
                                        uint16_t nlri_len,
                                        uint8_t **data_out,
                                        uint16_t *len_out) {
    int value_len = bgp_mp_value_length(0, 0, nlri_len);
    if (value_len < 0 || (nlri_len && !nlri_data)) return -1;

    if (bgp_alloc_marshaled_attr(BGP_ATTR_FLAG_OPTIONAL, BGP_ATTR_MP_UNREACH_NLRI,
                                 value_len, data_out, len_out) < 0) {
        return -1;
    }

    bgp_serialize_mp_unreach_attr(*data_out, afi, safi, nlri_data, nlri_len);
    return 0;
}

int bgp_builder_init(bgp_builder_t *builder) {
    memset(builder, 0, sizeof(*builder));
    builder->result = calloc(1, sizeof(*builder->result));
    return builder->result ? 0 : -1;
}

void bgp_update_result_free(bgp_update_result_t *result) {
    int i;

    if (!result) {
        return;
    }

    for (i = 0; i < result->num_messages; i++) {
        free(result->messages[i]);
    }

    free(result->messages);
    free(result->message_lens);
    free(result);
}

void bgp_builder_release(bgp_builder_t *builder) {
    if (builder->result) {
        bgp_update_result_free(builder->result);
        builder->result = NULL;
    }
    builder->capacity = 0;
}

void bgp_builder_clear(bgp_builder_t *builder) {
    int i;

    // A slot that a caller took is NULL; free(NULL) does nothing.
    if (!builder->result) {
        return;
    }

    for (i = 0; i < builder->result->num_messages; i++) {
        free(builder->result->messages[i]);
        builder->result->messages[i] = NULL;
    }
    builder->result->num_messages = 0;
}

bgp_update_result_t* bgp_builder_take(bgp_builder_t *builder) {
    bgp_update_result_t *result = builder->result;

    builder->result = NULL;
    builder->capacity = 0;
    return result;
}

static int bgp_builder_ensure_capacity(bgp_builder_t *builder, int min_capacity) {
    uint8_t **messages;
    uint16_t *message_lens;
    int       new_capacity = builder->capacity ? builder->capacity : 4;
    int       count = builder->result->num_messages;

    if (builder->capacity >= min_capacity) {
        return 0;
    }

    while (new_capacity < min_capacity) {
        new_capacity *= 2;
    }

    messages = malloc(sizeof(*messages) * (size_t)new_capacity);
    if (!messages) {
        return -1;
    }

    message_lens = malloc(sizeof(*message_lens) * (size_t)new_capacity);
    if (!message_lens) {
        free(messages);
        return -1;
    }

    if (count > 0) {
        memcpy(messages, builder->result->messages, sizeof(*messages) * (size_t)count);
        memcpy(message_lens, builder->result->message_lens, sizeof(*message_lens) * (size_t)count);
    }

    free(builder->result->messages);
    free(builder->result->message_lens);
    builder->result->messages = messages;
    builder->result->message_lens = message_lens;
    builder->capacity = new_capacity;
    return 0;
}

int bgp_builder_append(bgp_builder_t *builder,
                       const uint8_t *withdrawn,
                       uint16_t withdrawn_len,
                       const uint8_t *attrs,
                       uint16_t attrs_len,
                       const uint8_t *nlri,
                       uint16_t nlri_len) {
    bgp_header_t *header;
    uint8_t      *message;
    size_t        total_len = BGP_HEADER_SIZE + 2U + withdrawn_len + 2U + attrs_len + nlri_len;
    uint16_t      withdrawn_len_net = htons(withdrawn_len);
    uint16_t      attrs_len_net = htons(attrs_len);
    int           offset = BGP_HEADER_SIZE;
    int           next_index;

    if (!builder || !builder->result || total_len > UINT16_MAX ||
        (withdrawn_len && !withdrawn) || (attrs_len && !attrs) || (nlri_len && !nlri)) {
        return -1;
    }
    message = malloc(total_len);
    if (!message) {
        return -1;
    }

    header = (bgp_header_t *)message;
    memset(header->marker, 0xFF, BGP_MARKER_SIZE);
    /*
     * TODO(WIRE_MUTATION): Corrupt the 2-byte BGP message length field.
     *
     * This is the OUTER message boundary on the TCP stream. A wrong
     * value ends the session, not just this UPDATE: the peer reads
     * the wrong number of bytes and mis-locates the start of the next
     * BGP header. BGP has no re-synchronization; the peer does not
     * scan for the next 0xFF marker. It sends a NOTIFICATION and
     * closes the connection (RFC 4271 section 6.1).
     *
     * Useful mutations, with the expected peer reaction:
     *   - shrink by N (result still >= 23): the UPDATE body is cut
     *     short, so its own length checks fail first (UPDATE Message
     *     Error, RFC 4271 section 6.3). Otherwise the next "header"
     *     starts inside this UPDATE, its marker is not all ones, and
     *     the peer sends Message Header Error / Connection Not
     *     Synchronized.
     *   - grow by N: the peer reads the start of the next message as
     *     the tail of this UPDATE and fails to parse it. With no data
     *     after this UPDATE, the peer waits, and the session ends
     *     with Hold Timer Expired.
     *   - set below 23 (for example 19, header only): less than the
     *     minimum UPDATE length, so Message Header Error / Bad
     *     Message Length (RFC 4271 section 6.1).
     *   - set above 4096 (for example 0xFFFF): Bad Message Length,
     *     unless both peers negotiated the Extended Message
     *     capability (RFC 8654, limit 65535); then it acts as "grow".
     *
     * Expected result of every mutation here: a NOTIFICATION and a
     * closed session. A peer that keeps the session up, or that
     * accepts routes from the mis-framed bytes, has a bug.
     */
    header->length = htons(total_len);
    header->type = BGP_MSG_UPDATE;

    /*
     * TODO(WIRE_MUTATION): Corrupt the 2-byte withdrawn routes length.
     *
     * Internal UPDATE delimiter. Tells the peer how many bytes of
     * withdrawn-routes data follow before the total-path-attribute
     * length field is read. A wrong value cascades through the
     * remainder of this UPDATE: the attrs-length field is read from
     * the wrong offset, which in turn shifts where trailing NLRI
     * starts. Scoped to one UPDATE (does not desync the TCP stream).
     *
     * Useful mutations:
     *   - grow beyond actual withdrawn bytes: peer reads the attrs
     *     and NLRI as additional withdrawn prefixes, potentially
     *     flushing real routes from its RIB
     *   - shrink: peer reads what should be withdrawn-prefix bytes
     *     as the attrs-length, typically producing an absurd
     *     attrs-length that overruns the declared message size
     *   - set to 0xFFFF: claims withdrawn routes run past message end
     *
     * Classic "length trusted without cross-check against BGP header
     * length" bug class. Parsers that don't enforce header_len == 19
     * + 2 + withdrawn_len + 2 + attrs_len + nlri_len can be induced
     * to walk off the end of the buffer.
     */
    memcpy(message + offset, &withdrawn_len_net, sizeof(withdrawn_len_net));
    offset += 2;
    if (withdrawn_len > 0) {
        memcpy(message + offset, withdrawn, withdrawn_len);
        offset += withdrawn_len;
    }

    /*
     * TODO(WIRE_MUTATION): Corrupt the 2-byte total path attribute length.
     *
     * Internal UPDATE delimiter between the path-attributes region
     * and the trailing NLRI. NLRI implicitly starts at (attrs_start
     * + total_attr_len) and runs to end of message. A wrong value
     * shifts the NLRI boundary in either direction within the same
     * UPDATE.
     *
     * Useful mutations:
     *   - shrink by N: last N bytes of real path attributes are
     *     read as NLRI, producing prefix-length parse errors or
     *     injecting bogus NLRIs into the peer's RIB
     *   - grow by N: first N bytes of real NLRI are absorbed into
     *     the path-attributes region and decoded as a malformed
     *     trailing attribute header
     *   - set to 0xFFFF: claims attrs run past the declared end of
     *     the UPDATE
     *
     * Most historical BGP parser CVEs in this area are rooted in
     * incomplete cross-checks between this length and the outer
     * BGP header length.
     */
    memcpy(message + offset, &attrs_len_net, sizeof(attrs_len_net));
    offset += 2;
    if (attrs_len > 0) {
        memcpy(message + offset, attrs, attrs_len);
        offset += attrs_len;
    }
    if (nlri_len > 0) {
        memcpy(message + offset, nlri, nlri_len);
    }

    next_index = builder->result->num_messages + 1;
    if (bgp_builder_ensure_capacity(builder, next_index) < 0) {
        free(message);
        return -1;
    }

    builder->result->messages[builder->result->num_messages] = message;
    builder->result->message_lens[builder->result->num_messages] = total_len;
    builder->result->num_messages = next_index;
    return 0;
}

int bgp_builder_append_attrs_only(bgp_builder_t *builder, const uint8_t *attrs, uint16_t attrs_len) {
    return bgp_builder_append(builder, NULL, 0, attrs, attrs_len, NULL, 0);
}

int bgp_builder_append_mp(bgp_builder_t *builder, const bgp_mp_args_t *args) {
    bgp_header_t *header;
    uint8_t      *message;
    size_t        mp_value_len;
    size_t        mp_attr_len;
    size_t        total_attr_len;
    size_t        total_len;
    uint16_t      withdrawn_len_net;
    uint16_t      total_attr_len_net;
    int           offset = BGP_HEADER_SIZE;
    int           next_index;

    if (!builder || !builder->result || !args ||
        (args->withdrawn_len && !args->withdrawn) || (args->attrs_len && !args->attrs) ||
        (args->nlri_len && !args->nlri) || (args->mp_nlri_len && !args->mp_nlri) ||
        (args->is_reach && args->nh_len && !args->next_hop)) {
        return -1;
    }
    int measured = bgp_mp_value_length(args->is_reach, args->nh_len, args->mp_nlri_len);
    if (measured < 0) {
        return -1;
    }
    mp_value_len = (size_t)measured;
    mp_attr_len = (size_t)bgp_marshaled_attr_size(BGP_ATTR_FLAG_OPTIONAL, (uint16_t)mp_value_len);
    total_attr_len = args->attrs_len + mp_attr_len;
    total_len = BGP_HEADER_SIZE + 2U + args->withdrawn_len + 2U + total_attr_len + args->nlri_len;
    if (total_len > UINT16_MAX) {
        return -1;
    }
    withdrawn_len_net = htons(args->withdrawn_len);
    total_attr_len_net = htons(total_attr_len);

    message = malloc(total_len);
    if (!message) {
        return -1;
    }

    header = (bgp_header_t *)message;
    memset(header->marker, 0xFF, BGP_MARKER_SIZE);
    /*
     * TODO(WIRE_MUTATION): Corrupt the 2-byte BGP message length field.
     *
     * Same framing hazard as in bgp_builder_append(): this is the
     * outer TCP-stream message boundary. A wrong value here ends the
     * session with a NOTIFICATION, not just this UPDATE. The MP_REACH /
     * MP_UNREACH path is the common case (IPv6, VPN, EVPN, SR Policy
     * all flow through here), so this is the site most fuzz runs
     * will touch.
     *
     * See the sibling marker in bgp_builder_append() for the full
     * rationale, mutation recipes, and expected peer reactions.
     */
    header->length = htons(total_len);
    header->type = BGP_MSG_UPDATE;

    /*
     * TODO(WIRE_MUTATION): Corrupt the 2-byte withdrawn routes length.
     *
     * Internal UPDATE delimiter. Even in an MP_REACH message the
     * classic withdrawn-routes length is still present (and almost
     * always zero). Corrupting a "known-zero" field to a nonzero
     * value is a particularly high-value trip-up: peers that cache
     * the invariant "MP messages carry zero classic withdrawn bytes"
     * may skip past it without reading, then find their attrs
     * length at the wrong offset.
     *
     * Useful mutations:
     *   - set to N > 0 with zero actual withdrawn bytes: peer reads
     *     the next N bytes (which are the 2-byte attrs-length plus
     *     start of MP_REACH attribute) as classic withdrawn NLRI
     *   - set to 0xFFFF: overflows declared message size
     *
     * See the sibling marker in bgp_builder_append() for additional
     * mutation recipes.
     */
    memcpy(message + offset, &withdrawn_len_net, sizeof(withdrawn_len_net));
    offset += 2;
    if (args->withdrawn_len > 0) {
        memcpy(message + offset, args->withdrawn, args->withdrawn_len);
        offset += args->withdrawn_len;
    }

    /*
     * TODO(WIRE_MUTATION): Corrupt the 2-byte total path attribute length.
     *
     * Internal UPDATE delimiter between path attributes and any
     * trailing classic NLRI. In the MP path the MP_REACH /
     * MP_UNREACH attribute itself lives inside this region, so
     * shrinking total_attr_len by even one byte typically truncates
     * the MP attribute mid-NLRI and produces a decoder state where
     * it has parsed part of an MP NLRI list then hit "end of
     * attributes". Growing it pulls bytes from the classic NLRI
     * tail (usually empty for MP) into the attrs region.
     *
     * Useful mutations:
     *   - shrink by 1-2: truncates tail of the MP_REACH attribute,
     *     typically cutting off the last NLRI mid-prefix
     *   - shrink to just below MP_REACH header size: claims MP attr
     *     ends before its value starts
     *   - grow by N: absorbs classic NLRI tail (or next message if
     *     header length was also mutated)
     *   - set to 0xFFFF: claims attrs run past message end
     *
     * Particularly interesting in combination with a header-length
     * mutation: cross-check gaps between these two lengths are
     * where the richest parser bugs live.
     */
    memcpy(message + offset, &total_attr_len_net, sizeof(total_attr_len_net));
    offset += 2;

    if (args->is_reach) {
        offset += bgp_serialize_mp_reach_attr(message + offset, args->afi, args->safi,
                                              args->next_hop, args->nh_len,
                                              args->mp_nlri, args->mp_nlri_len);
    } else {
        offset += bgp_serialize_mp_unreach_attr(message + offset, args->afi, args->safi,
                                                args->mp_nlri, args->mp_nlri_len);
    }

    if (args->attrs_len > 0) {
        memcpy(message + offset, args->attrs, args->attrs_len);
        offset += args->attrs_len;
    }

    if (args->nlri_len > 0) {
        memcpy(message + offset, args->nlri, args->nlri_len);
    }

    next_index = builder->result->num_messages + 1;
    if (bgp_builder_ensure_capacity(builder, next_index) < 0) {
        free(message);
        return -1;
    }

    builder->result->messages[builder->result->num_messages] = message;
    builder->result->message_lens[builder->result->num_messages] = total_len;
    builder->result->num_messages = next_index;
    return 0;
}

/*
 * Encode a standard (non-VPN) next hop.  Accepts AF_INET or AF_INET6.
 * When next_hop is NULL, defaults to an all-zero IPv4 address.
 */
int bgp_encode_standard_next_hop(const bgp_next_hop_t *next_hop, uint8_t *buffer, uint8_t *nh_len_out) {
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
        return 0;
    }

    if (effective->af == AF_INET6) {
        memcpy(buffer, &effective->address.ipv6, 16);
        *nh_len_out = 16;
        if (effective->has_link_local) {
            memcpy(buffer + 16, &effective->link_local, 16);
            *nh_len_out = 32;
        }
        return 0;
    }

    return -1;
}

int bgp_encode_ipv6_next_hop(const bgp_next_hop_t *next_hop, uint8_t *buffer, uint8_t *nh_len_out) {
    bgp_next_hop_t        default_next_hop;
    const bgp_next_hop_t *effective = next_hop;

    if (!effective) {
        memset(&default_next_hop, 0, sizeof(default_next_hop));
        default_next_hop.af = AF_INET6;
        effective = &default_next_hop;
    }

    if (effective->af != AF_INET6) {
        // TODO(FUZZ_GATE): Allow non-IPv6 next-hop AF in the IPv6-only helper.
        return -1;
    }

    /*
     * IPv6 MP_REACH next hop is either:
     *   global(16)
     * or
     *   global(16) | link-local(16)
     * depending on whether the caller explicitly supplies a link-local.
     */
    memcpy(buffer, &effective->address.ipv6, 16);
    *nh_len_out = 16;
    // TODO(WIRE_MUTATION): Corrupt the IPv6 global next-hop bytes after encode.

    if (effective->has_link_local) {
        memcpy(buffer + 16, &effective->link_local, 16);
        *nh_len_out = 32;
        // TODO(WIRE_MUTATION): Corrupt the IPv6 link-local next-hop bytes after encode.
    }

    return 0;
}

int bgp_encode_ipv6_family_next_hop(const bgp_next_hop_t *next_hop, uint8_t *buffer, uint8_t *nh_len_out) {
    bgp_next_hop_t        default_next_hop;
    const bgp_next_hop_t *effective = next_hop;

    if (!effective) {
        memset(&default_next_hop, 0, sizeof(default_next_hop));
        default_next_hop.af = AF_INET6;
        effective = &default_next_hop;
    }

    if (effective->af == AF_INET6) {
        return bgp_encode_ipv6_next_hop(effective, buffer, nh_len_out);
    }

    if (effective->af == AF_INET) {
        /*
         * RFC 8950 allows IPv4 next hops for IPv6-family NLRI by carrying
         * them as IPv4-mapped IPv6 addresses inside MP_REACH.
         */
        // TODO(WIRE_MUTATION): Corrupt the IPv4-mapped IPv6 next-hop bytes after encode.
        memset(buffer, 0, 10);
        buffer[10] = 0xFF;
        buffer[11] = 0xFF;
        memcpy(buffer + 12, &effective->address.ipv4, 4);
        *nh_len_out = 16;
        return 0;
    }

    // TODO(FUZZ_GATE): Allow other next-hop AF encodings for IPv6-family NLRIs.
    return -1;
}

static void bgp_encode_ipv4_mapped_ipv6_addr(uint8_t *buffer, const struct in_addr *addr) {
    memset(buffer, 0, 10);
    buffer[10] = 0xFF;
    buffer[11] = 0xFF;
    memcpy(buffer + 12, addr, 4);
}

int bgp_encode_labeled_ipv4_next_hop(const bgp_next_hop_t *next_hop, uint8_t *buffer, uint8_t *nh_len_out) {
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
        return 0;
    }

    if (effective->af == AF_INET6) {
        return bgp_encode_ipv6_next_hop(effective, buffer, nh_len_out);
    }

    // TODO(FUZZ_GATE): Allow other next-hop AF encodings for labeled IPv4.
    return -1;
}

int bgp_encode_evpn_next_hop(const bgp_next_hop_t *next_hop, uint8_t *buffer, uint8_t *nh_len_out) {
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
        // TODO(WIRE_MUTATION): Corrupt the EVPN IPv4 next-hop bytes after encode.
        return 0;
    }

    if (effective->af == AF_INET6) {
        memcpy(buffer, &effective->address.ipv6, 16);
        *nh_len_out = 16;
        // TODO(WIRE_MUTATION): Corrupt the EVPN IPv6 next-hop bytes after encode.
        if (effective->has_link_local) {
            /*
             * RFC 7432 says the MP_REACH next hop for EVPN routes is the IPv4
             * or IPv6 address of the advertising PE. Keep the strict helper on
             * that 4-byte or 16-byte form and leave any 32-byte global +
             * link-local experiments to a future fuzz policy or raw mutator.
             */
            // TODO(FUZZ_GATE): Allow 32-byte EVPN IPv6 next-hop encodings with link-local.
            return -1;
        }
        return 0;
    }

    // TODO(FUZZ_GATE): Allow non-IPv4/IPv6 next-hop AF in the EVPN helper.
    return -1;
}

int bgp_encode_vpn_next_hop(uint16_t afi,
                            bgp_vpn_transport_t transport,
                            const bgp_next_hop_t *next_hop,
                            uint8_t *buffer,
                            uint8_t *nh_len_out) {
    bgp_next_hop_t        default_next_hop;
    const bgp_next_hop_t *effective = next_hop;
    int                   offset = 0;

    if (!effective) {
        memset(&default_next_hop, 0, sizeof(default_next_hop));
        default_next_hop.af = (transport == BGP_VPN_TRANSPORT_IPV4) ?
                              AF_INET : AF_INET6;
        effective = &default_next_hop;
    }

    if (transport == BGP_VPN_TRANSPORT_IPV4) {
        if (effective->af != AF_INET) {
            /*
             * TODO(FUZZ_GATE): Allow VPN transport / next-hop AF mismatch.
             *
             * RFC 4364 section 4.3.2 and RFC 4659 specify how the
             * VPN next-hop is encoded: an 8-octet all-zero RD field
             * followed by the transport-address bytes. The transport
             * choice (IPv4 vs IPv6) is a per-session deployment
             * decision independent of the VPN family (VPNv4 or
             * VPNv6): RFC 5549 / 8950 allow VPNv4 over IPv6 and
             * vice versa.
             *
             * The strict encoder pairs transport with a next-hop of
             * the matching AF. This gate rejects the case where a
             * caller configures BGP_VPN_TRANSPORT_IPV4 but supplies
             * an IPv6 next-hop (or vice versa).
             *
             * Fuzz use case: force a transport/AF mismatch to test
             * whether the peer rejects the MP_REACH cleanly or tries
             * to consume the wrong number of next-hop bytes. RFC 4760
             * says the next-hop AF is determined by AFI/SAFI, not by
             * an explicit field in the NH payload, so a transport
             * mismatch produces bytes that don't parse as the
             * expected address family.
             *
             * Proposed allow key: "next-hop.vpn-transport-mismatch"
             */
            return -1;
        }
    } else if (transport == BGP_VPN_TRANSPORT_IPV6) {
        if (effective->af != AF_INET6) {
            /*
             * TODO(FUZZ_GATE): Allow VPN transport / next-hop AF mismatch.
             *
             * Symmetric to the IPv4-transport case above. See that
             * marker for rationale and the proposed allow key.
             */
            return -1;
        }
    } else {
        return -1;
    }

    /*
     * RFC 4364 / RFC 4659 prepend an 8-octet zero RD field to the VPN
     * next-hop payload. The transport-address bytes follow that RD-shaped
     * zero field.
     */
    memset(buffer, 0, 8);
    offset = 8;
    // TODO(WIRE_MUTATION): Corrupt the VPN next-hop RD field after encode.

    if (transport == BGP_VPN_TRANSPORT_IPV4) {
        if (afi == AFI_IPV4) {
            memcpy(buffer + offset, &effective->address.ipv4, 4);
            offset += 4;
            // TODO(WIRE_MUTATION): Corrupt VPN IPv4-transport next-hop IPv4 bytes.
        } else {
            bgp_encode_ipv4_mapped_ipv6_addr(buffer + offset, &effective->address.ipv4);
            offset += 16;
            // TODO(WIRE_MUTATION): Corrupt VPN IPv4-transport IPv4-mapped IPv6 bytes.
        }
        *nh_len_out = (uint8_t)offset;
        return 0;
    }

    memcpy(buffer + offset, &effective->address.ipv6, 16);
    offset += 16;
    // TODO(WIRE_MUTATION): Corrupt VPN IPv6-transport global next-hop bytes.
    if (effective->has_link_local) {
        memset(buffer + offset, 0, 8);
        offset += 8;
        // TODO(WIRE_MUTATION): Corrupt VPN IPv6-transport link-local RD-zero bytes.
        memcpy(buffer + offset, &effective->link_local, 16);
        offset += 16;
        // TODO(WIRE_MUTATION): Corrupt VPN IPv6-transport link-local next-hop bytes.
    }

    *nh_len_out = (uint8_t)offset;
    return 0;
}

/*
 * Route distinguisher as carried in VPN, EVPN, MVPN, VPLS and FlowSpec VPN NLRI: the two-octet type, then the
 * six-octet value (RFC 4364 section 4.2). Always 8 bytes.
 */
void bgp_encode_rd(uint8_t *buffer, const route_distinguisher_t *rd) {
    uint16_t type_net = htons(rd->type);

    memcpy(buffer, &type_net, 2);
    memcpy(buffer + 2, rd->value, 6);
}

void bgp_encode_mpls_label(uint8_t *buffer, const mpls_label_t *label) {
    uint32_t label_val = label->label & 0xFFFFFU;
    uint8_t  tc = label->tc & 0x07U;
    uint8_t  s = label->s & 0x01U;

    /*
     * TODO(WIRE_MUTATION): Corrupt MPLS label / TC / S bits.
     *
     * The 3-byte MPLS label entry packs four logical fields:
     *   bits 0..19  label value (20 bits)
     *   bits 20..22 Traffic Class / EXP (3 bits)
     *   bit  23     S (Bottom-of-Stack) bit
     *   [byte 2 low nibble interleaves with label bits 0..3]
     *
     * Useful mutations:
     *
     *   - Flip the S bit:  *** HIGHEST FRAMING VALUE ***
     *       FRAMING HAZARD. The S bit tells the decoder whether
     *       more label entries follow.
     *         * S=0 where strict S=1: decoder keeps reading labels
     *           past the end of the configured stack, consuming the
     *           following RD / prefix / next-hop bytes as more
     *           labels until something happens to realign. In a VPN
     *           NLRI this means the RD bytes are read as two more
     *           label entries (6 bytes), shifting the prefix by 6.
     *         * S=1 where strict S=0: decoder stops early, treats
     *           the second label entry as the start of RD / prefix.
     *       This is one of the highest-value framing hooks in the
     *       encoder for VPN and labeled-unicast targets.
     *
     *   - Corrupt the 20-bit label value:
     *       Value-level. Tests reserved-label handling (0=explicit
     *       null, 1=router alert, 2=ipv6 explicit null, 3=implicit
     *       null, 13=GAL, 14=OAM alert). Peer may reject or warn.
     *
     *   - Set TC/EXP to nonzero:
     *       Value-level. Most BGP-SPEC decoders ignore TC on the
     *       control plane; tests whether any of them reject it.
     *
     * For a fuzz run targeting VPN or labeled-unicast decoders, the
     * S-bit flip is the first thing to try.
     */
    buffer[0] = (uint8_t)((label_val >> 12) & 0xFFU);
    buffer[1] = (uint8_t)((label_val >> 4) & 0xFFU);
    buffer[2] = (uint8_t)(((label_val & 0x0FU) << 4) | (tc << 1) | s);
}

bgp_path_attr_t* bgp_attr_create_mp_reach_raw(uint16_t afi,
                                              uint8_t safi,
                                              const uint8_t *next_hop,
                                              uint8_t nh_len,
                                              const uint8_t *nlri_data,
                                              uint16_t nlri_len) {
    bgp_path_attr_t *attr = bgp_attr_alloc(
        BGP_ATTR_FLAG_OPTIONAL, BGP_ATTR_MP_REACH_NLRI,
        (uint16_t)(2 + 1 + 1 + nh_len + 1 + nlri_len));
    uint16_t afi_net = htons(afi);
    int      offset = 0;

    if (!attr) {
        return NULL;
    }

    // Raw helper mirrors RFC 4760 MP_REACH value layout exactly.
    memcpy(attr->value + offset, &afi_net, sizeof(afi_net));
    offset += 2;
    attr->value[offset++] = safi;
    attr->value[offset++] = nh_len;
    if (nh_len > 0) {
        memcpy(attr->value + offset, next_hop, nh_len);
        offset += nh_len;
    }
    attr->value[offset++] = 0;
    if (nlri_len > 0) {
        memcpy(attr->value + offset, nlri_data, nlri_len);
    }

    return attr;
}

bgp_path_attr_t* bgp_attr_create_mp_unreach_raw(uint16_t afi,
                                                uint8_t safi,
                                                const uint8_t *nlri_data,
                                                uint16_t nlri_len) {
    bgp_path_attr_t *attr = bgp_attr_alloc(
        BGP_ATTR_FLAG_OPTIONAL, BGP_ATTR_MP_UNREACH_NLRI,
        (uint16_t)(2 + 1 + nlri_len));
    uint16_t afi_net = htons(afi);
    int      offset = 0;

    if (!attr) {
        return NULL;
    }

    // Raw helper mirrors RFC 4760 MP_UNREACH value layout exactly.
    memcpy(attr->value + offset, &afi_net, sizeof(afi_net));
    offset += 2;
    attr->value[offset++] = safi;
    if (nlri_len > 0) {
        memcpy(attr->value + offset, nlri_data, nlri_len);
    }

    return attr;
}

void bgp_path_attr_free(bgp_path_attr_t *attr) {
    if (!attr) {
        return;
    }

    free(attr->value);
    free(attr);
}

void bgp_path_attr_list_free(bgp_path_attr_t *list) {
    while (list) {
        bgp_path_attr_t *next = list->next;
        bgp_path_attr_free(list);
        list = next;
    }
}

// Helper Functions for Prefix Encoding

int bgp_encode_ipv4_prefix(uint8_t *buffer, ipv4_prefix_t *prefix) {
    if (!buffer || !prefix || prefix->prefix_len > 32) return -1;
    int bytes_needed = bgp_prefix_bytes_needed(prefix->prefix_len);

    /*
     * TODO(WIRE_MUTATION): Corrupt the 1-byte IPv4 NLRI prefix length.
     *
     * Scoped to one NLRI but cascades to every following NLRI in the
     * same list, because the decoder walks the NLRI region by
     * repeatedly reading prefix_len and then consuming
     * ceil(prefix_len / 8) address bytes. A wrong value shifts the
     * start of the next NLRI, and the cascade continues until the
     * decoder hits end-of-message or a prefix_len value that happens
     * to realign the walk.
     *
     * Useful mutations:
     *   - > 32: structurally invalid for IPv4; tests range validation
     *     (RFC 4271 strictly requires prefix_len <= 32)
     *   - off-by-one (e.g. 24 -> 25): peer consumes one extra byte,
     *     misaligning every following NLRI in the list
     *   - 0: zero-byte prefix (default route shape); edge case in
     *     prefix-consumption and longest-match logic
     *   - 32 on a shorter-shaped NLRI: reads trailing bytes of the
     *     NLRI list (or whatever follows) as prefix octets
     *
     * This is the single most common NLRI format on real BGP
     * sessions, so any bug here has broad blast radius. Parity with
     * the existing prefix-length markers on IPv6, labeled IPv4/IPv6,
     * and VPNv4/v6 prefix encoders.
     */
    buffer[0] = prefix->prefix_len;
    memcpy(buffer + 1, &prefix->prefix, bytes_needed);
    /*
     * TODO(WIRE_MUTATION): Corrupt the IPv4 NLRI prefix bytes after encode.
     *
     * Value-level corruption, parity with the IPv6 marker below.
     * Not a framing hazard on its own (the prefix region is still
     * bytes_needed long), but useful for testing prefix validation
     * such as reserved ranges, multicast address space, or peer
     * policies that reject bogons.
     */

    return 1 + bytes_needed;
}

int bgp_encode_ipv6_prefix(uint8_t *buffer, ipv6_prefix_t *prefix) {
    if (!buffer || !prefix || prefix->prefix_len > 128) return -1;
    int bytes_needed = bgp_prefix_bytes_needed(prefix->prefix_len);

    /*
     * TODO(WIRE_MUTATION): Corrupt the 1-byte IPv6 NLRI prefix length.
     *
     * Same framing cascade as IPv4 prefix_len: wrong value shifts
     * the start of the next NLRI in the list. RFC 4760 section 5
     * specifies IPv6 unicast prefix_len is bounded at 128.
     *
     * Useful mutations (same taxonomy as IPv4 prefix_len):
     *   - > 128: structurally invalid for IPv6
     *   - off-by-one (e.g. 64 -> 65): consumes one extra byte,
     *     cascades to every following NLRI
     *   - 0: default route shape
     *   - 128 on a shorter-shaped NLRI: reads trailing bytes as
     *     prefix octets, cascading
     *
     * See the IPv4 prefix-length marker above for the full taxonomy.
     */
    buffer[0] = prefix->prefix_len;
    memcpy(buffer + 1, prefix->prefix, bytes_needed);
    /*
     * TODO(WIRE_MUTATION): Corrupt the IPv6 NLRI prefix bytes after encode.
     *
     * Value-level. Useful for testing peer policies around IPv6
     * reserved ranges (2001:db8::/32 documentation, fe80::/10
     * link-local, fc00::/7 ULA, ff00::/8 multicast). Not a framing
     * hazard on its own.
     */

    return 1 + bytes_needed;
}

int bgp_encode_labeled_ipv4_prefix(uint8_t *buffer, labeled_ipv4_prefix_t *prefix) {
    if (!buffer || !prefix || prefix->prefix_len > 56 || prefix->label.label > 0xFFFFF) return -1;
    int ip_prefix_len = prefix->prefix_len >= 24 ? (prefix->prefix_len - 24) : -1;
    int bytes_needed;

    if (ip_prefix_len < 0) {
        return -1;
    }

    /*
     * TODO(WIRE_MUTATION): Corrupt the 1-byte labeled IPv4 NLRI prefix length.
     *
     * RFC 8277 encodes labeled unicast prefix_len as:
     *   label bits (20 per label, +3 reserved, +1 S = 24 per entry)
     *   + IP prefix bits
     * So a /24 IPv4 with one label has prefix_len = 24 + 24 = 48.
     * The decoder uses this to compute (1) how many label entries
     * to read and (2) how many prefix bytes follow.
     *
     * Useful mutations:
     *
     *   - Shrink below 24:  *** RFC 8277 VIOLATION ***
     *       Declares no room for even one label. Already guarded by
     *       the FUZZ_GATE check in bgp_detect_labeled_ipv4_add_path
     *       below. Fuzz policy may allow this; decoders that don't
     *       range-check can be induced to read negative label count.
     *
     *   - Off-by-24 (claim extra label):
     *       e.g. /24 IPv4 with one label encoded as 48 but sent as
     *       72. Decoder reads RD bytes (VPN case) or prefix bytes
     *       as a second label, cascading into prefix misalignment.
     *
     *   - Off-by-one on IP portion:
     *       e.g. send 49 instead of 48. Same cascade as plain IPv4
     *       prefix_len: one extra prefix byte consumed, next NLRI
     *       walk starts one byte late.
     *
     *   - Large values (> 56 for labeled IPv4 with single label):
     *       Structurally invalid; tests range validation.
     *
     * Labeled unicast is a high-value cascade target because the
     * prefix_len drives BOTH label-stack walking AND prefix-byte
     * walking in one field.
     */
    buffer[0] = prefix->prefix_len;
    bgp_encode_mpls_label(buffer + 1, &prefix->label);
    bytes_needed = bgp_prefix_bytes_needed((uint8_t)ip_prefix_len);
    memcpy(buffer + 4, &prefix->prefix, bytes_needed);
    /*
     * TODO(WIRE_MUTATION): Corrupt the labeled IPv4 prefix bytes.
     *
     * Value-level; not a framing hazard. Same considerations as the
     * plain IPv4 prefix bytes marker.
     */

    return 4 + bytes_needed;
}

int bgp_encode_labeled_ipv6_prefix(uint8_t *buffer, labeled_ipv6_prefix_t *prefix) {
    if (!buffer || !prefix || prefix->prefix_len > 152 || prefix->label.label > 0xFFFFF) return -1;
    int ip_prefix_len = prefix->prefix_len >= 24 ? (prefix->prefix_len - 24) : -1;
    int bytes_needed;

    if (ip_prefix_len < 0) {
        return -1;
    }

    /*
     * TODO(WIRE_MUTATION): Corrupt the 1-byte labeled IPv6 NLRI prefix length.
     *
     * Same RFC 8277 framing semantics as labeled IPv4. The IP
     * portion is bounded at 128 bits rather than 32. See the
     * labeled IPv4 marker above for the full mutation taxonomy.
     */
    buffer[0] = prefix->prefix_len;
    bgp_encode_mpls_label(buffer + 1, &prefix->label);
    bytes_needed = bgp_prefix_bytes_needed((uint8_t)ip_prefix_len);
    memcpy(buffer + 4, prefix->prefix, bytes_needed);
    /*
     * TODO(WIRE_MUTATION): Corrupt the labeled IPv6 prefix bytes.
     *
     * Value-level; not a framing hazard.
     */

    return 4 + bytes_needed;
}

DEFINE_ADD_PATH_DETECTOR(bgp_detect_ipv4_add_path, ipv4_nlri_list_t,
                        do { if (list->prefix.prefix_len > 32) return -1; } while (0))

DEFINE_ADD_PATH_DETECTOR(bgp_detect_ipv6_add_path, ipv6_nlri_list_t,
                        do { if (list->prefix.prefix_len > 128) return -1; } while (0))

DEFINE_ADD_PATH_DETECTOR(
    bgp_detect_labeled_ipv4_add_path,
    labeled_ipv4_nlri_t,
    do {
        if (list->prefix.prefix_len < 24 || list->prefix.prefix_len > 56 || list->prefix.label.label > 0xFFFFF) {
            // TODO(FUZZ_GATE): Allow labeled IPv4 NLRIs shorter than the 24-bit label field.
            return -1;
        }
    } while (0))

DEFINE_ADD_PATH_DETECTOR(
    bgp_detect_labeled_ipv6_add_path,
    labeled_ipv6_nlri_t,
    do {
        if (list->prefix.prefix_len < 24 || list->prefix.prefix_len > 152 || list->prefix.label.label > 0xFFFFF) {
            // TODO(FUZZ_GATE): Allow labeled IPv6 NLRIs shorter than the 24-bit label field.
            return -1;
        }
    } while (0))

static int bgp_encode_ipv4_nlri(uint8_t *buffer, const ipv4_nlri_list_t *nlri, int add_path) {
    int offset = 0;

    if (add_path) {
        uint32_t path_id_net = htonl(nlri->path_id);

        memcpy(buffer + offset, &path_id_net, sizeof(path_id_net));
        offset += sizeof(path_id_net);
    }

    return offset + bgp_encode_ipv4_prefix(buffer + offset, (ipv4_prefix_t *)&nlri->prefix);
}

static int bgp_encode_ipv6_nlri(uint8_t *buffer, const ipv6_nlri_list_t *nlri, int add_path) {
    int offset = 0;

    if (add_path) {
        uint32_t path_id_net = htonl(nlri->path_id);

        memcpy(buffer + offset, &path_id_net, sizeof(path_id_net));
        offset += sizeof(path_id_net);
        // TODO(WIRE_MUTATION): Corrupt the IPv6 ADD-PATH path-id after encode.
    }

    return offset + bgp_encode_ipv6_prefix(buffer + offset, (ipv6_prefix_t *)&nlri->prefix);
}

static int bgp_encode_labeled_ipv4_nlri(uint8_t *buffer,
                                        const labeled_ipv4_nlri_t *nlri,
                                        int add_path,
                                        int withdraw_mode) {
    int offset = 0;
    int ip_prefix_len = nlri->prefix.prefix_len - 24;
    int prefix_bytes = bgp_prefix_bytes_needed((uint8_t)ip_prefix_len);

    if (add_path) {
        uint32_t path_id_net = htonl(nlri->path_id);

        memcpy(buffer + offset, &path_id_net, sizeof(path_id_net));
        offset += sizeof(path_id_net);
        // TODO(WIRE_MUTATION): Corrupt the labeled IPv4 ADD-PATH path-id after encode.
    }

    buffer[offset++] = nlri->prefix.prefix_len;
    if (withdraw_mode) {
        /*
         * RFC 8277 section 2.4 replaces the advertised label field with a
         * 3-byte compatibility field when withdrawing labeled-unicast NLRIs.
         */
        // TODO(WIRE_MUTATION): Corrupt the labeled-unicast withdraw compatibility field.
        buffer[offset++] = 0x80;
        buffer[offset++] = 0x00;
        buffer[offset++] = 0x00;
    } else {
        bgp_encode_mpls_label(buffer + offset, &nlri->prefix.label);
        offset += 3;
    }

    memcpy(buffer + offset, &nlri->prefix.prefix, prefix_bytes);
    return offset + prefix_bytes;
}

static int bgp_encode_labeled_ipv6_nlri(uint8_t *buffer,
                                        const labeled_ipv6_nlri_t *nlri,
                                        int add_path,
                                        int withdraw_mode) {
    int offset = 0;
    int ip_prefix_len = nlri->prefix.prefix_len - 24;
    int prefix_bytes = bgp_prefix_bytes_needed((uint8_t)ip_prefix_len);

    if (add_path) {
        uint32_t path_id_net = htonl(nlri->path_id);

        memcpy(buffer + offset, &path_id_net, sizeof(path_id_net));
        offset += sizeof(path_id_net);
        // TODO(WIRE_MUTATION): Corrupt the labeled IPv6 ADD-PATH path-id after encode.
    }

    buffer[offset++] = nlri->prefix.prefix_len;
    if (withdraw_mode) {
        // TODO(WIRE_MUTATION): Corrupt the labeled-unicast withdraw compatibility field.
        buffer[offset++] = 0x80;
        buffer[offset++] = 0x00;
        buffer[offset++] = 0x00;
    } else {
        bgp_encode_mpls_label(buffer + offset, &nlri->prefix.label);
        offset += 3;
    }

    memcpy(buffer + offset, nlri->prefix.prefix, prefix_bytes);
    return offset + prefix_bytes;
}

static int bgp_encode_ipv4_chunk(ipv4_nlri_list_t **cursor, uint8_t *buffer, int max_bytes, int add_path) {
    int written = 0;

    while (*cursor) {
        int needed = 1 + bgp_prefix_bytes_needed((*cursor)->prefix.prefix_len);

        if ((int)(*cursor)->add_path != add_path) {
            return -1;
        }
        if (add_path) {
            needed += 4;
        }

        if (written + needed > max_bytes) {
            return (written > 0) ? written : -1;
        }

        written += bgp_encode_ipv4_nlri(buffer + written, *cursor, add_path);
        *cursor = (*cursor)->next;
    }

    return written;
}

static int bgp_encode_ipv6_chunk(ipv6_nlri_list_t **cursor, uint8_t *buffer, int max_bytes, int add_path) {
    int written = 0;

    while (*cursor) {
        int needed = 1 + bgp_prefix_bytes_needed((*cursor)->prefix.prefix_len);

        if ((int)(*cursor)->add_path != add_path) {
            return -1;
        }
        if (add_path) {
            needed += 4;
        }

        if (written + needed > max_bytes) {
            return (written > 0) ? written : -1;
        }

        written += bgp_encode_ipv6_nlri(buffer + written, *cursor, add_path);
        *cursor = (*cursor)->next;
    }

    return written;
}

static int bgp_encode_labeled_ipv4_chunk(labeled_ipv4_nlri_t **cursor,
                                         uint8_t *buffer,
                                         int max_bytes,
                                         int add_path,
                                         int withdraw_mode) {
    int written = 0;

    while (*cursor) {
        int ip_prefix_len = (*cursor)->prefix.prefix_len - 24;
        int needed;

        if ((int)(*cursor)->add_path != add_path || ip_prefix_len < 0) {
            // TODO(FUZZ_GATE): Allow malformed labeled IPv4 MP payload mode or prefix length.
            return -1;
        }

        needed = 1 + 3 + bgp_prefix_bytes_needed((uint8_t)ip_prefix_len);
        if (add_path) {
            needed += 4;
        }

        if (written + needed > max_bytes) {
            return (written > 0) ? written : -1;
        }

        written += bgp_encode_labeled_ipv4_nlri(buffer + written, *cursor, add_path, withdraw_mode);
        *cursor = (*cursor)->next;
    }

    return written;
}

static int bgp_encode_labeled_ipv6_chunk(labeled_ipv6_nlri_t **cursor,
                                         uint8_t *buffer,
                                         int max_bytes,
                                         int add_path,
                                         int withdraw_mode) {
    int written = 0;

    while (*cursor) {
        int ip_prefix_len = (*cursor)->prefix.prefix_len - 24;
        int needed;

        if ((int)(*cursor)->add_path != add_path || ip_prefix_len < 0) {
            // TODO(FUZZ_GATE): Allow malformed labeled IPv6 MP payload mode or prefix length.
            return -1;
        }

        needed = 1 + 3 + bgp_prefix_bytes_needed((uint8_t)ip_prefix_len);
        if (add_path) {
            needed += 4;
        }

        if (written + needed > max_bytes) {
            return (written > 0) ? written : -1;
        }

        written += bgp_encode_labeled_ipv6_nlri(buffer + written, *cursor, add_path, withdraw_mode);
        *cursor = (*cursor)->next;
    }

    return written;
}

static int bgp_as_path_contains_4byte(as_path_segment_t *segments, int num_segments) {
    int i;
    int j;

    for (i = 0; i < num_segments; i++) {
        for (j = 0; j < segments[i].length; j++) {
            if (segments[i].as_numbers[j] > 65535U) {
                return 1;
            }
        }
    }

    return 0;
}

static int bgp_as_path_calculate_length(as_path_segment_t *segments, int num_segments, int asn_width) {
    int total_len = 0;
    int i;

    for (i = 0; i < num_segments; i++) {
        total_len += 2 + (segments[i].length * asn_width);
    }

    return total_len;
}

static void bgp_as_path_serialize(uint8_t *buffer,
                                  as_path_segment_t *segments,
                                  int num_segments,
                                  int asn_width,
                                  int use_as_trans) {
    int i;
    int j;
    int offset = 0;

    for (i = 0; i < num_segments; i++) {
        buffer[offset++] = segments[i].type;
        buffer[offset++] = segments[i].length;
        /*
         * TODO(WIRE_MUTATION): Corrupt AS_PATH segment header.
         *
         * Each AS_PATH segment is [type(1) | length(1) | AS values].
         * The length byte counts AS VALUES, not bytes, so one length
         * unit = 2 or 4 wire bytes depending on asn_width.
         *
         * Useful mutations:
         *
         *   - Corrupt length:  *** FRAMING HAZARD ***
         *     The decoder walks segments by reading type, then length,
         *     then consuming (length * asn_width) bytes before looking
         *     for the next segment header. Wrong length cascades to
         *     every following segment in this AS_PATH, and since the
         *     AS_PATH attribute value is itself bounded by the outer
         *     attr-length, the cascade can push segment-walk past the
         *     attr boundary.
         *       * shrink by 1: remaining ASN bytes of the current
         *         segment are read as (type, length, ASN...) of the
         *         next segment, producing a segment with a type byte
         *         that's actually an ASN byte
         *       * grow by 1: next segment's type byte is consumed as
         *         part of current segment's last ASN
         *
         *   - Corrupt type:
         *     Valid types are AS_SET(1), AS_SEQUENCE(2), AS_CONFED_SEQ(3),
         *     AS_CONFED_SET(4). Setting type=0 or type>=5 tests
         *     unknown-segment-type handling; some parsers accept,
         *     others reset the session.
         *
         *   - Length = 0:
         *     Empty segment. RFC 4271 is silent on whether this is
         *     legal mid-path. Tests edge-case handling.
         *
         *   - Length = 255:
         *     Maximum possible value, claims (255 * asn_width) bytes
         *     of ASNs follow. Almost certainly overruns the attr.
         */

        for (j = 0; j < segments[i].length; j++) {
            uint32_t asn = segments[i].as_numbers[j];

            if (asn_width == 2) {
                uint16_t asn16 = (uint16_t)((use_as_trans && asn > 65535U) ? AS_TRANS : asn);
                asn16 = htons(asn16);
                memcpy(buffer + offset, &asn16, 2);
                offset += 2;
                /*
                 * TODO(WIRE_MUTATION): Corrupt 2-byte AS_PATH ASN.
                 *
                 * Value-level. Most interesting as an AS_TRANS
                 * (23456) probe: the encoder substitutes AS_TRANS
                 * when a 4-byte ASN is being written into a 2-byte
                 * slot, so mutating ASNs at exactly 23456 tests
                 * whether the peer correctly pairs with AS4_PATH.
                 * Corrupting to 0 / 65535 tests reserved-ASN rules.
                 */
            } else {
                uint32_t asn32 = htonl(asn);
                memcpy(buffer + offset, &asn32, 4);
                offset += 4;
                /*
                 * TODO(WIRE_MUTATION): Corrupt 4-byte AS_PATH ASN.
                 *
                 * Value-level. Mutations worth trying: 0 (reserved),
                 * 65535 (last 2-byte), 23456 (AS_TRANS), 4294967295
                 * (reserved), any value in 64496-64511 (documentation
                 * range), 64512-65534 and 4200000000-4294967294
                 * (private ranges). Each tests a different policy /
                 * filter path.
                 */
            }
        }
    }
}

// NLRI List Management

static int bgp_parse_nlri_address(const char *text, uint8_t bits, int af, void *address) {
    return text && bits <= (af == AF_INET6 ? 128 : 32) && inet_pton(af, text, address) == 1 ? 0 : -1;
}

static ipv4_nlri_list_t* ipv4_nlri_create_internal(const char *prefix_str,
                                                   uint8_t prefix_len,
                                                   int add_path,
                                                   uint32_t path_id) {
    ipv4_nlri_list_t *nlri = calloc(1, sizeof(ipv4_nlri_list_t));

    if (!nlri) {
        return NULL;
    }

    nlri->prefix.prefix_len = prefix_len;
    if (bgp_parse_nlri_address(prefix_str, prefix_len, AF_INET, &nlri->prefix.prefix) < 0) {
        free(nlri);
        return NULL;
    }
    nlri->path_id = path_id;
    nlri->add_path = (uint8_t)(add_path ? 1 : 0);
    nlri->next = NULL;

    return nlri;
}

DEFINE_BASIC_NLRI_CREATE_WRAPPERS(ipv4_nlri_list_t, ipv4_nlri)
DEFINE_BASIC_NLRI_TAIL_WRAPPERS(ipv4_nlri_list_t, ipv4_nlri)
DEFINE_NLRI_LIST_UTILS(ipv4_nlri_list_t, ipv4_nlri)

static ipv6_nlri_list_t* ipv6_nlri_create_internal(const char *prefix_str,
                                                   uint8_t prefix_len,
                                                   int add_path,
                                                   uint32_t path_id) {
    ipv6_nlri_list_t *nlri = calloc(1, sizeof(ipv6_nlri_list_t));

    if (!nlri) {
        return NULL;
    }

    nlri->prefix.prefix_len = prefix_len;
    if (bgp_parse_nlri_address(prefix_str, prefix_len, AF_INET6, nlri->prefix.prefix) < 0) {
        free(nlri);
        return NULL;
    }
    nlri->path_id = path_id;
    nlri->add_path = (uint8_t)(add_path ? 1 : 0);
    nlri->next = NULL;

    return nlri;
}

DEFINE_BASIC_NLRI_CREATE_WRAPPERS(ipv6_nlri_list_t, ipv6_nlri)
DEFINE_BASIC_NLRI_TAIL_WRAPPERS(ipv6_nlri_list_t, ipv6_nlri)
DEFINE_NLRI_LIST_UTILS(ipv6_nlri_list_t, ipv6_nlri)

/*
 * RFC 8277 labeled-unicast list helpers. The stored prefix length is the
 * wire length, i.e. 24 label bits plus the actual IP prefix length.
 */
static labeled_ipv4_nlri_t* labeled_ipv4_nlri_create_internal(
        const char *prefix_str,
        uint8_t prefix_len,
        uint32_t label,
        int add_path,
        uint32_t path_id) {
    if (label > 0xFFFFF) return NULL;
    labeled_ipv4_nlri_t *nlri = calloc(1, sizeof(labeled_ipv4_nlri_t));

    if (!nlri) {
        return NULL;
    }

    nlri->prefix.prefix_len = (uint8_t)(24 + prefix_len);
    nlri->prefix.label.label = label;
    nlri->prefix.label.tc = 0;
    nlri->prefix.label.s = 1;
    nlri->prefix.label.ttl = 0;
    if (bgp_parse_nlri_address(prefix_str, prefix_len, AF_INET, &nlri->prefix.prefix) < 0) {
        free(nlri);
        return NULL;
    }
    nlri->path_id = path_id;
    nlri->add_path = (uint8_t)(add_path ? 1 : 0);
    nlri->next = NULL;
    return nlri;
}

DEFINE_LABELED_NLRI_CREATE_WRAPPERS(labeled_ipv4_nlri_t, labeled_ipv4_nlri)
DEFINE_LABELED_NLRI_TAIL_WRAPPERS(labeled_ipv4_nlri_t, labeled_ipv4_nlri)
DEFINE_NLRI_LIST_UTILS(labeled_ipv4_nlri_t, labeled_ipv4_nlri)

static labeled_ipv6_nlri_t* labeled_ipv6_nlri_create_internal(
        const char *prefix_str,
        uint8_t prefix_len,
        uint32_t label,
        int add_path,
        uint32_t path_id) {
    if (label > 0xFFFFF) return NULL;
    labeled_ipv6_nlri_t *nlri = calloc(1, sizeof(labeled_ipv6_nlri_t));

    if (!nlri) {
        return NULL;
    }

    nlri->prefix.prefix_len = (uint8_t)(24 + prefix_len);
    nlri->prefix.label.label = label;
    nlri->prefix.label.tc = 0;
    nlri->prefix.label.s = 1;
    nlri->prefix.label.ttl = 0;
    if (bgp_parse_nlri_address(prefix_str, prefix_len, AF_INET6, nlri->prefix.prefix) < 0) {
        free(nlri);
        return NULL;
    }
    nlri->path_id = path_id;
    nlri->add_path = (uint8_t)(add_path ? 1 : 0);
    nlri->next = NULL;
    return nlri;
}

DEFINE_LABELED_NLRI_CREATE_WRAPPERS(labeled_ipv6_nlri_t, labeled_ipv6_nlri)
DEFINE_LABELED_NLRI_TAIL_WRAPPERS(labeled_ipv6_nlri_t, labeled_ipv6_nlri)
DEFINE_NLRI_LIST_UTILS(labeled_ipv6_nlri_t, labeled_ipv6_nlri)

// Path Attribute Creation Functions

bgp_path_attr_t* bgp_attr_create_origin(uint8_t origin) {
    bgp_path_attr_t *attr = bgp_attr_alloc(BGP_ATTR_FLAG_TRANSITIVE, BGP_ATTR_ORIGIN, 1);

    if (!attr) {
        return NULL;
    }

    attr->value[0] = origin;
    return attr;
}

bgp_path_attr_t* bgp_attr_create_as_path_mode(as_path_segment_t *segments,
                                              int num_segments,
                                              bgp_asn_encoding_mode_t mode) {
    bgp_path_attr_t *attr;
    int              use_as_trans;
    int              asn_width;
    int              total_len;

    if (mode == BGP_ASN_ENCODE_2BYTE && bgp_as_path_contains_4byte(segments, num_segments)) {
        /*
         * TODO(FUZZ_GATE): Allow 2-byte AS_PATH encode with 4-byte ASN(s).
         *
         * RFC 6793 (formerly RFC 4893) defines the migration from
         * 2-byte to 4-byte ASNs. A speaker that has negotiated only
         * 2-byte ASN capability cannot represent ASNs > 65535 in
         * AS_PATH; RFC 6793 section 4 says such ASNs MUST be
         * represented as AS_TRANS (23456) in AS_PATH, with the
         * original 4-byte ASNs carried in a parallel AS4_PATH
         * attribute.
         *
         * The strict encoder rejects this case entirely: if any
         * 4-byte ASN is present, the caller must select
         * ENCODE_4BYTE or ENCODE_TRANSITION. A future fuzz policy
         * may allow BGP_ASN_ENCODE_2BYTE with 4-byte ASNs to test
         * the peer's handling of:
         *
         *   - Truncated encoding: the low 16 bits of the 4-byte
         *     ASN written into the 2-byte slot (no AS_TRANS, no
         *     AS4_PATH). Peer sees a garbled AS_PATH that may
         *     look like a valid 2-byte ASN but encode the wrong
         *     value. Tests whether the peer detects the
         *     inconsistency via the negotiated capability.
         *
         *   - Modulo encoding: same as above but with explicit
         *     modulo 65536.
         *
         * Proposed allow key: "aspath.2byte-encode-has-4byte"
         */
        return NULL;
    }

    asn_width = (mode == BGP_ASN_ENCODE_4BYTE) ? 4 : 2;
    use_as_trans = (mode == BGP_ASN_ENCODE_TRANSITION);
    total_len = bgp_as_path_calculate_length(segments, num_segments, asn_width);

    attr = bgp_attr_alloc(BGP_ATTR_FLAG_TRANSITIVE, BGP_ATTR_AS_PATH, (uint16_t)total_len);
    if (!attr) {
        return NULL;
    }

    bgp_as_path_serialize(attr->value, segments, num_segments, asn_width, use_as_trans);
    return attr;
}

bgp_path_attr_t* bgp_attr_create_as_path(as_path_segment_t *segments, int num_segments) {
    return bgp_attr_create_as_path_mode(segments, num_segments, BGP_ASN_ENCODE_4BYTE);
}

int bgp_serialize_as_path_attr(uint8_t *buffer, size_t capacity, as_path_segment_t *segments, int num_segments) {
    int value_len = bgp_as_path_calculate_length(segments, num_segments, 4);
    int attr_len;
    int header_len;

    if (value_len > UINT16_MAX) {
        return -1;
    }

    /*
     * The header is 3 octets, or 4 when the value is longer than 255 octets (Extended Length flag);
     * bgp_marshaled_attr_size() and bgp_write_raw_attr_header() agree on this.
     */
    attr_len = bgp_marshaled_attr_size(BGP_ATTR_FLAG_TRANSITIVE, (uint16_t)value_len);
    if ((size_t)attr_len > capacity) {
        return -1;
    }

    header_len = bgp_write_raw_attr_header(buffer, BGP_ATTR_FLAG_TRANSITIVE, BGP_ATTR_AS_PATH, (uint16_t)value_len);
    bgp_as_path_serialize(buffer + header_len, segments, num_segments, 4, 0);
    return attr_len;
}

bgp_path_attr_t* bgp_attr_create_as4_path(as_path_segment_t *segments, int num_segments) {
    bgp_path_attr_t *attr;
    int              total_len = bgp_as_path_calculate_length(segments, num_segments, 4);

    attr = bgp_attr_alloc(BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANSITIVE, BGP_ATTR_AS4_PATH, (uint16_t)total_len);
    if (!attr) {
        return NULL;
    }

    bgp_as_path_serialize(attr->value, segments, num_segments, 4, 0);
    return attr;
}

bgp_path_attr_t* bgp_attr_create_as_path_transition(
    as_path_segment_t *segments,
    int num_segments,
    bgp_path_attr_t **as4_path_out) {
    bgp_path_attr_t *as_path;

    if (as4_path_out) {
        *as4_path_out = NULL;
    }

    as_path = bgp_attr_create_as_path_mode(segments, num_segments, BGP_ASN_ENCODE_TRANSITION);
    if (!as_path) {
        return NULL;
    }

    if (as4_path_out && bgp_as_path_contains_4byte(segments, num_segments)) {
        *as4_path_out = bgp_attr_create_as4_path(segments, num_segments);
        if (!*as4_path_out) {
            bgp_path_attr_free(as_path);
            return NULL;
        }
    }

    return as_path;
}

bgp_path_attr_t* bgp_attr_create_next_hop(const bgp_next_hop_t *next_hop) {
    bgp_path_attr_t *attr = bgp_attr_alloc(BGP_ATTR_FLAG_TRANSITIVE, BGP_ATTR_NEXT_HOP, 4);

    if (!attr || !next_hop || next_hop->af != AF_INET) {
        // TODO(FUZZ_GATE): Allow classic NEXT_HOP attr creation from non-IPv4 input.
        bgp_path_attr_free(attr);
        return NULL;
    }

    /*
     * NEXT_HOP (attribute 3) is only for the classic IPv4 UPDATE format.
     * Every MP family uses MP_REACH next-hop encoding instead.
     */
    memcpy(attr->value, &next_hop->address.ipv4, 4);
    // TODO(WIRE_MUTATION): Corrupt classic NEXT_HOP attr bytes after encode.
    return attr;
}

bgp_path_attr_t* bgp_attr_create_med(uint32_t med) {
    bgp_path_attr_t *attr = bgp_attr_alloc(BGP_ATTR_FLAG_OPTIONAL, BGP_ATTR_MULTI_EXIT_DISC, 4);
    uint32_t         med_net = htonl(med);

    if (!attr) {
        return NULL;
    }

    memcpy(attr->value, &med_net, 4);
    return attr;
}

bgp_path_attr_t* bgp_attr_create_local_pref(uint32_t local_pref) {
    bgp_path_attr_t *attr = bgp_attr_alloc(BGP_ATTR_FLAG_TRANSITIVE, BGP_ATTR_LOCAL_PREF, 4);
    uint32_t         lp_net = htonl(local_pref);

    if (!attr) {
        return NULL;
    }

    memcpy(attr->value, &lp_net, 4);
    return attr;
}

/*
 * Allocate one 8-octet Extended Community attribute (RFC 4360) with its Type
 * and Sub-Type set and the 6-octet value zeroed. Every 8-octet community
 * builder starts here and fills in only its own value octets.
 */
bgp_path_attr_t* bgp_attr_alloc_ext_comm(uint8_t type, uint8_t sub_type) {
    bgp_path_attr_t *attr = bgp_attr_alloc(BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANSITIVE, BGP_ATTR_EXT_COMM, 8);

    if (!attr) {
        return NULL;
    }

    memset(attr->value, 0, 8);
    attr->value[0] = type;
    attr->value[1] = sub_type;
    return attr;
}

/*
 * Two-Octet AS Specific layout (RFC 4360 section 3.1):
 *   Type | Sub-Type | Global Administrator (2) | Local Administrator (4)
 */
bgp_path_attr_t* bgp_attr_create_ext_comm_global2(uint8_t type,
                                                  uint8_t sub_type,
                                                  uint16_t global_admin,
                                                  uint32_t local_admin) {
    bgp_path_attr_t *attr = bgp_attr_alloc_ext_comm(type, sub_type);
    uint16_t         ga_net = htons(global_admin);
    uint32_t         la_net = htonl(local_admin);

    if (!attr) {
        return NULL;
    }

    memcpy(attr->value + 2, &ga_net, 2);
    memcpy(attr->value + 4, &la_net, 4);
    return attr;
}

/*
 * IPv4 Address Specific (RFC 4360 section 3.2) and Four-Octet AS Specific
 * (RFC 5668) layout:
 *   Type | Sub-Type | Global Administrator (4) | Local Administrator (2)
 * An IPv4 Global Administrator is given in host order.
 */
bgp_path_attr_t* bgp_attr_create_ext_comm_global4(uint8_t type,
                                                  uint8_t sub_type,
                                                  uint32_t global_admin,
                                                  uint16_t local_admin) {
    bgp_path_attr_t *attr = bgp_attr_alloc_ext_comm(type, sub_type);
    uint32_t         ga_net = htonl(global_admin);
    uint16_t         la_net = htons(local_admin);

    if (!attr) {
        return NULL;
    }

    memcpy(attr->value + 2, &ga_net, 4);
    memcpy(attr->value + 6, &la_net, 2);
    return attr;
}

/*
 * Encapsulation Extended Community (Type 0x03, Sub-Type 0x0c) for tunnel_type.
 */
bgp_path_attr_t* bgp_attr_create_ext_comm_encap(uint16_t tunnel_type) {
    bgp_path_attr_t *attr = bgp_attr_alloc_ext_comm(0x03, 0x0c);
    uint16_t         tunnel_type_net = htons(tunnel_type);

    if (!attr) {
        return NULL;
    }

    /*
     * RFC 9012 section 4.1 encodes the Encapsulation Extended Community as:
     *   Type=0x03 | Sub-Type=0x0c | Reserved(2) | Reserved(2) | Tunnel Type(2)
     * The helper leaves tunnel-type selection to the caller because the
     * registry is extensible and the wire format is the same for every value.
     */
    attr->value[2] = 0;
    attr->value[3] = 0;
    attr->value[4] = 0;
    attr->value[5] = 0;
    memcpy(attr->value + 6, &tunnel_type_net, 2);
    // TODO(WIRE_MUTATION): Corrupt Encapsulation EC type/subtype/reserved/tunnel type.

    return attr;
}

/*
 * Route Target with a 2-octet AS administrator (Type 0x00, Sub-Type 0x02, RFC 4360).
 */
bgp_path_attr_t* bgp_attr_create_ext_comm_rt(uint16_t global_admin, uint32_t local_admin) {
    return bgp_attr_create_ext_comm_global2(0x00, 0x02, global_admin, local_admin);
}

/*
 * Route Target with a 4-octet AS administrator (Type 0x02, Sub-Type 0x02, RFC 5668).
 */
bgp_path_attr_t* bgp_attr_create_ext_comm_rt_as4(uint32_t global_admin, uint16_t local_admin) {
    return bgp_attr_create_ext_comm_global4(0x02, 0x02, global_admin, local_admin);
}

/*
 * Route Target with an IPv4 administrator (Type 0x01, Sub-Type 0x02, RFC 4360).
 */
bgp_path_attr_t* bgp_attr_create_ext_comm_rt_ip(uint32_t ipv4_address, uint16_t local_admin) {
    return bgp_attr_create_ext_comm_global4(0x01, 0x02, ipv4_address, local_admin);
}

/*
 * Append the entries of one community-list attribute to another of the same
 * type. A single attribute can legally carry many entries; EVPN RT-2 / RT-5
 * routes commonly need this when a route carries both Encapsulation EC and
 * EVPN Router's MAC EC, and FlowSpec routes carry several actions.
 */
static int bgp_attr_append_entries(bgp_path_attr_t *dst,
                                   const bgp_path_attr_t *src,
                                   uint8_t type_code,
                                   uint16_t entry_len) {
    uint8_t *new_value;

    if (!dst || !src ||
        dst->type_code != type_code ||
        src->type_code != type_code ||
        dst->length == 0 || src->length == 0 ||
        (dst->length % entry_len) != 0 || (src->length % entry_len) != 0 ||
        (uint32_t)dst->length + src->length > UINT16_MAX) {
        return -1;
    }

    new_value = realloc(dst->value, (size_t)dst->length + src->length);
    if (!new_value) {
        return -1;
    }

    memcpy(new_value + dst->length, src->value, src->length);
    dst->value = new_value;
    dst->length = (uint16_t)(dst->length + src->length);
    return 0;
}

/*
 * Append the 8-octet entries of src to dst, both EXTENDED_COMMUNITIES attributes.
 */
int bgp_attr_ext_comm_append_attr(bgp_path_attr_t *dst, const bgp_path_attr_t *src) {
    return bgp_attr_append_entries(dst, src, BGP_ATTR_EXT_COMM, 8);
}

/*
 * Color Extended Community (RFC 9012 section 4.3):
 *   Type=0x03 | Sub-Type=0x0b | Flags(2) | Color(4)
 *
 * RFC 9830 section 3 assigns the two high-order flag bits to the Color-Only
 * type (CO bits). The other 14 bits stay unassigned: send zero, ignore on
 * receipt.
 */
void bgp_ext_comm_color_write(uint8_t out[8], uint32_t color, uint16_t flags) {
    uint16_t flags_net = htons(flags);
    uint32_t color_net = htonl(color);

    out[0] = 0x03;
    out[1] = 0x0b;
    memcpy(out + 2, &flags_net, 2);
    // TODO(WIRE_MUTATION): Set unassigned Color flag bits; receiver must ignore them.
    memcpy(out + 4, &color_net, 4);
}

/*
 * One Color community attribute with the whole flags field given.
 */
bgp_path_attr_t* bgp_attr_create_ext_comm_color_flags(uint32_t color, uint16_t flags) {
    bgp_path_attr_t *attr = bgp_attr_alloc_ext_comm(0x03, 0x0b);

    if (!attr) {
        return NULL;
    }

    bgp_ext_comm_color_write(attr->value, color, flags);
    return attr;
}

/*
 * co_type 3 (bits 11) is reserved: a sender SHOULD NOT use it and a receiver
 * MUST treat it as type 0 (RFC 9830 section 3). It is accepted here so that
 * tests can send it.
 */
bgp_path_attr_t* bgp_attr_create_ext_comm_color(uint32_t color, uint8_t co_type) {
    if (co_type > BGP_COLOR_CO_RESERVED) {
        return NULL;
    }

    return bgp_attr_create_ext_comm_color_flags(color, BGP_COLOR_CO_FLAGS(co_type));
}

/*
 * IPv6 Address Specific Extended Community (RFC 5701): a separate path
 * attribute (type 25) whose value is a list of 20-octet entries:
 *   Type(1) | Sub-Type(1) | IPv6 Global Administrator(16) | Local Admin(2)
 */
bgp_path_attr_t* bgp_attr_create_ipv6_ext_comm(uint8_t type,
                                               uint8_t sub_type,
                                               const struct in6_addr *address,
                                               uint16_t local_admin) {
    bgp_path_attr_t *attr;
    uint16_t         la_net = htons(local_admin);

    if (!address) {
        return NULL;
    }

    attr = bgp_attr_alloc(BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANSITIVE, BGP_ATTR_IPV6_EXT_COMM, 20);
    if (!attr) {
        return NULL;
    }

    attr->value[0] = type;
    attr->value[1] = sub_type;
    memcpy(attr->value + 2, address, 16);
    memcpy(attr->value + 18, &la_net, 2);
    // TODO(WIRE_MUTATION): Corrupt the entry type/sub-type or make the value length not a multiple of 20.
    return attr;
}

/*
 * Append the 20-octet entries of src to dst, both IPv6 Address Specific Extended Community attributes (attribute 25).
 */
int bgp_attr_ipv6_ext_comm_append_attr(bgp_path_attr_t *dst, const bgp_path_attr_t *src) {
    return bgp_attr_append_entries(dst, src, BGP_ATTR_IPV6_EXT_COMM, 20);
}

bgp_path_attr_t* bgp_attr_create_mp_reach_ipv6(const bgp_next_hop_t *next_hop, ipv6_nlri_list_t *nlri_list) {
    bgp_next_hop_t    default_next_hop;
    uint8_t           nh_buffer[32];
    uint8_t           nh_len = 0;
    size_t            nlri_len = 0;
    bgp_path_attr_t  *attr = NULL;
    ipv6_nlri_list_t *curr = nlri_list;
    uint16_t          afi_net = htons(AFI_IPV6);
    int               offset = 0;
    int               add_path = 0;

    if (!next_hop) {
        memset(&default_next_hop, 0, sizeof(default_next_hop));
        default_next_hop.af = AF_INET6;
        next_hop = &default_next_hop;
    }

    if (bgp_detect_ipv6_add_path(nlri_list, &add_path) < 0 ||
        bgp_encode_ipv6_family_next_hop(next_hop, nh_buffer, &nh_len) < 0) {
        return NULL;
    }

    while (curr) {
        nlri_len += 1U + bgp_prefix_bytes_needed(curr->prefix.prefix_len) + (add_path ? 4 : 0);
        if (nlri_len > UINT16_MAX - 5U - nh_len) return NULL;
        curr = curr->next;
    }

    /*
     * Keep the public helper shape, but write NLRI directly into attr->value so
     * large IPv6 lists do not bounce through a second temporary buffer first.
     */
    attr = bgp_attr_alloc(BGP_ATTR_FLAG_OPTIONAL,
                          BGP_ATTR_MP_REACH_NLRI,
                          (uint16_t)(2 + 1 + 1 + nh_len + 1 + nlri_len));
    if (!attr) {
        return NULL;
    }

    memcpy(attr->value + offset, &afi_net, sizeof(afi_net));
    offset += 2;
    attr->value[offset++] = SAFI_UNICAST;
    attr->value[offset++] = nh_len;
    if (nh_len > 0) {
        memcpy(attr->value + offset, nh_buffer, nh_len);
        offset += nh_len;
    }
    attr->value[offset++] = 0;

    curr = nlri_list;
    while (curr) {
        offset += bgp_encode_ipv6_nlri(attr->value + offset, curr, add_path);
        curr = curr->next;
    }

    return attr;
}

bgp_path_attr_t* bgp_attr_create_mp_unreach_ipv6(ipv6_nlri_list_t *withdrawn_list) {
    size_t            nlri_len = 0;
    bgp_path_attr_t  *attr = NULL;
    ipv6_nlri_list_t *curr = withdrawn_list;
    uint16_t          afi_net = htons(AFI_IPV6);
    int               offset = 0;
    int               add_path = 0;

    if (bgp_detect_ipv6_add_path(withdrawn_list, &add_path) < 0) {
        return NULL;
    }

    while (curr) {
        nlri_len += 1U + bgp_prefix_bytes_needed(curr->prefix.prefix_len) + (add_path ? 4 : 0);
        if (nlri_len > UINT16_MAX - 3U) return NULL;
        curr = curr->next;
    }

    attr = bgp_attr_alloc(BGP_ATTR_FLAG_OPTIONAL, BGP_ATTR_MP_UNREACH_NLRI, (uint16_t)(2 + 1 + nlri_len));
    if (!attr) {
        return NULL;
    }

    memcpy(attr->value + offset, &afi_net, sizeof(afi_net));
    offset += 2;
    attr->value[offset++] = SAFI_UNICAST;

    curr = withdrawn_list;
    while (curr) {
        offset += bgp_encode_ipv6_nlri(attr->value + offset, curr, add_path);
        curr = curr->next;
    }

    return attr;
}

// BGP UPDATE Message Generation

bgp_update_result_t* bgp_generate_update_labeled_ipv4(
    labeled_ipv4_nlri_t *nlri_list,
    bgp_path_attr_t *attributes,
    labeled_ipv4_nlri_t *withdrawn_list,
    uint16_t max_pdu_size,
    const bgp_next_hop_t *next_hop) {
    bgp_builder_t        builder = {0};
    uint8_t             *base_attr_data = NULL;
    uint16_t             base_attr_len = 0;
    uint8_t             *chunk_buf = NULL;
    uint8_t              nh_buf[BGP_STANDARD_NEXT_HOP_BUF_SIZE];
    uint8_t              nh_len = 0;
    int                  available_space;
    int                  nlri_add_path = 0;
    int                  withdrawn_add_path = 0;
    labeled_ipv4_nlri_t *cursor;

    if (max_pdu_size == 0) {
        max_pdu_size = BGP_MAX_PDU_SIZE;
    }
    if (max_pdu_size < BGP_UPDATE_MIN_SIZE) {
        return NULL;
    }
    if (bgp_detect_labeled_ipv4_add_path(nlri_list, &nlri_add_path) < 0 ||
        bgp_detect_labeled_ipv4_add_path(withdrawn_list, &withdrawn_add_path) < 0) {
        return NULL;
    }

    if (bgp_attr_list_contains_type(attributes, BGP_ATTR_MP_REACH_NLRI) ||
        bgp_attr_list_contains_type(attributes, BGP_ATTR_MP_UNREACH_NLRI)) {
        return NULL;
    }

    if (bgp_serialize_path_attributes_alloc(attributes,
                                            &base_attr_data,
                                            &base_attr_len) < 0) {
        return NULL;
    }

    if (nlri_list) {
        // TODO(FUZZ_GATE): Allow labeled IPv4 MP_REACH with invalid attrs or next-hop form.
        if (!bgp_validate_mp_attrs(attributes) ||
            bgp_encode_labeled_ipv4_next_hop(next_hop, nh_buf, &nh_len) < 0) {
            goto fail;
        }
    }

    if (bgp_builder_init(&builder) < 0) {
        goto fail;
    }

    chunk_buf = malloc(max_pdu_size);
    if (!chunk_buf) {
        goto fail;
    }

    if (withdrawn_list) {
        available_space = bgp_mp_unreach_payload_budget(max_pdu_size);
        if (available_space <= 0) {
            goto fail;
        }

        cursor = withdrawn_list;
        while (cursor) {
            int chunk_len = bgp_encode_labeled_ipv4_chunk(&cursor, chunk_buf, available_space, withdrawn_add_path, 1);
            if (chunk_len <= 0 ||
                bgp_builder_append_mp(&builder, &(bgp_mp_args_t){
                    .afi         = AFI_IPV4,
                    .safi        = SAFI_LABELED_UNICAST,
                    .mp_nlri     = chunk_buf,            /* withdrawn NLRI */
                    .mp_nlri_len = (uint16_t)chunk_len,
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

        cursor = nlri_list;
        while (cursor) {
            int chunk_len = bgp_encode_labeled_ipv4_chunk(&cursor, chunk_buf, available_space, nlri_add_path, 0);
            if (chunk_len <= 0 ||
                bgp_builder_append_mp(&builder, &(bgp_mp_args_t){
                    .attrs       = base_attr_data,  /* origin + as_path + ... */
                    .attrs_len   = base_attr_len,
                    .is_reach    = 1,               /* MP_REACH_NLRI          */
                    .afi         = AFI_IPV4,
                    .safi        = SAFI_LABELED_UNICAST,
                    .next_hop    = nh_buf,          /* encoded next-hop       */
                    .nh_len      = nh_len,
                    .mp_nlri     = chunk_buf,       /* labeled unicast NLRI   */
                    .mp_nlri_len = (uint16_t)chunk_len,
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
    free(chunk_buf);
    return bgp_builder_take(&builder);

fail:
    free(base_attr_data);
    free(chunk_buf);
    bgp_builder_release(&builder);
    return NULL;
}

bgp_update_result_t* bgp_generate_update_labeled_ipv6(
    labeled_ipv6_nlri_t *nlri_list,
    bgp_path_attr_t *attributes,
    labeled_ipv6_nlri_t *withdrawn_list,
    uint16_t max_pdu_size,
    const bgp_next_hop_t *next_hop) {
    bgp_builder_t        builder = {0};
    uint8_t             *base_attr_data = NULL;
    uint16_t             base_attr_len = 0;
    uint8_t             *chunk_buf = NULL;
    uint8_t              nh_buf[BGP_STANDARD_NEXT_HOP_BUF_SIZE];
    uint8_t              nh_len = 0;
    int                  available_space;
    int                  nlri_add_path = 0;
    int                  withdrawn_add_path = 0;
    labeled_ipv6_nlri_t *cursor;

    if (max_pdu_size == 0) {
        max_pdu_size = BGP_MAX_PDU_SIZE;
    }
    if (max_pdu_size < BGP_UPDATE_MIN_SIZE) {
        return NULL;
    }
    if (bgp_detect_labeled_ipv6_add_path(nlri_list, &nlri_add_path) < 0 ||
        bgp_detect_labeled_ipv6_add_path(withdrawn_list, &withdrawn_add_path) < 0) {
        return NULL;
    }

    if (bgp_attr_list_contains_type(attributes, BGP_ATTR_MP_REACH_NLRI) ||
        bgp_attr_list_contains_type(attributes, BGP_ATTR_MP_UNREACH_NLRI)) {
        return NULL;
    }

    if (bgp_serialize_path_attributes_alloc(attributes,
                                            &base_attr_data,
                                            &base_attr_len) < 0) {
        return NULL;
    }

    if (nlri_list) {
        // TODO(FUZZ_GATE): Allow labeled IPv6 MP_REACH with invalid attrs or next-hop form.
        if (!bgp_validate_mp_attrs(attributes) ||
            bgp_encode_ipv6_family_next_hop(next_hop, nh_buf, &nh_len) < 0) {
            goto fail;
        }
    }

    if (bgp_builder_init(&builder) < 0) {
        goto fail;
    }

    chunk_buf = malloc(max_pdu_size);
    if (!chunk_buf) {
        goto fail;
    }

    if (withdrawn_list) {
        available_space = bgp_mp_unreach_payload_budget(max_pdu_size);
        if (available_space <= 0) {
            goto fail;
        }

        cursor = withdrawn_list;
        while (cursor) {
            int chunk_len = bgp_encode_labeled_ipv6_chunk(&cursor, chunk_buf, available_space, withdrawn_add_path, 1);
            if (chunk_len <= 0 ||
                bgp_builder_append_mp(&builder, &(bgp_mp_args_t){
                    .afi         = AFI_IPV6,
                    .safi        = SAFI_LABELED_UNICAST,
                    .mp_nlri     = chunk_buf,            /* withdrawn NLRI */
                    .mp_nlri_len = (uint16_t)chunk_len,
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

        cursor = nlri_list;
        while (cursor) {
            int chunk_len = bgp_encode_labeled_ipv6_chunk(&cursor, chunk_buf, available_space, nlri_add_path, 0);
            if (chunk_len <= 0 ||
                bgp_builder_append_mp(&builder, &(bgp_mp_args_t){
                    .attrs       = base_attr_data,  /* origin + as_path + ... */
                    .attrs_len   = base_attr_len,
                    .is_reach    = 1,               /* MP_REACH_NLRI          */
                    .afi         = AFI_IPV6,
                    .safi        = SAFI_LABELED_UNICAST,
                    .next_hop    = nh_buf,          /* encoded next-hop       */
                    .nh_len      = nh_len,
                    .mp_nlri     = chunk_buf,       /* labeled unicast NLRI   */
                    .mp_nlri_len = (uint16_t)chunk_len,
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
    free(chunk_buf);
    return bgp_builder_take(&builder);

fail:
    free(base_attr_data);
    free(chunk_buf);
    bgp_builder_release(&builder);
    return NULL;
}

bgp_update_result_t* bgp_generate_update_ipv4(
    ipv4_nlri_list_t *nlri_list,
    bgp_path_attr_t *attributes,
    ipv4_nlri_list_t *withdrawn_list,
    uint16_t max_pdu_size) {
    bgp_builder_t     builder = {0};
    uint8_t          *chunk_buf = NULL;
    uint8_t          *base_attr_data = NULL;
    uint16_t          base_attr_len = 0;
    int               available_space;
    ipv4_nlri_list_t *cursor;
    int               nlri_add_path = 0;
    int               withdrawn_add_path = 0;

    if (max_pdu_size == 0) {
        max_pdu_size = BGP_MAX_PDU_SIZE;
    }
    if (max_pdu_size < BGP_UPDATE_MIN_SIZE) {
        return NULL;
    }
    if (bgp_detect_ipv4_add_path(nlri_list, &nlri_add_path) < 0 ||
        bgp_detect_ipv4_add_path(withdrawn_list, &withdrawn_add_path) < 0) {
        return NULL;
    }

    if (bgp_builder_init(&builder) < 0) {
        return NULL;
    }

    chunk_buf = malloc(max_pdu_size);
    if (!chunk_buf ||
        bgp_serialize_path_attributes_alloc(attributes,
                                            &base_attr_data,
                                            &base_attr_len) < 0) {
        goto fail;
    }

    if (withdrawn_list) {
        available_space = max_pdu_size - (BGP_HEADER_SIZE + 2 + 2);
        if (available_space <= 0) {
            goto fail;
        }

        cursor = withdrawn_list;
        while (cursor) {
            int chunk_len = bgp_encode_ipv4_chunk(&cursor, chunk_buf, available_space, withdrawn_add_path);
            if (chunk_len <= 0 ||
                bgp_builder_append(&builder,
                                   chunk_buf, (uint16_t)chunk_len,  /* withdrawn */
                                   NULL, 0,                         /* attrs     */
                                   NULL, 0) < 0) {                  /* NLRI      */
                goto fail;
            }
        }
    }

    if (nlri_list) {
        // TODO(FUZZ_GATE): Allow classic IPv4 UPDATEs that fail mandatory-attr validation.
        if (!bgp_validate_ipv4_attrs(attributes)) {
            goto fail;
        }

        available_space = max_pdu_size - (BGP_HEADER_SIZE + 2 + 2 + base_attr_len);
        if (available_space <= 0) {
            goto fail;
        }

        cursor = nlri_list;
        while (cursor) {
            int chunk_len = bgp_encode_ipv4_chunk(&cursor, chunk_buf, available_space, nlri_add_path);
            if (chunk_len <= 0 ||
                bgp_builder_append(&builder,
                                   NULL, 0,                                /* withdrawn */
                                   base_attr_data, base_attr_len,          /* attrs     */
                                   chunk_buf, (uint16_t)chunk_len) < 0) {  /* NLRI      */
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
    free(chunk_buf);
    return bgp_builder_take(&builder);

fail:
    free(base_attr_data);
    free(chunk_buf);
    bgp_builder_release(&builder);
    return NULL;
}

bgp_update_result_t* bgp_generate_update_ipv4_mp(
    ipv4_nlri_list_t *nlri_list,
    bgp_path_attr_t *attributes,
    ipv4_nlri_list_t *withdrawn_list,
    uint16_t max_pdu_size,
    const bgp_next_hop_t *next_hop) {
    bgp_builder_t     builder = {0};
    uint8_t          *base_attr_data = NULL;
    uint16_t          base_attr_len = 0;
    uint8_t          *chunk_buf = NULL;
    uint8_t           nh_buf[BGP_STANDARD_NEXT_HOP_BUF_SIZE];
    uint8_t           nh_len = 0;
    int               available_space;
    ipv4_nlri_list_t *cursor;
    int               nlri_add_path = 0;
    int               withdrawn_add_path = 0;

    if (max_pdu_size == 0) {
        max_pdu_size = BGP_MAX_PDU_SIZE;
    }
    if (max_pdu_size < BGP_UPDATE_MIN_SIZE) {
        return NULL;
    }
    if (bgp_detect_ipv4_add_path(nlri_list, &nlri_add_path) < 0 ||
        bgp_detect_ipv4_add_path(withdrawn_list, &withdrawn_add_path) < 0) {
        return NULL;
    }

    if (bgp_attr_list_contains_type(attributes, BGP_ATTR_MP_REACH_NLRI) ||
        bgp_attr_list_contains_type(attributes, BGP_ATTR_MP_UNREACH_NLRI)) {
        return NULL;
    }

    if (bgp_serialize_path_attributes_alloc(attributes,
                                            &base_attr_data,
                                            &base_attr_len) < 0) {
        return NULL;
    }

    if (nlri_list) {
        /*
         * RFC 8950 carries IPv4 unicast NLRI in MP_REACH_NLRI when the
         * recursive next hop is IPv6, so legacy NEXT_HOP is not required.
         */
        if (!bgp_validate_mp_attrs(attributes) ||
            bgp_encode_ipv6_family_next_hop(next_hop, nh_buf, &nh_len) < 0) {
            goto fail;
        }
    }

    if (bgp_builder_init(&builder) < 0) {
        goto fail;
    }

    chunk_buf = malloc(max_pdu_size);
    if (!chunk_buf) {
        goto fail;
    }

    if (withdrawn_list) {
        available_space = bgp_mp_unreach_payload_budget(max_pdu_size);
        if (available_space <= 0) {
            goto fail;
        }

        cursor = withdrawn_list;
        while (cursor) {
            int chunk_len = bgp_encode_ipv4_chunk(&cursor, chunk_buf, available_space, withdrawn_add_path);
            if (chunk_len <= 0) {
                goto fail;
            }

            if (bgp_builder_append_mp(&builder, &(bgp_mp_args_t){
                    .afi         = AFI_IPV4,
                    .safi        = SAFI_UNICAST,
                    .mp_nlri     = chunk_buf,            /* withdrawn NLRI */
                    .mp_nlri_len = (uint16_t)chunk_len,
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

        cursor = nlri_list;
        while (cursor) {
            int chunk_len = bgp_encode_ipv4_chunk(&cursor, chunk_buf, available_space, nlri_add_path);
            if (chunk_len <= 0) {
                goto fail;
            }

            if (bgp_builder_append_mp(&builder, &(bgp_mp_args_t){
                    .attrs       = base_attr_data,  /* origin + as_path + ... */
                    .attrs_len   = base_attr_len,
                    .is_reach    = 1,               /* MP_REACH_NLRI          */
                    .afi         = AFI_IPV4,
                    .safi        = SAFI_UNICAST,
                    .next_hop    = nh_buf,          /* encoded next-hop       */
                    .nh_len      = nh_len,
                    .mp_nlri     = chunk_buf,       /* unicast NLRI           */
                    .mp_nlri_len = (uint16_t)chunk_len,
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
    free(chunk_buf);
    return bgp_builder_take(&builder);

fail:
    free(base_attr_data);
    free(chunk_buf);
    bgp_builder_release(&builder);
    return NULL;
}

bgp_update_result_t* bgp_generate_update_ipv6(
    ipv6_nlri_list_t *nlri_list,
    bgp_path_attr_t *attributes,
    ipv6_nlri_list_t *withdrawn_list,
    uint16_t max_pdu_size,
    const bgp_next_hop_t *next_hop) {
    bgp_builder_t     builder = {0};
    uint8_t          *base_attr_data = NULL;
    uint16_t          base_attr_len = 0;
    uint8_t          *chunk_buf = NULL;
    uint8_t           nh_buf[BGP_STANDARD_NEXT_HOP_BUF_SIZE];
    uint8_t           nh_len = 0;
    int               available_space;
    ipv6_nlri_list_t *cursor;
    int               nlri_add_path = 0;
    int               withdrawn_add_path = 0;

    if (max_pdu_size == 0) {
        max_pdu_size = BGP_MAX_PDU_SIZE;
    }
    if (max_pdu_size < BGP_UPDATE_MIN_SIZE) {
        return NULL;
    }
    if (bgp_detect_ipv6_add_path(nlri_list, &nlri_add_path) < 0 ||
        bgp_detect_ipv6_add_path(withdrawn_list, &withdrawn_add_path) < 0) {
        return NULL;
    }

    if (bgp_attr_list_contains_type(attributes, BGP_ATTR_MP_REACH_NLRI) ||
        bgp_attr_list_contains_type(attributes, BGP_ATTR_MP_UNREACH_NLRI)) {
        return NULL;
    }

    if (bgp_serialize_path_attributes_alloc(attributes,
                                            &base_attr_data,
                                            &base_attr_len) < 0) {
        return NULL;
    }

    if (nlri_list) {
        // TODO(FUZZ_GATE): Allow IPv6 MP_REACH with invalid attrs or next-hop form.
        if (!bgp_validate_mp_attrs(attributes) ||
            bgp_encode_ipv6_family_next_hop(next_hop, nh_buf, &nh_len) < 0) {
            goto fail;
        }
    }

    if (bgp_builder_init(&builder) < 0) {
        goto fail;
    }

    chunk_buf = malloc(max_pdu_size);
    if (!chunk_buf) {
        goto fail;
    }

    if (withdrawn_list) {
        available_space = bgp_mp_unreach_payload_budget(max_pdu_size);
        if (available_space <= 0) {
            goto fail;
        }

        cursor = withdrawn_list;
        while (cursor) {
            int chunk_len = bgp_encode_ipv6_chunk(&cursor, chunk_buf, available_space, withdrawn_add_path);
            if (chunk_len <= 0) {
                goto fail;
            }

            /*
             * Serialize MP_UNREACH directly into the final UPDATE so split
             * message generation does not allocate one heap buffer per chunk.
             */
            if (bgp_builder_append_mp(&builder, &(bgp_mp_args_t){
                    .afi         = AFI_IPV6,
                    .safi        = SAFI_UNICAST,
                    .mp_nlri     = chunk_buf,            /* withdrawn NLRI */
                    .mp_nlri_len = (uint16_t)chunk_len,
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

        cursor = nlri_list;
        while (cursor) {
            int chunk_len = bgp_encode_ipv6_chunk(&cursor, chunk_buf, available_space, nlri_add_path);
            if (chunk_len <= 0) {
                goto fail;
            }

            if (bgp_builder_append_mp(&builder, &(bgp_mp_args_t){
                    .attrs       = base_attr_data,  /* origin + as_path + ... */
                    .attrs_len   = base_attr_len,
                    .is_reach    = 1,               /* MP_REACH_NLRI          */
                    .afi         = AFI_IPV6,
                    .safi        = SAFI_UNICAST,
                    .next_hop    = nh_buf,          /* encoded next-hop       */
                    .nh_len      = nh_len,
                    .mp_nlri     = chunk_buf,       /* unicast NLRI           */
                    .mp_nlri_len = (uint16_t)chunk_len,
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
    free(chunk_buf);
    return bgp_builder_take(&builder);

fail:
    free(base_attr_data);
    free(chunk_buf);
    bgp_builder_release(&builder);
    return NULL;
}
