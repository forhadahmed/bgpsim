/*
 * BGP UPDATE Message Generation - SR Policy Extensions
 * Implements SR Policy (AFI 1/2, SAFI 73) support per RFC 9830.
 */

#define OUTPUT_STDIO_REMAP

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "bgp.h"
#include "output.h"
#include "bgp_update.h"

// SR Policy NLRI Functions

static srpolicy_nlri_list_t* srpolicy_nlri_create_internal(
    uint32_t distinguisher,
    uint32_t color,
    int endpoint_af,
    const char *endpoint_str,
    int add_path,
    uint32_t path_id) {
    if (endpoint_af != AFI_IPV4 && endpoint_af != AFI_IPV6) return NULL;
    srpolicy_nlri_list_t *nlri = calloc(1, sizeof(srpolicy_nlri_list_t));

    if (!nlri) {
        return NULL;
    }

    nlri->prefix.distinguisher = distinguisher;
    nlri->prefix.color = color;
    nlri->prefix.endpoint_af = endpoint_af;

    memset(nlri->prefix.endpoint, 0, 16);
    if (endpoint_str) {
        int af = (endpoint_af == AFI_IPV6) ? AF_INET6 : AF_INET;
        if (inet_pton(af, endpoint_str, nlri->prefix.endpoint) != 1) {
            free(nlri);
            return NULL;
        }
    }

    nlri->path_id = path_id;
    nlri->add_path = (uint8_t)(add_path ? 1 : 0);
    nlri->next = NULL;

    return nlri;
}

srpolicy_nlri_list_t* srpolicy_nlri_create(uint32_t distinguisher,
                                           uint32_t color,
                                           int endpoint_af,
                                           const char *endpoint_str) {
    return srpolicy_nlri_create_internal(distinguisher, color, endpoint_af, endpoint_str, 0, 0);
}

srpolicy_nlri_list_t* srpolicy_nlri_create_path_id(uint32_t distinguisher,
                                                   uint32_t color,
                                                   int endpoint_af,
                                                   const char *endpoint_str,
                                                   uint32_t path_id) {
    return srpolicy_nlri_create_internal(distinguisher, color, endpoint_af, endpoint_str, 1, path_id);
}

DEFINE_NLRI_LIST_UTILS(srpolicy_nlri_list_t, srpolicy_nlri)

// SR Policy NLRI Encoding

int bgp_encode_srpolicy_prefix(uint8_t *buffer, srpolicy_prefix_t *prefix) {
    if (!buffer || !prefix || (prefix->endpoint_af != AFI_IPV4 && prefix->endpoint_af != AFI_IPV6)) return -1;
    int offset = 0;
    int endpoint_len = (prefix->endpoint_af == AFI_IPV6) ? 16 : 4;

    // NLRI length in bits
    buffer[offset++] = (uint8_t)((4 + 4 + endpoint_len) * 8);

    // Distinguisher (4 bytes, network order)
    uint32_t dist_net = htonl(prefix->distinguisher);
    memcpy(buffer + offset, &dist_net, 4);
    offset += 4;

    // Color (4 bytes, network order)
    uint32_t color_net = htonl(prefix->color);
    memcpy(buffer + offset, &color_net, 4);
    offset += 4;

    // Endpoint (4 bytes for IPv4, 16 bytes for IPv6)
    memcpy(buffer + offset, prefix->endpoint, endpoint_len);
    offset += endpoint_len;

    return offset;
}

// SR Policy Next-Hop Encoding

/*
 * SR Policy next-hop is AFI-independent: the next-hop AF does not need to
 * match the NLRI AFI. An IPv4 NLRI can carry an IPv6 next hop and vice versa.
 * This function accepts any AF and writes a raw IPv4 (4 bytes) or
 * IPv6 (16 bytes) next hop.
 */
int bgp_encode_srpolicy_next_hop(const bgp_next_hop_t *next_hop, uint8_t *buffer, uint8_t *nh_len_out) {
    if (!next_hop || next_hop->af == 0) {
        // Default: 4-byte all-zero next hop
        memset(buffer, 0, 4);
        *nh_len_out = 4;
        return 0;
    }

    if (next_hop->af == AF_INET) {
        memcpy(buffer, &next_hop->address.ipv4, 4);
        *nh_len_out = 4;
    } else if (next_hop->af == AF_INET6) {
        memcpy(buffer, &next_hop->address.ipv6, 16);
        *nh_len_out = 16;
        if (next_hop->has_link_local) {
            memcpy(buffer + 16, &next_hop->link_local, 16);
            *nh_len_out = 32;
        }
    } else {
        return -1;
    }

    return 0;
}

// Tunnel Encapsulation Attribute (Type 23)

static void srpolicy_encode_binding_sid_label(uint8_t *buffer, uint32_t label) {
    /*
     * RFC 9830 Binding SID sub-TLV uses the full 4-octet MPLS label field.
     * TC, S, and TTL are reserved here and therefore encoded as zero.
     */
    buffer[0] = (uint8_t)((label >> 12) & 0xFF);
    buffer[1] = (uint8_t)((label >> 4) & 0xFF);
    buffer[2] = (uint8_t)((label & 0x0F) << 4);
    buffer[3] = 0;
}

static void srpolicy_encode_segment_type_a_label(uint8_t *buffer, uint32_t label) {
    /*
     * RFC 9830 Segment Type A also uses the 4-octet MPLS label field.
     * The helper does not expose explicit TC/TTL knobs, so use TC=0,
     * S=0, and TTL=255 to express "receiver may choose the TTL".
     */
    buffer[0] = (uint8_t)((label >> 12) & 0xFF);
    buffer[1] = (uint8_t)((label >> 4) & 0xFF);
    buffer[2] = (uint8_t)((label & 0x0F) << 4);
    buffer[3] = 0xFF;
}

static int srpolicy_decode_segment_mpls_label(const sr_segment_t *segment, uint32_t *label_out) {
    uint32_t label_net;

    if (!segment || !label_out) {
        return -1;
    }

    memcpy(&label_net, segment->sid, sizeof(label_net));
    *label_out = ntohl(label_net);
    return 0;
}

static int srpolicy_srv6_behavior_valid(const srpolicy_srv6_behavior_t *behavior) {
    uint16_t total;

    if (!behavior) {
        return 0;
    }

    total = (uint16_t)behavior->locator_block_len +
            (uint16_t)behavior->locator_node_len +
            (uint16_t)behavior->function_len +
            (uint16_t)behavior->argument_len;
    return total <= 128;
}

static void srpolicy_encode_srv6_behavior(uint8_t *buffer, const srpolicy_srv6_behavior_t *behavior) {
    uint16_t endpoint_behavior_net = htons(behavior->endpoint_behavior);
    uint16_t reserved = 0;

    memcpy(buffer, &endpoint_behavior_net, sizeof(endpoint_behavior_net));
    memcpy(buffer + 2, &reserved, sizeof(reserved));
    buffer[4] = behavior->locator_block_len;
    buffer[5] = behavior->locator_node_len;
    buffer[6] = behavior->function_len;
    buffer[7] = behavior->argument_len;
}

static uint8_t srpolicy_binding_sid_wire_flags(const srpolicy_binding_sid_t *binding_sid) {
    return binding_sid->flags & (SRPOLICY_BSID_FLAG_S | SRPOLICY_BSID_FLAG_I);
}

static int srpolicy_binding_sid_value_len(const srpolicy_binding_sid_t *binding_sid) {
    switch (binding_sid->type) {
        case SRPOLICY_BINDING_SID_NONE:
            return 2;
        case SRPOLICY_BINDING_SID_MPLS:
            return 6;
        case SRPOLICY_BINDING_SID_SRV6:
            return 18;
        default:
            return -1;
    }
}

static int srpolicy_binding_sid_valid(const srpolicy_binding_sid_t *binding_sid) {
    if (!binding_sid) {
        return 0;
    }
    if ((binding_sid->flags & ~(SRPOLICY_BSID_FLAG_S | SRPOLICY_BSID_FLAG_I)) != 0) {
        return 0;
    }

    switch (binding_sid->type) {
        case SRPOLICY_BINDING_SID_NONE:
            return 1;
        case SRPOLICY_BINDING_SID_MPLS:
            return binding_sid->mpls_label >= 16 &&
                   binding_sid->mpls_label <= 0xFFFFFU;
        case SRPOLICY_BINDING_SID_SRV6:
            return 1;
        default:
            return 0;
    }
}

static uint8_t srpolicy_srv6_binding_sid_wire_flags(const srpolicy_srv6_binding_sid_t *binding_sid) {
    return (binding_sid->flags & (SRPOLICY_BSID_FLAG_S | SRPOLICY_BSID_FLAG_I)) |
           (binding_sid->has_behavior ? SRPOLICY_SRV6_BSID_FLAG_B : 0);
}

static int srpolicy_srv6_binding_sid_value_len(const srpolicy_srv6_binding_sid_t *binding_sid) {
    return binding_sid->has_behavior ? 26 : 18;
}

static int srpolicy_validate_srv6_binding_sid_list(
    const srpolicy_srv6_binding_sid_t *binding_sids,
    int num_binding_sids) {
    if (num_binding_sids < 0) {
        return 0;
    }
    if (num_binding_sids > 0 && !binding_sids) {
        return 0;
    }

    for (int i = 0; i < num_binding_sids; i++) {
        const srpolicy_srv6_binding_sid_t *binding_sid = &binding_sids[i];

        if ((binding_sid->flags & ~(SRPOLICY_BSID_FLAG_S | SRPOLICY_BSID_FLAG_I)) != 0) {
            return 0;
        }
        if (binding_sid->has_behavior &&
            !srpolicy_srv6_behavior_valid(&binding_sid->behavior)) {
            return 0;
        }
    }

    return 1;
}

static uint8_t srpolicy_segment_wire_flags(const srpolicy_segment_t *segment) {
    return (segment->flags & SRPOLICY_SEGMENT_FLAG_V) |
           (segment->has_srv6_behavior ? SRPOLICY_SEGMENT_FLAG_B : 0);
}

static int srpolicy_segment_wire_size(const srpolicy_segment_t *segment) {
    if (!segment) {
        return -1;
    }

    if (segment->type == SR_SEGMENT_TYPE_MPLS) {
        return 8;
    }

    if (segment->type == SR_SEGMENT_TYPE_SRV6) {
        return segment->has_srv6_behavior ? 28 : 20;
    }

    return -1;
}

static int srpolicy_segment_list_value_len(const srpolicy_segment_list_t *segment_list) {
    int value_len = 1; /* Segment List sub-TLV reserved octet */

    if (!segment_list) {
        return -1;
    }

    value_len += 8; /* Weight sub-TLV */

    for (int i = 0; i < segment_list->num_segments; i++) {
        int seg_size = srpolicy_segment_wire_size(&segment_list->segments[i]);

        if (seg_size < 0) {
            return -1;
        }
        if (value_len > UINT16_MAX - seg_size) {
            return -1;
        }
        value_len += seg_size;
    }

    return value_len;
}

static int srpolicy_validate_segment_lists(const srpolicy_segment_list_t *segment_lists, int num_segment_lists) {
    if (num_segment_lists < 0) {
        return 0;
    }
    if (num_segment_lists > 0 && !segment_lists) {
        return 0;
    }

    for (int i = 0; i < num_segment_lists; i++) {
        const srpolicy_segment_list_t *list = &segment_lists[i];
        sr_segment_type_t              first_type;

        if (list->weight == 0 || list->num_segments < 0) {
            return 0;
        }
        if (list->num_segments > 0 && !list->segments) {
            return 0;
        }
        if (list->num_segments == 0) {
            continue;
        }

        first_type = list->segments[0].type;
        for (int j = 0; j < list->num_segments; j++) {
            const srpolicy_segment_t *seg = &list->segments[j];

            if (seg->type != first_type) {
                // TODO(FUZZ_GATE): Allow mixed SR-MPLS and SRv6 segment lists.
                return 0;
            }

            if ((seg->flags & ~SRPOLICY_SEGMENT_FLAG_V) != 0) {
                return 0;
            }

            if (seg->type == SR_SEGMENT_TYPE_MPLS) {
                sr_segment_t basic_segment = {0};
                uint32_t     label;

                basic_segment.type = seg->type;
                memcpy(basic_segment.sid, seg->sid, sizeof(basic_segment.sid));
                if (seg->has_srv6_behavior ||
                    srpolicy_decode_segment_mpls_label(&basic_segment, &label) < 0 ||
                    label < 16) {
                    // TODO(FUZZ_GATE): Allow reserved MPLS labels 0-15.
                    return 0;
                }
            } else if (seg->type == SR_SEGMENT_TYPE_SRV6) {
                if (seg->has_srv6_behavior &&
                    !srpolicy_srv6_behavior_valid(&seg->srv6_behavior)) {
                    return 0;
                }
            } else {
                // TODO(FUZZ_GATE): Allow unsupported segment types.
                return 0;
            }
        }
    }

    return 1;
}

static int srpolicy_name_subtlv_wire_size(const char *name) {
    size_t name_len;

    if (!name) {
        return 0;
    }

    name_len = strlen(name);
    if (name_len > 65534U) {
        return -1;
    }

    return (int)(1 + 2 + 1 + name_len);
}

static int srpolicy_encode_segment_lists(uint8_t *p,
                                         const srpolicy_segment_list_t *segment_lists,
                                         int num_segment_lists) {
    uint8_t *start = p;

    for (int i = 0; i < num_segment_lists; i++) {
        const srpolicy_segment_list_t *segment_list = &segment_lists[i];
        int                            sl_value_len = srpolicy_segment_list_value_len(segment_list);
        uint16_t                       sl_len = htons((uint16_t)sl_value_len);

        /*
         * TODO(WIRE_MUTATION): Corrupt Segment List sub-TLV header.
         *
         * DEEPEST NESTED FRAMING TARGET IN THE SR POLICY ENCODER
         *
         * Per RFC 9830 section 2.4.4 the Segment List sub-TLV is
         * [Type(1) | Length(2) | Reserved(1) | sub-TLVs(variable)],
         * where Type = 128 and Length is the byte count of the
         * sub-TLV payload (Weight + zero-or-more Segment sub-TLVs).
         *
         * Length is 2 bytes here (NOT 1) because RFC 9012 says type
         * codes >= 128 use a 2-octet length. This type-driven length
         * width is itself a fuzz opportunity: a decoder that caches
         * "all sub-TLVs are 1-byte length" would misframe here.
         *
         * Framing cascades:
         *
         *   - Corrupt Type (128 -> some other value):
         *       Decoder may now treat this as a 1-byte-length sub-TLV
         *       type. The next byte (which is actually the high byte
         *       of the 2-byte length) is read as the full length. The
         *       low byte of the length AND the reserved byte become
         *       part of the value. Cascades immediately.
         *       ** This is the type-vs-length-width trip-up you asked
         *       about: a wrong type byte changes how many bytes are
         *       read for the length field. **
         *
         *   - Shrink Length by N:
         *       Last N bytes of the Segment List payload (typically
         *       part of the final Segment sub-TLV) are read as
         *       "start of the next outer sub-TLV in the Tunnel
         *       Encapsulation attribute". Next outer-sub-TLV walk
         *       begins mid-segment.
         *
         *   - Grow Length by N:
         *       Next N bytes of whatever follows (another Segment
         *       List sub-TLV, or the attribute end) are absorbed as
         *       extra Segment sub-TLVs. Decoder parses N extra bytes
         *       as type/length pairs that don't align.
         *
         *   - Length = 0:
         *       Empty Segment List. RFC 9830 allows zero Segment
         *       sub-TLVs but implies at least the Weight sub-TLV
         *       should be present if declared. Tests "empty segment
         *       list" handling.
         *
         *   - Length > attribute remaining:
         *       Claims Segment List extends past end of parent
         *       Tunnel Encapsulation attribute. Cross-check bug.
         *
         *   - Reserved byte != 0:
         *       RFC says "MUST be set to zero on transmission and
         *       MUST be ignored on receipt". Corrupting tests whether
         *       a peer accidentally enforces or crashes.
         */
        *p++ = 128;
        memcpy(p, &sl_len, sizeof(sl_len));
        p += sizeof(sl_len);
        *p++ = 0;

        /*
         * TODO(WIRE_MUTATION): Corrupt Weight sub-TLV header.
         *
         * Per RFC 9830 section 2.4.4.1 Weight is [Type=9(1) |
         * Length=6(1) | Flags(1) | Reserved(1) | Weight(4)].
         * Length field is 1 byte because type < 128. Total sub-TLV
         * size on the wire is 2 + 6 = 8 bytes.
         *
         * Framing cascades:
         *
         *   - Length = 5 (shrink by 1):
         *       Decoder reads Flags, Reserved, and 3 of 4 Weight
         *       bytes as value; last Weight byte becomes the Type
         *       of the next Segment sub-TLV. Entire segment walk
         *       misaligns within this Segment List.
         *
         *   - Length = 7 (grow by 1):
         *       First byte of the next Segment sub-TLV's type is
         *       absorbed into Weight's value. Next segment walk
         *       hits wrong length.
         *
         *   - Length = 0:
         *       Zero-length Weight; decoder may treat as absent,
         *       or as an error. RFC 9830 says Weight is OPTIONAL
         *       inside Segment List; tests how "present but empty"
         *       is handled.
         *
         *   - Type = 0:
         *       Reserved/invalid sub-TLV type; tests unknown-type
         *       propagation (RFC 9012 section 2 requires unknown
         *       sub-TLVs be propagated).
         */
        *p++ = 9;
        *p++ = 6;
        *p++ = 0;
        *p++ = 0;
        uint32_t w_val = htonl(segment_list->weight);
        memcpy(p, &w_val, sizeof(w_val));
        p += sizeof(w_val);

        for (int j = 0; j < segment_list->num_segments; j++) {
            const srpolicy_segment_t *seg = &segment_list->segments[j];

            if (seg->type == SR_SEGMENT_TYPE_MPLS) {
                sr_segment_t basic_segment = {0};
                uint32_t     label;
                uint8_t      flags = srpolicy_segment_wire_flags(seg);

                basic_segment.type = seg->type;
                memcpy(basic_segment.sid, seg->sid, sizeof(basic_segment.sid));
                srpolicy_decode_segment_mpls_label(&basic_segment, &label);

                /*
                 * TODO(WIRE_MUTATION): Corrupt Segment Type A sub-TLV header.
                 *
                 * Per RFC 9830 section 2.4.4.2.1 Type A is [Type=1(1)
                 * | Length=6(1) | Flags(1) | Reserved(1) | Label(4)].
                 * The Label field holds the 20-bit MPLS label left-
                 * shifted into a 32-bit word.
                 *
                 * Framing cascades: same shape as Weight sub-TLV
                 * corruption above (one-byte length, shrink/grow by 1
                 * causes next Segment sub-TLV misalignment).
                 *
                 * Type-specific mutations:
                 *
                 *   - Swap Type 1 (Type A) <-> Type 13 (Type B):
                 *       Decoder tries to parse a 6-byte Type A
                 *       payload as a 18-or-26-byte Type B SID, or
                 *       vice versa. Length check may catch this, but
                 *       parsers that dispatch on type before checking
                 *       length will consume wrong amount.
                 *
                 *   - Flags: V bit corruption (RFC 9830 section
                 *       2.4.4.2.1 defines V for SID verification).
                 */
                *p++ = 1;
                *p++ = 6;
                *p++ = flags;
                *p++ = 0;
                srpolicy_encode_segment_type_a_label(p, label);
                p += 4;
            } else {
                uint8_t flags = srpolicy_segment_wire_flags(seg);

                /*
                 * TODO(WIRE_MUTATION): Corrupt Segment Type B sub-TLV header.
                 *
                 * Per RFC 9830 section 2.4.4.2.2 Type B is [Type=13(1)
                 * | Length(1) | Flags(1) | Reserved(1) | SID(16) |
                 * optional SRv6 Endpoint Behavior(8)]. Length is 18
                 * without behavior, 26 with behavior.
                 *
                 * Framing hazard specific to Type B:
                 *
                 *   - Length corruption between 18 and 26:
                 *       Decoder expecting no behavior reads 8 bytes
                 *       of the next sub-TLV as behavior structure, or
                 *       vice versa. Behavior parse result is
                 *       undefined garbage.
                 *
                 *   - Length = 16 (just the SID, no flags/reserved):
                 *       Tests whether decoder reads flags/reserved
                 *       before SID or after (spec says before, but
                 *       some parsers skip length validation).
                 *
                 * See the Type A marker above for the shared
                 * one-byte-length framing cascade taxonomy.
                 */
                *p++ = 13;
                *p++ = seg->has_srv6_behavior ? 26 : 18;
                *p++ = flags;
                *p++ = 0;
                memcpy(p, seg->sid, 16);
                p += 16;
                if (seg->has_srv6_behavior) {
                    /*
                     * TODO(WIRE_MUTATION): Corrupt SRv6 Endpoint Behavior bytes.
                     *
                     * Value-level. The behavior structure is a fixed
                     * 8-byte trailer containing endpoint behavior and
                     * SID structure. Not a framing hazard (length is
                     * already committed), but useful for testing
                     * per-behavior validation.
                     */
                    srpolicy_encode_srv6_behavior(p, &seg->srv6_behavior);
                    p += 8;
                }
            }
        }
    }

    return (int)(p - start);
}

/*
 * SR Policy Tunnel Encapsulation helper. It covers the RFC 9830 sub-TLV
 * surface:
 *   Preference
 *   Binding SID (none, SR-MPLS, or legacy SRv6 form)
 *   ENLP
 *   Priority
 *   SRv6 Binding SID sub-TLV(s)
 *   Candidate Path Name
 *   Policy Name
 *   Segment Lists with Type B optional behavior / structure blocks
 *
 * srpolicy_tunnel_encap_len() checks spec and measures the attribute value; srpolicy_tunnel_encap_write() writes
 * it. bgp_attr_create_tunnel_encap_srpolicy() writes it to a new attribute and
 * bgp_serialize_tunnel_encap_srpolicy_attr() to a caller buffer.
 */

/*
 * Return the value length (the 4-octet tunnel header and the sub-TLVs) and set *tunnel_value_len_out to the sub-TLV
 * length. Returns -1 when spec is not valid.
 */
static int srpolicy_tunnel_encap_len(const srpolicy_tunnel_encap_t *spec, int *tunnel_value_len_out) {
    size_t tunnel_value_len = 0;
    int    binding_sid_value_len = 0;
    int    candidate_name_wire_len;
    int    policy_name_wire_len;

    candidate_name_wire_len = srpolicy_name_subtlv_wire_size(spec->candidate_path_name);
    policy_name_wire_len = srpolicy_name_subtlv_wire_size(spec->policy_name);

    if ((spec->has_binding_sid &&
         !srpolicy_binding_sid_valid(&spec->binding_sid)) ||
        (spec->has_enlp && (spec->enlp < 1 || spec->enlp > 4)) ||
        !srpolicy_validate_srv6_binding_sid_list(spec->srv6_binding_sids, spec->num_srv6_binding_sids) ||
        !srpolicy_validate_segment_lists(spec->segment_lists, spec->num_segment_lists) ||
        candidate_name_wire_len < 0 ||
        policy_name_wire_len < 0) {
        // TODO(FUZZ_GATE): Bypass strict tunnel-encap pre-encode validation.
        return -1;
    }

    if (spec->has_preference) {
        tunnel_value_len += 8;
    }
    if (spec->has_binding_sid) {
        binding_sid_value_len = srpolicy_binding_sid_value_len(&spec->binding_sid);
        tunnel_value_len += 2 + binding_sid_value_len;
    }
    if (spec->has_enlp) {
        tunnel_value_len += 5;
    }
    if (spec->has_priority) {
        tunnel_value_len += 4;
    }
    for (int i = 0; i < spec->num_srv6_binding_sids; i++) {
        tunnel_value_len += 2 +
                            srpolicy_srv6_binding_sid_value_len(&spec->srv6_binding_sids[i]);
        if (tunnel_value_len > UINT16_MAX - 4U) {
            return -1;
        }
    }
    if (candidate_name_wire_len > 0) {
        tunnel_value_len += candidate_name_wire_len;
    }
    if (policy_name_wire_len > 0) {
        tunnel_value_len += policy_name_wire_len;
    }
    if (tunnel_value_len > UINT16_MAX - 4U) {
        return -1;
    }
    for (int i = 0; i < spec->num_segment_lists; i++) {
        int seg_list_value_len =
            srpolicy_segment_list_value_len(&spec->segment_lists[i]);

        if (seg_list_value_len < 0) {
            return -1;
        }
        tunnel_value_len += 3 + seg_list_value_len;
        if (tunnel_value_len > UINT16_MAX - 4U) {
            return -1;
        }
    }

    *tunnel_value_len_out = (int)tunnel_value_len;
    return 4 + (int)tunnel_value_len;
}

/*
 * Write the value that srpolicy_tunnel_encap_len() measured for spec at p. The Binding SID and name sub-TLV
 * lengths are measured again here; that is cheap, and it keeps the two functions with one shared argument.
 */
static void srpolicy_tunnel_encap_write(uint8_t *p, const srpolicy_tunnel_encap_t *spec, int tunnel_value_len) {
    int binding_sid_value_len =
        spec->has_binding_sid ? srpolicy_binding_sid_value_len(&spec->binding_sid) : 0;
    int candidate_name_wire_len = srpolicy_name_subtlv_wire_size(spec->candidate_path_name);
    int policy_name_wire_len = srpolicy_name_subtlv_wire_size(spec->policy_name);

    // TODO(WIRE_MUTATION): Corrupt Tunnel Type after encode.
    uint16_t tunnel_type = htons(15);
    memcpy(p, &tunnel_type, 2);
    p += 2;

    // TODO(WIRE_MUTATION): Corrupt Tunnel Length after encode.
    uint16_t tunnel_len = htons((uint16_t)tunnel_value_len);
    memcpy(p, &tunnel_len, 2);
    p += 2;

    if (spec->has_preference) {
        // TODO(WIRE_MUTATION): Corrupt Preference type/length/flags/reserved/value.
        *p++ = 12;
        *p++ = 6;
        *p++ = 0;
        *p++ = 0;
        uint32_t pref_val = htonl(spec->preference);
        memcpy(p, &pref_val, sizeof(pref_val));
        p += sizeof(pref_val);
    }

    if (spec->has_binding_sid) {
        const srpolicy_binding_sid_t *binding_sid = &spec->binding_sid;

        // TODO(WIRE_MUTATION): Corrupt Binding SID type/length/flags/reserved/value.
        *p++ = 13;
        *p++ = (uint8_t)binding_sid_value_len;
        *p++ = srpolicy_binding_sid_wire_flags(binding_sid);
        *p++ = 0;
        if (binding_sid->type == SRPOLICY_BINDING_SID_MPLS) {
            srpolicy_encode_binding_sid_label(p, binding_sid->mpls_label);
            p += 4;
        } else if (binding_sid->type == SRPOLICY_BINDING_SID_SRV6) {
            memcpy(p, binding_sid->srv6_sid, 16);
            p += 16;
        }
    }

    if (spec->has_enlp) {
        // TODO(WIRE_MUTATION): Corrupt ENLP type/length/flags/reserved/value.
        *p++ = 14;
        *p++ = 3;
        *p++ = 0;
        *p++ = 0;
        *p++ = spec->enlp;
    }

    if (spec->has_priority) {
        // TODO(WIRE_MUTATION): Corrupt Priority type/length/value/reserved.
        *p++ = 15;
        *p++ = 2;
        *p++ = spec->priority;
        *p++ = 0;
    }

    for (int i = 0; i < spec->num_srv6_binding_sids; i++) {
        const srpolicy_srv6_binding_sid_t *binding_sid =
            &spec->srv6_binding_sids[i];
        int value_len = srpolicy_srv6_binding_sid_value_len(binding_sid);

        // TODO(WIRE_MUTATION): Corrupt SRv6 Binding SID type/length/flags/reserved/SID.
        *p++ = 20;
        *p++ = (uint8_t)value_len;
        *p++ = srpolicy_srv6_binding_sid_wire_flags(binding_sid);
        *p++ = 0;
        memcpy(p, binding_sid->sid, 16);
        p += 16;
        if (binding_sid->has_behavior) {
            // TODO(WIRE_MUTATION): Corrupt SRv6 Binding SID behavior/structure bytes.
            srpolicy_encode_srv6_behavior(p, &binding_sid->behavior);
            p += 8;
        }
    }

    if (candidate_name_wire_len > 0) {
        size_t   candidate_name_len = strlen(spec->candidate_path_name);
        uint16_t candidate_len = htons((uint16_t)(candidate_name_len + 1));

        // TODO(WIRE_MUTATION): Corrupt Candidate Path Name type/length/reserved/name bytes.
        *p++ = 129;
        memcpy(p, &candidate_len, sizeof(candidate_len));
        p += sizeof(candidate_len);
        *p++ = 0;
        memcpy(p, spec->candidate_path_name, candidate_name_len);
        p += candidate_name_len;
    }

    if (policy_name_wire_len > 0) {
        size_t   policy_name_len = strlen(spec->policy_name);
        uint16_t policy_len = htons((uint16_t)(policy_name_len + 1));

        // TODO(WIRE_MUTATION): Corrupt Policy Name type/length/reserved/name bytes.
        *p++ = 130;
        memcpy(p, &policy_len, sizeof(policy_len));
        p += sizeof(policy_len);
        *p++ = 0;
        memcpy(p, spec->policy_name, policy_name_len);
        p += policy_name_len;
    }

    srpolicy_encode_segment_lists(p, spec->segment_lists, spec->num_segment_lists);
}

bgp_path_attr_t* bgp_attr_create_tunnel_encap_srpolicy(const srpolicy_tunnel_encap_t *spec) {
    bgp_path_attr_t *attr;
    int              tunnel_value_len;
    int              total_len;

    if (!spec) {
        return NULL;
    }

    total_len = srpolicy_tunnel_encap_len(spec, &tunnel_value_len);
    if (total_len < 0 || total_len > UINT16_MAX) {
        return NULL;
    }

    attr = bgp_attr_alloc(BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANSITIVE, BGP_ATTR_TUNNEL_ENCAP,
                          (uint16_t)total_len);
    if (!attr) {
        return NULL;
    }

    srpolicy_tunnel_encap_write(attr->value, spec, tunnel_value_len);
    return attr;
}

int bgp_serialize_tunnel_encap_srpolicy_attr(uint8_t *buffer, size_t capacity, const srpolicy_tunnel_encap_t *spec) {
    const uint8_t flags = BGP_ATTR_FLAG_OPTIONAL | BGP_ATTR_FLAG_TRANSITIVE;
    int           tunnel_value_len;
    int           total_len;
    int           attr_len;
    int           header_len;

    if (!spec) {
        return -1;
    }

    // The attribute length field has 16 bits.
    total_len = srpolicy_tunnel_encap_len(spec, &tunnel_value_len);
    if (total_len < 0 || total_len > UINT16_MAX) {
        return -1;
    }

    attr_len = bgp_marshaled_attr_size(flags, (uint16_t)total_len);
    if ((size_t)attr_len > capacity) {
        return -1;
    }

    /*
     * With a NULL value, bgp_serialize_raw_path_attr() writes only the header (3 or 4 octets, with the Extended
     * Length flag when the value is longer than 255 octets). The value goes after it.
     */
    header_len = attr_len - total_len;
    bgp_serialize_raw_path_attr(buffer, flags, BGP_ATTR_TUNNEL_ENCAP, (uint16_t)total_len, NULL);
    srpolicy_tunnel_encap_write(buffer + header_len, spec, tunnel_value_len);
    return attr_len;
}

// MP-BGP Attribute Helpers

DEFINE_ADD_PATH_DETECTOR(bgp_detect_srpolicy_add_path, srpolicy_nlri_list_t, do { } while (0))

static int bgp_srpolicy_list_matches_afi(const srpolicy_nlri_list_t *list, uint16_t nlri_afi) {
    const srpolicy_nlri_list_t *curr = list;

    while (curr) {
        if ((uint16_t)curr->prefix.endpoint_af != nlri_afi) {
            return 0;
        }
        curr = curr->next;
    }

    return 1;
}

static int bgp_encode_srpolicy_nlri(uint8_t *buffer, const srpolicy_nlri_list_t *nlri, int add_path) {
    int offset = 0;

    if (add_path) {
        uint32_t path_id_net = htonl(nlri->path_id);

        memcpy(buffer + offset, &path_id_net, sizeof(path_id_net));
        offset += sizeof(path_id_net);
    }

    int len = bgp_encode_srpolicy_prefix(buffer + offset, (srpolicy_prefix_t *)&nlri->prefix);
    return len < 0 ? -1 : offset + len;
}

static int encode_srpolicy_chunk(srpolicy_nlri_list_t **cursor, uint8_t *buffer, int max_bytes, int add_path) {
    int written = 0;

    while (*cursor) {
        int endpoint_len = ((*cursor)->prefix.endpoint_af == AFI_IPV6) ? 16 : 4;
        int needed = 1 + 4 + 4 + endpoint_len;  /* len + dist + color + endpoint */

        if ((int)(*cursor)->add_path != add_path) {
            return -1;
        }
        if (add_path) {
            needed += 4;
        }

        if (written + needed > max_bytes) {
            return (written > 0) ? written : -1;
        }

        int encoded = bgp_encode_srpolicy_nlri(buffer + written, *cursor, add_path);
        if (encoded < 0) return -1;
        written += encoded;
        *cursor = (*cursor)->next;
    }

    return written;
}

// MESSAGE GENERATION with splitting support

bgp_update_result_t* bgp_generate_update_srpolicy(
    srpolicy_nlri_list_t *nlri_list,
    bgp_path_attr_t *attributes,
    srpolicy_nlri_list_t *withdrawn_list,
    uint16_t max_pdu_size,
    uint16_t nlri_afi,
    const bgp_next_hop_t *next_hop)
{
    bgp_builder_t         builder = {0};
    uint8_t              *base_attr_data = NULL;
    uint16_t              base_attr_len = 0;
    uint8_t              *nlri_buffer = NULL;
    uint8_t               nh_buf[BGP_STANDARD_NEXT_HOP_BUF_SIZE];
    uint8_t               nh_len = 0;
    int                   available_space;
    int                   nlri_add_path = 0;
    int                   withdrawn_add_path = 0;
    srpolicy_nlri_list_t *curr;

    if (nlri_afi != AFI_IPV4 && nlri_afi != AFI_IPV6) {
        return NULL;
    }
    /*
     * Strict mode keeps the MP_REACH/MP_UNREACH AFI aligned with the
     * endpoint AF encoded inside each SR Policy NLRI. If we later add a
     * protocol-fuzz profile, this is one of the checks that can be made
     * conditional rather than unconditional.
     */
    // TODO(FUZZ_GATE): Allow explicit AFI / endpoint-family mismatch.
    if (!bgp_srpolicy_list_matches_afi(nlri_list, nlri_afi) ||
        !bgp_srpolicy_list_matches_afi(withdrawn_list, nlri_afi)) {
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

    if (bgp_detect_srpolicy_add_path(nlri_list, &nlri_add_path) < 0 ||
        bgp_detect_srpolicy_add_path(withdrawn_list, &withdrawn_add_path) < 0) {
        return NULL;
    }

    if (bgp_serialize_path_attributes_alloc(attributes,
                                            &base_attr_data,
                                            &base_attr_len) < 0) {
        return NULL;
    }

    if (nlri_list) {
        if (!bgp_validate_mp_attrs(attributes) ||
            bgp_encode_srpolicy_next_hop(next_hop,
                                         nh_buf,
                                         &nh_len) < 0) {
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
            int nlri_len = encode_srpolicy_chunk(&curr, nlri_buffer, available_space, withdrawn_add_path);
            if (nlri_len <= 0 ||
                bgp_builder_append_mp(&builder, &(bgp_mp_args_t){
                    .afi         = nlri_afi,
                    .safi        = SAFI_SR_POLICY,
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
            int nlri_len = encode_srpolicy_chunk(&curr, nlri_buffer, available_space, nlri_add_path);
            if (nlri_len <= 0 ||
                bgp_builder_append_mp(&builder, &(bgp_mp_args_t){
                    .attrs       = base_attr_data,
                    .attrs_len   = base_attr_len,
                    .is_reach    = 1,
                    .afi         = nlri_afi,
                    .safi        = SAFI_SR_POLICY,
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
