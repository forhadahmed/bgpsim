/*
 * BGP UPDATE Message Generation - EVPN Types 1-5
 * Implements Ethernet Auto-Discovery, MAC/IP Advertisement,
 * Inclusive Multicast, Ethernet Segment, and IP Prefix route types
 * (RFC 7432 and RFC 9136).
 */

#define OUTPUT_STDIO_REMAP

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "bgp.h"
#include "output.h"
#include "bgp_update.h"

/*
 * Encode an EVPN label field (3 bytes). With an MPLS encapsulation it is an MPLS label (RFC 7432); with VXLAN, NVGRE
 * and other IP-based encapsulations it carries the 24-bit VNI itself, high-order octet first (RFC 8365 section 5.1.3).
 */
static void encode_evpn_label(uint8_t *buffer, const mpls_label_t *label, int vni) {
    if (!vni) {
        bgp_encode_mpls_label(buffer, label);
        return;
    }
    buffer[0] = (uint8_t)(label->label >> 16);
    buffer[1] = (uint8_t)(label->label >> 8);
    buffer[2] = (uint8_t)label->label;
}

static int evpn_type2_ip_length_valid(uint8_t ip_addr_len) {
    return ip_addr_len == 0 || ip_addr_len == 32 || ip_addr_len == 128;
}

static int evpn_single_flag_bit_only(uint8_t flags) {
    return (flags & ~0x01u) == 0;
}

static int evpn_router_mac_invalid(const uint8_t router_mac[6]) {
    int all_ones = 1;

    if (!router_mac) {
        return 1;
    }

    /*
     * RFC 9136 treats broadcast or multicast MAC encodings as invalid when a
     * Router's MAC EC is used as RT-5 overlay-index input. The helper keeps
     * those obviously invalid encodings out of the strict path.
     */
    if ((router_mac[0] & 0x01u) != 0) {
        return 1;
    }

    for (int i = 0; i < 6; i++) {
        if (router_mac[i] != 0xFFu) {
            all_ones = 0;
            break;
        }
    }

    return all_ones;
}

// EVPN Type 1 - Ethernet Auto-Discovery

static evpn_type1_nlri_t* evpn_type1_nlri_create_internal(
    route_distinguisher_t rd,
    evpn_esi_t esi,
    uint32_t ethernet_tag_id,
    uint32_t label,
    int add_path,
    uint32_t path_id) {
    evpn_type1_nlri_t *nlri = calloc(1, sizeof(evpn_type1_nlri_t));

    if (!nlri) {
        return NULL;
    }

    nlri->prefix.route_type = EVPN_RT_ETHERNET_AUTO_DISCOVERY;
    nlri->prefix.rd = rd;
    nlri->prefix.esi = esi;
    nlri->prefix.ethernet_tag_id = ethernet_tag_id;
    nlri->prefix.label.label = label;
    nlri->prefix.label.tc = 0;
    nlri->prefix.label.s = 1;
    nlri->prefix.label.ttl = 0;

    nlri->path_id = path_id;
    nlri->add_path = (uint8_t)(add_path ? 1 : 0);
    nlri->next = NULL;
    return nlri;
}

evpn_type1_nlri_t* evpn_type1_nlri_create(
    route_distinguisher_t rd,
    evpn_esi_t esi,
    uint32_t ethernet_tag_id,
    uint32_t label) {
    return evpn_type1_nlri_create_internal(rd, esi, ethernet_tag_id, label, 0, 0);
}

evpn_type1_nlri_t* evpn_type1_nlri_create_path_id(
    route_distinguisher_t rd,
    evpn_esi_t esi,
    uint32_t ethernet_tag_id,
    uint32_t label,
    uint32_t path_id) {
    return evpn_type1_nlri_create_internal(rd, esi, ethernet_tag_id, label, 1, path_id);
}

DEFINE_NLRI_LIST_UTILS(evpn_type1_nlri_t, evpn_type1_nlri)

int bgp_encode_evpn_type1_prefix(uint8_t *buffer, evpn_type1_prefix_t *prefix) {
    int offset = 0;
    if (!buffer || !prefix || prefix->route_type != EVPN_RT_ETHERNET_AUTO_DISCOVERY ||
        prefix->rd.type > 2 || prefix->label.label > (prefix->label_vni ? 0xFFFFFFU : 0xFFFFFU)) return -1;

    // Route Type
    // TODO(WIRE_MUTATION): Corrupt EVPN Type 1 route type after encode.
    buffer[offset++] = prefix->route_type;

    // Length (placeholder)
    int length_offset = offset;

    offset++;

    // RD (8 bytes)
    bgp_encode_rd(buffer + offset, &prefix->rd);
    offset += 8;

    // ESI (10 bytes)
    buffer[offset++] = prefix->esi.type;
    memcpy(buffer + offset, prefix->esi.value, 9);
    offset += 9;

    // Ethernet Tag ID (4 bytes)
    uint32_t tag_net = htonl(prefix->ethernet_tag_id);

    memcpy(buffer + offset, &tag_net, 4);
    offset += 4;

    // MPLS Label or VNI (3 bytes)
    encode_evpn_label(buffer + offset, &prefix->label, prefix->label_vni);
    offset += 3;

    // Fill in length: everything after route_type and length byte
    // TODO(WIRE_MUTATION): Corrupt EVPN Type 1 route-length after encode.
    buffer[length_offset] = offset - length_offset - 1;

    return offset;
}

// EVPN Type 2 - MAC/IP Advertisement

static evpn_type2_nlri_t* evpn_type2_nlri_create_internal(
    route_distinguisher_t rd,
    evpn_esi_t esi,
    uint32_t ethernet_tag_id,
    const uint8_t *mac_addr,
    uint8_t ip_addr_len,
    const uint8_t *ip_addr_bytes,
    uint32_t label1,
    int add_path,
    uint32_t path_id) {
    evpn_type2_nlri_t *nlri = calloc(1, sizeof(evpn_type2_nlri_t));

    if (!nlri) {
        return NULL;
    }

    nlri->prefix.route_type = EVPN_RT_MAC_IP_ADVERTISEMENT;
    nlri->prefix.rd = rd;
    nlri->prefix.esi = esi;
    nlri->prefix.ethernet_tag_id = ethernet_tag_id;

    if (mac_addr) {
        memcpy(nlri->prefix.mac_addr, mac_addr, 6);
    } else {
        memset(nlri->prefix.mac_addr, 0, 6);
    }

    nlri->prefix.ip_addr_len = ip_addr_len;
    memset(nlri->prefix.ip_addr, 0, 16);
    if (ip_addr_bytes && ip_addr_len > 0) {
        int ip_bytes = (ip_addr_len == 128) ? 16 : 4;

        memcpy(nlri->prefix.ip_addr, ip_addr_bytes, ip_bytes);
    }

    nlri->prefix.label1.label = label1;
    nlri->prefix.label1.tc = 0;
    nlri->prefix.label1.s = 1;
    nlri->prefix.label1.ttl = 0;

    nlri->prefix.has_label2 = 0;
    nlri->prefix.label2.label = 0;
    nlri->prefix.label2.tc = 0;
    nlri->prefix.label2.s = 1;
    nlri->prefix.label2.ttl = 0;

    nlri->path_id = path_id;
    nlri->add_path = (uint8_t)(add_path ? 1 : 0);
    nlri->next = NULL;
    return nlri;
}

evpn_type2_nlri_t* evpn_type2_nlri_create_ipv4(
    route_distinguisher_t rd,
    evpn_esi_t esi,
    uint32_t ethernet_tag_id,
    const uint8_t *mac_addr,
    const char *ip_addr,
    uint32_t label1) {
    uint8_t ip_bytes[16];

    memset(ip_bytes, 0, 16);
    if (ip_addr && inet_pton(AF_INET, ip_addr, ip_bytes) != 1) {
        return NULL;
    }
    return evpn_type2_nlri_create_internal(rd, esi, ethernet_tag_id,
                                           mac_addr,
                                           ip_addr ? 32 : 0,
                                           ip_addr ? ip_bytes : NULL,
                                           label1, 0, 0);
}

evpn_type2_nlri_t* evpn_type2_nlri_create_ipv4_path_id(
    route_distinguisher_t rd,
    evpn_esi_t esi,
    uint32_t ethernet_tag_id,
    const uint8_t *mac_addr,
    const char *ip_addr,
    uint32_t label1,
    uint32_t path_id) {
    uint8_t ip_bytes[16];

    memset(ip_bytes, 0, 16);
    if (ip_addr && inet_pton(AF_INET, ip_addr, ip_bytes) != 1) {
        return NULL;
    }
    return evpn_type2_nlri_create_internal(rd, esi, ethernet_tag_id,
                                           mac_addr,
                                           ip_addr ? 32 : 0,
                                           ip_addr ? ip_bytes : NULL,
                                           label1, 1, path_id);
}

evpn_type2_nlri_t* evpn_type2_nlri_create_ipv6(
    route_distinguisher_t rd,
    evpn_esi_t esi,
    uint32_t ethernet_tag_id,
    const uint8_t *mac_addr,
    const char *ip_addr,
    uint32_t label1) {
    uint8_t ip_bytes[16];

    memset(ip_bytes, 0, 16);
    if (ip_addr && inet_pton(AF_INET6, ip_addr, ip_bytes) != 1) {
        return NULL;
    }
    return evpn_type2_nlri_create_internal(rd, esi, ethernet_tag_id,
                                           mac_addr,
                                           ip_addr ? 128 : 0,
                                           ip_addr ? ip_bytes : NULL,
                                           label1, 0, 0);
}

evpn_type2_nlri_t* evpn_type2_nlri_create_ipv6_path_id(
    route_distinguisher_t rd,
    evpn_esi_t esi,
    uint32_t ethernet_tag_id,
    const uint8_t *mac_addr,
    const char *ip_addr,
    uint32_t label1,
    uint32_t path_id) {
    uint8_t ip_bytes[16];

    memset(ip_bytes, 0, 16);
    if (ip_addr && inet_pton(AF_INET6, ip_addr, ip_bytes) != 1) {
        return NULL;
    }
    return evpn_type2_nlri_create_internal(rd, esi, ethernet_tag_id,
                                           mac_addr,
                                           ip_addr ? 128 : 0,
                                           ip_addr ? ip_bytes : NULL,
                                           label1, 1, path_id);
}

evpn_type2_nlri_t* evpn_type2_nlri_create_mac_only(
    route_distinguisher_t rd,
    evpn_esi_t esi,
    uint32_t ethernet_tag_id,
    const uint8_t *mac_addr,
    uint32_t label1) {
    return evpn_type2_nlri_create_internal(rd, esi, ethernet_tag_id, mac_addr, 0, NULL, label1, 0, 0);
}

evpn_type2_nlri_t* evpn_type2_nlri_create_mac_only_path_id(
    route_distinguisher_t rd,
    evpn_esi_t esi,
    uint32_t ethernet_tag_id,
    const uint8_t *mac_addr,
    uint32_t label1,
    uint32_t path_id) {
    return evpn_type2_nlri_create_internal(rd, esi, ethernet_tag_id, mac_addr, 0, NULL, label1, 1, path_id);
}

void evpn_type2_nlri_set_label2(evpn_type2_nlri_t *nlri, uint32_t label2) {
    if (!nlri) {
        return;
    }
    nlri->prefix.has_label2 = 1;
    nlri->prefix.label2.label = label2;
    nlri->prefix.label2.tc = 0;
    nlri->prefix.label2.s = 1;
    nlri->prefix.label2.ttl = 0;
}

DEFINE_NLRI_LIST_UTILS(evpn_type2_nlri_t, evpn_type2_nlri)

int bgp_encode_evpn_type2_prefix(uint8_t *buffer, evpn_type2_prefix_t *prefix) {
    if (!buffer || !prefix || prefix->route_type != EVPN_RT_MAC_IP_ADVERTISEMENT || prefix->rd.type > 2) return -1;
    uint32_t label_max = prefix->label_vni ? 0xFFFFFFU : 0xFFFFFU;
    int      offset = 0;

    if (!evpn_type2_ip_length_valid(prefix->ip_addr_len)) {
        /*
         * TODO(FUZZ_GATE): Allow non-standard EVPN Type 2 IP address lengths.
         *
         * RFC 7432 section 7.2 mandates IP address length ∈ {0, 32,
         * 128} bits for EVPN Type 2: 0 = no IP, 32 = IPv4, 128 =
         * IPv6. Any other value is malformed per the spec.
         *
         * The strict encoder rejects at the typed level (before
         * wire bytes are written). A fuzz policy may allow this
         * gate to produce nonstandard values like 40, 48, 64 that
         * test the receiver's length validation. These are the
         * SEMANTIC counterpart to the WIRE_MUTATION of the IP
         * length byte: this gate emits the bad value from a typed
         * route model, while the wire mutation patches it post-
         * encode from a strict route model.
         *
         * The difference matters: semantic relaxation produces a
         * self-consistent (but spec-violating) NLRI where the IP
         * bytes actually match the declared length. Wire mutation
         * produces an inconsistent NLRI where declared length and
         * actual bytes disagree. Different bug classes.
         *
         * Useful values to relax to: 40, 48, 56, 64 (odd), 16 (too
         * small for any IP), 160 (larger than max).
         *
         * Proposed allow key: "evpn.type2.ip-length-nonstandard"
         */
        return -1;
    }
    if (prefix->label1.label > label_max) {
        /*
         * TODO(FUZZ_GATE): Allow EVPN Type 2 Label1 > 20 bits.
         *
         * MPLS labels are 20-bit values (RFC 3032); a VNI is 24 bits (RFC 8365). The encoder
         * masks with 0xFFFFF when writing to the wire, so a value
         * > 0xFFFFF would be silently truncated if this gate didn't
         * reject it.
         *
         * For fuzz, the interesting case isn't the truncated
         * write (already safe) but the POLICY question: some
         * implementations might treat out-of-range label values
         * as a session error rather than silently masking. By
         * allowing this gate and letting the encoder mask the
         * value, the generated UPDATE appears valid on the wire
         * but its source route config was semantically invalid.
         *
         * A more interesting wire mutation is to directly corrupt
         * the 3-byte label entry to place bits outside the 20-bit
         * label field (i.e. overlap the TC or S bit positions).
         * That's the companion WIRE_MUTATION marker on
         * bgp_encode_mpls_label().
         *
         * Proposed allow key: "evpn.type2.label-overflow"
         */
        return -1;
    }
    if (prefix->has_label2 && prefix->label2.label > label_max) {
        /*
         * TODO(FUZZ_GATE): Allow EVPN Type 2 Label2 > 20 bits.
         *
         * Same rationale as the Label1 gate above. See that marker
         * for context and proposed allow key pattern.
         */
        return -1;
    }

    // Route Type
    /*
     * TODO(WIRE_MUTATION): Corrupt the 1-byte EVPN route type.
     *
     * Per RFC 7432 section 7.2 each EVPN NLRI is [route_type(1) |
     * length(1) | route-type-specific(variable)]. Route type 2 is
     * MAC/IP advertisement. Valid types in the original spec are
     * 1..4; RFC 9136 adds type 5 (IP prefix), and IANA has assigned
     * further types (6..11) for later features.
     *
     * Useful mutations:
     *
     *   - Unknown type (e.g. 0xFF):
     *       Tests RFC 7432 section 11 "a BGP speaker that does not
     *       recognize a route type MUST consider the route
     *       malformed". Mutating type=2 to type=0xFF while keeping
     *       the route-specific fields unchanged tests whether the
     *       peer honors the length field and skips the whole NLRI
     *       cleanly, or tries to parse it as the original type
     *       anyway.
     *
     *   - Swap to a defined but different type (e.g. 2 -> 5):
     *       Decoder tries to parse MAC/IP payload as IP Prefix,
     *       producing field-interpretation errors (MAC bytes as
     *       ESI, ethernet-tag as IP prefix length, etc). Classic
     *       "type/length-matched field confusion".
     *
     *   - Type = 0:
     *       Reserved; tests reserved-value handling.
     */
    buffer[offset++] = prefix->route_type;

    // Length (placeholder)
    int length_offset = offset;

    offset++;

    // RD (8 bytes)
    bgp_encode_rd(buffer + offset, &prefix->rd);
    offset += 8;
    // TODO(WIRE_MUTATION): Corrupt EVPN Type 2 RD bytes after encode.

    // ESI (10 bytes)
    buffer[offset++] = prefix->esi.type;
    memcpy(buffer + offset, prefix->esi.value, 9);
    offset += 9;
    // TODO(WIRE_MUTATION): Corrupt EVPN Type 2 ESI type/value after encode.

    // Ethernet Tag ID (4 bytes)
    uint32_t tag_net = htonl(prefix->ethernet_tag_id);

    memcpy(buffer + offset, &tag_net, 4);
    offset += 4;
    // TODO(WIRE_MUTATION): Corrupt EVPN Type 2 Ethernet Tag ID after encode.

    /*
     * RFC 7432 Type 2 always carries a 48-bit MAC length here. The helper
     * keeps that strict and lets fuzzing mutate the field afterward.
     */
    /*
     * TODO(WIRE_MUTATION): Corrupt the 1-byte EVPN Type 2 MAC length.
     *
     * INTERNAL FRAMING HAZARD
     *
     * Per RFC 7432 section 7.2 this byte MUST be 48 (bits). A wrong
     * value shifts everything that follows within the route:
     *   - MAC bytes (always 6 on the wire)
     *   - IP length byte
     *   - IP bytes
     *   - Label1
     *   - optional Label2
     *
     * The outer route-length field still says "this route is N
     * bytes total", so a MAC length mismatch produces a parser
     * that walks off the end of the route body before reaching the
     * next EVPN NLRI. Depending on the decoder, either the current
     * route is marked malformed (safe) or the next route's header
     * is read from inside the current route body (unsafe cascade).
     *
     * Useful mutations:
     *   - 32: claims 4-byte MAC. Decoder reads 4 bytes as MAC, then
     *     IP length byte lands on MAC byte 5, cascade
     *   - 64: claims 8-byte MAC, reads 2 bytes of IP length region
     *     as MAC suffix
     *   - 0: zero-length MAC, decoder may skip MAC entirely
     *   - 255: absurd value, exceeds route body
     */
    buffer[offset++] = 48;

    // MAC Address (6 bytes)
    memcpy(buffer + offset, prefix->mac_addr, 6);
    offset += 6;
    /*
     * TODO(WIRE_MUTATION): Corrupt the 6-byte EVPN Type 2 MAC address.
     *
     * Value-level. Interesting for policy tests: reserved ranges
     * (broadcast FF:FF:FF:FF:FF:FF, multicast high bit, zero MAC),
     * locally-administered bit flip, IANA reserved ranges.
     */

    // IP Address Length (1 byte: 0, 32, or 128)
    /*
     * TODO(WIRE_MUTATION): Corrupt the 1-byte EVPN Type 2 IP address length.
     *
     * INTERNAL FRAMING HAZARD
     *
     * Per RFC 7432 section 7.2 this MUST be 0, 32, or 128 (bits).
     * Decoder uses this to know whether 0, 4, or 16 IP bytes
     * follow. Wrong value cascades within the route:
     *
     *   - Set to 32 when strict was 0: decoder reads 4 bytes of
     *     what's actually Label1 as an IPv4 address, then Label1
     *     parse consumes what would have been optional Label2 bytes,
     *     which may or may not exist depending on has_label2
     *   - Set to 0 when strict was 32: decoder skips IP bytes and
     *     reads the 4 IP bytes as Label1 (which occupies 3 of them)
     *     plus one extra byte that shifts everything
     *   - Set to 128 when strict was 32: decoder reads 16 bytes
     *     (IP + Label1 + some of Label2) as IPv6 address
     *   - Nonstandard values (e.g. 40, 64): decoder behavior is
     *     undefined; some parsers accept and walk by prefix_len/8
     *     bytes, others reject
     *
     * This is one of the most subtle EVPN Type 2 fuzz targets
     * because the outer route length masks the misalignment until
     * the decoder tries to match Label1 expectations.
     */
    buffer[offset++] = prefix->ip_addr_len;

    // IP Address (variable: 0, 4, or 16 bytes)
    if (prefix->ip_addr_len == 32) {
        memcpy(buffer + offset, prefix->ip_addr, 4);
        offset += 4;
        // TODO(WIRE_MUTATION): Corrupt EVPN Type 2 IPv4 address bytes after encode.
    } else if (prefix->ip_addr_len == 128) {
        memcpy(buffer + offset, prefix->ip_addr, 16);
        offset += 16;
        // TODO(WIRE_MUTATION): Corrupt EVPN Type 2 IPv6 address bytes after encode.
    }

    /*
     * RFC 7432 names the two optional label fields in Type 2 as Label1 and
     * Label2, so the code keeps that vocabulary to match the on-wire layout.
     */
    // MPLS Label1 or VNI (3 bytes)
    encode_evpn_label(buffer + offset, &prefix->label1, prefix->label_vni);
    offset += 3;
    // TODO(WIRE_MUTATION): Corrupt EVPN Type 2 Label1 after encode.

    // MPLS Label2 or VNI (0 or 3 bytes)
    if (prefix->has_label2) {
        encode_evpn_label(buffer + offset, &prefix->label2, prefix->label_vni);
        offset += 3;
        // TODO(WIRE_MUTATION): Corrupt EVPN Type 2 optional Label2 after encode.
    }

    // Fill in length
    /*
     * TODO(WIRE_MUTATION): Corrupt the 1-byte EVPN Type 2 route length.
     *
     * HIGHEST FRAMING VALUE in the EVPN encoder
     *
     * Per RFC 7432 section 7.2 this byte indicates the length in
     * octets of the route-type-specific portion of the EVPN NLRI.
     * The decoder uses it to skip to the next EVPN NLRI in the
     * MP_REACH/MP_UNREACH NLRI list.
     *
     * Classic TLV-length cascade: wrong value here shifts the start
     * of the NEXT EVPN route. The next route's route_type byte is
     * actually the last byte of this route's body (or a byte that
     * should have been part of the next route's body).
     *
     * Useful mutations:
     *
     *   - Shrink by 1-2:
     *       Last bytes of this route (usually Label1 or Label2)
     *       become the route_type and length of "the next route".
     *       Cascades to end of NLRI list.
     *
     *   - Grow by 1-2:
     *       Next route's route_type byte is absorbed into this
     *       route's trailing bytes. Next-route parse starts with
     *       a byte that was supposed to be its length.
     *
     *   - Set to 0:
     *       Zero-length route. RFC says length covers variable
     *       route-type-specific portion, which for Type 2 has a
     *       minimum size (RD+ESI+EthTag+MACLen+MAC+IPLen = 30
     *       bytes). Shrinking to 0 or below minimum tests whether
     *       the peer validates length against a per-type minimum.
     *
     *   - Set to 255:
     *       Maximum value; tests range enforcement against outer
     *       MP_REACH NLRI length.
     *
     * In a fuzz run targeting EVPN parsers, this route-length
     * corruption should be tried in combination with MP_REACH's
     * nh_len corruption to find two-level cascade bugs.
     */
    buffer[length_offset] = offset - length_offset - 1;

    return offset;
}

// EVPN Type 3 - Inclusive Multicast Ethernet Tag

static evpn_type3_nlri_t* evpn_type3_nlri_create_internal(
    route_distinguisher_t rd,
    uint32_t ethernet_tag_id,
    uint8_t ip_addr_len,
    const uint8_t *orig_router_ip,
    int add_path,
    uint32_t path_id) {
    evpn_type3_nlri_t *nlri = calloc(1, sizeof(evpn_type3_nlri_t));

    if (!nlri) {
        return NULL;
    }

    nlri->prefix.route_type = EVPN_RT_INCLUSIVE_MULTICAST;
    nlri->prefix.rd = rd;
    nlri->prefix.ethernet_tag_id = ethernet_tag_id;
    nlri->prefix.ip_addr_len = ip_addr_len;
    memset(nlri->prefix.orig_router_ip, 0, 16);
    if (orig_router_ip) {
        int ip_bytes = (ip_addr_len == 128) ? 16 : 4;

        memcpy(nlri->prefix.orig_router_ip, orig_router_ip, ip_bytes);
    }

    nlri->path_id = path_id;
    nlri->add_path = (uint8_t)(add_path ? 1 : 0);
    nlri->next = NULL;
    return nlri;
}

evpn_type3_nlri_t* evpn_type3_nlri_create_ipv4(
    route_distinguisher_t rd,
    uint32_t ethernet_tag_id,
    const char *orig_router_ip) {
    uint8_t ip_bytes[16];

    memset(ip_bytes, 0, 16);
    if (!orig_router_ip || inet_pton(AF_INET, orig_router_ip, ip_bytes) != 1) return NULL;
    return evpn_type3_nlri_create_internal(rd, ethernet_tag_id, 32, ip_bytes, 0, 0);
}

evpn_type3_nlri_t* evpn_type3_nlri_create_ipv4_path_id(
    route_distinguisher_t rd,
    uint32_t ethernet_tag_id,
    const char *orig_router_ip,
    uint32_t path_id) {
    uint8_t ip_bytes[16];

    memset(ip_bytes, 0, 16);
    if (!orig_router_ip || inet_pton(AF_INET, orig_router_ip, ip_bytes) != 1) return NULL;
    return evpn_type3_nlri_create_internal(rd, ethernet_tag_id, 32, ip_bytes, 1, path_id);
}

evpn_type3_nlri_t* evpn_type3_nlri_create_ipv6(
    route_distinguisher_t rd,
    uint32_t ethernet_tag_id,
    const char *orig_router_ip) {
    uint8_t ip_bytes[16];

    memset(ip_bytes, 0, 16);
    if (!orig_router_ip || inet_pton(AF_INET6, orig_router_ip, ip_bytes) != 1) return NULL;
    return evpn_type3_nlri_create_internal(rd, ethernet_tag_id, 128, ip_bytes, 0, 0);
}

evpn_type3_nlri_t* evpn_type3_nlri_create_ipv6_path_id(
    route_distinguisher_t rd,
    uint32_t ethernet_tag_id,
    const char *orig_router_ip,
    uint32_t path_id) {
    uint8_t ip_bytes[16];

    memset(ip_bytes, 0, 16);
    if (!orig_router_ip || inet_pton(AF_INET6, orig_router_ip, ip_bytes) != 1) return NULL;
    return evpn_type3_nlri_create_internal(rd, ethernet_tag_id, 128, ip_bytes, 1, path_id);
}

DEFINE_NLRI_LIST_UTILS(evpn_type3_nlri_t, evpn_type3_nlri)

int bgp_encode_evpn_type3_prefix(uint8_t *buffer, evpn_type3_prefix_t *prefix) {
    int offset = 0;
    if (!buffer || !prefix || prefix->route_type != EVPN_RT_INCLUSIVE_MULTICAST || prefix->rd.type > 2 ||
        (prefix->ip_addr_len != 32 && prefix->ip_addr_len != 128)) return -1;

    // Route Type
    // TODO(WIRE_MUTATION): Corrupt EVPN Type 3 route type after encode.
    buffer[offset++] = prefix->route_type;

    // Length (placeholder)
    int length_offset = offset;

    offset++;

    // RD (8 bytes)
    bgp_encode_rd(buffer + offset, &prefix->rd);
    offset += 8;

    // Ethernet Tag ID (4 bytes)
    uint32_t tag_net = htonl(prefix->ethernet_tag_id);

    memcpy(buffer + offset, &tag_net, 4);
    offset += 4;

    // IP Address Length (1 byte)
    buffer[offset++] = prefix->ip_addr_len;

    // Originating Router's IP (4 or 16 bytes)
    int ip_len = (prefix->ip_addr_len == 128) ? 16 : 4;

    memcpy(buffer + offset, prefix->orig_router_ip, ip_len);
    offset += ip_len;

    // Fill in length
    // TODO(WIRE_MUTATION): Corrupt EVPN Type 3 route-length after encode.
    buffer[length_offset] = offset - length_offset - 1;

    return offset;
}

// EVPN Type 4 - Ethernet Segment

static evpn_type4_nlri_t* evpn_type4_nlri_create_internal(
    route_distinguisher_t rd,
    evpn_esi_t esi,
    uint8_t ip_addr_len,
    const uint8_t *orig_router_ip,
    int add_path,
    uint32_t path_id) {
    evpn_type4_nlri_t *nlri = calloc(1, sizeof(evpn_type4_nlri_t));

    if (!nlri) {
        return NULL;
    }

    nlri->prefix.route_type = EVPN_RT_ETHERNET_SEGMENT;
    nlri->prefix.rd = rd;
    nlri->prefix.esi = esi;
    nlri->prefix.ip_addr_len = ip_addr_len;
    memset(nlri->prefix.orig_router_ip, 0, 16);
    if (orig_router_ip) {
        int ip_bytes = (ip_addr_len == 128) ? 16 : 4;

        memcpy(nlri->prefix.orig_router_ip, orig_router_ip, ip_bytes);
    }

    nlri->path_id = path_id;
    nlri->add_path = (uint8_t)(add_path ? 1 : 0);
    nlri->next = NULL;
    return nlri;
}

evpn_type4_nlri_t* evpn_type4_nlri_create_ipv4(route_distinguisher_t rd, evpn_esi_t esi, const char *orig_router_ip) {
    uint8_t ip_bytes[16];

    memset(ip_bytes, 0, 16);
    if (!orig_router_ip || inet_pton(AF_INET, orig_router_ip, ip_bytes) != 1) return NULL;
    return evpn_type4_nlri_create_internal(rd, esi, 32, ip_bytes, 0, 0);
}

evpn_type4_nlri_t* evpn_type4_nlri_create_ipv4_path_id(
    route_distinguisher_t rd,
    evpn_esi_t esi,
    const char *orig_router_ip,
    uint32_t path_id) {
    uint8_t ip_bytes[16];

    memset(ip_bytes, 0, 16);
    if (!orig_router_ip || inet_pton(AF_INET, orig_router_ip, ip_bytes) != 1) return NULL;
    return evpn_type4_nlri_create_internal(rd, esi, 32, ip_bytes, 1, path_id);
}

evpn_type4_nlri_t* evpn_type4_nlri_create_ipv6(route_distinguisher_t rd, evpn_esi_t esi, const char *orig_router_ip) {
    uint8_t ip_bytes[16];

    memset(ip_bytes, 0, 16);
    if (!orig_router_ip || inet_pton(AF_INET6, orig_router_ip, ip_bytes) != 1) return NULL;
    return evpn_type4_nlri_create_internal(rd, esi, 128, ip_bytes, 0, 0);
}

evpn_type4_nlri_t* evpn_type4_nlri_create_ipv6_path_id(
    route_distinguisher_t rd,
    evpn_esi_t esi,
    const char *orig_router_ip,
    uint32_t path_id) {
    uint8_t ip_bytes[16];

    memset(ip_bytes, 0, 16);
    if (!orig_router_ip || inet_pton(AF_INET6, orig_router_ip, ip_bytes) != 1) return NULL;
    return evpn_type4_nlri_create_internal(rd, esi, 128, ip_bytes, 1, path_id);
}

DEFINE_NLRI_LIST_UTILS(evpn_type4_nlri_t, evpn_type4_nlri)

int bgp_encode_evpn_type4_prefix(uint8_t *buffer, evpn_type4_prefix_t *prefix) {
    int offset = 0;
    if (!buffer || !prefix || prefix->route_type != EVPN_RT_ETHERNET_SEGMENT || prefix->rd.type > 2 ||
        (prefix->ip_addr_len != 32 && prefix->ip_addr_len != 128)) return -1;

    // Route Type
    // TODO(WIRE_MUTATION): Corrupt EVPN Type 4 route type after encode.
    buffer[offset++] = prefix->route_type;

    // Length (placeholder)
    int length_offset = offset;

    offset++;

    // RD (8 bytes)
    bgp_encode_rd(buffer + offset, &prefix->rd);
    offset += 8;

    // ESI (10 bytes)
    buffer[offset++] = prefix->esi.type;
    memcpy(buffer + offset, prefix->esi.value, 9);
    offset += 9;

    // IP Address Length (1 byte)
    buffer[offset++] = prefix->ip_addr_len;

    // Originating Router's IP (4 or 16 bytes)
    int ip_len = (prefix->ip_addr_len == 128) ? 16 : 4;

    memcpy(buffer + offset, prefix->orig_router_ip, ip_len);
    offset += ip_len;

    // Fill in length
    // TODO(WIRE_MUTATION): Corrupt EVPN Type 4 route-length after encode.
    buffer[length_offset] = offset - length_offset - 1;

    return offset;
}

// EVPN Type 5 - IP Prefix

static evpn_type5_nlri_t* evpn_type5_nlri_create_ipv4_internal(
    const char *prefix_str,
    uint8_t prefix_len,
    route_distinguisher_t rd,
    uint32_t ethernet_tag_id,
    const char *gateway_ip,
    uint32_t label,
    int add_path,
    uint32_t path_id) {
    evpn_type5_nlri_t *nlri = calloc(1, sizeof(evpn_type5_nlri_t));

    if (!nlri) {
        return NULL;
    }

    nlri->prefix.route_type = EVPN_RT_IP_PREFIX;
    nlri->prefix.af = AF_INET;
    nlri->prefix.rd = rd;

    /*
     * RFC 9136 allows Type 5 to carry either zero ESI or a non-zero ESI as an
     * overlay index. The constructors default to zero ESI; callers that need a
     * non-zero overlay-index ESI can set it explicitly via the public setter.
     */
    nlri->prefix.esi.type = 0;
    memset(nlri->prefix.esi.value, 0, 9);

    nlri->prefix.ethernet_tag_id = ethernet_tag_id;
    nlri->prefix.ip_prefix_len = prefix_len;

    memset(nlri->prefix.ip_prefix, 0, sizeof(nlri->prefix.ip_prefix));
    inet_pton(AF_INET, prefix_str, nlri->prefix.ip_prefix);

    memset(nlri->prefix.gateway_ip, 0, sizeof(nlri->prefix.gateway_ip));
    if (gateway_ip) {
        inet_pton(AF_INET, gateway_ip, nlri->prefix.gateway_ip);
    }

    nlri->prefix.label.label = label;
    nlri->prefix.label.tc = 0;
    nlri->prefix.label.s = 1;
    nlri->prefix.label.ttl = 0;

    nlri->path_id = path_id;
    nlri->add_path = (uint8_t)(add_path ? 1 : 0);
    nlri->next = NULL;
    return nlri;
}

DEFINE_EVPN_TYPE5_CREATE_WRAPPERS(ipv4)

static evpn_type5_nlri_t* evpn_type5_nlri_create_ipv6_internal(
    const char *prefix_str,
    uint8_t prefix_len,
    route_distinguisher_t rd,
    uint32_t ethernet_tag_id,
    const char *gateway_ip,
    uint32_t label,
    int add_path,
    uint32_t path_id) {
    evpn_type5_nlri_t *nlri = calloc(1, sizeof(evpn_type5_nlri_t));

    if (!nlri) {
        return NULL;
    }

    nlri->prefix.route_type = EVPN_RT_IP_PREFIX;
    nlri->prefix.af = AF_INET6;
    nlri->prefix.rd = rd;
    nlri->prefix.esi.type = 0;
    memset(nlri->prefix.esi.value, 0, 9);
    nlri->prefix.ethernet_tag_id = ethernet_tag_id;
    nlri->prefix.ip_prefix_len = prefix_len;

    memset(nlri->prefix.ip_prefix, 0, sizeof(nlri->prefix.ip_prefix));
    inet_pton(AF_INET6, prefix_str, nlri->prefix.ip_prefix);

    memset(nlri->prefix.gateway_ip, 0, sizeof(nlri->prefix.gateway_ip));
    if (gateway_ip) {
        inet_pton(AF_INET6, gateway_ip, nlri->prefix.gateway_ip);
    }

    nlri->prefix.label.label = label;
    nlri->prefix.label.tc = 0;
    nlri->prefix.label.s = 1;
    nlri->prefix.label.ttl = 0;

    nlri->path_id = path_id;
    nlri->add_path = (uint8_t)(add_path ? 1 : 0);
    nlri->next = NULL;
    return nlri;
}

DEFINE_EVPN_TYPE5_CREATE_WRAPPERS(ipv6)

DEFINE_NLRI_LIST_UTILS(evpn_type5_nlri_t, evpn_type5_nlri)

void evpn_type5_prefix_set_esi(evpn_type5_prefix_t *prefix, evpn_esi_t esi) {
    if (!prefix) {
        return;
    }

    prefix->esi = esi;
}

void evpn_type5_nlri_set_esi(evpn_type5_nlri_t *nlri, evpn_esi_t esi) {
    if (!nlri) {
        return;
    }

    evpn_type5_prefix_set_esi(&nlri->prefix, esi);
}

int bgp_encode_evpn_type5_prefix(uint8_t *buffer, evpn_type5_prefix_t *prefix) {
    if (!buffer || !prefix || prefix->route_type != EVPN_RT_IP_PREFIX || prefix->rd.type > 2 ||
        (prefix->af != AF_INET && prefix->af != AF_INET6) ||
        prefix->ip_prefix_len > (prefix->af == AF_INET ? 32 : 128) ||
        prefix->label.label > (prefix->label_vni ? 0xFFFFFFU : 0xFFFFFU)) return -1;
    int esi_nonzero = 0;
    int gw_nonzero = 0;
    int gw_len = (prefix->af == AF_INET6) ? 16 : 4;
    int offset = 0;

    // RFC 9136: ESI and GW IP MUST NOT both be non-zero
    if (prefix->esi.type != 0) {
        esi_nonzero = 1;
    } else {
        for (int i = 0; i < 9; i++) {
            if (prefix->esi.value[i] != 0) {
                esi_nonzero = 1;
                break;
            }
        }
    }
    for (int i = 0; i < gw_len; i++) {
        if (prefix->gateway_ip[i] != 0) {
            gw_nonzero = 1;
            break;
        }
    }
    if (esi_nonzero && gw_nonzero) {
        fprintf(stderr, "EVPN Type 5: ESI and GW IP must not both be non-zero (RFC 9136)\n");
        /*
         * TODO(FUZZ_GATE): Allow EVPN Type 5 ESI and Gateway IP both set.
         *
         * RFC 9136 section 3.1 makes ESI and Gateway IP mutually
         * exclusive in EVPN Type 5 (IP Prefix) routes: the ESI is
         * used for Single-Active or All-Active multihoming, and
         * the Gateway IP is used to indicate a recursive next-hop
         * for reaching the advertised prefix. Using both in the
         * same route is semantically contradictory.
         *
         * Fuzz use case: a peer's EVPN Type 5 receive code path
         * may have an "if ESI or Gateway" dispatch that doesn't
         * validate mutual exclusion. Generating a route with both
         * populated tests whether the peer:
         *   - rejects the NLRI cleanly
         *   - silently prefers one field over the other
         *   - attempts to install both interpretations (buggy)
         *
         * This is semantic relaxation, not wire mutation: the
         * resulting NLRI is structurally well-formed (every field
         * has the right length, outer route-length is correct),
         * it just violates a "SHOULD NOT" in the spec.
         *
         * Proposed allow key: "evpn.type5.esi-and-gateway"
         */
        return -1;
    }

    // Route Type
    // TODO(WIRE_MUTATION): Corrupt EVPN Type 5 route type after encode.
    buffer[offset++] = prefix->route_type;

    // Length (calculated later, placeholder)
    int length_offset = offset;
    offset++;

    // RD (8 bytes: 2-byte type + 6-byte value per RFC 4364)
    bgp_encode_rd(buffer + offset, &prefix->rd);
    offset += 8;
    // TODO(WIRE_MUTATION): Corrupt EVPN Type 5 RD bytes after encode.

    // ESI (10 bytes)
    buffer[offset++] = prefix->esi.type;
    memcpy(buffer + offset, prefix->esi.value, 9);
    offset += 9;
    // TODO(WIRE_MUTATION): Corrupt EVPN Type 5 ESI type/value after encode.

    // Ethernet Tag ID (4 bytes)
    uint32_t tag_net = htonl(prefix->ethernet_tag_id);
    memcpy(buffer + offset, &tag_net, 4);
    offset += 4;
    // TODO(WIRE_MUTATION): Corrupt EVPN Type 5 Ethernet Tag ID after encode.

    // IP Prefix Length
    // TODO(WIRE_MUTATION): Corrupt EVPN Type 5 IP prefix length after encode.
    buffer[offset++] = prefix->ip_prefix_len;

    // IP Prefix: fixed-width per RFC 9136 (4 bytes IPv4, 16 bytes IPv6).
    int ip_len = (prefix->af == AF_INET6) ? 16 : 4;
    memcpy(buffer + offset, prefix->ip_prefix, ip_len);
    offset += ip_len;
    // TODO(WIRE_MUTATION): Corrupt EVPN Type 5 IP prefix bytes after encode.

    // Gateway IP uses the same fixed width as the Type 5 IP Prefix field.
    memcpy(buffer + offset, prefix->gateway_ip, ip_len);
    offset += ip_len;
    // TODO(WIRE_MUTATION): Corrupt EVPN Type 5 Gateway IP bytes after encode.

    // MPLS Label (3 bytes)
    encode_evpn_label(buffer + offset, &prefix->label, prefix->label_vni);
    offset += 3;
    // TODO(WIRE_MUTATION): Corrupt EVPN Type 5 MPLS label after encode.

    // Fill in length
    // TODO(WIRE_MUTATION): Corrupt EVPN Type 5 route-length after encode.
    buffer[length_offset] = offset - length_offset - 1;

    return offset;
}

// EVPN Extended Community Helpers

/*
 * MAC Mobility Extended Community (RFC 7432 Section 7.7)
 * Type = 0x06 (EVPN), Sub-Type = 0x00
 */
bgp_path_attr_t* bgp_attr_create_ext_comm_mac_mobility(uint8_t flags, uint32_t seq_number) {
    bgp_path_attr_t *attr;

    if (!evpn_single_flag_bit_only(flags)) {
        // TODO(FUZZ_GATE): Allow reserved MAC Mobility flag bits to be set.
        return NULL;
    }

    attr = bgp_attr_alloc_ext_comm(0x06, 0x00);
    if (!attr) {
        return NULL;
    }

    attr->value[2] = flags;
    attr->value[3] = 0;     /* Reserved */
    // TODO(WIRE_MUTATION): Corrupt MAC Mobility type/subtype/flags/reserved.

    uint32_t seq_net = htonl(seq_number);

    memcpy(attr->value + 4, &seq_net, 4);
    // TODO(WIRE_MUTATION): Corrupt MAC Mobility sequence number bytes.

    return attr;
}

/*
 * ESI Label Extended Community (RFC 7432 Section 7.5)
 * Type = 0x06 (EVPN), Sub-Type = 0x01
 */
bgp_path_attr_t* bgp_attr_create_ext_comm_esi_label(uint8_t flags, uint32_t esi_label) {
    bgp_path_attr_t *attr;

    if (!evpn_single_flag_bit_only(flags)) {
        // TODO(FUZZ_GATE): Allow reserved ESI Label flag bits to be set.
        return NULL;
    }
    if (esi_label > 0xFFFFF) {
        // TODO(FUZZ_GATE): Allow ESI Label values that overflow the 20-bit field.
        return NULL;
    }

    attr = bgp_attr_alloc_ext_comm(0x06, 0x01);
    if (!attr) {
        return NULL;
    }

    attr->value[2] = flags;
    attr->value[3] = 0;  /* Reserved */
    attr->value[4] = 0;  /* Reserved */
    // TODO(WIRE_MUTATION): Corrupt ESI Label type/subtype/flags/reserved.

    // ESI Label is 3 bytes, encoded like an MPLS label
    attr->value[5] = (uint8_t)((esi_label >> 12) & 0xFF);
    attr->value[6] = (uint8_t)((esi_label >> 4) & 0xFF);
    attr->value[7] = (uint8_t)((esi_label << 4) & 0xF0);
    // TODO(WIRE_MUTATION): Corrupt ESI Label payload bits after encode.

    return attr;
}

/*
 * Default Gateway Extended Community (RFC 7432 Section 7.8)
 * Type = 0x03 (Opaque), Sub-Type = 0x0d.
 * The remaining 6 octets are reserved and encoded as zero in strict mode.
 */
bgp_path_attr_t* bgp_attr_create_ext_comm_default_gateway(void) {
    bgp_path_attr_t *attr = bgp_attr_alloc_ext_comm(0x03, 0x0d);

    if (!attr) {
        return NULL;
    }

    // TODO(WIRE_MUTATION): Corrupt Default Gateway type/subtype/reserved bytes.

    return attr;
}

/*
 * EVPN Router's MAC Extended Community (RFC 9135 section 8.1)
 * Type = 0x06 (EVPN), Sub-Type = 0x03.
 * RFC 9135 defines this for RT-2 symmetric-IRB advertisements, and RFC 9136
 * reuses it on RT-5 when the route is associated with an Ethernet NVO tunnel.
 */
bgp_path_attr_t* bgp_attr_create_ext_comm_router_mac(const uint8_t router_mac[6]) {
    bgp_path_attr_t *attr;

    if (evpn_router_mac_invalid(router_mac)) {
        // TODO(FUZZ_GATE): Allow invalid Router's MAC EC payloads in fuzz mode.
        return NULL;
    }

    attr = bgp_attr_alloc_ext_comm(0x06, 0x03);
    if (!attr) {
        return NULL;
    }

    memcpy(attr->value + 2, router_mac, 6);
    // TODO(WIRE_MUTATION): Corrupt Router's MAC EC type/subtype/MAC bytes.

    return attr;
}

// MP-BGP Attribute Helpers

DEFINE_ADD_PATH_DETECTOR(bgp_detect_evpn_type1_add_path, evpn_type1_nlri_t, do { } while (0))

DEFINE_ADD_PATH_DETECTOR(bgp_detect_evpn_type2_add_path, evpn_type2_nlri_t, do { } while (0))

DEFINE_ADD_PATH_DETECTOR(bgp_detect_evpn_type3_add_path, evpn_type3_nlri_t, do { } while (0))

DEFINE_ADD_PATH_DETECTOR(bgp_detect_evpn_type4_add_path, evpn_type4_nlri_t, do { } while (0))

DEFINE_ADD_PATH_DETECTOR(bgp_detect_evpn_type5_add_path, evpn_type5_nlri_t, do { } while (0))

// NLRI encoding (single entry)

static int bgp_encode_evpn_type1_nlri(uint8_t *buffer, const evpn_type1_nlri_t *nlri, int add_path) {
    int offset = 0;
    int len;

    if (add_path) {
        uint32_t path_id_net = htonl(nlri->path_id);

        memcpy(buffer + offset, &path_id_net, sizeof(path_id_net));
        offset += sizeof(path_id_net);
    }

    len = bgp_encode_evpn_type1_prefix(buffer + offset, (evpn_type1_prefix_t *)&nlri->prefix);
    return (len < 0) ? -1 : offset + len;
}

static int bgp_encode_evpn_type2_nlri(uint8_t *buffer, const evpn_type2_nlri_t *nlri, int add_path) {
    int offset = 0;
    int len;

    if (add_path) {
        uint32_t path_id_net = htonl(nlri->path_id);

        memcpy(buffer + offset, &path_id_net, sizeof(path_id_net));
        offset += sizeof(path_id_net);
    }

    len = bgp_encode_evpn_type2_prefix(buffer + offset, (evpn_type2_prefix_t *)&nlri->prefix);
    return (len < 0) ? -1 : offset + len;
}

static int bgp_encode_evpn_type3_nlri(uint8_t *buffer, const evpn_type3_nlri_t *nlri, int add_path) {
    int offset = 0;
    int len;

    if (add_path) {
        uint32_t path_id_net = htonl(nlri->path_id);

        memcpy(buffer + offset, &path_id_net, sizeof(path_id_net));
        offset += sizeof(path_id_net);
    }

    len = bgp_encode_evpn_type3_prefix(buffer + offset, (evpn_type3_prefix_t *)&nlri->prefix);
    return (len < 0) ? -1 : offset + len;
}

static int bgp_encode_evpn_type4_nlri(uint8_t *buffer, const evpn_type4_nlri_t *nlri, int add_path) {
    int offset = 0;
    int len;

    if (add_path) {
        uint32_t path_id_net = htonl(nlri->path_id);

        memcpy(buffer + offset, &path_id_net, sizeof(path_id_net));
        offset += sizeof(path_id_net);
    }

    len = bgp_encode_evpn_type4_prefix(buffer + offset, (evpn_type4_prefix_t *)&nlri->prefix);
    return (len < 0) ? -1 : offset + len;
}

static int bgp_encode_evpn_type5_nlri(uint8_t *buffer, const evpn_type5_nlri_t *nlri, int add_path) {
    int offset = 0;
    int len;

    if (add_path) {
        uint32_t path_id_net = htonl(nlri->path_id);

        memcpy(buffer + offset, &path_id_net, sizeof(path_id_net));
        offset += sizeof(path_id_net);
    }

    len = bgp_encode_evpn_type5_prefix(buffer + offset, (evpn_type5_prefix_t *)&nlri->prefix);
    return (len < 0) ? -1 : offset + len;
}

// Chunking functions

/*
 * Type 1: fixed size = rt(1) + len(1) + RD(8) + ESI(10) + ETag(4) + Label(3) = 27
 */
static int encode_evpn_type1_chunk(evpn_type1_nlri_t **cursor, uint8_t *buffer, int max_bytes, int add_path) {
    int written = 0;

    while (*cursor) {
        int needed = 27;

        if ((int)(*cursor)->add_path != add_path) {
            return -1;
        }
        if (add_path) {
            needed += 4;
        }

        if (written + needed > max_bytes) {
            return (written > 0) ? written : -1;
        }

        int len = bgp_encode_evpn_type1_nlri(buffer + written, *cursor, add_path);

        if (len <= 0) {
            return -1;
        }
        written += len;
        *cursor = (*cursor)->next;
    }

    return written;
}

/*
 * Type 2: variable size depending on IP address length and label2
 */
static int evpn_type2_wire_size(const evpn_type2_prefix_t *prefix) {
    /*
     * rt(1) + len(1) + RD(8) + ESI(10) + ETag(4) + MAC_LEN(1) + MAC(6)
     * + IP_LEN(1) + IP(0/4/16) + Label1(3) + Label2(0/3)
     */
    int size = 1 + 1 + 8 + 10 + 4 + 1 + 6 + 1 + 3;

    if (!evpn_type2_ip_length_valid(prefix->ip_addr_len)) {
        // TODO(FUZZ_GATE): Allow EVPN Type 2 sizing for malformed IP lengths.
        return -1;
    }

    if (prefix->ip_addr_len == 32) {
        size += 4;
    } else if (prefix->ip_addr_len == 128) {
        size += 16;
    }
    if (prefix->has_label2) {
        size += 3;
    }
    return size;
}

static int encode_evpn_type2_chunk(evpn_type2_nlri_t **cursor, uint8_t *buffer, int max_bytes, int add_path) {
    int written = 0;

    while (*cursor) {
        int needed = evpn_type2_wire_size(&(*cursor)->prefix);

        if ((int)(*cursor)->add_path != add_path) {
            return -1;
        }
        if (add_path) {
            needed += 4;
        }

        if (written + needed > max_bytes) {
            return (written > 0) ? written : -1;
        }

        int len = bgp_encode_evpn_type2_nlri(buffer + written, *cursor, add_path);

        if (len <= 0) {
            return -1;
        }
        written += len;
        *cursor = (*cursor)->next;
    }

    return written;
}

/*
 * Type 3: size depends on IP address length
 */
static int encode_evpn_type3_chunk(evpn_type3_nlri_t **cursor, uint8_t *buffer, int max_bytes, int add_path) {
    int written = 0;

    while (*cursor) {
        // rt(1) + len(1) + RD(8) + ETag(4) + IP_LEN(1) + IP(4 or 16)
        int ip_len = ((*cursor)->prefix.ip_addr_len == 128) ? 16 : 4;
        int needed = 1 + 1 + 8 + 4 + 1 + ip_len;

        if ((int)(*cursor)->add_path != add_path) {
            return -1;
        }
        if (add_path) {
            needed += 4;
        }

        if (written + needed > max_bytes) {
            return (written > 0) ? written : -1;
        }

        int len = bgp_encode_evpn_type3_nlri(buffer + written, *cursor, add_path);

        if (len <= 0) {
            return -1;
        }
        written += len;
        *cursor = (*cursor)->next;
    }

    return written;
}

/*
 * Type 4: size depends on IP address length
 */
static int encode_evpn_type4_chunk(evpn_type4_nlri_t **cursor, uint8_t *buffer, int max_bytes, int add_path) {
    int written = 0;

    while (*cursor) {
        // rt(1) + len(1) + RD(8) + ESI(10) + IP_LEN(1) + IP(4 or 16)
        int ip_len = ((*cursor)->prefix.ip_addr_len == 128) ? 16 : 4;
        int needed = 1 + 1 + 8 + 10 + 1 + ip_len;

        if ((int)(*cursor)->add_path != add_path) {
            return -1;
        }
        if (add_path) {
            needed += 4;
        }

        if (written + needed > max_bytes) {
            return (written > 0) ? written : -1;
        }

        int len = bgp_encode_evpn_type4_nlri(buffer + written, *cursor, add_path);

        if (len <= 0) {
            return -1;
        }
        written += len;
        *cursor = (*cursor)->next;
    }

    return written;
}

static int evpn_type5_wire_size(const evpn_type5_prefix_t *prefix) {
    int ip_len = (prefix->af == AF_INET6) ? 16 : 4;

    /*
     * Type 5 is fixed per AF:
     *   rt(1) + len(1) + RD(8) + ESI(10) + ETag(4) +
     *   IP_LEN(1) + IP prefix(4/16) + GW IP(4/16) + Label(3)
     */
    return 1 + 1 + 8 + 10 + 4 + 1 + ip_len + ip_len + 3;
}

/*
 * Type 5: fixed size per AF and optional ADD-PATH path-id
 */
static int encode_evpn_type5_chunk(evpn_type5_nlri_t **cursor, uint8_t *buffer, int max_bytes, int add_path) {
    int written = 0;

    while (*cursor) {
        int needed = evpn_type5_wire_size(&(*cursor)->prefix);

        if ((int)(*cursor)->add_path != add_path) {
            return -1;
        }
        if (add_path) {
            needed += 4;
        }

        if (written + needed > max_bytes) {
            return (written > 0) ? written : -1;
        }

        /*
         * Type 5 NLRI size is fixed per AF, so write straight into the output
         * chunk and avoid a temporary per-prefix scratch buffer.
         */
        int len = bgp_encode_evpn_type5_nlri(buffer + written, *cursor, add_path);

        if (len <= 0) {
            return -1;
        }
        written += len;
        *cursor = (*cursor)->next;
    }

    return written;
}

// MESSAGE GENERATION with splitting support

/*
 * Macro to generate an EVPN UPDATE generator for a given type.
 * Keep this as a macro rather than five hand-copied functions: each
 * instantiation still produces a concrete public symbol per EVPN route type,
 * but the shared MP_REACH / MP_UNREACH framing stays in one place. Only the
 * NLRI list type, add-path detector, and chunk encoder vary across types.
 */
#define DEFINE_EVPN_GENERATOR(type_num, nlri_type, detect_fn, chunk_fn)      \
bgp_update_result_t* bgp_generate_update_evpn_type##type_num(                \
    nlri_type *nlri_list,                                                    \
    bgp_path_attr_t *attributes,                                             \
    nlri_type *withdrawn_list,                                               \
    uint16_t max_pdu_size,                                                   \
    const bgp_next_hop_t *next_hop)                                          \
{                                                                            \
    bgp_builder_t builder = {0};                                             \
    uint8_t      *base_attr_data = NULL;                                     \
    uint16_t      base_attr_len = 0;                                         \
    uint8_t      *nlri_buffer = NULL;                                        \
    uint8_t       nh_buf[BGP_EVPN_NEXT_HOP_BUF_SIZE];                        \
    uint8_t       nh_len = 0;                                                \
    int           available_space;                                           \
    int           nlri_add_path = 0;                                         \
    int           withdrawn_add_path = 0;                                    \
    nlri_type    *curr;                                                      \
                                                                             \
    if (max_pdu_size == 0) {                                                 \
        max_pdu_size = BGP_MAX_PDU_SIZE;                                     \
    }                                                                        \
    if (max_pdu_size < BGP_UPDATE_MIN_SIZE) {                                \
        return NULL;                                                         \
    }                                                                        \
                                                                             \
    if (bgp_attr_list_contains_type(attributes, BGP_ATTR_MP_REACH_NLRI) ||   \
        bgp_attr_list_contains_type(attributes, BGP_ATTR_MP_UNREACH_NLRI)) { \
        return NULL;                                                         \
    }                                                                        \
                                                                             \
    if (detect_fn(nlri_list, &nlri_add_path) < 0 ||                          \
        detect_fn(withdrawn_list, &withdrawn_add_path) < 0) {                \
        return NULL;                                                         \
    }                                                                        \
                                                                             \
    if (bgp_serialize_path_attributes_alloc(attributes,                      \
                                            &base_attr_data,                 \
                                            &base_attr_len) < 0) {           \
        return NULL;                                                         \
    }                                                                        \
                                                                             \
    if (nlri_list) {                                                         \
        if (!bgp_validate_mp_attrs(attributes) ||                            \
            bgp_encode_evpn_next_hop(next_hop, nh_buf, &nh_len) < 0) {       \
            goto fail;                                                       \
        }                                                                    \
    }                                                                        \
                                                                             \
    if (bgp_builder_init(&builder) < 0) {                                    \
        goto fail;                                                           \
    }                                                                        \
                                                                             \
    nlri_buffer = malloc(max_pdu_size);                                      \
    if (!nlri_buffer) {                                                      \
        goto fail;                                                           \
    }                                                                        \
                                                                             \
    if (withdrawn_list) {                                                    \
        available_space = bgp_mp_unreach_payload_budget(max_pdu_size);       \
        if (available_space <= 0) {                                          \
            goto fail;                                                       \
        }                                                                    \
                                                                             \
        curr = withdrawn_list;                                               \
        while (curr) {                                                       \
            int nlri_len = chunk_fn(&curr, nlri_buffer,                      \
                                    available_space,                         \
                                    withdrawn_add_path);                     \
            if (nlri_len <= 0 ||                                             \
                bgp_builder_append_mp(&builder, &(bgp_mp_args_t){            \
                    .afi         = AFI_L2VPN,                                \
                    .safi        = SAFI_EVPN,                                \
                    .mp_nlri     = nlri_buffer,                              \
                    .mp_nlri_len = (uint16_t)nlri_len,                       \
                }) < 0) {                                                    \
                goto fail;                                                   \
            }                                                                \
        }                                                                    \
    }                                                                        \
                                                                             \
    if (nlri_list) {                                                         \
        available_space = bgp_mp_reach_payload_budget(max_pdu_size,          \
                                                      base_attr_len,         \
                                                      nh_len);               \
        if (available_space <= 0) {                                          \
            goto fail;                                                       \
        }                                                                    \
                                                                             \
        curr = nlri_list;                                                    \
        while (curr) {                                                       \
            int nlri_len = chunk_fn(&curr, nlri_buffer,                      \
                                    available_space,                         \
                                    nlri_add_path);                          \
            if (nlri_len <= 0 ||                                             \
                bgp_builder_append_mp(&builder, &(bgp_mp_args_t){            \
                    .attrs       = base_attr_data,                           \
                    .attrs_len   = base_attr_len,                            \
                    .is_reach    = 1,                                        \
                    .afi         = AFI_L2VPN,                                \
                    .safi        = SAFI_EVPN,                                \
                    .next_hop    = nh_buf,                                   \
                    .nh_len      = nh_len,                                   \
                    .mp_nlri     = nlri_buffer,                              \
                    .mp_nlri_len = (uint16_t)nlri_len,                       \
                }) < 0) {                                                    \
                goto fail;                                                   \
            }                                                                \
        }                                                                    \
    } else if (!withdrawn_list) {                                            \
        if (bgp_builder_append_attrs_only(&builder,                          \
                                          base_attr_data,                    \
                                          base_attr_len) < 0) {              \
            goto fail;                                                       \
        }                                                                    \
    }                                                                        \
                                                                             \
    free(base_attr_data);                                                    \
    free(nlri_buffer);                                                       \
    return bgp_builder_take(&builder);                                       \
                                                                             \
fail:                                                                        \
    free(base_attr_data);                                                    \
    free(nlri_buffer);                                                       \
    bgp_builder_release(&builder);                                           \
    return NULL;                                                             \
}

DEFINE_EVPN_GENERATOR(1, evpn_type1_nlri_t, bgp_detect_evpn_type1_add_path, encode_evpn_type1_chunk)

DEFINE_EVPN_GENERATOR(2, evpn_type2_nlri_t, bgp_detect_evpn_type2_add_path, encode_evpn_type2_chunk)

DEFINE_EVPN_GENERATOR(3, evpn_type3_nlri_t, bgp_detect_evpn_type3_add_path, encode_evpn_type3_chunk)

DEFINE_EVPN_GENERATOR(4, evpn_type4_nlri_t, bgp_detect_evpn_type4_add_path, encode_evpn_type4_chunk)

DEFINE_EVPN_GENERATOR(5, evpn_type5_nlri_t, bgp_detect_evpn_type5_add_path, encode_evpn_type5_chunk)
