/*
 * BGP UPDATE Message Generation - VPN Extensions
 * Implements VPNv4 and VPNv6 support.
 */

#define OUTPUT_STDIO_REMAP

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "bgp.h"
#include "output.h"
#include "bgp_update.h"

// Route Distinguisher Helper Functions

/*
 * Create Type 0 RD: <2-byte Admin>:<4-byte Assigned>
 */
route_distinguisher_t rd_create_type0(uint16_t admin, uint32_t assigned) {
    route_distinguisher_t rd;
    rd.type = 0;

    uint16_t admin_net = htons(admin);
    memcpy(rd.value, &admin_net, 2);

    uint32_t assigned_net = htonl(assigned);
    memcpy(rd.value + 2, &assigned_net, 4);

    return rd;
}

/*
 * Create Type 1 RD: <4-byte IP>:<2-byte Assigned>
 */
route_distinguisher_t rd_create_type1(uint32_t ip, uint16_t assigned) {
    route_distinguisher_t rd;
    rd.type = 1;

    uint32_t ip_net = htonl(ip);
    memcpy(rd.value, &ip_net, 4);

    uint16_t assigned_net = htons(assigned);
    memcpy(rd.value + 4, &assigned_net, 2);

    return rd;
}

/*
 * Create Type 2 RD: <4-byte AS>:<2-byte Assigned>
 */
route_distinguisher_t rd_create_type2(uint32_t asn, uint16_t assigned) {
    route_distinguisher_t rd;
    rd.type = 2;

    uint32_t asn_net = htonl(asn);
    memcpy(rd.value, &asn_net, 4);

    uint16_t assigned_net = htons(assigned);
    memcpy(rd.value + 4, &assigned_net, 2);

    return rd;
}

// VPNv4 NLRI Functions

static vpnv4_nlri_list_t* vpnv4_nlri_create_internal(const char *prefix_str,
                                                     uint8_t prefix_len,
                                                     uint32_t label,
                                                     route_distinguisher_t rd,
                                                     int add_path,
                                                     uint32_t path_id) {
    if (!prefix_str || prefix_len > 32 || label > 0xFFFFF || rd.type > 2) return NULL;
    vpnv4_nlri_list_t *nlri = calloc(1, sizeof(vpnv4_nlri_list_t));

    if (!nlri) {
        return NULL;
    }

    // VPNv4 NLRI length is label(24) + RD(64) + IPv4 prefix bits.
    nlri->prefix.prefix_len = 24 + 64 + prefix_len;
    nlri->prefix.label.label = label;
    nlri->prefix.label.tc = 0;
    nlri->prefix.label.s = 1;  /* Bottom of stack */
    nlri->prefix.label.ttl = 0;
    nlri->prefix.rd = rd;

    if (inet_pton(AF_INET, prefix_str, &nlri->prefix.prefix) != 1) {
        free(nlri);
        return NULL;
    }
    nlri->path_id = path_id;
    nlri->add_path = (uint8_t)(add_path ? 1 : 0);
    nlri->next = NULL;

    return nlri;
}

DEFINE_VPN_NLRI_CREATE_WRAPPERS(vpnv4_nlri_list_t, vpnv4_nlri)
DEFINE_VPN_NLRI_TAIL_WRAPPERS(vpnv4_nlri_list_t, vpnv4_nlri)
DEFINE_NLRI_LIST_UTILS(vpnv4_nlri_list_t, vpnv4_nlri)

int bgp_encode_vpnv4_prefix(uint8_t *buffer, vpnv4_prefix_t *prefix) {
    if (!buffer || !prefix || prefix->prefix_len < 88 || prefix->prefix_len > 120 ||
        prefix->rd.type > 2 || prefix->label.label > 0xFFFFF) return -1;
    int offset = 0;

    // Prefix length = label(24) + RD(64) + IPv4 prefix bits.
    /*
     * TODO(WIRE_MUTATION): Corrupt the 1-byte VPNv4 NLRI prefix length.
     *
     * Per RFC 4364 section 4.3.4, VPNv4 prefix_len covers the entire
     * bit-count of:
     *   label(24 bits) + RD(64 bits) + IPv4 prefix(0..32 bits)
     * So a /24 VPNv4 route has prefix_len = 24 + 64 + 24 = 112.
     *
     * This is the RICHEST framing cascade in the encoder: the
     * single prefix_len byte determines how many of the following
     * bytes are label (3), RD (8), and prefix (0..4). A wrong value
     * shifts all three boundaries at once.
     *
     * Useful mutations:
     *
     *   - Off-by-one (e.g. 112 -> 113):
     *       Decoder consumes one extra byte as prefix, next NLRI
     *       walk starts one byte late. Classic cascade.
     *
     *   - Shrink by 64 (claim no RD):
     *       Decoder skips RD parsing, treats RD bytes as prefix.
     *       Only useful if the decoder honors prefix_len rather
     *       than assuming fixed RD offset.
     *
     *   - Shrink by 24 (claim no label):
     *       Same idea but for the label entry. Even more aggressive
     *       since it shifts RD/prefix boundaries.
     *
     *   - Grow beyond (24+64+32) = 120:
     *       Structurally invalid for VPNv4. Tests range validation.
     *
     *   - Exactly 88 (= 24 + 64, no IP bits):
     *       All-prefix default route. Edge case in longest-match.
     *
     * Because VPN decoders typically assume fixed label and RD
     * offsets, they may ignore prefix_len for label/RD sizing and
     * only use it for the prefix portion. Fuzzing exposes whether
     * the decoder trusts the field or the structure.
     */
    buffer[offset++] = prefix->prefix_len;

    // MPLS label (3 bytes)
    bgp_encode_mpls_label(buffer + offset, &prefix->label);
    offset += 3;

    // Route Distinguisher (8 bytes)
    bgp_encode_rd(buffer + offset, &prefix->rd);
    offset += 8;

    // IPv4 prefix (variable length)
    int ip_prefix_len = prefix->prefix_len - 24 - 64;  /* Remove label and RD bits */
    int bytes_needed = bgp_prefix_bytes_needed(ip_prefix_len);
    memcpy(buffer + offset, &prefix->prefix, bytes_needed);
    offset += bytes_needed;

    return offset;
}

// VPNv6 NLRI Functions

static vpnv6_nlri_list_t* vpnv6_nlri_create_internal(const char *prefix_str,
                                                     uint8_t prefix_len,
                                                     uint32_t label,
                                                     route_distinguisher_t rd,
                                                     int add_path,
                                                     uint32_t path_id) {
    if (!prefix_str || prefix_len > 128 || label > 0xFFFFF || rd.type > 2) return NULL;
    vpnv6_nlri_list_t *nlri = calloc(1, sizeof(vpnv6_nlri_list_t));

    if (!nlri) {
        return NULL;
    }

    // VPNv6 keeps the same label(24) + RD(64) + prefix-bits structure as VPNv4.
    nlri->prefix.prefix_len = 24 + 64 + prefix_len;
    nlri->prefix.label.label = label;
    nlri->prefix.label.tc = 0;
    nlri->prefix.label.s = 1;
    nlri->prefix.label.ttl = 0;
    nlri->prefix.rd = rd;

    if (inet_pton(AF_INET6, prefix_str, nlri->prefix.prefix) != 1) {
        free(nlri);
        return NULL;
    }
    nlri->path_id = path_id;
    nlri->add_path = (uint8_t)(add_path ? 1 : 0);
    nlri->next = NULL;

    return nlri;
}

DEFINE_VPN_NLRI_CREATE_WRAPPERS(vpnv6_nlri_list_t, vpnv6_nlri)
DEFINE_VPN_NLRI_TAIL_WRAPPERS(vpnv6_nlri_list_t, vpnv6_nlri)
DEFINE_NLRI_LIST_UTILS(vpnv6_nlri_list_t, vpnv6_nlri)

int bgp_encode_vpnv6_prefix(uint8_t *buffer, vpnv6_prefix_t *prefix) {
    if (!buffer || !prefix || prefix->prefix_len < 88 || prefix->prefix_len > 216 ||
        prefix->rd.type > 2 || prefix->label.label > 0xFFFFF) return -1;
    int offset = 0;

    // Prefix length = label(24) + RD(64) + IPv6 prefix bits.
    /*
     * TODO(WIRE_MUTATION): Corrupt the 1-byte VPNv6 NLRI prefix length.
     *
     * Per RFC 4659 section 3.2.1, VPNv6 prefix_len uses the same
     * structure as VPNv4 but with a 0..128 bit IPv6 portion:
     *   label(24) + RD(64) + IPv6 prefix(0..128) = max 216 bits.
     *
     * Same framing cascade as VPNv4 (see the VPNv4 marker above for
     * the full mutation taxonomy). VPNv6 additionally allows larger
     * prefix_len values, so "grow beyond 216" tests the IPv6 upper
     * bound specifically.
     */
    buffer[offset++] = prefix->prefix_len;

    // MPLS label
    bgp_encode_mpls_label(buffer + offset, &prefix->label);
    offset += 3;

    // Route Distinguisher (8 bytes)
    bgp_encode_rd(buffer + offset, &prefix->rd);
    offset += 8;

    // IPv6 prefix
    int ip_prefix_len = prefix->prefix_len - 24 - 64;
    int bytes_needed = bgp_prefix_bytes_needed(ip_prefix_len);
    memcpy(buffer + offset, prefix->prefix, bytes_needed);
    offset += bytes_needed;

    return offset;
}

// MP-BGP Attribute Helpers

DEFINE_ADD_PATH_DETECTOR(bgp_detect_vpnv4_add_path, vpnv4_nlri_list_t, do { } while (0))

DEFINE_ADD_PATH_DETECTOR(bgp_detect_vpnv6_add_path, vpnv6_nlri_list_t, do { } while (0))

static int bgp_encode_vpnv4_nlri(uint8_t *buffer, const vpnv4_nlri_list_t *nlri, int add_path) {
    int offset = 0;

    if (add_path) {
        uint32_t path_id_net = htonl(nlri->path_id);

        memcpy(buffer + offset, &path_id_net, sizeof(path_id_net));
        offset += sizeof(path_id_net);
    }

    int len = bgp_encode_vpnv4_prefix(buffer + offset, (vpnv4_prefix_t *)&nlri->prefix);
    return len < 0 ? -1 : offset + len;
}

static int bgp_encode_vpnv6_nlri(uint8_t *buffer, const vpnv6_nlri_list_t *nlri, int add_path) {
    int offset = 0;

    if (add_path) {
        uint32_t path_id_net = htonl(nlri->path_id);

        memcpy(buffer + offset, &path_id_net, sizeof(path_id_net));
        offset += sizeof(path_id_net);
    }

    int len = bgp_encode_vpnv6_prefix(buffer + offset, (vpnv6_prefix_t *)&nlri->prefix);
    return len < 0 ? -1 : offset + len;
}

static int bgp_vpn_prefix_wire_size(uint8_t total_prefix_len) {
    /*
     * VPN NLRI is encoded as prefix-len octet + MPLS label(3) + RD(8) +
     * variable IP prefix bytes. The on-struct prefix_len counts the label and
     * RD bits too, so strip those 24 + 64 bits before sizing the IP payload.
     */
    uint8_t ip_prefix_len = (uint8_t)(total_prefix_len - 24 - 64);

    return 1 + 3 + 8 + bgp_prefix_bytes_needed(ip_prefix_len);
}

static int encode_vpnv4_chunk(vpnv4_nlri_list_t **cursor, uint8_t *buffer, int max_bytes, int add_path) {
    int written = 0;

    while (*cursor) {
        int needed = bgp_vpn_prefix_wire_size((*cursor)->prefix.prefix_len);

        /*
         * ADD-PATH is negotiated per AFI/SAFI, so each MP_REACH_NLRI or
         * MP_UNREACH_NLRI payload must use one encoding mode consistently.
         */
        if ((int)(*cursor)->add_path != add_path) {
            return -1;
        }
        if (add_path) {
            needed += 4;
        }

        if (written + needed > max_bytes) {
            return (written > 0) ? written : -1;
        }

        int encoded = bgp_encode_vpnv4_nlri(buffer + written, *cursor, add_path);
        if (encoded < 0) return -1;
        written += encoded;
        *cursor = (*cursor)->next;
    }

    return written;
}

static int encode_vpnv6_chunk(vpnv6_nlri_list_t **cursor, uint8_t *buffer, int max_bytes, int add_path) {
    int written = 0;

    while (*cursor) {
        int needed = bgp_vpn_prefix_wire_size((*cursor)->prefix.prefix_len);

        if ((int)(*cursor)->add_path != add_path) {
            return -1;
        }
        if (add_path) {
            needed += 4;
        }

        if (written + needed > max_bytes) {
            return (written > 0) ? written : -1;
        }

        int encoded = bgp_encode_vpnv6_nlri(buffer + written, *cursor, add_path);
        if (encoded < 0) return -1;
        written += encoded;
        *cursor = (*cursor)->next;
    }

    return written;
}

// MESSAGE GENERATION with splitting support

bgp_update_result_t* bgp_generate_update_vpnv4(
    vpnv4_nlri_list_t *nlri_list,
    bgp_path_attr_t *attributes,
    vpnv4_nlri_list_t *withdrawn_list,
    uint16_t max_pdu_size,
    bgp_vpn_transport_t transport,
    const bgp_next_hop_t *next_hop)
{
    bgp_builder_t      builder = {0};
    uint8_t           *base_attr_data = NULL;
    uint16_t           base_attr_len = 0;
    uint8_t           *nlri_buffer = NULL;
    uint8_t            nh_buf[BGP_VPN_NEXT_HOP_BUF_SIZE];
    uint8_t            nh_len = 0;
    int                available_space;
    int                nlri_add_path = 0;
    int                withdrawn_add_path = 0;
    vpnv4_nlri_list_t *curr;

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

    if (bgp_detect_vpnv4_add_path(nlri_list, &nlri_add_path) < 0 ||
        bgp_detect_vpnv4_add_path(withdrawn_list, &withdrawn_add_path) < 0) {
        return NULL;
    }

    if (bgp_serialize_path_attributes_alloc(attributes,
                                            &base_attr_data,
                                            &base_attr_len) < 0) {
        return NULL;
    }

    if (nlri_list) {
        if (!bgp_validate_mp_attrs(attributes) ||
            bgp_encode_vpn_next_hop(AFI_IPV4,
                                    transport,
                                    next_hop,
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
            int nlri_len = encode_vpnv4_chunk(&curr, nlri_buffer, available_space, withdrawn_add_path);
            if (nlri_len <= 0 ||
                bgp_builder_append_mp(&builder, &(bgp_mp_args_t){
                    .afi         = AFI_IPV4,
                    .safi        = SAFI_MPLS_VPN,
                    .mp_nlri     = nlri_buffer,          /* withdrawn VPNv4 NLRI */
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
            int nlri_len = encode_vpnv4_chunk(&curr, nlri_buffer, available_space, nlri_add_path);
            if (nlri_len <= 0 ||
                bgp_builder_append_mp(&builder, &(bgp_mp_args_t){
                    .attrs       = base_attr_data,  /* origin + as_path + ... */
                    .attrs_len   = base_attr_len,
                    .is_reach    = 1,               /* MP_REACH_NLRI          */
                    .afi         = AFI_IPV4,
                    .safi        = SAFI_MPLS_VPN,
                    .next_hop    = nh_buf,          /* encoded next-hop       */
                    .nh_len      = nh_len,
                    .mp_nlri     = nlri_buffer,     /* VPNv4 NLRI             */
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

bgp_update_result_t* bgp_generate_update_vpnv6(
    vpnv6_nlri_list_t *nlri_list,
    bgp_path_attr_t *attributes,
    vpnv6_nlri_list_t *withdrawn_list,
    uint16_t max_pdu_size,
    bgp_vpn_transport_t transport,
    const bgp_next_hop_t *next_hop)
{
    bgp_builder_t      builder = {0};
    uint8_t           *base_attr_data = NULL;
    uint16_t           base_attr_len = 0;
    uint8_t           *nlri_buffer = NULL;
    uint8_t            nh_buf[BGP_VPN_NEXT_HOP_BUF_SIZE];
    uint8_t            nh_len = 0;
    int                available_space;
    int                nlri_add_path = 0;
    int                withdrawn_add_path = 0;
    vpnv6_nlri_list_t *curr;

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

    if (bgp_detect_vpnv6_add_path(nlri_list, &nlri_add_path) < 0 ||
        bgp_detect_vpnv6_add_path(withdrawn_list, &withdrawn_add_path) < 0) {
        return NULL;
    }

    if (bgp_serialize_path_attributes_alloc(attributes,
                                            &base_attr_data,
                                            &base_attr_len) < 0) {
        return NULL;
    }

    if (nlri_list) {
        if (!bgp_validate_mp_attrs(attributes) ||
            bgp_encode_vpn_next_hop(AFI_IPV6,
                                    transport,
                                    next_hop,
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
            int nlri_len = encode_vpnv6_chunk(&curr, nlri_buffer, available_space, withdrawn_add_path);
            if (nlri_len <= 0 ||
                bgp_builder_append_mp(&builder, &(bgp_mp_args_t){
                    .afi         = AFI_IPV6,
                    .safi        = SAFI_MPLS_VPN,
                    .mp_nlri     = nlri_buffer,          /* withdrawn VPNv6 NLRI */
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
            int nlri_len = encode_vpnv6_chunk(&curr, nlri_buffer, available_space, nlri_add_path);
            if (nlri_len <= 0 ||
                bgp_builder_append_mp(&builder, &(bgp_mp_args_t){
                    .attrs       = base_attr_data,  /* origin + as_path + ... */
                    .attrs_len   = base_attr_len,
                    .is_reach    = 1,               /* MP_REACH_NLRI          */
                    .afi         = AFI_IPV6,
                    .safi        = SAFI_MPLS_VPN,
                    .next_hop    = nh_buf,          /* encoded next-hop       */
                    .nh_len      = nh_len,
                    .mp_nlri     = nlri_buffer,     /* VPNv6 NLRI             */
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
