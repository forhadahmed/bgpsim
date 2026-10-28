// BGP UPDATE Message Generation - VPLS (RFC 4761)

#define OUTPUT_STDIO_REMAP

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "bgp.h"
#include "output.h"
#include "bgp_update.h"

// VPLS NLRI Functions (RFC 4761)

static vpls_nlri_list_t* vpls_nlri_create_internal(route_distinguisher_t rd,
                                                    uint16_t ve_id,
                                                    uint16_t ve_block_offset,
                                                    uint16_t ve_block_size,
                                                    uint32_t label_base,
                                                    int add_path,
                                                    uint32_t path_id) {
    vpls_nlri_list_t *nlri = calloc(1, sizeof(vpls_nlri_list_t));

    if (!nlri) {
        return NULL;
    }

    /*
     * RFC 4761 carries a 2-octet NLRI Length field whose value excludes the
     * Length field itself. For VPLS that value is always 17, while the fully
     * encoded NLRI occupies 19 bytes on the wire.
     */
    nlri->prefix.length = 17;
    nlri->prefix.rd = rd;
    nlri->prefix.ve_id = ve_id;
    nlri->prefix.ve_block_offset = ve_block_offset;
    nlri->prefix.ve_block_size = ve_block_size;
    nlri->prefix.label_base.label = label_base;
    nlri->prefix.label_base.tc = 0;
    nlri->prefix.label_base.s = 1;  /* Bottom of stack */
    nlri->prefix.label_base.ttl = 0;

    nlri->path_id = path_id;
    nlri->add_path = (uint8_t)(add_path ? 1 : 0);
    nlri->next = NULL;

    return nlri;
}

/*
 * Create a VPLS NLRI.
 */
vpls_nlri_list_t* vpls_nlri_create(route_distinguisher_t rd,
                                   uint16_t ve_id,
                                   uint16_t ve_block_offset,
                                   uint16_t ve_block_size,
                                   uint32_t label_base) {
    return vpls_nlri_create_internal(rd, ve_id, ve_block_offset, ve_block_size, label_base, 0, 0);
}

/*
 * Create a VPLS NLRI with ADD-PATH path ID.
 */
vpls_nlri_list_t* vpls_nlri_create_path_id(route_distinguisher_t rd,
                                           uint16_t ve_id,
                                           uint16_t ve_block_offset,
                                           uint16_t ve_block_size,
                                           uint32_t label_base,
                                           uint32_t path_id) {
    return vpls_nlri_create_internal(rd, ve_id, ve_block_offset, ve_block_size, label_base, 1, path_id);
}

DEFINE_NLRI_LIST_UTILS(vpls_nlri_list_t, vpls_nlri)

/*
 * Encode a VPLS prefix into the wire format per RFC 4761.
 * Returns the number of bytes written (always 19).
 */
int bgp_encode_vpls_prefix(uint8_t *buffer, vpls_prefix_t *prefix) {
    int offset = 0;
    if (!buffer || !prefix || prefix->length != 17 || prefix->rd.type > 2 ||
        prefix->label_base.label > 0xFFFFF) return -1;

    // NLRI Length (2 bytes, network byte order, value = 17)
    uint16_t length_net = htons(prefix->length);
    memcpy(buffer + offset, &length_net, 2);
    offset += 2;

    // RD (8 bytes)
    bgp_encode_rd(buffer + offset, &prefix->rd);
    offset += 8;

    // VE ID (2 bytes, network byte order)
    uint16_t ve_id_net = htons(prefix->ve_id);
    memcpy(buffer + offset, &ve_id_net, 2);
    offset += 2;

    // VE Block Offset (2 bytes, network byte order)
    uint16_t ve_block_offset_net = htons(prefix->ve_block_offset);
    memcpy(buffer + offset, &ve_block_offset_net, 2);
    offset += 2;

    // VE Block Size (2 bytes, network byte order)
    uint16_t ve_block_size_net = htons(prefix->ve_block_size);
    memcpy(buffer + offset, &ve_block_size_net, 2);
    offset += 2;

    // Label Base (3 bytes, MPLS label encoding)
    bgp_encode_mpls_label(buffer + offset, &prefix->label_base);
    offset += 3;

    return offset;
}

// Extended Community Helper

/*
 * Create a Layer2 Info Extended Community (type 0x800A, RFC 4761).
 * Encoded as: type(2) + encap_type(1) + control_flags(1) + MTU(2) + rsvd(2).
 * The helper leaves encapsulation and control-flag choices to the caller so
 * the test tool can exercise the different valid RFC 4761 combinations.
 */
bgp_path_attr_t* bgp_attr_create_ext_comm_l2info(uint8_t encap_type, uint8_t control_flags, uint16_t mtu) {
    // Extended Community Type: 0x800A (VPLS Layer2 Info)
    bgp_path_attr_t *attr = bgp_attr_alloc_ext_comm(0x80, 0x0A);

    if (!attr) {
        return NULL;
    }

    // Encapsulation Type
    attr->value[2] = encap_type;

    // Control Flags
    attr->value[3] = control_flags;

    // Layer-2 MTU (2 bytes, network byte order)
    uint16_t mtu_net = htons(mtu);
    memcpy(attr->value + 4, &mtu_net, 2);

    // Reserved (2 bytes, must be zero)
    attr->value[6] = 0;
    attr->value[7] = 0;

    return attr;
}

// ADD-PATH Detector

DEFINE_ADD_PATH_DETECTOR(bgp_detect_vpls_add_path, vpls_nlri_list_t, do { } while (0))

// Per-NLRI Wire Encoder

static int bgp_encode_vpls_nlri(uint8_t *buffer, const vpls_nlri_list_t *nlri, int add_path) {
    int offset = 0;

    if (add_path) {
        uint32_t path_id_net = htonl(nlri->path_id);

        memcpy(buffer + offset, &path_id_net, sizeof(path_id_net));
        offset += sizeof(path_id_net);
    }

    int len = bgp_encode_vpls_prefix(buffer + offset, (vpls_prefix_t *)&nlri->prefix);
    return len < 0 ? -1 : offset + len;
}

// Chunk Encoder

static int encode_vpls_chunk(vpls_nlri_list_t **cursor, uint8_t *buffer, int max_bytes, int add_path) {
    int written = 0;

    while (*cursor) {
        /*
         * VPLS NLRI is fixed size: length(2) + RD(8) + VE_ID(2) + offset(2) +
         * size(2) + label(3) = 19 bytes
         */
        int needed = 19;

        if ((int)(*cursor)->add_path != add_path) {
            return -1;
        }
        if (add_path) {
            needed += 4;
        }

        if (written + needed > max_bytes) {
            return (written > 0) ? written : -1;
        }

        int encoded = bgp_encode_vpls_nlri(buffer + written, *cursor, add_path);
        if (encoded < 0) return -1;
        written += encoded;
        *cursor = (*cursor)->next;
    }

    return written;
}

// MESSAGE GENERATION with splitting support

bgp_update_result_t* bgp_generate_update_vpls(
    vpls_nlri_list_t *nlri_list,
    bgp_path_attr_t *attributes,
    vpls_nlri_list_t *withdrawn_list,
    uint16_t max_pdu_size,
    const bgp_next_hop_t *next_hop)
{
    bgp_builder_t     builder = {0};
    uint8_t          *base_attr_data = NULL;
    uint16_t          base_attr_len = 0;
    uint8_t          *nlri_buffer = NULL;
    uint8_t           nh_buf[BGP_STANDARD_NEXT_HOP_BUF_SIZE];
    uint8_t           nh_len = 0;
    int               available_space;
    int               nlri_add_path = 0;
    int               withdrawn_add_path = 0;
    vpls_nlri_list_t *curr;

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

    if (bgp_detect_vpls_add_path(nlri_list, &nlri_add_path) < 0 ||
        bgp_detect_vpls_add_path(withdrawn_list, &withdrawn_add_path) < 0) {
        return NULL;
    }

    if (bgp_serialize_path_attributes_alloc(attributes,
                                            &base_attr_data,
                                            &base_attr_len) < 0) {
        return NULL;
    }

    if (nlri_list) {
        if (!bgp_validate_mp_attrs(attributes) ||
            bgp_encode_standard_next_hop(next_hop, nh_buf, &nh_len) < 0) {
            goto fail;
        }
        /*
         * RFC 4761 only describes 4-octet IPv4 and 16-octet IPv6 next
         * hops for VPLS. Keep that strict default here; a later
         * protocol-fuzz mode can make this RFC conformance check
         * conditional instead of removing it outright.
         */
        // TODO(FUZZ_GATE): Allow the 32-octet IPv6 global+link-local form.
        if (nh_len == 32) {
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
            int nlri_len = encode_vpls_chunk(&curr, nlri_buffer, available_space, withdrawn_add_path);
            if (nlri_len <= 0 ||
                bgp_builder_append_mp(&builder, &(bgp_mp_args_t){
                    .afi         = AFI_L2VPN,
                    .safi        = SAFI_VPLS,
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
            int nlri_len = encode_vpls_chunk(&curr, nlri_buffer, available_space, nlri_add_path);
            if (nlri_len <= 0 ||
                bgp_builder_append_mp(&builder, &(bgp_mp_args_t){
                    .attrs       = base_attr_data,
                    .attrs_len   = base_attr_len,
                    .is_reach    = 1,
                    .afi         = AFI_L2VPN,
                    .safi        = SAFI_VPLS,
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
