// BGP UPDATE Message Generation - RTC (RFC 4684)

#define OUTPUT_STDIO_REMAP

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "bgp.h"
#include "output.h"
#include "bgp_update.h"

// RTC NLRI Functions (RFC 4684)

static rtc_nlri_list_t* rtc_nlri_create_internal(uint32_t origin_as,
                                                  const uint8_t *rt_data,
                                                  uint8_t rt_len,
                                                  int add_path,
                                                  uint32_t path_id) {
    rtc_nlri_list_t *nlri;

    /*
     * This helper currently exposes octet-aligned Route Target prefixes only.
     * RFC 4684 allows membership lengths 32-96 plus the zero-length default,
     * so sub-octet RT prefix support remains follow-up work at this layer.
     */
    // rt_len must be 0..8; total prefix_len is zero or 32..96.
    if (rt_len > 8 || (rt_len && !rt_data)) {
        return NULL;
    }

    nlri = calloc(1, sizeof(rtc_nlri_list_t));
    if (!nlri) {
        return NULL;
    }

    memset(nlri, 0, sizeof(*nlri));

    if (rt_len == 0 && origin_as == 0) {
        // Default RTC route: prefix_len = 0
        nlri->prefix.prefix_len = 0;
    } else {
        nlri->prefix.prefix_len = 32 + (rt_len * 8);  /* origin_as bits + RT bits */
        nlri->prefix.origin_as = htonl(origin_as);
        if (rt_data && rt_len > 0) {
            memcpy(nlri->prefix.route_target, rt_data, rt_len);
        }
    }

    nlri->path_id = path_id;
    nlri->add_path = (uint8_t)(add_path ? 1 : 0);
    nlri->next = NULL;

    return nlri;
}

/*
 * Create an RTC NLRI with a specific origin AS and route target.
 */
rtc_nlri_list_t* rtc_nlri_create(uint32_t origin_as, const uint8_t *rt_data, uint8_t rt_len) {
    return rtc_nlri_create_internal(origin_as, rt_data, rt_len, 0, 0);
}

/*
 * Create an RTC NLRI with ADD-PATH path ID.
 */
rtc_nlri_list_t* rtc_nlri_create_path_id(uint32_t origin_as, const uint8_t *rt_data, uint8_t rt_len, uint32_t path_id) {
    return rtc_nlri_create_internal(origin_as, rt_data, rt_len, 1, path_id);
}

/*
 * Create an RTC default route (prefix_len = 0).
 */
rtc_nlri_list_t* rtc_nlri_create_default(void) {
    return rtc_nlri_create_internal(0, NULL, 0, 0, 0);
}

/*
 * Create an RTC default route with ADD-PATH path ID.
 */
rtc_nlri_list_t* rtc_nlri_create_default_path_id(uint32_t path_id) {
    return rtc_nlri_create_internal(0, NULL, 0, 1, path_id);
}

DEFINE_NLRI_LIST_UTILS(rtc_nlri_list_t, rtc_nlri)

static int rtc_prefix_length_valid(uint8_t bits) {
    return bits == 0 || (bits >= 32 && bits <= 96);
}

/*
 * Encode an RTC prefix into the wire format per RFC 4684.
 * Returns the number of bytes written.
 */
int bgp_encode_rtc_prefix(uint8_t *buffer, rtc_prefix_t *prefix) {
    if (!buffer || !prefix || !rtc_prefix_length_valid(prefix->prefix_len)) return -1;
    int bytes = (prefix->prefix_len + 7) / 8;
    buffer[0] = prefix->prefix_len;
    if (!bytes) return 1;
    memcpy(buffer + 1, &prefix->origin_as, 4);
    if (bytes > 4) memcpy(buffer + 5, prefix->route_target, (size_t)(bytes - 4));
    if (prefix->prefix_len % 8) buffer[bytes] &= (uint8_t)(0xFF << (8 - prefix->prefix_len % 8));
    return 1 + bytes;
}

// RTC Extended Community Helper

/*
 * Create an RTC Route Target Extended Community.
 * This is just the standard RT ext community used in RTC context.
 */

// ADD-PATH Detector

DEFINE_ADD_PATH_DETECTOR(bgp_detect_rtc_add_path, rtc_nlri_list_t, do { } while (0))

// Per-NLRI Wire Encoder

static int bgp_encode_rtc_nlri(uint8_t *buffer, const rtc_nlri_list_t *nlri, int add_path) {
    int offset = 0;

    if (add_path) {
        uint32_t path_id_net = htonl(nlri->path_id);

        memcpy(buffer + offset, &path_id_net, sizeof(path_id_net));
        offset += sizeof(path_id_net);
    }

    int len = bgp_encode_rtc_prefix(buffer + offset, (rtc_prefix_t *)&nlri->prefix);
    return len < 0 ? -1 : offset + len;
}

// Chunk Encoder

static int encode_rtc_chunk(rtc_nlri_list_t **cursor, uint8_t *buffer, int max_bytes, int add_path) {
    int written = 0;

    while (*cursor) {
        if (!rtc_prefix_length_valid((*cursor)->prefix.prefix_len)) return -1;
        int needed = 1 + ((*cursor)->prefix.prefix_len + 7) / 8;

        if ((int)(*cursor)->add_path != add_path) {
            return -1;
        }
        if (add_path) {
            needed += 4;
        }

        if (written + needed > max_bytes) {
            return (written > 0) ? written : -1;
        }

        int encoded = bgp_encode_rtc_nlri(buffer + written, *cursor, add_path);
        if (encoded <= 0) {
            return -1;
        }
        written += encoded;
        *cursor = (*cursor)->next;
    }

    return written;
}

// MESSAGE GENERATION with splitting support

bgp_update_result_t* bgp_generate_update_rtc(
    rtc_nlri_list_t *nlri_list,
    bgp_path_attr_t *attributes,
    rtc_nlri_list_t *withdrawn_list,
    uint16_t max_pdu_size,
    const bgp_next_hop_t *next_hop)
{
    bgp_builder_t    builder = {0};
    uint8_t         *base_attr_data = NULL;
    uint16_t         base_attr_len = 0;
    uint8_t         *nlri_buffer = NULL;
    uint8_t          nh_buf[BGP_STANDARD_NEXT_HOP_BUF_SIZE];
    uint8_t          nh_len = 0;
    int              available_space;
    int              nlri_add_path = 0;
    int              withdrawn_add_path = 0;
    rtc_nlri_list_t *curr;

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

    if (bgp_detect_rtc_add_path(nlri_list, &nlri_add_path) < 0 ||
        bgp_detect_rtc_add_path(withdrawn_list, &withdrawn_add_path) < 0) {
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
         * RFC 4684 constrains RTC MP_REACH next hop length to 4 octets
         * for IPv4 or 16 octets for IPv6. Keep the strict behavior by
         * default; a future protocol-fuzz mode could make this gate
         * conditional when we intentionally want malformed vectors.
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
            int nlri_len = encode_rtc_chunk(&curr, nlri_buffer, available_space, withdrawn_add_path);
            if (nlri_len <= 0 ||
                bgp_builder_append_mp(&builder, &(bgp_mp_args_t){
                    .afi         = AFI_IPV4,
                    .safi        = SAFI_RTC,
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
            int nlri_len = encode_rtc_chunk(&curr, nlri_buffer, available_space, nlri_add_path);
            if (nlri_len <= 0 ||
                bgp_builder_append_mp(&builder, &(bgp_mp_args_t){
                    .attrs       = base_attr_data,
                    .attrs_len   = base_attr_len,
                    .is_reach    = 1,
                    .afi         = AFI_IPV4,
                    .safi        = SAFI_RTC,
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
