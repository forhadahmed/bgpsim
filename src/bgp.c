#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "bgp.h"
#include "log.h"
#include "bgp_router.h"
#include "bgp_neighbor.h"

/*
 * Convert BGP state enum to human-readable string
 */
const char* bgp_state_to_string(bgp_state_t state) {
    switch (state) {
        case BGP_STATE_IDLE: return "Idle";
        case BGP_STATE_CONNECT: return "Connect";
        case BGP_STATE_ACTIVE: return "Active";
        case BGP_STATE_OPENSENT: return "OpenSent";
        case BGP_STATE_OPENCONFIRM: return "OpenConfirm";
        case BGP_STATE_ESTABLISHED: return "Established";
        default: return "Unknown";
    }
}

/*
 * Look up the ADD-PATH capability field for an AFI/SAFI pair.
 */
static uint8_t *bgp_caps_add_path_slot(bgp_capabilities_t *caps, uint16_t afi, uint8_t safi) {
    const bgp_family_t *family = bgp_family_lookup(afi, safi);

    if (caps == NULL || family == NULL) {
        return NULL;
    }

    return (uint8_t *)((char *)caps + family->add_path_offset);
}

static const uint8_t *bgp_caps_add_path_slot_const(const bgp_capabilities_t *caps, uint16_t afi, uint8_t safi) {
    return bgp_caps_add_path_slot((bgp_capabilities_t *)caps, afi, safi);
}

/*
 * Return the index of an AFI/SAFI pair in bgp_families[], used as the
 * bit position in the GR family/forwarding masks.  Returns -1 if the
 * pair is not a known family.
 */
static int bgp_caps_gr_family_index(uint16_t afi, uint8_t safi) {
    const bgp_family_t *family = bgp_family_lookup(afi, safi);

    return family ? (int)(family - bgp_families) : -1;
}

/*
 * Check whether the multiprotocol capability flag is set for an
 * AFI/SAFI pair.
 */
static int bgp_caps_mp_family_enabled(const bgp_capabilities_t *caps, uint16_t afi, uint8_t safi) {
    const bgp_family_t *family = bgp_family_lookup(afi, safi);

    if (caps == NULL || family == NULL) {
        return 0;
    }

    return *(const int *)((const char *)caps + family->mp_offset);
}

static int *bgp_caps_ext_nh_slot(bgp_capabilities_t *caps,
                                 uint16_t nlri_afi, uint8_t nlri_safi,
                                 uint16_t next_hop_afi) {
    const bgp_family_t *family = bgp_family_lookup(nlri_afi, nlri_safi);

    if (caps == NULL || next_hop_afi != AFI_IPV6 ||
        family == NULL || family->ext_nh_offset == NO_CAP_OFFSET) {
        return NULL;
    }

    return (int *)((char *)caps + family->ext_nh_offset);
}

static const int *bgp_caps_ext_nh_slot_const(
    const bgp_capabilities_t *caps, uint16_t nlri_afi,
    uint8_t nlri_safi, uint16_t next_hop_afi) {
    return bgp_caps_ext_nh_slot((bgp_capabilities_t *)caps, nlri_afi, nlri_safi, next_hop_afi);
}

/*
 * ADD-PATH mode (ADD_PATH_SEND / ADD_PATH_RECEIVE bits) for a family; 0 when the family is unknown.
 */
uint8_t bgp_caps_get_add_path(const bgp_capabilities_t *caps, uint16_t afi, uint8_t safi) {
    const uint8_t *slot = bgp_caps_add_path_slot_const(caps, afi, safi);
    return slot != NULL ? *slot : 0;
}

/*
 * Set the ADD-PATH mode of a family. Unknown families and modes out of range are ignored.
 */
void bgp_caps_set_add_path(bgp_capabilities_t *caps, uint16_t afi, uint8_t safi, uint8_t mode) {
    uint8_t *slot;

    if (mode > (ADD_PATH_SEND | ADD_PATH_RECEIVE)) {
        return;
    }

    slot = bgp_caps_add_path_slot(caps, afi, safi);
    if (slot != NULL) {
        *slot = mode;
    }
}

/*
 * Return 1 when the graceful-restart capability lists this family.
 */
int bgp_caps_has_gr_family(const bgp_capabilities_t *caps, uint16_t afi, uint8_t safi) {
    int index = bgp_caps_gr_family_index(afi, safi);

    if (caps == NULL || index < 0) {
        return 0;
    }

    return (caps->gr_family_mask & (1u << index)) != 0;
}

/*
 * Graceful-restart AFI/SAFI flags of a family: 0x80 when forwarding state was kept, else 0.
 */
uint8_t bgp_caps_get_gr_flags(const bgp_capabilities_t *caps, uint16_t afi, uint8_t safi) {
    int index = bgp_caps_gr_family_index(afi, safi);

    if (caps == NULL || index < 0 ||
        (caps->gr_family_mask & (1u << index)) == 0) {
        return 0;
    }

    return (caps->gr_forwarding_mask & (1u << index)) ? 0x80 : 0;
}

/*
 * Add a family to the graceful-restart capability, with forwarding state kept when flags has 0x80. The masks have one
 * bit per bgp_families[] row, so they are 32 bits wide for 18 rows.
 */
void bgp_caps_set_gr_flags(bgp_capabilities_t *caps, uint16_t afi, uint8_t safi, uint8_t flags) {
    int      index = bgp_caps_gr_family_index(afi, safi);
    uint32_t mask;

    if (caps == NULL || index < 0) {
        return;
    }

    mask = (1u << index);
    caps->gr_family_mask |= mask;
    if (flags & 0x80) {
        caps->gr_forwarding_mask |= mask;
    } else {
        caps->gr_forwarding_mask &= ~mask;
    }
}

int bgp_caps_add_path_can_send(const bgp_capabilities_t *local_caps,
                               const bgp_capabilities_t *peer_caps,
                               uint16_t afi, uint8_t safi) {
    uint8_t local_mode = bgp_caps_get_add_path(local_caps, afi, safi);
    uint8_t peer_mode = bgp_caps_get_add_path(peer_caps, afi, safi);
    return (local_mode & ADD_PATH_SEND) && (peer_mode & ADD_PATH_RECEIVE);
}

int bgp_caps_add_path_can_recv(const bgp_capabilities_t *local_caps,
                               const bgp_capabilities_t *peer_caps,
                               uint16_t afi, uint8_t safi) {
    uint8_t local_mode = bgp_caps_get_add_path(local_caps, afi, safi);
    uint8_t peer_mode = bgp_caps_get_add_path(peer_caps, afi, safi);
    return (local_mode & ADD_PATH_RECEIVE) && (peer_mode & ADD_PATH_SEND);
}

int bgp_caps_has_ext_nh(const bgp_capabilities_t *caps, uint16_t nlri_afi, uint8_t nlri_safi, uint16_t next_hop_afi) {
    const int *slot = bgp_caps_ext_nh_slot_const(caps, nlri_afi, nlri_safi, next_hop_afi);
    return slot != NULL ? *slot : 0;
}

void bgp_caps_set_ext_nh(bgp_capabilities_t *caps,
                         uint16_t nlri_afi, uint8_t nlri_safi,
                         uint16_t next_hop_afi, int enabled) {
    int *slot = bgp_caps_ext_nh_slot(caps, nlri_afi, nlri_safi, next_hop_afi);
    if (slot != NULL) {
        *slot = enabled ? 1 : 0;
    }
}

/*
 * Begin a variable-length capability inside the single Type-2 parameter.
 * Writes the cap code and reserves one byte for cap_len (back-patched by
 * bgp_open_finish_capability).  No Type-2 parameter header is emitted --
 * the caller has already opened the parameter.
 */
static uint8_t *bgp_open_begin_capability(uint8_t *ptr,
                                          uint8_t code,
                                          uint8_t **param_len_ptr_unused,
                                          uint8_t **cap_len_ptr) {
    (void)param_len_ptr_unused;
    *ptr++ = code;
    *cap_len_ptr = ptr++;
    return ptr;
}

/*
 * Back-patch the capability length after the value bytes have been written.
 */
static void bgp_open_finish_capability(uint8_t *value_start,
                                       uint8_t *value_end,
                                       uint8_t *param_len_ptr_unused,
                                       uint8_t *cap_len_ptr) {
    (void)param_len_ptr_unused;
    size_t value_len = (size_t)(value_end - value_start);
    *cap_len_ptr = (uint8_t)value_len;
}

typedef struct {
    const uint8_t *params;
    size_t         params_len;
    size_t         param_len_size;
} bgp_open_optional_params_view_t;

static int bgp_open_get_optional_params(const uint8_t *msg, size_t msg_len, bgp_open_optional_params_view_t *view) {
    const bgp_open_t *open;
    size_t            offset = BGP_HEADER_SIZE + sizeof(bgp_open_t);
    const uint8_t    *ptr;

    if (msg == NULL || view == NULL || msg_len < offset) {
        return -1;
    }

    open = (const bgp_open_t *)(msg + BGP_HEADER_SIZE);
    memset(view, 0, sizeof(*view));

    if (open->opt_param_len == 0) {
        if (msg_len != offset) {
            return -1;
        }
        view->params = msg + offset;
        view->param_len_size = 1;
        return 0;
    }

    if (msg_len < offset + 1) {
        return -1;
    }

    ptr = msg + offset;
    if (*ptr == BGP_OPEN_EXTENDED_OPT_PARAMS_MARKER) {
        size_t ext_len;

        // RFC 9072: marker octet 255 followed by the 2-byte extended length.
        if (msg_len < offset + 3) {
            return -1;
        }

        ext_len = (size_t)(((uint16_t)ptr[1] << 8) | ptr[2]);
        if (msg_len != offset + 3 + ext_len) {
            return -1;
        }

        view->params = ptr + 3;
        view->params_len = ext_len;
        view->param_len_size = 2;
        return 0;
    }

    if (msg_len != offset + open->opt_param_len) {
        return -1;
    }

    view->params = ptr;
    view->params_len = open->opt_param_len;
    view->param_len_size = 1;
    return 0;
}

int bgp_build_keepalive(uint8_t *buffer, size_t buffer_size) {
    bgp_header_t *hdr;

    if (!buffer || buffer_size < BGP_HEADER_SIZE) {
        return -1;
    }

    hdr = (bgp_header_t *)buffer;
    memset(hdr->marker, 0xFF, BGP_MARKER_SIZE);
    hdr->length = htons(BGP_HEADER_SIZE);
    hdr->type = BGP_MSG_KEEPALIVE;
    return BGP_HEADER_SIZE;
}

void bgp_open_set_hold_time(uint8_t *open_message, uint16_t seconds) {
    ((bgp_open_t *)(open_message + BGP_HEADER_SIZE))->hold_time = htons(seconds);
}

int bgp_build_notification(uint8_t *buffer, size_t buffer_size, uint8_t error_code, uint8_t error_subcode) {
    bgp_header_t       *hdr;
    bgp_notification_t *notif;

    if (!buffer || buffer_size < BGP_HEADER_SIZE + sizeof(bgp_notification_t)) {
        return -1;
    }

    hdr = (bgp_header_t *)buffer;
    notif = (bgp_notification_t *)(buffer + BGP_HEADER_SIZE);
    memset(hdr->marker, 0xFF, BGP_MARKER_SIZE);
    hdr->length = htons(BGP_HEADER_SIZE + sizeof(bgp_notification_t));
    hdr->type = BGP_MSG_NOTIFICATION;
    notif->error_code = error_code;
    notif->error_subcode = error_subcode;
    return BGP_HEADER_SIZE + (int)sizeof(bgp_notification_t);
}

/*
 * Build BGP OPEN message with capabilities
 * Returns: message length on success, -1 on error
 */
int bgp_build_open_with_capabilities(uint8_t *buffer,
                                     size_t buffer_size,
                                     uint32_t my_as,
                                     uint32_t router_id,
                                     bgp_capabilities_t *caps) {
    uint8_t  capability_payload[BGP_MAX_MESSAGE_SIZE];
    int      four_byte_asn_enabled;
    uint8_t *ptr = capability_payload;
    uint8_t *cap_len_ptr = NULL;
    uint8_t *value_start = NULL;
    size_t   cap_payload_len;
    size_t   opt_params_len;
    int      use_extended_open;
    size_t   total_len;

    if (buffer == NULL || caps == NULL ||
        buffer_size < BGP_HEADER_SIZE + sizeof(bgp_open_t)) {
        log_write("Invalid OPEN buffer or capabilities");
        return -1;
    }

    four_byte_asn_enabled = caps->four_byte_asn;
    if (!four_byte_asn_enabled && my_as > 65535U) {
        log_write("Cannot encode local AS %u without four-byte ASN capability", my_as);
        return -1;
    }

    /*
     * Helper: write a fixed-length capability header into the capability
     * payload. The outer optional-parameter wrapper is added later once we
     * know whether RFC 9072 extended OPEN encoding is required.
     */
    #define ADD_CAPABILITY(code, len)               \
        do {                                        \
            *ptr++ = (code); /* Capability Code */  \
            *ptr++ = (len); /* Capability Length */ \
        } while (0)

    // Capability 1: Multiprotocol BGP -- one tuple per enabled family
    for (int i = 0; i < BGP_NUM_FAMILIES; i++) {
        int enabled = *(const int *)((const char *)caps + bgp_families[i].mp_offset);
        if (enabled) {
            ADD_CAPABILITY(BGP_CAP_MP_BGP, 4);
            *ptr++ = (bgp_families[i].afi >> 8) & 0xFF;
            *ptr++ = bgp_families[i].afi & 0xFF;
            *ptr++ = 0; /* Reserved */
            *ptr++ = bgp_families[i].safi;
        }
    }

    // Capability 2: Route Refresh
    if (caps->route_refresh) {
        ADD_CAPABILITY(BGP_CAP_ROUTE_REFRESH, 0);
    }

    // Capability 6: Extended Message (RFC 8654 section 3: no value)
    if (caps->extended_message) {
        ADD_CAPABILITY(BGP_CAP_EXTENDED_MESSAGE, 0);
    }

    // Capability 64: Graceful Restart
    if (caps->graceful_restart) {
        ptr = bgp_open_begin_capability(ptr, BGP_CAP_GRACEFUL_RESTART, NULL, &cap_len_ptr);
        value_start = ptr;

        // High 4 bits are flags, low 12 bits are restart time.
        *ptr++ = (caps->restart_time >> 8) & 0x0F;
        *ptr++ = caps->restart_time & 0xFF;

        for (int i = 0; i < BGP_NUM_FAMILIES; i++) {
            uint16_t afi = bgp_families[i].afi;
            uint8_t  safi = bgp_families[i].safi;

            if (!bgp_caps_mp_family_enabled(caps, afi, safi)) {
                continue;
            }

            *ptr++ = (uint8_t)((afi >> 8) & 0xFF);
            *ptr++ = (uint8_t)(afi & 0xFF);
            *ptr++ = safi;
            *ptr++ = bgp_caps_get_gr_flags(caps, afi, safi);
        }

        bgp_open_finish_capability(value_start, ptr, NULL, cap_len_ptr);
    }

    // Capability 65: 4-byte ASN
    if (four_byte_asn_enabled) {
        ADD_CAPABILITY(BGP_CAP_4BYTE_ASN, 4);
        *ptr++ = (my_as >> 24) & 0xFF;
        *ptr++ = (my_as >> 16) & 0xFF;
        *ptr++ = (my_as >> 8) & 0xFF;
        *ptr++ = my_as & 0xFF;
    }

    // RFC 7911 requires all AFI/SAFI tuples to live in one capability.
    value_start = ptr;
    cap_len_ptr = NULL;
    for (int i = 0; i < BGP_NUM_FAMILIES; i++) {
        if (!bgp_caps_mp_family_enabled(caps,
                                        bgp_families[i].afi,
                                        bgp_families[i].safi)) {
            continue;
        }

        uint8_t mode = bgp_caps_get_add_path(caps, bgp_families[i].afi, bgp_families[i].safi);
        if (mode == 0) {
            continue;
        }
        if (cap_len_ptr == NULL) {
            ptr = bgp_open_begin_capability(ptr, BGP_CAP_ADD_PATH, NULL, &cap_len_ptr);
            value_start = ptr;
        }

        *ptr++ = (uint8_t)((bgp_families[i].afi >> 8) & 0xFF);
        *ptr++ = (uint8_t)(bgp_families[i].afi & 0xFF);
        *ptr++ = bgp_families[i].safi;
        *ptr++ = mode;
    }
    if (cap_len_ptr != NULL) {
        bgp_open_finish_capability(value_start, ptr, NULL, cap_len_ptr);
    }

    /*
     * RFC 8950 serializes capability tuples as <NLRI AFI, NLRI SAFI,
     * Next-hop AFI> with SAFI carried on two octets inside the capability.
     */
    value_start = ptr;
    cap_len_ptr = NULL;
    for (int i = 0; i < BGP_NUM_FAMILIES; i++) {
        const bgp_family_t *family = &bgp_families[i];

        if (!bgp_caps_mp_family_enabled(caps, family->afi, family->safi) ||
            !bgp_caps_has_ext_nh(caps, family->afi, family->safi, AFI_IPV6)) {
            continue;
        }
        if (cap_len_ptr == NULL) {
            ptr = bgp_open_begin_capability(ptr, BGP_CAP_EXTENDED_NEXTHOP, NULL, &cap_len_ptr);
            value_start = ptr;
        }

        *ptr++ = (uint8_t)((family->afi >> 8) & 0xFF);
        *ptr++ = (uint8_t)(family->afi & 0xFF);
        *ptr++ = 0;
        *ptr++ = family->safi;
        *ptr++ = 0;
        *ptr++ = AFI_IPV6;
    }
    if (cap_len_ptr != NULL) {
        bgp_open_finish_capability(value_start, ptr, NULL, cap_len_ptr);
    }

    #undef ADD_CAPABILITY

    cap_payload_len = (size_t)(ptr - capability_payload);
    if (cap_payload_len > UINT16_MAX) {
        log_write("OPEN capability payload too large: %zu", cap_payload_len);
        return -1;
    }

    /*
     * Legacy OPEN allows only a one-octet optional-parameters length.
     * Switch to RFC 9072 extended encoding once the single Type-2 wrapper
     * would exceed that limit.
     */
    use_extended_open = (cap_payload_len + 2) > UINT8_MAX;
    opt_params_len = cap_payload_len == 0 ? 0 :
                     cap_payload_len + (use_extended_open ? 3 : 2);
    total_len = BGP_HEADER_SIZE + sizeof(bgp_open_t) +
                (use_extended_open ? 3 : 0) + opt_params_len;

    if (total_len > buffer_size) {
        log_write("Buffer too small for OPEN message");
        return -1;
    }

    ptr = buffer;

    // Build BGP header (fill length later)
    bgp_header_t *hdr = (bgp_header_t *)ptr;
    memset(hdr->marker, 0xFF, BGP_MARKER_SIZE);
    hdr->type = BGP_MSG_OPEN;
    ptr += BGP_HEADER_SIZE;

    // Build OPEN message
    bgp_open_t *open = (bgp_open_t *)ptr;
    open->version = BGP_VERSION;

    /*
     * NEW speakers advertise capability 65 even when the local AS fits in the
     * 16-bit OPEN field. AS_TRANS is only required when the ASN itself does
     * not fit there.
     */
    if (my_as > 65535U) {
        open->my_as = htons(AS_TRANS);
    } else {
        open->my_as = htons((uint16_t)my_as);
    }

    open->hold_time = htons(BGP_HOLD_TIME);
    open->bgp_identifier = htonl(router_id);
    ptr += sizeof(bgp_open_t);

    if (cap_payload_len == 0) {
        open->opt_param_len = 0;
    } else if (use_extended_open) {
        /*
         * RFC 9072 adds a three-octet prefix after opt_param_len:
         * marker 255 plus the 2-byte extended optional-parameters length.
         */
        open->opt_param_len = BGP_OPEN_EXTENDED_OPT_PARAMS_MARKER;
        *ptr++ = BGP_OPEN_EXTENDED_OPT_PARAMS_MARKER;
        *ptr++ = (uint8_t)((opt_params_len >> 8) & 0xFF);
        *ptr++ = (uint8_t)(opt_params_len & 0xFF);
        *ptr++ = 2; /* Parameter Type = Capability */
        *ptr++ = (uint8_t)((cap_payload_len >> 8) & 0xFF);
        *ptr++ = (uint8_t)(cap_payload_len & 0xFF);
    } else {
        open->opt_param_len = (uint8_t)opt_params_len;
        *ptr++ = 2; /* Parameter Type = Capability */
        *ptr++ = (uint8_t)cap_payload_len;
    }

    if (cap_payload_len > 0) {
        memcpy(ptr, capability_payload, cap_payload_len);
        ptr += cap_payload_len;
    }

    // Set total message length in header
    total_len = (size_t)(ptr - buffer);
    hdr->length = htons((uint16_t)total_len);

    return (int)total_len;
}

int bgp_parse_open_message(const uint8_t *msg, size_t msg_len,
                           const bgp_capabilities_t *local_caps,
                           bgp_open_info_t *open_info) {
    const bgp_open_t               *open;
    bgp_open_optional_params_view_t opt_view;
    uint32_t                        remote_as_4byte = 0;
    int                             peer_supports_4byte_asn = 0;

    if (!open_info) {
        return -1;
    }
    memset(open_info, 0, sizeof(*open_info));
    if (!msg || msg_len < BGP_HEADER_SIZE + sizeof(bgp_open_t)) {
        return -1;
    }
    open = (const bgp_open_t *)(msg + BGP_HEADER_SIZE);

    if (open->version != BGP_VERSION) {
        open_info->error_subcode = BGP_OPEN_ERR_UNSUPPORTED_VERSION;
        return -1;
    }

    open_info->remote_as = ntohs(open->my_as);
    open_info->hold_time = ntohs(open->hold_time);
    open_info->remote_id = ntohl(open->bgp_identifier);
    if (open_info->hold_time == 1 || open_info->hold_time == 2) {
        open_info->error_subcode = BGP_OPEN_ERR_UNACCEPTABLE_HOLD;
        return -1;
    }
    if (open_info->remote_id == 0) {
        open_info->error_subcode = BGP_OPEN_ERR_BAD_IDENTIFIER;
        return -1;
    }

    if (bgp_open_get_optional_params(msg, msg_len, &opt_view) != 0) {
        return -1;
    }

    if (opt_view.params_len > 0) {
        const uint8_t *ptr = opt_view.params;
        const uint8_t *end = ptr + opt_view.params_len;

        while (ptr < end) {
            if ((size_t)(end - ptr) < 1 + opt_view.param_len_size) {
                return -1;
            }
            uint8_t param_type = *ptr++;
            size_t  param_len;

            if (opt_view.param_len_size == 1) {
                param_len = *ptr++;
            } else {
                param_len = (size_t)(((uint16_t)ptr[0] << 8) | ptr[1]);
                ptr += 2;
            }

            if (param_len > (size_t)(end - ptr)) {
                return -1;
            }
            if (param_type != 2) {
                open_info->error_subcode = BGP_OPEN_ERR_UNSUPPORTED_PARAMETER;
                return -1;
            }
            if (param_len < 2) {
                return -1;
            }

            if (param_type == 2 && param_len >= 2) {  /* Capability parameter */
                // A capability parameter can contain multiple capabilities
                const uint8_t *param_end = ptr + param_len;

                while (ptr < param_end) {
                    if ((size_t)(param_end - ptr) < 2) {
                        return -1;
                    }
                    uint8_t cap_code = *ptr++;
                    uint8_t cap_len = *ptr++;

                    // Ensure we don't read past the parameter boundary
                    if (cap_len > (size_t)(param_end - ptr)) {
                        return -1;
                    }

                    switch (cap_code) {
                        case BGP_CAP_MP_BGP:  /* Multiprotocol BGP */
                            open_info->mp_capability_received = 1;
                            if (cap_len >= 4) {
                                uint16_t afi = (uint16_t)((ptr[0] << 8) | ptr[1]);
                                uint8_t  safi = ptr[3];

                                for (int i = 0; i < BGP_NUM_FAMILIES; i++) {
                                    if (bgp_families[i].afi == afi &&
                                        bgp_families[i].safi == safi) {
                                        *(int *)((char *)&open_info->capabilities + bgp_families[i].mp_offset) = 1;
                                        break;
                                    }
                                }
                            }
                            break;

                        case BGP_CAP_ROUTE_REFRESH:  /* Route refresh */
                            open_info->capabilities.route_refresh = 1;
                            break;

                        case BGP_CAP_EXTENDED_MESSAGE:
                            open_info->capabilities.extended_message = 1;
                            break;

                        case BGP_CAP_GRACEFUL_RESTART:  /* Graceful restart */
                            if (cap_len >= 2) {
                                size_t offset;

                                open_info->capabilities.graceful_restart = 1;
                                open_info->capabilities.restart_time =
                                    (uint16_t)(((ptr[0] & 0x0F) << 8) | ptr[1]);
                                // RFC 4724 section 3: only the last instance counts, family tuples included.
                                open_info->capabilities.gr_family_mask = 0;
                                open_info->capabilities.gr_forwarding_mask = 0;

                                for (offset = 2; offset + 4 <= cap_len; offset += 4) {
                                    uint16_t afi_gr =
                                        (uint16_t)((ptr[offset] << 8) | ptr[offset + 1]);
                                    uint8_t safi_gr = ptr[offset + 2];
                                    uint8_t flags_gr = ptr[offset + 3];

                                    bgp_caps_set_gr_flags(&open_info->capabilities, afi_gr, safi_gr, flags_gr);
                                }
                            }
                            break;

                        case BGP_CAP_4BYTE_ASN:
                            if (cap_len >= 4) {
                                peer_supports_4byte_asn = 1;
                                open_info->capabilities.four_byte_asn = 1;
                                remote_as_4byte = ((uint32_t)ptr[0] << 24) |
                                                  ((uint32_t)ptr[1] << 16) |
                                                  ((uint32_t)ptr[2] << 8) |
                                                  (uint32_t)ptr[3];
                            }
                            break;

                        case BGP_CAP_ADD_PATH:  /* ADD-PATH */
                            for (size_t offset = 0; offset + 4 <= cap_len; offset += 4) {
                                uint16_t afi_ap =
                                    (uint16_t)((ptr[offset] << 8) | ptr[offset + 1]);
                                uint8_t safi_ap = ptr[offset + 2];
                                uint8_t send_receive = ptr[offset + 3];

                                if (send_receive > (ADD_PATH_SEND | ADD_PATH_RECEIVE)) {
                                    continue;
                                }
                                bgp_caps_set_add_path(
                                    &open_info->capabilities,  /* caps */
                                    afi_ap,                    /* afi  */
                                    safi_ap,                   /* safi */
                                    send_receive);             /* mode */
                            }
                            break;

                        case BGP_CAP_EXTENDED_NEXTHOP:  /* RFC 8950 */
                            for (size_t offset = 0; offset + 6 <= cap_len; offset += 6) {
                                uint16_t nlri_afi =
                                    (uint16_t)((ptr[offset] << 8) | ptr[offset + 1]);
                                uint16_t safi_field =
                                    (uint16_t)((ptr[offset + 2] << 8) | ptr[offset + 3]);
                                uint16_t next_hop_afi =
                                    (uint16_t)((ptr[offset + 4] << 8) | ptr[offset + 5]);

                                if (safi_field > UINT8_MAX) {
                                    continue;
                                }
                                bgp_caps_set_ext_nh(
                                    &open_info->capabilities,  /* caps         */
                                    nlri_afi,                  /* nlri_afi     */
                                    (uint8_t)safi_field,       /* nlri_safi    */
                                    next_hop_afi,              /* next_hop_afi */
                                    1);                        /* enabled      */
                            }
                            break;
                    }

                    ptr += cap_len;
                }

                // Ensure we're at the end of this parameter
                ptr = param_end;
            } else {
                ptr += param_len;
            }
        }
    }

    open_info->peer_supports_4byte_asn = peer_supports_4byte_asn;
    if (local_caps && local_caps->four_byte_asn &&
        peer_supports_4byte_asn &&
        remote_as_4byte != 0) {
        open_info->remote_as = remote_as_4byte;
    }

    return 0;
}

/*
 * Shared OPEN policy and state application; the caller owns notification I/O.
 */
int bgp_accept_open(bgp_router_t *router, bgp_neighbor_t *neighbor, const uint8_t *msg,
                     size_t msg_len, bgp_open_info_t *open_info) {
    if (bgp_parse_open_message(msg, msg_len, &neighbor->capabilities, open_info) != 0) return -1;
    if (open_info->remote_as != neighbor->remote_as) {
        open_info->error_subcode = BGP_OPEN_ERR_BAD_PEER_AS;
        return -1;
    }
    if (router && open_info->remote_as == router->local_as && open_info->remote_id == router->router_id) {
        open_info->error_subcode = BGP_OPEN_ERR_BAD_IDENTIFIER;
        return -1;
    }
    neighbor->peer_capabilities = open_info->capabilities;
    neighbor->peer_capabilities_received = 1;
    neighbor->peer_mp_capability_received = open_info->mp_capability_received;
    neighbor->remote_id = open_info->remote_id;
    // RFC 4271 section 4.2: the smaller of the two proposed hold times.
    neighbor->hold_time = open_info->hold_time < neighbor->hold_time_config ? open_info->hold_time
                                                                           : neighbor->hold_time_config;
    neighbor->last_msg_time = time(NULL);
    return 0;
}
