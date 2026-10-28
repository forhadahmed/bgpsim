#ifndef BGPSIM_TEST_WIRE_H
#define BGPSIM_TEST_WIRE_H

#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include "bgp.h"

/*
 * Independent test-side readers, never the encoder's serialization helpers.
 */
static inline uint16_t read_u16(const uint8_t *ptr) {
    uint16_t value;
    memcpy(&value, ptr, sizeof(value));
    return ntohs(value);
}

static inline uint32_t read_u32(const uint8_t *ptr) {
    uint32_t value;
    memcpy(&value, ptr, sizeof(value));
    return ntohl(value);
}

/*
 * The 20-bit label of a 3-octet label entry (RFC 3032); TC and S are dropped.
 */
static inline uint32_t decode_wire_label(const uint8_t *data) {
    return ((uint32_t)data[0] << 12) |
           ((uint32_t)data[1] << 4) |
           ((uint32_t)data[2] >> 4);
}

/*
 * 1 when the 8-octet route distinguisher at p has this type, administrator and assigned number (RFC 4364 section
 * 4.2): type 0 is a two-octet AS and a four-octet number, types 1 and 2 a four-octet IPv4 address or AS and a
 * two-octet number.
 */
static inline int test_wire_rd_is(const uint8_t *p, uint16_t type, uint32_t admin, uint32_t assigned) {
    if (read_u16(p) != type) return 0;
    if (type == 0) return read_u16(p + 2) == admin && read_u32(p + 4) == assigned;
    return read_u32(p + 2) == admin && read_u16(p + 6) == assigned;
}

static inline int test_wire_update_header(const uint8_t *msg, size_t size) {
    if (!msg || size < BGP_HEADER_SIZE + 4 || size > BGP_MAX_MESSAGE_SIZE ||
        read_u16(msg + 16) != size || msg[18] != BGP_MSG_UPDATE) return 0;
    for (size_t i = 0; i < 16; i++) {
        if (msg[i] != 0xff) return 0;
    }
    return 1;
}

static inline int test_wire_find_attr(const uint8_t *msg, size_t size, uint8_t wanted,
                                     const uint8_t **value_out, uint16_t *length_out,
                                     uint8_t *flags_out) {
    if (!test_wire_update_header(msg, size)) return 0;
    size_t offset = BGP_HEADER_SIZE + 2 + read_u16(msg + BGP_HEADER_SIZE);
    if (offset > size - 2) return 0;
    size_t attributes = read_u16(msg + offset);
    offset += 2;
    if (attributes > size - offset) return 0;
    size_t         end = offset + attributes;
    const uint8_t *found = NULL;
    uint16_t       found_length = 0;
    uint8_t        found_flags = 0;
    while (offset < end) {
        if (end - offset < 3) return 0;
        uint8_t flags = msg[offset++], type = msg[offset++];
        size_t  width = flags & 0x10 ? 2 : 1;  /* RFC 4271 extended-length flag. */
        if (end - offset < width) return 0;
        uint16_t length = width == 2 ? read_u16(msg + offset) : msg[offset];
        offset += width;
        if (length > end - offset) return 0;
        if (type == wanted) {
            if (found) return 0;
            found = msg + offset;
            found_length = length;
            found_flags = flags;
        }
        offset += length;
    }
    if (!found) return 0;
    if (value_out) *value_out = found;
    if (length_out) *length_out = found_length;
    if (flags_out) *flags_out = found_flags;
    return 1;
}

/*
 * Offset of the NLRI inside an MP_REACH_NLRI value (after AFI, SAFI, next-hop length, next hop and the reserved
 * octet) or an MP_UNREACH_NLRI value (after AFI and SAFI). 0 when the value is too short.
 */
static inline int mp_reach_nlri_offset(const uint8_t *value, uint16_t length, int *offset_out) {
    int offset;

    if (!value || length < 5) {
        return 0;
    }

    offset = 5 + value[3];
    if (offset > length) {
        return 0;
    }

    *offset_out = offset;
    return 1;
}

static inline int mp_unreach_nlri_offset(const uint8_t *value, uint16_t length, int *offset_out) {
    if (!value || length < 3) {
        return 0;
    }

    *offset_out = 3;
    return 1;
}

/*
 * The route parts of one UPDATE: Withdrawn Routes, the classic NLRI field after the attributes, and the NLRI of
 * MP_REACH_NLRI / MP_UNREACH_NLRI with their AFI and SAFI. attr_count counts every path attribute.
 */
typedef struct {
    const uint8_t *withdrawn;
    size_t         withdrawn_len;
    const uint8_t *nlri;
    size_t         nlri_len;
    const uint8_t *reach;
    size_t         reach_len;
    uint16_t       reach_afi;
    uint8_t        reach_safi;
    int            has_reach;
    const uint8_t *unreach;
    size_t         unreach_len;
    uint16_t       unreach_afi;
    uint8_t        unreach_safi;
    int            has_unreach;
    size_t         attr_count;
} test_wire_update_t;

/*
 * Parse one UPDATE into view. Returns 0 when the framing, a length or an MP attribute does not parse.
 */
static inline int test_wire_update_view(const uint8_t *msg, size_t size, test_wire_update_t *view) {
    memset(view, 0, sizeof(*view));
    if (!test_wire_update_header(msg, size)) return 0;
    size_t offset = BGP_HEADER_SIZE;
    view->withdrawn_len = read_u16(msg + offset);
    offset += 2;
    if (view->withdrawn_len > size - offset - 2) return 0;
    view->withdrawn = msg + offset;
    offset += view->withdrawn_len;
    size_t attributes = read_u16(msg + offset);
    offset += 2;
    if (attributes > size - offset) return 0;
    size_t end = offset + attributes;
    view->nlri = msg + end;
    view->nlri_len = size - end;
    while (offset < end) {
        if (end - offset < 3) return 0;
        uint8_t flags = msg[offset++], type = msg[offset++];
        size_t  width = flags & 0x10 ? 2 : 1;
        if (end - offset < width) return 0;
        size_t length = width == 2 ? read_u16(msg + offset) : msg[offset];
        offset += width;
        if (length > end - offset) return 0;
        const uint8_t *value = msg + offset;
        if (type == 14) { /* MP_REACH_NLRI: AFI, SAFI, next-hop length, next hop, reserved, NLRI */
            if (view->has_reach || length < 5 || (size_t)5 + value[3] > length) return 0;
            view->has_reach = 1;
            view->reach_afi = read_u16(value);
            view->reach_safi = value[2];
            view->reach = value + 5 + value[3];
            view->reach_len = length - 5 - value[3];
        } else if (type == 15) { /* MP_UNREACH_NLRI: AFI, SAFI, NLRI */
            if (view->has_unreach || length < 3) return 0;
            view->has_unreach = 1;
            view->unreach_afi = read_u16(value);
            view->unreach_safi = value[2];
            view->unreach = value + 3;
            view->unreach_len = length - 3;
        }
        view->attr_count++;
        offset += length;
    }
    return 1;
}

/*
 * Negative lengths distinguish malformed/truncated input from an empty field.
 */
static inline int test_wire_path_attr_len(const uint8_t *msg, size_t size) {
    test_wire_update_t view;
    if (!test_wire_update_view(msg, size, &view)) return -1;
    return (int)(view.nlri - msg - BGP_HEADER_SIZE - 4 - view.withdrawn_len);
}

static inline int test_wire_withdrawn_len(const uint8_t *msg, size_t size) {
    test_wire_update_t view;
    if (!test_wire_update_view(msg, size, &view)) return -1;
    return (int)view.withdrawn_len;
}

/*
 * Octets of the NLRI at p of (afi, safi), the Add-Path ID included, or 0 when it does not fit in len.
 */
static inline size_t test_wire_nlri_size(uint16_t afi, uint8_t safi, int add_path, const uint8_t *p, size_t len) {
    size_t id = add_path ? 4 : 0, size;
    if (len < id + 1) return 0;
    if ((afi == 25 && safi == 70) || safi == 5) { /* EVPN/MVPN: route type, length, value */
        if (len < id + 2) return 0;
        size = id + 2 + p[id + 1];
    } else if (afi == 25 && safi == 65) { /* VPLS: two-octet length */
        if (len < id + 2) return 0;
        size = id + 2 + read_u16(p + id);
    } else if (afi == 16388 && safi == 71) { /* BGP-LS: type, two-octet length */
        if (len < id + 4) return 0;
        size = id + 4 + read_u16(p + id + 2);
    } else if (safi == 73) { /* SR Policy: length in bits */
        size = id + 1 + p[id] / 8;
    } else if (safi == 133 || safi == 134) { /* FlowSpec: 0xfnnn is a 12-bit length */
        if (p[id] >= 0xf0) {
            if (len < id + 2) return 0;
            size = id + 2 + (((size_t)(p[id] & 0x0f) << 8) | p[id + 1]);
        } else {
            size = id + 1 + p[id];
        }
    } else { /* Prefix, labeled prefix and VPN prefix: length in bits */
        size = id + 1 + ((size_t)p[id] + 7) / 8;
    }
    return size <= len ? size : 0;
}

#endif
