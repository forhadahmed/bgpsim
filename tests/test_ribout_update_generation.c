#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <arpa/inet.h>
#include "bgp.h"
#include "test_case.h"
#include "test_wire.h"
#include "bgp_ribout.h"
#include "bgp_update.h"
#include "bgp_ribout_snapshot.h"
#include "test_nlri_templates.h"

static int buffer_contains(const uint8_t *buffer, size_t buffer_len, const uint8_t *needle, size_t needle_len) {
    if (!buffer || !needle || needle_len == 0 || buffer_len < needle_len) {
        return 0;
    }

    for (size_t i = 0; i + needle_len <= buffer_len; i++) {
        if (memcmp(buffer + i, needle, needle_len) == 0) {
            return 1;
        }
    }

    return 0;
}

static int find_attr(const uint8_t *msg, size_t size, uint8_t type_code,
                     const uint8_t **value_out, uint16_t *length_out) {
    return test_wire_find_attr(msg, size, type_code, value_out, length_out, NULL);
}

static int count_ipv4_nlri(const uint8_t *data, uint16_t length) {
    int count = 0;
    int offset = 0;

    while (offset < length) {
        uint8_t prefix_len = data[offset++];
        int     prefix_bytes = (prefix_len + 7) / 8;

        if (offset + prefix_bytes > length) {
            return -1;
        }

        offset += prefix_bytes;
        count++;
    }

    return (offset == length) ? count : -1;
}

static int count_ipv6_nlri(const uint8_t *data, uint16_t length) {
    int count = 0;
    int offset = 0;

    while (offset < length) {
        uint8_t prefix_len = data[offset++];
        int     prefix_bytes = (prefix_len + 7) / 8;

        if (offset + prefix_bytes > length) {
            return -1;
        }

        offset += prefix_bytes;
        count++;
    }

    return (offset == length) ? count : -1;
}

static int count_labeled_nlri(const uint8_t *data, uint16_t length, int add_path) {
    int count = 0;
    int offset = 0;

    while (offset < length) {
        uint8_t prefix_len;
        int     prefix_bits;
        int     prefix_bytes;

        if (add_path) {
            if (offset + 4 > length) {
                return -1;
            }
            offset += 4;
        }

        if (offset + 4 > length) {
            return -1;
        }

        prefix_len = data[offset++];
        if (prefix_len < 24) {
            return -1;
        }

        prefix_bits = prefix_len - 24;
        prefix_bytes = (prefix_bits + 7) / 8;
        if (offset + 3 + prefix_bytes > length) {
            return -1;
        }

        offset += 3 + prefix_bytes;
        count++;
    }

    return (offset == length) ? count : -1;
}

static int extract_mp_reach_afi(const uint8_t *msg, size_t size,
                                uint16_t expected_afi,
                                uint8_t expected_safi,
                                const uint8_t **next_hop_out,
                                uint8_t *next_hop_len_out,
                                const uint8_t **nlri_out,
                                uint16_t *nlri_len_out) {
    const uint8_t *value = NULL;
    uint16_t       length = 0;
    uint8_t        nh_len;
    int            base_len;
    uint16_t       afi;

    if (!find_attr(msg, size, BGP_ATTR_MP_REACH_NLRI, &value, &length) || length < 5) {
        return 0;
    }

    afi = read_u16(value);
    if (afi != expected_afi || value[2] != expected_safi) {
        return 0;
    }

    nh_len = value[3];
    base_len = 2 + 1 + 1 + nh_len + 1;
    if ((uint16_t)base_len > length || value[4 + nh_len] != 0) {
        return 0;
    }

    if (next_hop_out) {
        *next_hop_out = value + 4;
    }
    if (next_hop_len_out) {
        *next_hop_len_out = nh_len;
    }
    if (nlri_out) {
        *nlri_out = value + base_len;
    }
    if (nlri_len_out) {
        *nlri_len_out = (uint16_t)(length - base_len);
    }

    return 1;
}

static int extract_mp_reach_ipv6(const uint8_t *msg, size_t size,
                                 const uint8_t **next_hop_out,
                                 uint8_t *next_hop_len_out,
                                 const uint8_t **nlri_out,
                                 uint16_t *nlri_len_out) {
    return extract_mp_reach_afi(msg, size,
                                AFI_IPV6,
                                SAFI_UNICAST,
                                next_hop_out,
                                next_hop_len_out,
                                nlri_out,
                                nlri_len_out);
}

static int extract_mp_reach_ipv4(const uint8_t *msg, size_t size,
                                 const uint8_t **next_hop_out,
                                 uint8_t *next_hop_len_out,
                                 const uint8_t **nlri_out,
                                 uint16_t *nlri_len_out) {
    return extract_mp_reach_afi(msg, size,
                                AFI_IPV4,
                                SAFI_UNICAST,
                                next_hop_out,
                                next_hop_len_out,
                                nlri_out,
                                nlri_len_out);
}

static int extract_mp_reach_labeled_ipv4(const uint8_t *msg, size_t size,
                                         const uint8_t **next_hop_out,
                                         uint8_t *next_hop_len_out,
                                         const uint8_t **nlri_out,
                                         uint16_t *nlri_len_out) {
    return extract_mp_reach_afi(msg, size,
                                AFI_IPV4,
                                SAFI_LABELED_UNICAST,
                                next_hop_out,
                                next_hop_len_out,
                                nlri_out,
                                nlri_len_out);
}

static int extract_mp_reach_labeled_ipv6(const uint8_t *msg, size_t size,
                                         const uint8_t **next_hop_out,
                                         uint8_t *next_hop_len_out,
                                         const uint8_t **nlri_out,
                                         uint16_t *nlri_len_out) {
    return extract_mp_reach_afi(msg, size,
                                AFI_IPV6,
                                SAFI_LABELED_UNICAST,
                                next_hop_out,
                                next_hop_len_out,
                                nlri_out,
                                nlri_len_out);
}

static int extract_mp_reach_vpnv4(const uint8_t *msg, size_t size,
                                  const uint8_t **next_hop_out,
                                  uint8_t *next_hop_len_out,
                                  const uint8_t **nlri_out,
                                  uint16_t *nlri_len_out) {
    return extract_mp_reach_afi(msg, size,
                                AFI_IPV4,
                                SAFI_MPLS_VPN,
                                next_hop_out,
                                next_hop_len_out,
                                nlri_out,
                                nlri_len_out);
}

static int extract_mp_reach_vpnv6(const uint8_t *msg, size_t size,
                                  const uint8_t **next_hop_out,
                                  uint8_t *next_hop_len_out,
                                  const uint8_t **nlri_out,
                                  uint16_t *nlri_len_out) {
    return extract_mp_reach_afi(msg, size,
                                AFI_IPV6,
                                SAFI_MPLS_VPN,
                                next_hop_out,
                                next_hop_len_out,
                                nlri_out,
                                nlri_len_out);
}

static int extract_mp_reach_evpn_type5(const uint8_t *msg, size_t size,
                                       const uint8_t **next_hop_out,
                                       uint8_t *next_hop_len_out,
                                       const uint8_t **nlri_out,
                                       uint16_t *nlri_len_out) {
    return extract_mp_reach_afi(msg, size,
                                AFI_L2VPN,
                                SAFI_EVPN,
                                next_hop_out,
                                next_hop_len_out,
                                nlri_out,
                                nlri_len_out);
}

static int extract_mp_reach_srpolicy4(const uint8_t *msg, size_t size,
                                      const uint8_t **next_hop_out,
                                      uint8_t *next_hop_len_out,
                                      const uint8_t **nlri_out,
                                      uint16_t *nlri_len_out) {
    return extract_mp_reach_afi(msg, size,
                                AFI_IPV4,
                                SAFI_SR_POLICY,
                                next_hop_out,
                                next_hop_len_out,
                                nlri_out,
                                nlri_len_out);
}

static int extract_mp_reach_srpolicy6(const uint8_t *msg, size_t size,
                                      const uint8_t **next_hop_out,
                                      uint8_t *next_hop_len_out,
                                      const uint8_t **nlri_out,
                                      uint16_t *nlri_len_out) {
    return extract_mp_reach_afi(msg, size,
                                AFI_IPV6,
                                SAFI_SR_POLICY,
                                next_hop_out,
                                next_hop_len_out,
                                nlri_out,
                                nlri_len_out);
}

static int count_srpolicy_nlri(const uint8_t *data, uint16_t length, uint16_t expected_afi, int add_path) {
    int count = 0;
    int offset = 0;
    int expected_bits = (expected_afi == AFI_IPV6) ? 192 : 96;

    while (offset < length) {
        int payload_bytes;

        if (add_path) {
            if (offset + 4 > length) {
                return -1;
            }
            offset += 4;
        }

        if (offset + 1 > length || data[offset] != (uint8_t)expected_bits) {
            return -1;
        }

        payload_bytes = (data[offset++] + 7) / 8;
        if (offset + payload_bytes > length) {
            return -1;
        }

        offset += payload_bytes;
        count++;
    }

    return (offset == length) ? count : -1;
}

static int count_vpn_nlri(const uint8_t *data, uint16_t length, int add_path) {
    int count = 0;
    int offset = 0;

    while (offset < length) {
        uint8_t prefix_len;
        int     prefix_bits;
        int     prefix_bytes;

        if (add_path) {
            if (offset + 4 > length) {
                return -1;
            }
            offset += 4;
        }

        if (offset + 12 > length) {
            return -1;
        }

        prefix_len = data[offset++];
        if (prefix_len < 88) {
            return -1;
        }

        prefix_bits = prefix_len - 24 - 64;
        prefix_bytes = (prefix_bits + 7) / 8;
        if (offset + 3 + 8 + prefix_bytes > length) {
            return -1;
        }

        offset += 3 + 8 + prefix_bytes;
        count++;
    }

    return (offset == length) ? count : -1;
}

static int count_evpn_nlri(const uint8_t *data, uint16_t length, int add_path) {
    int count = 0;
    int offset = 0;

    while (offset < length) {
        uint8_t route_len;

        if (add_path) {
            if (offset + 4 > length) {
                return -1;
            }
            offset += 4;
        }

        if (offset + 2 > length) {
            return -1;
        }

        if (data[offset++] != EVPN_RT_IP_PREFIX) {
            return -1;
        }

        route_len = data[offset++];
        if (offset + route_len > length) {
            return -1;
        }

        offset += route_len;
        count++;
    }

    return (offset == length) ? count : -1;
}

static int count_evpn_type2_nlri(const uint8_t *data, uint16_t length, int add_path) {
    int count = 0;
    int offset = 0;

    while (offset < length) {
        uint8_t        route_len;
        const uint8_t *body;
        uint8_t        ip_len;
        int            ip_bytes;
        int            min_len;

        if (add_path) {
            if (offset + 4 > length) {
                return -1;
            }
            offset += 4;
        }

        if (offset + 2 > length || data[offset++] != EVPN_RT_MAC_IP_ADVERTISEMENT) {
            return -1;
        }

        route_len = data[offset++];
        if (offset + route_len > length) {
            return -1;
        }

        body = data + offset;
        min_len = 8 + 10 + 4 + 1 + 6 + 1 + 3;
        if (route_len < min_len || body[22] != 48) {
            return -1;
        }

        ip_len = body[29];
        if (ip_len == 0) {
            ip_bytes = 0;
        } else if (ip_len == 32) {
            ip_bytes = 4;
        } else if (ip_len == 128) {
            ip_bytes = 16;
        } else {
            return -1;
        }

        min_len += ip_bytes;
        if (!(route_len == min_len || route_len == (uint8_t)(min_len + 3))) {
            return -1;
        }

        offset += route_len;
        count++;
    }

    return (offset == length) ? count : -1;
}

static int validate_vpn_update_message(const bgp_msg_t *msg,
                                       uint16_t expected_afi,
                                       uint8_t expected_origin,
                                       uint32_t expected_local_pref,
                                       uint32_t expected_med,
                                       int expected_med_present,
                                       const uint8_t *expected_next_hop,
                                       uint8_t expected_next_hop_len,
                                       uint16_t expected_ext_comm_len,
                                       int expected_add_path,
                                       int *nlri_count_out) {
    const uint8_t *value = NULL;
    uint16_t       length = 0;
    const uint8_t *nlri = NULL;
    uint16_t       nlri_len = 0;
    uint8_t        nh_len = 0;
    int            nlri_count;

    if (!msg || !msg->data || msg->length < BGP_HEADER_SIZE + 4) {
        return 0;
    }

    if (msg->length != read_u16(msg->data + 16) || msg->data[18] != BGP_MSG_UPDATE) {
        return 0;
    }

    if (read_u16(msg->data + BGP_HEADER_SIZE) != 0) {
        return 0;
    }

    if (!find_attr(msg->data, msg->length, BGP_ATTR_ORIGIN, &value, &length) ||
        length != 1 || value[0] != expected_origin) {
        return 0;
    }

    if (!find_attr(msg->data, msg->length, BGP_ATTR_AS_PATH, NULL, NULL) ||
        !find_attr(msg->data, msg->length, BGP_ATTR_LOCAL_PREF, &value, &length) ||
        length != 4 || read_u32(value) != expected_local_pref ||
        find_attr(msg->data, msg->length, BGP_ATTR_NEXT_HOP, NULL, NULL)) {
        return 0;
    }

    if (expected_med_present) {
        if (!find_attr(msg->data, msg->length, BGP_ATTR_MULTI_EXIT_DISC, &value, &length) ||
            length != 4 || read_u32(value) != expected_med) {
            return 0;
        }
    } else if (find_attr(msg->data, msg->length, BGP_ATTR_MULTI_EXIT_DISC, NULL, NULL)) {
        return 0;
    }

    if (!find_attr(msg->data, msg->length, BGP_ATTR_EXT_COMM, &value, &length) ||
        length != expected_ext_comm_len) {
        return 0;
    }

    if (!(expected_afi == AFI_IPV4 ?
              extract_mp_reach_vpnv4(msg->data, msg->length, &value, &nh_len, &nlri, &nlri_len) :
              extract_mp_reach_vpnv6(msg->data, msg->length, &value, &nh_len, &nlri, &nlri_len)) ||
        nh_len != expected_next_hop_len ||
        memcmp(value, expected_next_hop, expected_next_hop_len) != 0) {
        return 0;
    }

    nlri_count = count_vpn_nlri(nlri, nlri_len, expected_add_path);
    if (nlri_count <= 0) {
        return 0;
    }

    *nlri_count_out = nlri_count;
    return 1;
}

static int validate_evpn_update_message(const bgp_msg_t *msg,
                                        uint8_t expected_origin,
                                        uint32_t expected_local_pref,
                                        uint32_t expected_med,
                                        int expected_med_present,
                                        const uint8_t *expected_next_hop,
                                        uint8_t expected_next_hop_len,
                                        uint16_t expected_ext_comm_len,
                                        int expected_add_path,
                                        int *nlri_count_out) {
    const uint8_t *value = NULL;
    uint16_t       length = 0;
    const uint8_t *nlri = NULL;
    uint16_t       nlri_len = 0;
    uint8_t        nh_len = 0;
    int            nlri_count;

    if (!msg || !msg->data || msg->length < BGP_HEADER_SIZE + 4) {
        return 0;
    }

    if (msg->length != read_u16(msg->data + 16) || msg->data[18] != BGP_MSG_UPDATE) {
        return 0;
    }

    if (read_u16(msg->data + BGP_HEADER_SIZE) != 0) {
        return 0;
    }

    if (!find_attr(msg->data, msg->length, BGP_ATTR_ORIGIN, &value, &length) ||
        length != 1 || value[0] != expected_origin) {
        return 0;
    }

    if (!find_attr(msg->data, msg->length, BGP_ATTR_AS_PATH, NULL, NULL) ||
        !find_attr(msg->data, msg->length, BGP_ATTR_LOCAL_PREF, &value, &length) ||
        length != 4 || read_u32(value) != expected_local_pref ||
        find_attr(msg->data, msg->length, BGP_ATTR_NEXT_HOP, NULL, NULL)) {
        return 0;
    }

    if (expected_med_present) {
        if (!find_attr(msg->data, msg->length, BGP_ATTR_MULTI_EXIT_DISC, &value, &length) ||
            length != 4 || read_u32(value) != expected_med) {
            return 0;
        }
    } else if (find_attr(msg->data, msg->length, BGP_ATTR_MULTI_EXIT_DISC, NULL, NULL)) {
        return 0;
    }

    if (!find_attr(msg->data, msg->length, BGP_ATTR_EXT_COMM, &value, &length) ||
        length != expected_ext_comm_len) {
        return 0;
    }

    if (!extract_mp_reach_evpn_type5(msg->data, msg->length, &value, &nh_len, &nlri, &nlri_len) ||
        nh_len != expected_next_hop_len ||
        memcmp(value, expected_next_hop, expected_next_hop_len) != 0) {
        return 0;
    }

    nlri_count = count_evpn_nlri(nlri, nlri_len, expected_add_path);
    if (nlri_count <= 0) {
        return 0;
    }

    *nlri_count_out = nlri_count;
    return 1;
}

static int validate_evpn_type2_update_message(const bgp_msg_t *msg,
                                              uint8_t expected_origin,
                                              uint32_t expected_local_pref,
                                              uint32_t expected_med,
                                              int expected_med_present,
                                              const uint8_t *expected_next_hop,
                                              uint8_t expected_next_hop_len,
                                              uint16_t expected_ext_comm_len,
                                              int expected_add_path,
                                              int *nlri_count_out) {
    const uint8_t *value = NULL;
    uint16_t       length = 0;
    const uint8_t *nlri = NULL;
    uint16_t       nlri_len = 0;
    uint8_t        nh_len = 0;
    int            nlri_count;

    if (!msg || !msg->data || msg->length < BGP_HEADER_SIZE + 4) {
        return 0;
    }

    if (msg->length != read_u16(msg->data + 16) || msg->data[18] != BGP_MSG_UPDATE) {
        return 0;
    }

    if (read_u16(msg->data + BGP_HEADER_SIZE) != 0) {
        return 0;
    }

    if (!find_attr(msg->data, msg->length, BGP_ATTR_ORIGIN, &value, &length) ||
        length != 1 || value[0] != expected_origin) {
        return 0;
    }

    if (!find_attr(msg->data, msg->length, BGP_ATTR_AS_PATH, NULL, NULL) ||
        !find_attr(msg->data, msg->length, BGP_ATTR_LOCAL_PREF, &value, &length) ||
        length != 4 || read_u32(value) != expected_local_pref ||
        find_attr(msg->data, msg->length, BGP_ATTR_NEXT_HOP, NULL, NULL)) {
        return 0;
    }

    if (expected_med_present) {
        if (!find_attr(msg->data, msg->length, BGP_ATTR_MULTI_EXIT_DISC, &value, &length) ||
            length != 4 || read_u32(value) != expected_med) {
            return 0;
        }
    } else if (find_attr(msg->data, msg->length, BGP_ATTR_MULTI_EXIT_DISC, NULL, NULL)) {
        return 0;
    }

    if (!find_attr(msg->data, msg->length, BGP_ATTR_EXT_COMM, &value, &length) ||
        length != expected_ext_comm_len) {
        return 0;
    }

    if (!extract_mp_reach_evpn_type5(msg->data, msg->length, &value, &nh_len, &nlri, &nlri_len) ||
        nh_len != expected_next_hop_len ||
        memcmp(value, expected_next_hop, expected_next_hop_len) != 0) {
        return 0;
    }

    nlri_count = count_evpn_type2_nlri(nlri, nlri_len, expected_add_path);
    if (nlri_count <= 0) {
        return 0;
    }

    *nlri_count_out = nlri_count;
    return 1;
}

static int validate_evpn_type2_against_generator(const bgp_msg_t *msg,
                                                 bgp_ribout_config_t *block,
                                                 int expected_add_path) {
    bgp_ribout_gen_t gen;
    const uint8_t   *nlri = NULL;
    uint16_t         nlri_len = 0;
    int              offset = 0;

    if (!msg || !msg->data || msg->length < BGP_HEADER_SIZE + 4 || bgp_ribout_generator_init(&gen, block) != 0) {
        return 0;
    }

    if (!extract_mp_reach_evpn_type5(msg->data, msg->length, NULL, NULL, &nlri, &nlri_len)) {
        return 0;
    }

    while (offset < nlri_len) {
        bgp_gen_path_t expected;
        const uint8_t *body;
        uint8_t        route_len;
        uint8_t        ip_len;
        int            ip_bytes;
        uint32_t       wire_path_id = 0;
        uint32_t       wire_eth_tag;
        uint32_t       wire_label1;
        uint32_t       wire_label2;

        if (!bgp_ribout_generator_has_next(&gen) ||
            bgp_ribout_generator_next(&gen, &expected) != 0) {
            return 0;
        }

        if (expected_add_path) {
            if (offset + 4 > nlri_len) {
                return 0;
            }
            wire_path_id = read_u32(nlri + offset);
            if (wire_path_id != expected.path_id) {
                return 0;
            }
            offset += 4;
        }

        if (offset + 2 > nlri_len ||
            nlri[offset++] != EVPN_RT_MAC_IP_ADVERTISEMENT) {
            return 0;
        }

        route_len = nlri[offset++];
        if (offset + route_len > nlri_len) {
            return 0;
        }

        body = nlri + offset;
        if (memcmp(body, &expected.rd, sizeof(expected.rd)) != 0 ||
            memcmp(body + 8, &expected.esi, sizeof(expected.esi)) != 0 ||
            body[22] != 48 ||
            memcmp(body + 23, expected.mac_addr, sizeof(expected.mac_addr)) != 0) {
            return 0;
        }

        wire_eth_tag = read_u32(body + 18);
        if (wire_eth_tag != expected.ethernet_tag_id) {
            return 0;
        }

        ip_len = body[29];
        if (expected.has_ip) {
            if (expected.ip_af == AF_INET) {
                if (ip_len != 32 ||
                    memcmp(body + 30,
                           &expected.ip_addr.ipv4,
                           sizeof(expected.ip_addr.ipv4)) != 0) {
                    return 0;
                }
                ip_bytes = 4;
            } else {
                if (ip_len != 128 ||
                    memcmp(body + 30,
                           &expected.ip_addr.ipv6,
                           sizeof(expected.ip_addr.ipv6)) != 0) {
                    return 0;
                }
                ip_bytes = 16;
            }
        } else {
            if (ip_len != 0) {
                return 0;
            }
            ip_bytes = 0;
        }

        wire_label1 = decode_wire_label(body + 30 + ip_bytes);
        if (wire_label1 != expected.label) {
            return 0;
        }

        if (expected.has_label2) {
            if (route_len != (uint8_t)(33 + ip_bytes + 3)) {
                return 0;
            }
            wire_label2 = decode_wire_label(body + 33 + ip_bytes);
            if (wire_label2 != expected.label2) {
                return 0;
            }
        } else if (route_len != (uint8_t)(33 + ip_bytes)) {
            return 0;
        }

        offset += route_len;
    }

    return offset == nlri_len && !bgp_ribout_generator_has_next(&gen);
}

static int validate_ipv4_add_path_against_generator(const bgp_msg_t *msg, bgp_ribout_config_t *block) {
    bgp_ribout_gen_t   gen;
    test_wire_update_t view;
    int                offset;
    int                end;

    if (!msg || !msg->data || msg->length < BGP_HEADER_SIZE + 4 || bgp_ribout_generator_init(&gen, block) != 0) {
        return 0;
    }

    if (!test_wire_update_view(msg->data, msg->length, &view)) return 0;
    offset = (int)(view.nlri - msg->data);
    end = msg->length;

    while (offset < end) {
        bgp_gen_path_t expected;
        uint32_t       path_id;
        uint8_t        prefix_len;
        int            prefix_bytes;

        if (!bgp_ribout_generator_has_next(&gen) ||
            bgp_ribout_generator_next(&gen, &expected) != 0 ||
            expected.prefix_af != AF_INET ||
            offset + 5 > end) {
            return 0;
        }

        path_id = read_u32(msg->data + offset);
        offset += 4;
        prefix_len = msg->data[offset++];
        prefix_bytes = (prefix_len + 7) / 8;

        if (path_id != expected.path_id ||
            prefix_len != expected.prefix_len ||
            offset + prefix_bytes > end ||
            memcmp(msg->data + offset,
                   &expected.prefix_addr.ipv4,
                   (size_t)prefix_bytes) != 0) {
            return 0;
        }

        offset += prefix_bytes;
    }

    return (offset == end) && !bgp_ribout_generator_has_next(&gen);
}

static int validate_ipv6_add_path_against_generator(const bgp_msg_t *msg, bgp_ribout_config_t *block) {
    bgp_ribout_gen_t gen;
    const uint8_t   *nlri = NULL;
    uint16_t         nlri_len = 0;
    int              offset = 0;

    if (!msg || !msg->data || msg->length < BGP_HEADER_SIZE + 4 ||
        bgp_ribout_generator_init(&gen, block) != 0 ||
        !extract_mp_reach_ipv6(msg->data, msg->length, NULL, NULL, &nlri, &nlri_len)) {
        return 0;
    }

    while (offset < nlri_len) {
        bgp_gen_path_t expected;
        uint32_t       path_id;
        uint8_t        prefix_len;
        int            prefix_bytes;

        if (!bgp_ribout_generator_has_next(&gen) ||
            bgp_ribout_generator_next(&gen, &expected) != 0 ||
            expected.prefix_af != AF_INET6 ||
            offset + 5 > nlri_len) {
            return 0;
        }

        path_id = read_u32(nlri + offset);
        offset += 4;
        prefix_len = nlri[offset++];
        prefix_bytes = (prefix_len + 7) / 8;

        if (path_id != expected.path_id ||
            prefix_len != expected.prefix_len ||
            offset + prefix_bytes > nlri_len ||
            memcmp(nlri + offset,
                   &expected.prefix_addr.ipv6,
                   (size_t)prefix_bytes) != 0) {
            return 0;
        }

        offset += prefix_bytes;
    }

    return (offset == nlri_len) && !bgp_ribout_generator_has_next(&gen);
}

static int validate_ipv4_mp_add_path_against_generator(const bgp_msg_t *msg, bgp_ribout_config_t *block) {
    bgp_ribout_gen_t gen;
    const uint8_t   *nlri = NULL;
    uint16_t         nlri_len = 0;
    int              offset = 0;

    if (!msg || !msg->data || msg->length < BGP_HEADER_SIZE + 4 ||
        bgp_ribout_generator_init(&gen, block) != 0 ||
        !extract_mp_reach_ipv4(msg->data, msg->length, NULL, NULL, &nlri, &nlri_len)) {
        return 0;
    }

    while (offset < nlri_len) {
        bgp_gen_path_t expected;
        uint32_t       path_id;
        uint8_t        prefix_len;
        int            prefix_bytes;

        if (!bgp_ribout_generator_has_next(&gen) ||
            bgp_ribout_generator_next(&gen, &expected) != 0 ||
            expected.prefix_af != AF_INET ||
            offset + 5 > nlri_len) {
            return 0;
        }

        path_id = read_u32(nlri + offset);
        offset += 4;
        prefix_len = nlri[offset++];
        prefix_bytes = (prefix_len + 7) / 8;

        if (path_id != expected.path_id ||
            prefix_len != expected.prefix_len ||
            offset + prefix_bytes > nlri_len ||
            memcmp(nlri + offset,
                   &expected.prefix_addr.ipv4,
                   (size_t)prefix_bytes) != 0) {
            return 0;
        }

        offset += prefix_bytes;
    }

    return (offset == nlri_len) && !bgp_ribout_generator_has_next(&gen);
}

static int validate_srpolicy_against_generator(const bgp_msg_t *msg,
                                               bgp_ribout_config_t *block,
                                               uint16_t expected_afi,
                                               int add_path) {
    bgp_ribout_gen_t gen;
    const uint8_t   *nlri = NULL;
    uint16_t         nlri_len = 0;
    int              offset = 0;

    if (!msg || !msg->data || msg->length < BGP_HEADER_SIZE + 4 || bgp_ribout_generator_init(&gen, block) != 0) {
        return 0;
    }

    if (expected_afi == AFI_IPV4) {
        if (!extract_mp_reach_srpolicy4(msg->data, msg->length, NULL, NULL, &nlri, &nlri_len)) {
            return 0;
        }
    } else if (!extract_mp_reach_srpolicy6(msg->data, msg->length, NULL, NULL, &nlri, &nlri_len)) {
        return 0;
    }

    while (offset < nlri_len) {
        bgp_gen_path_t expected;
        uint32_t       path_id = 0;
        uint8_t        wire_bits;
        uint32_t       wire_distinguisher;
        uint32_t       wire_color;
        int            endpoint_len = (expected_afi == AFI_IPV6) ? 16 : 4;

        if (!bgp_ribout_generator_has_next(&gen) ||
            bgp_ribout_generator_next(&gen, &expected) != 0 ||
            offset + 1 > nlri_len) {
            return 0;
        }

        if (add_path) {
            if (offset + 4 > nlri_len) {
                return 0;
            }
            path_id = read_u32(nlri + offset);
            offset += 4;
            if (path_id != expected.path_id) {
                return 0;
            }
        }

        wire_bits = nlri[offset++];
        if (wire_bits != (uint8_t)((4 + 4 + endpoint_len) * 8) ||
            offset + 8 + endpoint_len > nlri_len) {
            return 0;
        }

        wire_distinguisher = read_u32(nlri + offset);
        offset += 4;
        wire_color = read_u32(nlri + offset);
        offset += 4;

        if (wire_distinguisher != expected.distinguisher ||
            wire_color != expected.color) {
            return 0;
        }

        if (expected_afi == AFI_IPV4) {
            if (memcmp(nlri + offset,
                       &expected.endpoint_addr.ipv4,
                       sizeof(expected.endpoint_addr.ipv4)) != 0) {
                return 0;
            }
        } else if (memcmp(nlri + offset, &expected.endpoint_addr.ipv6, sizeof(expected.endpoint_addr.ipv6)) != 0) {
            return 0;
        }

        offset += endpoint_len;
    }

    return (offset == nlri_len) && !bgp_ribout_generator_has_next(&gen);
}

static size_t count_messages(bgp_msg_t *messages) {
    size_t count = 0;

    while (messages) {
        count++;
        messages = messages->next;
    }

    return count;
}

static int validate_ipv4_update_message(const bgp_msg_t *msg,
                                        uint8_t expected_origin,
                                        uint32_t expected_local_pref,
                                        const uint8_t *expected_next_hop,
                                        int *nlri_count_out) {
    const uint8_t     *value = NULL;
    uint16_t           length = 0;
    test_wire_update_t view;
    int                nlri_offset;
    int                nlri_len;
    int                nlri_count;

    if (!msg || !msg->data || msg->length < BGP_HEADER_SIZE + 4) {
        return 0;
    }

    if (msg->length != read_u16(msg->data + 16) || msg->data[18] != BGP_MSG_UPDATE) {
        return 0;
    }

    if (memcmp(msg->data, "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
                          "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 16) != 0) {
        return 0;
    }

    if (!test_wire_update_view(msg->data, msg->length, &view) || view.withdrawn_len != 0) {
        return 0;
    }

    if (!find_attr(msg->data, msg->length, BGP_ATTR_ORIGIN, &value, &length) ||
        length != 1 || value[0] != expected_origin) {
        return 0;
    }

    if (!find_attr(msg->data, msg->length, BGP_ATTR_AS_PATH, NULL, NULL)) {
        return 0;
    }

    if (!find_attr(msg->data, msg->length, BGP_ATTR_NEXT_HOP, &value, &length) ||
        length != 4 || memcmp(value, expected_next_hop, 4) != 0) {
        return 0;
    }

    if (!find_attr(msg->data, msg->length, BGP_ATTR_LOCAL_PREF, &value, &length) ||
        length != 4 || read_u32(value) != expected_local_pref) {
        return 0;
    }

    if (view.attr_count == 0) {
        return 0;
    }

    nlri_offset = (int)(view.nlri - msg->data);
    nlri_len = (int)view.nlri_len;
    if (nlri_len <= 0) {
        return 0;
    }

    nlri_count = count_ipv4_nlri(msg->data + nlri_offset, (uint16_t)nlri_len);
    if (nlri_count <= 0) {
        return 0;
    }

    *nlri_count_out = nlri_count;
    return 1;
}

static int validate_ipv6_update_message(const bgp_msg_t *msg,
                                        uint8_t expected_origin,
                                        uint32_t expected_local_pref,
                                        const uint8_t *expected_next_hop,
                                        uint8_t expected_next_hop_len,
                                        int *nlri_count_out) {
    const uint8_t *value = NULL;
    uint16_t       length = 0;
    const uint8_t *nlri = NULL;
    uint16_t       nlri_len = 0;
    uint8_t        nh_len = 0;
    int            nlri_count;

    if (!msg || !msg->data || msg->length < BGP_HEADER_SIZE + 4) {
        return 0;
    }

    if (msg->length != read_u16(msg->data + 16) || msg->data[18] != BGP_MSG_UPDATE) {
        return 0;
    }

    if (memcmp(msg->data, "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
                          "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 16) != 0) {
        return 0;
    }

    if (read_u16(msg->data + BGP_HEADER_SIZE) != 0) {
        return 0;
    }

    if (!find_attr(msg->data, msg->length, BGP_ATTR_ORIGIN, &value, &length) ||
        length != 1 || value[0] != expected_origin) {
        return 0;
    }

    if (!find_attr(msg->data, msg->length, BGP_ATTR_AS_PATH, NULL, NULL) ||
        !find_attr(msg->data, msg->length, BGP_ATTR_LOCAL_PREF, &value, &length) ||
        length != 4 || read_u32(value) != expected_local_pref ||
        find_attr(msg->data, msg->length, BGP_ATTR_NEXT_HOP, NULL, NULL) ||
        !extract_mp_reach_ipv6(msg->data, msg->length, &value, &nh_len, &nlri, &nlri_len) ||
        nh_len != expected_next_hop_len ||
        memcmp(value, expected_next_hop, expected_next_hop_len) != 0) {
        return 0;
    }

    nlri_count = count_ipv6_nlri(nlri, nlri_len);
    if (nlri_count <= 0) {
        return 0;
    }

    *nlri_count_out = nlri_count;
    return 1;
}

static int validate_ipv4_rfc8950_update_message(const bgp_msg_t *msg,
                                                uint8_t expected_origin,
                                                uint32_t expected_local_pref,
                                                const uint8_t *expected_next_hop,
                                                uint8_t expected_next_hop_len,
                                                int *nlri_count_out) {
    const uint8_t *value = NULL;
    uint16_t       length = 0;
    const uint8_t *nlri = NULL;
    uint16_t       nlri_len = 0;
    uint8_t        nh_len = 0;
    int            nlri_count;

    if (!msg || !msg->data || msg->length < BGP_HEADER_SIZE + 4) {
        return 0;
    }

    if (msg->length != read_u16(msg->data + 16) || msg->data[18] != BGP_MSG_UPDATE) {
        return 0;
    }

    if (memcmp(msg->data, "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
                          "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 16) != 0) {
        return 0;
    }

    if (read_u16(msg->data + BGP_HEADER_SIZE) != 0) {
        return 0;
    }

    if (!find_attr(msg->data, msg->length, BGP_ATTR_ORIGIN, &value, &length) ||
        length != 1 || value[0] != expected_origin) {
        return 0;
    }

    if (!find_attr(msg->data, msg->length, BGP_ATTR_AS_PATH, NULL, NULL) ||
        !find_attr(msg->data, msg->length, BGP_ATTR_LOCAL_PREF, &value, &length) ||
        length != 4 || read_u32(value) != expected_local_pref ||
        find_attr(msg->data, msg->length, BGP_ATTR_NEXT_HOP, NULL, NULL) ||
        !extract_mp_reach_ipv4(msg->data, msg->length, &value, &nh_len, &nlri, &nlri_len) ||
        nh_len != expected_next_hop_len ||
        memcmp(value, expected_next_hop, expected_next_hop_len) != 0) {
        return 0;
    }

    nlri_count = count_ipv4_nlri(nlri, nlri_len);
    if (nlri_count <= 0) {
        return 0;
    }

    *nlri_count_out = nlri_count;
    return 1;
}

static int validate_labeled_ipv4_update_message(const bgp_msg_t *msg,
                                                uint8_t expected_origin,
                                                uint32_t expected_local_pref,
                                                const uint8_t *expected_next_hop,
                                                uint8_t expected_next_hop_len,
                                                int expected_add_path,
                                                int *nlri_count_out) {
    const uint8_t *value = NULL;
    uint16_t       length = 0;
    const uint8_t *nlri = NULL;
    uint16_t       nlri_len = 0;
    uint8_t        nh_len = 0;
    int            nlri_count;

    if (!msg || !msg->data || msg->length < BGP_HEADER_SIZE + 4) {
        return 0;
    }

    if (msg->length != read_u16(msg->data + 16) || msg->data[18] != BGP_MSG_UPDATE) {
        return 0;
    }

    if (read_u16(msg->data + BGP_HEADER_SIZE) != 0) {
        return 0;
    }

    if (!find_attr(msg->data, msg->length, BGP_ATTR_ORIGIN, &value, &length) ||
        length != 1 || value[0] != expected_origin) {
        return 0;
    }

    if (!find_attr(msg->data, msg->length, BGP_ATTR_AS_PATH, NULL, NULL) ||
        !find_attr(msg->data, msg->length, BGP_ATTR_LOCAL_PREF, &value, &length) ||
        length != 4 || read_u32(value) != expected_local_pref ||
        find_attr(msg->data, msg->length, BGP_ATTR_NEXT_HOP, NULL, NULL) ||
        !extract_mp_reach_labeled_ipv4(msg->data, msg->length, &value, &nh_len, &nlri, &nlri_len) ||
        nh_len != expected_next_hop_len ||
        memcmp(value, expected_next_hop, expected_next_hop_len) != 0) {
        return 0;
    }

    nlri_count = count_labeled_nlri(nlri, nlri_len, expected_add_path);
    if (nlri_count <= 0) {
        return 0;
    }

    *nlri_count_out = nlri_count;
    return 1;
}

static int validate_labeled_ipv6_update_message(const bgp_msg_t *msg,
                                                uint8_t expected_origin,
                                                uint32_t expected_local_pref,
                                                const uint8_t *expected_next_hop,
                                                uint8_t expected_next_hop_len,
                                                int expected_add_path,
                                                int *nlri_count_out) {
    const uint8_t *value = NULL;
    uint16_t       length = 0;
    const uint8_t *nlri = NULL;
    uint16_t       nlri_len = 0;
    uint8_t        nh_len = 0;
    int            nlri_count;

    if (!msg || !msg->data || msg->length < BGP_HEADER_SIZE + 4) {
        return 0;
    }

    if (msg->length != read_u16(msg->data + 16) || msg->data[18] != BGP_MSG_UPDATE) {
        return 0;
    }

    if (read_u16(msg->data + BGP_HEADER_SIZE) != 0) {
        return 0;
    }

    if (!find_attr(msg->data, msg->length, BGP_ATTR_ORIGIN, &value, &length) ||
        length != 1 || value[0] != expected_origin) {
        return 0;
    }

    if (!find_attr(msg->data, msg->length, BGP_ATTR_AS_PATH, NULL, NULL) ||
        !find_attr(msg->data, msg->length, BGP_ATTR_LOCAL_PREF, &value, &length) ||
        length != 4 || read_u32(value) != expected_local_pref ||
        find_attr(msg->data, msg->length, BGP_ATTR_NEXT_HOP, NULL, NULL) ||
        !extract_mp_reach_labeled_ipv6(msg->data, msg->length, &value, &nh_len, &nlri, &nlri_len) ||
        nh_len != expected_next_hop_len ||
        memcmp(value, expected_next_hop, expected_next_hop_len) != 0) {
        return 0;
    }

    nlri_count = count_labeled_nlri(nlri, nlri_len, expected_add_path);
    if (nlri_count <= 0) {
        return 0;
    }

    *nlri_count_out = nlri_count;
    return 1;
}

static int validate_labeled_ipv4_add_path_against_generator(const bgp_msg_t *msg, bgp_ribout_config_t *block) {
    bgp_ribout_gen_t gen;
    const uint8_t   *nlri = NULL;
    uint16_t         nlri_len = 0;
    int              offset = 0;

    if (!msg || !msg->data || msg->length < BGP_HEADER_SIZE + 4 ||
        bgp_ribout_generator_init(&gen, block) != 0 ||
        !extract_mp_reach_labeled_ipv4(msg->data, msg->length, NULL, NULL, &nlri, &nlri_len)) {
        return 0;
    }

    while (offset < nlri_len) {
        bgp_gen_path_t expected;
        uint32_t       path_id;
        uint8_t        prefix_len;
        int            prefix_bytes;

        if (!bgp_ribout_generator_has_next(&gen) ||
            bgp_ribout_generator_next(&gen, &expected) != 0 ||
            expected.prefix_af != AF_INET ||
            !expected.has_label ||
            offset + 8 > nlri_len) {
            return 0;
        }

        path_id = read_u32(nlri + offset);
        offset += 4;
        prefix_len = nlri[offset++];
        prefix_bytes = (expected.prefix_len + 7) / 8;

        if (path_id != expected.path_id ||
            prefix_len != (uint8_t)(24 + expected.prefix_len) ||
            decode_wire_label(nlri + offset) != expected.label ||
            offset + 3 + prefix_bytes > nlri_len ||
            memcmp(nlri + offset + 3,
                   &expected.prefix_addr.ipv4,
                   (size_t)prefix_bytes) != 0) {
            return 0;
        }

        offset += 3 + prefix_bytes;
    }

    return (offset == nlri_len) && !bgp_ribout_generator_has_next(&gen);
}

static int validate_labeled_ipv6_add_path_against_generator(const bgp_msg_t *msg, bgp_ribout_config_t *block) {
    bgp_ribout_gen_t gen;
    const uint8_t   *nlri = NULL;
    uint16_t         nlri_len = 0;
    int              offset = 0;

    if (!msg || !msg->data || msg->length < BGP_HEADER_SIZE + 4 ||
        bgp_ribout_generator_init(&gen, block) != 0 ||
        !extract_mp_reach_labeled_ipv6(msg->data, msg->length, NULL, NULL, &nlri, &nlri_len)) {
        return 0;
    }

    while (offset < nlri_len) {
        bgp_gen_path_t expected;
        uint32_t       path_id;
        uint8_t        prefix_len;
        int            prefix_bytes;

        if (!bgp_ribout_generator_has_next(&gen) ||
            bgp_ribout_generator_next(&gen, &expected) != 0 ||
            expected.prefix_af != AF_INET6 ||
            !expected.has_label ||
            offset + 8 > nlri_len) {
            return 0;
        }

        path_id = read_u32(nlri + offset);
        offset += 4;
        prefix_len = nlri[offset++];
        prefix_bytes = (expected.prefix_len + 7) / 8;

        if (path_id != expected.path_id ||
            prefix_len != (uint8_t)(24 + expected.prefix_len) ||
            decode_wire_label(nlri + offset) != expected.label ||
            offset + 3 + prefix_bytes > nlri_len ||
            memcmp(nlri + offset + 3,
                   &expected.prefix_addr.ipv6,
                   (size_t)prefix_bytes) != 0) {
            return 0;
        }

        offset += 3 + prefix_bytes;
    }

    return (offset == nlri_len) && !bgp_ribout_generator_has_next(&gen);
}

static void test_ribout_config_to_encoded_updates(void) {
    bgp_ribout_config_t block;
    bgp_msg_t          *msg;
    uint8_t             next_hop[4];
    size_t              actual_messages;
    int                 total_nlri = 0;

    TEST("Config -> map -> encoded UPDATE bytes");

    bgp_ribout_init(&block, "e2e-wire");

    ASSERT(bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/24 x 1500") == 0, "Failed to parse prefix");
    ASSERT(bgp_ribout_parse_next_hop(&block, "next-hop 192.0.2.1") == 0, "Failed to parse next-hop");
    ASSERT(bgp_ribout_parse_aspath(&block, "as-path 65001 65002 65003") == 0, "Failed to parse AS path");
    ASSERT(bgp_ribout_parse_localpref(&block, "localpref 150") == 0, "Failed to parse localpref");
    ASSERT(bgp_ribout_parse_origin(&block, "origin incomplete") == 0, "Failed to parse origin");

    ASSERT(bgp_ribout_generate_map(&block) == 0, "Map generation failed");
    ASSERT(block.ribout != NULL, "Map not created");
    ASSERT(block.ribout->entry_count == 1, "Expected one grouped path-attribute entry");
    ASSERT(block.ribout->total_nlri_count == 1500, "Expected 1500 generated NLRIs");

    ASSERT(bgp_ribout_generate_messages(&block) == 0, "Message generation failed");
    ASSERT(block.ribout == NULL, "Message generation should release the temporary map");
    ASSERT(block.messages != NULL, "No encoded messages were produced");
    ASSERT(block.message_count > 1, "Expected split UPDATE messages");
    ASSERT(block.generation_time_ms >= 0.0, "Missing generation time");

    inet_pton(AF_INET, "192.0.2.1", next_hop);
    actual_messages = count_messages(block.messages);
    ASSERT(actual_messages == block.message_count, "Linked-list message count does not match metadata");

    /*
     * This walks the real wire bytes produced by the ribout pipeline. It
     * validates that every split UPDATE still carries the expected attributes
     * and that the total NLRI count matches the configured prefix count.
     */
    for (msg = block.messages; msg; msg = msg->next) {
        int message_nlri = 0;

        ASSERT(validate_ipv4_update_message(msg,
                                            BGP_ORIGIN_INCOMPLETE,
                                            150,
                                            next_hop,
                                            &message_nlri),
               "Encoded UPDATE bytes are not RFC-shaped");
        total_nlri += message_nlri;
    }

    ASSERT(total_nlri == 1500, "Encoded NLRI total does not match configured prefixes");

    bgp_ribout_destroy(&block);
    PASS();
}

static void test_ribout_ipv6_config_to_encoded_updates(void) {
    bgp_ribout_config_t block;
    bgp_msg_t          *msg;
    uint8_t             next_hop[16];
    int                 total_nlri = 0;

    TEST("IPv6 config -> map -> encoded UPDATE bytes");

    bgp_ribout_init(&block, "e2e-wire-v6");

    ASSERT(bgp_ribout_parse_prefix(&block, "prefix 2001:db8::/64 x 1500") == 0, "Failed to parse IPv6 prefix");
    ASSERT(bgp_ribout_parse_next_hop(&block, "next-hop 2001:db8:ffff::1") == 0, "Failed to parse IPv6 next-hop");
    ASSERT(bgp_ribout_parse_aspath(&block, "as-path 65001 65002 65003") == 0, "Failed to parse AS path");
    ASSERT(bgp_ribout_parse_localpref(&block, "localpref 175") == 0, "Failed to parse localpref");
    ASSERT(bgp_ribout_parse_origin(&block, "origin incomplete") == 0, "Failed to parse origin");

    ASSERT(bgp_ribout_generate_map(&block) == 0, "Map generation failed");
    ASSERT(block.ribout != NULL, "Map not created");
    ASSERT(block.ribout->entry_count == 1, "Expected one grouped path-attribute entry");
    ASSERT(block.ribout->total_nlri_count == 1500, "Expected 1500 generated NLRIs");

    ASSERT(bgp_ribout_generate_messages(&block) == 0, "Message generation failed");
    ASSERT(block.ribout == NULL, "Message generation should release the temporary map");
    ASSERT(block.messages != NULL, "No encoded messages were produced");
    ASSERT(block.message_count > 1, "Expected split IPv6 UPDATE messages");

    inet_pton(AF_INET6, "2001:db8:ffff::1", next_hop);

    for (msg = block.messages; msg; msg = msg->next) {
        int message_nlri = 0;

        ASSERT(validate_ipv6_update_message(msg,
                                            BGP_ORIGIN_INCOMPLETE,
                                            175,
                                            next_hop,
                                            16,
                                            &message_nlri),
               "Encoded IPv6 UPDATE bytes are not RFC-shaped");
        total_nlri += message_nlri;
    }

    ASSERT(total_nlri == 1500, "Encoded IPv6 NLRI total does not match configured prefixes");

    bgp_ribout_destroy(&block);
    PASS();
}

static void test_ribout_ipv4_rfc8950_config_to_encoded_updates(void) {
    bgp_ribout_config_t block;
    bgp_msg_t          *msg;
    uint8_t             next_hop[16];
    int                 total_nlri = 0;

    TEST("IPv4 RFC 8950 config -> MP UPDATE bytes");

    bgp_ribout_init(&block, "e2e-wire-v4-mp");

    ASSERT(bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/24 x 1500") == 0, "Failed to parse IPv4 prefix");
    ASSERT(bgp_ribout_parse_next_hop(&block, "next-hop 2001:db8:ffff::1") == 0, "Failed to parse IPv6 next-hop");
    ASSERT(bgp_ribout_parse_aspath(&block, "as-path 65001 65002 65003") == 0, "Failed to parse AS path");
    ASSERT(bgp_ribout_parse_localpref(&block, "localpref 160") == 0, "Failed to parse localpref");
    ASSERT(bgp_ribout_parse_origin(&block, "origin incomplete") == 0, "Failed to parse origin");

    ASSERT(bgp_ribout_generate_map(&block) == 0, "Map generation failed");
    ASSERT(block.ribout != NULL, "Map not created");
    ASSERT(block.ribout->entry_count == 1, "Expected one grouped path-attribute entry");
    ASSERT(block.ribout->total_nlri_count == 1500, "Expected 1500 generated NLRIs");

    ASSERT(bgp_ribout_generate_messages(&block) == 0, "Message generation failed");
    ASSERT(block.ribout == NULL, "Message generation should release the temporary map");
    ASSERT(block.messages != NULL, "No encoded messages were produced");
    ASSERT(block.message_count > 1, "Expected split RFC 8950 UPDATE messages");

    inet_pton(AF_INET6, "2001:db8:ffff::1", next_hop);

    for (msg = block.messages; msg; msg = msg->next) {
        int message_nlri = 0;

        ASSERT(validate_ipv4_rfc8950_update_message(msg,
                                                    BGP_ORIGIN_INCOMPLETE,
                                                    160,
                                                    next_hop,
                                                    16,
                                                    &message_nlri),
               "Encoded RFC 8950 UPDATE bytes are not RFC-shaped");
        total_nlri += message_nlri;
    }

    ASSERT(total_nlri == 1500, "Encoded NLRI total does not match configured prefixes");

    bgp_ribout_destroy(&block);
    PASS();
}

static void test_ribout_labeled_ipv4_config_to_encoded_updates(void) {
    bgp_ribout_config_t block;
    bgp_msg_t          *msg;
    uint8_t             next_hop[4];
    int                 total_nlri = 0;

    TEST("IPv4 labeled-unicast config -> MP UPDATE bytes");

    bgp_ribout_init(&block, "e2e-wire-lu-v4");

    ASSERT(bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/24 x 1500") == 0, "Failed to parse IPv4 prefix");
    ASSERT(bgp_ribout_parse_label(&block, "label 16000") == 0, "Failed to parse label");
    ASSERT(bgp_ribout_parse_next_hop(&block, "next-hop 192.0.2.1") == 0, "Failed to parse next-hop");
    ASSERT(bgp_ribout_parse_aspath(&block, "as-path 65001 65002 65003") == 0, "Failed to parse AS path");
    ASSERT(bgp_ribout_parse_localpref(&block, "localpref 155") == 0, "Failed to parse localpref");
    ASSERT(bgp_ribout_parse_origin(&block, "origin incomplete") == 0, "Failed to parse origin");

    ASSERT(bgp_ribout_generate_map(&block) == 0, "Map generation failed");
    ASSERT(block.ribout != NULL, "Map not created");
    ASSERT(block.ribout->entry_count == 1, "Expected one grouped path-attribute entry");
    ASSERT(block.ribout->total_nlri_count == 1500, "Expected 1500 generated NLRIs");

    ASSERT(bgp_ribout_generate_messages(&block) == 0, "Message generation failed");
    ASSERT(block.ribout == NULL, "Message generation should release the temporary map");
    ASSERT(block.messages != NULL, "No encoded messages were produced");
    ASSERT(block.message_count > 1, "Expected split labeled UPDATE messages");

    inet_pton(AF_INET, "192.0.2.1", next_hop);

    for (msg = block.messages; msg; msg = msg->next) {
        int message_nlri = 0;

        ASSERT(validate_labeled_ipv4_update_message(msg,
                                                    BGP_ORIGIN_INCOMPLETE,
                                                    155,
                                                    next_hop,
                                                    4,
                                                    0,
                                                    &message_nlri),
               "Encoded labeled IPv4 UPDATE bytes are not RFC-shaped");
        total_nlri += message_nlri;
    }

    ASSERT(total_nlri == 1500, "Encoded labeled IPv4 NLRI total does not match prefixes");

    bgp_ribout_destroy(&block);
    PASS();
}

static void test_ribout_labeled_ipv4_rfc8950_config_to_encoded_updates(void) {
    bgp_ribout_config_t block;
    bgp_msg_t          *msg;
    uint8_t             next_hop[16];
    int                 total_nlri = 0;

    TEST("IPv4 labeled-unicast RFC 8950 config -> MP UPDATE bytes");

    bgp_ribout_init(&block, "e2e-wire-lu-v4-mp");

    ASSERT(bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/24 x 1500") == 0, "Failed to parse IPv4 prefix");
    ASSERT(bgp_ribout_parse_label(&block, "label 24000") == 0, "Failed to parse label");
    ASSERT(bgp_ribout_parse_next_hop(&block, "next-hop 2001:db8:ffff::1") == 0, "Failed to parse IPv6 next-hop");
    ASSERT(bgp_ribout_parse_aspath(&block, "as-path 65001 65002 65003") == 0, "Failed to parse AS path");
    ASSERT(bgp_ribout_parse_localpref(&block, "localpref 165") == 0, "Failed to parse localpref");
    ASSERT(bgp_ribout_parse_origin(&block, "origin incomplete") == 0, "Failed to parse origin");

    ASSERT(bgp_ribout_generate_map(&block) == 0, "Map generation failed");
    ASSERT(block.ribout != NULL, "Map not created");
    ASSERT(block.ribout->entry_count == 1, "Expected one grouped path-attribute entry");
    ASSERT(block.ribout->total_nlri_count == 1500, "Expected 1500 generated NLRIs");

    ASSERT(bgp_ribout_generate_messages(&block) == 0, "Message generation failed");
    ASSERT(block.ribout == NULL, "Message generation should release the temporary map");
    ASSERT(block.messages != NULL, "No encoded messages were produced");
    ASSERT(block.message_count > 1, "Expected split labeled RFC 8950 UPDATE messages");

    inet_pton(AF_INET6, "2001:db8:ffff::1", next_hop);

    for (msg = block.messages; msg; msg = msg->next) {
        int message_nlri = 0;

        ASSERT(validate_labeled_ipv4_update_message(msg,
                                                    BGP_ORIGIN_INCOMPLETE,
                                                    165,
                                                    next_hop,
                                                    16,
                                                    0,
                                                    &message_nlri),
               "Encoded labeled IPv4 RFC 8950 UPDATE bytes are not RFC-shaped");
        total_nlri += message_nlri;
    }

    ASSERT(total_nlri == 1500, "Encoded labeled IPv4 RFC 8950 NLRI total mismatch");

    bgp_ribout_destroy(&block);
    PASS();
}

static void test_ribout_labeled_ipv6_config_to_encoded_updates(void) {
    bgp_ribout_config_t block;
    bgp_msg_t          *msg;
    uint8_t             next_hop[16];
    int                 total_nlri = 0;

    TEST("IPv6 labeled-unicast config -> MP UPDATE bytes");

    bgp_ribout_init(&block, "e2e-wire-lu-v6");

    ASSERT(bgp_ribout_parse_prefix(&block, "prefix 2001:db8::/64 x 1500") == 0, "Failed to parse IPv6 prefix");
    ASSERT(bgp_ribout_parse_label(&block, "label 32000") == 0, "Failed to parse label");
    ASSERT(bgp_ribout_parse_next_hop(&block, "next-hop 2001:db8:ffff::1") == 0, "Failed to parse IPv6 next-hop");
    ASSERT(bgp_ribout_parse_aspath(&block, "as-path 65001 65002 65003") == 0, "Failed to parse AS path");
    ASSERT(bgp_ribout_parse_localpref(&block, "localpref 175") == 0, "Failed to parse localpref");
    ASSERT(bgp_ribout_parse_origin(&block, "origin incomplete") == 0, "Failed to parse origin");

    ASSERT(bgp_ribout_generate_map(&block) == 0, "Map generation failed");
    ASSERT(block.ribout != NULL, "Map not created");
    ASSERT(block.ribout->entry_count == 1, "Expected one grouped path-attribute entry");
    ASSERT(block.ribout->total_nlri_count == 1500, "Expected 1500 generated NLRIs");

    ASSERT(bgp_ribout_generate_messages(&block) == 0, "Message generation failed");
    ASSERT(block.ribout == NULL, "Message generation should release the temporary map");
    ASSERT(block.messages != NULL, "No encoded messages were produced");
    ASSERT(block.message_count > 1, "Expected split labeled IPv6 UPDATE messages");

    inet_pton(AF_INET6, "2001:db8:ffff::1", next_hop);

    for (msg = block.messages; msg; msg = msg->next) {
        int message_nlri = 0;

        ASSERT(validate_labeled_ipv6_update_message(msg,
                                                    BGP_ORIGIN_INCOMPLETE,
                                                    175,
                                                    next_hop,
                                                    16,
                                                    0,
                                                    &message_nlri),
               "Encoded labeled IPv6 UPDATE bytes are not RFC-shaped");
        total_nlri += message_nlri;
    }

    ASSERT(total_nlri == 1500, "Encoded labeled IPv6 NLRI total does not match prefixes");

    bgp_ribout_destroy(&block);
    PASS();
}

static void test_ribout_vpnv4_config_to_encoded_updates(void) {
    bgp_ribout_config_t block;
    bgp_msg_t          *msg;
    uint8_t             next_hop[12] = {0};
    int                 total_nlri = 0;

    TEST("VPNv4 config -> MP UPDATE bytes");

    bgp_ribout_init(&block, "e2e-wire-vpnv4");

    ASSERT(bgp_ribout_parse_prefix(&block, "prefix 10.10.0.0/24 x 3") == 0, "Failed to parse VPNv4 prefix");
    ASSERT(bgp_ribout_parse_rd(&block, "rd 65000:100") == 0, "Failed to parse RD");
    ASSERT(bgp_ribout_parse_label(&block, "label 16000") == 0, "Failed to parse label");
    ASSERT(bgp_ribout_parse_next_hop(&block, "next-hop 192.0.2.1") == 0, "Failed to parse next-hop");
    ASSERT(bgp_ribout_parse_rt(&block, "rt 65000:100") == 0, "Failed to parse RT");
    ASSERT(bgp_ribout_parse_soo(&block, "soo 65000:9") == 0, "Failed to parse SoO");
    ASSERT(bgp_ribout_parse_med(&block, "med 50") == 0, "Failed to parse MED");
    ASSERT(bgp_ribout_parse_aspath(&block, "as-path 65100 65200") == 0, "Failed to parse AS path");
    ASSERT(bgp_ribout_parse_localpref(&block, "localpref 200") == 0, "Failed to parse localpref");
    ASSERT(bgp_ribout_parse_origin(&block, "origin igp") == 0, "Failed to parse origin");

    ASSERT(bgp_ribout_generate_map(&block) == 0, "Map generation failed");
    ASSERT(block.ribout != NULL, "Map not created");
    ASSERT(block.ribout->entry_count == 1, "Expected one VPNv4 attribute group");
    ASSERT(block.ribout->total_nlri_count == 3, "Expected 3 generated VPNv4 NLRIs");

    ASSERT(bgp_ribout_generate_messages(&block) == 0, "Message generation failed");
    ASSERT(block.messages != NULL, "No encoded messages were produced");

    next_hop[8] = 192;
    next_hop[9] = 0;
    next_hop[10] = 2;
    next_hop[11] = 1;

    for (msg = block.messages; msg; msg = msg->next) {
        int message_nlri = 0;

        ASSERT(validate_vpn_update_message(msg,
                                           AFI_IPV4,
                                           BGP_ORIGIN_IGP,
                                           200,
                                           50,
                                           1,
                                           next_hop,
                                           12,
                                           16,
                                           0,
                                           &message_nlri),
               "Encoded VPNv4 UPDATE bytes are not RFC-shaped");
        total_nlri += message_nlri;
    }

    ASSERT(total_nlri == 3, "Encoded VPNv4 NLRI total does not match configured prefixes");

    bgp_ribout_destroy(&block);
    PASS();
}

static void test_ribout_vpnv6_ipv4_transport_config_to_encoded_updates(void) {
    bgp_ribout_config_t block;
    bgp_msg_t          *msg;
    uint8_t             next_hop[24] = {0};
    int                 total_nlri = 0;

    TEST("VPNv6 over IPv4 transport config -> MP UPDATE bytes");

    bgp_ribout_init(&block, "e2e-wire-vpnv6-v4");

    ASSERT(bgp_ribout_parse_prefix(&block, "prefix 2001:db8:100::/64 x 2") == 0, "Failed to parse VPNv6 prefix");
    ASSERT(bgp_ribout_parse_rd(&block, "rd 65000:200") == 0, "Failed to parse RD");
    ASSERT(bgp_ribout_parse_label(&block, "label 24000") == 0, "Failed to parse label");
    ASSERT(bgp_ribout_parse_next_hop(&block, "next-hop 192.0.2.33") == 0, "Failed to parse next-hop");
    ASSERT(bgp_ribout_parse_rt(&block, "rt 65000:200") == 0, "Failed to parse RT");
    ASSERT(bgp_ribout_parse_med(&block, "med 25") == 0, "Failed to parse MED");
    ASSERT(bgp_ribout_parse_aspath(&block, "as-path 65300 65400") == 0, "Failed to parse AS path");
    ASSERT(bgp_ribout_parse_localpref(&block, "localpref 175") == 0, "Failed to parse localpref");
    ASSERT(bgp_ribout_parse_origin(&block, "origin incomplete") == 0, "Failed to parse origin");

    ASSERT(bgp_ribout_generate_map(&block) == 0, "Map generation failed");
    ASSERT(block.ribout != NULL, "Map not created");
    ASSERT(block.ribout->entry_count == 1, "Expected one VPNv6 attribute group");
    ASSERT(block.ribout->total_nlri_count == 2, "Expected 2 generated VPNv6 NLRIs");

    ASSERT(bgp_ribout_generate_messages(&block) == 0, "Message generation failed");
    ASSERT(block.messages != NULL, "No encoded messages were produced");

    next_hop[18] = 0xFF;
    next_hop[19] = 0xFF;
    next_hop[20] = 192;
    next_hop[21] = 0;
    next_hop[22] = 2;
    next_hop[23] = 33;

    for (msg = block.messages; msg; msg = msg->next) {
        int message_nlri = 0;

        ASSERT(validate_vpn_update_message(msg,
                                           AFI_IPV6,
                                           BGP_ORIGIN_INCOMPLETE,
                                           175,
                                           25,
                                           1,
                                           next_hop,
                                           24,
                                           8,
                                           0,
                                           &message_nlri),
               "Encoded VPNv6 UPDATE bytes are not RFC-shaped");
        total_nlri += message_nlri;
    }

    ASSERT(total_nlri == 2, "Encoded VPNv6 NLRI total does not match configured prefixes");

    bgp_ribout_destroy(&block);
    PASS();
}

static void test_ribout_vpnv4_ext_nh_config_to_encoded_updates(void) {
    bgp_ribout_config_t block;
    bgp_msg_t          *msg;
    uint8_t             next_hop[24] = {0};
    int                 total_nlri = 0;

    TEST("VPNv4 RFC 8950 config -> MP UPDATE bytes");

    bgp_ribout_init(&block, "e2e-wire-vpnv4-extnh");

    ASSERT(bgp_ribout_parse_prefix(&block, "prefix 10.20.0.0/24 x 2") == 0, "Failed to parse VPNv4 prefix");
    ASSERT(bgp_ribout_parse_rd(&block, "rd 65000:110") == 0, "Failed to parse RD");
    ASSERT(bgp_ribout_parse_label(&block, "label 16010") == 0, "Failed to parse label");
    ASSERT(bgp_ribout_parse_next_hop(&block, "next-hop 2001:db8:ffff::1") == 0, "Failed to parse IPv6 next-hop");
    ASSERT(bgp_ribout_parse_rt(&block, "rt 65000:110") == 0, "Failed to parse RT");
    ASSERT(bgp_ribout_parse_med(&block, "med 60") == 0, "Failed to parse MED");
    ASSERT(bgp_ribout_parse_aspath(&block, "as-path 65110 65210") == 0, "Failed to parse AS path");
    ASSERT(bgp_ribout_parse_localpref(&block, "localpref 210") == 0, "Failed to parse localpref");
    ASSERT(bgp_ribout_parse_origin(&block, "origin incomplete") == 0, "Failed to parse origin");

    ASSERT(bgp_ribout_generate_map(&block) == 0, "Map generation failed");
    ASSERT(block.ribout != NULL, "Map not created");
    ASSERT(block.ribout->entry_count == 1, "Expected one VPNv4 ext-nh attribute group");
    ASSERT(block.ribout->total_nlri_count == 2, "Expected 2 generated VPNv4 NLRIs");

    ASSERT(bgp_ribout_generate_messages(&block) == 0, "Message generation failed");
    ASSERT(block.messages != NULL, "No encoded messages were produced");

    inet_pton(AF_INET6, "2001:db8:ffff::1", next_hop + 8);

    for (msg = block.messages; msg; msg = msg->next) {
        int message_nlri = 0;

        ASSERT(validate_vpn_update_message(msg,
                                           AFI_IPV4,
                                           BGP_ORIGIN_INCOMPLETE,
                                           210,
                                           60,
                                           1,
                                           next_hop,
                                           24,
                                           8,
                                           0,
                                           &message_nlri),
               "Encoded VPNv4 RFC 8950 UPDATE bytes are not RFC-shaped");
        total_nlri += message_nlri;
    }

    ASSERT(total_nlri == 2, "Encoded VPNv4 ext-nh NLRI total does not match configured prefixes");

    bgp_ribout_destroy(&block);
    PASS();
}

static void test_ribout_vpnv6_ipv6_transport_config_to_encoded_updates(void) {
    bgp_ribout_config_t block;
    bgp_msg_t          *msg;
    uint8_t             next_hop[48] = {0};
    int                 total_nlri = 0;

    TEST("VPNv6 over IPv6 transport config -> MP UPDATE bytes");

    bgp_ribout_init(&block, "e2e-wire-vpnv6-v6");

    ASSERT(bgp_ribout_parse_prefix(&block, "prefix 2001:db8:200::/64 x 2") == 0, "Failed to parse VPNv6 prefix");
    ASSERT(bgp_ribout_parse_rd(&block, "rd 65000:210") == 0, "Failed to parse RD");
    ASSERT(bgp_ribout_parse_label(&block, "label 24010") == 0, "Failed to parse label");
    ASSERT(bgp_ribout_parse_next_hop(
               &block,
               "next-hop 2001:db8:ffff::1 link-local fe80::1") == 0,
           "Failed to parse IPv6 next-hop with link-local");
    ASSERT(bgp_ribout_parse_rt(&block, "rt 65000:210") == 0, "Failed to parse RT");
    ASSERT(bgp_ribout_parse_med(&block, "med 30") == 0, "Failed to parse MED");
    ASSERT(bgp_ribout_parse_aspath(&block, "as-path 65310 65410") == 0, "Failed to parse AS path");
    ASSERT(bgp_ribout_parse_localpref(&block, "localpref 180") == 0, "Failed to parse localpref");
    ASSERT(bgp_ribout_parse_origin(&block, "origin igp") == 0, "Failed to parse origin");

    ASSERT(bgp_ribout_generate_map(&block) == 0, "Map generation failed");
    ASSERT(block.ribout != NULL, "Map not created");
    ASSERT(block.ribout->entry_count == 1, "Expected one VPNv6 IPv6-transport attribute group");
    ASSERT(block.ribout->total_nlri_count == 2, "Expected 2 generated VPNv6 NLRIs");

    ASSERT(bgp_ribout_generate_messages(&block) == 0, "Message generation failed");
    ASSERT(block.messages != NULL, "No encoded messages were produced");

    inet_pton(AF_INET6, "2001:db8:ffff::1", next_hop + 8);
    inet_pton(AF_INET6, "fe80::1", next_hop + 32);

    for (msg = block.messages; msg; msg = msg->next) {
        int message_nlri = 0;

        ASSERT(validate_vpn_update_message(msg,
                                           AFI_IPV6,
                                           BGP_ORIGIN_IGP,
                                           180,
                                           30,
                                           1,
                                           next_hop,
                                           48,
                                           8,
                                           0,
                                           &message_nlri),
               "Encoded VPNv6 IPv6-transport UPDATE bytes are not RFC-shaped");
        total_nlri += message_nlri;
    }

    ASSERT(total_nlri == 2, "Encoded VPNv6 IPv6-transport NLRI total does not match configured prefixes");

    bgp_ribout_destroy(&block);
    PASS();
}

static void test_ribout_evpn_type5_config_to_encoded_updates(void) {
    bgp_ribout_config_t block;
    bgp_msg_t          *msg;
    uint8_t             next_hop[4];
    int                 total_nlri = 0;
    int                 short_rt_msgs = 0;
    int                 long_rt_msgs = 0;

    TEST("EVPN type 5 config -> MP UPDATE bytes");

    bgp_ribout_init(&block, "e2e-wire-evpn5");

    ASSERT(bgp_ribout_parse_prefix(&block, "prefix 192.168.0.0/24 x 2") == 0, "Failed to parse EVPN prefix");
    ASSERT(bgp_ribout_parse_rd(&block, "rd 65000:300") == 0, "Failed to parse RD");
    ASSERT(bgp_ribout_parse_label(&block, "label 30000") == 0, "Failed to parse label");
    ASSERT(bgp_ribout_parse_ethernet_tag(&block, "ethernet-tag 0") == 0, "Failed to parse Ethernet Tag");
    ASSERT(bgp_ribout_parse_gateway_ip(&block, "gateway-ip 10.255.0.1") == 0, "Failed to parse gateway IP");
    ASSERT(bgp_ribout_parse_next_hop(&block, "next-hop 192.0.2.10") == 0, "Failed to parse next-hop");
    ASSERT(bgp_ribout_parse_rt_set(&block, "rt-set [65000:300] [65000:301,65000:302]") == 0, "Failed to parse RT sets");
    ASSERT(bgp_ribout_parse_med(&block, "med 10") == 0, "Failed to parse MED");
    ASSERT(bgp_ribout_parse_aspath(&block, "as-path 65500") == 0, "Failed to parse AS path");
    ASSERT(bgp_ribout_parse_localpref(&block, "localpref 250") == 0, "Failed to parse localpref");
    ASSERT(bgp_ribout_parse_origin(&block, "origin igp") == 0, "Failed to parse origin");

    ASSERT(bgp_ribout_generate_map(&block) == 0, "Map generation failed");
    ASSERT(block.ribout != NULL, "Map not created");
    ASSERT(block.ribout->entry_count == 2, "Expected one EVPN group per RT set");
    ASSERT(block.ribout->total_nlri_count == 2, "Expected 2 generated EVPN NLRIs");

    ASSERT(bgp_ribout_generate_messages(&block) == 0, "Message generation failed");
    ASSERT(block.messages != NULL, "No encoded messages were produced");
    ASSERT(block.message_count == 2, "Expected one UPDATE per EVPN RT set");

    inet_pton(AF_INET, "192.0.2.10", next_hop);

    for (msg = block.messages; msg; msg = msg->next) {
        int            message_nlri = 0;
        const uint8_t *ext_comm = NULL;
        uint16_t       ext_comm_len = 0;

        ASSERT(find_attr(msg->data, msg->length, BGP_ATTR_EXT_COMM,
                         &ext_comm, &ext_comm_len),
               "Missing EVPN extended communities");
        if (ext_comm_len == 8) {
            short_rt_msgs++;
        } else if (ext_comm_len == 16) {
            long_rt_msgs++;
        } else {
            ASSERT(0, "Unexpected EVPN extended communities length");
        }

        ASSERT(validate_evpn_update_message(msg,
                                            BGP_ORIGIN_IGP,
                                            250,
                                            10,
                                            1,
                                            next_hop,
                                            4,
                                            ext_comm_len,
                                            0,
                                            &message_nlri),
               "Encoded EVPN type 5 UPDATE bytes are not RFC-shaped");
        total_nlri += message_nlri;
    }

    ASSERT(short_rt_msgs == 1 && long_rt_msgs == 1, "Expected one EVPN message per RT set shape");
    ASSERT(total_nlri == 2, "Encoded EVPN NLRI total does not match configured prefixes");

    bgp_ribout_destroy(&block);
    PASS();
}

static void test_ribout_evpn_type5_ipv6_config_to_encoded_updates(void) {
    bgp_ribout_config_t block;
    bgp_msg_t          *msg;
    uint8_t             next_hop[16];
    int                 total_nlri = 0;

    TEST("EVPN type 5 IPv6 config -> MP UPDATE bytes");

    bgp_ribout_init(&block, "e2e-wire-evpn5-v6");

    ASSERT(bgp_ribout_parse_prefix(&block, "prefix 2001:db8:feed::/64 x 2") == 0, "Failed to parse EVPN IPv6 prefix");
    ASSERT(bgp_ribout_parse_rd(&block, "rd 65000:310") == 0, "Failed to parse RD");
    ASSERT(bgp_ribout_parse_label(&block, "label 31000") == 0, "Failed to parse label");
    ASSERT(bgp_ribout_parse_ethernet_tag(&block, "ethernet-tag 0") == 0, "Failed to parse Ethernet Tag");
    ASSERT(bgp_ribout_parse_gateway_ip(&block, "gateway-ip 2001:db8:ffff::10") == 0, "Failed to parse gateway IP");
    ASSERT(bgp_ribout_parse_next_hop(&block, "next-hop 2001:db8:ee::10") == 0, "Failed to parse next-hop");
    ASSERT(bgp_ribout_parse_rt(&block, "rt 65000:310") == 0, "Failed to parse RT");
    ASSERT(bgp_ribout_parse_med(&block, "med 15") == 0, "Failed to parse MED");
    ASSERT(bgp_ribout_parse_aspath(&block, "as-path 65510") == 0, "Failed to parse AS path");
    ASSERT(bgp_ribout_parse_localpref(&block, "localpref 225") == 0, "Failed to parse localpref");
    ASSERT(bgp_ribout_parse_origin(&block, "origin incomplete") == 0, "Failed to parse origin");

    ASSERT(bgp_ribout_generate_map(&block) == 0, "Map generation failed");
    ASSERT(block.ribout != NULL, "Map not created");
    ASSERT(block.ribout->entry_count == 1, "Expected one EVPN IPv6 attribute group");
    ASSERT(block.ribout->total_nlri_count == 2, "Expected 2 generated EVPN IPv6 NLRIs");

    ASSERT(bgp_ribout_generate_messages(&block) == 0, "Message generation failed");
    ASSERT(block.messages != NULL, "No encoded messages were produced");
    ASSERT(block.message_count == 1, "Expected one EVPN IPv6 UPDATE");

    inet_pton(AF_INET6, "2001:db8:ee::10", next_hop);

    for (msg = block.messages; msg; msg = msg->next) {
        int message_nlri = 0;

        ASSERT(validate_evpn_update_message(msg,
                                            BGP_ORIGIN_INCOMPLETE,
                                            225,
                                            15,
                                            1,
                                            next_hop,
                                            16,
                                            8,
                                            0,
                                            &message_nlri),
               "Encoded EVPN type 5 IPv6 UPDATE bytes are not RFC-shaped");
        total_nlri += message_nlri;
    }

    ASSERT(total_nlri == 2, "Encoded EVPN IPv6 NLRI total does not match configured prefixes");

    bgp_ribout_destroy(&block);
    PASS();
}

static void test_ribout_evpn_type5_attr_ext_comms_to_encoded_updates(void) {
    bgp_ribout_config_t block;
    bgp_msg_t          *msg;
    uint8_t             next_hop[4];
    const uint8_t      *ext_comm = NULL;
    uint16_t            ext_comm_len = 0;
    int                 message_nlri = 0;

    TEST("EVPN type 5 encap/router-mac config -> MP UPDATE bytes");

    bgp_ribout_init(&block, "e2e-wire-evpn5-ext");

    ASSERT(bgp_ribout_parse_prefix(&block, "prefix 192.168.10.0/24") == 0, "Failed to parse EVPN prefix");
    ASSERT(bgp_ribout_parse_rd(&block, "rd 65000:330") == 0, "Failed to parse RD");
    ASSERT(bgp_ribout_parse_label(&block, "label 33000") == 0, "Failed to parse label");
    ASSERT(bgp_ribout_parse_ethernet_tag(&block, "ethernet-tag 0") == 0, "Failed to parse Ethernet Tag");
    ASSERT(bgp_ribout_parse_gateway_ip(&block, "gateway-ip 10.255.0.9") == 0, "Failed to parse gateway IP");
    ASSERT(bgp_ribout_parse_next_hop(&block, "next-hop 192.0.2.19") == 0, "Failed to parse next-hop");
    ASSERT(bgp_ribout_parse_rt(&block, "rt 65000:330") == 0, "Failed to parse RT");
    ASSERT(bgp_ribout_parse_encap(&block, "encap vxlan") == 0, "Failed to parse encap");
    ASSERT(bgp_ribout_parse_router_mac(&block, "router-mac 1") == 0, "Failed to parse router-mac");
    ASSERT(bgp_ribout_parse_aspath(&block, "as-path 65530") == 0, "Failed to parse AS path");
    ASSERT(bgp_ribout_parse_localpref(&block, "localpref 250") == 0, "Failed to parse localpref");
    ASSERT(bgp_ribout_parse_origin(&block, "origin igp") == 0, "Failed to parse origin");

    ASSERT(bgp_ribout_generate_map(&block) == 0, "Map generation failed");
    ASSERT(block.ribout != NULL, "Map not created");
    ASSERT(block.ribout->entry_count == 1, "Expected one EVPN Type 5 attribute group");
    ASSERT(block.ribout->total_nlri_count == 1, "Expected one generated EVPN Type 5 NLRI");

    ASSERT(bgp_ribout_generate_messages(&block) == 0, "Message generation failed");
    ASSERT(block.messages != NULL && block.message_count == 1, "Expected one EVPN Type 5 UPDATE");

    inet_pton(AF_INET, "192.0.2.19", next_hop);
    msg = block.messages;

    ASSERT(validate_evpn_update_message(msg,
                                        BGP_ORIGIN_IGP,
                                        250,
                                        0,
                                        0,
                                        next_hop,
                                        4,
                                        24,
                                        0,
                                        &message_nlri),
           "Encoded EVPN type 5 attr UPDATE bytes are not RFC-shaped");
    ASSERT(find_attr(msg->data, msg->length, BGP_ATTR_EXT_COMM, &ext_comm, &ext_comm_len) &&
           ext_comm_len == 24,
           "EVPN Type 5 attr UPDATE carries RT, encap, and router-mac");
    ASSERT(ext_comm[8] == 0x03 && ext_comm[9] == 0x0c &&
           read_u16(ext_comm + 14) == 8,
           "EVPN Type 5 attr UPDATE encodes VXLAN encap after RT");
    ASSERT(ext_comm[16] == 0x06 && ext_comm[17] == 0x03 &&
           memcmp(ext_comm + 18, (const uint8_t[]){0x00,0x00,0x00,0x00,0x00,0x01}, 6) == 0,
           "EVPN Type 5 attr UPDATE encodes Router's MAC after encap");
    ASSERT(message_nlri == 1, "Encoded EVPN Type 5 attr NLRI total is one");

    bgp_ribout_destroy(&block);
    PASS();
}

/*
 * Tunnel type of the UPDATE's Encapsulation extended community (RFC 9012), 0 without one.
 */
static uint16_t update_encap_tunnel(const uint8_t *msg, size_t size) {
    const uint8_t *value = NULL;
    uint16_t       length = 0;

    if (!find_attr(msg, size, BGP_ATTR_EXT_COMM, &value, &length)) {
        return 0;
    }
    for (uint16_t offset = 0; offset + 8 <= length; offset += 8) {
        if (value[offset] == 0x03 && value[offset + 1] == 0x0c) {
            return read_u16(value + offset + 6);
        }
    }
    return 0;
}

/*
 * The 3-byte EVPN label field for value: the VNI itself (RFC 8365), or an MPLS label with the bottom-of-stack bit.
 */
static void evpn_label_field(uint32_t value, int vni, uint8_t field[3]) {
    uint32_t bits = vni ? value : ((value << 4) | 1);

    field[0] = (uint8_t)(bits >> 16);
    field[1] = (uint8_t)(bits >> 8);
    field[2] = (uint8_t)bits;
}

/*
 * Walk the EVPN Type 2 and Type 5 NLRI of every UPDATE and check that each label field holds label (and Label2 holds
 * label2 when non-zero) in the form the UPDATE's encapsulation calls for: a VNI with VXLAN, NVGRE, VXLAN-GPE or Geneve,
 * an MPLS label otherwise. Counts the NLRI of each form; returns 0, or -1 on the first mismatch.
 */
static int check_evpn_label_forms(const bgp_msg_t *messages, uint32_t label, uint32_t label2, int *vni_nlri,
                                  int *mpls_nlri) {
    *vni_nlri = 0;
    *mpls_nlri = 0;
    for (const bgp_msg_t *msg = messages; msg; msg = msg->next) {
        uint16_t       tunnel = update_encap_tunnel(msg->data, msg->length);
        int            vni = tunnel == 8 || tunnel == 9 || tunnel == 12 || tunnel == 19;
        const uint8_t *next_hop = NULL;
        const uint8_t *nlri = NULL;
        uint8_t        next_hop_len = 0;
        uint16_t       nlri_len = 0;
        uint16_t       offset = 0;

        if (!extract_mp_reach_evpn_type5(msg->data, msg->length, &next_hop, &next_hop_len, &nlri, &nlri_len)) {
            return -1;
        }
        while (offset < nlri_len) {
            const uint8_t *route = nlri + offset + 2;
            uint8_t        route_len = (offset + 2 <= nlri_len) ? nlri[offset + 1] : 0;
            const uint8_t *field1 = NULL;
            const uint8_t *field2 = NULL;
            uint8_t        want[3];

            if (offset + 2 > nlri_len || offset + 2 + route_len > nlri_len) {
                return -1;
            }
            if (nlri[offset] == 5) {
                field1 = route + route_len - 3;  /* The label ends a Type 5 route (RFC 9136 section 3.1) */
            } else if (nlri[offset] == 2) {
                // RD (8), ESI (10), Ethernet tag (4), MAC length, MAC (6), IP length, IP, Label1, Label2
                field1 = route + 30 + route[29] / 8;
                field2 = (field1 + 3 < route + route_len) ? field1 + 3 : NULL;
            } else {
                return -1;
            }
            evpn_label_field(label, vni, want);
            if (memcmp(field1, want, 3) != 0) {
                return -1;
            }
            if (label2) {
                evpn_label_field(label2, vni, want);
                if (!field2 || memcmp(field2, want, 3) != 0) {
                    return -1;
                }
            }
            if (vni) {
                (*vni_nlri)++;
            } else {
                (*mpls_nlri)++;
            }
            offset += 2 + route_len;
        }
    }
    return 0;
}

/*
 * EVPN Type 2 with ip rotate on the wire: every MAC/IP route carries MAC i and IP i, once each, so the UPDATEs hold
 * 300 bindings (not 300 x 300 routes) whatever the attribute groups.
 */
static void test_ribout_evpn_type2_ip_rotate_bindings_on_wire(void) {
    bgp_ribout_config_t block;
    uint8_t             seen[300] = {0};
    int                 routes = 0;
    int                 bound = 1;

    TEST("EVPN Type 2 ip rotate: one MAC/IP binding per route on the wire");
    bgp_ribout_init(&block, "evpn2-bindings");
    ASSERT(bgp_ribout_parse_rd(&block, "rd 65551:7") == 0 &&
               bgp_ribout_parse_mac(&block, "mac 02:00:00:00:00:01 x 300") == 0 &&
               bgp_ribout_parse_ip(&block, "ip rotate 10.1.0.1 x 300") == 0 &&
               bgp_ribout_parse_label(&block, "label 20001 x 100") == 0 &&
               bgp_ribout_parse_rt_set(&block, "rt-set [65551:1] [65551:2] [65551:3]") == 0 &&
               bgp_ribout_parse_next_hop(&block, "next-hop 192.0.2.1") == 0 &&
               bgp_ribout_parse_aspath(&block, "as-path 65530") == 0,
           "Configure the Type 2 ribout");
    ASSERT(bgp_ribout_generate_map(&block) == 0 && bgp_ribout_generate_messages(&block) == 0, "Generate");
    for (const bgp_msg_t *msg = block.messages; msg; msg = msg->next) {
        const uint8_t *next_hop = NULL;
        const uint8_t *nlri = NULL;
        uint8_t        next_hop_len = 0;
        uint16_t       nlri_len = 0;

        ASSERT(extract_mp_reach_evpn_type5(msg->data, msg->length, &next_hop, &next_hop_len, &nlri, &nlri_len),
               "Every UPDATE carries EVPN MP_REACH_NLRI");
        for (uint16_t offset = 0; offset + 2 <= nlri_len; offset += 2 + nlri[offset + 1]) {
            // RD (8), ESI (10), Ethernet tag (4), MAC length, MAC (6), IP length, IP
            const uint8_t *route = nlri + offset + 2;
            int            host = ((route[27] << 8) | route[28]) - 1;
            uint32_t ip = ((uint32_t)route[30] << 24) | ((uint32_t)route[31] << 16) |
                          ((uint32_t)route[32] << 8) | route[33];

            bound = bound && nlri[offset] == 2 && route[29] == 32 && host >= 0 && host < 300 && !seen[host] &&
                    ip == 0x0A010001u + (uint32_t)host;
            if (host >= 0 && host < 300) {
                seen[host] = 1;
            }
            routes++;
        }
    }
    bgp_ribout_destroy(&block);
    ASSERT(routes == 300 && bound, "300 routes, each MAC i with IP i, every MAC once");
    PASS();
}

/*
 * One VRF per rotation step on the wire: VPNv4 with rd rotate, an rt-set sequence and label rotate (rotate-period 50,
 * rotate-every 2). Every NLRI's RD and label are those of its UPDATE's route target, and of its prefix: prefix i is in
 * VRF (i / 2) % 50 + 1.
 */
static void test_ribout_vpn_rotations_on_wire(void) {
    bgp_ribout_config_t block;
    int                 routes = 0;
    int                 in_step = 1;

    TEST("VPNv4 rd rotate, rt-set sequence, label rotate: one VRF per NLRI on the wire");
    bgp_ribout_init(&block, "vrfs-wire");
    ASSERT(bgp_ribout_parse_prefix(&block, "prefix 10.20.0.0/24 x 300") == 0 &&
               bgp_ribout_parse_rd(&block, "rd rotate 65551:1 x 50") == 0 &&
               bgp_ribout_parse_label(&block, "label rotate 24001 x 50") == 0 &&
               bgp_ribout_parse_rt_set(&block, "rt-set [65551:1] x 50") == 0 &&
               bgp_ribout_parse_rotate_every(&block, "rotate-every 2") == 0 &&
               bgp_ribout_parse_rotate_period(&block, "rotate-period 50") == 0 &&
               bgp_ribout_parse_next_hop(&block, "next-hop 192.0.2.1") == 0 &&
               bgp_ribout_parse_aspath(&block, "as-path 65530") == 0,
           "Configure the VPNv4 ribout");
    ASSERT(bgp_ribout_generate_map(&block) == 0 && bgp_ribout_generate_messages(&block) == 0, "Generate");
    for (const bgp_msg_t *msg = block.messages; msg; msg = msg->next) {
        const uint8_t *next_hop = NULL, *nlri = NULL, *ext_comm = NULL;
        uint8_t        next_hop_len = 0;
        uint16_t       nlri_len = 0, ext_comm_len = 0;
        uint32_t       vrf;

        ASSERT(extract_mp_reach_afi(msg->data, msg->length, AFI_IPV4, SAFI_MPLS_VPN, &next_hop, &next_hop_len, &nlri, &nlri_len) &&
                   find_attr(msg->data, msg->length, BGP_ATTR_EXT_COMM, &ext_comm, &ext_comm_len) && ext_comm_len == 8,
               "Every UPDATE carries VPNv4 NLRI and one route target");
        vrf = read_u16(ext_comm + 6);
        for (uint16_t offset = 0; offset < nlri_len;) {
            // length in bits, label (3), RD (8: type, AS (4), assigned (2)), prefix
            const uint8_t *route = nlri + offset;
            uint32_t       label = decode_wire_label(route + 1);
            uint32_t       prefix = ((uint32_t)route[12] << 16) | ((uint32_t)route[13] << 8) | route[14];  /* a /24 */
            uint32_t       index = prefix - 0x0A1400u;

            in_step = in_step && read_u16(route + 10) == vrf && label == 24000 + vrf &&
                      vrf == (index / 2) % 50 + 1;
            offset += 1 + (route[0] + 7) / 8;
            routes++;
        }
    }
    bgp_ribout_destroy(&block);
    ASSERT(routes == 300 && in_step, "300 routes, each RD and label the VRF of its route target and prefix");
    PASS();
}

/*
 * Apply "keyword value" lines to a fresh block; NULL ends the list.
 */
static int configure_lines(bgp_ribout_config_t *block, const char *name, const char *const *lines) {
    bgp_ribout_init(block, name);
    for (; *lines; lines++) {
        char        keyword[32];
        const char *value = strchr(*lines, ' ');

        if (!value || (size_t)(value - *lines) >= sizeof(keyword)) {
            return -1;
        }
        snprintf(keyword, sizeof(keyword), "%.*s", (int)(value - *lines), *lines);
        if (bgp_ribout_edit(block, keyword, value + 1, 0) != 0) {
            return -1;
        }
    }
    return 0;
}

/*
 * The path attributes of an UPDATE come in ascending type order (RFC 4271 section 5: SHOULD), MP_REACH_NLRI and
 * MP_UNREACH_NLRI aside.
 */
static int attrs_ascending(const uint8_t *msg, size_t size) {
    test_wire_update_t view;
    if (!test_wire_update_view(msg, size, &view)) return 0;
    size_t offset = BGP_HEADER_SIZE + 2 + view.withdrawn_len;
    size_t end = (size_t)(view.nlri - msg);
    int    last = 0;

    for (offset += 2; offset < end;) {
        uint8_t flags = msg[offset], type = msg[offset + 1];
        size_t  length = flags & 0x10 ? read_u16(msg + offset + 2) : msg[offset + 2];

        if (type != BGP_ATTR_MP_REACH_NLRI && type != BGP_ATTR_MP_UNREACH_NLRI) {
            if (type <= last) {
                return 0;
            }
            last = type;
        }
        offset += 2 + (flags & 0x10 ? 2 : 1) + length;
    }
    return 1;
}

/*
 * Write a 32-bit value in network byte order: the expected attribute bytes.
 */
static void put_be32(uint8_t *out, uint32_t value) {
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}

/*
 * COMMUNITIES (8, RFC 1997) and LARGE_COMMUNITY (32, RFC 8092) on the wire: optional transitive, one set per rotation
 * step, so the routes of an UPDATE share their set and route i carries community set i % 3 and large-community set
 * i % 2. Attributes keep ascending type order.
 */
static void test_ribout_communities_on_wire(void) {
    static const char *const k_lines[] = {
        "prefix 10.0.0.0/24 x 12",
        "next-hop 192.0.2.1",
        "as-path 65001",
        "localpref 200",
        "community [65000:1,no-export] 65000:100 x 2",
        "large-community [65000:1:10] [4200000000:7:7,1:2:3]",
        NULL,
    };
    // Wire values of the sets: [65000:1,no-export] [65000:100] [65000:101]; [65000:1:10] [4200000000:7:7,1:2:3]
    static const uint32_t k_comm[3][2] = {{0xFDE80001u, 0xFFFFFF01u}, {0xFDE80064u, 0}, {0xFDE80065u, 0}};
    static const int k_comm_count[3] = {2, 1, 1};
    static const uint32_t k_large[2][2][3] = {{{65000, 1, 10}, {0}}, {{4200000000u, 7, 7}, {1, 2, 3}}};
    static const int k_large_count[2] = {1, 2};
    bgp_ribout_config_t block;
    int                 routes = 0, messages = 0, matched = 1;
    uint32_t            seen = 0;

    TEST("COMMUNITIES and LARGE_COMMUNITY rotate per route on the wire, flags and order per RFC");
    ASSERT(configure_lines(&block, "comm-wire", k_lines) == 0, "Configure the ribout");
    ASSERT(bgp_ribout_generate_map(&block) == 0 && bgp_ribout_generate_messages(&block) == 0, "Generate");
    for (const bgp_msg_t *msg = block.messages; msg; msg = msg->next) {
        test_wire_update_t view;
        const uint8_t     *comm = NULL, *large = NULL;
        uint16_t           comm_len = 0, large_len = 0;
        uint8_t            comm_flags = 0, large_flags = 0;

        ASSERT(test_wire_update_view(msg->data, msg->length, &view) &&
               !view.has_reach &&
               view.nlri_len > 0,
               "Every UPDATE carries classic IPv4 NLRI");
        ASSERT(test_wire_find_attr(msg->data, msg->length, BGP_ATTR_COMMUNITIES, &comm, &comm_len, &comm_flags) &&
               test_wire_find_attr(msg->data, msg->length, BGP_ATTR_LARGE_COMMUNITY, &large, &large_len, &large_flags),
               "Every UPDATE carries one COMMUNITIES and one LARGE_COMMUNITY attribute");
        ASSERT(comm_flags == 0xC0 && large_flags == 0xC0, "Both are optional transitive, not partial");
        ASSERT(attrs_ascending(msg->data, msg->length), "Path attributes in ascending type order");
        for (size_t offset = 0; offset < view.nlri_len; offset += 1 + (view.nlri[offset] + 7) / 8) {
            int     index = view.nlri[offset + 3];  /* 10.0.<index>.0/24 */
            int     c = index % 3, l = index % 2;
            uint8_t want[24];

            matched = matched && view.nlri[offset] == 24 && comm_len == 4 * k_comm_count[c] &&
                      large_len == 12 * k_large_count[l];
            for (int j = 0; matched && j < k_comm_count[c]; j++) {
                put_be32(want + 4 * j, k_comm[c][j]);
            }
            matched = matched && memcmp(comm, want, comm_len) == 0;
            for (int j = 0; matched && j < k_large_count[l]; j++) {
                put_be32(want + 12 * j, k_large[l][j][0]);
                put_be32(want + 12 * j + 4, k_large[l][j][1]);
                put_be32(want + 12 * j + 8, k_large[l][j][2]);
            }
            matched = matched && memcmp(large, want, large_len) == 0;
            seen |= 1u << index;
            routes++;
        }
        messages++;
    }
    bgp_ribout_destroy(&block);
    ASSERT(routes == 12 && seen == 0xFFF, "Each of the 12 routes once");
    ASSERT(matched, "Route i carries community set i % 3 and large-community set i % 2, value for value");
    ASSERT(messages == 6, "Six combinations of the two rotations: six UPDATEs");
    PASS();
}

/*
 * The largest sets: 16 communities (64 octets) and 16 large communities (192 octets) still fit a one-octet length.
 */
static void test_ribout_largest_community_sets_on_wire(void) {
    bgp_ribout_config_t block;
    char                comm_line[512], large_line[768];
    const uint8_t *comm = NULL, *large = NULL;
    uint16_t       comm_len = 0, large_len = 0;
    uint8_t        comm_flags = 0, large_flags = 0;
    int                 len, ordered = 1;

    TEST("16 communities and 16 large communities in one set encode with one-octet lengths");
    bgp_ribout_init(&block, "comm-max");
    len = snprintf(comm_line, sizeof(comm_line), "community [");
    for (int i = 0; i < MAX_COMMUNITIES_PER_SET; i++) {
        len += snprintf(comm_line + len, sizeof(comm_line) - (size_t)len, "%s65000:%d", i ? "," : "", 100 + i);
    }
    snprintf(comm_line + len, sizeof(comm_line) - (size_t)len, "]");
    len = snprintf(large_line, sizeof(large_line), "large-community [");
    for (int i = 0; i < MAX_LARGE_COMMUNITIES_PER_SET; i++) {
        len += snprintf(large_line + len, sizeof(large_line) - (size_t)len, "%s4294967295:%d:4294967295",
                        i ? "," : "", i);
    }
    snprintf(large_line + len, sizeof(large_line) - (size_t)len, "]");
    ASSERT(bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/24") == 0 &&
           bgp_ribout_parse_next_hop(&block, "next-hop 192.0.2.1") == 0 &&
           bgp_ribout_parse_community(&block, comm_line) == 0 &&
           bgp_ribout_parse_large_community(&block, large_line) == 0,
           "Configure the largest sets");
    ASSERT(bgp_ribout_generate_map(&block) == 0 &&
           bgp_ribout_generate_messages(&block) == 0 &&
           block.messages &&
           !block.messages->next,
           "Generate one UPDATE");
    ASSERT(test_wire_find_attr(block.messages->data, block.messages->length, BGP_ATTR_COMMUNITIES,
                               &comm, &comm_len, &comm_flags) &&
           test_wire_find_attr(block.messages->data, block.messages->length, BGP_ATTR_LARGE_COMMUNITY,
                               &large, &large_len, &large_flags),
           "Find both attributes");
    for (int i = 0; i < 16; i++) {
        ordered = ordered && read_u32(comm + 4 * i) == (65000u << 16 | (uint32_t)(100 + i)) &&
                  read_u32(large + 12 * i) == UINT32_MAX && read_u32(large + 12 * i + 4) == (uint32_t)i &&
                  read_u32(large + 12 * i + 8) == UINT32_MAX;
    }
    bgp_ribout_destroy(&block);
    ASSERT(comm_len == 64 &&
           large_len == 192 &&
           comm_flags == 0xC0 &&
           large_flags == 0xC0,
           "64 and 192 octets, no extended-length flag");
    ASSERT(ordered, "Values in configured order");
    PASS();
}

/*
 * Every ribout family carries the community sets: the attributes are family independent. Two community sets and
 * one large-community set; each family generates two routes, one per community set.
 */
static void test_ribout_communities_every_family(void) {
#define COMM_LINES "community 65000:1 x 2", "large-community 65551:0:1", "as-path 65001"
#define SR_LINES   "segment-list 1 weight 10 mpls 16001", "rt 192.0.2.1:100"
    static const struct {
        const char *name;
        const char *lines[10];
    } k_families[] = {
        {
            "ipv4",
            {
                "prefix 10.0.0.0/24 x 2",
                "next-hop 192.0.2.1",
                COMM_LINES,
                NULL,
            },
        },
        {
            "ipv6",
            {
                "prefix 2001:db8::/64 x 2",
                "next-hop 2001:db8::1",
                COMM_LINES,
                NULL,
            },
        },
        {
            "lu4",
            {
                "prefix 10.0.0.0/24 x 2",
                "label 100",
                "next-hop 192.0.2.1",
                COMM_LINES,
                NULL,
            },
        },
        {
            "lu6",
            {
                "prefix 2001:db8::/64 x 2",
                "label 100",
                "next-hop 2001:db8::1",
                COMM_LINES,
                NULL,
            },
        },
        {
            "vpn4",
            {
                "prefix 10.0.0.0/24 x 2",
                "rd 65000:1",
                "label 100",
                "next-hop 192.0.2.1",
                COMM_LINES,
                NULL,
            },
        },
        {
            "vpn6",
            {
                "prefix 2001:db8::/64 x 2",
                "rd 65000:1",
                "label 100",
                "next-hop 192.0.2.1",
                COMM_LINES,
                NULL,
            },
        },
        {
            "evpn5",
            {
                "prefix 10.0.0.0/24 x 2",
                "rd 65000:1",
                "label 100",
                "ethernet-tag 0",
                "next-hop 192.0.2.1",
                COMM_LINES,
                NULL,
            },
        },
        {
            "evpn2",
            {
                "rd 65000:1",
                "mac 00:11:22:33:44:00 x 2",
                "label 100",
                COMM_LINES,
                NULL,
            },
        },
        {
            "sr4",
            {
                "distinguisher 1",
                "color 100 101",
                "endpoint 10.0.0.1",
                SR_LINES,
                COMM_LINES,
                NULL,
            },
        },
        {
            "sr6",
            {
                "distinguisher 1",
                "color 100 101",
                "endpoint 2001:db8::1",
                SR_LINES,
                COMM_LINES,
                NULL,
            },
        },
        {
            "fs4",
            {
                "address-family ipv4 flowspec",
                "prefix 10.0.0.0/24 x 2",
                "protocol 6",
                COMM_LINES,
                NULL,
            },
        },
        {
            "fs6",
            {
                "address-family ipv6 flowspec",
                "prefix 2001:db8::/64 x 2",
                "protocol 6",
                COMM_LINES,
                NULL,
            },
        },
        {
            "fsvpn4",
            {
                "address-family ipv4 flowspec-vpn",
                "prefix 10.0.0.0/24 x 2",
                "rd 65000:1",
                "protocol 6",
                COMM_LINES,
                NULL,
            },
        },
    };
#undef COMM_LINES
#undef SR_LINES
    char failure[160];

    TEST("Every family carries COMMUNITIES and LARGE_COMMUNITY, one community set per route");
    for (size_t i = 0; i < sizeof(k_families) / sizeof(k_families[0]); i++) {
        bgp_ribout_config_t block;
        uint32_t            seen = 0;
        int                 ok = 1;

        snprintf(failure, sizeof(failure), "%s: configure and generate", k_families[i].name);
        ASSERT(configure_lines(&block, k_families[i].name, k_families[i].lines) == 0 &&
               bgp_ribout_generate_map(&block) == 0 &&
               bgp_ribout_generate_messages(&block) == 0,
               failure);
        for (const bgp_msg_t *msg = block.messages; msg; msg = msg->next) {
            const uint8_t *comm = NULL, *large = NULL;
            uint16_t       comm_len = 0, large_len = 0;

            ok = ok && test_wire_find_attr(msg->data, msg->length, BGP_ATTR_COMMUNITIES, &comm, &comm_len, NULL) &&
                 comm_len == 4 && (read_u32(comm) == 0xFDE80001u || read_u32(comm) == 0xFDE80002u) &&
                 test_wire_find_attr(msg->data, msg->length, BGP_ATTR_LARGE_COMMUNITY, &large, &large_len, NULL) &&
                 large_len == 12 && read_u32(large) == 65551 && read_u32(large + 8) == 1 &&
                 attrs_ascending(msg->data, msg->length);
            if (ok) {
                seen |= 1u << (read_u32(comm) & 0xFFFF);
            }
        }
        bgp_ribout_destroy(&block);
        snprintf(failure, sizeof(failure), "%s: every UPDATE carries one set of each, both community sets used",
                 k_families[i].name);
        ASSERT(ok && seen == 0x6, failure);
    }
    PASS();
}

/*
 * SR Policy key rotation on the wire (RFC 9830 section 2.1, Add-Path RFC 7911): every NLRI is Path ID, length in
 * bits, distinguisher, color, endpoint. With color rotate 100 x 3 and path-id rotate 7 8 policy i (distinguisher
 * 1 + i / 4, endpoint 10.0.0.1 + i % 4) carries color 100 + i % 3 and Path ID 7 + i % 2, each policy once.
 */
static void test_ribout_srpolicy_rotation_on_wire(void) {
    static const char *const k_lines[] = {
        "distinguisher 1 x 2",
        "color rotate 100 x 3",
        "endpoint 10.0.0.1 x 4",
        "path-id rotate 7 8",
        "segment-list 1 weight 10 mpls 16001",
        "rt 192.0.2.1:100",
        "as-path 65001",
        NULL,
    };
    bgp_ribout_config_t block;
    int                 seen[8] = {0};
    int                 routes = 0, in_step = 1;

    TEST("SR Policy color rotate and path-id rotate: one key per policy on the wire, values in step");
    ASSERT(configure_lines(&block, "sr-rot-wire", k_lines) == 0, "Configure the ribout");
    ASSERT(bgp_ribout_generate_map(&block) == 0 && bgp_ribout_generate_messages(&block) == 0, "Generate");
    for (const bgp_msg_t *msg = block.messages; msg; msg = msg->next) {
        const uint8_t *nlri = NULL;
        uint16_t       nlri_len = 0;

        ASSERT(extract_mp_reach_afi(msg->data, msg->length, AFI_IPV4, SAFI_SR_POLICY, NULL, NULL, &nlri, &nlri_len),
               "Every UPDATE carries IPv4 SR Policy NLRI");
        for (uint16_t off = 0; off < nlri_len;) {
            const uint8_t *r = nlri + off;  /* Path ID (4), length (1, bits), distinguisher, color, endpoint */
            uint32_t       path_id = read_u32(r), distinguisher = read_u32(r + 5), color = read_u32(r + 9);
            uint32_t       endpoint = read_u32(r + 13);
            int            index = (int)((distinguisher - 1) * 4 + (endpoint - 0x0A000001u));

            ASSERT(r[4] == 96 && index >= 0 && index < 8, "A 96-bit IPv4 policy key of the configured ranges");
            in_step = in_step && color == 100u + (uint32_t)(index % 3) && path_id == 7u + (uint32_t)(index % 2);
            seen[index]++;
            routes++;
            off += 4 + 1 + 12;
        }
    }
    bgp_ribout_destroy(&block);
    ASSERT(routes == 8 && in_step, "8 policies: policy i with color 100 + i % 3 and Path ID 7 + i % 2");
    for (int i = 0; i < 8; i++) {
        ASSERT(seen[i] == 1, "Each policy once");
    }
    PASS();
}

/*
 * The first value of each FlowSpec component of one IPv4 NLRI (RFC 8955 section 4.2): destination prefix third octet
 * in dest, the numeric components by type in value[]. Returns the NLRI's octets, or 0 when it does not decode.
 */
static size_t decode_flowspec_v4(const uint8_t *p, size_t len, uint32_t *dest, uint32_t value[14]) {
    size_t size, off;

    if (len < 1) {
        return 0;
    }
    size = (p[0] < 0xf0) ? 1u + p[0] : 2u + (((p[0] & 0x0fu) << 8) | p[1]);
    off = (p[0] < 0xf0) ? 1 : 2;
    if (size > len) {
        return 0;
    }
    memset(value, 0xff, sizeof(uint32_t) * 14);
    while (off < size) {
        uint8_t type = p[off++];

        if (type == 1 || type == 2) {  /* prefix length, prefix octets */
            uint8_t bits = p[off];

            if (type == 1) {
                *dest = bits >= 24 ? p[off + 3] : 0;
            }
            off += 1 + (bits + 7) / 8;
        } else if (type >= 3 && type <= 13) {  /* (operator, value) pairs until the end-of-list bit */
            int first = 1;

            for (;;) {
                uint8_t  op = p[off++];
                size_t   width = (size_t)1 << ((op >> 4) & 3);
                uint32_t v = 0;

                for (size_t k = 0; k < width; k++) {
                    v = v << 8 | p[off + k];
                }
                off += width;
                if (first) {
                    value[type] = v;
                    first = 0;
                }
                if (op & 0x80) {
                    break;
                }
            }
        } else {
            return 0;
        }
    }
    return off == size ? size : 0;
}

/*
 * FlowSpec component rotate on the wire: rule i (destination 10.0.(i / 2).0/24, source port 1 + i % 2) carries
 * protocol 6 or 17 and destination port 80 + i % 3 of rotation step i; every rule once.
 */
static void test_ribout_flowspec_rotation_on_wire(void) {
    static const char *const k_lines[] = {
        "address-family ipv4 flowspec",
        "prefix 10.0.0.0/24 x 2",
        "protocol rotate each(6, 17)",
        "dst-port rotate 80 x 3",
        "src-port each(1, 2)",
        "action traffic-rate bytes 0",
        "as-path 65001",
        NULL,
    };
    bgp_ribout_config_t block;
    int                 seen[4] = {0};
    int                 rules = 0, in_step = 1;

    TEST("FlowSpec component rotate: rotating components take one value per rule on the wire");
    ASSERT(configure_lines(&block, "fs-rot-wire", k_lines) == 0, "Configure the ribout");
    ASSERT(bgp_ribout_generate_map(&block) == 0 && bgp_ribout_generate_messages(&block) == 0, "Generate");
    for (const bgp_msg_t *msg = block.messages; msg; msg = msg->next) {
        const uint8_t *nlri = NULL;
        uint16_t       nlri_len = 0;

        ASSERT(extract_mp_reach_afi(msg->data, msg->length, AFI_IPV4, SAFI_FLOWSPEC, NULL, NULL, &nlri, &nlri_len),
               "Every UPDATE carries IPv4 FlowSpec NLRI");
        for (uint16_t off = 0; off < nlri_len;) {
            uint32_t dest = 0, value[14];
            size_t   size = decode_flowspec_v4(nlri + off, nlri_len - off, &dest, value);
            int      index;

            ASSERT(size > 0, "The NLRI decodes");
            index = (int)(dest * 2 + value[6] - 1);  /* type 6: source port */
            ASSERT(dest < 2 && (value[6] == 1 || value[6] == 2),
                   "Destination and source port of the configured ranges");
            in_step = in_step && value[3] == (index % 2 ? 17u : 6u) && value[5] == 80u + (uint32_t)(index % 3);
            seen[index]++;
            rules++;
            off += (uint16_t)size;
        }
    }
    bgp_ribout_destroy(&block);
    ASSERT(rules == 4 && in_step, "4 rules: rule i with protocol 6/17 and destination port 80 + i % 3 of step i");
    for (int i = 0; i < 4; i++) {
        ASSERT(seen[i] == 1, "Each rule once");
    }
    PASS();
}

/*
 * EVPN ethernet-tag rotate on the wire (RFC 9136 Type 5, RFC 7432 Type 2): Type 5 route i carries RD 65551:(1 + i % 3)
 * and Ethernet tag 100 + i % 3, so the tag goes with the RD; Type 2 MAC i carries tag 10 + i % 2 and IP i.
 */
static void test_ribout_evpn_tag_rotation_on_wire(void) {
    static const char *const k_type5[] = {
        "prefix 10.0.0.0/24 x 6",
        "rd rotate 65551:1 x 3",
        "ethernet-tag rotate 100 x 3",
        "label 10",
        "next-hop 192.0.2.1",
        "as-path 65001",
        NULL,
    };
    static const char *const k_type2[] = {
        "rd 65551:1",
        "mac 02:00:00:00:00:01 x 4",
        "ethernet-tag rotate 10 x 2",
        "ip rotate 10.1.0.1 x 4",
        "label 20",
        "next-hop 192.0.2.1",
        "as-path 65001",
        NULL,
    };
    bgp_ribout_config_t block;
    int                 routes = 0, in_step = 1;

    TEST("EVPN ethernet-tag rotate: Type 5 tag in step with rd rotate, Type 2 tag per MAC, on the wire");
    ASSERT(configure_lines(&block, "t5-tags", k_type5) == 0, "Configure the Type 5 ribout");
    ASSERT(bgp_ribout_generate_map(&block) == 0 && bgp_ribout_generate_messages(&block) == 0, "Generate");
    for (const bgp_msg_t *msg = block.messages; msg; msg = msg->next) {
        const uint8_t *nlri = NULL;
        uint16_t       nlri_len = 0;

        ASSERT(extract_mp_reach_afi(msg->data, msg->length, AFI_L2VPN, SAFI_EVPN, NULL, NULL, &nlri, &nlri_len), "EVPN NLRI");
        for (uint16_t off = 0; off < nlri_len; off += (uint16_t)(2 + nlri[off + 1])) {
            const uint8_t *v = nlri + off + 2;  /* RD (8), ESI (10), tag (4), IP length, IP, gateway, label */
            uint32_t       assigned = read_u16(v + 6), tag = read_u32(v + 18), index = v[25];

            ASSERT(nlri[off] == 5 && v[22] == 24, "A Type 5 route of a /24");
            in_step = in_step && assigned == 1 + index % 3 && tag == 100 + index % 3;
            routes++;
        }
    }
    bgp_ribout_destroy(&block);
    ASSERT(routes == 6 && in_step, "6 routes: route i with RD 65551:(1 + i % 3) and tag 100 + i % 3");

    routes = 0;
    ASSERT(configure_lines(&block, "t2-tags", k_type2) == 0, "Configure the Type 2 ribout");
    ASSERT(bgp_ribout_generate_map(&block) == 0 && bgp_ribout_generate_messages(&block) == 0, "Generate");
    for (const bgp_msg_t *msg = block.messages; msg; msg = msg->next) {
        const uint8_t *nlri = NULL;
        uint16_t       nlri_len = 0;

        ASSERT(extract_mp_reach_afi(msg->data, msg->length, AFI_L2VPN, SAFI_EVPN, NULL, NULL, &nlri, &nlri_len), "EVPN NLRI");
        for (uint16_t off = 0; off < nlri_len; off += (uint16_t)(2 + nlri[off + 1])) {
            // RD (8), ESI (10), tag (4), MAC length, MAC (6), IP length, IP, label
            const uint8_t *v = nlri + off + 2;
            uint32_t       tag = read_u32(v + 18), mac = v[28], ip = read_u32(v + 30);

            ASSERT(nlri[off] == 2 && v[22] == 48 && v[29] == 32, "A Type 2 MAC/IPv4 route");
            in_step = in_step && mac >= 1 && mac <= 4 && tag == 10 + (mac - 1) % 2 && ip == 0x0A010000u + mac;
            routes++;
        }
    }
    bgp_ribout_destroy(&block);
    ASSERT(routes == 4 && in_step, "4 routes: MAC i with tag 10 + (i - 1) % 2 and IP 10.1.0.i");
    PASS();
}

/*
 * path-id rotate on the wire (RFC 7911): classic IPv4 NLRI with Path IDs, prefix i once with Path ID 1 + i % 3.
 */
static void test_ribout_path_id_rotation_on_wire(void) {
    static const char *const k_lines[] = {
        "prefix 10.0.0.0/24 x 5",
        "path-id rotate 1 x 3",
        "next-hop 192.0.2.1",
        "as-path 65001",
        NULL,
    };
    bgp_ribout_config_t block;
    int                 seen[5] = {0};
    int                 routes = 0, in_step = 1;

    TEST("path-id rotate: each prefix once, with Path ID 1 + i % 3, on the wire");
    ASSERT(configure_lines(&block, "ids-wire", k_lines) == 0, "Configure the ribout");
    ASSERT(bgp_ribout_generate_map(&block) == 0 && bgp_ribout_generate_messages(&block) == 0, "Generate");
    for (const bgp_msg_t *msg = block.messages; msg; msg = msg->next) {
        test_wire_update_t view;

        ASSERT(test_wire_update_view(msg->data, msg->length, &view) && !view.has_reach, "Classic IPv4 NLRI");
        for (size_t off = 0; off < view.nlri_len; off += 4 + 1 + 3) {
            const uint8_t *r = view.nlri + off;  /* Path ID (4), length, 3 prefix octets */
            uint32_t       index = r[7];

            ASSERT(r[4] == 24 && index < 5, "A /24 of the range");
            in_step = in_step && read_u32(r) == 1 + index % 3;
            seen[index]++;
            routes++;
        }
    }
    bgp_ribout_destroy(&block);
    ASSERT(routes == 5 && in_step, "5 routes: prefix i with Path ID 1 + i % 3");
    for (int i = 0; i < 5; i++) {
        ASSERT(seen[i] == 1, "Each prefix once");
    }
    PASS();
}

/*
 * Dual-stack EVPN Type 2 on the wire: every MAC twice, with its IPv4 and its IPv6 binding of the same number.
 */
static void test_ribout_evpn_type2_dual_stack_on_wire(void) {
    bgp_ribout_config_t block;
    uint8_t             seen[2][50] = {{0}};
    int routes = 0;
    int bound = 1;

    TEST("Dual-stack EVPN Type 2: an IPv4 and an IPv6 binding per MAC on the wire");
    bgp_ribout_init(&block, "evpn2-dual-wire");
    ASSERT(bgp_ribout_parse_rd(&block, "rd 65551:6") == 0 &&
               bgp_ribout_parse_mac(&block, "mac 02:00:00:00:00:01 x 50") == 0 &&
               bgp_ribout_parse_ip(&block, "ip rotate 172.20.0.1 x 50") == 0 &&
               bgp_ribout_parse_ip(&block, "ip rotate 2001:db8:20::1 x 50") == 0 &&
               bgp_ribout_parse_label(&block, "label 40001") == 0 &&
               bgp_ribout_parse_next_hop(&block, "next-hop 192.0.2.20") == 0 &&
               bgp_ribout_parse_aspath(&block, "as-path 65530") == 0,
           "Configure the dual-stack Type 2 ribout");
    ASSERT(bgp_ribout_generate_map(&block) == 0 && bgp_ribout_generate_messages(&block) == 0, "Generate");
    for (const bgp_msg_t *msg = block.messages; msg; msg = msg->next) {
        const uint8_t *next_hop = NULL, *nlri = NULL;
        uint8_t        next_hop_len = 0;
        uint16_t       nlri_len = 0;

        ASSERT(extract_mp_reach_evpn_type5(msg->data, msg->length, &next_hop, &next_hop_len, &nlri, &nlri_len),
               "Every UPDATE carries EVPN MP_REACH_NLRI");
        for (uint16_t offset = 0; offset + 2 <= nlri_len; offset += 2 + nlri[offset + 1]) {
            // RD (8), ESI (10), Ethernet tag (4), MAC length, MAC (6), IP length, IP
            const uint8_t *route = nlri + offset + 2;
            int            host = route[28] - 1;
            int            ipv6 = route[29] == 128;
            int match = ipv6 ? route[30] == 0x20 && route[45] == host + 1
                             : (((uint32_t)route[30] << 24) | ((uint32_t)route[31] << 16) |
                                ((uint32_t)route[32] << 8) | route[33]) == 0xAC140001u + (uint32_t)host;

            bound = bound && nlri[offset] == 2 && host >= 0 && host < 50 && (route[29] == 32 || ipv6) && match &&
                    !seen[ipv6][host];
            if (host >= 0 && host < 50) {
                seen[ipv6][host] = 1;
            }
            routes++;
        }
    }
    bgp_ribout_destroy(&block);
    ASSERT(routes == 100 && bound, "100 routes: each of 50 MACs with IPv4 i and IPv6 i, once each");
    PASS();
}

/*
 * An EVPN block: Type 5 with eight IPv4 prefixes, or Type 2 with eight MACs (and Label2 when label2 is set).
 */
static int configure_evpn_label_block(bgp_ribout_config_t *block, int type2, const char *label, const char *label2,
                                      const char *encap) {
    bgp_ribout_init(block, type2 ? "evpn2-label-form" : "evpn5-label-form");
    if (type2) {
        if (bgp_ribout_parse_mac(block, "mac 00:11:22:33:44:00 x 8") < 0 ||
            bgp_ribout_parse_ip(block, "ip 192.0.2.40") < 0 ||
            (label2 && bgp_ribout_parse_label2(block, label2) < 0)) {
            return -1;
        }
    } else if (bgp_ribout_parse_prefix(block, "prefix 172.16.0.0/24 x 8") < 0) {
        return -1;
    }
    return (bgp_ribout_parse_rd(block, "rd 65000:5") == 0 &&
            bgp_ribout_parse_label(block, label) == 0 &&
            bgp_ribout_parse_ethernet_tag(block, "ethernet-tag 0") == 0 &&
            bgp_ribout_parse_next_hop(block, "next-hop 192.0.2.10") == 0 &&
            bgp_ribout_parse_rt(block, "rt 65000:5") == 0 &&
            (!encap || bgp_ribout_parse_encap(block, encap) == 0) &&
            bgp_ribout_parse_aspath(block, "as-path 65530") == 0 &&
            bgp_ribout_parse_origin(block, "origin igp") == 0) ? 0 : -1;
}

/*
 * EVPN with VXLAN carries the VNI in the label field (RFC 8365 section 5.1.3), so "label 30000" with "encap vxlan" goes
 * on the wire as 00 75 30; without a VNI encapsulation it is the MPLS label 07 53 01. A rotated encap decides per path.
 */
static void test_ribout_evpn_labels_follow_encap(void) {
    static const struct {
        int         type2;
        const char *label2;
        const char *encap;
        int         vni_nlri;
        int         mpls_nlri;
    } cases[] = {
        {0, NULL, "encap vxlan", 8, 0},
        {0, NULL, NULL, 0, 8},
        {0, NULL, "encap mpls-in-gre", 0, 8},
        {0, NULL, "encap nvgre", 8, 0},
        {0, NULL, "encap 12", 8, 0},
        {0, NULL, "encap 19", 8, 0},
        {0, NULL, "encap vxlan mpls-in-gre", 4, 4},
        {1, "label2 40000", "encap vxlan", 8, 0},
        {1, "label2 40000", NULL, 0, 8},
        {1, NULL, "encap gre vxlan", 4, 4},
    };

    TEST("EVPN labels: a VNI with VXLAN-like encaps, an MPLS label otherwise, per path");

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        bgp_ribout_config_t block;
        int                 vni_nlri = -1;
        int                 mpls_nlri = -1;
        int ok = configure_evpn_label_block(&block, cases[i].type2, "label 30000", cases[i].label2,
                                            cases[i].encap) == 0 &&
                 bgp_ribout_generate_map(&block) == 0 && bgp_ribout_generate_messages(&block) == 0 &&
                 check_evpn_label_forms(block.messages, 30000, cases[i].label2 ? 40000 : 0, &vni_nlri, &mpls_nlri) == 0;

        bgp_ribout_destroy(&block);
        if (!ok || vni_nlri != cases[i].vni_nlri || mpls_nlri != cases[i].mpls_nlri) {
            printf("    case %zu (Type %d, %s): %d VNI and %d MPLS NLRI\n", i, cases[i].type2 ? 2 : 5,
                   cases[i].encap ? cases[i].encap : "no encap", vni_nlri, mpls_nlri);
        }
        ASSERT(ok && vni_nlri == cases[i].vni_nlri && mpls_nlri == cases[i].mpls_nlri,
               "EVPN label fields have the form of their UPDATE's encap");
    }
    PASS();
}

/*
 * Generation succeeds for this EVPN block; checks the label value on the wire when it does.
 */
static int evpn_label_block_generates(int type2, const char *label, const char *label2, const char *encap,
                                      uint32_t wire_label) {
    bgp_ribout_config_t block;
    int                 vni_nlri = 0;
    int                 mpls_nlri = 0;
    int generated = configure_evpn_label_block(&block, type2, label, label2, encap) == 0 &&
                    bgp_ribout_generate_map(&block) == 0 && bgp_ribout_generate_messages(&block) == 0;

    if (generated && wire_label != 0 &&
        check_evpn_label_forms(block.messages, wire_label, 0, &vni_nlri, &mpls_nlri) < 0) {
        generated = 0;
    }
    bgp_ribout_destroy(&block);
    return generated;
}

/*
 * A label field holds 24 bits. Parsing accepts up to 16777215; generation allows more than 20 bits only as a VNI, on an
 * EVPN ribout whose every rotated encap is a VNI tunnel, since an MPLS label would lose its high bits.
 */
static void test_ribout_label_width_follows_encap(void) {
    bgp_ribout_config_t block;
    int                 lu_rejected;

    TEST("ribout labels: 24-bit VNIs only on EVPN with VXLAN-like encaps");

    bgp_ribout_init(&block, "label-width");
    ASSERT(bgp_ribout_parse_label(&block, "label 16777215") == 0, "Parse accepts the largest VNI");
    ASSERT(bgp_ribout_parse_label(&block, "label 16777216") < 0, "Parse rejects 25-bit labels");
    ASSERT(bgp_ribout_parse_label(&block, "label 16777214 x 3") < 0, "Parse rejects sequences past 24 bits");
    ASSERT(bgp_ribout_parse_label2(&block, "label2 16777215") == 0, "Parse accepts the largest Label2 VNI");
    ASSERT(bgp_ribout_parse_label2(&block, "label2 16777216") < 0, "Parse rejects 25-bit Label2");
    bgp_ribout_destroy(&block);

    ASSERT(evpn_label_block_generates(0, "label 16777215", NULL, "encap vxlan", 16777215),
           "Type 5 VXLAN sends VNI 16777215");
    ASSERT(evpn_label_block_generates(0, "label 2000000", NULL, "encap nvgre 12 19", 2000000),
           "Type 5 with only VNI encaps sends a 21-bit VNI");
    ASSERT(evpn_label_block_generates(1, "label 30000", "label2 16777215", "encap vxlan", 30000),
           "Type 2 VXLAN accepts a 24-bit Label2");
    ASSERT(evpn_label_block_generates(0, "label 1048575", NULL, NULL, 1048575),
           "Type 5 without encap sends the largest MPLS label");
    ASSERT(!evpn_label_block_generates(0, "label 1048576", NULL, NULL, 0),
           "Type 5 without encap rejects a 21-bit label");
    ASSERT(!evpn_label_block_generates(0, "label 2000000", NULL, "encap vxlan mpls-in-gre", 0),
           "A 21-bit label is rejected when one rotated encap is MPLS");
    ASSERT(!evpn_label_block_generates(1, "label 30000", "label2 1048576", "encap gre", 0),
           "Type 2 GRE rejects a 21-bit Label2");

    bgp_ribout_init(&block, "lu-label-width");
    lu_rejected = bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/24") == 0 &&
                  bgp_ribout_parse_label(&block, "label 1048576") == 0 &&
                  bgp_ribout_parse_next_hop(&block, "next-hop 192.0.2.1") == 0 &&
                  bgp_ribout_generate_map(&block) != 0;
    bgp_ribout_destroy(&block);
    ASSERT(lu_rejected, "Labeled unicast rejects a 21-bit label at generation");
    PASS();
}

static void test_ribout_evpn_type2_config_to_encoded_updates(void) {
    bgp_ribout_config_t block;
    bgp_msg_t          *msg;
    uint8_t             next_hop[4];
    int                 total_nlri = 0;

    TEST("EVPN type 2 config -> MP UPDATE bytes");

    bgp_ribout_init(&block, "e2e-wire-evpn2");

    ASSERT(bgp_ribout_parse_rd(&block, "rd 65000:320") == 0, "Failed to parse RD");
    ASSERT(bgp_ribout_parse_ethernet_tag(&block, "ethernet-tag 10") == 0, "Failed to parse Ethernet Tag");
    ASSERT(bgp_ribout_parse_mac(&block, "mac 1 x 2") == 0, "Failed to parse MAC generator");
    ASSERT(bgp_ribout_parse_ip(&block, "ip 192.0.2.1 x 2") == 0, "Failed to parse optional IP generator");
    ASSERT(bgp_ribout_parse_label(&block, "label 30000 30001") == 0, "Failed to parse label");
    ASSERT(bgp_ribout_parse_label2(&block, "label2 40000 40001") == 0, "Failed to parse label2");
    ASSERT(bgp_ribout_parse_esi(&block, "esi 00112233445566778899 x 2") == 0, "Failed to parse ESI");
    ASSERT(bgp_ribout_parse_next_hop(&block, "next-hop 192.0.2.10") == 0, "Failed to parse next-hop");
    ASSERT(bgp_ribout_parse_rt(&block, "rt 65000:320") == 0, "Failed to parse RT");
    ASSERT(bgp_ribout_parse_med(&block, "med 10") == 0, "Failed to parse MED");
    ASSERT(bgp_ribout_parse_aspath(&block, "as-path 65520") == 0, "Failed to parse AS path");
    ASSERT(bgp_ribout_parse_localpref(&block, "localpref 240") == 0, "Failed to parse localpref");
    ASSERT(bgp_ribout_parse_origin(&block, "origin egp") == 0, "Failed to parse origin");

    ASSERT(bgp_ribout_generate_map(&block) == 0, "Map generation failed");
    ASSERT(block.ribout != NULL, "Map not created");
    ASSERT(block.ribout->entry_count == 1, "Expected one EVPN Type 2 attribute group");
    ASSERT(block.ribout->total_nlri_count == 4, "Expected 4 generated EVPN Type 2 NLRIs");

    ASSERT(bgp_ribout_generate_messages(&block) == 0, "Message generation failed");
    ASSERT(block.messages != NULL, "No encoded messages were produced");
    ASSERT(block.message_count == 1, "Expected one EVPN Type 2 UPDATE");

    inet_pton(AF_INET, "192.0.2.10", next_hop);

    for (msg = block.messages; msg; msg = msg->next) {
        int message_nlri = 0;

        ASSERT(validate_evpn_type2_update_message(msg,
                                                  BGP_ORIGIN_EGP,
                                                  240,
                                                  10,
                                                  1,
                                                  next_hop,
                                                  4,
                                                  8,
                                                  0,
                                                  &message_nlri),
               "Encoded EVPN Type 2 UPDATE bytes are not RFC-shaped");
        ASSERT(validate_evpn_type2_against_generator(msg, &block, 0),
               "EVPN Type 2 wire payload does not follow generator order");
        total_nlri += message_nlri;
    }

    ASSERT(total_nlri == 4, "Encoded EVPN Type 2 NLRI total does not match configured MAC/IP bindings");

    bgp_ribout_destroy(&block);
    PASS();
}

static void test_ribout_evpn_type2_attr_ext_comms_to_encoded_updates(void) {
    bgp_ribout_config_t block;
    bgp_msg_t          *msg;
    uint8_t             next_hop[4];
    const uint8_t      *ext_comm = NULL;
    uint16_t            ext_comm_len = 0;
    int                 message_nlri = 0;

    TEST("EVPN type 2 encap/router-mac config -> MP UPDATE bytes");

    bgp_ribout_init(&block, "e2e-wire-evpn2-ext");

    ASSERT(bgp_ribout_parse_rd(&block, "rd 65000:340") == 0, "Failed to parse RD");
    ASSERT(bgp_ribout_parse_ethernet_tag(&block, "ethernet-tag 10") == 0, "Failed to parse Ethernet Tag");
    ASSERT(bgp_ribout_parse_mac(&block, "mac 00:11:22:33:44:00") == 0, "Failed to parse MAC");
    ASSERT(bgp_ribout_parse_ip(&block, "ip 192.0.2.40") == 0, "Failed to parse optional IP");
    ASSERT(bgp_ribout_parse_label(&block, "label 34000") == 0, "Failed to parse label");
    ASSERT(bgp_ribout_parse_next_hop(&block, "next-hop 192.0.2.20") == 0, "Failed to parse next-hop");
    ASSERT(bgp_ribout_parse_rt(&block, "rt 65000:340") == 0, "Failed to parse RT");
    ASSERT(bgp_ribout_parse_encap(&block, "encap vxlan") == 0, "Failed to parse encap");
    ASSERT(bgp_ribout_parse_router_mac(&block, "router-mac 1") == 0, "Failed to parse router-mac");
    ASSERT(bgp_ribout_parse_aspath(&block, "as-path 65540") == 0, "Failed to parse AS path");
    ASSERT(bgp_ribout_parse_localpref(&block, "localpref 240") == 0, "Failed to parse localpref");
    ASSERT(bgp_ribout_parse_origin(&block, "origin igp") == 0, "Failed to parse origin");

    ASSERT(bgp_ribout_generate_map(&block) == 0, "Map generation failed");
    ASSERT(block.ribout != NULL, "Map not created");
    ASSERT(block.ribout->entry_count == 1, "Expected one EVPN Type 2 attribute group");
    ASSERT(block.ribout->total_nlri_count == 1, "Expected one generated EVPN Type 2 NLRI");

    ASSERT(bgp_ribout_generate_messages(&block) == 0, "Message generation failed");
    ASSERT(block.messages != NULL && block.message_count == 1, "Expected one EVPN Type 2 UPDATE");

    inet_pton(AF_INET, "192.0.2.20", next_hop);
    msg = block.messages;

    ASSERT(validate_evpn_type2_update_message(msg,
                                              BGP_ORIGIN_IGP,
                                              240,
                                              0,
                                              0,
                                              next_hop,
                                              4,
                                              24,
                                              0,
                                              &message_nlri),
           "Encoded EVPN Type 2 attr UPDATE bytes are not RFC-shaped");
    ASSERT(find_attr(msg->data, msg->length, BGP_ATTR_EXT_COMM, &ext_comm, &ext_comm_len) &&
           ext_comm_len == 24,
           "EVPN Type 2 attr UPDATE carries RT, encap, and router-mac");
    ASSERT(ext_comm[8] == 0x03 && ext_comm[9] == 0x0c &&
           read_u16(ext_comm + 14) == 8,
           "EVPN Type 2 attr UPDATE encodes VXLAN encap after RT");
    ASSERT(ext_comm[16] == 0x06 && ext_comm[17] == 0x03 &&
           memcmp(ext_comm + 18, (const uint8_t[]){0x00,0x00,0x00,0x00,0x00,0x01}, 6) == 0,
           "EVPN Type 2 attr UPDATE encodes Router's MAC after encap");
    ASSERT(message_nlri == 1, "Encoded EVPN Type 2 attr NLRI total is one");

    bgp_ribout_destroy(&block);
    PASS();
}

static void test_ribout_evpn_type2_add_path_bytes_follow_generator_order(void) {
    bgp_ribout_config_t block;
    bgp_msg_t          *msg;
    uint8_t             next_hop[4];
    int                 total_nlri = 0;

    TEST("EVPN type 2 ADD-PATH wire order matches generator preview order");

    bgp_ribout_init(&block, "e2e-wire-evpn2-ap");

    ASSERT(bgp_ribout_parse_rd(&block, "rd 65000:321") == 0, "Failed to parse RD");
    ASSERT(bgp_ribout_parse_ethernet_tag(&block, "ethernet-tag 20") == 0, "Failed to parse Ethernet Tag");
    ASSERT(bgp_ribout_parse_mac(&block, "mac 00:11:22:33:55:00 x 2") == 0, "Failed to parse MAC generator");
    ASSERT(bgp_ribout_parse_ip(&block, "ip 192.0.2.10 x 2") == 0, "Failed to parse optional IP generator");
    ASSERT(bgp_ribout_parse_label(&block, "label 30100 30101") == 0, "Failed to parse label");
    ASSERT(bgp_ribout_parse_label2(&block, "label2 40100 40101") == 0, "Failed to parse label2");
    ASSERT(bgp_ribout_parse_path_ids(&block, "path-id 7 8") == 0, "Failed to parse path-id");
    ASSERT(bgp_ribout_parse_next_hop(&block, "next-hop 192.0.2.11") == 0, "Failed to parse next-hop");
    ASSERT(bgp_ribout_parse_rt(&block, "rt 65000:321") == 0, "Failed to parse RT");
    ASSERT(bgp_ribout_parse_aspath(&block, "as-path 65521") == 0, "Failed to parse AS path");
    ASSERT(bgp_ribout_parse_localpref(&block, "localpref 225") == 0, "Failed to parse localpref");
    ASSERT(bgp_ribout_parse_origin(&block, "origin igp") == 0, "Failed to parse origin");

    ASSERT(bgp_ribout_generate_map(&block) == 0, "Map generation failed");
    ASSERT(block.ribout != NULL, "Map not created");
    ASSERT(block.ribout->entry_count == 1, "Expected one EVPN Type 2 ADD-PATH attribute group");
    ASSERT(block.ribout->total_nlri_count == 8, "Expected 8 generated EVPN Type 2 ADD-PATH NLRIs");

    ASSERT(bgp_ribout_generate_messages(&block) == 0, "Message generation failed");
    ASSERT(block.messages != NULL, "No encoded messages were produced");
    ASSERT(block.message_count == 1, "Expected one EVPN Type 2 ADD-PATH UPDATE");

    inet_pton(AF_INET, "192.0.2.11", next_hop);

    for (msg = block.messages; msg; msg = msg->next) {
        int message_nlri = 0;

        ASSERT(validate_evpn_type2_update_message(msg,
                                                  BGP_ORIGIN_IGP,
                                                  225,
                                                  0,
                                                  0,
                                                  next_hop,
                                                  4,
                                                  8,
                                                  1,
                                                  &message_nlri),
               "Encoded EVPN Type 2 ADD-PATH UPDATE bytes are not RFC-shaped");
        ASSERT(validate_evpn_type2_against_generator(msg, &block, 1),
               "EVPN Type 2 ADD-PATH wire order does not follow generator order");
        total_nlri += message_nlri;
    }

    ASSERT(total_nlri == 8, "Encoded EVPN Type 2 ADD-PATH NLRI total does not match configured bindings");

    bgp_ribout_destroy(&block);
    PASS();
}

static void test_ribout_evpn_type2_message_splitting(void) {
    bgp_ribout_config_t block;
    bgp_msg_t          *msg;
    uint8_t             next_hop[4];
    int                 total_nlri = 0;

    TEST("EVPN type 2 message splitting");

    bgp_ribout_init(&block, "e2e-wire-evpn2-split");

    ASSERT(bgp_ribout_parse_rd(&block, "rd 65000:322") == 0, "Failed to parse RD");
    ASSERT(bgp_ribout_parse_ethernet_tag(&block, "ethernet-tag 30") == 0, "Failed to parse Ethernet Tag");
    ASSERT(bgp_ribout_parse_mac(&block, "mac 00:11:22:33:66:00 x 200") == 0, "Failed to parse MAC generator");
    ASSERT(bgp_ribout_parse_ip(&block, "ip 192.0.2.20 x 2") == 0, "Failed to parse optional IP generator");
    ASSERT(bgp_ribout_parse_label(&block, "label 30200") == 0, "Failed to parse label");
    ASSERT(bgp_ribout_parse_next_hop(&block, "next-hop 192.0.2.12") == 0, "Failed to parse next-hop");
    ASSERT(bgp_ribout_parse_rt(&block, "rt 65000:322") == 0, "Failed to parse RT");
    ASSERT(bgp_ribout_parse_aspath(&block, "as-path 65522") == 0, "Failed to parse AS path");
    ASSERT(bgp_ribout_parse_localpref(&block, "localpref 230") == 0, "Failed to parse localpref");
    ASSERT(bgp_ribout_parse_origin(&block, "origin igp") == 0, "Failed to parse origin");

    ASSERT(bgp_ribout_generate_map(&block) == 0, "Map generation failed");
    ASSERT(block.ribout != NULL, "Map not created");
    ASSERT(block.ribout->entry_count == 1, "Expected one EVPN Type 2 split attribute group");
    ASSERT(block.ribout->total_nlri_count == 400, "Expected 400 generated EVPN Type 2 NLRIs");

    ASSERT(bgp_ribout_generate_messages(&block) == 0, "Message generation failed");
    ASSERT(block.messages != NULL, "No encoded messages were produced");
    ASSERT(block.message_count > 1, "Expected EVPN Type 2 messages to split on size");

    inet_pton(AF_INET, "192.0.2.12", next_hop);

    for (msg = block.messages; msg; msg = msg->next) {
        int            message_nlri = 0;
        const uint8_t *nlri = NULL;
        uint16_t       nlri_len = 0;

        ASSERT(extract_mp_reach_evpn_type5(msg->data, msg->length, NULL, NULL, &nlri, &nlri_len),
               "Split EVPN Type 2 UPDATE is missing MP_REACH");
        message_nlri = count_evpn_type2_nlri(nlri, nlri_len, 0);
        ASSERT(message_nlri > 0, "Split EVPN Type 2 UPDATE payload does not decode as Type 2 NLRIs");
        total_nlri += message_nlri;
    }

    ASSERT(total_nlri == 400, "Split EVPN Type 2 NLRI total does not match configured host-binding count");

    bgp_ribout_destroy(&block);
    PASS();
}

static void test_ribout_srpolicy_ipv4_config_to_encoded_updates(void) {
    bgp_ribout_config_t block;
    const uint8_t      *next_hop = NULL;
    const uint8_t      *nlri = NULL;
    const uint8_t      *tunnel = NULL;
    const uint8_t      *ext_comm = NULL;
    uint8_t             nh_len = 0;
    uint16_t            nlri_len = 0;
    uint16_t            tunnel_len = 0;
    uint16_t            ext_comm_len = 0;
    uint8_t             expected_nh[16];

    TEST("SR Policy IPv4 config -> MP UPDATE bytes");

    bgp_ribout_init(&block, "e2e-wire-srpol4");

    ASSERT(bgp_ribout_parse_distinguisher(&block, "distinguisher 100 101") == 0, "Failed to parse distinguisher");
    ASSERT(bgp_ribout_parse_color(&block, "color 200") == 0, "Failed to parse color");
    ASSERT(bgp_ribout_parse_endpoint(&block, "endpoint 10.0.0.1 x 2") == 0, "Failed to parse endpoint");
    ASSERT(bgp_ribout_parse_next_hop(&block, "next-hop 2001:db8::1") == 0, "Failed to parse next-hop");
    ASSERT(bgp_ribout_parse_rt(&block, "rt 192.0.2.10:100") == 0, "Failed to parse route-target");
    ASSERT(bgp_ribout_parse_preference(&block, "preference 300") == 0, "Failed to parse preference");
    ASSERT(bgp_ribout_parse_binding_sid(&block, "binding-sid mpls 16000") == 0, "Failed to parse binding SID");
    ASSERT(bgp_ribout_parse_segment_list(&block, "segment-list 1 weight 10 mpls 16010 16011") == 0,
           "Failed to parse segment-list");
    ASSERT(bgp_ribout_parse_aspath(&block, "as-path 65001 65002") == 0, "Failed to parse AS path");
    ASSERT(bgp_ribout_parse_localpref(&block, "localpref 200") == 0, "Failed to parse localpref");
    ASSERT(bgp_ribout_parse_origin(&block, "origin egp") == 0, "Failed to parse origin");

    ASSERT(bgp_ribout_generate_map(&block) == 0, "Map generation failed");
    ASSERT(block.ribout != NULL, "Map not created");
    ASSERT(block.ribout->entry_count == 1, "Expected one grouped SR Policy IPv4 attribute entry");
    ASSERT(block.ribout->total_nlri_count == 4, "Expected 4 generated SR Policy IPv4 NLRIs");

    ASSERT(bgp_ribout_generate_messages(&block) == 0, "Message generation failed");
    ASSERT(block.message_count == 1, "Expected a single SR Policy IPv4 UPDATE");
    ASSERT(block.messages != NULL && block.messages->next == NULL,
           "Expected a single SR Policy IPv4 message in the list");

    inet_pton(AF_INET6, "2001:db8::1", expected_nh);

    ASSERT(find_attr(block.messages->data, block.messages->length, BGP_ATTR_EXT_COMM,
                     &ext_comm, &ext_comm_len) &&
           ext_comm_len == 8 &&
           ext_comm[0] == 0x01 && ext_comm[1] == 0x02,
           "SR Policy IPv4 UPDATE carries one IPv4-address RT");
    ASSERT(find_attr(block.messages->data, block.messages->length, BGP_ATTR_TUNNEL_ENCAP,
                     &tunnel, &tunnel_len) &&
           tunnel_len > 4 &&
           read_u16(tunnel) == 15,
           "SR Policy IPv4 UPDATE carries Tunnel Encapsulation type 15");
    ASSERT(extract_mp_reach_srpolicy4(block.messages->data, block.messages->length, &next_hop, &nh_len, &nlri, &nlri_len),
           "Missing SR Policy IPv4 MP_REACH_NLRI");
    ASSERT(nh_len == 16 && memcmp(next_hop, expected_nh, sizeof(expected_nh)) == 0,
           "SR Policy IPv4 next-hop keeps AF-independent IPv6 encoding");
    ASSERT(count_srpolicy_nlri(nlri, nlri_len, AFI_IPV4, 0) == 4, "SR Policy IPv4 MP_REACH carries four NLRIs");
    ASSERT(validate_srpolicy_against_generator(block.messages, &block, AFI_IPV4, 0),
           "SR Policy IPv4 wire payload drifted from generator order");

    bgp_ribout_destroy(&block);
    PASS();
}

static void test_ribout_srpolicy_ipv6_config_to_encoded_updates(void) {
    bgp_ribout_config_t block;
    const uint8_t      *next_hop = NULL;
    const uint8_t      *nlri = NULL;
    const uint8_t      *tunnel = NULL;
    uint8_t             nh_len = 0;
    uint16_t            nlri_len = 0;
    uint16_t            tunnel_len = 0;
    uint8_t             expected_nh[4];

    TEST("SR Policy IPv6 config -> MP UPDATE bytes");

    bgp_ribout_init(&block, "e2e-wire-srpol6");

    ASSERT(bgp_ribout_parse_distinguisher(&block, "distinguisher 500") == 0, "Failed to parse distinguisher");
    ASSERT(bgp_ribout_parse_color(&block, "color 600 601") == 0, "Failed to parse color");
    ASSERT(bgp_ribout_parse_endpoint(&block, "endpoint 2001:db8::1 x 2") == 0, "Failed to parse endpoint");
    ASSERT(bgp_ribout_parse_next_hop(&block, "next-hop 192.0.2.1") == 0, "Failed to parse next-hop");
    ASSERT(bgp_ribout_parse_rt(&block, "rt 192.0.2.20:200") == 0, "Failed to parse route-target");
    ASSERT(bgp_ribout_parse_preference(&block, "preference 700") == 0, "Failed to parse preference");
    ASSERT(bgp_ribout_parse_segment_list(&block,
           "segment-list 7 weight 70 srv6 2001:db8:7::1 2001:db8:7::2") == 0,
           "Failed to parse segment-list");
    ASSERT(bgp_ribout_parse_aspath(&block, "as-path 65011 65012") == 0, "Failed to parse AS path");
    ASSERT(bgp_ribout_parse_localpref(&block, "localpref 225") == 0, "Failed to parse localpref");
    ASSERT(bgp_ribout_parse_origin(&block, "origin incomplete") == 0, "Failed to parse origin");

    ASSERT(bgp_ribout_generate_map(&block) == 0, "Map generation failed");
    ASSERT(block.ribout != NULL, "Map not created");
    ASSERT(block.ribout->entry_count == 1, "Expected one grouped SR Policy IPv6 attribute entry");
    ASSERT(block.ribout->total_nlri_count == 4, "Expected 4 generated SR Policy IPv6 NLRIs");

    ASSERT(bgp_ribout_generate_messages(&block) == 0, "Message generation failed");
    ASSERT(block.message_count == 1, "Expected a single SR Policy IPv6 UPDATE");
    ASSERT(block.messages != NULL && block.messages->next == NULL,
           "Expected a single SR Policy IPv6 message in the list");

    inet_pton(AF_INET, "192.0.2.1", expected_nh);

    ASSERT(find_attr(block.messages->data, block.messages->length, BGP_ATTR_TUNNEL_ENCAP,
                     &tunnel, &tunnel_len) &&
           tunnel_len > 4 &&
           read_u16(tunnel) == 15,
           "SR Policy IPv6 UPDATE carries Tunnel Encapsulation type 15");
    ASSERT(extract_mp_reach_srpolicy6(block.messages->data, block.messages->length, &next_hop, &nh_len, &nlri, &nlri_len),
           "Missing SR Policy IPv6 MP_REACH_NLRI");
    ASSERT(nh_len == 4 && memcmp(next_hop, expected_nh, sizeof(expected_nh)) == 0,
           "SR Policy IPv6 next-hop keeps AF-independent IPv4 encoding");
    ASSERT(count_srpolicy_nlri(nlri, nlri_len, AFI_IPV6, 0) == 4, "SR Policy IPv6 MP_REACH carries four NLRIs");
    ASSERT(validate_srpolicy_against_generator(block.messages, &block, AFI_IPV6, 0),
           "SR Policy IPv6 wire payload drifted from generator order");

    bgp_ribout_destroy(&block);
    PASS();
}

static void test_ribout_srpolicy_extended_tunnel_encoding(void) {
    bgp_ribout_config_t block;
    const uint8_t      *tunnel = NULL;
    uint16_t            tunnel_len = 0;
    uint8_t             expected_bsid[16];
    uint8_t             binding_sid_pattern[20];
    uint8_t enlp_pattern[] = {14, 3, 0, 0, 3};
    uint8_t priority_pattern[] = {15, 2, 7, 0};
    uint8_t behavior_pattern[] = {0x12, 0x34, 0x00, 0x00, 48, 16, 16, 48};

    TEST("SR Policy ribout emits extended tunnel-encap sub-TLVs");

    bgp_ribout_init(&block, "e2e-wire-srpol-extended");

    ASSERT(bgp_ribout_parse_distinguisher(&block, "distinguisher 100") == 0, "Failed to parse distinguisher");
    ASSERT(bgp_ribout_parse_color(&block, "color 200") == 0, "Failed to parse color");
    ASSERT(bgp_ribout_parse_endpoint(&block, "endpoint 2001:db8::1") == 0, "Failed to parse endpoint");
    ASSERT(bgp_ribout_parse_next_hop(&block, "next-hop 192.0.2.1") == 0, "Failed to parse next-hop");
    ASSERT(bgp_ribout_parse_rt(&block, "rt 192.0.2.20:200") == 0, "Failed to parse route-target");
    ASSERT(bgp_ribout_parse_enlp(&block, "enlp 3") == 0, "Failed to parse ENLP");
    ASSERT(bgp_ribout_parse_priority(&block, "priority 7") == 0, "Failed to parse priority");
    ASSERT(bgp_ribout_parse_preference(&block, "preference 700") == 0, "Failed to parse preference");
    ASSERT(bgp_ribout_parse_binding_sid(&block, "binding-sid srv6 fc00:0:77::1") == 0,
           "Failed to parse SRv6 binding SID");
    ASSERT(bgp_ribout_parse_segment_list(&block,
           "segment-list 7 weight 70 srv6 "
           "2001:db8:7::1 behavior 4660 structure 48 16 16 48 "
           "2001:db8:7::2") == 0,
           "Failed to parse SRv6 segment-list");

    ASSERT(bgp_ribout_generate_map(&block) == 0, "Map generation failed");
    ASSERT(bgp_ribout_generate_messages(&block) == 0, "Message generation failed");
    ASSERT(block.message_count == 1, "Expected a single extended SR Policy UPDATE");
    ASSERT(find_attr(block.messages->data, block.messages->length, BGP_ATTR_TUNNEL_ENCAP,
                     &tunnel, &tunnel_len) &&
           tunnel_len > 4,
           "Extended SR Policy UPDATE carries tunnel-encap");

    inet_pton(AF_INET6, "fc00:0:77::1", expected_bsid);
    binding_sid_pattern[0] = 13;
    binding_sid_pattern[1] = 18;
    binding_sid_pattern[2] = 0;
    binding_sid_pattern[3] = 0;
    memcpy(binding_sid_pattern + 4, expected_bsid, sizeof(expected_bsid));

    ASSERT(buffer_contains(tunnel, tunnel_len, enlp_pattern, sizeof(enlp_pattern)),
           "Tunnel-encap carries ENLP sub-TLV");
    ASSERT(buffer_contains(tunnel, tunnel_len, priority_pattern, sizeof(priority_pattern)),
           "Tunnel-encap carries Priority sub-TLV");
    ASSERT(buffer_contains(tunnel, tunnel_len,
                           binding_sid_pattern, sizeof(binding_sid_pattern)),
           "Tunnel-encap carries legacy SRv6 Binding SID sub-TLV");
    ASSERT(buffer_contains(tunnel, tunnel_len,
                           behavior_pattern, sizeof(behavior_pattern)),
           "Tunnel-encap carries SRv6 behavior/structure bytes");

    bgp_ribout_destroy(&block);
    PASS();
}

/*
 * RFC 9830 Figure 13: the Segment Flags B-Flag is bit 3 of the octet (0x10). A ribout SRv6 segment configured with a
 * behavior is a Type B segment sub-TLV (type 13, length 26) whose flags octet is exactly B.
 */
static void test_ribout_srpolicy_srv6_segment_b_flag(void) {
    bgp_ribout_config_t block;
    const uint8_t      *tunnel = NULL;
    uint16_t            tunnel_len = 0;
    uint8_t             segment_pattern[4 + 16] = {13, 26, 0x10, 0x00};

    TEST("SR Policy ribout SRv6 segment with behavior sets the RFC 9830 B-Flag (0x10)");

    bgp_ribout_init(&block, "e2e-wire-srpol-b-flag");
    ASSERT(bgp_ribout_parse_distinguisher(&block, "distinguisher 100") == 0, "Failed to parse distinguisher");
    ASSERT(bgp_ribout_parse_color(&block, "color 200") == 0, "Failed to parse color");
    ASSERT(bgp_ribout_parse_endpoint(&block, "endpoint 2001:db8::1") == 0, "Failed to parse endpoint");
    ASSERT(bgp_ribout_parse_next_hop(&block, "next-hop 192.0.2.1") == 0, "Failed to parse next-hop");
    ASSERT(bgp_ribout_parse_rt(&block, "rt 192.0.2.20:200") == 0, "Failed to parse route-target");
    ASSERT(bgp_ribout_parse_segment_list(&block,
           "segment-list 7 weight 70 srv6 "
           "2001:db8:7::1 behavior 4660 structure 48 16 16 48") == 0,
           "Failed to parse SRv6 segment-list");

    ASSERT(bgp_ribout_generate_map(&block) == 0, "Map generation failed");
    ASSERT(bgp_ribout_generate_messages(&block) == 0, "Message generation failed");
    ASSERT(find_attr(block.messages->data, block.messages->length, BGP_ATTR_TUNNEL_ENCAP, &tunnel, &tunnel_len) && tunnel_len > 4,
           "SR Policy UPDATE carries tunnel-encap");

    inet_pton(AF_INET6, "2001:db8:7::1", segment_pattern + 4);
    ASSERT(buffer_contains(tunnel, tunnel_len, segment_pattern, sizeof(segment_pattern)),
           "RFC 9830 section 2.4.4.2.3: a Type B segment with a behavior has flags B (0x10)");

    bgp_ribout_destroy(&block);
    PASS();
}

static void test_ribout_srpolicy_add_path_bytes_follow_generator_order(void) {
    bgp_ribout_config_t block;
    const uint8_t      *nlri = NULL;
    uint16_t            nlri_len = 0;

    TEST("SR Policy ADD-PATH wire order matches generator preview order");

    bgp_ribout_init(&block, "e2e-add-path-srpol4");

    ASSERT(bgp_ribout_parse_distinguisher(&block, "distinguisher 100") == 0, "Failed to parse distinguisher");
    ASSERT(bgp_ribout_parse_color(&block, "color 200 201") == 0, "Failed to parse color");
    ASSERT(bgp_ribout_parse_endpoint(&block, "endpoint 10.0.0.1 x 2") == 0, "Failed to parse endpoint");
    ASSERT(bgp_ribout_parse_path_ids(&block, "path-id 7 8") == 0, "Failed to parse path-id");
    ASSERT(bgp_ribout_parse_next_hop(&block, "next-hop 192.0.2.1") == 0, "Failed to parse next-hop");
    ASSERT(bgp_ribout_parse_rt(&block, "rt 192.0.2.10:100") == 0, "Failed to parse route-target");
    ASSERT(bgp_ribout_parse_preference(&block, "preference 300") == 0, "Failed to parse preference");
    ASSERT(bgp_ribout_parse_binding_sid(&block, "binding-sid mpls 16000") == 0, "Failed to parse binding SID");
    ASSERT(bgp_ribout_parse_segment_list(&block, "segment-list 1 weight 10 mpls 16010 16011") == 0,
           "Failed to parse segment-list");
    ASSERT(bgp_ribout_parse_aspath(&block, "as-path 65001 65002") == 0, "Failed to parse AS path");
    ASSERT(bgp_ribout_parse_localpref(&block, "localpref 200") == 0, "Failed to parse localpref");
    ASSERT(bgp_ribout_parse_origin(&block, "origin igp") == 0, "Failed to parse origin");

    ASSERT(bgp_ribout_generate_map(&block) == 0, "Map generation failed");
    ASSERT(block.ribout != NULL, "Map not created");
    ASSERT(block.ribout->entry_count == 1, "Expected one grouped SR Policy ADD-PATH attribute entry");
    ASSERT(block.ribout->total_nlri_count == 8, "Expected 8 generated SR Policy ADD-PATH NLRIs");

    ASSERT(bgp_ribout_generate_messages(&block) == 0, "Message generation failed");
    ASSERT(block.message_count == 1, "Expected a single SR Policy ADD-PATH UPDATE");
    ASSERT(extract_mp_reach_srpolicy4(block.messages->data, block.messages->length, NULL, NULL, &nlri, &nlri_len),
           "Missing SR Policy IPv4 MP_REACH_NLRI");
    ASSERT(count_srpolicy_nlri(nlri, nlri_len, AFI_IPV4, 1) > 0,
           "SR Policy ADD-PATH message carries path-id encoded NLRIs");
    ASSERT(validate_srpolicy_against_generator(block.messages, &block, AFI_IPV4, 1),
           "SR Policy ADD-PATH wire encoding drifted from generator order");

    bgp_ribout_destroy(&block);
    PASS();
}

static void test_ribout_srpolicy_message_splitting(void) {
    bgp_ribout_config_t block;
    bgp_msg_t          *msg;
    int                 total_nlri = 0;

    TEST("SR Policy ribout splits large UPDATE sets cleanly");

    bgp_ribout_init(&block, "e2e-split-srpol4");

    ASSERT(bgp_ribout_parse_distinguisher(&block, "distinguisher 100") == 0, "Failed to parse distinguisher");
    ASSERT(bgp_ribout_parse_color(&block, "color 200") == 0, "Failed to parse color");
    ASSERT(bgp_ribout_parse_endpoint(&block, "endpoint 10.0.0.1 x 400") == 0, "Failed to parse endpoint");
    ASSERT(bgp_ribout_parse_path_ids(&block, "path-id 7 8") == 0, "Failed to parse path-id");
    ASSERT(bgp_ribout_parse_rt(&block, "rt 192.0.2.10:100") == 0, "Failed to parse route-target");
    ASSERT(bgp_ribout_parse_segment_list(&block, "segment-list 1 weight 10 mpls 16010 16011") == 0,
           "Failed to parse segment-list");
    ASSERT(bgp_ribout_parse_aspath(&block, "as-path 65001 65002") == 0, "Failed to parse AS path");
    ASSERT(bgp_ribout_parse_localpref(&block, "localpref 200") == 0, "Failed to parse localpref");
    ASSERT(bgp_ribout_parse_origin(&block, "origin igp") == 0, "Failed to parse origin");

    ASSERT(bgp_ribout_generate_map(&block) == 0, "Map generation failed");
    ASSERT(block.ribout != NULL, "Map not created");
    ASSERT(block.ribout->entry_count == 1, "Expected one grouped SR Policy split-test entry");
    ASSERT(block.ribout->total_nlri_count == 800, "Expected 800 generated SR Policy NLRIs");

    ASSERT(bgp_ribout_generate_messages(&block) == 0, "Message generation failed");
    ASSERT(block.message_count > 1, "Large SR Policy ribout should split across multiple UPDATEs");
    ASSERT(count_messages(block.messages) == block.message_count,
           "Message list length matches SR Policy split counter");

    for (msg = block.messages; msg; msg = msg->next) {
        const uint8_t *nlri = NULL;
        uint16_t       nlri_len = 0;
        int            message_nlri;

        ASSERT(extract_mp_reach_srpolicy4(msg->data, msg->length, NULL, NULL, &nlri, &nlri_len),
               "Split SR Policy UPDATE is missing MP_REACH");
        message_nlri = count_srpolicy_nlri(nlri, nlri_len, AFI_IPV4, 1);
        ASSERT(message_nlri > 0, "Each split SR Policy UPDATE carries at least one NLRI");
        total_nlri += message_nlri;
    }

    ASSERT(total_nlri == 800, "Split SR Policy UPDATE sequence preserves all generated NLRIs");

    bgp_ribout_destroy(&block);
    PASS();
}

static void test_ribout_vpnv4_add_path_bytes_follow_generator_order(void) {
    bgp_ribout_config_t block;
    bgp_ribout_gen_t    gen;
    const uint8_t      *nlri = NULL;
    uint16_t            nlri_len = 0;
    int                 offset = 0;

    TEST("VPNv4 ADD-PATH wire order matches generator preview order");

    bgp_ribout_init(&block, "e2e-add-path-vpnv4");

    ASSERT(bgp_ribout_parse_prefix(&block, "prefix 10.20.0.0/24 x 3") == 0, "Failed to parse VPNv4 prefix");
    ASSERT(bgp_ribout_parse_rd(&block, "rd 65000:100") == 0, "Failed to parse RD");
    ASSERT(bgp_ribout_parse_label(&block, "label 16000") == 0, "Failed to parse label");
    ASSERT(bgp_ribout_parse_path_ids(&block, "path-id 101 202") == 0, "Failed to parse path-id");
    ASSERT(bgp_ribout_parse_next_hop(&block, "next-hop 192.0.2.1") == 0, "Failed to parse next-hop");
    ASSERT(bgp_ribout_parse_rt(&block, "rt 65000:100") == 0, "Failed to parse RT");
    ASSERT(bgp_ribout_parse_aspath(&block, "as-path 65001 65002") == 0, "Failed to parse AS path");
    ASSERT(bgp_ribout_parse_localpref(&block, "localpref 100") == 0, "Failed to parse localpref");
    ASSERT(bgp_ribout_parse_origin(&block, "origin igp") == 0, "Failed to parse origin");

    ASSERT(bgp_ribout_generate_map(&block) == 0, "Map generation failed");
    ASSERT(block.ribout != NULL, "Map not created");
    ASSERT(block.ribout->entry_count == 1, "Expected one grouped VPNv4 attribute entry");
    ASSERT(block.ribout->total_nlri_count == 6, "Expected 6 generated VPNv4 NLRIs");

    ASSERT(bgp_ribout_generate_messages(&block) == 0, "Message generation failed");
    ASSERT(block.message_count == 1, "Expected a single VPNv4 UPDATE");
    ASSERT(block.messages != NULL && block.messages->next == NULL, "Expected a single VPNv4 message in the list");
    ASSERT(bgp_ribout_generator_init(&gen, &block) == 0, "Failed to initialize VPNv4 generator");
    ASSERT(extract_mp_reach_vpnv4(block.messages->data, block.messages->length, NULL, NULL, &nlri, &nlri_len),
           "Missing VPNv4 MP_REACH_NLRI");

    while (offset < nlri_len) {
        bgp_gen_path_t expected;
        uint32_t       path_id;
        uint8_t        wire_prefix_len;
        int            prefix_bytes;

        ASSERT(bgp_ribout_generator_has_next(&gen) &&
               bgp_ribout_generator_next(&gen, &expected) == 0,
               "Generator preview exhausted before VPNv4 wire payload");
        ASSERT(expected.prefix_af == AF_INET && expected.has_rd && expected.has_label,
               "Generator emitted unexpected VPNv4 path shape");
        ASSERT(offset + 16 <= nlri_len, "VPNv4 wire payload truncated");

        path_id = read_u32(nlri + offset);
        offset += 4;
        wire_prefix_len = nlri[offset++];
        prefix_bytes = (expected.prefix_len + 7) / 8;

        ASSERT(path_id == expected.path_id, "VPNv4 path-id drifted from generator order");
        ASSERT(wire_prefix_len == (uint8_t)(expected.prefix_len + 88),
               "VPNv4 wire prefix length drifted from generator order");
        ASSERT(decode_wire_label(nlri + offset) == expected.label, "VPNv4 label drifted from generator order");
        ASSERT(read_u16(nlri + offset + 3) == expected.rd.type, "VPNv4 RD type drifted from generator order");
        ASSERT(memcmp(nlri + offset + 5, expected.rd.value, 6) == 0, "VPNv4 RD value drifted from generator order");
        ASSERT(memcmp(nlri + offset + 11,
                      &expected.prefix_addr.ipv4,
                      (size_t)prefix_bytes) == 0,
               "VPNv4 prefix drifted from generator order");

        offset += 3 + 8 + prefix_bytes;
    }

    ASSERT(offset == nlri_len && !bgp_ribout_generator_has_next(&gen),
           "VPNv4 wire payload length drifted from generator total");

    bgp_ribout_destroy(&block);
    PASS();
}

static void test_ribout_add_path_bytes_follow_generator_order(void) {
    bgp_ribout_config_t block;

    TEST("ADD-PATH wire order matches generator preview order");

    bgp_ribout_init(&block, "e2e-add_path");

    ASSERT(bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/24 x 3") == 0, "Failed to parse prefix");
    ASSERT(bgp_ribout_parse_path_ids(&block, "path-id 100 200") == 0, "Failed to parse path-id");
    ASSERT(bgp_ribout_parse_next_hop(&block, "next-hop 192.0.2.1") == 0, "Failed to parse next-hop");
    ASSERT(bgp_ribout_parse_aspath(&block, "as-path 65001 65002") == 0, "Failed to parse AS path");
    ASSERT(bgp_ribout_parse_localpref(&block, "localpref 100") == 0, "Failed to parse localpref");
    ASSERT(bgp_ribout_parse_origin(&block, "origin igp") == 0, "Failed to parse origin");

    ASSERT(bgp_ribout_generate_map(&block) == 0, "Map generation failed");
    ASSERT(block.ribout != NULL, "Map not created");
    ASSERT(block.ribout->entry_count == 1, "Expected one grouped path-attribute entry");
    ASSERT(block.ribout->total_nlri_count == 6, "Expected 6 generated NLRIs");

    ASSERT(bgp_ribout_generate_messages(&block) == 0, "Message generation failed");
    ASSERT(block.message_count == 1, "Expected a single UPDATE");
    ASSERT(block.messages != NULL && block.messages->next == NULL, "Expected a single message in the list");
    ASSERT(validate_ipv4_add_path_against_generator(block.messages, &block),
           "ADD-PATH wire encoding drifted from generator order");

    bgp_ribout_destroy(&block);
    PASS();
}

static void test_ribout_ipv4_rfc8950_add_path_bytes_follow_generator_order(void) {
    bgp_ribout_config_t block;
    const uint8_t      *nlri = NULL;
    uint16_t            nlri_len = 0;

    TEST("IPv4 RFC 8950 ADD-PATH wire order matches generator preview order");

    bgp_ribout_init(&block, "e2e-add_path-v4-mp");

    ASSERT(bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/24 x 3") == 0, "Failed to parse IPv4 prefix");
    ASSERT(bgp_ribout_parse_path_ids(&block, "path-id 100 200") == 0, "Failed to parse path-id");
    ASSERT(bgp_ribout_parse_next_hop(&block, "next-hop 2001:db8::1") == 0, "Failed to parse IPv6 next-hop");
    ASSERT(bgp_ribout_parse_aspath(&block, "as-path 65001 65002") == 0, "Failed to parse AS path");
    ASSERT(bgp_ribout_parse_localpref(&block, "localpref 100") == 0, "Failed to parse localpref");
    ASSERT(bgp_ribout_parse_origin(&block, "origin igp") == 0, "Failed to parse origin");

    ASSERT(bgp_ribout_generate_map(&block) == 0, "Map generation failed");
    ASSERT(block.ribout != NULL, "Map not created");
    ASSERT(block.ribout->entry_count == 1, "Expected one grouped path-attribute entry");
    ASSERT(block.ribout->total_nlri_count == 6, "Expected 6 generated NLRIs");

    ASSERT(bgp_ribout_generate_messages(&block) == 0, "Message generation failed");
    ASSERT(block.message_count == 1, "Expected a single RFC 8950 UPDATE");
    ASSERT(block.messages != NULL && block.messages->next == NULL, "Expected a single message in the list");
    ASSERT(extract_mp_reach_ipv4(block.messages->data, block.messages->length, NULL, NULL, &nlri, &nlri_len),
           "Missing IPv4 MP_REACH_NLRI");
    ASSERT(nlri_len > 0, "Missing IPv4 MP NLRI payload");
    ASSERT(validate_ipv4_mp_add_path_against_generator(block.messages, &block),
           "IPv4 RFC 8950 ADD-PATH wire encoding drifted from generator order");

    bgp_ribout_destroy(&block);
    PASS();
}

static void test_ribout_ipv6_add_path_bytes_follow_generator_order(void) {
    bgp_ribout_config_t block;
    const uint8_t      *nlri = NULL;
    uint16_t            nlri_len = 0;

    TEST("IPv6 ADD-PATH wire order matches generator preview order");

    bgp_ribout_init(&block, "e2e-add_path-v6");

    ASSERT(bgp_ribout_parse_prefix(&block, "prefix 2001:db8::/64 x 3") == 0, "Failed to parse IPv6 prefix");
    ASSERT(bgp_ribout_parse_path_ids(&block, "path-id 100 200") == 0, "Failed to parse path-id");
    ASSERT(bgp_ribout_parse_next_hop(&block, "next-hop 2001:db8::1") == 0, "Failed to parse IPv6 next-hop");
    ASSERT(bgp_ribout_parse_aspath(&block, "as-path 65001 65002") == 0, "Failed to parse AS path");
    ASSERT(bgp_ribout_parse_localpref(&block, "localpref 100") == 0, "Failed to parse localpref");
    ASSERT(bgp_ribout_parse_origin(&block, "origin igp") == 0, "Failed to parse origin");

    ASSERT(bgp_ribout_generate_map(&block) == 0, "Map generation failed");
    ASSERT(block.ribout != NULL, "Map not created");
    ASSERT(block.ribout->entry_count == 1, "Expected one grouped path-attribute entry");
    ASSERT(block.ribout->total_nlri_count == 6, "Expected 6 generated NLRIs");

    ASSERT(bgp_ribout_generate_messages(&block) == 0, "Message generation failed");
    ASSERT(block.message_count == 1, "Expected a single IPv6 UPDATE");
    ASSERT(block.messages != NULL && block.messages->next == NULL, "Expected a single message in the list");
    ASSERT(extract_mp_reach_ipv6(block.messages->data, block.messages->length, NULL, NULL, &nlri, &nlri_len),
           "Missing MP_REACH_NLRI");
    ASSERT(nlri_len > 0, "Missing IPv6 NLRI payload");
    ASSERT(validate_ipv6_add_path_against_generator(block.messages, &block),
           "IPv6 ADD-PATH wire encoding drifted from generator order");

    bgp_ribout_destroy(&block);
    PASS();
}

static void test_ribout_labeled_ipv4_add_path_bytes_follow_generator_order(void) {
    bgp_ribout_config_t block;
    const uint8_t      *nlri = NULL;
    uint16_t            nlri_len = 0;

    TEST("IPv4 labeled-unicast ADD-PATH matches generator preview order");

    bgp_ribout_init(&block, "e2e-add_path-lu-v4");

    ASSERT(bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/24 x 3") == 0, "Failed to parse IPv4 prefix");
    ASSERT(bgp_ribout_parse_label(&block, "label 16000 16001") == 0, "Failed to parse labels");
    ASSERT(bgp_ribout_parse_path_ids(&block, "path-id 100 200") == 0, "Failed to parse path-id");
    ASSERT(bgp_ribout_parse_next_hop(&block, "next-hop 192.0.2.1") == 0, "Failed to parse next-hop");
    ASSERT(bgp_ribout_parse_aspath(&block, "as-path 65001 65002") == 0, "Failed to parse AS path");
    ASSERT(bgp_ribout_parse_localpref(&block, "localpref 100") == 0, "Failed to parse localpref");
    ASSERT(bgp_ribout_parse_origin(&block, "origin igp") == 0, "Failed to parse origin");

    ASSERT(bgp_ribout_generate_map(&block) == 0, "Map generation failed");
    ASSERT(block.ribout != NULL, "Map not created");
    ASSERT(block.ribout->entry_count == 1, "Expected one grouped path-attribute entry");
    ASSERT(block.ribout->total_nlri_count == 12, "Expected 12 generated NLRIs");

    ASSERT(bgp_ribout_generate_messages(&block) == 0, "Message generation failed");
    ASSERT(block.message_count == 1, "Expected a single labeled IPv4 UPDATE");
    ASSERT(block.messages != NULL && block.messages->next == NULL, "Expected a single message in the list");
    ASSERT(extract_mp_reach_labeled_ipv4(block.messages->data, block.messages->length, NULL, NULL, &nlri, &nlri_len),
           "Missing labeled IPv4 MP_REACH_NLRI");
    ASSERT(nlri_len > 0, "Missing labeled IPv4 NLRI payload");
    ASSERT(validate_labeled_ipv4_add_path_against_generator(block.messages, &block),
           "Labeled IPv4 ADD-PATH wire encoding drifted from generator order");

    bgp_ribout_destroy(&block);
    PASS();
}

static void test_ribout_labeled_ipv6_add_path_bytes_follow_generator_order(void) {
    bgp_ribout_config_t block;
    const uint8_t      *nlri = NULL;
    uint16_t            nlri_len = 0;

    TEST("IPv6 labeled-unicast ADD-PATH matches generator preview order");

    bgp_ribout_init(&block, "e2e-add_path-lu-v6");

    ASSERT(bgp_ribout_parse_prefix(&block, "prefix 2001:db8::/64 x 3") == 0, "Failed to parse IPv6 prefix");
    ASSERT(bgp_ribout_parse_label(&block, "label 32000 32001") == 0, "Failed to parse labels");
    ASSERT(bgp_ribout_parse_path_ids(&block, "path-id 100 200") == 0, "Failed to parse path-id");
    ASSERT(bgp_ribout_parse_next_hop(&block, "next-hop 2001:db8::1") == 0, "Failed to parse IPv6 next-hop");
    ASSERT(bgp_ribout_parse_aspath(&block, "as-path 65001 65002") == 0, "Failed to parse AS path");
    ASSERT(bgp_ribout_parse_localpref(&block, "localpref 100") == 0, "Failed to parse localpref");
    ASSERT(bgp_ribout_parse_origin(&block, "origin igp") == 0, "Failed to parse origin");

    ASSERT(bgp_ribout_generate_map(&block) == 0, "Map generation failed");
    ASSERT(block.ribout != NULL, "Map not created");
    ASSERT(block.ribout->entry_count == 1, "Expected one grouped path-attribute entry");
    ASSERT(block.ribout->total_nlri_count == 12, "Expected 12 generated NLRIs");

    ASSERT(bgp_ribout_generate_messages(&block) == 0, "Message generation failed");
    ASSERT(block.message_count == 1, "Expected a single labeled IPv6 UPDATE");
    ASSERT(block.messages != NULL && block.messages->next == NULL, "Expected a single message in the list");
    ASSERT(extract_mp_reach_labeled_ipv6(block.messages->data, block.messages->length, NULL, NULL, &nlri, &nlri_len),
           "Missing labeled IPv6 MP_REACH_NLRI");
    ASSERT(nlri_len > 0, "Missing labeled IPv6 NLRI payload");
    ASSERT(validate_labeled_ipv6_add_path_against_generator(block.messages, &block),
           "Labeled IPv6 ADD-PATH wire encoding drifted from generator order");

    bgp_ribout_destroy(&block);
    PASS();
}

/*
 * FlowSpec: the library encoding of every generated path, in generator order.
 */
typedef struct {
    uint8_t *bytes;
    int      length;
    int      seen;
} flowspec_expected_nlri_t;

/*
 * Free the first count entries and the array from build_flowspec_expected.
 */
static void free_flowspec_expected(flowspec_expected_nlri_t *expected, int count) {
    for (int i = 0; expected && i < count; i++) {
        free(expected[i].bytes);
    }
    free(expected);
}

/*
 * Run the generator over the block and encode each path with the FlowSpec library encoder, in generator order. These
 * bytes are the reference for the wire NLRIs. Returns NULL on any failure.
 */
static flowspec_expected_nlri_t *build_flowspec_expected(bgp_ribout_config_t *block,
                                                         uint16_t afi,
                                                         int add_path,
                                                         int *count_out) {
    bgp_ribout_gen_t          gen;
    flowspec_expected_nlri_t *expected;
    uint8_t                   buffer[FLOWSPEC_MAX_NLRI_ENTRY_LEN];
    int                       count = 0;
    int                       capacity = 64;

    if (bgp_ribout_generator_init(&gen, block) != 0) {
        return NULL;
    }
    expected = calloc((size_t)capacity, sizeof(*expected));

    while (expected && bgp_ribout_generator_has_next(&gen)) {
        bgp_gen_path_t             path;
        bgp_ribout_flowspec_nlri_t nlri;
        int                        length;

        if (bgp_ribout_generator_next(&gen, &path) != 0 || !path.has_flowspec ||
            bgp_ribout_flowspec_materialize(block, path.flowspec_instance, &nlri) != 0) {
            free_flowspec_expected(expected, count);
            return NULL;
        }
        length = bgp_encode_flowspec_nlri_entry(buffer, &nlri.rule, path.has_rd ? &path.rd : NULL,
                                                afi, add_path, path.path_id);
        if (length <= 0) {
            free_flowspec_expected(expected, count);
            return NULL;
        }
        if (count == capacity) {
            flowspec_expected_nlri_t *grown = realloc(expected, (size_t)capacity * 2 * sizeof(*expected));

            if (!grown) {
                free_flowspec_expected(expected, count);
                return NULL;
            }
            memset(grown + capacity, 0, (size_t)capacity * sizeof(*grown));
            expected = grown;
            capacity *= 2;
        }
        expected[count].bytes = malloc((size_t)length);
        if (!expected[count].bytes) {
            free_flowspec_expected(expected, count);
            return NULL;
        }
        memcpy(expected[count].bytes, buffer, (size_t)length);
        expected[count].length = length;
        count++;
    }

    *count_out = count;
    return expected;
}

/*
 * Every NLRI in every message is the library encoding of one generated path;
 * inside a message the paths keep generator order; no path is lost or sent
 * twice. Returns the NLRI count, or -1.
 */
static int validate_flowspec_against_generator(bgp_ribout_config_t *block, uint16_t afi, uint8_t safi, int add_path) {
    flowspec_expected_nlri_t *expected;
    int                       count = 0;
    int                       matched = 0;

    expected = build_flowspec_expected(block, afi, add_path, &count);
    if (!expected) {
        return -1;
    }

    for (bgp_msg_t *msg = block->messages; msg; msg = msg->next) {
        const uint8_t *nlri = NULL;
        uint16_t       nlri_len = 0;
        int            offset = 0;
        int            last = -1;

        if (!extract_mp_reach_afi(msg->data, msg->length, afi, safi, NULL, NULL, &nlri, &nlri_len) || nlri_len == 0) {
            free_flowspec_expected(expected, count);
            return -1;
        }

        while (offset < nlri_len) {
            int found = -1;

            for (int i = last + 1; i < count; i++) {
                if (!expected[i].seen && expected[i].length <= nlri_len - offset &&
                    memcmp(expected[i].bytes, nlri + offset, (size_t)expected[i].length) == 0) {
                    found = i;
                    break;
                }
            }
            if (found < 0) {
                free_flowspec_expected(expected, count);
                return -1;
            }
            expected[found].seen = 1;
            offset += expected[found].length;
            last = found;
            matched++;
        }
    }

    free_flowspec_expected(expected, count);
    return (matched == count) ? matched : -1;
}

/*
 * 1 if the extended community attribute holds this 8-octet entry.
 */
static int ext_comm_has(const uint8_t *msg, size_t size, const uint8_t entry[8]) {
    const uint8_t *value = NULL;
    uint16_t       length = 0;

    if (!find_attr(msg, size, BGP_ATTR_EXT_COMM, &value, &length)) {
        return 0;
    }
    for (uint16_t offset = 0; offset + 8 <= length; offset += 8) {
        if (memcmp(value + offset, entry, 8) == 0) {
            return 1;
        }
    }
    return 0;
}

static void test_ribout_flowspec_ipv4_config_to_encoded_updates(void) {
    bgp_ribout_config_t block;
    const uint8_t      *next_hop = NULL;
    const uint8_t      *nlri = NULL;
    uint8_t             nh_len = 0xFF;
    uint16_t            nlri_len = 0;
    // RFC 8955: dst 10.1.0.0/24, protocol =6, dst-port =80 =443.
    static const uint8_t web0[] = {
        0x0e, 0x01, 0x18, 0x0a, 0x01, 0x00, 0x03, 0x81, 0x06,
        0x05, 0x01, 0x50, 0x91, 0x01, 0xbb
    };
    static const uint8_t mark10[8] = {0x80, 0x09, 0, 0, 0, 0, 0, 0x0a};
    static const uint8_t mark46[8] = {0x80, 0x09, 0, 0, 0, 0, 0, 0x2e};
    int mark10_messages = 0;

    TEST("FlowSpec IPv4 config -> MP UPDATE bytes");

    bgp_ribout_init(&block, "e2e-wire-fs4");

    ASSERT(bgp_ribout_parse_address_family(&block, "address-family ipv4 flowspec") == 0,
           "Failed to parse address-family");
    ASSERT(bgp_ribout_parse_aspath(&block, "as-path 65001 65002") == 0, "Failed to parse AS path");
    ASSERT(bgp_ribout_parse_origin(&block, "origin egp") == 0, "Failed to parse origin");
    ASSERT(bgp_ribout_parse_prefix(&block, "prefix 10.1.0.0/24 x 3") == 0 &&
           bgp_ribout_flowspec_parse_component(&block, "protocol", "6") == 0 &&
           bgp_ribout_flowspec_parse_component(&block, "dst-port", "80 443") == 0 &&
           bgp_ribout_flowspec_parse_action(&block, "mark 10 46") == 0,
           "Failed to configure the FlowSpec match and the rotating mark");

    ASSERT(bgp_ribout_generate_map(&block) == 0, "Map generation failed");
    ASSERT(block.ribout != NULL, "Map not created");
    ASSERT(block.ribout->entry_count == 2, "Expected one attribute entry per mark");
    ASSERT(block.ribout->total_nlri_count == 3, "Expected 3 generated FlowSpec NLRIs");

    ASSERT(bgp_ribout_generate_messages(&block) == 0, "Message generation failed");
    ASSERT(block.message_count == 2, "Expected one UPDATE per attribute entry");
    ASSERT(validate_flowspec_against_generator(&block, AFI_IPV4, SAFI_FLOWSPEC, 0) == 3,
           "FlowSpec IPv4 wire NLRIs drifted from the generator and library encoder");

    for (bgp_msg_t *msg = block.messages; msg; msg = msg->next) {
        ASSERT(extract_mp_reach_afi(msg->data, msg->length, AFI_IPV4, SAFI_FLOWSPEC,
                                    &next_hop, &nh_len, &nlri, &nlri_len),
               "FlowSpec UPDATE carries MP_REACH AFI 1 SAFI 133");
        ASSERT(nh_len == 0, "RFC 8955 section 4: FlowSpec next-hop length is 0");
        ASSERT(!find_attr(msg->data, msg->length, BGP_ATTR_NEXT_HOP, NULL, NULL),
               "FlowSpec UPDATE has no NEXT_HOP attribute");
        ASSERT(read_u16(msg->data + BGP_HEADER_SIZE) == 0, "FlowSpec UPDATE has no withdrawn routes");
        if (ext_comm_has(msg->data, msg->length, mark10)) {
            // Paths 1 and 3 (10.1.0.0/24 and 10.1.2.0/24) get the first mark.
            ASSERT(!ext_comm_has(msg->data, msg->length, mark46), "The marks do not mix between entries");
            ASSERT(nlri_len == 2 * sizeof(web0), "Mark 10 carries two NLRIs of equal size");
            ASSERT(memcmp(nlri, web0, sizeof(web0)) == 0, "The first NLRI matches the hand-encoded RFC 8955 bytes");
            mark10_messages++;
        } else {
            ASSERT(ext_comm_has(msg->data, msg->length, mark46) && nlri_len == sizeof(web0),
                   "Path 2 (10.1.1.0/24) gets the second mark");
        }
    }
    ASSERT(mark10_messages == 1, "Exactly one UPDATE carries mark 10");

    bgp_ribout_destroy(&block);
    PASS();
}

static void test_ribout_flowspec_vpn_ipv6_redirect_next_hop_to_encoded_updates(void) {
    bgp_ribout_config_t block;
    const uint8_t      *next_hop = NULL;
    const uint8_t      *nlri = NULL;
    const uint8_t      *ipv6_ext = NULL;
    uint8_t             nh_len = 0;
    uint16_t            nlri_len = 0;
    uint16_t            ipv6_ext_len = 0;
    uint8_t             endpoint[16];
    uint8_t             rt_ipv6[20] = {0x00, 0x0d};
    static const uint8_t redirect_nh[8] = {0x08, 0x00, 0, 0, 0, 0, 0, 0};
    static const uint8_t color7[8] = {0x03, 0x0b, 0, 0, 0, 0, 0, 0x07};
    static const uint8_t rd_type0[8] = {0, 0, 0xfd, 0xe8, 0, 0, 0, 1};

    TEST("FlowSpec VPN IPv6 redirect-next-hop + Color -> MP UPDATE bytes");

    inet_pton(AF_INET6, "2001:db8::99", endpoint);
    inet_pton(AF_INET6, "2001:db8::1", rt_ipv6 + 2);
    rt_ipv6[18] = 0x01;
    rt_ipv6[19] = 0x2c;

    bgp_ribout_init(&block, "e2e-wire-fsvpn6");

    ASSERT(bgp_ribout_parse_address_family(&block, "address-family ipv6 flowspec-vpn") == 0,
           "Failed to parse address-family");
    ASSERT(bgp_ribout_parse_rd(&block, "rd 65000:1") == 0, "Failed to parse RD");
    ASSERT(bgp_ribout_parse_path_ids(&block, "path-id 7 8") == 0, "Failed to parse path-id");
    ASSERT(bgp_ribout_parse_prefix(&block, "prefix 2001:db8:1::/48 x 2") == 0 &&
           bgp_ribout_flowspec_parse_component(&block, "flow-label", "5") == 0 &&
           bgp_ribout_parse_next_hop(&block, "next-hop 2001:db8::99") == 0 &&
           bgp_ribout_flowspec_parse_action(&block, "redirect-vrf 2001:db8::1:300") == 0 &&
           bgp_ribout_flowspec_parse_action(&block, "redirect-next-hop") == 0 &&
           bgp_ribout_parse_color(&block, "color 7") == 0,
           "Failed to configure the IPv6 FlowSpec VPN block");

    ASSERT(bgp_ribout_resolve_family(&block) == BGP_RIBOUT_FAMILY_FLOWSPEC_VPN_IPV6,
           "Block resolves to IPv6 FlowSpec VPN");
    ASSERT(bgp_ribout_generate_map(&block) == 0, "Map generation failed");
    ASSERT(block.ribout->total_nlri_count == 4, "Expected 2 prefixes x 2 path-ids");
    ASSERT(bgp_ribout_generate_messages(&block) == 0, "Message generation failed");
    ASSERT(block.message_count == 1, "Expected a single UPDATE");
    ASSERT(validate_flowspec_against_generator(&block, AFI_IPV6, SAFI_FLOWSPEC_VPN, 1) == 4,
           "FlowSpec VPN ADD-PATH wire NLRIs drifted from generator order");

    ASSERT(extract_mp_reach_afi(block.messages->data, block.messages->length, AFI_IPV6, SAFI_FLOWSPEC_VPN,
                                &next_hop, &nh_len, &nlri, &nlri_len),
           "UPDATE carries MP_REACH AFI 2 SAFI 134");
    ASSERT(nh_len == 16 && memcmp(next_hop, endpoint, 16) == 0,
           "Redirect-to-next-hop sends the configured next hop in MP_REACH");
    ASSERT(read_u32(nlri) == 7, "First NLRI carries the first path-id");
    ASSERT(nlri[4] == nlri_len / 4 - 5 && memcmp(nlri + 5, rd_type0, 8) == 0,
           "VPN NLRI length covers the RD that leads the NLRI value");
    ASSERT(ext_comm_has(block.messages->data, block.messages->length, redirect_nh) &&
           ext_comm_has(block.messages->data, block.messages->length, color7),
           "Attribute 16 carries redirect-to-next-hop and Color 7");
    ASSERT(find_attr(block.messages->data, block.messages->length, BGP_ATTR_IPV6_EXT_COMM, &ipv6_ext, &ipv6_ext_len) &&
           ipv6_ext_len == 20 && memcmp(ipv6_ext, rt_ipv6, 20) == 0,
           "IPv6 redirect-vrf travels in attribute 25 as rt-redirect-ipv6");

    bgp_ribout_destroy(&block);
    PASS();
}

static void test_ribout_flowspec_ipv6_redirect_ip_color_to_encoded_updates(void) {
    bgp_ribout_config_t block;
    const uint8_t      *ipv6_ext = NULL;
    uint16_t            ipv6_ext_len = 0;
    uint8_t             nh_len = 0xFF;
    uint8_t             redirect_ip[20] = {0x00, 0x0c};
    static const uint8_t color9_co10[8] = {0x03, 0x0b, 0x80, 0, 0, 0, 0, 0x09};

    TEST("FlowSpec IPv6 redirect-ip + Color -> attribute 25 and Color CO bits");

    inet_pton(AF_INET6, "2001:db8::77", redirect_ip + 2);

    bgp_ribout_init(&block, "e2e-wire-fs6");

    ASSERT(bgp_ribout_parse_address_family(&block, "address-family ipv6 flowspec") == 0,
           "Failed to parse address-family");
    ASSERT(bgp_ribout_flowspec_parse_action(&block, "redirect-ip 2001:db8::77") == 0 &&
           bgp_ribout_parse_color(&block, "color 9 co 10") == 0,
           "Failed to parse redirect-ip and color");
    ASSERT(bgp_ribout_parse_prefix(&block, "prefix 2001:db8:1::/64-96") == 0 &&
           bgp_ribout_flowspec_parse_component(&block, "fragment", "any(isf)") == 0,
           "Failed to configure the IPv6 match (destination offset 64)");

    ASSERT(bgp_ribout_generate_map(&block) == 0, "Map generation failed");
    ASSERT(bgp_ribout_generate_messages(&block) == 0, "Message generation failed");
    ASSERT(validate_flowspec_against_generator(&block, AFI_IPV6, SAFI_FLOWSPEC, 0) == 1,
           "FlowSpec IPv6 wire NLRI drifted from the library encoder");
    ASSERT(extract_mp_reach_afi(block.messages->data, block.messages->length, AFI_IPV6, SAFI_FLOWSPEC,
                                NULL, &nh_len, NULL, NULL) && nh_len == 0,
           "Redirect-to-IP keeps the FlowSpec next-hop length at 0");
    ASSERT(find_attr(block.messages->data, block.messages->length, BGP_ATTR_IPV6_EXT_COMM, &ipv6_ext, &ipv6_ext_len) &&
           ipv6_ext_len == 20 && memcmp(ipv6_ext, redirect_ip, 20) == 0,
           "IPv6 redirect-to-IP travels in attribute 25 with the C bit clear");
    ASSERT(ext_comm_has(block.messages->data, block.messages->length, color9_co10),
           "RFC 9830 CO bits 10 set the two high flag bits of the Color EC");

    bgp_ribout_destroy(&block);
    PASS();
}

static void test_ribout_flowspec_action_rotation_to_encoded_updates(void) {
    bgp_ribout_config_t block;
    int                 groups_ok = 1;
    int                 total_nlri = 0;

    TEST("FlowSpec redirect-ip and color rotate together, one value per path");

    // The FlowSpec SR-TE scale-test shape: rule i goes to policy (.201 + i mod 3, color 1 + i mod 3).
    bgp_ribout_init(&block, "e2e-wire-fs-rotate");
    ASSERT(bgp_ribout_parse_address_family(&block, "address-family ipv4 flowspec") == 0 &&
           bgp_ribout_parse_prefix(&block, "prefix 10.1.0.0/24 x 6") == 0 &&
           bgp_ribout_flowspec_parse_action(&block, "redirect-ip 10.255.0.201 x 3") == 0 &&
           bgp_ribout_parse_color(&block, "color 1 x 3") == 0,
           "Failed to configure the rotating FlowSpec block");
    ASSERT(bgp_ribout_generate_map(&block) == 0 && block.ribout->entry_count == 3,
           "Three (redirect, color) pairs make three attribute groups");
    ASSERT(bgp_ribout_generate_messages(&block) == 0 && block.message_count == 3,
           "Expected one UPDATE per attribute group");

    for (bgp_msg_t *msg = block.messages; msg; msg = msg->next) {
        const uint8_t *value = NULL;
        const uint8_t *nlri = NULL;
        uint16_t       length = 0;
        uint16_t       nlri_len = 0;
        uint32_t       k;

        // Attribute 16: the Color, then the redirect (0x010c, IPv4, local admin 0).
        if (!find_attr(msg->data, msg->length, BGP_ATTR_EXT_COMM, &value, &length) || length != 16 ||
            !extract_mp_reach_afi(msg->data, msg->length, AFI_IPV4, SAFI_FLOWSPEC, NULL, NULL, &nlri, &nlri_len)) {
            groups_ok = 0;
            break;
        }
        k = (uint32_t)value[7] - 1u;
        groups_ok &= (k < 3) && value[0] == 0x03 && value[1] == 0x0b &&
                     value[8] == 0x01 && value[9] == 0x0c && value[13] == 201u + k;
        // Each NLRI is <len 6> <type 1> <24> 10.1.<n>: n mod 3 must be k.
        for (int off = 0; off + 6 <= nlri_len; off += 6) {
            groups_ok &= (nlri[off] == 5) && ((uint32_t)nlri[off + 5] % 3 == k);
            total_nlri++;
        }
    }
    ASSERT(groups_ok && total_nlri == 6, "Each UPDATE pairs redirect .201+k with Color 1+k");
    bgp_ribout_destroy(&block);
    PASS();
}

static void test_ribout_flowspec_long_nlri_and_message_splitting(void) {
    bgp_ribout_config_t block;
    int                 long_form = 1;

    TEST("FlowSpec ribout splits large rule sets and uses 2-octet NLRI lengths");

    bgp_ribout_init(&block, "e2e-split-fs6");

    ASSERT(bgp_ribout_parse_address_family(&block, "address-family ipv6 flowspec") == 0,
           "Failed to parse address-family");
    ASSERT(bgp_ribout_parse_path_ids(&block, "path-id 1") == 0, "Failed to parse path-id");
    ASSERT(bgp_ribout_parse_prefix(&block, "prefix 2001:db8::1/128 x 100") == 0 &&
           bgp_ribout_flowspec_parse_component(&block, "src-prefix", "2001:db8::2/128") == 0 &&
           bgp_ribout_flowspec_parse_component(&block, "protocol", "1 2 3 4 5 6 7 8") == 0 &&
           bgp_ribout_flowspec_parse_component(&block, "port", "1000 1001 1002 1003 1004 1005 1006 1007") == 0 &&
           bgp_ribout_flowspec_parse_component(&block, "dst-port",
                                                       ">=1024&<=2047 >=3000&<=3999 8080 8443 9000 9001") == 0 &&
           bgp_ribout_flowspec_parse_component(&block, "src-port", "2000 2001 2002 2003 2004 2005 2006 2007") == 0 &&
           bgp_ribout_flowspec_parse_component(&block, "icmp-type", "1 2 3 4 128 129 133 134") == 0 &&
           bgp_ribout_flowspec_parse_component(&block, "icmp-code", "0 1 2 3 4 5 6 7") == 0 &&
           bgp_ribout_flowspec_parse_component(&block, "tcp-flags", "syn !rst fin+ack any(ack)&!syn") == 0 &&
           bgp_ribout_flowspec_parse_component(&block, "packet-length", ">=1000&<=1499 1500 9000 9216") == 0 &&
           bgp_ribout_flowspec_parse_component(&block, "dscp", "0 8 10 18 26 34 46 48") == 0 &&
           bgp_ribout_flowspec_parse_component(&block, "fragment", "any(isf) any(ff) any(lf) ff+lf") == 0 &&
           bgp_ribout_flowspec_parse_component(&block, "flow-label",
                                                       "100000 100001 100002 100003 "
                                                       "100004 100005 100006 100007") == 0 &&
           bgp_ribout_flowspec_parse_action(&block, "traffic-rate bytes 0") == 0,
           "Failed to configure the long FlowSpec match");

    ASSERT(bgp_ribout_generate_map(&block) == 0, "Map generation failed");
    ASSERT(block.ribout->total_nlri_count == 100, "Expected 100 generated FlowSpec NLRIs");
    ASSERT(bgp_ribout_generate_messages(&block) == 0, "Message generation failed");
    ASSERT(block.message_count > 1, "Large FlowSpec ribout splits across UPDATEs");
    ASSERT(count_messages(block.messages) == block.message_count,
           "Message list length matches the FlowSpec split counter");

    for (bgp_msg_t *msg = block.messages; msg; msg = msg->next) {
        const uint8_t *nlri = NULL;
        uint16_t       nlri_len = 0;

        ASSERT(msg->length <= BGP_MAX_MESSAGE_SIZE &&
               read_u16(msg->data + 16) == msg->length,
               "Each split FlowSpec UPDATE fits RFC 4271 4096 octets");
        ASSERT(extract_mp_reach_afi(msg->data, msg->length, AFI_IPV6, SAFI_FLOWSPEC, NULL, NULL, &nlri, &nlri_len),
               "Each split FlowSpec UPDATE carries MP_REACH");
        // path-id(4), then 0xFnnn: RFC 8955 section 4.1 2-octet length.
        if ((nlri[4] & 0xF0) != 0xF0 || (((nlri[4] & 0x0F) << 8) | nlri[5]) < 240) {
            long_form = 0;
        }
    }
    ASSERT(long_form, "NLRIs of 240 octets or more use the 2-octet length form");
    ASSERT(validate_flowspec_against_generator(&block, AFI_IPV6, SAFI_FLOWSPEC, 1) == 100,
           "Split FlowSpec UPDATE sequence preserves all generated NLRIs in order");

    bgp_ribout_destroy(&block);
    PASS();
}

/*
 * The block must fail generation; nothing is generated.
 */
static int flowspec_generation_rejected(const char *family, const char *rd, const char *next_hop,
                                        const char *prefix, const char *component, const char *args,
                                        const char *action) {
    bgp_ribout_config_t block;
    int                 configured;
    int                 rejected;

    bgp_ribout_init(&block, "e2e-fs-reject");
    configured = (!family || bgp_ribout_parse_address_family(&block, family) == 0) &&
                 (!rd || bgp_ribout_parse_rd(&block, rd) == 0) &&
                 (!next_hop || bgp_ribout_parse_next_hop(&block, next_hop) == 0) &&
                 (!prefix || bgp_ribout_parse_prefix(&block, prefix) == 0) &&
                 (!component || bgp_ribout_flowspec_parse_component(&block, component, args) == 0) &&
                 (!action || bgp_ribout_flowspec_parse_action(&block, action) == 0);

    // Only a block that configured cleanly may count as rejected.
    rejected = configured && bgp_ribout_generate_map(&block) != 0 &&
               (block.ribout == NULL || block.ribout->total_nlri_count == 0);
    bgp_ribout_destroy(&block);
    return rejected;
}

static void test_ribout_flowspec_generation_rejects_invalid_blocks(void) {
    TEST("FlowSpec generation rejects blocks that cannot encode");

    ASSERT(flowspec_generation_rejected(
           "address-family ipv4 flowspec", NULL, NULL,
           NULL, NULL, NULL, "traffic-rate bytes 0"),
           "A FlowSpec block needs a prefix, src-prefix or component");
    ASSERT(flowspec_generation_rejected(
           "address-family ipv4 flowspec", NULL, NULL,
           "prefix 10.0.0.0/24", "flow-label", "5", NULL),
           "RFC 8956: flow-label is IPv6 only");
    ASSERT(flowspec_generation_rejected(
           "address-family ipv6 flowspec", NULL, NULL,
           "prefix 2001:db8::/32", "fragment", "df", NULL),
           "RFC 8956: IPv6 fragment has no DF bit");
    ASSERT(flowspec_generation_rejected(
           "address-family ipv6 flowspec", NULL, NULL,
           "prefix 10.0.0.0/24", NULL, NULL, NULL),
           "FlowSpec prefixes must match the block family");
    ASSERT(flowspec_generation_rejected(
           "address-family ipv4 flowspec-vpn", NULL, NULL,
           "prefix 10.0.0.0/24", NULL, NULL, NULL),
           "FlowSpec VPN needs an RD");
    ASSERT(flowspec_generation_rejected(
           "address-family ipv4 flowspec", "rd 65000:1", NULL,
           "prefix 10.0.0.0/24", NULL, NULL, NULL),
           "An RD conflicts with non-VPN FlowSpec");
    ASSERT(flowspec_generation_rejected(
           "address-family ipv4 flowspec", NULL, "next-hop 192.0.2.1",
           "prefix 10.0.0.0/24", NULL, NULL, NULL),
           "RFC 8955 section 4: a next hop needs a redirect-to-next-hop action");
    ASSERT(flowspec_generation_rejected(
           "address-family ipv4 flowspec", NULL, NULL,
           "prefix 10.0.0.0/24", NULL, NULL, "redirect-next-hop"),
           "Redirect-to-next-hop needs a next hop");
    ASSERT(flowspec_generation_rejected(
           "address-family ipv6", NULL, "next-hop 2001:db8::1",
           "prefix 2001:db8::/8-64", NULL, NULL, NULL),
           "A prefix offset is only valid for an IPv6 FlowSpec destination");

    PASS();
}

/*
 * One wire NLRI as <length><prefix bytes>, zero padded for sorting.
 */
typedef struct {
    uint8_t bytes[17];
} wire_prefix_key_t;

/*
 * qsort order for wire_prefix_key_t: bytewise.
 */
static int wire_prefix_key_cmp(const void *a, const void *b) {
    return memcmp(a, b, sizeof(wire_prefix_key_t));
}

/*
 * Append every prefix in a plain NLRI field to keys; -1 on a framing error.
 */
static int collect_wire_prefixes(const uint8_t *data, uint16_t length,
                                 wire_prefix_key_t *keys, int max_keys, int *count) {
    int offset = 0;

    while (offset < length) {
        uint8_t prefix_len = data[offset];
        int     prefix_bytes = (prefix_len + 7) / 8;

        if (*count >= max_keys || prefix_bytes > 16 || offset + 1 + prefix_bytes > length) {
            return -1;
        }
        memset(&keys[*count], 0, sizeof(keys[*count]));
        memcpy(keys[*count].bytes, data + offset, (size_t)(1 + prefix_bytes));
        (*count)++;
        offset += 1 + prefix_bytes;
    }

    return 0;
}

/*
 * Count the distinct prefixes that a ribout block puts on the wire.
 */
static int count_distinct_wire_prefixes(const char *prefix_cmd, const char *next_hop_cmd, int *total_out) {
    enum { MAX_KEYS = 4096 };
    static wire_prefix_key_t keys[MAX_KEYS];
    bgp_ribout_config_t block;
    bgp_msg_t          *msg;
    int                 count = 0;
    int                 distinct = 0;

    bgp_ribout_init(&block, "prefix-step");
    if (bgp_ribout_parse_prefix(&block, prefix_cmd) != 0 ||
        bgp_ribout_parse_next_hop(&block, next_hop_cmd) != 0 ||
        bgp_ribout_parse_aspath(&block, "as-path 65001") != 0 ||
        bgp_ribout_generate_map(&block) != 0 ||
        bgp_ribout_generate_messages(&block) != 0) {
        bgp_ribout_destroy(&block);
        return -1;
    }

    for (msg = block.messages; msg; msg = msg->next) {
        const uint8_t     *nlri = NULL;
        uint16_t           nlri_len = 0;
        test_wire_update_t view;
        if (!test_wire_update_view(msg->data, msg->length, &view)) {
            bgp_ribout_destroy(&block);
            return -1;
        }

        if (extract_mp_reach_ipv6(msg->data, msg->length, NULL, NULL, &nlri, &nlri_len)) {
            // MP_REACH NLRI for IPv6.
        } else {
            nlri = view.nlri;
            nlri_len = (uint16_t)view.nlri_len;
        }
        if (collect_wire_prefixes(nlri, nlri_len, keys, MAX_KEYS, &count) < 0) {
            bgp_ribout_destroy(&block);
            return -1;
        }
    }

    qsort(keys, (size_t)count, sizeof(keys[0]), wire_prefix_key_cmp);
    for (int i = 0; i < count; i++) {
        if (i == 0 || memcmp(&keys[i], &keys[i - 1], sizeof(keys[i])) != 0) {
            distinct++;
        }
    }

    *total_out = count;
    bgp_ribout_destroy(&block);
    return distinct;
}

/*
 * 1 if the message's extended communities are exactly the library encoding of (color, co_type).
 */
static int ext_comms_are_color(const uint8_t *msg, size_t size, uint32_t color, uint8_t co_type) {
    bgp_path_attr_t *expected = bgp_attr_create_ext_comm_color(color, co_type);
    const uint8_t   *value = NULL;
    uint16_t         length = 0;
    int same = expected && find_attr(msg, size, BGP_ATTR_EXT_COMM, &value, &length) && length == 8 &&
               memcmp(value, expected->value, 8) == 0;

    bgp_path_attr_free(expected);
    return same;
}

static void test_ribout_color_community_to_encoded_updates(void) {
    bgp_ribout_config_t block;
    bgp_msg_t          *msg;
    int                 groups_ok = 1;
    int                 total_nlri = 0;

    TEST("Unicast color -> one Color community per path, in step with the next hop");

    // The FlowSpec SR-TE scale-test shape: route i goes to policy (endpoint .201 + i mod 3, color 1 + i mod 3).
    bgp_ribout_init(&block, "e2e-wire-color4");
    ASSERT(bgp_ribout_parse_prefix(&block, "prefix 10.1.0.0/24 x 6") == 0, "Failed to parse prefix");
    ASSERT(bgp_ribout_parse_next_hop(&block, "next-hop 10.255.0.201 x 3") == 0, "Failed to parse next-hop");
    ASSERT(bgp_ribout_parse_color(&block, "color 1 x 3 co 01") == 0, "Failed to parse color");
    ASSERT(bgp_ribout_resolve_family(&block) == BGP_RIBOUT_FAMILY_IPV4_UNICAST, "Block must stay IPv4 unicast");
    ASSERT(bgp_ribout_generate_map(&block) == 0, "Map generation failed");
    ASSERT(block.ribout->entry_count == 3, "Three (next hop, color) pairs make three attribute groups");
    ASSERT(bgp_ribout_generate_messages(&block) == 0, "Message generation failed");
    ASSERT(block.message_count == 3, "Expected one UPDATE per attribute group");

    for (msg = block.messages; msg; msg = msg->next) {
        const uint8_t     *next_hop = NULL;
        uint16_t           next_hop_len = 0;
        test_wire_update_t view;
        uint32_t           k;

        if (!test_wire_update_view(msg->data, msg->length, &view) ||
            !find_attr(msg->data, msg->length, BGP_ATTR_NEXT_HOP, &next_hop, &next_hop_len) || next_hop_len != 4) {
            groups_ok = 0;
            break;
        }
        k = (uint32_t)next_hop[3] - 201u;
        groups_ok &= (k < 3) && ext_comms_are_color(msg->data, msg->length, 1 + k, BGP_COLOR_CO_NULL);
        // Both prefixes of the group are 10.1.<k or k+3>.0/24.
        for (size_t off = (size_t)(view.nlri - msg->data); off + 4 <= msg->length; off += 4) {
            groups_ok &= (msg->data[off] == 24) && ((uint32_t)msg->data[off + 3] % 3 == k);
            total_nlri++;
        }
    }
    ASSERT(groups_ok && total_nlri == 6, "Each UPDATE pairs next hop .201+k with Color 1+k (CO 01)");
    bgp_ribout_destroy(&block);

    // IPv6 unicast (MP_REACH): per-value CO types, and the RT comes before the Color.
    bgp_ribout_init(&block, "e2e-wire-color6");
    ASSERT(bgp_ribout_parse_prefix(&block, "prefix 2001:db8:1::/64 x 2") == 0, "Failed to parse IPv6 prefix");
    ASSERT(bgp_ribout_parse_next_hop(&block, "next-hop 2001:db8:255::201") == 0, "Failed to parse IPv6 next-hop");
    ASSERT(bgp_ribout_parse_color(&block, "color 4 co 10 7") == 0, "Failed to parse color list");
    ASSERT(bgp_ribout_generate_map(&block) == 0 && bgp_ribout_generate_messages(&block) == 0,
           "IPv6 message generation failed");
    ASSERT(block.message_count == 2, "Two colors make two IPv6 UPDATEs");
    // The messages follow the attribute groups, not the configured color order.
    ASSERT((ext_comms_are_color(block.messages->data, block.messages->length, 4, BGP_COLOR_CO_ANY) &&
            ext_comms_are_color(block.messages->next->data, block.messages->next->length, 7, BGP_COLOR_CO_SPECIFIC)) ||
           (ext_comms_are_color(block.messages->data, block.messages->length, 7, BGP_COLOR_CO_SPECIFIC) &&
            ext_comms_are_color(block.messages->next->data, block.messages->next->length, 4, BGP_COLOR_CO_ANY)),
           "The two IPv6 UPDATEs carry Color 4 (CO 10) and Color 7 (CO 00)");
    bgp_ribout_destroy(&block);

    bgp_ribout_init(&block, "e2e-wire-color-rt");
    {
        static const uint8_t rt[8] = {0x00, 0x02, 0xfd, 0xe8, 0x00, 0x00, 0x00, 0x01};
        bgp_path_attr_t *color = bgp_attr_create_ext_comm_color(9, BGP_COLOR_CO_SPECIFIC);
        const uint8_t   *value = NULL;
        uint16_t         length = 0;

        // rt needs rd, so this is a colored VPNv4 route.
        ASSERT(bgp_ribout_parse_prefix(&block, "prefix 10.9.0.0/24") == 0 &&
               bgp_ribout_parse_rd(&block, "rd 65000:1") == 0 &&
               bgp_ribout_parse_label(&block, "label 16000") == 0 &&
               bgp_ribout_parse_next_hop(&block, "next-hop 192.0.2.1") == 0 &&
               bgp_ribout_parse_rt(&block, "rt 65000:1") == 0 &&
               bgp_ribout_parse_color(&block, "color 9") == 0, "Failed to configure RT + color block");
        ASSERT(bgp_ribout_resolve_family(&block) == BGP_RIBOUT_FAMILY_VPNV4, "rd + color must stay VPNv4");
        ASSERT(bgp_ribout_generate_map(&block) == 0 && bgp_ribout_generate_messages(&block) == 0,
               "RT + color message generation failed");
        ASSERT(find_attr(block.messages->data, block.messages->length, BGP_ATTR_EXT_COMM, &value, &length) && length == 16 &&
               memcmp(value, rt, 8) == 0 && color && memcmp(value + 8, color->value, 8) == 0,
               "VPNv4 attribute 16 holds the RT, then the Color community");
        bgp_path_attr_free(color);
    }
    bgp_ribout_destroy(&block);
    PASS();
}

static void test_color_sets_on_wire(void) {
    /*
     * The largest Color is deliberately in the middle. Preserve all values and CO bits so the DUT,
     * rather than the generator, exercises its own highest-Color selection.
     */
    static const uint8_t colors[] = {
        0x03, 0x0b, 0x40, 0, 0, 0, 0, 100,
        0x03, 0x0b, 0x80, 0, 0, 0, 1, 44,
        0x03, 0x0b, 0x00, 0, 0, 0, 0, 200,
    };
    static const uint8_t rt[] = {0, 2, 0xfd, 0xe8, 0, 0, 0, 1};
    for (unsigned variant = 0; variant < 8; variant++) {
        bgp_ribout_config_t block;
        int                 ipv6 = variant & 1, vpn = variant & 2, flowspec = variant & 4;
        char                name[48];
        snprintf(name, sizeof(name), "Color set on %s%s%s wire", ipv6 ? "IPv6" : "IPv4",
                 vpn ? " VPN" : "", flowspec ? " FlowSpec" : "");
        TEST(name);
        ASSERT(bgp_ribout_init(&block, "color-set") == 0 &&
               bgp_ribout_edit(&block, "prefix", ipv6 ? "2001:db8::/64 x 2" : "10.0.0.0/24 x 2", 0) == 0 &&
               bgp_ribout_edit(&block, "color", "set 100 co 01 300 co 10 200", 0) == 0,
               "Color set fixture parses");
        if (vpn) {
            ASSERT(bgp_ribout_edit(&block, "rd", "65000:1", 0) == 0 &&
                   bgp_ribout_edit(&block, "rt", "65000:1", 0) == 0, "VPN RD/RT fixture");
            if (!flowspec) ASSERT(bgp_ribout_edit(&block, "label", "16000", 0) == 0, "VPN label");
        }
        if (flowspec) {
            ASSERT(bgp_ribout_edit(&block, "action", "redirect-ip 192.0.2.9", 0) == 0, "FlowSpec redirect action");
        } else {
            ASSERT(bgp_ribout_edit(&block, "next-hop", ipv6 ? "2001:db8:ffff::1" : "192.0.2.1", 0) == 0,
                   "Next hop fixture");
        }
        ASSERT(bgp_ribout_generate(&block) == BGP_RIBOUT_GENERATED && block.message_count == 1,
               "Both routes with the same fixed Color set share one UPDATE");
        bgp_msg_t     *msg = block.messages;
        const uint8_t *ext = NULL;
        uint16_t       len = 0;
        ASSERT(find_attr(msg->data, msg->length, BGP_ATTR_EXT_COMM, &ext, &len) &&
               len == sizeof(colors) + (vpn ? 8 : 0) + (flowspec ? 8 : 0) &&
               (!vpn || !memcmp(ext, rt, sizeof(rt))) && !memcmp(ext + (vpn ? 8 : 0), colors, sizeof(colors)),
               "One attribute carries every Color, its CO flags, and any route target");
        test_wire_update_t view;
        ASSERT(test_wire_update_view(msg->data, msg->length, &view) && !view.withdrawn_len && !view.has_unreach,
               "Valid advertisement framing");
        const uint8_t *nlri = view.has_reach ? view.reach : view.nlri;
        size_t         left = view.has_reach ? view.reach_len : view.nlri_len;
        uint16_t       afi = view.has_reach ? view.reach_afi : 1;
        uint8_t        safi = view.has_reach ? view.reach_safi : 1;
        unsigned       routes = 0;
        while (left) {
            size_t n = test_wire_nlri_size(afi, safi, 0, nlri, left);
            ASSERT(n && n <= left, "Independent decoder can consume each NLRI");
            nlri += n;
            left -= n;
            routes++;
        }
        ASSERT(routes == 2 && block.snapshot->config->color_set, "No Color multiplication or dropped route");
        bgp_ribout_destroy(&block);
        PASS();
    }

    TEST("Color sets enforce the aggregate per-path extended-community budget");
    bgp_ribout_config_t block;
    char                value[64];
    bgp_ribout_init(&block, "color-budget");
    ASSERT(bgp_ribout_edit(&block, "prefix", "10.0.0.0/24", 0) == 0 &&
           bgp_ribout_edit(&block, "action", "mark 1", 0) == 0, "FlowSpec budget fixture");
    snprintf(value, sizeof(value), "set 1 x %u", MAX_EXT_COMMS_PER_ROUTE - 1);
    ASSERT(bgp_ribout_edit(&block, "color", value, 0) == 0 &&
           bgp_ribout_generate(&block) == BGP_RIBOUT_GENERATED, "Colors plus one action exactly fill the budget");
    uint64_t id = block.snapshot->id;
    snprintf(value, sizeof(value), "set 1 x %u", MAX_EXT_COMMS_PER_ROUTE);
    ASSERT(bgp_ribout_edit(&block, "color", value, 0) == 0 &&
           bgp_ribout_generate(&block) == BGP_RIBOUT_MAP_FAILED && block.dirty && block.snapshot->id == id,
           "An action exceeding the shared budget fails without replacing the previous snapshot");
    bgp_ribout_destroy(&block);
    PASS();
}

static void test_ribout_prefix_sequence_is_distinct_on_wire(void) {
    int total = 0;

    TEST("prefix x N steps by whole prefix blocks (distinct NLRIs on the wire)");

    /*
     * The old generator added 1 to the address, so 1500 /24 routes collapsed
     * into 6 distinct NLRIs and 1500 /64 routes into one.
     */
    ASSERT(count_distinct_wire_prefixes("prefix 10.0.0.0/24 x 1500", "next-hop 192.0.2.1", &total) == 1500 &&
           total == 1500,
           "IPv4 /24 x 1500 must give 1500 distinct NLRIs");
    ASSERT(count_distinct_wire_prefixes("prefix 2001:db8:100::/64 x 1500", "next-hop 2001:db8::1", &total) == 1500 &&
           total == 1500,
           "IPv6 /64 x 1500 must give 1500 distinct NLRIs");
    ASSERT(count_distinct_wire_prefixes("prefix 10.0.0.0/20 x 300", "next-hop 192.0.2.1", &total) == 300,
           "IPv4 /20 x 300 must give 300 distinct NLRIs");
    ASSERT(count_distinct_wire_prefixes("prefix 2001:db8::/45 x 100", "next-hop 2001:db8::1", &total) == 100,
           "IPv6 /45 x 100 (step not on an octet boundary) must give 100 distinct NLRIs");
    PASS();
}

static void test_ribout_prefix_sequence_bounds(void) {
    bgp_ribout_config_t block;
    char                text[64];

    TEST("prefix x N rejects counts past the address space and bad lengths");

    bgp_ribout_init(&block, "prefix-bounds");
    ASSERT(bgp_ribout_parse_prefix(&block, "prefix 255.255.255.0/24 x 1") == 0, "last /24 alone is valid");
    ASSERT(bgp_ribout_parse_prefix(&block, "prefix 255.255.254.0/24 x 2") == 0, "last two /24s are valid");
    ASSERT(bgp_ribout_parse_prefix(&block, "prefix 255.255.255.0/24 x 2") < 0, "wrap past 255.255.255.0/24");
    ASSERT(bgp_ribout_parse_prefix(&block, "prefix 0.0.0.0/0 x 2") < 0, "two /0 prefixes do not exist");
    ASSERT(bgp_ribout_parse_prefix(&block, "prefix ffff:ffff:ffff:ffff::/64 x 2") < 0, "IPv6 wrap");
    ASSERT(bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/24 x 0") < 0, "count 0");
    ASSERT(bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/abc") < 0, "non-numeric length");
    ASSERT(bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/24junk") < 0, "trailing text in length");
    ASSERT(bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/ x 2") < 0, "empty length");
    ASSERT(bgp_ribout_parse_prefix(&block, "prefix 10.0.0.0/24 x 2 extra") < 0, "trailing text after count");

    ASSERT(bgp_ribout_parse_prefix(&block, "prefix 10.255.255.0/24 x 2") == 0, "carry into the next octet");
    bgp_prefix_to_string(&block.prefix_spec, 1, text, sizeof(text));
    ASSERT(strcmp(text, "11.0.0.0/24") == 0, "second /24 after 10.255.255.0 is 11.0.0.0");
    ASSERT(bgp_ribout_parse_prefix(&block, "prefix 2001:db8::/45 x 3") == 0, "IPv6 /45");
    bgp_prefix_to_string(&block.prefix_spec, 2, text, sizeof(text));
    ASSERT(strcmp(text, "2001:db8:10::/45") == 0, "third /45 is 2001:db8:10::/45");
    bgp_ribout_destroy(&block);
    PASS();
}

static int template_stream_matches(const bgp_msg_t *messages, const template_vector_t *v, unsigned count,
                                    int add_path, int withdrawn) {
    unsigned seen = 0;
    for (const bgp_msg_t *msg = messages; msg; msg = msg->next) {
        test_wire_update_t view;
        if (msg->length > 4096 || !test_wire_update_view(msg->data, msg->length, &view)) return 0;
        const uint8_t *nlri = withdrawn ? view.unreach : view.reach;
        size_t         len = withdrawn ? view.unreach_len : view.reach_len;
        if (!nlri || !len || (withdrawn ? view.unreach_afi : view.reach_afi) != v->afi ||
            (withdrawn ? view.unreach_safi : view.reach_safi) != v->safi ||
            (withdrawn && (view.has_reach || view.attr_count != 1))) return 0;
        size_t off = 0;
        while (off < len) {
            uint8_t  expected[256];
            unsigned instance = seen / (add_path ? 2 : 1);
            size_t   needed = template_expected(v, instance, add_path, seen % 2 ? 9 : 7, expected);
            if (instance >= count || needed > len - off || memcmp(nlri + off, expected, needed)) return 0;
            off += needed;
            seen++;
        }
    }
    return seen == count * (add_path ? 2U : 1U);
}

static void test_typed_template_pipeline(const template_vector_t *v, int add_path) {
    char name[128], line[1200];
    snprintf(name, sizeof(name), "%s config -> split UPDATEs -> frozen withdrawal (ADD-PATH %s)",
                v->name, add_path ? "on" : "off");
    TEST(name);
    bgp_ribout_config_t block;
    bgp_ribout_init(&block, "templates");
    unsigned count = v->count == 1 ? 1 : 1000;
    snprintf(line, sizeof(line), "%s x %u", v->command + 5, count);
    int ok = bgp_ribout_edit(&block, "nlri", line, 0) == 0 &&
             bgp_ribout_edit(&block, "next-hop", "192.0.2.9", 0) == 0 &&
             (!add_path || bgp_ribout_edit(&block, "path-id", "7 9", 0) == 0) &&
             bgp_ribout_generate(&block) == BGP_RIBOUT_GENERATED;
    bgp_ribout_snapshot_t *frozen = ok ? bgp_ribout_snapshot_ref(block.snapshot) : NULL;
    if (ok) {
        ok = frozen->profile.afi == v->afi && frozen->profile.safi == v->safi &&
             frozen->profile.add_path == add_path &&
             template_stream_matches(frozen->adv->msgs, v, count, add_path, 0) &&
             (count == 1 || frozen->adv->count > 1);
    }
    // Later edits must not change an already published generation.
    if (ok) ok = bgp_ribout_edit(&block, "nlri", "rtc default", 0) == 0;
    bgp_msg_stream_t *withdrawal = frozen ? bgp_ribout_snapshot_withdrawal(frozen) : NULL;
    ok = ok && withdrawal && template_stream_matches(withdrawal->msgs, v, count, add_path, 1);
    bgp_msg_stream_unref(withdrawal);
    bgp_ribout_snapshot_unref(frozen);
    bgp_ribout_destroy(&block);
    ASSERT(ok, "independent vectors, exact cardinality and IDs, splitting, and immutable withdrawals");
    PASS();
}

static void test_template_rejections_and_attrs(void) {
    TEST("Typed templates reject invalid input atomically and emit family attributes");
    bgp_ribout_config_t b;
    bgp_ribout_gen_t    gen;
    bgp_ribout_init(&b, "templates");
    int                   ok = bgp_ribout_edit(&b, "nlri", "rtc origin-as 65000 target 65000:1", 0) == 0;
    bgp_ribout_template_t original = b.nlri_template;
    const char *bad[] = {
        "rtc", "rtc origin-as 1", "rtc default x 2", "rtc origin-as 1 target 65000:4294967295 x 2",
        "vpls rd 65000:1 ve-id 65535 offset 0 size 8 label-base 1000 x 2",
        "vpls rd 65000:1 ve-id 1 offset 0 size 8 label-base 1048575",
        "evpn type3 rd 65000:1 ethernet-tag 1 router invalid",
        "evpn type4 rd 65000:1 esi 0 router 192.0.2.1 step ethernet-tag x 2",
        "mvpn4 type3 rd 65000:1 source 2001:db8::1 group 239.1.1.1 router 192.0.2.1",
        "mvpn4 type5 rd 65000:1 source 192.0.2.1 group 239.255.255.255 step group x 2",
        "bgp-ls node protocol 3 identifier 18446744073709551615 local-as 1 local-router 1.2.3.4 x 2",
        "bgp-ls node protocol 1 identifier 1 local-as 1 local-router 1.2.3.4",
        "rtc default trailing", "rtc default x 0", "rtc default x -1", NULL
    };
    for (const char **p = bad; *p; p++) {
        ok = bgp_ribout_edit(&b, "nlri", *p, 0) < 0 &&
             memcmp(&original, &b.nlri_template, sizeof(original)) == 0 && ok;
    }
    ok = bgp_ribout_edit(&b, "prefix", "10.0.0.0/24", 0) == 0 &&
         bgp_ribout_generator_init(&gen, &b) < 0 && ok;
    bgp_ribout_edit(&b, "prefix", "", 1);
    ok = bgp_ribout_edit(&b, "pmsi", "flags 0 type 6 label 1000 id c0000201", 0) == 0 &&
         bgp_ribout_generator_init(&gen, &b) < 0 && ok;
    ok = bgp_ribout_edit(&b, "nlri", "evpn type3 rd 65000:1 ethernet-tag 1 router 192.0.2.1", 0) == 0 &&
         bgp_ribout_generate(&b) == BGP_RIBOUT_GENERATED && ok;
    const uint8_t pmsi[] = {0, 6, 0, 0x3e, 0x80, 192, 0, 2, 1};
    const uint8_t *value = NULL;
    uint16_t       len = 0;
    ok = b.messages && find_attr(b.messages->data, b.messages->length, 22, &value, &len) &&
         len == sizeof(pmsi) && memcmp(value, pmsi, len) == 0 && ok;
    bgp_ribout_edit(&b, "pmsi", "", 1);
    ok = bgp_ribout_edit(&b, "nlri", "vpls rd 65000:1 ve-id 1 offset 0 size 8 label-base 1000", 0) == 0 &&
         bgp_ribout_edit(&b, "rt", "65000:1", 0) == 0 &&
         bgp_ribout_edit(&b, "l2-info", "encap 19 flags 0 mtu 1500", 0) == 0 &&
         bgp_ribout_generate(&b) == BGP_RIBOUT_GENERATED && ok;
    const uint8_t communities[] = {0, 2, 0xfd, 0xe8, 0, 0, 0, 1, 0x80, 0x0a, 19, 0, 5, 0xdc, 0, 0};
    ok = b.messages && find_attr(b.messages->data, b.messages->length, 16, &value, &len) &&
         len == sizeof(communities) && memcmp(value, communities, len) == 0 && ok;
    bgp_ribout_edit(&b, "l2-info", "", 1);
    ok = bgp_ribout_edit(&b, "nlri", &TEMPLATE_LS_NODE_COMMAND[5], 0) == 0 &&
         bgp_ribout_edit(&b, "ls-attribute", "type 1026 value 6e6f6465", 0) == 0 &&
         bgp_ribout_generate(&b) == BGP_RIBOUT_GENERATED && ok;
    const uint8_t ls_attr[] = {4, 2, 0, 4, 'n', 'o', 'd', 'e'};
    ok = b.messages && find_attr(b.messages->data, b.messages->length, 29, &value, &len) &&
         len == sizeof(ls_attr) && memcmp(value, ls_attr, len) == 0 && ok;
    bgp_ribout_destroy(&b);
    ASSERT(ok, "invalid grammar, overflow, mixed families, and independent attribute bytes");
    PASS();
}

int main(void) {
    for (size_t i = 0; i < sizeof(template_vectors) / sizeof(*template_vectors); i++) {
        test_typed_template_pipeline(&template_vectors[i], 0);
        test_typed_template_pipeline(&template_vectors[i], 1);
    }
    test_template_rejections_and_attrs();
    printf("BGP RIB-OUT UPDATE End-to-End Tests\n");
    printf("===================================\n");

    test_ribout_config_to_encoded_updates();
    test_ribout_color_community_to_encoded_updates();
    test_color_sets_on_wire();
    test_ribout_prefix_sequence_is_distinct_on_wire();
    test_ribout_prefix_sequence_bounds();
    test_ribout_ipv6_config_to_encoded_updates();
    test_ribout_ipv4_rfc8950_config_to_encoded_updates();
    test_ribout_labeled_ipv4_config_to_encoded_updates();
    test_ribout_labeled_ipv4_rfc8950_config_to_encoded_updates();
    test_ribout_labeled_ipv6_config_to_encoded_updates();
    test_ribout_vpnv4_config_to_encoded_updates();
    test_ribout_vpnv4_ext_nh_config_to_encoded_updates();
    test_ribout_vpnv6_ipv4_transport_config_to_encoded_updates();
    test_ribout_vpnv6_ipv6_transport_config_to_encoded_updates();
    test_ribout_evpn_type5_config_to_encoded_updates();
    test_ribout_evpn_type5_ipv6_config_to_encoded_updates();
    test_ribout_evpn_type5_attr_ext_comms_to_encoded_updates();
    test_ribout_evpn_type2_config_to_encoded_updates();
    test_ribout_evpn_type2_attr_ext_comms_to_encoded_updates();
    test_ribout_evpn_type2_add_path_bytes_follow_generator_order();
    test_ribout_evpn_type2_message_splitting();
    test_ribout_evpn_labels_follow_encap();
    test_ribout_label_width_follows_encap();
    test_ribout_evpn_type2_ip_rotate_bindings_on_wire();
    test_ribout_vpn_rotations_on_wire();
    test_ribout_communities_on_wire();
    test_ribout_largest_community_sets_on_wire();
    test_ribout_communities_every_family();
    test_ribout_srpolicy_rotation_on_wire();
    test_ribout_flowspec_rotation_on_wire();
    test_ribout_evpn_tag_rotation_on_wire();
    test_ribout_path_id_rotation_on_wire();
    test_ribout_evpn_type2_dual_stack_on_wire();
    test_ribout_srpolicy_ipv4_config_to_encoded_updates();
    test_ribout_srpolicy_ipv6_config_to_encoded_updates();
    test_ribout_srpolicy_extended_tunnel_encoding();
    test_ribout_srpolicy_srv6_segment_b_flag();
    test_ribout_srpolicy_add_path_bytes_follow_generator_order();
    test_ribout_srpolicy_message_splitting();
    test_ribout_flowspec_ipv4_config_to_encoded_updates();
    test_ribout_flowspec_vpn_ipv6_redirect_next_hop_to_encoded_updates();
    test_ribout_flowspec_ipv6_redirect_ip_color_to_encoded_updates();
    test_ribout_flowspec_action_rotation_to_encoded_updates();
    test_ribout_flowspec_long_nlri_and_message_splitting();
    test_ribout_flowspec_generation_rejects_invalid_blocks();
    test_ribout_vpnv4_add_path_bytes_follow_generator_order();
    test_ribout_add_path_bytes_follow_generator_order();
    test_ribout_ipv4_rfc8950_add_path_bytes_follow_generator_order();
    test_ribout_ipv6_add_path_bytes_follow_generator_order();
    test_ribout_labeled_ipv4_add_path_bytes_follow_generator_order();
    test_ribout_labeled_ipv6_add_path_bytes_follow_generator_order();

    printf("\n===================================\n");
    printf("Tests run:    %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);
    printf("===================================\n");

    return (tests_failed == 0) ? 0 : 1;
}
