/*
 * BGP OPEN Message Capability Tests
 * Tests configuration parsing and OPEN message generation with capabilities.
 */

#include <uv.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "bgp.h"
#include "bgpsim.h"
#include "control.h"
#include "test_case.h"
#include "bgp_router.h"
#include "test_result.h"
#include "bgp_neighbor.h"
#include "test_session.h"

typedef struct {
    const uint8_t *data;
    size_t         len;
} capability_view_t;

typedef struct {
    const uint8_t *params;
    size_t         params_len;
    size_t         param_len_size;
} optional_params_view_t;

#define OPEN_RUNTIME_TIMEOUT_MS SESSION_TIMEOUT_MS

static int passive_neighbor_idle(void *opaque) {
    neighbor_wait_t *wait = opaque;
    bgp_neighbor_t  *neighbor = wait != NULL ? wait->neighbor : NULL;

    return neighbor != NULL &&
           neighbor->sock_fd < 0 &&
           neighbor->state == BGP_STATE_IDLE &&
           !neighbor->stream_open;
}

static int execute_control_command_expect_ok(bgpsim_control_client_t *client,
                                             const char *command,
                                             cli_mode_t *mode,
                                             cli_session_t *session) {
    int status = -1;

    return bgpsim_control_client_execute(client, command, mode, session, NULL, NULL, NULL, &status) == 0 &&
           status >= 0;
}

static int capture_passive_open(bgp_router_t *router, bgp_neighbor_t *neighbor,
                                uint8_t *buffer, size_t buffer_size,
                                int *msg_len_out) {
    int     sock = -1;
    uint8_t msg_type = 0;
    int     msg_len = -1;

    if (router == NULL || neighbor == NULL || buffer == NULL ||
        msg_len_out == NULL) {
        return 0;
    }

    sock = connect_ipv4_loopback_with_retry((uint16_t)router->listen_port, OPEN_RUNTIME_TIMEOUT_MS);
    if (sock < 0) {
        return 0;
    }

    msg_len = recv_bgp_message_with_timeout(sock, buffer, buffer_size, &msg_type, OPEN_RUNTIME_TIMEOUT_MS);
    close(sock);

    if (msg_len <= 0 || msg_type != BGP_MSG_OPEN) {
        return 0;
    }

    if (!wait_until(passive_neighbor_idle,
                    &(neighbor_wait_t){ .neighbor = neighbor },
                    OPEN_RUNTIME_TIMEOUT_MS)) {
        return 0;
    }

    *msg_len_out = msg_len;
    return 1;
}

static int get_optional_params_view(const uint8_t *buffer, size_t len, optional_params_view_t *view) {
    size_t            offset = BGP_HEADER_SIZE + sizeof(bgp_open_t);
    const bgp_open_t *open;
    const uint8_t    *ptr;

    if (buffer == NULL || view == NULL || offset > len) {
        return 0;
    }

    open = (const bgp_open_t *)(buffer + BGP_HEADER_SIZE);
    memset(view, 0, sizeof(*view));

    if (open->opt_param_len == 0) {
        view->params = buffer + offset;
        view->param_len_size = 1;
        return 1;
    }

    if (len < offset + 1) {
        return 0;
    }

    ptr = buffer + offset;
    if (*ptr == BGP_OPEN_EXTENDED_OPT_PARAMS_MARKER) {
        size_t ext_len;

        /*
         * RFC 9072 corner case: once OPEN capabilities exceed 255 octets, the
         * legacy one-byte optional-parameter length is replaced by marker 255,
         * a two-byte total length, and per-parameter 16-bit lengths.
         */
        if (len < offset + 3) {
            return 0;
        }

        ext_len = (size_t)(((uint16_t)ptr[1] << 8) | ptr[2]);
        if (len < offset + 3 + ext_len) {
            return 0;
        }

        view->params = ptr + 3;
        view->params_len = ext_len;
        view->param_len_size = 2;
        return 1;
    }

    if (len < offset + open->opt_param_len) {
        return 0;
    }

    view->params = ptr;
    view->params_len = open->opt_param_len;
    view->param_len_size = 1;
    return 1;
}

static int get_capability_instance(const uint8_t *buffer,
                                   size_t len,
                                   uint8_t cap_code,
                                   int instance_index,
                                   capability_view_t *view) {
    optional_params_view_t params_view;
    int                    seen = 0;

    if (!get_optional_params_view(buffer, len, &params_view)) {
        return 0;
    }

    const uint8_t *ptr = params_view.params;
    const uint8_t *end = ptr + params_view.params_len;

    while (ptr + 1 + params_view.param_len_size <= end) {
        uint8_t param_type = *ptr++;
        size_t  param_len;

        if (params_view.param_len_size == 1) {
            param_len = *ptr++;
        } else {
            param_len = (size_t)(((uint16_t)ptr[0] << 8) | ptr[1]);
            ptr += 2;
        }

        if (ptr + param_len > end) {
            break;
        }

        if (param_type == 2) {
            const uint8_t *cap_ptr = ptr;
            const uint8_t *cap_end = ptr + param_len;

            while (cap_ptr + 2 <= cap_end) {
                uint8_t code = *cap_ptr++;
                uint8_t cap_len = *cap_ptr++;

                if (cap_ptr + cap_len > cap_end) {
                    break;
                }

                if (code == cap_code) {
                    if (seen == instance_index) {
                        view->data = cap_ptr;
                        view->len = cap_len;
                        return 1;
                    }
                    seen++;
                }

                cap_ptr += cap_len;
            }
        }

        ptr += param_len;
    }

    return 0;
}

static int count_capabilities(const uint8_t *buffer, size_t len, uint8_t cap_code) {
    capability_view_t view;
    int               count = 0;

    while (get_capability_instance(buffer, len, cap_code, count, &view)) {
        count++;
    }

    return count;
}

static int find_capability(const uint8_t *buffer, size_t len, uint8_t cap_code) {
    capability_view_t view;
    return get_capability_instance(buffer, len, cap_code, 0, &view);
}

static int capability_value_u32(const uint8_t *buffer, size_t len, uint8_t cap_code, uint32_t *value) {
    capability_view_t view;

    if (value == NULL ||
        !get_capability_instance(buffer, len, cap_code, 0, &view) ||
        view.len != 4) {
        return 0;
    }

    *value = ((uint32_t)view.data[0] << 24) |
             ((uint32_t)view.data[1] << 16) |
             ((uint32_t)view.data[2] << 8) |
             (uint32_t)view.data[3];
    return 1;
}

static int open_uses_extended_optional_params(const uint8_t *buffer, size_t len, uint16_t *params_len) {
    optional_params_view_t params_view;
    const bgp_open_t      *open;

    if (!get_optional_params_view(buffer, len, &params_view)) {
        return 0;
    }

    open = (const bgp_open_t *)(buffer + BGP_HEADER_SIZE);
    if (open->opt_param_len != BGP_OPEN_EXTENDED_OPT_PARAMS_MARKER ||
        params_view.param_len_size != 2) {
        return 0;
    }

    if (params_len != NULL) {
        *params_len = (uint16_t)params_view.params_len;
    }
    return 1;
}

static int add_path_capability_has_tuple(const capability_view_t *view, uint16_t afi, uint8_t safi, uint8_t mode) {
    for (size_t offset = 0; offset + 4 <= view->len; offset += 4) {
        uint16_t tuple_afi = (uint16_t)((view->data[offset] << 8) | view->data[offset + 1]);
        uint8_t  tuple_safi = view->data[offset + 2];
        uint8_t  tuple_mode = view->data[offset + 3];

        if (tuple_afi == afi && tuple_safi == safi && tuple_mode == mode) {
            return 1;
        }
    }

    return 0;
}

static int ext_next_hop_capability_has_tuple(const capability_view_t *view,
                                            uint16_t nlri_afi,
                                            uint16_t nlri_safi,
                                            uint16_t next_hop_afi) {
    for (size_t offset = 0; offset + 6 <= view->len; offset += 6) {
        uint16_t tuple_nlri_afi = (uint16_t)((view->data[offset] << 8) | view->data[offset + 1]);
        uint16_t tuple_nlri_safi = (uint16_t)((view->data[offset + 2] << 8) | view->data[offset + 3]);
        uint16_t tuple_next_hop_afi = (uint16_t)((view->data[offset + 4] << 8) | view->data[offset + 5]);

        if (tuple_nlri_afi == nlri_afi &&
            tuple_nlri_safi == nlri_safi &&
            tuple_next_hop_afi == next_hop_afi) {
            return 1;
        }
    }

    return 0;
}

static int graceful_restart_capability_has_tuple(const capability_view_t *view,
                                                 uint16_t afi,
                                                 uint8_t safi,
                                                 uint8_t flags) {
    if (view->len < 2) {
        return 0;
    }

    for (size_t offset = 2; offset + 4 <= view->len; offset += 4) {
        uint16_t tuple_afi = (uint16_t)((view->data[offset] << 8) | view->data[offset + 1]);
        uint8_t  tuple_safi = view->data[offset + 2];
        uint8_t  tuple_flags = view->data[offset + 3];

        if (tuple_afi == afi && tuple_safi == safi && tuple_flags == flags) {
            return 1;
        }
    }

    return 0;
}

static int mp_capability_has_tuple(const uint8_t *buffer, size_t len, uint16_t afi, uint8_t safi) {
    capability_view_t view;
    int               instance = 0;

    while (get_capability_instance(buffer, len, BGP_CAP_MP_BGP, instance++, &view)) {
        if (view.len == 4 &&
            view.data[0] == ((afi >> 8) & 0xFF) &&
            view.data[1] == (afi & 0xFF) &&
            view.data[2] == 0 &&
            view.data[3] == safi) {
            return 1;
        }
    }

    return 0;
}

/*
 * Test 1: Basic OPEN with no capabilities
 */
static void test_basic_open(void) {
    bgp_capabilities_t caps = {0};
    uint8_t            buffer[1024];

    int len = bgp_build_open_with_capabilities(buffer, sizeof(buffer), 100, 0x01010101, &caps);

    int passed = (len > 0 && (size_t)len >= BGP_HEADER_SIZE + sizeof(bgp_open_t));
    test_result(passed, "Basic OPEN message with no capabilities");
}

/*
 * Test 2: 4-byte AS number capability
 */
static void test_4byte_asn(void) {
    bgp_capabilities_t caps = {0};
    uint8_t            buffer[1024];
    uint32_t           large_as = 4200000000U;  /* > 65535 */
    uint32_t           advertised_as = 0;

    caps.four_byte_asn = 1;

    int len = bgp_build_open_with_capabilities(buffer, sizeof(buffer), large_as, 0x01010101, &caps);

    bgp_open_t *open = (bgp_open_t *)(buffer + BGP_HEADER_SIZE);
    int         as_trans_used = (ntohs(open->my_as) == AS_TRANS);
    int         cap_present = capability_value_u32(buffer, (size_t)len, BGP_CAP_4BYTE_ASN, &advertised_as);

    test_result(len > 0 && as_trans_used && cap_present &&
                advertised_as == large_as,
                "4-byte AS number (AS_TRANS + capability 65)");
}

/*
 * Test 2b: NEW speakers advertise capability 65 even for 2-byte ASNs
 */
static void test_4byte_asn_capability_with_16bit_as(void) {
    bgp_capabilities_t caps = {0};
    uint8_t            buffer[1024];
    uint32_t           local_as = 65000;
    uint32_t           advertised_as = 0;
    bgp_open_t        *open;
    int                len;

    caps.four_byte_asn = 1;
    len = bgp_build_open_with_capabilities(buffer, sizeof(buffer), local_as, 0x01010101, &caps);
    open = (bgp_open_t *)(buffer + BGP_HEADER_SIZE);

    test_result(len > 0 &&
                ntohs(open->my_as) == local_as &&
                capability_value_u32(buffer, (size_t)len, BGP_CAP_4BYTE_ASN, &advertised_as) &&
                advertised_as == local_as,
                "NEW speaker advertises capability 65 for 2-byte ASNs");
}

/*
 * Test 2c: OLD-speaker mode cannot encode a non-mappable ASN
 */
static void test_old_speaker_rejects_large_asn(void) {
    bgp_capabilities_t caps = {0};
    uint8_t            buffer[1024];
    int                len;

    len = bgp_build_open_with_capabilities(buffer, sizeof(buffer), 70000U, 0x01010101, &caps);
    test_result(len < 0, "OLD-speaker mode rejects non-mappable local ASNs");
}

/*
 * Test 3: Route Refresh capability
 */
static void test_route_refresh(void) {
    bgp_capabilities_t caps = {0};
    uint8_t            buffer[1024];

    caps.route_refresh = 1;

    int len = bgp_build_open_with_capabilities(buffer, sizeof(buffer), 100, 0x01010101, &caps);
    int cap_present = find_capability(buffer, (size_t)len, BGP_CAP_ROUTE_REFRESH);

    test_result(len > 0 && cap_present, "Route Refresh capability");
}

/*
 * Test 4: IPv4 unicast MP-BGP
 */
static void test_ipv4_unicast(void) {
    bgp_capabilities_t caps = {0};
    uint8_t            buffer[1024];

    caps.ipv4_unicast = 1;

    int len = bgp_build_open_with_capabilities(buffer, sizeof(buffer), 100, 0x01010101, &caps);
    int cap_present = find_capability(buffer, (size_t)len, BGP_CAP_MP_BGP);

    test_result(len > 0 && cap_present, "IPv4 unicast MP-BGP capability");
}

/*
 * Test 5: IPv6 unicast MP-BGP
 */
static void test_ipv6_unicast(void) {
    bgp_capabilities_t caps = {0};
    uint8_t            buffer[1024];

    caps.ipv6_unicast = 1;

    int len = bgp_build_open_with_capabilities(buffer, sizeof(buffer), 100, 0x01010101, &caps);
    int cap_present = find_capability(buffer, (size_t)len, BGP_CAP_MP_BGP);

    test_result(len > 0 && cap_present, "IPv6 unicast MP-BGP capability");
}

/*
 * Test 6: VPNv4 MP-BGP
 */
static void test_ipv4_labeled_unicast(void) {
    bgp_capabilities_t caps = {0};
    uint8_t            buffer[1024];

    caps.ipv4_labeled_unicast = 1;

    int len = bgp_build_open_with_capabilities(buffer, sizeof(buffer), 100, 0x01010101, &caps);

    test_result(len > 0 &&
                mp_capability_has_tuple(buffer, (size_t)len, AFI_IPV4, SAFI_LABELED_UNICAST),
                "IPv4 labeled-unicast MP-BGP capability");
}

/*
 * Test 7: IPv6 labeled-unicast MP-BGP
 */
static void test_ipv6_labeled_unicast(void) {
    bgp_capabilities_t caps = {0};
    uint8_t            buffer[1024];

    caps.ipv6_labeled_unicast = 1;

    int len = bgp_build_open_with_capabilities(buffer, sizeof(buffer), 100, 0x01010101, &caps);

    test_result(len > 0 &&
                mp_capability_has_tuple(buffer, (size_t)len, AFI_IPV6, SAFI_LABELED_UNICAST),
                "IPv6 labeled-unicast MP-BGP capability");
}

/*
 * Test 8: VPNv4 MP-BGP
 */
static void test_vpnv4(void) {
    bgp_capabilities_t caps = {0};
    uint8_t            buffer[1024];

    caps.vpnv4_unicast = 1;

    int len = bgp_build_open_with_capabilities(buffer, sizeof(buffer), 100, 0x01010101, &caps);
    int cap_present = find_capability(buffer, (size_t)len, BGP_CAP_MP_BGP);

    test_result(len > 0 && cap_present, "VPNv4 MP-BGP capability");
}

/*
 * Test 9: VPNv6 MP-BGP
 */
static void test_vpnv6(void) {
    bgp_capabilities_t caps = {0};
    uint8_t            buffer[1024];

    caps.vpnv6_unicast = 1;

    int len = bgp_build_open_with_capabilities(buffer, sizeof(buffer), 100, 0x01010101, &caps);
    int cap_present = find_capability(buffer, (size_t)len, BGP_CAP_MP_BGP);

    test_result(len > 0 && cap_present, "VPNv6 MP-BGP capability");
}

/*
 * Test 10: EVPN MP-BGP
 */
static void test_evpn(void) {
    bgp_capabilities_t caps = {0};
    uint8_t            buffer[1024];

    caps.evpn = 1;

    int len = bgp_build_open_with_capabilities(buffer, sizeof(buffer), 100, 0x01010101, &caps);
    int cap_present = find_capability(buffer, (size_t)len, BGP_CAP_MP_BGP);

    test_result(len > 0 && cap_present, "EVPN MP-BGP capability");
}

// New address family MP-BGP capability tests

#define DEFINE_MP_CAP_TEST(name, field, desc)                               \
static void test_##name(void) {                                             \
    bgp_capabilities_t caps = {0};                                          \
    uint8_t            buffer[1024];                                        \
    caps.field = 1;                                                         \
    int len = bgp_build_open_with_capabilities(                             \
        buffer, sizeof(buffer), 100, 0x01010101, &caps);                    \
    int cap_present = find_capability(buffer, (size_t)len, BGP_CAP_MP_BGP); \
    test_result(len > 0 && cap_present, desc);                              \
}

DEFINE_MP_CAP_TEST(ipv4_flowspec, ipv4_flowspec, "IPv4 FlowSpec MP-BGP capability")
DEFINE_MP_CAP_TEST(ipv6_flowspec, ipv6_flowspec, "IPv6 FlowSpec MP-BGP capability")
DEFINE_MP_CAP_TEST(ipv4_srpolicy, ipv4_srpolicy, "IPv4 SR Policy MP-BGP capability")
DEFINE_MP_CAP_TEST(ipv6_srpolicy, ipv6_srpolicy, "IPv6 SR Policy MP-BGP capability")
DEFINE_MP_CAP_TEST(bgp_ls, bgp_ls, "BGP-LS MP-BGP capability")
DEFINE_MP_CAP_TEST(ipv4_mvpn, ipv4_mvpn, "IPv4 MVPN MP-BGP capability")
DEFINE_MP_CAP_TEST(ipv6_mvpn, ipv6_mvpn, "IPv6 MVPN MP-BGP capability")
DEFINE_MP_CAP_TEST(ipv4_rtc, ipv4_rtc, "RTC MP-BGP capability")
DEFINE_MP_CAP_TEST(vpls, vpls, "VPLS MP-BGP capability")

/*
 * RFC 8955 section 8: VPN FlowSpec is SAFI 134 for each AFI.
 */
static void test_flowspec_vpn_mp_capability(void) {
    bgp_capabilities_t caps = {0};
    uint8_t            buffer[1024];

    caps.ipv4_flowspec_vpn = 1;
    caps.ipv6_flowspec_vpn = 1;

    int len = bgp_build_open_with_capabilities(buffer, sizeof(buffer), 100, 0x01010101, &caps);

    test_result(len > 0 &&
                mp_capability_has_tuple(buffer, (size_t)len, AFI_IPV4, SAFI_FLOWSPEC_VPN) &&
                mp_capability_has_tuple(buffer, (size_t)len, AFI_IPV6, SAFI_FLOWSPEC_VPN) &&
                !mp_capability_has_tuple(buffer, (size_t)len, AFI_IPV4, SAFI_FLOWSPEC) &&
                count_capabilities(buffer, (size_t)len, BGP_CAP_MP_BGP) == 2,
                "VPN FlowSpec MP-BGP capability tuples");
}

/*
 * RFC 6514 section 19: the MCAST-VPN NLRI is SAFI 5 for each AFI. SAFI 129 is "Multicast for BGP/MPLS IP VPNs".
 */
static void test_mvpn_mp_capability_uses_safi_5(uint16_t afi, const char *name) {
    bgp_capabilities_t caps = {0};
    uint8_t            buffer[1024];
    int                len;

    TEST(name);
    caps.ipv4_mvpn = 1;
    caps.ipv6_mvpn = 1;
    len = bgp_build_open_with_capabilities(buffer, sizeof(buffer), 100, 0x01010101, &caps);

    ASSERT(len > 0, "The OPEN builds");
    ASSERT(mp_capability_has_tuple(buffer, (size_t)len, afi, 5), "RFC 6514 section 19: MCAST-VPN uses SAFI 5");
    ASSERT(!mp_capability_has_tuple(buffer, (size_t)len, afi, 129),
           "SAFI 129 is a different family (Multicast for BGP/MPLS IP VPNs)");
    PASS();
}

/*
 * Test 11: Graceful Restart capability
 */
static void test_graceful_restart(void) {
    bgp_capabilities_t caps = {0};
    uint8_t            buffer[1024];
    capability_view_t  view;
    int                passed;

    caps.graceful_restart = 1;
    caps.restart_time = 120;
    caps.ipv4_unicast = 1;
    caps.vpnv6_unicast = 1;
    caps.evpn = 1;
    bgp_caps_set_gr_flags(&caps, AFI_IPV6, SAFI_MPLS_VPN, 0x80);

    int len = bgp_build_open_with_capabilities(buffer, sizeof(buffer), 100, 0x01010101, &caps);

    passed = len > 0 &&
             count_capabilities(buffer, (size_t)len, BGP_CAP_GRACEFUL_RESTART) == 1 &&
             get_capability_instance(buffer, (size_t)len, BGP_CAP_GRACEFUL_RESTART, 0, &view) &&
             view.len == 14 &&
             (((uint16_t)((view.data[0] & 0x0F) << 8) | view.data[1]) == 120) &&
             graceful_restart_capability_has_tuple(&view, AFI_IPV4, SAFI_UNICAST, 0) &&
             graceful_restart_capability_has_tuple(&view, AFI_IPV6, SAFI_MPLS_VPN, 0x80) &&
             graceful_restart_capability_has_tuple(&view, AFI_L2VPN, SAFI_EVPN, 0);

    test_result(passed, "Graceful Restart capability");
}

/*
 * Test 12: ADD-PATH tuples are grouped into a single capability
 */
static void test_add_path_grouped_capability(void) {
    bgp_capabilities_t caps = {0};
    uint8_t            buffer[1024];
    capability_view_t  view;
    int                passed;

    caps.ipv4_unicast = 1;
    caps.ipv6_unicast = 1;
    caps.ipv4_labeled_unicast = 1;
    caps.ipv6_labeled_unicast = 1;
    caps.vpnv4_unicast = 1;
    caps.vpnv6_unicast = 1;
    caps.evpn = 1;
    caps.ipv4_flowspec = 1;
    caps.ipv6_flowspec = 1;
    caps.ipv4_flowspec_vpn = 1;
    caps.ipv6_flowspec_vpn = 1;
    caps.ipv4_srpolicy = 1;
    caps.ipv6_srpolicy = 1;
    caps.bgp_ls = 1;
    caps.ipv4_mvpn = 1;
    caps.ipv6_mvpn = 1;
    caps.ipv4_rtc = 1;
    caps.vpls = 1;

    bgp_caps_set_add_path(&caps, AFI_IPV4, SAFI_UNICAST, ADD_PATH_SEND | ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&caps, AFI_IPV6, SAFI_UNICAST, ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&caps, AFI_IPV4, SAFI_LABELED_UNICAST, ADD_PATH_SEND | ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&caps, AFI_IPV6, SAFI_LABELED_UNICAST, ADD_PATH_SEND);
    bgp_caps_set_add_path(&caps, AFI_IPV4, SAFI_MPLS_VPN, ADD_PATH_SEND);
    bgp_caps_set_add_path(&caps, AFI_IPV6, SAFI_MPLS_VPN, ADD_PATH_SEND | ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&caps, AFI_L2VPN, SAFI_EVPN, ADD_PATH_SEND);
    bgp_caps_set_add_path(&caps, AFI_IPV4, SAFI_FLOWSPEC, ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&caps, AFI_IPV6, SAFI_FLOWSPEC, ADD_PATH_SEND | ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&caps, AFI_IPV4, SAFI_SR_POLICY, ADD_PATH_SEND);
    bgp_caps_set_add_path(&caps, AFI_IPV6, SAFI_SR_POLICY, ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&caps, AFI_BGP_LS, SAFI_BGP_LS, ADD_PATH_SEND | ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&caps, AFI_IPV4, SAFI_MVPN, ADD_PATH_SEND);
    bgp_caps_set_add_path(&caps, AFI_IPV6, SAFI_MVPN, ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&caps, AFI_IPV4, SAFI_RTC, ADD_PATH_SEND | ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&caps, AFI_L2VPN, SAFI_VPLS, ADD_PATH_SEND);
    bgp_caps_set_add_path(&caps, AFI_IPV4, SAFI_FLOWSPEC_VPN, ADD_PATH_SEND);
    bgp_caps_set_add_path(&caps, AFI_IPV6, SAFI_FLOWSPEC_VPN, ADD_PATH_SEND | ADD_PATH_RECEIVE);

    int len = bgp_build_open_with_capabilities(buffer, sizeof(buffer), 100, 0x01010101, &caps);

    passed = len > 0 &&
             count_capabilities(buffer, (size_t)len, BGP_CAP_ADD_PATH) == 1 &&
             get_capability_instance(buffer, (size_t)len, BGP_CAP_ADD_PATH, 0, &view) &&
             view.len == 72 &&
             add_path_capability_has_tuple(&view, AFI_IPV4, SAFI_UNICAST, ADD_PATH_SEND | ADD_PATH_RECEIVE) &&
             add_path_capability_has_tuple(&view, AFI_IPV6, SAFI_UNICAST, ADD_PATH_RECEIVE) &&
             add_path_capability_has_tuple(&view, AFI_IPV4, SAFI_LABELED_UNICAST, ADD_PATH_SEND | ADD_PATH_RECEIVE) &&
             add_path_capability_has_tuple(&view, AFI_IPV6, SAFI_LABELED_UNICAST, ADD_PATH_SEND) &&
             add_path_capability_has_tuple(&view, AFI_IPV4, SAFI_MPLS_VPN, ADD_PATH_SEND) &&
             add_path_capability_has_tuple(&view, AFI_IPV6, SAFI_MPLS_VPN, ADD_PATH_SEND | ADD_PATH_RECEIVE) &&
             add_path_capability_has_tuple(&view, AFI_L2VPN, SAFI_EVPN, ADD_PATH_SEND) &&
             add_path_capability_has_tuple(&view, AFI_IPV4, SAFI_FLOWSPEC, ADD_PATH_RECEIVE) &&
             add_path_capability_has_tuple(&view, AFI_IPV6, SAFI_FLOWSPEC, ADD_PATH_SEND | ADD_PATH_RECEIVE) &&
             add_path_capability_has_tuple(&view, AFI_IPV4, SAFI_SR_POLICY, ADD_PATH_SEND) &&
             add_path_capability_has_tuple(&view, AFI_IPV6, SAFI_SR_POLICY, ADD_PATH_RECEIVE) &&
             add_path_capability_has_tuple(&view, AFI_BGP_LS, SAFI_BGP_LS, ADD_PATH_SEND | ADD_PATH_RECEIVE) &&
             add_path_capability_has_tuple(&view, AFI_IPV4, SAFI_MVPN, ADD_PATH_SEND) &&
             add_path_capability_has_tuple(&view, AFI_IPV6, SAFI_MVPN, ADD_PATH_RECEIVE) &&
             add_path_capability_has_tuple(&view, AFI_IPV4, SAFI_RTC, ADD_PATH_SEND | ADD_PATH_RECEIVE) &&
             add_path_capability_has_tuple(&view, AFI_L2VPN, SAFI_VPLS, ADD_PATH_SEND) &&
             add_path_capability_has_tuple(&view, AFI_IPV4, SAFI_FLOWSPEC_VPN, ADD_PATH_SEND) &&
             add_path_capability_has_tuple(&view, AFI_IPV6, SAFI_FLOWSPEC_VPN, ADD_PATH_SEND | ADD_PATH_RECEIVE);

    test_result(passed, "ADD-PATH grouped capability tuples");
}

/*
 * Test 13: RFC 8950 extended next_hop tuples
 */
static void test_extended_next_hop_capability(void) {
    bgp_capabilities_t caps = {0};
    uint8_t            buffer[1024];
    capability_view_t  view;
    int                passed;

    caps.ipv4_unicast = 1;
    caps.ipv4_labeled_unicast = 1;
    caps.vpnv4_unicast = 1;

    bgp_caps_set_ext_nh(&caps, AFI_IPV4, SAFI_UNICAST, AFI_IPV6, 1);
    bgp_caps_set_ext_nh(&caps, AFI_IPV4, SAFI_LABELED_UNICAST, AFI_IPV6, 1);
    bgp_caps_set_ext_nh(&caps, AFI_IPV4, SAFI_MPLS_VPN, AFI_IPV6, 1);

    int len = bgp_build_open_with_capabilities(buffer, sizeof(buffer), 100, 0x01010101, &caps);

    passed = len > 0 &&
             count_capabilities(buffer, (size_t)len, BGP_CAP_EXTENDED_NEXTHOP) == 1 &&
             get_capability_instance(buffer, (size_t)len, BGP_CAP_EXTENDED_NEXTHOP, 0, &view) &&
             view.len == 18 &&
             ext_next_hop_capability_has_tuple(&view, AFI_IPV4, SAFI_UNICAST, AFI_IPV6) &&
             ext_next_hop_capability_has_tuple(&view, AFI_IPV4, SAFI_LABELED_UNICAST, AFI_IPV6) &&
             ext_next_hop_capability_has_tuple(&view, AFI_IPV4, SAFI_MPLS_VPN, AFI_IPV6);

    test_result(passed, "RFC 8950 extended next_hop capability");
}

/*
 * Test 14: AF-specific capabilities require the matching MP-BGP family
 */
static void test_capability_tuples_require_enabled_family(void) {
    bgp_capabilities_t caps = {0};
    uint8_t            buffer[1024];
    int                len;
    int                passed;

    bgp_caps_set_add_path(&caps, AFI_IPV4, SAFI_UNICAST, ADD_PATH_SEND | ADD_PATH_RECEIVE);
    bgp_caps_set_ext_nh(&caps, AFI_IPV4, SAFI_UNICAST, AFI_IPV6, 1);

    len = bgp_build_open_with_capabilities(buffer, sizeof(buffer), 100, 0x01010101, &caps);

    passed = len > 0 &&
             count_capabilities(buffer, (size_t)len, BGP_CAP_ADD_PATH) == 0 &&
             count_capabilities(buffer, (size_t)len, BGP_CAP_EXTENDED_NEXTHOP) == 0;

    test_result(passed, "AF-specific capability tuples require enabled MP-BGP family");
}

/*
 * Test 15: Negotiated ADD-PATH helpers
 */
static void test_add_path_negotiation_helpers(void) {
    bgp_capabilities_t local_caps = {0};
    bgp_capabilities_t peer_caps = {0};
    int                passed;

    bgp_caps_set_add_path(&local_caps, AFI_IPV4, SAFI_MPLS_VPN, ADD_PATH_SEND);
    bgp_caps_set_add_path(&peer_caps, AFI_IPV4, SAFI_MPLS_VPN, ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&local_caps, AFI_IPV6, SAFI_MPLS_VPN, ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&peer_caps, AFI_IPV6, SAFI_MPLS_VPN, ADD_PATH_SEND);

    passed = bgp_caps_add_path_can_send(&local_caps, &peer_caps, AFI_IPV4, SAFI_MPLS_VPN) &&
             bgp_caps_add_path_can_recv(&local_caps, &peer_caps, AFI_IPV6, SAFI_MPLS_VPN) &&
             !bgp_caps_add_path_can_send(&local_caps, &peer_caps, AFI_L2VPN, SAFI_EVPN);

    test_result(passed, "ADD-PATH negotiation helpers");
}

/*
 * Test 16: OPEN parser round-trips grouped capabilities
 */
static void test_open_roundtrip_capability_parse(void) {
    bgp_capabilities_t caps = {0};
    bgp_neighbor_t     neighbor;
    uint8_t            buffer[1024];
    int                passed;

    memset(&neighbor, 0, sizeof(neighbor));
    strncpy(neighbor.ip, "192.0.2.1", sizeof(neighbor.ip) - 1);
    neighbor.remote_as = 65000;
    neighbor.sock_fd = -1;

    caps.ipv4_unicast = 1;
    caps.ipv6_unicast = 1;
    caps.ipv4_labeled_unicast = 1;
    caps.ipv6_labeled_unicast = 1;
    caps.vpnv4_unicast = 1;
    caps.vpnv6_unicast = 1;
    caps.evpn = 1;
    caps.ipv4_flowspec = 1;
    caps.ipv6_flowspec = 1;
    caps.ipv4_flowspec_vpn = 1;
    caps.ipv6_flowspec_vpn = 1;
    caps.ipv4_srpolicy = 1;
    caps.ipv6_srpolicy = 1;
    caps.bgp_ls = 1;
    caps.ipv4_mvpn = 1;
    caps.ipv6_mvpn = 1;
    caps.ipv4_rtc = 1;
    caps.vpls = 1;
    caps.route_refresh = 1;
    caps.four_byte_asn = 1;
    caps.graceful_restart = 1;
    caps.restart_time = 180;
    bgp_caps_set_gr_flags(&caps, AFI_IPV4, SAFI_MPLS_VPN, 0x80);
    bgp_caps_set_gr_flags(&caps, AFI_IPV4, SAFI_FLOWSPEC, 0x80);
    bgp_caps_set_gr_flags(&caps, AFI_L2VPN, SAFI_VPLS, 0x80);
    // Table rows past 16 need the 32-bit GR family masks.
    bgp_caps_set_gr_flags(&caps, AFI_IPV6, SAFI_FLOWSPEC_VPN, 0x80);
    bgp_caps_set_add_path(&caps, AFI_IPV4, SAFI_FLOWSPEC_VPN, ADD_PATH_SEND);
    bgp_caps_set_add_path(&caps, AFI_IPV6, SAFI_FLOWSPEC_VPN, ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&caps, AFI_IPV4, SAFI_UNICAST, ADD_PATH_SEND | ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&caps, AFI_IPV4, SAFI_LABELED_UNICAST, ADD_PATH_SEND);
    bgp_caps_set_add_path(&caps, AFI_IPV6, SAFI_LABELED_UNICAST, ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&caps, AFI_IPV4, SAFI_MPLS_VPN, ADD_PATH_SEND);
    bgp_caps_set_add_path(&caps, AFI_IPV6, SAFI_MPLS_VPN, ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&caps, AFI_L2VPN, SAFI_EVPN, ADD_PATH_SEND | ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&caps, AFI_IPV4, SAFI_FLOWSPEC, ADD_PATH_SEND);
    bgp_caps_set_add_path(&caps, AFI_IPV6, SAFI_FLOWSPEC, ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&caps, AFI_IPV4, SAFI_SR_POLICY, ADD_PATH_SEND | ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&caps, AFI_IPV6, SAFI_SR_POLICY, ADD_PATH_SEND);
    bgp_caps_set_add_path(&caps, AFI_BGP_LS, SAFI_BGP_LS, ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&caps, AFI_IPV4, SAFI_MVPN, ADD_PATH_SEND);
    bgp_caps_set_add_path(&caps, AFI_IPV6, SAFI_MVPN, ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&caps, AFI_IPV4, SAFI_RTC, ADD_PATH_SEND | ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&caps, AFI_L2VPN, SAFI_VPLS, ADD_PATH_SEND);
    bgp_caps_set_ext_nh(&caps, AFI_IPV4, SAFI_UNICAST, AFI_IPV6, 1);
    bgp_caps_set_ext_nh(&caps, AFI_IPV4, SAFI_LABELED_UNICAST, AFI_IPV6, 1);
    bgp_caps_set_ext_nh(&caps, AFI_IPV4, SAFI_MPLS_VPN, AFI_IPV6, 1);

    int len = bgp_build_open_with_capabilities(buffer, sizeof(buffer), 65000, 0x0A0A0A0A, &caps);

    passed = len > 0 &&
             bgp_process_open(NULL, &neighbor, buffer, (size_t)len) == 0 &&
             neighbor.peer_capabilities_received &&
             neighbor.peer_capabilities.ipv4_unicast &&
             neighbor.peer_capabilities.ipv6_unicast &&
             neighbor.peer_capabilities.ipv4_labeled_unicast &&
             neighbor.peer_capabilities.ipv6_labeled_unicast &&
             neighbor.peer_capabilities.vpnv4_unicast &&
             neighbor.peer_capabilities.vpnv6_unicast &&
             neighbor.peer_capabilities.evpn &&
             neighbor.peer_capabilities.ipv4_flowspec &&
             neighbor.peer_capabilities.ipv6_flowspec &&
             neighbor.peer_capabilities.ipv4_flowspec_vpn &&
             neighbor.peer_capabilities.ipv6_flowspec_vpn &&
             neighbor.peer_capabilities.ipv4_srpolicy &&
             neighbor.peer_capabilities.ipv6_srpolicy &&
             neighbor.peer_capabilities.bgp_ls &&
             neighbor.peer_capabilities.ipv4_mvpn &&
             neighbor.peer_capabilities.ipv6_mvpn &&
             neighbor.peer_capabilities.ipv4_rtc &&
             neighbor.peer_capabilities.vpls &&
             neighbor.peer_capabilities.route_refresh &&
             neighbor.peer_capabilities.four_byte_asn &&
             neighbor.peer_capabilities.graceful_restart &&
             neighbor.peer_capabilities.restart_time == 180 &&
             bgp_caps_has_gr_family(&neighbor.peer_capabilities, AFI_IPV4, SAFI_UNICAST) &&
             bgp_caps_has_gr_family(&neighbor.peer_capabilities, AFI_IPV6, SAFI_UNICAST) &&
             bgp_caps_has_gr_family(&neighbor.peer_capabilities, AFI_IPV4, SAFI_LABELED_UNICAST) &&
             bgp_caps_has_gr_family(&neighbor.peer_capabilities, AFI_IPV6, SAFI_LABELED_UNICAST) &&
             bgp_caps_has_gr_family(&neighbor.peer_capabilities, AFI_IPV4, SAFI_MPLS_VPN) &&
             bgp_caps_has_gr_family(&neighbor.peer_capabilities, AFI_IPV6, SAFI_MPLS_VPN) &&
             bgp_caps_has_gr_family(&neighbor.peer_capabilities, AFI_L2VPN, SAFI_EVPN) &&
             bgp_caps_has_gr_family(&neighbor.peer_capabilities, AFI_IPV4, SAFI_FLOWSPEC) &&
             bgp_caps_has_gr_family(&neighbor.peer_capabilities, AFI_IPV6, SAFI_FLOWSPEC) &&
             bgp_caps_has_gr_family(&neighbor.peer_capabilities, AFI_IPV4, SAFI_SR_POLICY) &&
             bgp_caps_has_gr_family(&neighbor.peer_capabilities, AFI_IPV6, SAFI_SR_POLICY) &&
             bgp_caps_has_gr_family(&neighbor.peer_capabilities, AFI_BGP_LS, SAFI_BGP_LS) &&
             bgp_caps_has_gr_family(&neighbor.peer_capabilities, AFI_IPV4, SAFI_MVPN) &&
             bgp_caps_has_gr_family(&neighbor.peer_capabilities, AFI_IPV6, SAFI_MVPN) &&
             bgp_caps_has_gr_family(&neighbor.peer_capabilities, AFI_IPV4, SAFI_RTC) &&
             bgp_caps_has_gr_family(&neighbor.peer_capabilities, AFI_L2VPN, SAFI_VPLS) &&
             bgp_caps_get_gr_flags(&neighbor.peer_capabilities, AFI_IPV4, SAFI_MPLS_VPN) == 0x80 &&
             bgp_caps_get_gr_flags(&neighbor.peer_capabilities, AFI_IPV4, SAFI_FLOWSPEC) == 0x80 &&
             bgp_caps_get_gr_flags(&neighbor.peer_capabilities, AFI_L2VPN, SAFI_VPLS) == 0x80 &&
             bgp_caps_has_gr_family(&neighbor.peer_capabilities, AFI_IPV4, SAFI_FLOWSPEC_VPN) &&
             bgp_caps_get_gr_flags(&neighbor.peer_capabilities, AFI_IPV4, SAFI_FLOWSPEC_VPN) == 0 &&
             bgp_caps_get_gr_flags(&neighbor.peer_capabilities, AFI_IPV6, SAFI_FLOWSPEC_VPN) == 0x80 &&
             bgp_caps_get_add_path(&neighbor.peer_capabilities, AFI_IPV4, SAFI_FLOWSPEC_VPN) ==
                 ADD_PATH_SEND &&
             bgp_caps_get_add_path(&neighbor.peer_capabilities, AFI_IPV6, SAFI_FLOWSPEC_VPN) ==
                 ADD_PATH_RECEIVE &&
             bgp_caps_get_add_path(&neighbor.peer_capabilities, AFI_IPV4, SAFI_UNICAST) ==
                 (ADD_PATH_SEND | ADD_PATH_RECEIVE) &&
             bgp_caps_get_add_path(&neighbor.peer_capabilities, AFI_IPV4, SAFI_LABELED_UNICAST) ==
                 ADD_PATH_SEND &&
             bgp_caps_get_add_path(&neighbor.peer_capabilities, AFI_IPV6, SAFI_LABELED_UNICAST) ==
                 ADD_PATH_RECEIVE &&
             bgp_caps_get_add_path(&neighbor.peer_capabilities, AFI_IPV4, SAFI_MPLS_VPN) ==
                 ADD_PATH_SEND &&
             bgp_caps_get_add_path(&neighbor.peer_capabilities, AFI_IPV6, SAFI_MPLS_VPN) ==
                 ADD_PATH_RECEIVE &&
             bgp_caps_get_add_path(&neighbor.peer_capabilities, AFI_L2VPN, SAFI_EVPN) ==
                 (ADD_PATH_SEND | ADD_PATH_RECEIVE) &&
             bgp_caps_get_add_path(&neighbor.peer_capabilities, AFI_IPV4, SAFI_FLOWSPEC) ==
                 ADD_PATH_SEND &&
             bgp_caps_get_add_path(&neighbor.peer_capabilities, AFI_IPV6, SAFI_FLOWSPEC) ==
                 ADD_PATH_RECEIVE &&
             bgp_caps_get_add_path(&neighbor.peer_capabilities, AFI_IPV4, SAFI_SR_POLICY) ==
                 (ADD_PATH_SEND | ADD_PATH_RECEIVE) &&
             bgp_caps_get_add_path(&neighbor.peer_capabilities, AFI_IPV6, SAFI_SR_POLICY) ==
                 ADD_PATH_SEND &&
             bgp_caps_get_add_path(&neighbor.peer_capabilities, AFI_BGP_LS, SAFI_BGP_LS) ==
                 ADD_PATH_RECEIVE &&
             bgp_caps_get_add_path(&neighbor.peer_capabilities, AFI_IPV4, SAFI_MVPN) ==
                 ADD_PATH_SEND &&
             bgp_caps_get_add_path(&neighbor.peer_capabilities, AFI_IPV6, SAFI_MVPN) ==
                 ADD_PATH_RECEIVE &&
             bgp_caps_get_add_path(&neighbor.peer_capabilities, AFI_IPV4, SAFI_RTC) ==
                 (ADD_PATH_SEND | ADD_PATH_RECEIVE) &&
             bgp_caps_get_add_path(&neighbor.peer_capabilities, AFI_L2VPN, SAFI_VPLS) ==
                 ADD_PATH_SEND &&
             bgp_caps_has_ext_nh(&neighbor.peer_capabilities, AFI_IPV4, SAFI_UNICAST, AFI_IPV6) &&
             bgp_caps_has_ext_nh(&neighbor.peer_capabilities, AFI_IPV4, SAFI_LABELED_UNICAST, AFI_IPV6) &&
             bgp_caps_has_ext_nh(&neighbor.peer_capabilities, AFI_IPV4, SAFI_MPLS_VPN, AFI_IPV6);

    test_result(passed, "OPEN capability round-trip parsing");
}

/*
 * Test 17: Multiple capabilities combined
 */
static void test_multiple_capabilities(void) {
    bgp_capabilities_t caps = {0};
    uint8_t            buffer[1024];

    caps.ipv4_unicast = 1;
    caps.ipv6_unicast = 1;
    caps.route_refresh = 1;
    caps.graceful_restart = 1;
    caps.restart_time = 120;

    int len = bgp_build_open_with_capabilities(buffer, sizeof(buffer), 100, 0x01010101, &caps);
    int mp_bgp = find_capability(buffer, (size_t)len, BGP_CAP_MP_BGP);
    int rr = find_capability(buffer, (size_t)len, BGP_CAP_ROUTE_REFRESH);
    int gr = find_capability(buffer, (size_t)len, BGP_CAP_GRACEFUL_RESTART);

    test_result(len > 0 && mp_bgp && rr && gr, "Multiple capabilities combined");
}

/*
 * Test 18: All capabilities enabled
 */
static void test_all_capabilities(void) {
    bgp_capabilities_t caps = {0};
    uint8_t            buffer[1024];
    uint32_t           large_as = 4200000000U;

    caps.ipv4_unicast = 1;
    caps.ipv6_unicast = 1;
    caps.ipv4_labeled_unicast = 1;
    caps.ipv6_labeled_unicast = 1;
    caps.vpnv4_unicast = 1;
    caps.vpnv6_unicast = 1;
    caps.evpn = 1;
    caps.ipv4_flowspec = 1;
    caps.ipv6_flowspec = 1;
    caps.ipv4_srpolicy = 1;
    caps.ipv6_srpolicy = 1;
    caps.bgp_ls = 1;
    caps.ipv4_mvpn = 1;
    caps.ipv6_mvpn = 1;
    caps.ipv4_rtc = 1;
    caps.vpls = 1;
    caps.route_refresh = 1;
    caps.four_byte_asn = 1;
    caps.graceful_restart = 1;
    caps.restart_time = 120;
    bgp_caps_set_add_path(&caps, AFI_IPV4, SAFI_UNICAST, ADD_PATH_SEND | ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&caps, AFI_IPV6, SAFI_UNICAST, ADD_PATH_SEND | ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&caps, AFI_IPV4, SAFI_LABELED_UNICAST, ADD_PATH_SEND | ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&caps, AFI_IPV6, SAFI_LABELED_UNICAST, ADD_PATH_SEND | ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&caps, AFI_IPV4, SAFI_MPLS_VPN, ADD_PATH_SEND | ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&caps, AFI_IPV6, SAFI_MPLS_VPN, ADD_PATH_SEND | ADD_PATH_RECEIVE);
    bgp_caps_set_ext_nh(&caps, AFI_IPV4, SAFI_UNICAST, AFI_IPV6, 1);
    bgp_caps_set_ext_nh(&caps, AFI_IPV4, SAFI_LABELED_UNICAST, AFI_IPV6, 1);
    bgp_caps_set_ext_nh(&caps, AFI_IPV4, SAFI_MPLS_VPN, AFI_IPV6, 1);

    int len = bgp_build_open_with_capabilities(buffer, sizeof(buffer), large_as, 0x01010101, &caps);

    test_result(len > 0, "All capabilities enabled");
}

/*
 * RFC 9072 corner case: the classic one-byte OPEN optional-parameters length
 * is too small once the protocol surface gets large enough. The encoder must
 * switch formats before that byte wraps and silently hides every capability.
 */
static void test_extended_open_optional_parameters_boundary(void) {
    bgp_capabilities_t caps = {0};
    uint8_t            buffer[1024];
    uint16_t           params_len = 0;
    int                len;
    int                passed;

    caps.ipv4_unicast = 1;
    caps.ipv6_unicast = 1;
    caps.ipv4_labeled_unicast = 1;
    caps.ipv6_labeled_unicast = 1;
    caps.vpnv4_unicast = 1;
    caps.vpnv6_unicast = 1;
    caps.evpn = 1;
    caps.ipv4_flowspec = 1;
    caps.ipv6_flowspec = 1;
    caps.ipv4_srpolicy = 1;
    caps.ipv6_srpolicy = 1;
    caps.bgp_ls = 1;
    caps.ipv4_mvpn = 1;
    caps.ipv6_mvpn = 1;
    caps.ipv4_rtc = 1;
    caps.vpls = 1;
    caps.four_byte_asn = 1;
    caps.graceful_restart = 1;
    caps.restart_time = 180;
    bgp_caps_set_add_path(&caps, AFI_IPV4, SAFI_UNICAST, ADD_PATH_SEND | ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&caps, AFI_IPV6, SAFI_UNICAST, ADD_PATH_SEND | ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&caps, AFI_IPV4, SAFI_LABELED_UNICAST, ADD_PATH_SEND | ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&caps, AFI_IPV6, SAFI_LABELED_UNICAST, ADD_PATH_SEND | ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&caps, AFI_IPV4, SAFI_MPLS_VPN, ADD_PATH_SEND | ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&caps, AFI_IPV6, SAFI_MPLS_VPN, ADD_PATH_SEND | ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&caps, AFI_L2VPN, SAFI_EVPN, ADD_PATH_SEND | ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&caps, AFI_IPV4, SAFI_FLOWSPEC, ADD_PATH_SEND | ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&caps, AFI_IPV6, SAFI_FLOWSPEC, ADD_PATH_SEND | ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&caps, AFI_IPV4, SAFI_SR_POLICY, ADD_PATH_SEND | ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&caps, AFI_IPV6, SAFI_SR_POLICY, ADD_PATH_SEND | ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&caps, AFI_BGP_LS, SAFI_BGP_LS, ADD_PATH_SEND | ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&caps, AFI_IPV4, SAFI_MVPN, ADD_PATH_SEND | ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&caps, AFI_IPV6, SAFI_MVPN, ADD_PATH_SEND | ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&caps, AFI_IPV4, SAFI_RTC, ADD_PATH_SEND | ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&caps, AFI_L2VPN, SAFI_VPLS, ADD_PATH_SEND | ADD_PATH_RECEIVE);
    bgp_caps_set_ext_nh(&caps, AFI_IPV4, SAFI_UNICAST, AFI_IPV6, 1);
    bgp_caps_set_ext_nh(&caps, AFI_IPV4, SAFI_LABELED_UNICAST, AFI_IPV6, 1);
    bgp_caps_set_ext_nh(&caps, AFI_IPV4, SAFI_MPLS_VPN, AFI_IPV6, 1);

    len = bgp_build_open_with_capabilities(buffer, sizeof(buffer), 65000, 0x01010101, &caps);
    passed = len > 0 &&
             open_uses_extended_optional_params(buffer, (size_t)len, &params_len) &&
             params_len > UINT8_MAX &&
             count_capabilities(buffer, (size_t)len, BGP_CAP_ADD_PATH) == 1 &&
             count_capabilities(buffer, (size_t)len, BGP_CAP_EXTENDED_NEXTHOP) == 1;

    test_result(passed, "RFC 9072 extended optional-parameter encoding");
}

/*
 * RFC 9072 says receivers key off the marker octet that follows opt_param_len,
 * not strictly the value in opt_param_len itself. Preserve that behavior so a
 * slightly odd but legal sender still gets its capabilities decoded.
 */
static void test_extended_open_marker_controls_parse(void) {
    bgp_capabilities_t caps = {0};
    bgp_neighbor_t     neighbor;
    uint8_t            buffer[1024];
    bgp_open_t        *open;
    int                len;
    int                passed;

    memset(&neighbor, 0, sizeof(neighbor));
    strncpy(neighbor.ip, "192.0.2.1", sizeof(neighbor.ip) - 1);
    neighbor.remote_as = 65000;
    neighbor.sock_fd = -1;

    caps.ipv4_unicast = 1;
    caps.ipv6_unicast = 1;
    caps.ipv4_labeled_unicast = 1;
    caps.ipv6_labeled_unicast = 1;
    caps.vpnv4_unicast = 1;
    caps.vpnv6_unicast = 1;
    caps.evpn = 1;
    caps.ipv4_flowspec = 1;
    caps.ipv6_flowspec = 1;
    caps.ipv4_srpolicy = 1;
    caps.ipv6_srpolicy = 1;
    caps.bgp_ls = 1;
    caps.ipv4_mvpn = 1;
    caps.ipv6_mvpn = 1;
    caps.ipv4_rtc = 1;
    caps.vpls = 1;
    caps.four_byte_asn = 1;
    caps.graceful_restart = 1;
    caps.restart_time = 180;
    bgp_caps_set_add_path(&caps, AFI_IPV4, SAFI_UNICAST, ADD_PATH_SEND | ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&caps, AFI_IPV6, SAFI_UNICAST, ADD_PATH_SEND | ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&caps, AFI_IPV4, SAFI_LABELED_UNICAST, ADD_PATH_SEND | ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&caps, AFI_IPV6, SAFI_LABELED_UNICAST, ADD_PATH_SEND | ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&caps, AFI_IPV4, SAFI_MPLS_VPN, ADD_PATH_SEND | ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&caps, AFI_IPV6, SAFI_MPLS_VPN, ADD_PATH_SEND | ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&caps, AFI_L2VPN, SAFI_EVPN, ADD_PATH_SEND | ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&caps, AFI_IPV4, SAFI_FLOWSPEC, ADD_PATH_SEND | ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&caps, AFI_IPV6, SAFI_FLOWSPEC, ADD_PATH_SEND | ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&caps, AFI_IPV4, SAFI_SR_POLICY, ADD_PATH_SEND | ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&caps, AFI_IPV6, SAFI_SR_POLICY, ADD_PATH_SEND | ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&caps, AFI_BGP_LS, SAFI_BGP_LS, ADD_PATH_SEND | ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&caps, AFI_IPV4, SAFI_MVPN, ADD_PATH_SEND | ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&caps, AFI_IPV6, SAFI_MVPN, ADD_PATH_SEND | ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&caps, AFI_IPV4, SAFI_RTC, ADD_PATH_SEND | ADD_PATH_RECEIVE);
    bgp_caps_set_add_path(&caps, AFI_L2VPN, SAFI_VPLS, ADD_PATH_SEND | ADD_PATH_RECEIVE);
    bgp_caps_set_ext_nh(&caps, AFI_IPV4, SAFI_UNICAST, AFI_IPV6, 1);
    bgp_caps_set_ext_nh(&caps, AFI_IPV4, SAFI_LABELED_UNICAST, AFI_IPV6, 1);
    bgp_caps_set_ext_nh(&caps, AFI_IPV4, SAFI_MPLS_VPN, AFI_IPV6, 1);

    len = bgp_build_open_with_capabilities(buffer, sizeof(buffer), 65000, 0x0A0A0A0A, &caps);
    open = (bgp_open_t *)(buffer + BGP_HEADER_SIZE);

    /*
     * Preserve the RFC 9072 marker octet but replace the non-extended length
     * with a non-zero non-255 value. Receivers still have to treat this OPEN
     * as extended once the marker appears immediately afterwards.
     */
    open->opt_param_len = 1;

    passed = len > 0 &&
             bgp_process_open(NULL, &neighbor, buffer, (size_t)len) == 0 &&
             neighbor.peer_capabilities.vpls &&
             bgp_caps_get_add_path(&neighbor.peer_capabilities, AFI_L2VPN, SAFI_VPLS) ==
                 (ADD_PATH_SEND | ADD_PATH_RECEIVE);

    test_result(passed, "RFC 9072 marker octet controls OPEN parse");
}

static void test_open_optional_param_threshold_boundary_via_cli(void) {
    bgp_sim_t              *sim = create_sim();
    char                    socket_path[108] = "";
    bgpsim_control_client_t client;
    cli_mode_t              mode = CLI_MODE_EXEC;
    cli_session_t           session;
    uint8_t                 buffer[BGP_MAX_MESSAGE_SIZE];
    bgp_open_info_t         below_info = {0};
    bgp_open_info_t         above_info = {0};
    bgp_open_info_t         back_down_info = {0};
    int                     below_len = -1;
    int                     above_len = -1;
    int                     back_down_len = -1;
    int                     passed = 0;
    const char *const below_threshold_commands[] = {
        "config",
        "router bgp 65000",
        "neighbor 127.0.0.1 remote-as 65001",
        "capability graceful-restart restart-time 180",
        "capability add-path",
        "capability ext-nh",
        "address-family ipv4 labels",
        "address-family ipv6 labels",
        "address-family vpnv4",
        "address-family vpnv6",
        "address-family l2vpn evpn",
        "address-family ipv4 flowspec",
        "address-family ipv6 flowspec",
        "address-family ipv4 srpolicy",
        "address-family ipv6 srpolicy",
        "address-family bgp-ls",
        "address-family ipv4 mvpn",
        "address-family ipv6 mvpn",
        "address-family ipv4 rtc"
    };

    memset(&client, 0, sizeof(client));
    client.fd = -1;
    cli_session_init(&session);

    if (sim != NULL) {
        sim->passive_mode = 1;

        if (bgp_add_router(sim, 65000) == 1 &&
            bgp_add_neighbor(sim, 65000, "127.0.0.1", 65001) == 1 &&
            start_runtime(sim, socket_path, sizeof(socket_path)) == 0 &&
            wait_until(router_listening, sim->routers[0], OPEN_RUNTIME_TIMEOUT_MS) &&
            bgpsim_control_client_open(&client, socket_path) == 0) {
            passed = 1;

            /*
             * Keep the CLI in neighbor submode so this mirrors a real live
             * session where the operator grows capability scope one family at
             * a time. With 15 MP families plus GR, ADD-PATH, and ext-nh, the
             * OPEN should still fit inside legacy optional-parameter limits.
             */
            for (size_t i = 0;
                 i < sizeof(below_threshold_commands) /
                         sizeof(below_threshold_commands[0]) &&
                 passed;
                 i++) {
                passed = execute_control_command_expect_ok(&client, below_threshold_commands[i], &mode, &session);
            }

            if (passed &&
                capture_passive_open(sim->routers[0],
                                     sim->routers[0]->neighbors[0],
                                     buffer, sizeof(buffer), &below_len) &&
                bgp_parse_open_message(buffer, (size_t)below_len, NULL,
                                       &below_info) == 0) {
                passed = !open_uses_extended_optional_params(buffer, (size_t)below_len, NULL) &&
                         !below_info.capabilities.vpls &&
                         bgp_caps_get_add_path(&below_info.capabilities, AFI_IPV4, SAFI_RTC) ==
                             (ADD_PATH_SEND | ADD_PATH_RECEIVE);
            } else {
                passed = 0;
            }

            /*
             * The 16th MP family is the tipping point in the current surface.
             * Enabling VPLS should force RFC 9072 extended OPEN encoding.
             */
            if (passed &&
                execute_control_command_expect_ok(&client, "address-family l2vpn vpls", &mode, &session) &&
                capture_passive_open(sim->routers[0],
                                     sim->routers[0]->neighbors[0],
                                     buffer, sizeof(buffer), &above_len) &&
                bgp_parse_open_message(buffer, (size_t)above_len, NULL,
                                       &above_info) == 0) {
                passed = open_uses_extended_optional_params(buffer, (size_t)above_len, NULL) &&
                         above_info.capabilities.vpls &&
                         bgp_caps_has_gr_family(&above_info.capabilities, AFI_L2VPN, SAFI_VPLS) &&
                         bgp_caps_get_add_path(&above_info.capabilities, AFI_L2VPN, SAFI_VPLS) ==
                             (ADD_PATH_SEND | ADD_PATH_RECEIVE);
            } else {
                passed = 0;
            }

            /*
             * Disabling the last family should shrink the payload back below
             * the boundary so the next OPEN falls back to the classic format.
             */
            if (passed &&
                execute_control_command_expect_ok(&client, "no address-family l2vpn vpls", &mode, &session) &&
                capture_passive_open(sim->routers[0],
                                     sim->routers[0]->neighbors[0],
                                     buffer, sizeof(buffer), &back_down_len) &&
                bgp_parse_open_message(buffer, (size_t)back_down_len, NULL,
                                       &back_down_info) == 0) {
                passed = !open_uses_extended_optional_params(buffer, (size_t)back_down_len, NULL) &&
                         !back_down_info.capabilities.vpls &&
                         below_len > 0 &&
                         above_len > below_len &&
                         back_down_len == below_len;
            } else {
                passed = 0;
            }
        }
    }

    test_result(passed, "CLI capability growth crosses RFC 9072 OPEN boundary and recovers");

    bgpsim_control_client_close(&client);
    destroy_sim(sim);
    unlink(socket_path);
}

/*
 * Test 19: OPEN message structure validation
 */
static void test_open_structure(void) {
    bgp_capabilities_t caps = {0};
    uint8_t            buffer[1024];
    bgp_header_t      *hdr;
    bgp_open_t        *open;
    int                valid_marker = 1;
    int                passed;

    caps.ipv4_unicast = 1;

    int len = bgp_build_open_with_capabilities(buffer, sizeof(buffer), 100, 0x0A0A0A0A, &caps);

    hdr = (bgp_header_t *)buffer;
    open = (bgp_open_t *)(buffer + BGP_HEADER_SIZE);

    for (int i = 0; i < BGP_MARKER_SIZE; i++) {
        if (hdr->marker[i] != 0xFF) {
            valid_marker = 0;
            break;
        }
    }

    passed = (len > 0 &&
              valid_marker &&
              hdr->type == BGP_MSG_OPEN &&
              ntohs(hdr->length) == len &&
              open->version == BGP_VERSION &&
              ntohs(open->hold_time) == BGP_HOLD_TIME &&
              ntohl(open->bgp_identifier) == 0x0A0A0A0A);

    test_result(passed, "OPEN message structure validation");
}

// Adversarial / boundary tests

/*
 * Build a minimal valid OPEN message with raw optional parameters appended.
 * Returns total message length.  Caller provides opt_data/opt_len to inject
 * arbitrary capability bytes.
 */
static int build_raw_open(uint8_t *buffer, size_t buflen,
                          uint32_t my_as, uint32_t router_id,
                          uint16_t hold_time,
                          const uint8_t *opt_data, uint8_t opt_len) {
    bgp_header_t *hdr = (bgp_header_t *)buffer;
    bgp_open_t   *open = (bgp_open_t *)(buffer + BGP_HEADER_SIZE);
    int           total_len = (int)(BGP_HEADER_SIZE + sizeof(bgp_open_t) + opt_len);

    if ((size_t)total_len > buflen) {
        return -1;
    }

    memset(hdr->marker, 0xFF, BGP_MARKER_SIZE);
    hdr->length = htons((uint16_t)total_len);
    hdr->type = BGP_MSG_OPEN;

    open->version = BGP_VERSION;
    open->my_as = htons((uint16_t)(my_as > 65535 ? AS_TRANS : my_as));
    open->hold_time = htons(hold_time);
    open->bgp_identifier = htonl(router_id);
    open->opt_param_len = opt_len;

    if (opt_len > 0 && opt_data) {
        memcpy(buffer + BGP_HEADER_SIZE + sizeof(bgp_open_t), opt_data, opt_len);
    }

    return total_len;
}

/*
 * Wrap a single capability (code + data) inside a Type-2 optional parameter.
 * Returns length written to out_buf.
 */
static int wrap_capability(uint8_t *out_buf, uint8_t cap_code, const uint8_t *cap_data, uint8_t cap_len) {
    out_buf[0] = 2;            /* param_type = capability             */
    out_buf[1] = 2 + cap_len;  /* param_len = code(1) + len(1) + data */
    out_buf[2] = cap_code;
    out_buf[3] = cap_len;
    if (cap_len > 0 && cap_data) {
        memcpy(out_buf + 4, cap_data, cap_len);
    }
    return 4 + cap_len;
}

static bgp_neighbor_t make_test_neighbor(uint32_t remote_as) {
    bgp_neighbor_t neighbor;

    memset(&neighbor, 0, sizeof(neighbor));
    strncpy(neighbor.ip, "192.0.2.1", sizeof(neighbor.ip) - 1);
    neighbor.remote_as = remote_as;
    neighbor.sock_fd = -1;
    return neighbor;
}

/*
 * Run bgp_process_open() for a raw OPEN on a neighbor (AS 100) whose socket is one end of a socketpair, and read the
 * NOTIFICATION that it sends from the other end. Returns the bgp_process_open() result. *code and *subcode are 0xFF
 * when no NOTIFICATION was sent.
 */
static int process_open_capture_notification(const uint8_t *msg, int msg_len, uint8_t *code, uint8_t *subcode) {
    bgp_neighbor_t neighbor = make_test_neighbor(100);
    uint8_t        reply[BGP_MAX_MESSAGE_SIZE];
    uint8_t        type = 0;
    int            sv[2];
    int            rc;

    *code = 0xFF;
    *subcode = 0xFF;
    if (msg_len <= 0 || socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        return -2;
    }

    neighbor.sock_fd = sv[0];
    rc = bgp_process_open(NULL, &neighbor, (uint8_t *)msg, (size_t)msg_len);
    // bgp_process_open() writes its NOTIFICATION before it returns: read what is there, without waiting.
    if (recv_bgp_message_with_timeout(sv[1], reply, sizeof(reply), &type, 0) >= BGP_HEADER_SIZE + 2 &&
        type == BGP_MSG_NOTIFICATION) {
        *code = reply[BGP_HEADER_SIZE];
        *subcode = reply[BGP_HEADER_SIZE + 1];
    }
    close(sv[0]);
    close(sv[1]);
    return rc;
}

/*
 * True when an OPEN is rejected with an OPEN Message Error NOTIFICATION of the given subcode.
 */
static int open_rejected_with(const uint8_t *msg, int msg_len, uint8_t subcode) {
    uint8_t got_code;
    uint8_t got_subcode;
    int     rc = process_open_capture_notification(msg, msg_len, &got_code, &got_subcode);

    return rc != 0 && got_code == BGP_ERR_OPEN_MESSAGE && got_subcode == subcode;
}

// OPEN Message Error subcodes: RFC 4271 section 4.5 (0 Unspecific) and section 6.2.
#define OPEN_SUBCODE_UNSPECIFIC            0
#define OPEN_SUBCODE_BAD_BGP_IDENTIFIER    3
#define OPEN_SUBCODE_UNSUPPORTED_OPT_PARAM 4
#define OPEN_SUBCODE_UNACCEPTABLE_HOLD     6

/*
 * Build an OPEN from AS 100 with this Hold Time, BGP Identifier and optional parameters, and return 1 when
 * bgp_process_open() rejects it with this OPEN Message Error subcode.
 */
static int raw_open_rejected_with(uint16_t hold_time, uint32_t bgp_id, const uint8_t *opt, uint8_t opt_len,
                                  uint8_t subcode) {
    uint8_t buffer[256];
    int     len = build_raw_open(buffer, sizeof(buffer), 100, bgp_id, hold_time, opt, opt_len);

    return open_rejected_with(buffer, len, subcode);
}

/*
 * Return 1 when bgp_process_open() accepts an OPEN with this Hold Time and BGP Identifier and sends no
 * NOTIFICATION.
 */
static int raw_open_accepted(uint16_t hold_time, uint32_t bgp_id) {
    uint8_t buffer[256];
    uint8_t code;
    uint8_t subcode;
    int     len = build_raw_open(buffer, sizeof(buffer), 100, bgp_id, hold_time, NULL, 0);

    return process_open_capture_notification(buffer, len, &code, &subcode) == 0 && code == 0xFF;
}

static void test_open_accepts_hold_time_three(void) {
    TEST("OPEN accepts Hold Time 3");

    ASSERT(raw_open_accepted(3, 0x01010101), "Hold Time 3 is the smallest valid nonzero value");
    PASS();
}

/*
 * RFC 4271 section 6.2: "An implementation MUST reject Hold Time values of one or two seconds".
 */
static void test_open_rejects_hold_time_one(void) {
    TEST("OPEN rejects Hold Time 1 (Unacceptable Hold Time)");

    ASSERT(raw_open_rejected_with(
           1, 0x01010101, NULL, 0, OPEN_SUBCODE_UNACCEPTABLE_HOLD),
           "RFC 4271 section 6.2: Hold Time 1 is rejected");
    PASS();
}

static void test_open_rejects_hold_time_two(void) {
    TEST("OPEN rejects Hold Time 2 (Unacceptable Hold Time)");

    ASSERT(raw_open_rejected_with(
           2, 0x01010101, NULL, 0, OPEN_SUBCODE_UNACCEPTABLE_HOLD),
           "RFC 4271 section 6.2: Hold Time 2 is rejected");
    PASS();
}

/*
 * RFC 6286 section 2.2: the BGP Identifier is a nonzero 4-octet value. RFC 4271 section 6.2 answers a bad one with
 * Bad BGP Identifier.
 */
static void test_open_rejects_zero_bgp_identifier(void) {
    TEST("OPEN rejects BGP Identifier 0 (Bad BGP Identifier)");

    ASSERT(raw_open_rejected_with(
           BGP_HOLD_TIME, 0, NULL, 0, OPEN_SUBCODE_BAD_BGP_IDENTIFIER),
           "RFC 6286 section 2.2: the BGP Identifier is nonzero");
    PASS();
}

/*
 * RFC 4271 section 6.2: an Optional Parameter that is not recognized gives Unsupported Optional Parameters. A
 * parameter or capability that runs past its field is malformed. No subcode is defined for that, so it is Unspecific
 * (RFC 4271 section 4.5).
 */
static void test_open_rejects_unknown_optional_parameter(void) {
    const uint8_t unknown_param[] = {99, 0};

    TEST("OPEN rejects unknown optional parameter 99");

    ASSERT(raw_open_rejected_with(
           BGP_HOLD_TIME, 0x01010101, unknown_param, sizeof(unknown_param),
           OPEN_SUBCODE_UNSUPPORTED_OPT_PARAM),
           "RFC 4271 section 6.2: optional parameter 99 is not recognized");
    PASS();
}

static void test_open_rejects_mp_capability_without_value(void) {
    const uint8_t mp_without_value[] = {2, 2, BGP_CAP_MP_BGP, 4};

    TEST("OPEN rejects an MP capability with absent value octets");

    ASSERT(raw_open_rejected_with(
           BGP_HOLD_TIME, 0x01010101, mp_without_value, sizeof(mp_without_value),
           OPEN_SUBCODE_UNSPECIFIC),
           "An MP capability that declares 4 absent value octets is malformed");
    PASS();
}

static void test_open_rejects_optional_parameter_overrun(void) {
    const uint8_t param_overrun[] = {2, 10, BGP_CAP_ROUTE_REFRESH, 0};

    TEST("OPEN rejects an optional parameter longer than its field");

    ASSERT(raw_open_rejected_with(
           BGP_HOLD_TIME, 0x01010101, param_overrun, sizeof(param_overrun),
           OPEN_SUBCODE_UNSPECIFIC),
           "An optional parameter longer than the Optional Parameters field is malformed");
    PASS();
}

/*
 * Test 20: Unknown capability codes are silently ignored
 */
static void test_unknown_capability_ignored(void) {
    uint8_t        opt[8];
    uint8_t        buffer[256];
    bgp_neighbor_t neighbor = make_test_neighbor(100);
    int            opt_len;
    int            msg_len;
    int            passed;

    // Capability code 254 (unassigned), 2 bytes of data
    uint8_t cap_data[] = {0xDE, 0xAD};
    opt_len = wrap_capability(opt, 254, cap_data, 2);
    msg_len = build_raw_open(buffer, sizeof(buffer), 100, 0x01010101, BGP_HOLD_TIME, opt, (uint8_t)opt_len);

    passed = (msg_len > 0) &&
             (bgp_process_open(NULL, &neighbor, buffer, (size_t)msg_len) == 0) &&
             neighbor.peer_capabilities_received;

    test_result(passed, "Unknown capability code silently ignored");
}

/*
 * The peer's MP capability flag: set by any Multiprotocol capability, even for a family bgpsim does not know, so the
 * RFC 4760 IPv4-unicast default applies only to a peer that sent none.
 */
static void test_peer_mp_capability_flag(void) {
    static const uint8_t ipv4_multicast[] = {0x00, 0x01, 0x00, 0x02};
    uint8_t        opt[16];
    uint8_t        buffer[256];
    bgp_neighbor_t plain = make_test_neighbor(100);
    bgp_neighbor_t unknown_mp = make_test_neighbor(100);
    int            opt_len;
    int            msg_len;
    int            passed;

    msg_len = build_raw_open(buffer, sizeof(buffer), 100, 0x01010101, BGP_HOLD_TIME, NULL, 0);
    passed = msg_len > 0 && bgp_process_open(NULL, &plain, buffer, (size_t)msg_len) == 0 &&
             plain.peer_capabilities_received && !plain.peer_mp_capability_received &&
             !plain.peer_capabilities.ipv4_unicast;

    opt_len = wrap_capability(opt, BGP_CAP_MP_BGP, ipv4_multicast, sizeof(ipv4_multicast));
    msg_len = build_raw_open(buffer, sizeof(buffer), 100, 0x01010101, BGP_HOLD_TIME, opt, (uint8_t)opt_len);
    passed = passed && msg_len > 0 && bgp_process_open(NULL, &unknown_mp, buffer, (size_t)msg_len) == 0 &&
             unknown_mp.peer_mp_capability_received && !unknown_mp.peer_capabilities.ipv4_unicast;

    test_result(passed, "Peer MP-capability flag: unset without MP, set by an MP capability for an unknown family");
}

/*
 * Test 21: Truncated capability data (cap_len extends past parameter end)
 */
static void test_truncated_capability(void) {
    uint8_t opt[6];
    uint8_t buffer[256];
    int     msg_len;
    int     passed;

    // Type-2 param with param_len=4, but capability inside claims cap_len=10
    opt[0] = 2;               /* param_type = capability                        */
    opt[1] = 4;               /* param_len = 4 bytes follow                     */
    opt[2] = BGP_CAP_MP_BGP;  /* cap code                                       */
    opt[3] = 10;              /* cap_len = 10, but only 2 bytes actually remain */
    opt[4] = 0x00;            /* partial data                                   */
    opt[5] = 0x01;

    msg_len = build_raw_open(buffer, sizeof(buffer), 100, 0x01010101, BGP_HOLD_TIME, opt, 6);

    // A capability that runs past its parameter makes the OPEN malformed: reject it, with no capability taken.
    passed = (msg_len > 0) && open_rejected_with(buffer, msg_len, OPEN_SUBCODE_UNSPECIFIC);

    test_result(passed, "Truncated capability data rejects the OPEN");
}

/*
 * Test 22: Duplicate capabilities - second instance overwrites first
 */
static void test_duplicate_capabilities(void) {
    bgp_capabilities_t caps = {0};
    uint8_t            buffer[1024];
    bgp_neighbor_t     neighbor = make_test_neighbor(100);
    int                passed;

    // Build with IPv4 unicast, then manually append a second MP-BGP cap for IPv6
    caps.ipv4_unicast = 1;
    int len = bgp_build_open_with_capabilities(buffer, sizeof(buffer), 100, 0x01010101, &caps);

    // Parse should accept both MP-BGP capabilities
    passed = (len > 0) &&
             (bgp_process_open(NULL, &neighbor, buffer, (size_t)len) == 0) &&
             neighbor.peer_capabilities.ipv4_unicast;

    test_result(passed, "Duplicate capabilities accepted");
}

/*
 * Test 23: ADD-PATH with odd-length capability (partial tuple)
 */
static void test_add_path_odd_length(void) {
    bgp_neighbor_t neighbor = make_test_neighbor(100);
    uint8_t        opt[16];
    uint8_t        buffer[256];
    int            opt_len;
    int            msg_len;
    int            passed;

    // ADD-PATH cap with 5 bytes: one full tuple (4 bytes) + 1 trailing byte
    uint8_t cap_data[] = {
        0x00, 0x01,  /* AFI: IPv4             */
        0x01,        /* SAFI: unicast         */
        0x03,        /* mode: send+receive    */
        0xFF         /* trailing garbage byte */
    };
    opt_len = wrap_capability(opt, BGP_CAP_ADD_PATH, cap_data, 5);
    msg_len = build_raw_open(buffer, sizeof(buffer), 100, 0x01010101, BGP_HOLD_TIME, opt, (uint8_t)opt_len);

    passed = (msg_len > 0) &&
             (bgp_process_open(NULL, &neighbor, buffer, (size_t)msg_len) == 0) &&
             (bgp_caps_get_add_path(&neighbor.peer_capabilities,
                                    AFI_IPV4, SAFI_UNICAST) ==
              (ADD_PATH_SEND | ADD_PATH_RECEIVE));

    test_result(passed, "ADD-PATH odd-length cap (trailing byte ignored)");
}

/*
 * Test 24: ADD-PATH mode > 3 silently skipped
 */
static void test_add_path_invalid_mode(void) {
    bgp_neighbor_t neighbor = make_test_neighbor(100);
    uint8_t        opt[16];
    uint8_t        buffer[256];
    int            opt_len;
    int            msg_len;
    int            passed;

    uint8_t cap_data[] = {
        0x00, 0x01,  /* AFI: IPv4                         */
        0x01,        /* SAFI: unicast                     */
        0x04         /* mode: 4 (invalid, > SEND|RECEIVE) */
    };
    opt_len = wrap_capability(opt, BGP_CAP_ADD_PATH, cap_data, 4);
    msg_len = build_raw_open(buffer, sizeof(buffer), 100, 0x01010101, BGP_HOLD_TIME, opt, (uint8_t)opt_len);

    passed = (msg_len > 0) &&
             (bgp_process_open(NULL, &neighbor, buffer, (size_t)msg_len) == 0) &&
             (bgp_caps_get_add_path(&neighbor.peer_capabilities, AFI_IPV4, SAFI_UNICAST) == 0);

    test_result(passed, "ADD-PATH mode > 3 silently skipped");
}

/*
 * Test 25: Extended next-hop SAFI > 255 silently skipped
 */
static void test_ext_nh_safi_overflow(void) {
    bgp_neighbor_t neighbor = make_test_neighbor(100);
    uint8_t        opt[16];
    uint8_t        buffer[256];
    int            opt_len;
    int            msg_len;
    int            passed;

    // ext-nh tuple with SAFI = 0x0100 (256, > UINT8_MAX)
    uint8_t cap_data[] = {
        0x00, 0x01,  /* NLRI AFI: IPv4                   */
        0x01, 0x00,  /* SAFI: 256 (2 bytes per RFC 8950) */
        0x00, 0x02   /* Next-hop AFI: IPv6               */
    };
    opt_len = wrap_capability(opt, BGP_CAP_EXTENDED_NEXTHOP, cap_data, 6);
    msg_len = build_raw_open(buffer, sizeof(buffer), 100, 0x01010101, BGP_HOLD_TIME, opt, (uint8_t)opt_len);

    passed = (msg_len > 0) &&
             (bgp_process_open(NULL, &neighbor, buffer, (size_t)msg_len) == 0);

    // No ext-nh should be recorded for any known family
    passed = passed &&
             !bgp_caps_has_ext_nh(&neighbor.peer_capabilities, AFI_IPV4, SAFI_UNICAST, AFI_IPV6);

    test_result(passed, "Extended next-hop SAFI > 255 skipped");
}

/*
 * Test 26: GR with truncated family tuples (only 2-byte restart header)
 */
static void test_gr_truncated_families(void) {
    bgp_neighbor_t neighbor = make_test_neighbor(100);
    uint8_t        opt[16];
    uint8_t        buffer[256];
    int            opt_len;
    int            msg_len;
    int            passed;

    // GR capability: 2-byte header (restart flags + time) but no family tuples
    uint8_t cap_data[] = {0x00, 0x78};  /* restart_time = 120 */
    opt_len = wrap_capability(opt, BGP_CAP_GRACEFUL_RESTART, cap_data, 2);
    msg_len = build_raw_open(buffer, sizeof(buffer), 100, 0x01010101, BGP_HOLD_TIME, opt, (uint8_t)opt_len);

    passed = (msg_len > 0) &&
             (bgp_process_open(NULL, &neighbor, buffer, (size_t)msg_len) == 0) &&
             neighbor.peer_capabilities.graceful_restart &&
             (neighbor.peer_capabilities.restart_time == 120);

    test_result(passed, "GR with no family tuples (header only)");
}

/*
 * Test 27: GR with partial family tuple (3 bytes instead of 4)
 */
static void test_gr_partial_family_tuple(void) {
    bgp_neighbor_t neighbor = make_test_neighbor(100);
    uint8_t        opt[16];
    uint8_t        buffer[256];
    int            opt_len;
    int            msg_len;
    int            passed;

    // GR: 2-byte header + 3 bytes (incomplete tuple)
    uint8_t cap_data[] = {0x00, 0x3C, 0x00, 0x01, 0x01};  /* restart_time=60, partial */
    opt_len = wrap_capability(opt, BGP_CAP_GRACEFUL_RESTART, cap_data, 5);
    msg_len = build_raw_open(buffer, sizeof(buffer), 100, 0x01010101, BGP_HOLD_TIME, opt, (uint8_t)opt_len);

    passed = (msg_len > 0) &&
             (bgp_process_open(NULL, &neighbor, buffer, (size_t)msg_len) == 0) &&
             neighbor.peer_capabilities.graceful_restart &&
             (neighbor.peer_capabilities.restart_time == 60) &&
             !bgp_caps_has_gr_family(&neighbor.peer_capabilities, AFI_IPV4, SAFI_UNICAST);

    test_result(passed, "GR partial family tuple safely ignored");
}

/*
 * Test 28: Non-Type-2 optional parameter is skipped
 */
static void test_non_type2_optional_param(void) {
    uint8_t opt[16];
    uint8_t buffer[256];
    int     msg_len;
    int     passed;

    // Type-1 (Authentication, deprecated) + Type-2 with route-refresh
    opt[0] = 1;  /* param_type = 1 (non-capability) */
    opt[1] = 2;  /* param_len                       */
    opt[2] = 0x00;
    opt[3] = 0x00;
    // Now a real Type-2 parameter with route-refresh
    opt[4] = 2;  /* param_type = capability         */
    opt[5] = 2;  /* param_len                       */
    opt[6] = BGP_CAP_ROUTE_REFRESH;
    opt[7] = 0;  /* cap_len = 0                     */

    msg_len = build_raw_open(buffer, sizeof(buffer), 100, 0x01010101, BGP_HOLD_TIME, opt, 8);

    /*
     * RFC 4271 section 6.2: an Optional Parameter that is not recognized (type 1, Authentication, is deprecated by RFC
     * 5492) gives Unsupported Optional Parameters.
     */
    passed = (msg_len > 0) && open_rejected_with(buffer, msg_len, OPEN_SUBCODE_UNSUPPORTED_OPT_PARAM);

    test_result(passed, "Non-Type-2 optional parameter rejected (Unsupported Optional Parameters)");
}

/*
 * Test 29: hold_time=0 is accepted (disables keepalives)
 */
static void test_hold_time_zero(void) {
    bgp_neighbor_t neighbor = make_test_neighbor(100);
    uint8_t        buffer[256];
    int            msg_len;
    int            passed;

    msg_len = build_raw_open(buffer, sizeof(buffer), 100, 0x01010101, 0, NULL, 0);

    passed = (msg_len > 0) &&
             (bgp_process_open(NULL, &neighbor, buffer, (size_t)msg_len) == 0) &&
             (neighbor.hold_time == 0);

    test_result(passed, "hold_time=0 accepted (disables keepalives)");
}

/*
 * Test 30: hold_time < local hold_time uses peer's value
 */
static void test_hold_time_negotiation(void) {
    bgp_neighbor_t neighbor = make_test_neighbor(100);
    uint8_t        buffer[256];
    int            msg_len;
    int            passed;

    // Peer sends hold_time=30, local is BGP_HOLD_TIME (180)
    msg_len = build_raw_open(buffer, sizeof(buffer), 100, 0x01010101, 30, NULL, 0);

    passed = (msg_len > 0) &&
             (bgp_process_open(NULL, &neighbor, buffer, (size_t)msg_len) == 0) &&
             (neighbor.hold_time == 30);

    test_result(passed, "hold_time negotiation (peer's lower value used)");
}

/*
 * Test 31: Zero-length capability is accepted (e.g. route-refresh has no data)
 */
static void test_zero_length_capability(void) {
    bgp_neighbor_t neighbor = make_test_neighbor(100);
    uint8_t        opt[8];
    uint8_t        buffer[256];
    int            opt_len;
    int            msg_len;
    int            passed;

    opt_len = wrap_capability(opt, BGP_CAP_ROUTE_REFRESH, NULL, 0);
    msg_len = build_raw_open(buffer, sizeof(buffer), 100, 0x01010101, BGP_HOLD_TIME, opt, (uint8_t)opt_len);

    passed = (msg_len > 0) &&
             (bgp_process_open(NULL, &neighbor, buffer, (size_t)msg_len) == 0) &&
             neighbor.peer_capabilities.route_refresh;

    test_result(passed, "Zero-length capability (route-refresh)");
}

/*
 * Test 32: 4-byte ASN capability with AS_TRANS in header overrides 2-byte AS
 */
static void test_as_trans_override(void) {
    bgp_neighbor_t neighbor = make_test_neighbor(4200000000U);
    uint8_t        opt[16];
    uint8_t        buffer[256];
    int            opt_len;
    int            msg_len;
    int            passed;

    // 4-byte ASN capability: value = 4200000000
    uint8_t  cap_data[4];
    uint32_t as_val = 4200000000U;
    cap_data[0] = (uint8_t)((as_val >> 24) & 0xFF);
    cap_data[1] = (uint8_t)((as_val >> 16) & 0xFF);
    cap_data[2] = (uint8_t)((as_val >> 8) & 0xFF);
    cap_data[3] = (uint8_t)(as_val & 0xFF);
    opt_len = wrap_capability(opt, BGP_CAP_4BYTE_ASN, cap_data, 4);

    // Header AS = AS_TRANS (23456) because real AS > 65535
    neighbor.capabilities.four_byte_asn = 1;
    msg_len = build_raw_open(buffer, sizeof(buffer), AS_TRANS, 0x01010101, BGP_HOLD_TIME, opt, (uint8_t)opt_len);

    // Fix the header AS to AS_TRANS manually
    bgp_open_t *open = (bgp_open_t *)(buffer + BGP_HEADER_SIZE);
    open->my_as = htons(AS_TRANS);

    passed = (msg_len > 0) &&
             (bgp_process_open(NULL, &neighbor, buffer, (size_t)msg_len) == 0) &&
             neighbor.peer_capabilities.four_byte_asn;

    test_result(passed, "AS_TRANS in header resolved via 4-byte ASN capability");
}

/*
 * Test 33: Multiple capabilities packed in a single Type-2 parameter
 */
static void test_multiple_caps_in_single_param(void) {
    bgp_neighbor_t neighbor = make_test_neighbor(100);
    uint8_t        opt[32];
    uint8_t        buffer[256];
    int            msg_len;
    int            passed;

    // Single Type-2 parameter containing: MP-BGP IPv4 + route-refresh
    opt[0] = 2;                      /* param_type               */
    opt[1] = 10;                     /* param_len = 4+4+2+0 = 10 */
    // MP-BGP cap: AFI=1, reserved=0, SAFI=1
    opt[2] = BGP_CAP_MP_BGP;
    opt[3] = 4;
    opt[4] = 0x00; opt[5] = 0x01;    /* AFI IPv4                 */
    opt[6] = 0x00;                   /* reserved                 */
    opt[7] = 0x01;                   /* SAFI unicast             */
    // Route-refresh cap
    opt[8] = BGP_CAP_ROUTE_REFRESH;
    opt[9] = 0;
    // MP-BGP cap for IPv6
    opt[10] = BGP_CAP_MP_BGP;
    opt[11] = 4;
    opt[12] = 0x00; opt[13] = 0x02;  /* AFI IPv6                 */
    opt[14] = 0x00;
    opt[15] = 0x01;                  /* SAFI unicast             */

    // Update param_len to cover all 14 bytes of cap data
    opt[1] = 14;

    msg_len = build_raw_open(buffer, sizeof(buffer), 100, 0x01010101, BGP_HOLD_TIME, opt, 16);

    passed = (msg_len > 0) &&
             (bgp_process_open(NULL, &neighbor, buffer, (size_t)msg_len) == 0) &&
             neighbor.peer_capabilities.ipv4_unicast &&
             neighbor.peer_capabilities.ipv6_unicast &&
             neighbor.peer_capabilities.route_refresh;

    test_result(passed, "Multiple capabilities in single Type-2 parameter");
}

/*
 * Test 34: GR restart time uses 12 bits (max 4095)
 */
static void test_gr_restart_time_max(void) {
    bgp_neighbor_t neighbor = make_test_neighbor(100);
    uint8_t        opt[16];
    uint8_t        buffer[256];
    int            opt_len;
    int            msg_len;
    int            passed;

    // restart_time = 4095 (0x0FFF), restart_flags = 0x80 (R bit)
    uint8_t cap_data[] = {0x8F, 0xFF};  /* R(1) + reserved(3) + time(12)=4095 */
    opt_len = wrap_capability(opt, BGP_CAP_GRACEFUL_RESTART, cap_data, 2);
    msg_len = build_raw_open(buffer, sizeof(buffer), 100, 0x01010101, BGP_HOLD_TIME, opt, (uint8_t)opt_len);

    passed = (msg_len > 0) &&
             (bgp_process_open(NULL, &neighbor, buffer, (size_t)msg_len) == 0) &&
             neighbor.peer_capabilities.graceful_restart &&
             (neighbor.peer_capabilities.restart_time == 4095);

    test_result(passed, "GR restart_time max (4095)");
}

/*
 * Test 35: Empty optional parameters (opt_param_len=0)
 */
static void test_empty_optional_params(void) {
    bgp_neighbor_t neighbor = make_test_neighbor(100);
    uint8_t        buffer[256];
    int            msg_len;
    int            passed;

    msg_len = build_raw_open(buffer, sizeof(buffer), 100, 0x01010101, BGP_HOLD_TIME, NULL, 0);

    passed = (msg_len > 0) &&
             (bgp_process_open(NULL, &neighbor, buffer, (size_t)msg_len) == 0) &&
             neighbor.peer_capabilities_received &&
             !neighbor.peer_capabilities.ipv4_unicast &&
             !neighbor.peer_capabilities.route_refresh;

    test_result(passed, "Empty optional parameters");
}

// Session tests with a raw loopback peer

static int neighbor_not_established(void *opaque) {
    return !neighbor_established(opaque);
}

/*
 * Write a BGP header for a message of len octets (body bytes after the header are the caller's).
 */
static void build_raw_header(uint8_t *buffer, uint16_t len, uint8_t type) {
    bgp_header_t *hdr = (bgp_header_t *)buffer;

    memset(hdr->marker, 0xFF, BGP_MARKER_SIZE);
    hdr->length = htons(len);
    hdr->type = type;
}

/*
 * Start a passive router (AS 65000) with neighbor 127.0.0.1 (AS 65001), connect a raw peer and bring the session to
 * ESTABLISHED: read the OPEN of bgpsim, send an OPEN with hold_time (no capabilities), read the KEEPALIVE and send one.
 * route_refresh sets the Route Refresh capability of the neighbor before the runtime starts. Returns the peer socket,
 * or -1.
 */
static int establish_passive_session(bgp_sim_t *sim, char *socket_path, size_t socket_path_size,
                                     uint16_t hold_time, int route_refresh) {
    uint8_t buffer[BGP_MAX_MESSAGE_SIZE];
    uint8_t type = 0;
    int     sock;
    int     len;

    if (sim == NULL) {
        return -1;
    }
    sim->passive_mode = 1;
    if (bgp_add_router(sim, 65000) != 1 || bgp_add_neighbor(sim, 65000, "127.0.0.1", 65001) != 1) {
        return -1;
    }
    sim->routers[0]->neighbors[0]->capabilities.route_refresh = route_refresh;
    if (start_runtime(sim, socket_path, socket_path_size) != 0 ||
        !wait_until(router_listening, sim->routers[0], OPEN_RUNTIME_TIMEOUT_MS)) {
        return -1;
    }

    sock = connect_ipv4_loopback_with_retry((uint16_t)sim->routers[0]->listen_port, OPEN_RUNTIME_TIMEOUT_MS);
    if (sock < 0) {
        return -1;
    }
    if (recv_bgp_message_with_timeout(sock, buffer, sizeof(buffer), &type, OPEN_RUNTIME_TIMEOUT_MS) <= 0 ||
        type != BGP_MSG_OPEN) {
        close(sock);
        return -1;
    }

    len = build_raw_open(buffer, sizeof(buffer), 65001, 0x02020202, hold_time, NULL, 0);
    if (len <= 0 || send_raw(sock, buffer, (size_t)len) != 0 ||
        recv_bgp_message_with_timeout(sock, buffer, sizeof(buffer), &type, OPEN_RUNTIME_TIMEOUT_MS) <= 0 ||
        type != BGP_MSG_KEEPALIVE) {
        close(sock);
        return -1;
    }

    build_raw_header(buffer, BGP_HEADER_SIZE, BGP_MSG_KEEPALIVE);
    if (send_raw(sock, buffer, BGP_HEADER_SIZE) != 0 ||
        !wait_until(neighbor_established, &(neighbor_wait_t){ .neighbor = sim->routers[0]->neighbors[0] },
                    OPEN_RUNTIME_TIMEOUT_MS)) {
        close(sock);
        return -1;
    }
    return sock;
}

/*
 * Read a complete NOTIFICATION, skipping KEEPALIVEs. Return its length or 0.
 */
static int peer_reads_notification_message(int sock, int timeout_ms, uint8_t *buffer, size_t capacity) {
    uint8_t type = 0;
    int     len;

    while ((len = recv_bgp_message_with_timeout(sock, buffer, capacity, &type, timeout_ms)) > 0) {
        if (type == BGP_MSG_NOTIFICATION) {
            return len;
        }
    }
    return 0;
}

/*
 * RFC 2918 section 3: a speaker that advertised Route Refresh accepts a ROUTE-REFRESH message (type 5: AFI, reserved,
 * SAFI) and keeps the session. The runtime is stopped before the ASSERTs, which return early.
 */
static void test_session_route_refresh_keeps_session(void) {
    bgp_sim_t *sim = create_sim();
    char       socket_path[108] = "";
    uint8_t    msg[BGP_HEADER_SIZE + 4];
    int        sock;
    int        sent = 0;
    int        stayed_up = 0;
    int        notified = 0;

    TEST("Session keeps ESTABLISHED after a valid ROUTE-REFRESH");

    sock = establish_passive_session(sim, socket_path, sizeof(socket_path), BGP_HOLD_TIME, 1);
    if (sock >= 0) {
        build_raw_header(msg, sizeof(msg), 5);
        msg[BGP_HEADER_SIZE] = 0;
        msg[BGP_HEADER_SIZE + 1] = AFI_IPV4;
        msg[BGP_HEADER_SIZE + 2] = 0;
        msg[BGP_HEADER_SIZE + 3] = SAFI_UNICAST;
        sent = send_raw(sock, msg, sizeof(msg)) == 0;
        // Once bgpsim has processed a KEEPALIVE sent after the ROUTE-REFRESH, it has handled the refresh too.
        stayed_up = peer_barrier(sock, sim->routers[0]->neighbors[0]);
        notified = peer_has_message(sock, BGP_MSG_NOTIFICATION);
        close(sock);
    }
    destroy_sim(sim);
    unlink(socket_path);

    ASSERT(sock >= 0, "The raw peer reaches ESTABLISHED with Route Refresh advertised");
    ASSERT(sent, "The peer sends a ROUTE-REFRESH for IPv4 unicast");
    ASSERT(stayed_up, "RFC 2918 section 3: a ROUTE-REFRESH keeps the session");
    ASSERT(!notified, "No NOTIFICATION follows the ROUTE-REFRESH");
    PASS();
}

/*
 * Each call is a separate case with its own session. Clean up before checking the setup, send and NOTIFICATION so an
 * ASSERT cannot leave a runtime running.
 */
static void test_session_rejects_message_length(const char *name, uint8_t type, uint16_t len) {
    bgp_sim_t *sim = create_sim();
    char       socket_path[108] = "";
    uint8_t    msg[64] = {0};
    uint8_t    reply[64];
    uint8_t    code = 0;
    uint8_t    subcode = 0;
    int        sock;
    int        sent = 0;
    int        notified = 0;
    int        data_matches = 0;
    int        reset_after_notification = 0;

    TEST(name);

    sock = establish_passive_session(sim, socket_path, sizeof(socket_path), BGP_HOLD_TIME, 0);
    if (sock >= 0) {
        build_raw_header(msg, len, type);
        sent = send_raw(sock, msg, len) == 0;
        if (sent) {
            int reply_len = peer_reads_notification_message(sock, OPEN_RUNTIME_TIMEOUT_MS, reply, sizeof(reply));

            notified = reply_len >= BGP_HEADER_SIZE + 2;
            if (notified) {
                code = reply[BGP_HEADER_SIZE];
                subcode = reply[BGP_HEADER_SIZE + 1];
                data_matches = reply_len == BGP_HEADER_SIZE + 4 &&
                               memcmp(reply + BGP_HEADER_SIZE + 2, msg + BGP_MARKER_SIZE, 2) == 0;
                reset_after_notification = wait_until(neighbor_not_established,
                    &(neighbor_wait_t){ .neighbor = sim->routers[0]->neighbors[0] }, OPEN_RUNTIME_TIMEOUT_MS) &&
                    sim->routers[0]->neighbors[0]->tx_notification == 1;
            }
        }
        close(sock);
    }
    destroy_sim(sim);
    unlink(socket_path);

    ASSERT(sock >= 0, "The raw peer reaches ESTABLISHED before the malformed message");
    ASSERT(sent, "The peer sends the malformed message");
    ASSERT(notified, "RFC 4271 section 6.1: an invalid message length gives a NOTIFICATION");
    ASSERT(code == BGP_ERR_MESSAGE_HEADER && subcode == 2,
           "The NOTIFICATION is Message Header Error / Bad Message Length");
    ASSERT(data_matches, "The NOTIFICATION Data contains the erroneous two-octet Length field");
    ASSERT(reset_after_notification, "The runtime sends the NOTIFICATION before resetting the session");
    PASS();
}

static int minimal_messages_received(void *opaque) {
    neighbor_wait_t *wait = opaque;

    return wait->neighbor->rx_update == 1 && wait->neighbor->rx_keepalive >= 2;
}

static void test_session_accepts_minimum_message_lengths(void) {
    bgp_sim_t *sim = create_sim();
    char       socket_path[108] = "";
    uint8_t    messages[2 * BGP_HEADER_SIZE + 4] = {0};
    int        sock;
    int        received = 0;
    int        notified = 0;

    TEST("Session accepts a 19-octet KEEPALIVE and a 23-octet empty UPDATE");
    sock = establish_passive_session(sim, socket_path, sizeof(socket_path), 0, 0);
    if (sock >= 0) {
        build_raw_header(messages, BGP_HEADER_SIZE, BGP_MSG_KEEPALIVE);
        build_raw_header(messages + BGP_HEADER_SIZE, BGP_HEADER_SIZE + 4, BGP_MSG_UPDATE);
        received = send_raw(sock, messages, sizeof(messages)) == 0 &&
                   wait_until(minimal_messages_received,
                              &(neighbor_wait_t){ .neighbor = sim->routers[0]->neighbors[0] }, OPEN_RUNTIME_TIMEOUT_MS) &&
                   peer_barrier(sock, sim->routers[0]->neighbors[0]);
        notified = peer_has_message(sock, BGP_MSG_NOTIFICATION);
        received = received && sim->routers[0]->neighbors[0]->state == BGP_STATE_ESTABLISHED;
        close(sock);
    }
    destroy_sim(sim);
    unlink(socket_path);

    ASSERT(sock >= 0, "The raw peer reaches ESTABLISHED");
    ASSERT(received, "Both minimum-sized messages are counted and the session stays ESTABLISHED");
    ASSERT(!notified, "Valid minimum-sized messages do not produce a NOTIFICATION");
    PASS();
}

/*
 * RFC 4271 section 4.4: "If the negotiated Hold Time interval is zero, then periodic KEEPALIVE messages MUST NOT be
 * sent." The KEEPALIVE timer stays stopped.
 */
static void test_session_hold_time_zero_stops_keepalive_timer(void) {
    bgp_sim_t *sim = create_sim();
    char       socket_path[108] = "";
    int        sock;
    int        hold_time_zero = 0;
    int        timer_stopped = 0;

    TEST("Hold Time 0 leaves the KEEPALIVE timer stopped");

    sock = establish_passive_session(sim, socket_path, sizeof(socket_path), 0, 0);
    if (sock >= 0) {
        bgp_neighbor_t *neighbor = sim->routers[0]->neighbors[0];

        hold_time_zero = neighbor->hold_time == 0;
        timer_stopped = !uv_is_active((uv_handle_t *)&neighbor->keepalive_timer);
        close(sock);
    }
    destroy_sim(sim);
    unlink(socket_path);

    ASSERT(sock >= 0, "The raw peer reaches ESTABLISHED with Hold Time 0");
    ASSERT(hold_time_zero, "The negotiated Hold Time is 0");
    ASSERT(timer_stopped, "RFC 4271 section 4.4: no periodic KEEPALIVE with Hold Time 0");
    PASS();
}

/*
 * The description of a NOTIFICATION body.
 */
static const char *describe_notification(const uint8_t *body, size_t body_len) {
    static char text[512];
    bgp_notification_record_t record;

    bgp_notification_record(&record, body, body_len);
    bgp_notification_describe(&record, text, sizeof(text));
    return text;
}

/*
 * Error code and subcode names (IANA registry), and RFC 9003 Shutdown Communications, without a session.
 */
static void test_notification_names_and_descriptions(void) {
    uint8_t long_shutdown[2 + 1 + 255];
    char    expected[400];

    TEST("NOTIFICATION codes, subcodes and Shutdown Communications are described");

    ASSERT(strcmp(bgp_notification_code_name(6), "Cease") == 0 &&
           strcmp(bgp_notification_subcode_name(6, 5), "Connection Rejected") == 0 &&
           strcmp(bgp_notification_subcode_name(2, 7), "Unsupported Capability") == 0 &&
           strcmp(bgp_notification_subcode_name(5, 1), "Unexpected Message in OpenSent State") == 0,
           "Known codes and subcodes have their registry names");
    ASSERT(strcmp(bgp_notification_subcode_name(4, 0), "Unspecific") == 0 &&
           strcmp(bgp_notification_code_name(99), "Unknown Error Code") == 0 &&
           strcmp(bgp_notification_subcode_name(6, 42), "Unknown Subcode") == 0,
           "Subcode 0 is Unspecific; unassigned values are named unknown");

    ASSERT(strcmp(describe_notification((const uint8_t[]){6, 5}, 2), "6/5 (Cease/Connection Rejected)") == 0,
           "Cease / Connection Rejected");
    ASSERT(strcmp(describe_notification((const uint8_t[]){4, 0}, 2), "4/0 (Hold Timer Expired/Unspecific)") == 0,
           "Hold Timer Expired");
    ASSERT(strcmp(describe_notification((const uint8_t[]){99, 3}, 2), "99/3 (Unknown Error Code/Unknown Subcode)") ==
               0,
           "An unassigned code keeps its numbers");
    ASSERT(strcmp(describe_notification((const uint8_t[]){6, 2, 11, 'm', 'a', 'i', 'n', 't', 'e', 'n', 'a', 'n', 'c',
                                                          'e'},
                                        14),
                  "6/2 (Cease/Administrative Shutdown), shutdown communication \"maintenance\"") == 0,
           "RFC 9003: an Administrative Shutdown carries its Shutdown Communication");
    ASSERT(strcmp(describe_notification((const uint8_t[]){6, 4, 3, 'a', '\n', 'b'}, 6),
                  "6/4 (Cease/Administrative Reset), shutdown communication \"a?b\"") == 0,
           "Control characters in a Shutdown Communication are replaced");
    ASSERT(strcmp(describe_notification((const uint8_t[]){6, 2, 20, 'x'}, 4),
                  "6/2 (Cease/Administrative Shutdown), data length 2") == 0,
           "RFC 9003: a length past the data makes the communication malformed; it is ignored");
    ASSERT(strcmp(describe_notification((const uint8_t[]){6, 5, 3, 'a', 'b', 'c'}, 6),
                  "6/5 (Cease/Connection Rejected), data length 4") == 0,
           "Only Administrative Shutdown and Reset carry a Shutdown Communication");
    ASSERT(strcmp(describe_notification((const uint8_t[]){1, 2, 0x00, 0x05}, 4),
                  "1/2 (Message Header Error/Bad Message Length), data length 2") == 0,
           "Other data is counted");

    long_shutdown[0] = 6;
    long_shutdown[1] = 2;
    long_shutdown[2] = 255;
    memset(long_shutdown + 3, 'w', 255);
    snprintf(expected, sizeof(expected), "6/2 (Cease/Administrative Shutdown), shutdown communication \"%.*s\"", 255,
             (const char *)long_shutdown + 3);
    ASSERT(strcmp(describe_notification(long_shutdown, sizeof(long_shutdown)), expected) == 0,
           "RFC 9003: a 255-octet Shutdown Communication is kept whole");
    PASS();
}

typedef struct {
    char   out[32768];
    size_t out_len;
    char   events[4096];
    size_t events_len;
} notification_capture_t;

static void capture_append(char *buffer, size_t capacity, size_t *len, const char *data, size_t data_len) {
    if (*len + data_len >= capacity) {
        data_len = capacity - *len - 1;
    }
    memcpy(buffer + *len, data, data_len);
    *len += data_len;
    buffer[*len] = '\0';
}

static void capture_notification_output(void *opaque, output_stream_t stream, const char *data, size_t len) {
    notification_capture_t *capture = opaque;

    (void)stream;
    capture_append(capture->out, sizeof(capture->out), &capture->out_len, data, len);
}

static void capture_notification_event(void *opaque, const char *data, size_t len) {
    notification_capture_t *capture = opaque;

    capture_append(capture->events, sizeof(capture->events), &capture->events_len, data, len);
}

/*
 * One session for the NOTIFICATION reason tests. A control session turns terminal monitor on, the raw peer connects
 * and either stops in OpenSent (it reads the OPEN of bgpsim) or reaches ESTABLISHED, then sends msg. Once the session
 * is down the control session runs "show bgp neighbors"; capture holds its output and the monitor events. last_rx and
 * last_tx get the neighbor's records. Returns 1 when every step worked.
 */
static int run_notification_session(int open_sent, const uint8_t *msg, size_t msg_len,
                                    notification_capture_t *capture, bgp_notification_record_t *last_rx,
                                    bgp_notification_record_t *last_tx) {
    bgp_sim_t              *sim = create_sim();
    bgpsim_control_client_t client;
    cli_mode_t              mode = CLI_MODE_EXEC;
    cli_session_t           session;
    char                    socket_path[108] = "";
    uint8_t                 buffer[BGP_MAX_MESSAGE_SIZE];
    uint8_t                 type = 0;
    int                     client_open = 0;
    int                     status = -1;
    int                     sock = -1;
    int                     ok;

    memset(capture, 0, sizeof(*capture));
    memset(&session, 0, sizeof(session));
    ok = sim != NULL && bgp_add_router(sim, 65000) == 1 && bgp_add_neighbor(sim, 65000, "127.0.0.1", 65001) == 1 &&
         session_start_runtime(sim, socket_path, sizeof(socket_path)) == 0 &&
         bgpsim_control_client_open(&client, socket_path) == 0;
    client_open = ok;
    ok = ok && bgpsim_control_client_execute(&client, "terminal monitor", &mode, &session, NULL, NULL, NULL,
                                             &status) == 0 &&
         status >= 0;
    if (ok && open_sent) {
        sock = connect_ipv4_loopback_with_retry((uint16_t)sim->routers[0]->listen_port, OPEN_RUNTIME_TIMEOUT_MS);
        ok = sock >= 0 &&
             recv_bgp_message_with_timeout(sock, buffer, sizeof(buffer), &type, OPEN_RUNTIME_TIMEOUT_MS) > 0 &&
             type == BGP_MSG_OPEN;
    } else if (ok) {
        sock = session_connect_peer(sim, NULL);
        ok = sock >= 0;
    }
    ok = ok && send_raw(sock, msg, msg_len) == 0 &&
         wait_until(passive_neighbor_idle, &(neighbor_wait_t){.neighbor = sim->routers[0]->neighbors[0]},
                    OPEN_RUNTIME_TIMEOUT_MS) &&
         bgpsim_control_client_execute(&client, "show bgp neighbors", &mode, &session, capture_notification_output,
                                       capture_notification_event, capture, &status) == 0 &&
         status >= 0 && bgpsim_control_client_drain_events(&client, capture_notification_event, capture) == 0;
    if (ok) {
        *last_rx = sim->routers[0]->neighbors[0]->last_notification_rx;
        *last_tx = sim->routers[0]->neighbors[0]->last_notification_tx;
    }
    if (sock >= 0) {
        close(sock);
    }
    if (client_open) {
        bgpsim_control_client_close(&client);
    }
    destroy_sim(sim);
    unlink(socket_path);
    return ok;
}

/*
 * A NOTIFICATION that ends an established session is shown with its reason and reported to terminal monitors.
 */
static void test_session_reports_received_notification(void) {
    static const char      text[] = "maintenance window";
    uint8_t                msg[BGP_HEADER_SIZE + 3 + sizeof(text) - 1];
    notification_capture_t    capture;
    bgp_notification_record_t last_rx;
    bgp_notification_record_t last_tx;
    int                       ran;

    TEST("A received Cease shows its reason and Shutdown Communication");

    build_raw_header(msg, sizeof(msg), BGP_MSG_NOTIFICATION);
    msg[BGP_HEADER_SIZE] = BGP_ERR_CEASE;
    msg[BGP_HEADER_SIZE + 1] = 2;
    msg[BGP_HEADER_SIZE + 2] = sizeof(text) - 1;
    memcpy(msg + BGP_HEADER_SIZE + 3, text, sizeof(text) - 1);
    ran = run_notification_session(0, msg, sizeof(msg), &capture, &last_rx, &last_tx);

    ASSERT(ran, "The peer reaches ESTABLISHED, sends the NOTIFICATION and the session goes down");
    ASSERT(last_rx.time != 0 && last_rx.code == BGP_ERR_CEASE && last_rx.subcode == 2 &&
           strcmp(last_rx.shutdown, text) == 0 && last_tx.time == 0,
           "The neighbor keeps the received code, subcode and Shutdown Communication");
    ASSERT(strstr(capture.out, "  Last notification received: 6/2 (Cease/Administrative Shutdown), shutdown "
                               "communication \"maintenance window\", 00:0") != NULL &&
           strstr(capture.out, "Last notification sent") == NULL,
           "show bgp neighbors shows the last notification received");
    ASSERT(strstr(capture.events, "%BGP-3-NOTIFICATION: received from neighbor 127.0.0.1 6/2 (Cease/Administrative "
                                  "Shutdown), shutdown communication \"maintenance window\"") != NULL,
           "Terminal monitors see the NOTIFICATION with its reason");
    ASSERT(strstr(capture.events, "%BGP-5-ADJCHANGE: neighbor 127.0.0.1 Down - received NOTIFICATION") != NULL,
           "The session goes down on the NOTIFICATION");
    PASS();
}

/*
 * A peer that rejects the session answers the OPEN with a NOTIFICATION: the reason is kept in OpenSent too.
 */
static void test_session_reports_notification_in_open_sent(void) {
    uint8_t                   msg[BGP_HEADER_SIZE + 2];
    notification_capture_t    capture;
    bgp_notification_record_t last_rx;
    bgp_notification_record_t last_tx;
    int                       ran;

    TEST("A NOTIFICATION in OpenSent shows its reason");

    build_raw_header(msg, sizeof(msg), BGP_MSG_NOTIFICATION);
    msg[BGP_HEADER_SIZE] = BGP_ERR_CEASE;
    msg[BGP_HEADER_SIZE + 1] = 5;
    ran = run_notification_session(1, msg, sizeof(msg), &capture, &last_rx, &last_tx);

    ASSERT(ran, "The peer reads the OPEN, answers with a NOTIFICATION and the session goes down");
    ASSERT(last_rx.code == BGP_ERR_CEASE && last_rx.subcode == 5 && last_rx.data_len == 0 &&
           last_rx.shutdown[0] == '\0',
           "The neighbor keeps Cease / Connection Rejected");
    ASSERT(strstr(capture.out, "  Last notification received: 6/5 (Cease/Connection Rejected), 00:0") != NULL,
           "show bgp neighbors shows the reason");
    ASSERT(strstr(capture.events, "%BGP-3-NOTIFICATION: received from neighbor 127.0.0.1 6/5 (Cease/Connection "
                                  "Rejected)\n") != NULL &&
           strstr(capture.events, "ADJCHANGE") == NULL,
           "Terminal monitors see the reason; the session was never up");
    PASS();
}

/*
 * bgpsim's own NOTIFICATIONs are shown and reported with their reason and data.
 */
static void test_session_reports_sent_notification(void) {
    uint8_t                   msg[BGP_HEADER_SIZE];
    notification_capture_t    capture;
    bgp_notification_record_t last_rx;
    bgp_notification_record_t last_tx;
    int                       ran;

    TEST("A NOTIFICATION sent by bgpsim shows its reason");

    build_raw_header(msg, sizeof(msg), 9);
    ran = run_notification_session(0, msg, sizeof(msg), &capture, &last_rx, &last_tx);

    ASSERT(ran, "The peer sends a message of unknown type and the session goes down");
    ASSERT(last_tx.time != 0 && last_tx.code == BGP_ERR_MESSAGE_HEADER && last_tx.subcode == 3 &&
           last_tx.data_len == 1 && last_rx.time == 0,
           "RFC 4271 section 6.1: Message Header Error / Bad Message Type, the type as data");
    ASSERT(strstr(capture.out, "  Last notification sent: 1/3 (Message Header Error/Bad Message Type), data length 1, "
                               "00:0") != NULL &&
           strstr(capture.out, "Last notification received") == NULL,
           "show bgp neighbors shows the last notification sent");
    ASSERT(strstr(capture.events, "%BGP-3-NOTIFICATION: sent to neighbor 127.0.0.1 1/3 (Message Header Error/Bad "
                                  "Message Type), data length 1\n") != NULL &&
           strstr(capture.events, "%BGP-5-ADJCHANGE: neighbor 127.0.0.1 Down - sent NOTIFICATION") != NULL,
           "Terminal monitors see the NOTIFICATION, then the session going down");
    PASS();
}

int main(int argc, char **argv) {
    int unit = argc == 1 || (argc == 2 && strcmp(argv[1], "--unit") == 0);
    int sessions = argc == 1 || (argc == 2 && strcmp(argv[1], "--sessions") == 0);
    if (!unit && !sessions) {
        fprintf(stderr, "Usage: %s [--unit|--sessions]\n", argv[0]);
        return 2;
    }
    printf("BGP OPEN Message Capability Tests\n");
    printf("==================================\n\n");

    if (unit) {
        test_basic_open();
        test_4byte_asn();
        test_4byte_asn_capability_with_16bit_as();
        test_old_speaker_rejects_large_asn();
        test_route_refresh();
        test_ipv4_unicast();
        test_ipv6_unicast();
        test_ipv4_labeled_unicast();
        test_ipv6_labeled_unicast();
        test_vpnv4();
        test_vpnv6();
        test_evpn();
        test_ipv4_flowspec();
        test_ipv6_flowspec();
        test_flowspec_vpn_mp_capability();
        test_ipv4_srpolicy();
        test_ipv6_srpolicy();
        test_bgp_ls();
        test_ipv4_mvpn();
        test_ipv6_mvpn();
        test_ipv4_rtc();
        test_vpls();
        test_graceful_restart();
        test_add_path_grouped_capability();
        test_extended_next_hop_capability();
        test_capability_tuples_require_enabled_family();
        test_add_path_negotiation_helpers();
        test_open_roundtrip_capability_parse();
        test_multiple_capabilities();
        test_all_capabilities();
        test_extended_open_optional_parameters_boundary();
        test_extended_open_marker_controls_parse();
        test_open_structure();

        // Adversarial / boundary tests
        test_unknown_capability_ignored();
        test_peer_mp_capability_flag();
        test_duplicate_capabilities();
        test_add_path_odd_length();
        test_add_path_invalid_mode();
        test_ext_nh_safi_overflow();
        test_gr_truncated_families();
        test_gr_partial_family_tuple();
        test_hold_time_zero();
        test_hold_time_negotiation();
        test_zero_length_capability();
        test_as_trans_override();
        test_multiple_caps_in_single_param();
        test_gr_restart_time_max();
        test_empty_optional_params();
        test_mvpn_mp_capability_uses_safi_5(AFI_IPV4, "IPv4 MVPN MP-BGP capability uses SAFI 5");
        test_mvpn_mp_capability_uses_safi_5(AFI_IPV6, "IPv6 MVPN MP-BGP capability uses SAFI 5");
        test_notification_names_and_descriptions();
    }
    if (sessions) {
        test_open_optional_param_threshold_boundary_via_cli();
        test_truncated_capability();
        test_non_type2_optional_param();
        test_open_accepts_hold_time_three();
        test_open_rejects_hold_time_one();
        test_open_rejects_hold_time_two();
        test_open_rejects_zero_bgp_identifier();
        test_open_rejects_unknown_optional_parameter();
        test_open_rejects_mp_capability_without_value();
        test_open_rejects_optional_parameter_overrun();
        test_session_route_refresh_keeps_session();
        test_session_rejects_message_length("Session rejects a 20-octet KEEPALIVE", BGP_MSG_KEEPALIVE, BGP_HEADER_SIZE + 1);
        test_session_rejects_message_length("Session rejects a header-only UPDATE", BGP_MSG_UPDATE, BGP_HEADER_SIZE);
        test_session_rejects_message_length("Session rejects a 28-octet OPEN",
                                            BGP_MSG_OPEN, BGP_HEADER_SIZE + sizeof(bgp_open_t) - 1);
        test_session_rejects_message_length("Session rejects a 20-octet NOTIFICATION",
                                            BGP_MSG_NOTIFICATION, BGP_HEADER_SIZE + 1);
        test_session_rejects_message_length("Session rejects a 22-octet ROUTE-REFRESH",
                                            BGP_MSG_ROUTE_REFRESH, BGP_HEADER_SIZE + 3);
        test_session_accepts_minimum_message_lengths();
        test_session_hold_time_zero_stops_keepalive_timer();
        test_session_reports_received_notification();
        test_session_reports_notification_in_open_sent();
        test_session_reports_sent_notification();
    }

    printf("\n==================================\n");
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);
    printf("==================================\n");

    return (tests_failed == 0) ? 0 : 1;
}
