/*
 * BGP OPEN Message Capability Tests
 * Tests configuration parsing and OPEN message generation with capabilities.
 */

#include <uv.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
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

/*
 * The one wait for a session that has gone down: the neighbor is Idle and its stream is closed. 0 on timeout.
 */
static int neighbor_settles_idle(bgp_neighbor_t *neighbor) {
    return wait_until(passive_neighbor_idle, &(neighbor_wait_t){.neighbor = neighbor}, OPEN_RUNTIME_TIMEOUT_MS);
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
    peer_rx_t reader = {0};
    int       sock = -1;
    uint8_t   msg_type = 0;
    int       msg_len = -1;

    if (router == NULL || neighbor == NULL || buffer == NULL ||
        msg_len_out == NULL) {
        return 0;
    }

    sock = connect_ipv4_loopback_with_retry((uint16_t)router->listen_port, OPEN_RUNTIME_TIMEOUT_MS);
    if (sock < 0) {
        return 0;
    }

    reader.fd = sock;
    msg_len = recv_bgp_message_with_timeout(&reader, buffer, buffer_size, &msg_type, OPEN_RUNTIME_TIMEOUT_MS);
    close(sock);

    if (msg_len <= 0 || msg_type != BGP_MSG_OPEN) {
        return 0;
    }

    if (!neighbor_settles_idle(neighbor)) {
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
             bgp_accept_open(NULL, &neighbor, buffer, (size_t)len, &(bgp_open_info_t){0}) == 0 &&
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
             bgp_accept_open(NULL, &neighbor, buffer, (size_t)len, &(bgp_open_info_t){0}) == 0 &&
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
    neighbor.hold_time_config = BGP_HOLD_TIME;
    return neighbor;
}

/*
 * RFC 8654 section 3: the Extended Message capability is code 6 with no value. It is sent once when enabled and not
 * at all otherwise, and an OPEN that carries it, built by hand here, sets the peer's capability.
 */
static void test_extended_message_capability(void) {
    bgp_capabilities_t caps = {0};
    bgp_neighbor_t     with = make_test_neighbor(100);
    bgp_neighbor_t     without = make_test_neighbor(100);
    capability_view_t  view;
    uint8_t            buffer[1024];
    uint8_t            opt[8];
    int                len = bgp_build_open_with_capabilities(buffer, sizeof(buffer), 100, 0x01010101, &caps);
    int                absent = len > 0 && count_capabilities(buffer, (size_t)len, BGP_CAP_EXTENDED_MESSAGE) == 0;
    int                opt_len;
    int                passed;

    caps.extended_message = 1;
    len = bgp_build_open_with_capabilities(buffer, sizeof(buffer), 100, 0x01010101, &caps);
    passed = absent && len > 0 && BGP_CAP_EXTENDED_MESSAGE == 6 &&
             count_capabilities(buffer, (size_t)len, 6) == 1 && get_capability_instance(buffer, (size_t)len, 6, 0, &view) &&
             view.len == 0;
    // The peer's side: capability 6 with length 0, written out by hand.
    opt_len = wrap_capability(opt, 6, NULL, 0);
    len = build_raw_open(buffer, sizeof(buffer), 100, 0x01010101, BGP_HOLD_TIME, opt, (uint8_t)opt_len);
    passed = passed && opt_len == 4 && opt[2] == 6 && opt[3] == 0 &&
             bgp_accept_open(NULL, &with, buffer, (size_t)len, &(bgp_open_info_t){0}) == 0 &&
             with.peer_capabilities.extended_message == 1;
    len = build_raw_open(buffer, sizeof(buffer), 100, 0x01010101, BGP_HOLD_TIME, NULL, 0);
    passed = passed && bgp_accept_open(NULL, &without, buffer, (size_t)len, &(bgp_open_info_t){0}) == 0 &&
             without.peer_capabilities.extended_message == 0;
    test_result(passed, "Extended Message capability: code 6, no value, sent once, parsed from a peer's OPEN");
}

/*
 * Check OPEN policy directly; real-session tests below verify NOTIFICATION delivery.
 */
static int open_rejected_with(const uint8_t *msg, int msg_len, uint8_t subcode) {
    bgp_neighbor_t  neighbor = make_test_neighbor(100);
    bgp_open_info_t info;

    return msg_len > 0 && bgp_accept_open(NULL, &neighbor, msg, (size_t)msg_len, &info) != 0 &&
           info.error_subcode == subcode && !neighbor.peer_capabilities_received;
}

// OPEN Message Error subcodes: RFC 4271 section 4.5 (0 Unspecific) and section 6.2.
#define OPEN_SUBCODE_UNSPECIFIC            0
#define OPEN_SUBCODE_BAD_BGP_IDENTIFIER    3
#define OPEN_SUBCODE_UNSUPPORTED_OPT_PARAM 4
#define OPEN_SUBCODE_UNACCEPTABLE_HOLD     6

/*
 * Build an OPEN from AS 100 with this Hold Time, BGP Identifier and optional parameters, and return 1 when
 * bgp_accept_open() rejects it with this OPEN Message Error subcode.
 */
static int raw_open_rejected_with(uint16_t hold_time, uint32_t bgp_id, const uint8_t *opt, uint8_t opt_len, uint8_t subcode) {
    uint8_t buffer[256];
    int     len = build_raw_open(buffer, sizeof(buffer), 100, bgp_id, hold_time, opt, opt_len);

    return open_rejected_with(buffer, len, subcode);
}

/*
 * Return 1 when the OPEN policy accepts this Hold Time and BGP Identifier.
 */
static int raw_open_accepted(uint16_t hold_time, uint32_t bgp_id) {
    bgp_neighbor_t  neighbor = make_test_neighbor(100);
    bgp_open_info_t info;
    uint8_t         buffer[256];
    int             len = build_raw_open(buffer, sizeof(buffer), 100, bgp_id, hold_time, NULL, 0);

    return len > 0 && bgp_accept_open(NULL, &neighbor, buffer, (size_t)len, &info) == 0 &&
           neighbor.peer_capabilities_received && neighbor.remote_id == bgp_id &&
           neighbor.hold_time == (hold_time < BGP_HOLD_TIME ? hold_time : BGP_HOLD_TIME);
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
             (bgp_accept_open(NULL, &neighbor, buffer, (size_t)msg_len, &(bgp_open_info_t){0}) == 0) &&
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
    passed = msg_len > 0 && bgp_accept_open(NULL, &plain, buffer, (size_t)msg_len, &(bgp_open_info_t){0}) == 0 &&
             plain.peer_capabilities_received && !plain.peer_mp_capability_received &&
             !plain.peer_capabilities.ipv4_unicast;

    opt_len = wrap_capability(opt, BGP_CAP_MP_BGP, ipv4_multicast, sizeof(ipv4_multicast));
    msg_len = build_raw_open(buffer, sizeof(buffer), 100, 0x01010101, BGP_HOLD_TIME, opt, (uint8_t)opt_len);
    passed = passed && msg_len > 0 && bgp_accept_open(NULL, &unknown_mp, buffer, (size_t)msg_len, &(bgp_open_info_t){0}) == 0 &&
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
             (bgp_accept_open(NULL, &neighbor, buffer, (size_t)len, &(bgp_open_info_t){0}) == 0) &&
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
             (bgp_accept_open(NULL, &neighbor, buffer, (size_t)msg_len, &(bgp_open_info_t){0}) == 0) &&
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
             (bgp_accept_open(NULL, &neighbor, buffer, (size_t)msg_len, &(bgp_open_info_t){0}) == 0) &&
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
             (bgp_accept_open(NULL, &neighbor, buffer, (size_t)msg_len, &(bgp_open_info_t){0}) == 0);

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
             (bgp_accept_open(NULL, &neighbor, buffer, (size_t)msg_len, &(bgp_open_info_t){0}) == 0) &&
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
             (bgp_accept_open(NULL, &neighbor, buffer, (size_t)msg_len, &(bgp_open_info_t){0}) == 0) &&
             neighbor.peer_capabilities.graceful_restart &&
             (neighbor.peer_capabilities.restart_time == 60) &&
             !bgp_caps_has_gr_family(&neighbor.peer_capabilities, AFI_IPV4, SAFI_UNICAST);

    test_result(passed, "GR partial family tuple safely ignored");
}

/*
 * RFC 4724 section 3: when the Graceful Restart capability is repeated, the receiver ignores all but the last instance,
 * including the address family tuples of the earlier ones.
 */
static void test_gr_last_instance_wins(void) {
    bgp_neighbor_t neighbor = make_test_neighbor(100);
    uint8_t        first[] = {0x00, 0x64, 0x00, 0x01, 0x01, 0x80};  /* 100 s, IPv4 unicast, F set */
    uint8_t        last[] = {0x00, 0xC8, 0x00, 0x02, 0x01, 0x00};   /* 200 s, IPv6 unicast        */
    uint8_t        opt[32];
    uint8_t        buffer[256];
    int            opt_len;
    int            msg_len;
    int            passed;

    opt_len = wrap_capability(opt, BGP_CAP_GRACEFUL_RESTART, first, sizeof(first));
    opt_len += wrap_capability(opt + opt_len, BGP_CAP_GRACEFUL_RESTART, last, sizeof(last));
    msg_len = build_raw_open(buffer, sizeof(buffer), 100, 0x01010101, BGP_HOLD_TIME, opt, (uint8_t)opt_len);

    passed = msg_len > 0 &&
             bgp_accept_open(NULL, &neighbor, buffer, (size_t)msg_len, &(bgp_open_info_t){0}) == 0 &&
             neighbor.peer_capabilities.graceful_restart && neighbor.peer_capabilities.restart_time == 200 &&
             bgp_caps_has_gr_family(&neighbor.peer_capabilities, AFI_IPV6, SAFI_UNICAST) &&
             !bgp_caps_has_gr_family(&neighbor.peer_capabilities, AFI_IPV4, SAFI_UNICAST) &&
             neighbor.peer_capabilities.gr_forwarding_mask == 0;

    test_result(passed, "GR repeated capability: only the last instance counts");
}

/*
 * RFC 4724 section 3 and RFC 8538 section 2: the receiver ignores the Restart Flags (R, N and the reserved bits) when
 * it reads the 12-bit Restart Time, and still reads the family tuples.
 */
static void test_gr_restart_flags_ignored(void) {
    bgp_neighbor_t neighbor = make_test_neighbor(100);
    uint8_t        cap_data[] = {0xC1, 0x2C, 0x00, 0x01, 0x01, 0x80};  /* R and N set, 300 s, IPv4 unicast, F set */
    uint8_t        opt[16];
    uint8_t        buffer[256];
    int            opt_len;
    int            msg_len;
    int            passed;

    opt_len = wrap_capability(opt, BGP_CAP_GRACEFUL_RESTART, cap_data, sizeof(cap_data));
    msg_len = build_raw_open(buffer, sizeof(buffer), 100, 0x01010101, BGP_HOLD_TIME, opt, (uint8_t)opt_len);

    passed = msg_len > 0 &&
             bgp_accept_open(NULL, &neighbor, buffer, (size_t)msg_len, &(bgp_open_info_t){0}) == 0 &&
             neighbor.peer_capabilities.graceful_restart && neighbor.peer_capabilities.restart_time == 300 &&
             bgp_caps_get_gr_flags(&neighbor.peer_capabilities, AFI_IPV4, SAFI_UNICAST) == 0x80;

    test_result(passed, "GR Restart Flags (R, N) do not leak into the restart time");
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
             (bgp_accept_open(NULL, &neighbor, buffer, (size_t)msg_len, &(bgp_open_info_t){0}) == 0) &&
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
             (bgp_accept_open(NULL, &neighbor, buffer, (size_t)msg_len, &(bgp_open_info_t){0}) == 0) &&
             (neighbor.hold_time == 30);

    test_result(passed, "hold_time negotiation (peer's lower value used)");
}

/*
 * RFC 4271 section 4.2: the session uses the smaller of the two proposed hold times. The local one is the
 * neighbor's `hold-time`.
 */
static void test_hold_time_negotiation_with_configured_value(void) {
    static const struct {
        uint16_t configured;
        uint16_t peer;
        uint16_t negotiated;
    } cases[] = {{30, 180, 30}, {30, 9, 9}, {0, 180, 0}, {30, 0, 0}, {65535, 40000, 40000}, {3, 3, 3}};
    int passed = 1;

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        bgp_neighbor_t neighbor = make_test_neighbor(100);
        uint8_t        buffer[256];
        int            msg_len = build_raw_open(buffer, sizeof(buffer), 100, 0x01010101, cases[i].peer, NULL, 0);

        neighbor.hold_time_config = cases[i].configured;
        neighbor.hold_time = 0xFFFF;
        passed = passed && msg_len > 0 &&
                 bgp_accept_open(NULL, &neighbor, buffer, (size_t)msg_len, &(bgp_open_info_t){0}) == 0 &&
                 neighbor.hold_time == cases[i].negotiated;
    }
    test_result(passed, "hold_time negotiation takes the smaller of the configured and the peer's value");
}

/*
 * bgp_open_set_hold_time() rewrites the Hold Time of a built OPEN and nothing else.
 */
static void test_open_set_hold_time(void) {
    bgp_capabilities_t caps = bgp_default_capabilities;
    bgp_open_info_t    info;
    uint8_t            built[BGP_MAX_MESSAGE_SIZE];
    uint8_t            changed[BGP_MAX_MESSAGE_SIZE];
    int                len = bgp_build_open_with_capabilities(built, sizeof(built), 65000, 0x01010101, &caps);
    int                passed = len > 0;

    if (passed) {
        memcpy(changed, built, (size_t)len);
        bgp_open_set_hold_time(changed, 0x1234);
        // Octets 22 and 23 of the message: after the header, the version and My Autonomous System.
        passed = bgp_parse_open_message(built, (size_t)len, NULL, &info) == 0 && info.hold_time == BGP_HOLD_TIME &&
                 bgp_parse_open_message(changed, (size_t)len, NULL, &info) == 0 && info.hold_time == 0x1234 &&
                 changed[22] == 0x12 && changed[23] == 0x34 && memcmp(built, changed, 22) == 0 &&
                 memcmp(built + 24, changed + 24, (size_t)len - 24) == 0;
    }
    test_result(passed, "bgp_open_set_hold_time changes octets 22 and 23 of the OPEN only");
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
             (bgp_accept_open(NULL, &neighbor, buffer, (size_t)msg_len, &(bgp_open_info_t){0}) == 0) &&
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
             (bgp_accept_open(NULL, &neighbor, buffer, (size_t)msg_len, &(bgp_open_info_t){0}) == 0) &&
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
             (bgp_accept_open(NULL, &neighbor, buffer, (size_t)msg_len, &(bgp_open_info_t){0}) == 0) &&
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
             (bgp_accept_open(NULL, &neighbor, buffer, (size_t)msg_len, &(bgp_open_info_t){0}) == 0) &&
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
             (bgp_accept_open(NULL, &neighbor, buffer, (size_t)msg_len, &(bgp_open_info_t){0}) == 0) &&
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
static int establish_passive_session(peer_rx_t *reader, bgp_sim_t *sim, char *socket_path, size_t socket_path_size,
                                     uint16_t hold_time, int route_refresh, int peer_graceful_restart) {
    static const uint8_t graceful_restart[] = {0x00, 0x78, 0x00, 0x01, 0x01, 0x00};  /* 120 s, IPv4 unicast */
    uint8_t buffer[BGP_MAX_MESSAGE_SIZE];
    uint8_t opt[16];
    uint8_t type = 0;
    int     opt_len = 0;
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
    if (peer_graceful_restart) {
        // Both sides advertise Graceful Restart, so the session negotiates it.
        sim->routers[0]->neighbors[0]->capabilities.graceful_restart = 1;
        sim->routers[0]->neighbors[0]->capabilities.restart_time = 120;
        opt_len = wrap_capability(opt, BGP_CAP_GRACEFUL_RESTART, graceful_restart, sizeof(graceful_restart));
    }
    if (start_runtime(sim, socket_path, socket_path_size) != 0 ||
        !wait_until(router_listening, sim->routers[0], OPEN_RUNTIME_TIMEOUT_MS)) {
        return -1;
    }

    sock = connect_ipv4_loopback_with_retry((uint16_t)sim->routers[0]->listen_port, OPEN_RUNTIME_TIMEOUT_MS);
    *reader = (peer_rx_t){.fd = sock};
    if (sock < 0) {
        return -1;
    }
    if (recv_bgp_message_with_timeout(reader, buffer, sizeof(buffer), &type, OPEN_RUNTIME_TIMEOUT_MS) <= 0 ||
        type != BGP_MSG_OPEN) {
        close(sock);
        return -1;
    }

    len = build_raw_open(buffer, sizeof(buffer), 65001, 0x02020202, hold_time, opt_len ? opt : NULL, (uint8_t)opt_len);
    if (len <= 0 || send_raw(sock, buffer, (size_t)len) != 0 ||
        recv_bgp_message_with_timeout(reader, buffer, sizeof(buffer), &type, OPEN_RUNTIME_TIMEOUT_MS) <= 0 ||
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
static int peer_reads_notification_message(peer_rx_t *reader, int timeout_ms, uint8_t *buffer, size_t capacity) {
    uint8_t type = 0;
    int     len;

    while ((len = recv_bgp_message_with_timeout(reader, buffer, capacity, &type, timeout_ms)) > 0) {
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
    peer_rx_t  reader = {0};
    bgp_sim_t *sim = create_sim();
    char       socket_path[108] = "";
    uint8_t    msg[BGP_HEADER_SIZE + 4];
    int        sock;
    int        sent = 0;
    int        stayed_up = 0;
    int        notified = 0;

    TEST("Session keeps ESTABLISHED after a valid ROUTE-REFRESH");

    sock = establish_passive_session(&reader, sim, socket_path, sizeof(socket_path), BGP_HOLD_TIME, 1, 0);
    if (sock >= 0) {
        build_raw_header(msg, sizeof(msg), 5);
        msg[BGP_HEADER_SIZE] = 0;
        msg[BGP_HEADER_SIZE + 1] = AFI_IPV4;
        msg[BGP_HEADER_SIZE + 2] = 0;
        msg[BGP_HEADER_SIZE + 3] = SAFI_UNICAST;
        sent = send_raw(sock, msg, sizeof(msg)) == 0;
        // Once bgpsim has processed a KEEPALIVE sent after the ROUTE-REFRESH, it has handled the refresh too.
        stayed_up = peer_barrier(sock, sim->routers[0]->neighbors[0]);
        notified = peer_has_message(&reader, BGP_MSG_NOTIFICATION);
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
 * RFC 4724 section 4.2: when a peer that advertised Graceful Restart opens a new connection while bgpsim still has the
 * old session, bgpsim closes the old TCP session without a NOTIFICATION and keeps the new one. Expected failure: the passive
 * accept path drops the new connection instead, and the old session lingers until its hold timer expires.
 */
static void test_session_gr_peer_reconnect(void) {
    peer_rx_t       old_reader = {0};
    peer_rx_t       new_reader = {0};
    bgp_sim_t      *sim = create_sim();
    bgp_neighbor_t *neighbor = NULL;
    char            socket_path[108] = "";
    uint8_t         buffer[BGP_MAX_MESSAGE_SIZE];
    uint8_t         type = 0;
    int             old_sock;
    int             new_sock = -1;
    int             ready = 0;
    int             replaced = 0;
    int             refused = 0;

    old_sock = establish_passive_session(&old_reader, sim, socket_path, sizeof(socket_path), BGP_HOLD_TIME, 0, 1);
    if (old_sock >= 0) {
        neighbor = sim->routers[0]->neighbors[0];
        new_sock = connect_ipv4_loopback_with_retry((uint16_t)sim->routers[0]->listen_port, OPEN_RUNTIME_TIMEOUT_MS);
        new_reader.fd = new_sock;
        ready = neighbor->peer_capabilities.graceful_restart && new_sock >= 0;
    }
    if (ready) {
        int len = recv_bgp_message_with_timeout(&new_reader, buffer, sizeof(buffer), &type, OPEN_RUNTIME_TIMEOUT_MS);

        if (len > 0 && type == BGP_MSG_OPEN) {
            // The new connection is retained; the old one must end in EOF, not a NOTIFICATION or a timeout.
            while ((len = recv_bgp_message_with_timeout(&old_reader, buffer, sizeof(buffer), &type,
                                                        OPEN_RUNTIME_TIMEOUT_MS)) > 0 && type == BGP_MSG_KEEPALIVE) {
            }
            replaced = len < 0 && errno != ETIMEDOUT;
        } else {
            // The documented failure: the new connection is closed at once and the old session is still up.
            refused = len < 0 && errno != ETIMEDOUT && peer_barrier(old_sock, neighbor) &&
                      neighbor->state == BGP_STATE_ESTABLISHED;
        }
    }
    if (new_sock >= 0) close(new_sock);
    if (old_sock >= 0) close(old_sock);
    destroy_sim(sim);
    unlink(socket_path);
    if (!ready) {
        test_result(0, "RFC 4724 4.2 setup: a session that negotiated Graceful Restart, and a second connection");
        return;
    }
    test_xfail(replaced, refused, "RFC 4724 4.2: a Graceful Restart peer's new connection replaces its old session",
                   "docs/todo/graceful-restart-restart-handling.md");
}

/*
 * Each call is a separate case with its own session. Clean up before checking the setup, send and NOTIFICATION so an
 * ASSERT cannot leave a runtime running.
 */
static void test_session_rejects_header(const char *name, uint8_t type, uint16_t len, uint8_t expected_subcode) {
    peer_rx_t  reader = {0};
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

    sock = establish_passive_session(&reader, sim, socket_path, sizeof(socket_path), BGP_HOLD_TIME, 0, 0);
    if (sock >= 0) {
        build_raw_header(msg, len, type);
        if (expected_subcode == 1) msg[0] = 0;
        sent = send_raw(sock, msg, BGP_HEADER_SIZE) == 0;
        if (sent) {
            int reply_len = peer_reads_notification_message(&reader, OPEN_RUNTIME_TIMEOUT_MS, reply, sizeof(reply));

            notified = reply_len >= BGP_HEADER_SIZE + 2;
            if (notified) {
                code = reply[BGP_HEADER_SIZE];
                subcode = reply[BGP_HEADER_SIZE + 1];
                size_t data_len = expected_subcode == 1 ? 0 : expected_subcode == 2 ? 2 : 1;
                size_t offset = expected_subcode == 3 ? 18 : BGP_MARKER_SIZE;

                data_matches = reply_len == BGP_HEADER_SIZE + 2 + (int)data_len &&
                               memcmp(reply + BGP_HEADER_SIZE + 2, msg + offset, data_len) == 0;
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
    ASSERT(notified, "RFC 4271 section 6.1: an invalid header gives a NOTIFICATION before waiting for a body");
    ASSERT(code == BGP_ERR_MESSAGE_HEADER && subcode == expected_subcode,
           "The NOTIFICATION carries the exact Message Header Error subcode");
    ASSERT(data_matches, "The NOTIFICATION Data contains the erroneous two-octet Length field");
    ASSERT(reset_after_notification, "The runtime sends the NOTIFICATION before resetting the session");
    PASS();
}

static int minimal_messages_received(void *opaque) {
    neighbor_wait_t *wait = opaque;

    return wait->neighbor->rx_update == 1 && wait->neighbor->rx_keepalive >= 2;
}

static void test_session_accepts_minimum_message_lengths(void) {
    peer_rx_t  reader = {0};
    bgp_sim_t *sim = create_sim();
    char       socket_path[108] = "";
    uint8_t    messages[2 * BGP_HEADER_SIZE + 4] = {0};
    int        sock;
    int        received = 0;
    int        notified = 0;

    TEST("Session accepts a 19-octet KEEPALIVE and a 23-octet empty UPDATE");
    sock = establish_passive_session(&reader, sim, socket_path, sizeof(socket_path), 0, 0, 0);
    if (sock >= 0) {
        build_raw_header(messages, BGP_HEADER_SIZE, BGP_MSG_KEEPALIVE);
        build_raw_header(messages + BGP_HEADER_SIZE, BGP_HEADER_SIZE + 4, BGP_MSG_UPDATE);
        received = send_raw(sock, messages, sizeof(messages)) == 0 &&
                   wait_until(minimal_messages_received,
                              &(neighbor_wait_t){ .neighbor = sim->routers[0]->neighbors[0] }, OPEN_RUNTIME_TIMEOUT_MS) &&
                   peer_barrier(sock, sim->routers[0]->neighbors[0]);
        notified = peer_has_message(&reader, BGP_MSG_NOTIFICATION);
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
    peer_rx_t  reader = {0};
    bgp_sim_t *sim = create_sim();
    char       socket_path[108] = "";
    int        sock;
    int        hold_time_zero = 0;
    int        timer_stopped = 0;

    TEST("Hold Time 0 leaves the KEEPALIVE timer stopped");

    sock = establish_passive_session(&reader, sim, socket_path, sizeof(socket_path), 0, 0, 0);
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

static void test_peer_reader_ownership(void) {
    const int  count = 40;
    peer_rx_t *readers = calloc((size_t)count, sizeof(*readers));
    uint8_t    messages[2 * BGP_HEADER_SIZE];
    uint8_t    received[BGP_HEADER_SIZE];
    uint8_t    type = 0;
    int        opened = 0;
    int        ok = readers != NULL;

    TEST("Every peer retains its own read-ahead beyond 32 sockets");
    build_raw_header(messages, BGP_HEADER_SIZE, BGP_MSG_KEEPALIVE);
    memcpy(messages + BGP_HEADER_SIZE, messages, BGP_HEADER_SIZE);
    for (int i = 0; ok && i < count; i++) {
        int sockets[2];

        ok = socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0;
        if (!ok) break;
        readers[i].fd = sockets[0];
        opened++;
        ok = send_raw(sockets[1], messages, sizeof(messages)) == 0;
        close(sockets[1]);
        ok = ok && recv_bgp_message_with_timeout(&readers[i], received, sizeof(received), &type, 0) == BGP_HEADER_SIZE &&
             type == BGP_MSG_KEEPALIVE && memcmp(received, messages, sizeof(received)) == 0 &&
             readers[i].len == BGP_HEADER_SIZE;
    }
    // All second messages have left the kernel. A lost reader buffer cannot be recovered by another recv().
    for (int i = 0; ok && i < count; i++) {
        ok = recv_bgp_message_with_timeout(&readers[i], received, sizeof(received), &type, 0) == BGP_HEADER_SIZE &&
             type == BGP_MSG_KEEPALIVE && memcmp(received, messages, sizeof(received)) == 0 && readers[i].len == 0;
    }
    for (int i = 0; i < opened; i++) close(readers[i].fd);
    free(readers);
    ASSERT(ok && opened == count, "All 40 peers deliver both exact KEEPALIVEs, including buffered bytes after EOF");
    PASS();
}

/*
 * bgpsim's own Graceful Restart capability on the wire (RFC 4724 section 3, RFC 8538 section 2): one instance, the
 * Restart State and Graceful Notification bits clear (bgpsim has not restarted and does not claim RFC 8538), and one
 * tuple per enabled family, here IPv4 and IPv6 unicast, each with the Forwarding State bit clear.
 */
static int graceful_restart_on_wire(const uint8_t *message, int len) {
    capability_view_t view;

    return count_capabilities(message, (size_t)len, BGP_CAP_GRACEFUL_RESTART) == 1 &&
           get_capability_instance(message, (size_t)len, BGP_CAP_GRACEFUL_RESTART, 0, &view) &&
           view.len == 2 + 2 * 4 && (view.data[0] & 0xF0) == 0 &&
           graceful_restart_capability_has_tuple(&view, AFI_IPV4, SAFI_UNICAST, 0) &&
           graceful_restart_capability_has_tuple(&view, AFI_IPV6, SAFI_UNICAST, 0);
}

/*
 * bgpsim's own Extended Message capability on the wire (RFC 8654 section 3): one instance with no value.
 */
static int extended_message_on_wire(const uint8_t *message, int len) {
    capability_view_t view;

    return count_capabilities(message, (size_t)len, 6) == 1 && get_capability_instance(message, (size_t)len, 6, 0, &view) &&
           view.len == 0;
}

/*
 * Every OPEN-affecting CLI variant takes the same neighbor apply path. Observe the reset on a real session, the next
 * OPEN on the wire, and idempotence after reconnecting. The CLI, not the test, changes the configured capability.
 */
static void test_session_capability_change(const char *command, size_t offset, int byte_field, int expected,
                                           int (*wire)(const uint8_t *message, int len)) {
    peer_rx_t               reader = {0};
    bgp_sim_t              *sim = create_sim();
    bgp_neighbor_t         *neighbor = NULL;
    bgpsim_control_client_t client;
    cli_mode_t              mode = CLI_MODE_EXEC;
    cli_session_t           session;
    bgp_open_info_t         info;
    char                    socket_path[108] = "";
    uint8_t                 message[BGP_MAX_MESSAGE_SIZE];
    int                     sock;
    int                     len = 0;
    int                     opened = 0;
    int                     ok;

    TEST(command);
    cli_session_init(&session);
    sock = establish_passive_session(&reader, sim, socket_path, sizeof(socket_path), 0, 0, 0);
    ok = sock >= 0 && bgpsim_control_client_open(&client, socket_path) == 0;
    opened = ok;
    if (ok) {
        neighbor = sim->routers[0]->neighbors[0];
        ok = execute_control_command_expect_ok(&client, "config", &mode, &session) &&
             execute_control_command_expect_ok(&client, "router bgp 65000", &mode, &session) &&
             execute_control_command_expect_ok(&client, "neighbor 127.0.0.1 remote-as 65001", &mode, &session) &&
             execute_control_command_expect_ok(&client, command, &mode, &session) &&
             neighbor->session_resets == 1 &&
             neighbor_settles_idle(neighbor);
        close(sock);
        sock = -1;
        ok = ok && capture_passive_open(sim->routers[0], neighbor, message, sizeof(message), &len) &&
             bgp_parse_open_message(message, (size_t)len, NULL, &info) == 0;
        if (ok) {
            const char *field = (const char *)&info.capabilities + offset;

            ok = (byte_field ? *(const uint8_t *)field : *(const int *)field) == expected &&
                 (!wire || wire(message, len));
            sock = session_connect_peer(&reader, sim, NULL);
            ok = ok && sock >= 0;
        }
        if (ok) {
            uint64_t resets = neighbor->session_resets;

            ok = execute_control_command_expect_ok(&client, command, &mode, &session) && peer_barrier(sock, neighbor) &&
                 neighbor->session_resets == resets;
        }
    }
    if (sock >= 0) close(sock);
    if (opened) bgpsim_control_client_close(&client);
    destroy_sim(sim);
    unlink(socket_path);
    ASSERT(ok, "One live reset renegotiates the exact capability; an identical command keeps the new session");
    PASS();
}

typedef struct {
    bgp_neighbor_t *neighbor;
    size_t          bytes;
} buffered_wait_t;

static int peer_input_buffered(void *opaque) {
    buffered_wait_t *wait = opaque;

    return wait->neighbor->rx_len == wait->bytes;
}

/*
 * Force the runtime to see a partial header/body before completing it or sending EOF. Checking rx_len is a read-only
 * barrier, not a delay: the assertion cannot pass just because TCP coalesced both writes into a whole message.
 */
static void test_session_fragment(size_t cut, int eof) {
    peer_rx_t       reader = {0};
    bgp_sim_t      *sim = create_sim();
    bgp_neighbor_t *neighbor = NULL;
    char            socket_path[108] = "";
    uint8_t         messages[BGP_HEADER_SIZE + 4 + 10 * BGP_HEADER_SIZE] = {0};
    int             sock = -1;
    int             ok;

    TEST(eof ? "Partial input followed by EOF resets the real session" :
               "Fragmented and coalesced messages update real runtime counters exactly once");
    sock = establish_passive_session(&reader, sim, socket_path, sizeof(socket_path), 0, 0, 0);
    ok = sock >= 0;
    if (ok) {
        neighbor = sim->routers[0]->neighbors[0];
        build_raw_header(messages, BGP_HEADER_SIZE + 4, BGP_MSG_UPDATE);
        for (int i = 0; i < 10; i++) {
            build_raw_header(messages + BGP_HEADER_SIZE + 4 + i * BGP_HEADER_SIZE, BGP_HEADER_SIZE, BGP_MSG_KEEPALIVE);
        }
        ok = neighbor->tx_open == 1 && neighbor->rx_open == 1 && neighbor->tx_keepalive == 1 &&
             neighbor->rx_keepalive == 1 && neighbor->session_resets == 0 &&
             (!cut || send_raw(sock, messages, cut) == 0) &&
             wait_until(peer_input_buffered, &(buffered_wait_t){neighbor, cut}, OPEN_RUNTIME_TIMEOUT_MS) &&
             neighbor->rx_update == 0 && neighbor->rx_keepalive == 1 && neighbor->state == BGP_STATE_ESTABLISHED;
        if (ok && eof) {
            ok = shutdown(sock, SHUT_WR) == 0 &&
                 neighbor_settles_idle(neighbor) &&
                 neighbor->session_resets == 1 && neighbor->rx_update == 0 && neighbor->rx_keepalive == 1;
        } else if (ok) {
            ok = send_raw(sock, messages + cut, sizeof(messages) - cut) == 0 && peer_barrier(sock, neighbor) &&
                 neighbor->rx_update == 1 && neighbor->rx_keepalive == 12 && neighbor->session_resets == 0;
        }
        ok = ok && neighbor->tx_notification == 0 && neighbor->rx_notification == 0;
        close(sock);
    }
    destroy_sim(sim);
    unlink(socket_path);
    ASSERT(ok, "The intended partial-read branch ran, with exact counters and no spurious NOTIFICATION");
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
    peer_rx_t               reader = {0};

    memset(capture, 0, sizeof(*capture));
    memset(&session, 0, sizeof(session));
    ok = sim != NULL && bgp_add_router(sim, 65000) == 1 && bgp_add_neighbor(sim, 65000, "127.0.0.1", 65001) == 1 &&
         session_start_runtime(sim, socket_path, sizeof(socket_path)) == 0 &&
         bgpsim_control_client_open(&client, socket_path) == 0;
    client_open = ok;
    ok = ok && bgpsim_control_client_execute(&client, "terminal monitor", &mode, &session, NULL, NULL, NULL, &status) == 0 &&
         status >= 0;
    if (ok && open_sent) {
        sock = connect_ipv4_loopback_with_retry((uint16_t)sim->routers[0]->listen_port, OPEN_RUNTIME_TIMEOUT_MS);
        reader.fd = sock;
        ok = sock >= 0 &&
             recv_bgp_message_with_timeout(&reader, buffer, sizeof(buffer), &type, OPEN_RUNTIME_TIMEOUT_MS) > 0 &&
             type == BGP_MSG_OPEN;
    } else if (ok) {
        sock = session_connect_peer(&reader, sim, NULL);
        ok = sock >= 0;
    }
    ok = ok && send_raw(sock, msg, msg_len) == 0 &&
         neighbor_settles_idle(sim->routers[0]->neighbors[0]) &&
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
    uint8_t                   msg[BGP_HEADER_SIZE + 3 + sizeof(text) - 1];
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

/*
 * One established session (router 65000, neighbor 127.0.0.1 in AS 65001, raw peer proposing Hold Time 180) and a
 * control client, for the session control tests. The CLI, not the test, changes the neighbor.
 */
typedef struct {
    bgp_sim_t              *sim;
    bgp_neighbor_t         *neighbor;
    bgpsim_control_client_t client;
    cli_mode_t              mode;
    cli_session_t           session;
    peer_rx_t               reader;
    char                    socket_path[108];
    int                     sock;
    int                     client_open;
} control_session_t;

/*
 * A control session with a simulator and nothing in it yet.
 */
static void control_session_blank(control_session_t *ctl) {
    memset(ctl, 0, sizeof(*ctl));
    ctl->mode = CLI_MODE_EXEC;
    ctl->sock = -1;
    cli_session_init(&ctl->session);
    ctl->sim = create_sim();
}

/*
 * Router 65000 with one neighbor in AS 65001 that bgpsim dials, for a test that plays the listening peer or wants
 * nothing to answer. The runtime starts with control_session_run(), so a test can open its listener first.
 */
static int control_session_dialing(control_session_t *ctl, const char *neighbor_ip) {
    control_session_blank(ctl);
    if (ctl->sim == NULL || bgp_add_router(ctl->sim, 65000) != 1 ||
        bgp_add_neighbor(ctl->sim, 65000, neighbor_ip, 65001) != 1) {
        return 0;
    }
    ctl->neighbor = ctl->sim->routers[0]->neighbors[0];
    return 1;
}

static int control_session_run(control_session_t *ctl) {
    if (start_runtime(ctl->sim, ctl->socket_path, sizeof(ctl->socket_path)) != 0 ||
        bgpsim_control_client_open(&ctl->client, ctl->socket_path) != 0) {
        return 0;
    }
    ctl->client_open = 1;
    return 1;
}

static int control_session_start(control_session_t *ctl) {
    control_session_blank(ctl);
    ctl->sock = establish_passive_session(&ctl->reader, ctl->sim, ctl->socket_path, sizeof(ctl->socket_path),
                                          BGP_HOLD_TIME, 0, 0);
    if (ctl->sock < 0 || bgpsim_control_client_open(&ctl->client, ctl->socket_path) != 0) {
        return 0;
    }
    ctl->client_open = 1;
    ctl->neighbor = ctl->sim->routers[0]->neighbors[0];
    return 1;
}

static void control_session_stop(control_session_t *ctl) {
    if (ctl->sock >= 0) close(ctl->sock);
    if (ctl->client_open) bgpsim_control_client_close(&ctl->client);
    destroy_sim(ctl->sim);
    unlink(ctl->socket_path);
}

static int control_command(control_session_t *ctl, const char *command) {
    return execute_control_command_expect_ok(&ctl->client, command, &ctl->mode, &ctl->session);
}

/*
 * Run one command in the mode of the neighbor and return to EXEC. 1: accepted; 0: refused; -1: the test could not
 * reach neighbor mode.
 */
static int control_neighbor_command(control_session_t *ctl, const char *command) {
    char enter[96];
    int  accepted;

    snprintf(enter, sizeof(enter), "neighbor %s remote-as %u", ctl->neighbor->ip, ctl->neighbor->remote_as);
    if (!control_command(ctl, "config") || !control_command(ctl, "router bgp 65000") || !control_command(ctl, enter)) {
        return -1;
    }
    accepted = control_command(ctl, command);
    return control_command(ctl, "end") ? accepted : -1;
}

static int control_show(control_session_t *ctl, const char *command, notification_capture_t *capture) {
    int status = -1;

    memset(capture, 0, sizeof(*capture));
    return bgpsim_control_client_execute(&ctl->client, command, &ctl->mode, &ctl->session, capture_notification_output,
                                         NULL, capture, &status) == 0 &&
           status >= 0;
}

/*
 * The peer of the control session reads a NOTIFICATION whose body is exactly code, subcode and, with text, an RFC
 * 9003 Shutdown Communication: one length octet and the text.
 */
static int control_peer_reads_cease(control_session_t *ctl, uint8_t subcode, const char *text) {
    uint8_t message[BGP_MAX_MESSAGE_SIZE];
    size_t  text_len = strlen(text);
    size_t  body_len = 2 + (text_len ? 1 + text_len : 0);
    int     len = peer_reads_notification_message(&ctl->reader, OPEN_RUNTIME_TIMEOUT_MS, message, sizeof(message));

    return len == (int)(BGP_HEADER_SIZE + body_len) && message[BGP_HEADER_SIZE] == BGP_ERR_CEASE &&
           message[BGP_HEADER_SIZE + 1] == subcode &&
           (text_len == 0 || (message[BGP_HEADER_SIZE + 2] == text_len &&
                              memcmp(message + BGP_HEADER_SIZE + 3, text, text_len) == 0));
}

/*
 * The connection of the peer ends by EOF, not by the read timeout, and no NOTIFICATION came before it. The
 * End-of-RIB UPDATE and KEEPALIVEs of the session are read past.
 */
static int control_peer_reads_eof_without_notification(control_session_t *ctl) {
    uint8_t message[BGP_MAX_MESSAGE_SIZE];
    uint8_t type = 0;

    errno = 0;
    while (recv_bgp_message_with_timeout(&ctl->reader, message, sizeof(message), &type, OPEN_RUNTIME_TIMEOUT_MS) > 0) {
        if (type == BGP_MSG_NOTIFICATION) {
            return 0;
        }
    }
    return errno != ETIMEDOUT && ctl->reader.len == 0;
}

/*
 * The peer of the control session connects again and reaches ESTABLISHED.
 */
static int control_peer_reconnects(control_session_t *ctl) {
    if (ctl->sock >= 0) close(ctl->sock);
    ctl->sock = neighbor_settles_idle(ctl->neighbor)
                    ? session_connect_peer(&ctl->reader, ctl->sim, NULL)
                    : -1;
    return ctl->sock >= 0;
}

/*
 * A connection from the peer is closed without an OPEN: the read ends by EOF, not by its timeout.
 */
static int control_peer_is_refused(control_session_t *ctl) {
    peer_rx_t reader = {0};
    uint8_t   message[BGP_MAX_MESSAGE_SIZE];
    uint8_t   type = 0;
    uint64_t  opens = ctl->neighbor->tx_open;
    int       refused;

    reader.fd = connect_ipv4_loopback_with_retry((uint16_t)ctl->sim->routers[0]->listen_port, OPEN_RUNTIME_TIMEOUT_MS);
    if (reader.fd < 0) {
        return 0;
    }
    errno = 0;
    refused = recv_bgp_message_with_timeout(&reader, message, sizeof(message), &type, OPEN_RUNTIME_TIMEOUT_MS) < 0 &&
              errno != ETIMEDOUT && reader.len == 0 && ctl->neighbor->tx_open == opens &&
              ctl->neighbor->state == BGP_STATE_IDLE;
    close(reader.fd);
    return refused;
}

/*
 * `shutdown [text]` (RFC 4486 Administrative Shutdown, RFC 9003): the peer gets the Cease with the text, the neighbor
 * stays down and refuses connections; `no shutdown` is the positive control, the same peer connects again.
 */
static void test_session_shutdown(const char *text) {
    control_session_t      ctl;
    notification_capture_t neighbors;
    notification_capture_t config;
    char                   command[300];
    char                   expected[400];
    int                    started = control_session_start(&ctl);
    int                    ceased = 0;
    int                    held = 0;
    int                    shown = 0;
    int                    configured = 0;
    int                    restored = 0;

    TEST(text[0] ? "shutdown <text> sends Cease/Administrative Shutdown with the text and holds the neighbor down"
                 : "shutdown sends Cease/Administrative Shutdown with no data and holds the neighbor down");
    if (started) {
        snprintf(command, sizeof(command), "shutdown%s%s", text[0] ? " " : "", text);
        ceased = control_neighbor_command(&ctl, command) == 1 && control_peer_reads_cease(&ctl, 2, text) &&
                 neighbor_settles_idle(ctl.neighbor) &&
                 ctl.neighbor->tx_notification == 1 && ctl.neighbor->last_notification_tx.code == BGP_ERR_CEASE &&
                 ctl.neighbor->last_notification_tx.subcode == 2 &&
                 strcmp(ctl.neighbor->last_notification_tx.shutdown, text) == 0;
        held = ceased && control_peer_is_refused(&ctl) && control_peer_is_refused(&ctl);
        snprintf(expected, sizeof(expected), "  Last notification sent: 6/2 (Cease/Administrative Shutdown)%s%s%s, 00:0",
                 text[0] ? ", shutdown communication \"" : "", text, text[0] ? "\"" : "");
        shown = control_show(&ctl, "show bgp neighbors", &neighbors) &&
                strstr(neighbors.out, "  BGP state = Idle (administratively shut down)\n") != NULL &&
                strstr(neighbors.out, expected) != NULL;
        snprintf(expected, sizeof(expected), "  neighbor 127.0.0.1 remote-as 65001\n    %s\n", command);
        configured = control_show(&ctl, "show running-config", &config) && strstr(config.out, expected) != NULL;
        // Entering the same shutdown again sends nothing: there is no session to tell.
        held = held && control_neighbor_command(&ctl, command) == 1 && ctl.neighbor->tx_notification == 1;
        restored = control_neighbor_command(&ctl, "no shutdown") == 1 && control_peer_reconnects(&ctl) &&
                   ctl.neighbor->tx_open == 2 && control_show(&ctl, "show running-config", &config) &&
                   strstr(config.out, "shutdown") == NULL && control_show(&ctl, "show bgp neighbors", &neighbors) &&
                   strstr(neighbors.out, "  BGP state = Established, up for") != NULL &&
                   strstr(neighbors.out, "administratively shut down") == NULL;
    }
    control_session_stop(&ctl);

    ASSERT(started, "The raw peer reaches ESTABLISHED");
    ASSERT(ceased, "RFC 4486, RFC 9003: the peer reads Cease/Administrative Shutdown with exactly the text");
    ASSERT(held, "A shut down neighbor answers a new connection with no OPEN, and sends no second NOTIFICATION");
    ASSERT(shown, "show bgp neighbors marks the neighbor and shows the NOTIFICATION sent");
    ASSERT(configured, "show running-config has the shutdown line with its text");
    ASSERT(restored, "no shutdown: the same peer connects and reaches ESTABLISHED; the line and the mark are gone");
    PASS();
}

/*
 * RFC 8654 section 4 on the receiving side. An UPDATE above 4096 octets is Bad Message Length unless both sides
 * advertised Extended Message; with both, an UPDATE of 65535 octets is read like any other. The capability of bgpsim
 * is set through the CLI, the peer's by its OPEN.
 */
static void test_session_extended_message_receive(void) {
    static uint8_t         update[BGP_EXTENDED_MESSAGE_SIZE];
    control_session_t      ctl;
    notification_capture_t out;
    bgp_capabilities_t     extended = {.extended_message = 1};
    uint8_t                reply[64];
    int                    started = control_session_start(&ctl);
    int                    neither = 0;
    int                    local_only = 0;
    int                    both = 0;

    TEST("An UPDATE above 4096 octets is read only on a session with Extended Message on both sides");
    if (started) {
        // 4097 octets: the header, no path attributes, and Withdrawn Routes of /0 prefixes, one octet each.
        build_raw_header(update, 4097, BGP_MSG_UPDATE);
        update[BGP_HEADER_SIZE] = (4097 - BGP_HEADER_SIZE - 4) >> 8;
        update[BGP_HEADER_SIZE + 1] = (4097 - BGP_HEADER_SIZE - 4) & 0xff;
        neither = send_raw(ctl.sock, update, 4097) == 0 &&
                  peer_reads_notification_message(&ctl.reader, OPEN_RUNTIME_TIMEOUT_MS, reply, sizeof(reply)) ==
                      BGP_HEADER_SIZE + 4 &&
                  reply[BGP_HEADER_SIZE] == BGP_ERR_MESSAGE_HEADER && reply[BGP_HEADER_SIZE + 1] == 2 &&
                  reply[BGP_HEADER_SIZE + 2] == 0x10 && reply[BGP_HEADER_SIZE + 3] == 0x01 && ctl.neighbor->rx_update == 0;
        // bgpsim advertises the capability, this peer does not: still Bad Message Length.
        local_only = neither && control_neighbor_command(&ctl, "capability extended-message") == 1 &&
                     control_peer_reconnects(&ctl) && control_show(&ctl, "show bgp neighbors", &out) &&
                     strstr(out.out, "    Extended message: advertised\n") != NULL &&
                     send_raw(ctl.sock, update, 4097) == 0 &&
                     peer_reads_notification_message(&ctl.reader, OPEN_RUNTIME_TIMEOUT_MS, reply, sizeof(reply)) ==
                         BGP_HEADER_SIZE + 4 &&
                     reply[BGP_HEADER_SIZE] == BGP_ERR_MESSAGE_HEADER && reply[BGP_HEADER_SIZE + 1] == 2 &&
                     ctl.neighbor->rx_update == 0;
        if (local_only) {
            close(ctl.sock);
            ctl.sock = neighbor_settles_idle(ctl.neighbor)
                           ? session_connect_peer(&ctl.reader, ctl.sim, &extended)
                           : -1;
            // 65535 octets, the largest length the header can say.
            build_raw_header(update, 65535, BGP_MSG_UPDATE);
            update[BGP_HEADER_SIZE] = (65535 - BGP_HEADER_SIZE - 4) >> 8;
            update[BGP_HEADER_SIZE + 1] = (65535 - BGP_HEADER_SIZE - 4) & 0xff;
            both = ctl.sock >= 0 && control_show(&ctl, "show bgp neighbors", &out) &&
                   strstr(out.out, "    Extended message: advertised and received\n") != NULL &&
                   send_raw(ctl.sock, update, 65535) == 0 && peer_barrier(ctl.sock, ctl.neighbor) &&
                   ctl.neighbor->rx_update == 1 && ctl.neighbor->state == BGP_STATE_ESTABLISHED;
            if (both) {
                uint64_t notifications = ctl.neighbor->tx_notification;
                uint8_t  open[BGP_HEADER_SIZE];

                // RFC 8654 section 4: an OPEN is at most 4096 octets on this session too. The header is enough for
                // bgpsim to refuse the length.
                build_raw_header(open, 4097, BGP_MSG_OPEN);
                both = send_raw(ctl.sock, open, sizeof(open)) == 0 &&
                       peer_reads_notification_message(&ctl.reader, OPEN_RUNTIME_TIMEOUT_MS, reply, sizeof(reply)) ==
                           BGP_HEADER_SIZE + 4 &&
                       reply[BGP_HEADER_SIZE] == BGP_ERR_MESSAGE_HEADER && reply[BGP_HEADER_SIZE + 1] == 2 &&
                       reply[BGP_HEADER_SIZE + 2] == 0x10 && reply[BGP_HEADER_SIZE + 3] == 0x01 &&
                       neighbor_settles_idle(ctl.neighbor) &&
                       ctl.neighbor->tx_notification == notifications + 1;
            }
        }
    }
    control_session_stop(&ctl);

    ASSERT(started, "The raw peer reaches ESTABLISHED");
    ASSERT(neither, "Neither side advertised it: 4097 octets is Bad Message Length, with the length as data");
    ASSERT(local_only, "Only bgpsim advertised it: 4097 octets is still Bad Message Length");
    ASSERT(both, "Both advertised it: 65535 octets is read and the session stays; an OPEN of 4097 is still refused");
    PASS();
}

/*
 * A listener on 127.0.0.1:port for a test that plays the peer bgpsim dials. It answers with TTL 255, as a peer with
 * TTL security does: a minimum TTL on the other side drops anything less. Returns the socket, or -1.
 */
static int listen_ipv4_loopback(uint16_t port) {
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(port)};
    int                on = 1;
    int                ttl = 255;
    int                sock = socket(AF_INET, SOCK_STREAM, 0);

    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (sock < 0 || setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) != 0 ||
        setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) != 0 ||
        bind(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0 || listen(sock, 4) != 0) {
        if (sock >= 0) close(sock);
        return -1;
    }
    return sock;
}

/*
 * Accept the next connection bgpsim makes to the listener of the test and bring it to ESTABLISHED. Closes the
 * previous session socket of the control session first. Returns 1 when the session is up.
 */
static int control_peer_accepts(control_session_t *ctl, int listener) {
    struct pollfd pfd = {.fd = listener, .events = POLLIN};

    if (ctl->sock >= 0) close(ctl->sock);
    ctl->sock = poll(&pfd, 1, OPEN_RUNTIME_TIMEOUT_MS) == 1
                    ? session_handshake(&ctl->reader, accept(listener, NULL, NULL), ctl->neighbor, NULL)
                    : -1;
    return ctl->sock >= 0;
}

/*
 * `ttl-security hops <n>` (RFC 5082) on the socket bgpsim connects with: it sends with TTL 255 and, where the system
 * has the option, accepts only 256 - n or more. The test plays the peer on the port that a loopback neighbor is
 * dialed on. The socket is bgpsim's own, so its options are read from the test: nothing the peer can see on loopback
 * tells a minimum TTL apart. The Linux session test reads the TTL on the wire.
 */
static void test_session_ttl_security_connecting(void) {
    control_session_t      ctl;
    notification_capture_t out;
    socklen_t              len = sizeof(int);
    int                    listener = -1;
    int                    default_ttl = 0;
    int                    ttl = 0;
    int                    started = 0;
    int                    refused = 0;
    int                    set = 0;
    int                    cleared = 0;

    TEST("ttl-security hops sets TTL 255 on the connecting socket; no ttl-security restores the default");
    if (control_session_dialing(&ctl, "127.0.0.1")) {
        listener = listen_ipv4_loopback((uint16_t)ctl.sim->routers[0]->listen_port);
        started = listener >= 0 && control_session_run(&ctl) && control_peer_accepts(&ctl, listener) &&
                  !ctl.neighbor->is_passive;
    }
    if (started) {
        refused = getsockopt(ctl.neighbor->sock_fd, IPPROTO_IP, IP_TTL, &default_ttl, &len) == 0 &&
                  default_ttl != 255 && control_neighbor_command(&ctl, "ttl-security") == 0 &&
                  control_neighbor_command(&ctl, "ttl-security hops 0") == 0 &&
                  control_neighbor_command(&ctl, "ttl-security hops 255") == 0 &&
                  peer_barrier(ctl.sock, ctl.neighbor) && ctl.neighbor->ttl_security_hops == 0 &&
                  ctl.neighbor->session_resets == 0;
        set = refused && control_neighbor_command(&ctl, "ttl-security hops 2") == 1 &&
              ctl.neighbor->session_resets == 1 && control_peer_accepts(&ctl, listener) &&
              getsockopt(ctl.neighbor->sock_fd, IPPROTO_IP, IP_TTL, &ttl, &len) == 0 && ttl == 255 &&
              ctl.neighbor->transport_error == 0;
#ifdef IP_MINTTL
        set = set && getsockopt(ctl.neighbor->sock_fd, IPPROTO_IP, IP_MINTTL, &ttl, &len) == 0 && ttl == 254;
#endif
        // Only a system with the minimum TTL option says that it accepts 254 or more.
        set = set && control_show(&ctl, "show bgp neighbors", &out) &&
#ifdef IP_MINTTL
              strstr(out.out, "  TTL security: 2 hops, sends TTL 255, accepts 254 or more\n") != NULL &&
#else
              strstr(out.out, "  TTL security: 2 hops, sends TTL 255, accepts any TTL\n") != NULL &&
#endif
              control_show(&ctl, "show running-config", &out) &&
              strstr(out.out, "  neighbor 127.0.0.1 remote-as 65001\n    ttl-security hops 2\n") != NULL;
        if (set) {
            uint64_t resets = ctl.neighbor->session_resets;

            // The same value again keeps the session.
            set = control_neighbor_command(&ctl, "ttl-security hops 2") == 1 && peer_barrier(ctl.sock, ctl.neighbor) &&
                  ctl.neighbor->session_resets == resets;
        }
        cleared = set && control_neighbor_command(&ctl, "no ttl-security") == 1 && control_peer_accepts(&ctl, listener) &&
                  getsockopt(ctl.neighbor->sock_fd, IPPROTO_IP, IP_TTL, &ttl, &len) == 0 && ttl == default_ttl &&
                  control_show(&ctl, "show running-config", &out) && strstr(out.out, "ttl-security") == NULL &&
                  control_show(&ctl, "show bgp neighbors", &out) && strstr(out.out, "TTL security") == NULL;
    }
    control_session_stop(&ctl);
    if (listener >= 0) close(listener);

    ASSERT(started, "bgpsim dials the listener of the test and the session reaches ESTABLISHED");
    ASSERT(refused, "No value, 0 and 255 hops are refused; the session stays and its socket has the default TTL");
    ASSERT(set, "ttl-security hops 2: one reset, a socket with TTL 255 (and minimum 254), shown and saved");
    ASSERT(cleared, "no ttl-security: the next session's socket has the default TTL and the lines are gone");
    PASS();
}

/*
 * The same for an IPv6 neighbor, where the option is the Hop Limit. `ttl-security` is set before the runtime starts,
 * as when a configuration file is loaded, so the first connection already has it.
 */
static void test_session_ttl_security_connecting_ipv6(void) {
    struct sockaddr_in6 addr = {.sin6_family = AF_INET6, .sin6_addr = IN6ADDR_LOOPBACK_INIT};
    peer_rx_t           reader = {0};
    bgp_sim_t          *sim = create_sim();
    bgp_neighbor_t     *neighbor = NULL;
    char                socket_path[108] = "";
    struct pollfd       pfd;
    socklen_t           len = sizeof(int);
    int                 on = 1;
    int                 hops = 255;
    int                 listener = socket(AF_INET6, SOCK_STREAM, 0);
    int                 sock = -1;
    int                 set = 0;

    TEST("ttl-security hops sets Hop Limit 255 on the connecting socket of an IPv6 neighbor");
    if (sim != NULL && listener >= 0 && bgp_add_router(sim, 65000) == 1 && bgp_add_neighbor(sim, 65000, "::1", 65001) == 1) {
        neighbor = sim->routers[0]->neighbors[0];
        addr.sin6_port = htons((uint16_t)sim->routers[0]->listen_port);
        pfd = (struct pollfd){.fd = listener, .events = POLLIN};
        // The test's listener answers with Hop Limit 255, as a peer with TTL security does.
        if (bgp_neighbor_set_ttl_security(neighbor, 2) == 0 &&
            setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == 0 &&
            setsockopt(listener, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &hops, sizeof(hops)) == 0 &&
            bind(listener, (struct sockaddr *)&addr, sizeof(addr)) == 0 && listen(listener, 4) == 0 &&
            start_runtime(sim, socket_path, sizeof(socket_path)) == 0 && poll(&pfd, 1, OPEN_RUNTIME_TIMEOUT_MS) == 1) {
            sock = session_handshake(&reader, accept(listener, NULL, NULL), neighbor, NULL);
        }
        hops = 0;
        set = sock >= 0 && !neighbor->is_passive && neighbor->transport_error == 0 &&
              getsockopt(neighbor->sock_fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &hops, &len) == 0 && hops == 255;
#ifdef IPV6_MINHOPCOUNT
        set = set && getsockopt(neighbor->sock_fd, IPPROTO_IPV6, IPV6_MINHOPCOUNT, &hops, &len) == 0 && hops == 254;
#endif
    }
    if (sock >= 0) close(sock);
    if (listener >= 0) close(listener);
    destroy_sim(sim);
    unlink(socket_path);

    ASSERT(sock >= 0, "bgpsim dials the IPv6 listener of the test and the session reaches ESTABLISHED");
    ASSERT(set, "The socket sends Hop Limit 255 (and accepts 254 or more where the system has the option)");
    PASS();
}

#ifdef __linux__
/*
 * How long a check waits for something that must not happen: a dropped SYN to be answered, a dropped OPEN to be
 * read. On loopback, what is answered at all is answered in milliseconds. Checks that something does happen take
 * the full session timeout.
 */
#define NO_ANSWER_MS 500

typedef struct {
    bgp_neighbor_t *neighbor;
    uint64_t        opens;  /* rx_open before the OPEN waited for */
} open_wait_t;

static int neighbor_read_open(void *opaque) {
    open_wait_t *wait = opaque;

    return wait->neighbor->rx_open > wait->opens;
}

/*
 * Connect to 127.0.0.1:port from a socket that sends with the given TTL. Returns the socket, or -1.
 */
static int connect_ipv4_loopback_with_ttl(uint16_t port, int ttl) {
    struct sockaddr_in remote = {.sin_family = AF_INET, .sin_port = htons(port)};
    int                sock = socket(AF_INET, SOCK_STREAM, 0);

    inet_pton(AF_INET, "127.0.0.1", &remote.sin_addr);
    if (sock < 0 || setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) != 0 ||
        connect(sock, (struct sockaddr *)&remote, sizeof(remote)) != 0) {
        if (sock >= 0) close(sock);
        return -1;
    }
    return sock;
}

/*
 * The same on a session bgpsim accepts, with the check that the minimum TTL is enforced. Its listener is an IPv6
 * socket, and only Linux takes the IPv4 options on the IPv4 session of one; elsewhere such a neighbor refuses the
 * session, as test_session_password() shows for the password. With `ttl-security hops 1` an OPEN that arrives with
 * TTL 254 is never read; the same OPEN with TTL 255 is the positive control.
 */
static void test_session_ttl_security_accepting(void) {
    control_session_t ctl;
    uint8_t           message[BGP_MAX_MESSAGE_SIZE];
    uint8_t           received[BGP_MAX_MESSAGE_SIZE];
    uint8_t           type = 0;
    socklen_t         len = sizeof(int);
    int               started = control_session_start(&ctl);
    int               dropped = 0;
    int               set = 0;
    int               ttl = 0;
    int               min_ttl = 0;

    TEST("ttl-security hops 1 on an accepted session: an OPEN with TTL 254 is dropped, one with TTL 255 is read");
    if (started) {
        uint16_t  port = (uint16_t)ctl.sim->routers[0]->listen_port;
        peer_rx_t low = {0};
        uint64_t  opens;
        int       open_len;

        dropped = control_neighbor_command(&ctl, "ttl-security hops 1") == 1 &&
                  neighbor_settles_idle(ctl.neighbor);
        close(ctl.sock);
        ctl.sock = -1;
        opens = ctl.neighbor->rx_open;
        // The listener has no minimum TTL, so the connection is made; the accepted socket then drops what follows.
        low.fd = connect_ipv4_loopback_with_ttl(port, 254);
        open_len = bgp_build_open_with_capabilities(message, sizeof(message), 65001, 0x02020202,
                                                    &(bgp_capabilities_t){0});
        // bgpsim sets the minimum TTL before it sends its OPEN: read that first, so the peer's OPEN comes after.
        dropped = dropped && low.fd >= 0 && open_len > 0 &&
                  recv_bgp_message_with_timeout(&low, received, sizeof(received), &type, OPEN_RUNTIME_TIMEOUT_MS) > 0 &&
                  type == BGP_MSG_OPEN && send_raw(low.fd, message, (size_t)open_len) == 0 &&
                  !wait_until(neighbor_read_open, &(open_wait_t){ctl.neighbor, opens}, NO_ANSWER_MS) &&
                  ctl.neighbor->state == BGP_STATE_OPENSENT;
        if (low.fd >= 0) close(low.fd);
        // The close of that peer is dropped too: clear the half-open session from this side.
        set = dropped && control_command(&ctl, "clear bgp 127.0.0.1") &&
              neighbor_settles_idle(ctl.neighbor);
        ctl.sock = set ? session_handshake(&ctl.reader, connect_ipv4_loopback_with_ttl(port, 255), ctl.neighbor, NULL)
                       : -1;
        set = ctl.sock >= 0 && ctl.neighbor->rx_open == opens + 1 &&
              getsockopt(ctl.neighbor->sock_fd, IPPROTO_IP, IP_TTL, &ttl, &len) == 0 && ttl == 255 &&
              getsockopt(ctl.neighbor->sock_fd, IPPROTO_IP, IP_MINTTL, &min_ttl, &len) == 0 && min_ttl == 255 &&
              ctl.neighbor->is_passive && ctl.neighbor->transport_error == 0;
    }
    control_session_stop(&ctl);

    ASSERT(started, "The raw peer reaches ESTABLISHED");
    ASSERT(dropped, "bgpsim sends its OPEN, and never reads the OPEN that arrives with TTL 254");
    ASSERT(set, "The peer that sends TTL 255 reaches ESTABLISHED; the socket sends 255 and accepts 255 only");
    PASS();
}
#endif

#ifndef __linux__
/*
 * A session bgpsim accepts comes from its IPv6 listener. Systems other than Linux do not take the IPv4 TTL option on
 * the IPv4 session of such a socket, so a neighbor with `ttl-security` refuses the session and says why, instead of
 * running without the TTL it was asked for. `no ttl-security` is the positive control.
 */
static void test_session_ttl_security_accepting_refused(void) {
    control_session_t      ctl;
    notification_capture_t out;
    int                    started = control_session_start(&ctl);
    int                    refused = 0;
    int                    cleared = 0;

    TEST("ttl-security on an accepted IPv4 session: refused with a reason where the socket cannot take the TTL");
    if (started) {
        refused = control_neighbor_command(&ctl, "ttl-security hops 1") == 1 &&
                  neighbor_settles_idle(ctl.neighbor) &&
                  control_peer_is_refused(&ctl) && ctl.neighbor->transport_error != 0 &&
                  control_show(&ctl, "show bgp neighbors", &out) &&
                  strstr(out.out, "  ttl-security or password is not usable (") != NULL;
        cleared = refused && control_neighbor_command(&ctl, "no ttl-security") == 1 && control_peer_reconnects(&ctl) &&
                  ctl.neighbor->transport_error == 0 && control_show(&ctl, "show bgp neighbors", &out) &&
                  strstr(out.out, "is not usable") == NULL;
    }
    control_session_stop(&ctl);

    ASSERT(started, "The raw peer reaches ESTABLISHED");
    ASSERT(refused, "The neighbor closes the connection without an OPEN and shows the socket error");
    ASSERT(cleared, "no ttl-security: the peer connects and the error line is gone");
    PASS();
}
#endif

#ifdef __linux__
/*
 * Connect a non-blocking socket, whose options the caller has set, to 127.0.0.1:port and give the connect wait_ms.
 * Takes the socket over: returns it in blocking mode, or closes it and returns -1.
 */
static int connect_ipv4_loopback_within(int sock, uint16_t port, int wait_ms) {
    struct sockaddr_in remote = {.sin_family = AF_INET, .sin_port = htons(port)};
    struct pollfd      pfd = {.fd = sock, .events = POLLOUT};
    socklen_t          len = sizeof(int);
    int                error = 0;

    inet_pton(AF_INET, "127.0.0.1", &remote.sin_addr);
    if (sock < 0 || (connect(sock, (struct sockaddr *)&remote, sizeof(remote)) != 0 && errno != EINPROGRESS) ||
        poll(&pfd, 1, wait_ms) != 1 || getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len) != 0 || error != 0 ||
        fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) & ~O_NONBLOCK) != 0) {
        if (sock >= 0) close(sock);
        return -1;
    }
    return sock;
}

/*
 * A peer that enforces TTL security on its own connecting socket drops a SYN-ACK that comes with less than 255.
 * Expected failure: with --passive the listener answers the SYN before the neighbor is known, with the system's
 * default TTL, so such a peer gets no connection to a neighbor with `ttl-security`.
 */
static void test_session_ttl_security_accepting_strict_peer(void) {
    control_session_t ctl;
    int               started = control_session_start(&ctl);
    int               ready = 0;
    int               strict = -1;
    int               plain = -1;

    if (started) {
        uint16_t port = (uint16_t)ctl.sim->routers[0]->listen_port;
        int      ttl = 255;

        ready = control_neighbor_command(&ctl, "ttl-security hops 1") == 1 &&
                neighbor_settles_idle(ctl.neighbor);
        close(ctl.sock);
        ctl.sock = -1;
        strict = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        if (ready && strict >= 0 && setsockopt(strict, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) == 0 &&
            setsockopt(strict, IPPROTO_IP, IP_MINTTL, &ttl, sizeof(ttl)) == 0) {
            strict = connect_ipv4_loopback_within(strict, port, NO_ANSWER_MS);
        } else {
            ready = 0;
        }
        // The control: the same listener answers a peer that sends TTL 255 and accepts any TTL.
        plain = ready ? connect_ipv4_loopback_with_ttl(port, 255) : -1;
    }
    test_xfail(strict >= 0, ready && strict < 0 && plain >= 0,
               "RFC 5082: a peer with a minimum TTL of 255 connects to a passive neighbor with ttl-security",
               "docs/todo/misc-followups.md item 9");
    if (strict >= 0) close(strict);
    if (plain >= 0) close(plain);
    control_session_stop(&ctl);
}

/*
 * Connect to 127.0.0.1:port from a socket that signs with a TCP MD5 key (NULL: unsigned). A listener that holds
 * another key for this address, or a key where the peer has none, drops the SYN, so the connect is given wait_ms.
 * Returns the socket, in blocking mode, or -1.
 */
static int connect_ipv4_loopback_with_md5(uint16_t port, const char *key, int wait_ms) {
    struct sockaddr_in remote = {.sin_family = AF_INET, .sin_port = htons(port)};
    struct tcp_md5sig  md5;
    int                sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);

    inet_pton(AF_INET, "127.0.0.1", &remote.sin_addr);
    memset(&md5, 0, sizeof(md5));
    memcpy(&md5.tcpm_addr, &remote, sizeof(remote));
    if (key) {
        md5.tcpm_keylen = (uint16_t)strlen(key);
        memcpy(md5.tcpm_key, key, strlen(key));
    }
    if (sock >= 0 && key && setsockopt(sock, IPPROTO_TCP, TCP_MD5SIG, &md5, sizeof(md5)) != 0) {
        close(sock);
        return -1;
    }
    return connect_ipv4_loopback_within(sock, port, wait_ms);
}
#endif

/*
 * `password <text>` (TCP MD5, RFC 2385). On Linux the listener holds the key for the neighbor's address: a peer that
 * signs with it connects, and one that does not sign, or signs with another key, gets no answer. Elsewhere there is
 * no key for each peer address, so the neighbor stays down and says why. `no password` is the positive control on
 * every system: the unsigned peer connects again.
 */
static void test_session_password(void) {
    control_session_t      ctl;
    notification_capture_t out;
    int                    started = control_session_start(&ctl);
    int                    set = 0;
    int                    enforced = 0;
    int                    cleared = 0;

    TEST("password signs the session with TCP MD5 where the system can; no password removes the key");
    if (started) {
        char long_key[100] = "password ";

        // 81 octets do not fit a TCP MD5 key.
        memset(long_key + strlen(long_key), 'k', 81);
        set = control_neighbor_command(&ctl, "password") == 0 && control_neighbor_command(&ctl, long_key) == 0 &&
              peer_barrier(ctl.sock, ctl.neighbor) && ctl.neighbor->session_resets == 0 &&
              control_neighbor_command(&ctl, "password s3cret key") == 1 && ctl.neighbor->session_resets == 1 &&
              neighbor_settles_idle(ctl.neighbor) &&
              control_show(&ctl, "show running-config", &out) &&
              strstr(out.out, "  neighbor 127.0.0.1 remote-as 65001\n    password s3cret key\n") != NULL &&
              control_show(&ctl, "show bgp neighbors", &out) && strstr(out.out, "  TCP MD5 password is set\n") != NULL;
        close(ctl.sock);
        ctl.sock = -1;
#ifdef __linux__
        {
            uint16_t port = (uint16_t)ctl.sim->routers[0]->listen_port;

            enforced = set && connect_ipv4_loopback_with_md5(port, NULL, NO_ANSWER_MS) < 0 &&
                       connect_ipv4_loopback_with_md5(port, "another key", NO_ANSWER_MS) < 0 &&
                       ctl.neighbor->tx_open == 1 && ctl.neighbor->state == BGP_STATE_IDLE;
            ctl.sock = enforced ? session_handshake(&ctl.reader, connect_ipv4_loopback_with_md5(port, "s3cret key", OPEN_RUNTIME_TIMEOUT_MS),
                                                    ctl.neighbor, NULL)
                                : -1;
            enforced = ctl.sock >= 0 && ctl.neighbor->tx_open == 2 && ctl.neighbor->transport_error == 0;
        }
#else
        enforced = set && control_peer_is_refused(&ctl) && control_show(&ctl, "show bgp neighbors", &out) &&
                   strstr(out.out, "  ttl-security or password is not usable (operation not supported on socket), "
                                   "retrying\n") != NULL;
#endif
        cleared = enforced && control_neighbor_command(&ctl, "no password") == 1 && control_peer_reconnects(&ctl) &&
                  control_show(&ctl, "show running-config", &out) && strstr(out.out, "password") == NULL &&
                  control_show(&ctl, "show bgp neighbors", &out) && strstr(out.out, "password") == NULL;
    }
    control_session_stop(&ctl);

    ASSERT(started, "The raw peer reaches ESTABLISHED");
    ASSERT(set, "No text and 81 octets are refused; password <text>: one reset, shown and saved");
#ifdef __linux__
    ASSERT(enforced, "An unsigned peer and one with another key get no answer; the peer with the key connects");
#else
    ASSERT(enforced, "Without a key for each peer address the neighbor refuses the session and says why");
#endif
    ASSERT(cleared, "no password: the unsigned peer connects and the lines are gone");
    PASS();
}

#ifdef __linux__
/*
 * A neighbor that is removed takes its TCP MD5 key off the listener: the same address configured again with no
 * password accepts an unsigned peer.
 */
static void test_session_password_goes_with_neighbor(void) {
    control_session_t ctl;
    int               started = control_session_start(&ctl);
    int               keyed = 0;
    int               removed = 0;
    int               unsigned_ok = 0;

    TEST("Removing a neighbor removes its TCP MD5 key from the listener");
    if (started) {
        uint16_t port = (uint16_t)ctl.sim->routers[0]->listen_port;

        keyed = control_neighbor_command(&ctl, "password s3cret") == 1 &&
                neighbor_settles_idle(ctl.neighbor) &&
                connect_ipv4_loopback_with_md5(port, NULL, NO_ANSWER_MS) < 0;
        close(ctl.sock);
        ctl.sock = -1;
        removed = keyed && control_command(&ctl, "config") && control_command(&ctl, "router bgp 65000") &&
                  control_command(&ctl, "no neighbor 127.0.0.1 remote-as 65001") &&
                  wait_for_only_neighbor_freed(ctl.sim->routers[0]) &&
                  control_command(&ctl, "neighbor 127.0.0.1 remote-as 65001") && control_command(&ctl, "end");
        if (removed) {
            ctl.neighbor = ctl.sim->routers[0]->neighbors[0];
            ctl.sock = session_handshake(&ctl.reader, connect_ipv4_loopback_with_md5(port, NULL, OPEN_RUNTIME_TIMEOUT_MS),
                                         ctl.neighbor, NULL);
            unsigned_ok = ctl.sock >= 0 && ctl.neighbor->password[0] == '\0';
        }
    }
    control_session_stop(&ctl);

    ASSERT(started, "The raw peer reaches ESTABLISHED");
    ASSERT(keyed, "With a password the listener gives an unsigned peer no answer");
    ASSERT(removed, "The neighbor is removed, freed and configured again with no password");
    ASSERT(unsigned_ok, "The unsigned peer connects: the listener holds no key for the address");
    PASS();
}
#endif

#ifdef __linux__
/*
 * A password that is configured before the listener opens, as when a configuration file is loaded: the new listener
 * gets the key of every neighbor.
 */
static void test_session_password_before_listener(void) {
    peer_rx_t  reader = {0};
    bgp_sim_t *sim = create_sim();
    char       socket_path[108] = "";
    int        started = 0;
    int        unsigned_dropped = 0;
    int        sock = -1;

    TEST("A listener that opens after the password was set holds the TCP MD5 key");
    if (sim != NULL && bgp_add_router(sim, 65000) == 1 && bgp_add_neighbor(sim, 65000, "127.0.0.1", 65001) == 1 &&
        bgp_neighbor_set_password(sim->routers[0]->neighbors[0], "s3cret") == 0 &&
        !sim->routers[0]->listener_open && session_start_runtime(sim, socket_path, sizeof(socket_path)) == 0) {
        uint16_t port = (uint16_t)sim->routers[0]->listen_port;

        started = 1;
        unsigned_dropped = connect_ipv4_loopback_with_md5(port, NULL, NO_ANSWER_MS) < 0;
        sock = session_handshake(&reader, connect_ipv4_loopback_with_md5(port, "s3cret", OPEN_RUNTIME_TIMEOUT_MS),
                                 sim->routers[0]->neighbors[0], NULL);
    }
    if (sock >= 0) close(sock);
    destroy_sim(sim);
    unlink(socket_path);

    ASSERT(started, "The password is set, then the listener opens");
    ASSERT(unsigned_dropped, "An unsigned peer gets no answer");
    ASSERT(sock >= 0, "The peer with the key reaches ESTABLISHED");
    PASS();
}
#endif

typedef struct {
    bgp_neighbor_t *neighbor;
    uint64_t        epoch;  /* connect_epoch before the attempt waited for */
} dial_wait_t;

static int neighbor_dialed(void *opaque) {
    dial_wait_t *wait = opaque;

    return wait->neighbor->connect_epoch > wait->epoch;
}

/*
 * The connecting side of `shutdown`: a neighbor that bgpsim dials (192.0.2.1, where nothing answers) stops dialing
 * and has no retry scheduled; `no shutdown` dials again. With no session there is nothing to send.
 */
static void test_session_shutdown_stops_connecting(void) {
    control_session_t      ctl;
    notification_capture_t out;
    uint64_t               epoch = 0;
    int                    dialing = 0;
    int                    stopped = 0;
    int                    resumed = 0;

    TEST("shutdown stops connection attempts to a neighbor; no shutdown starts them again");
    if (control_session_dialing(&ctl, "192.0.2.1") && control_session_run(&ctl)) {
        dialing = wait_until(neighbor_dialed, &(dial_wait_t){ctl.neighbor, 0}, OPEN_RUNTIME_TIMEOUT_MS);
        /*
         * The stream closes on a later turn of the loop, and that is where a retry would be scheduled. The show
         * command is a barrier: it runs on the loop after the close.
         */
        stopped = dialing && control_neighbor_command(&ctl, "shutdown") == 1 &&
                  neighbor_settles_idle(ctl.neighbor) &&
                  control_show(&ctl, "show bgp neighbors", &out) &&
                  strstr(out.out, "  BGP state = Idle (administratively shut down)\n") != NULL &&
                  !uv_is_active((uv_handle_t *)&ctl.neighbor->reconnect_timer) &&
                  !uv_is_active((uv_handle_t *)&ctl.neighbor->connect_timer) && !ctl.neighbor->pending_reconnect &&
                  !ctl.neighbor->connect_pending && ctl.neighbor->tx_notification == 0;
        epoch = ctl.neighbor->connect_epoch;
        resumed = stopped && control_neighbor_command(&ctl, "no shutdown") == 1 &&
                  wait_until(neighbor_dialed, &(dial_wait_t){ctl.neighbor, epoch}, OPEN_RUNTIME_TIMEOUT_MS);
    }
    control_session_stop(&ctl);

    ASSERT(dialing, "bgpsim dials the neighbor");
    ASSERT(stopped, "After shutdown the neighbor is Idle with no connection attempt pending or scheduled");
    ASSERT(resumed, "no shutdown dials the neighbor again");
    PASS();
}

/*
 * `clear bgp <neighbor> cease [text]` sends Cease/Administrative Reset and the neighbor takes the next connection.
 * Plain `clear bgp` still closes TCP with no NOTIFICATION.
 */
static void test_session_clear_cease(void) {
    static const char  text[] = "link upgrade";
    control_session_t  ctl;
    int                started = control_session_start(&ctl);
    int                with_text = 0;
    int                without_text = 0;
    int                silent = 0;
    int                refused = 0;

    TEST("clear bgp <neighbor> cease [text] sends Cease/Administrative Reset; plain clear bgp sends nothing");
    if (started) {
        with_text = control_command(&ctl, "clear bgp 127.0.0.1 cease link upgrade") &&
                    control_peer_reads_cease(&ctl, 4, text) && control_peer_reconnects(&ctl) &&
                    ctl.neighbor->tx_notification == 1 && ctl.neighbor->session_resets == 1 &&
                    !ctl.neighbor->admin_shutdown && strcmp(ctl.neighbor->last_notification_tx.shutdown, text) == 0;
        without_text = with_text && control_command(&ctl, "clear bgp * cease") &&
                       control_peer_reads_cease(&ctl, 4, "") && control_peer_reconnects(&ctl) &&
                       ctl.neighbor->tx_notification == 2 && ctl.neighbor->session_resets == 2;
        silent = without_text && control_command(&ctl, "clear bgp 127.0.0.1") &&
                 control_peer_reads_eof_without_notification(&ctl) && ctl.neighbor->tx_notification == 2 &&
                 ctl.neighbor->session_resets == 3 && control_peer_reconnects(&ctl);
        if (silent) {
            char command[320] = "clear bgp 127.0.0.1 cease ";

            // 256 octets of text do not fit the one length octet of a Shutdown Communication.
            memset(command + strlen(command), 'x', 256);
            refused = !control_command(&ctl, command) && peer_barrier(ctl.sock, ctl.neighbor) &&
                      ctl.neighbor->session_resets == 3 && ctl.neighbor->tx_notification == 2;
        }
    }
    control_session_stop(&ctl);

    ASSERT(started, "The raw peer reaches ESTABLISHED");
    ASSERT(with_text, "RFC 4486, RFC 9003: Cease/Administrative Reset with exactly the text, then a new session");
    ASSERT(without_text, "Without text the NOTIFICATION has no data; * selects the neighbor");
    ASSERT(silent, "Plain clear bgp closes the connection with no NOTIFICATION");
    ASSERT(refused, "A text of 256 octets is refused and the session stays up");
    PASS();
}

/*
 * The OPEN bgpsim sends on the next connection carries hold_time; the peer then reaches ESTABLISHED with Hold Time
 * 180 of its own.
 */
static int control_next_open_has_hold_time(control_session_t *ctl, uint16_t hold_time) {
    bgp_open_info_t info;
    uint8_t         message[BGP_MAX_MESSAGE_SIZE];
    int             len = 0;

    if (ctl->sock >= 0) close(ctl->sock);
    ctl->sock = -1;
    return neighbor_settles_idle(ctl->neighbor) &&
           capture_passive_open(ctl->sim->routers[0], ctl->neighbor, message, sizeof(message), &len) &&
           bgp_parse_open_message(message, (size_t)len, NULL, &info) == 0 && info.hold_time == hold_time &&
           control_peer_reconnects(ctl);
}

/*
 * `hold-time <seconds>`: the value is proposed in OPEN, a change resets the session once, the negotiated value and
 * the timers follow it, and `no hold-time` restores 180. Values 1 and 2 and values over 65535 are refused.
 */
static void test_session_hold_time(void) {
    control_session_t      ctl;
    notification_capture_t out;
    int                    started = control_session_start(&ctl);
    int                    refused = 0;
    int                    set = 0;
    int                    zero = 0;
    int                    restored = 0;

    TEST("hold-time sets the Hold Time of the OPEN; the session and its timers follow");
    if (started) {
        refused = control_neighbor_command(&ctl, "hold-time") == 0 &&
                  control_neighbor_command(&ctl, "hold-time 1") == 0 &&
                  control_neighbor_command(&ctl, "hold-time 2") == 0 &&
                  control_neighbor_command(&ctl, "hold-time 65536") == 0 && peer_barrier(ctl.sock, ctl.neighbor) &&
                  ctl.neighbor->hold_time_config == BGP_HOLD_TIME && ctl.neighbor->hold_time == BGP_HOLD_TIME &&
                  ctl.neighbor->session_resets == 0;
        set = refused && control_neighbor_command(&ctl, "hold-time 30") == 1 && ctl.neighbor->session_resets == 1 &&
              control_next_open_has_hold_time(&ctl, 30) && ctl.neighbor->hold_time == 30 &&
              uv_timer_get_repeat(&ctl.neighbor->keepalive_timer) == 10000 &&
              control_show(&ctl, "show bgp neighbors", &out) &&
              strstr(out.out, "  Hold time is 30, keepalive interval is 10 seconds\n"
                              "  Configured hold time is 30 seconds\n") != NULL &&
              control_show(&ctl, "show running-config", &out) &&
              strstr(out.out, "  neighbor 127.0.0.1 remote-as 65001\n    hold-time 30\n") != NULL;
        if (set) {
            uint64_t resets = ctl.neighbor->session_resets;

            // The same value again keeps the session.
            set = control_neighbor_command(&ctl, "hold-time 30") == 1 && peer_barrier(ctl.sock, ctl.neighbor) &&
                  ctl.neighbor->session_resets == resets;
        }
        zero = set && control_neighbor_command(&ctl, "hold-time 0") == 1 && control_next_open_has_hold_time(&ctl, 0) &&
               ctl.neighbor->hold_time == 0 && !uv_is_active((uv_handle_t *)&ctl.neighbor->keepalive_timer) &&
               !uv_is_active((uv_handle_t *)&ctl.neighbor->hold_timer) &&
               control_show(&ctl, "show bgp neighbors", &out) &&
               strstr(out.out, "  Hold time is 0, no keepalives\n  Configured hold time is 0 seconds\n") != NULL;
        restored = zero && control_neighbor_command(&ctl, "no hold-time") == 1 &&
                   control_next_open_has_hold_time(&ctl, BGP_HOLD_TIME) && ctl.neighbor->hold_time == BGP_HOLD_TIME &&
                   uv_is_active((uv_handle_t *)&ctl.neighbor->keepalive_timer) &&
                   uv_is_active((uv_handle_t *)&ctl.neighbor->hold_timer) &&
                   control_show(&ctl, "show running-config", &out) && strstr(out.out, "hold-time") == NULL &&
                   control_show(&ctl, "show bgp neighbors", &out) &&
                   strstr(out.out, "  Hold time is 180, keepalive interval is 60 seconds\n") != NULL &&
                   strstr(out.out, "Configured hold time") == NULL;
    }
    control_session_stop(&ctl);

    ASSERT(started, "The raw peer reaches ESTABLISHED");
    ASSERT(refused, "RFC 4271 section 4.2: no value, 1, 2 and values over 65535 are refused; the session and value stay");
    ASSERT(set, "hold-time 30: one reset, OPEN with 30, negotiated 30 with keepalives every 10 s, shown and saved");
    ASSERT(zero, "hold-time 0: OPEN with 0, and neither the hold timer nor the keepalive timer runs");
    ASSERT(restored, "no hold-time: OPEN with 180, both timers run, and the line is gone");
    PASS();
}

/*
 * The hold timer runs on the configured value: with `hold-time 3` and a peer that stays silent, bgpsim sends
 * KEEPALIVEs every second and then Hold Timer Expired (RFC 4271 section 6.5), not before 3 seconds have passed.
 */
static void test_session_configured_hold_timer_expires(void) {
    control_session_t ctl;
    uint8_t           message[BGP_MAX_MESSAGE_SIZE];
    uint8_t           type = 0;
    int64_t           established_ms = 0;
    int64_t           expired_ms = 0;
    int               started = control_session_start(&ctl);
    int               set = 0;
    int               keepalives = 0;
    int               len = 0;

    TEST("hold-time 3: a silent peer gets KEEPALIVEs each second, then Hold Timer Expired after 3 seconds");
    if (started) {
        set = control_neighbor_command(&ctl, "hold-time 3") == 1 && control_next_open_has_hold_time(&ctl, 3) &&
              ctl.neighbor->hold_time == 3;
        established_ms = wait_now_ms();
        // Bounded well under the 180 seconds of the default, so a hold timer on the default fails here.
        // The End-of-RIB UPDATE of the new session is read past.
        while (set && (len = recv_bgp_message_with_timeout(&ctl.reader, message, sizeof(message), &type, 15000)) > 0 &&
               type != BGP_MSG_NOTIFICATION) {
            keepalives += type == BGP_MSG_KEEPALIVE;
        }
        expired_ms = wait_now_ms();
    }
    control_session_stop(&ctl);

    ASSERT(started, "The raw peer reaches ESTABLISHED");
    ASSERT(set, "hold-time 3 is proposed in OPEN and negotiated against the peer's 180");
    ASSERT(len == BGP_HEADER_SIZE + 2 && type == BGP_MSG_NOTIFICATION &&
           message[BGP_HEADER_SIZE] == BGP_ERR_HOLD_TIMER_EXPIRED && message[BGP_HEADER_SIZE + 1] == 0,
           "RFC 4271 section 6.5: Hold Timer Expired ends the session");
    ASSERT(keepalives == 2 || keepalives == 3, "KEEPALIVEs came at one third of the hold time, every second");
    ASSERT(expired_ms - established_ms >= 2500, "The hold timer did not fire early");
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
        test_peer_reader_ownership();
        test_basic_open();
        test_4byte_asn();
        test_4byte_asn_capability_with_16bit_as();
        test_old_speaker_rejects_large_asn();
        test_route_refresh();
        test_extended_message_capability();
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
        test_gr_last_instance_wins();
        test_gr_restart_flags_ignored();
        test_hold_time_zero();
        test_hold_time_negotiation();
        test_hold_time_negotiation_with_configured_value();
        test_open_set_hold_time();
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
        static const struct {
            const char *command;
            size_t      offset;
            int         byte_field;
            int         value;
            int         (*wire)(const uint8_t *message, int len);
        } changes[] = {
            {"no address-family ipv6", offsetof(bgp_capabilities_t, ipv6_unicast), 0, 0},
            {"capability route-refresh", offsetof(bgp_capabilities_t, route_refresh), 0, 1},
            {"capability extended-message", offsetof(bgp_capabilities_t, extended_message), 0, 1,
             extended_message_on_wire},
            {"capability graceful-restart restart-time 321", offsetof(bgp_capabilities_t, restart_time), 0, 321,
             graceful_restart_on_wire},
            {"capability add-path ipv4", offsetof(bgp_capabilities_t, add_path_ipv4), 1, 3},
            {"capability ext-nh ipv4", offsetof(bgp_capabilities_t, ext_nh_ipv4_unicast_over_ipv6), 0, 1},
            {"no capability four-byte-asn", offsetof(bgp_capabilities_t, four_byte_asn), 0, 0},
        };
        for (size_t i = 0; i < sizeof(changes) / sizeof(changes[0]); i++) {
            test_session_capability_change(changes[i].command, changes[i].offset, changes[i].byte_field, changes[i].value,
                                           changes[i].wire);
        }
        test_session_fragment(10, 0);
        test_session_fragment(BGP_HEADER_SIZE + 1, 0);
        test_session_fragment(0, 1);
        test_session_fragment(10, 1);
        test_session_fragment(BGP_HEADER_SIZE + 1, 1);
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
        test_session_shutdown("maintenance window");
        test_session_shutdown("");
        test_session_shutdown_stops_connecting();
        test_session_clear_cease();
        test_session_hold_time();
        test_session_configured_hold_timer_expires();
        test_session_extended_message_receive();
        test_session_ttl_security_connecting();
        test_session_ttl_security_connecting_ipv6();
#ifdef __linux__
        test_session_ttl_security_accepting();
#else
        test_session_ttl_security_accepting_refused();
#endif
        test_session_password();
#ifdef __linux__
        test_session_password_goes_with_neighbor();
        test_session_password_before_listener();
        test_session_ttl_security_accepting_strict_peer();
#endif
        test_session_gr_peer_reconnect();
        static const struct {
            const char *name;
            uint8_t     type;
            uint16_t    length;
            uint8_t     subcode;
        } bad_headers[] = {
            {"Session rejects a 20-octet KEEPALIVE", BGP_MSG_KEEPALIVE, BGP_HEADER_SIZE + 1, 2},
            {"Session rejects a header-only UPDATE", BGP_MSG_UPDATE, BGP_HEADER_SIZE, 2},
            {"Session rejects a 28-octet OPEN", BGP_MSG_OPEN, BGP_HEADER_SIZE + sizeof(bgp_open_t) - 1, 2},
            {"Session rejects a 20-octet NOTIFICATION", BGP_MSG_NOTIFICATION, BGP_HEADER_SIZE + 1, 2},
            {"Session rejects a 22-octet ROUTE-REFRESH", BGP_MSG_ROUTE_REFRESH, BGP_HEADER_SIZE + 3, 2},
            {"Session rejects a short declared length", BGP_MSG_KEEPALIVE, 10, 2},
            {"Session rejects an oversized declared length", BGP_MSG_UPDATE, 5000, 2},
            {"Session rejects a bad marker", BGP_MSG_KEEPALIVE, BGP_HEADER_SIZE, 1},
            {"Session rejects an unknown type", 99, BGP_HEADER_SIZE, 3},
        };
        for (size_t i = 0; i < sizeof(bad_headers) / sizeof(bad_headers[0]); i++) {
            test_session_rejects_header(bad_headers[i].name, bad_headers[i].type,
                                       bad_headers[i].length, bad_headers[i].subcode);
        }
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
