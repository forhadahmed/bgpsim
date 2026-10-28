// Snapshot compatibility with a peer's negotiated session: the rules that decide when an advertisement is withheld.
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include "bgp.h"
#include "bgp_tx.h"
#include "test_case.h"

/*
 * A session whose OPEN exchange already happened: local and peer capabilities set by the caller.
 */
static bgp_neighbor_t session(void) {
    bgp_neighbor_t neighbor;

    memset(&neighbor, 0, sizeof(neighbor));
    neighbor.peer_capabilities_received = 1;
    neighbor.peer_mp_capability_received = 1;
    neighbor.capabilities.four_byte_asn = 1;
    neighbor.peer_capabilities.four_byte_asn = 1;
    return neighbor;
}

static bgp_tx_profile_t profile(uint16_t afi, uint8_t safi, bgp_ribout_family_t family) {
    bgp_tx_profile_t p;

    memset(&p, 0, sizeof(p));
    p.afi = afi;
    p.safi = safi;
    p.family = (uint8_t)family;
    p.next_hop_af = AF_INET;
    return p;
}

static void test_family_negotiation(void) {
    bgp_neighbor_t   n = session();
    bgp_tx_profile_t vpn = profile(AFI_IPV4, SAFI_MPLS_VPN, BGP_RIBOUT_FAMILY_VPNV4);

    TEST("A family must be listed on both sides");
    n.capabilities.vpnv4_unicast = 1;
    ASSERT(bgp_tx_check(&vpn, &n) == BGP_TX_COMPAT_FAMILY, "peer did not list VPNv4");
    n.peer_capabilities.vpnv4_unicast = 1;
    ASSERT(bgp_tx_check(&vpn, &n) == BGP_TX_COMPAT_OK, "both listed VPNv4");
    n.capabilities.vpnv4_unicast = 0;
    ASSERT(bgp_tx_check(&vpn, &n) == BGP_TX_COMPAT_FAMILY, "we did not list VPNv4");
    n.peer_capabilities_received = 0;
    n.capabilities.vpnv4_unicast = 1;
    ASSERT(!bgp_tx_family_negotiated(&n, AFI_IPV4, SAFI_MPLS_VPN), "nothing is negotiated before the peer's OPEN");
    PASS();
}

static void test_rfc4760_default(void) {
    bgp_neighbor_t   n = session();
    bgp_tx_profile_t v4 = profile(AFI_IPV4, SAFI_UNICAST, BGP_RIBOUT_FAMILY_IPV4_UNICAST);
    bgp_tx_profile_t v6 = profile(AFI_IPV6, SAFI_UNICAST, BGP_RIBOUT_FAMILY_IPV6_UNICAST);

    TEST("Without a Multiprotocol capability a side supports IPv4 unicast only (RFC 4760)");
    n.capabilities.ipv4_unicast = 1;
    n.capabilities.ipv6_unicast = 1;
    n.peer_mp_capability_received = 0;
    ASSERT(bgp_tx_check(&v4, &n) == BGP_TX_COMPAT_OK, "peer without MP gets IPv4 unicast");
    ASSERT(bgp_tx_check(&v6, &n) == BGP_TX_COMPAT_FAMILY, "peer without MP gets no IPv6 unicast");

    n.peer_mp_capability_received = 1;  /* The peer listed some other family only */
    ASSERT(bgp_tx_check(&v4, &n) == BGP_TX_COMPAT_FAMILY, "an MP peer that did not list IPv4 unicast");

    n.peer_mp_capability_received = 0;
    n.capabilities.ipv4_unicast = 0;
    n.capabilities.ipv6_unicast = 0;
    ASSERT(bgp_tx_check(&v4, &n) == BGP_TX_COMPAT_OK, "neither side sent MP: IPv4 unicast on both");
    n.capabilities.ipv6_unicast = 1;
    ASSERT(bgp_tx_check(&v4, &n) == BGP_TX_COMPAT_FAMILY, "we listed IPv6 only, so not IPv4 unicast");
    PASS();
}

static void test_four_octet_as(void) {
    bgp_neighbor_t   n = session();
    bgp_tx_profile_t v4 = profile(AFI_IPV4, SAFI_UNICAST, BGP_RIBOUT_FAMILY_IPV4_UNICAST);

    TEST("4-octet AS must be negotiated on both sides");
    n.capabilities.ipv4_unicast = 1;
    n.peer_capabilities.ipv4_unicast = 1;
    n.peer_capabilities.four_byte_asn = 0;
    ASSERT(bgp_tx_check(&v4, &n) == BGP_TX_COMPAT_AS4, "peer without 4-octet AS");
    n.peer_capabilities.four_byte_asn = 1;
    n.capabilities.four_byte_asn = 0;
    ASSERT(bgp_tx_check(&v4, &n) == BGP_TX_COMPAT_AS4, "4-octet AS disabled locally");
    PASS();
}

static void test_add_path(void) {
    bgp_neighbor_t   n = session();
    bgp_tx_profile_t plain = profile(AFI_IPV6, SAFI_UNICAST, BGP_RIBOUT_FAMILY_IPV6_UNICAST);
    bgp_tx_profile_t ids = plain;

    TEST("Path IDs in the snapshot must match negotiated ADD-PATH send, both ways");
    ids.add_path = 1;
    n.capabilities.ipv6_unicast = 1;
    n.peer_capabilities.ipv6_unicast = 1;
    ASSERT(bgp_tx_check(&ids, &n) == BGP_TX_COMPAT_ADDPATH_REQUIRED, "path-id without ADD-PATH");
    ASSERT(bgp_tx_check(&plain, &n) == BGP_TX_COMPAT_OK, "no path-id, no ADD-PATH");

    n.capabilities.add_path_ipv6 = ADD_PATH_SEND | ADD_PATH_RECEIVE;
    n.peer_capabilities.add_path_ipv6 = ADD_PATH_SEND;
    ASSERT(bgp_tx_check(&ids, &n) == BGP_TX_COMPAT_ADDPATH_REQUIRED, "peer can send but not receive Path IDs");
    n.peer_capabilities.add_path_ipv6 = ADD_PATH_RECEIVE;
    ASSERT(bgp_tx_check(&ids, &n) == BGP_TX_COMPAT_OK, "both sides agree on Path IDs");
    ASSERT(bgp_tx_check(&plain, &n) == BGP_TX_COMPAT_ADDPATH_UNEXPECTED, "peer expects Path IDs we lack");

    n.capabilities.add_path_ipv6 = ADD_PATH_RECEIVE;
    ASSERT(bgp_tx_check(&ids, &n) == BGP_TX_COMPAT_ADDPATH_REQUIRED, "we advertised receive only");

    // A configured mode on a family whose MP is off is never advertised, so it does not count.
    n.capabilities.add_path_ipv6 = ADD_PATH_SEND | ADD_PATH_RECEIVE;
    n.capabilities.ipv6_unicast = 0;
    ASSERT(!bgp_tx_add_path_send(&n, AFI_IPV6, SAFI_UNICAST), "ADD-PATH needs local MP");
    PASS();
}

static void test_extended_next_hop(void) {
    bgp_neighbor_t   n = session();
    bgp_tx_profile_t lu = profile(AFI_IPV4, SAFI_LABELED_UNICAST, BGP_RIBOUT_FAMILY_LABELED_IPV4);
    bgp_tx_profile_t vpn6 = profile(AFI_IPV6, SAFI_MPLS_VPN, BGP_RIBOUT_FAMILY_VPNV6);

    TEST("IPv4 NLRI over an IPv6 next hop needs RFC 8950 on both sides");
    lu.next_hop_af = AF_INET6;
    lu.needs_ext_nh = 1;
    n.capabilities.ipv4_labeled_unicast = 1;
    n.peer_capabilities.ipv4_labeled_unicast = 1;
    ASSERT(bgp_tx_check(&lu, &n) == BGP_TX_COMPAT_EXT_NH, "no extended next hop");
    n.capabilities.ext_nh_ipv4_labeled_unicast_over_ipv6 = 1;
    ASSERT(bgp_tx_check(&lu, &n) == BGP_TX_COMPAT_EXT_NH, "local only");
    n.peer_capabilities.ext_nh_ipv4_labeled_unicast_over_ipv6 = 1;
    ASSERT(bgp_tx_check(&lu, &n) == BGP_TX_COMPAT_OK, "both sides");
    lu.needs_ext_nh = 0;
    lu.next_hop_af = AF_INET;
    n.peer_capabilities.ext_nh_ipv4_labeled_unicast_over_ipv6 = 0;
    ASSERT(bgp_tx_check(&lu, &n) == BGP_TX_COMPAT_OK, "an IPv4 next hop needs nothing");

    // VPNv6 over an IPv4 next hop is ordinary RFC 4659 encoding, not RFC 8950.
    n.capabilities.vpnv6_unicast = 1;
    n.peer_capabilities.vpnv6_unicast = 1;
    ASSERT(bgp_tx_check(&vpn6, &n) == BGP_TX_COMPAT_OK, "VPNv6 over IPv4");
    PASS();
}

static void test_reasons(void) {
    bgp_tx_profile_t vpn = profile(AFI_IPV4, SAFI_MPLS_VPN, BGP_RIBOUT_FAMILY_VPNV4);
    char             text[128];

    TEST("Withheld reasons name the family");
    bgp_tx_compat_reason(BGP_TX_COMPAT_FAMILY, &vpn, text, sizeof(text));
    ASSERT(strcmp(text, "VPNv4 Unicast not negotiated") == 0, text);
    bgp_tx_compat_reason(BGP_TX_COMPAT_ADDPATH_REQUIRED, &vpn, text, sizeof(text));
    ASSERT(strcmp(text, "ribout has path-id but ADD-PATH send is not negotiated for VPNv4 Unicast") == 0, text);
    bgp_tx_compat_reason(BGP_TX_COMPAT_ADDPATH_UNEXPECTED, &vpn, text, sizeof(text));
    ASSERT(strcmp(text, "ADD-PATH is negotiated for VPNv4 Unicast but the ribout has no path-id") == 0, text);
    bgp_tx_compat_reason(BGP_TX_COMPAT_AS4, &vpn, text, sizeof(text));
    ASSERT(strcmp(text, "4-octet AS not negotiated (AS_PATH is 4-octet)") == 0, text);
    bgp_tx_compat_reason(BGP_TX_COMPAT_EXT_NH, &vpn, text, sizeof(text));
    ASSERT(strcmp(text, "extended next hop for VPNv4 Unicast over IPv6 not negotiated") == 0, text);
    PASS();
}

int main(void) {
    test_family_negotiation();
    test_rfc4760_default();
    test_four_octet_as();
    test_add_path();
    test_extended_next_hop();
    test_reasons();
    printf("\nTests run: %d, passed: %d, failed: %d\n", tests_run, tests_passed, tests_failed);
    return tests_failed == 0 ? 0 : 1;
}
