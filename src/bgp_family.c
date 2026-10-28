/*
 * AFI/SAFI family table. It is data only, so the ribout pipeline links it
 * without the socket and logging code in bgp.c.
 */

#include <stddef.h>
#include <string.h>
#include "bgp.h"

/*
 * Unified family descriptor table.  Every AFI/SAFI-dependent lookup,
 * OPEN encode/parse block, CLI display loop, and command handler
 * iterates this single table instead of maintaining per-family
 * if-blocks.  To add a new family, add one row here.
 */
// Offset of a flag in bgp_capabilities_t.
#define CAP(field) offsetof(bgp_capabilities_t, field)

const bgp_family_t bgp_families[BGP_NUM_FAMILIES] = {
    /*
     * AFI, SAFI, enabled flag, ADD-PATH flag,
     *           RFC 8950 ext-nh flag, CLI keyword, display name
     */
    { AFI_IPV4,   SAFI_UNICAST,         CAP(ipv4_unicast),         CAP(add_path_ipv4),
                  CAP(ext_nh_ipv4_unicast_over_ipv6),         "ipv4",              "IPv4 Unicast" },
    { AFI_IPV6,   SAFI_UNICAST,         CAP(ipv6_unicast),         CAP(add_path_ipv6),
                  NO_CAP_OFFSET,                              "ipv6",              "IPv6 Unicast" },
    { AFI_IPV4,   SAFI_LABELED_UNICAST, CAP(ipv4_labeled_unicast), CAP(add_path_ipv4_labeled),
                  CAP(ext_nh_ipv4_labeled_unicast_over_ipv6), "ipv4 labels",       "IPv4 Labeled Unicast" },
    { AFI_IPV6,   SAFI_LABELED_UNICAST, CAP(ipv6_labeled_unicast), CAP(add_path_ipv6_labeled),
                  NO_CAP_OFFSET,                              "ipv6 labels",       "IPv6 Labeled Unicast" },
    { AFI_IPV4,   SAFI_MPLS_VPN,        CAP(vpnv4_unicast),        CAP(add_path_vpnv4),
                  CAP(ext_nh_vpnv4_unicast_over_ipv6),        "vpnv4",             "VPNv4 Unicast" },
    { AFI_IPV6,   SAFI_MPLS_VPN,        CAP(vpnv6_unicast),        CAP(add_path_vpnv6),
                  NO_CAP_OFFSET,                              "vpnv6",             "VPNv6 Unicast" },
    { AFI_L2VPN,  SAFI_EVPN,            CAP(evpn),                 CAP(add_path_evpn),
                  NO_CAP_OFFSET,                              "l2vpn evpn",        "L2VPN EVPN" },
    { AFI_IPV4,   SAFI_FLOWSPEC,        CAP(ipv4_flowspec),        CAP(add_path_ipv4_flowspec),
                  NO_CAP_OFFSET,                              "ipv4 flowspec",     "IPv4 FlowSpec" },
    { AFI_IPV6,   SAFI_FLOWSPEC,        CAP(ipv6_flowspec),        CAP(add_path_ipv6_flowspec),
                  NO_CAP_OFFSET,                              "ipv6 flowspec",     "IPv6 FlowSpec" },
    { AFI_IPV4,   SAFI_SR_POLICY,       CAP(ipv4_srpolicy),        CAP(add_path_ipv4_srpolicy),
                  NO_CAP_OFFSET,                              "ipv4 srpolicy",     "IPv4 SR Policy" },
    { AFI_IPV6,   SAFI_SR_POLICY,       CAP(ipv6_srpolicy),        CAP(add_path_ipv6_srpolicy),
                  NO_CAP_OFFSET,                              "ipv6 srpolicy",     "IPv6 SR Policy" },
    { AFI_BGP_LS, SAFI_BGP_LS,          CAP(bgp_ls),               CAP(add_path_bgp_ls),
                  NO_CAP_OFFSET,                              "bgp-ls",            "BGP-LS" },
    { AFI_IPV4,   SAFI_MVPN,            CAP(ipv4_mvpn),            CAP(add_path_ipv4_mvpn),
                  NO_CAP_OFFSET,                              "ipv4 mvpn",         "IPv4 MVPN" },
    { AFI_IPV6,   SAFI_MVPN,            CAP(ipv6_mvpn),            CAP(add_path_ipv6_mvpn),
                  NO_CAP_OFFSET,                              "ipv6 mvpn",         "IPv6 MVPN" },
    { AFI_IPV4,   SAFI_RTC,             CAP(ipv4_rtc),             CAP(add_path_ipv4_rtc),
                  NO_CAP_OFFSET,                              "ipv4 rtc",          "RTC" },
    { AFI_L2VPN,  SAFI_VPLS,            CAP(vpls),                 CAP(add_path_vpls),
                  NO_CAP_OFFSET,                              "l2vpn vpls",        "L2VPN VPLS" },
    { AFI_IPV4,   SAFI_FLOWSPEC_VPN,    CAP(ipv4_flowspec_vpn),    CAP(add_path_ipv4_flowspec_vpn),
                  NO_CAP_OFFSET,                              "ipv4 flowspec-vpn", "IPv4 FlowSpec VPN" },
    { AFI_IPV6,   SAFI_FLOWSPEC_VPN,    CAP(ipv6_flowspec_vpn),    CAP(add_path_ipv6_flowspec_vpn),
                  NO_CAP_OFFSET,                              "ipv6 flowspec-vpn", "IPv6 FlowSpec VPN" },
};

#undef CAP

/*
 * Row with this CLI keyword ("ipv4", "l2vpn evpn", ...), or NULL.
 */
const bgp_family_t *bgp_family_find(const char *cli_name) {
    for (int i = 0; cli_name && i < BGP_NUM_FAMILIES; i++) {
        if (strcmp(cli_name, bgp_families[i].cli_name) == 0) {
            return &bgp_families[i];
        }
    }

    return NULL;
}

/*
 * Row for an AFI/SAFI pair, or NULL.
 */
const bgp_family_t *bgp_family_lookup(uint16_t afi, uint8_t safi) {
    for (int i = 0; i < BGP_NUM_FAMILIES; i++) {
        if (bgp_families[i].afi == afi && bgp_families[i].safi == safi) {
            return &bgp_families[i];
        }
    }

    return NULL;
}
