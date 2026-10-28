# BGP UPDATE API

This document describes the low-level UPDATE-generation API in
`src/bgp_update.h` for:

- IPv4 unicast
- IPv6 unicast
- IPv4 labeled-unicast
- IPv6 labeled-unicast
- VPNv4
- VPNv6
- EVPN route types 1-5
- SR Policy
- FlowSpec
- RTC
- VPLS
- MVPN route types 1-7
- BGP-LS

## Scope

The low-level API is a wire-format encoder. It is useful when you want to:

- build NLRI lists directly
- build path-attribute lists directly
- generate UPDATE messages without going through ribout

It does not perform peer-specific policy or negotiated-send enforcement.

## Families Covered

- IPv4 unicast
- IPv4 unicast with IPv6 next hop (RFC 8950 style)
- IPv6 unicast
- IPv4 labeled-unicast
- IPv6 labeled-unicast
- VPNv4
- VPNv6
- EVPN route types 1-5
- SR Policy for IPv4 and IPv6 endpoints
- IPv4 and IPv6 FlowSpec
- RTC
- VPLS
- IPv4 and IPv6 MVPN route types 1-7
- BGP-LS
- withdrawals for all of the above
- ADD-PATH for all of the above

## Main Data Structures

Important public types:

- `bgp_path_attr_t`
- `bgp_next_hop_t`
- `bgp_update_result_t`
- `ipv4_nlri_list_t`
- `ipv6_nlri_list_t`
- `labeled_ipv4_nlri_t`
- `labeled_ipv6_nlri_t`
- `route_distinguisher_t`
- `bgp_vpn_transport_t`
- `vpnv4_nlri_list_t`
- `vpnv6_nlri_list_t`
- `evpn_type1_nlri_t`
- `evpn_type2_nlri_t`
- `evpn_type3_nlri_t`
- `evpn_type4_nlri_t`
- `evpn_type5_nlri_t`
- `srpolicy_nlri_list_t`
- `flowspec_nlri_t`
- `rtc_nlri_list_t`
- `vpls_nlri_list_t`
- `mvpn_type1_nlri_t` through `mvpn_type7_nlri_t`
- `bgpls_nlri_t`

`bgp_next_hop_t` is the typed next-hop container used by the public API.

VPN and EVPN callers also use Route Distinguisher helpers:

- `rd_create_type0(...)`
- `rd_create_type1(...)`
- `rd_create_type2(...)`

## Building NLRI Lists

The current public pattern is:

1. create individual entries with `*_create(...)` or `*_create_path_id(...)`
2. append them with `*_append(...)`
3. or use the tail-based helpers for bulk construction

Examples of the current helpers:

- `ipv4_nlri_create(...)`
- `ipv4_nlri_create_path_id(...)`
- `ipv4_nlri_append(...)`
- `ipv4_nlri_add_tail(...)`
- `ipv4_nlri_add_tail_path_id(...)`

Equivalent families exist for:

- IPv6
- labeled IPv4
- labeled IPv6
- VPNv4
- VPNv6
- EVPN Types 1-5
- SR Policy
- FlowSpec
- RTC
- VPLS
- MVPN Types 1-7
- BGP-LS

EVPN Type 5 helpers are:

- `evpn_type5_nlri_create_ipv4(...)`
- `evpn_type5_nlri_create_ipv4_path_id(...)`
- `evpn_type5_nlri_create_ipv6(...)`
- `evpn_type5_nlri_create_ipv6_path_id(...)`
- `evpn_type5_nlri_append(...)`
- `evpn_type5_prefix_set_esi(...)` and `evpn_type5_nlri_set_esi(...)`

VPN FlowSpec (SAFI 134) entries carry a Route Distinguisher:

- `flowspec_nlri_create_vpn(...)`
- `flowspec_nlri_create_vpn_path_id(...)`

The older tail-scanning `*_add()` helpers are no longer part of the public API.

List utility helpers also include `*_count(...)` functions for all exported NLRI
list types.

EVPN Type 5 currently exposes create/append helpers, but not `*_add_tail(...)`
helpers. The newer families generally follow the same `*_create(...)`,
`*_create_path_id(...)`, `*_append(...)`, `*_count(...)`, and `*_list_free(...)`
pattern even where they do not expose bulk `*_add_tail(...)` helpers.

## Path Attributes

Common public attribute helpers include:

- `bgp_attr_create_origin(...)`
- `bgp_attr_create_as_path(...)`
- `bgp_attr_create_as_path_mode(...)`
- `bgp_attr_create_as_path_transition(...)`
- `bgp_attr_create_as4_path(...)`
- `bgp_attr_create_next_hop(...)`
- `bgp_attr_create_med(...)`
- `bgp_attr_create_local_pref(...)`
- `bgp_attr_create_mp_reach_ipv6(...)`
- `bgp_attr_create_mp_unreach_ipv6(...)`
- `bgp_attr_create_ext_comm_rt(...)`
- `bgp_attr_create_ext_comm_rt_as4(...)`
- `bgp_attr_create_ext_comm_rt_ip(...)`
- `bgp_attr_create_ext_comm_encap(...)`
- `bgp_attr_create_ext_comm_color(...)` and
  `bgp_attr_create_ext_comm_color_flags(...)`
- `bgp_attr_ext_comm_append_attr(...)`
- `bgp_attr_create_ipv6_ext_comm(...)` and
  `bgp_attr_ipv6_ext_comm_append_attr(...)`

Put all 8-octet communities of a route in one Extended Communities attribute
with `bgp_attr_ext_comm_append_attr(...)`. The serializer writes the attribute
list as given, and a receiver keeps only the first copy of a repeated
attribute (RFC 7606 section 3 (g)). The same applies to the 20-octet IPv6
Address Specific communities (attribute 25).

The Color helper takes the 2-bit Color-Only type of RFC 9830 section 3
(`BGP_COLOR_CO_SPECIFIC`, `_NULL`, `_ANY`, `_RESERVED` for bits 00, 01, 10,
11). `_flags` sets the whole 16-bit flags field.

Family-specific attribute helpers also include:

- `bgp_attr_create_ext_comm_mac_mobility(...)`
- `bgp_attr_create_ext_comm_esi_label(...)`
- `bgp_attr_create_ext_comm_default_gateway(...)`
- `bgp_attr_create_ext_comm_router_mac(...)`
- `bgp_attr_create_ext_comm_l2info(...)`
- `bgp_attr_create_tunnel_encap_srpolicy(...)`
- `bgp_attr_create_pmsi_tunnel(...)`
- FlowSpec actions (RFC 8955 section 7, RFC 8956 section 6.1):
  `bgp_attr_create_flowspec_rate(...)`,
  `bgp_attr_create_flowspec_rate_pkts(...)`,
  `bgp_attr_create_flowspec_action(...)`,
  `bgp_attr_create_flowspec_redirect_rt(...)`,
  `bgp_attr_create_flowspec_redirect_rt_ip(...)`,
  `bgp_attr_create_flowspec_redirect_rt_as4(...)`,
  `bgp_attr_create_flowspec_redirect_rt_ipv6(...)`,
  `bgp_attr_create_flowspec_marking(...)`
- FlowSpec redirect-to-IP (draft-ietf-idr-flowspec-redirect-ip):
  `bgp_attr_create_flowspec_redirect_ipv4(...)`,
  `bgp_attr_create_flowspec_redirect_ipv6(...)`
- FlowSpec redirect to the MP_REACH next hop
  (draft-simpson-idr-flowspec-redirect): `bgp_attr_create_flowspec_redirect_nexthop(...)`
- FlowSpec interface-set (draft-ietf-idr-flowspec-interfaceset):
  `bgp_attr_create_flowspec_interface_set(...)`
- FlowSpec steering into an SR Policy (draft-ietf-idr-ts-flowspec-srv6-policy
  section 3.1.1): `bgp_attr_create_flowspec_srte(...)`
- `bgp_attr_create_bgpls(...)`

`bgp_attr_create_next_hop(...)` is the legacy IPv4 NEXT_HOP helper. MP families
use the typed `bgp_next_hop_t` passed directly to the generator.

## Main Generators

Public generators:

- `bgp_generate_update_ipv4(...)`
- `bgp_generate_update_ipv4_mp(...)`
- `bgp_generate_update_ipv6(...)`
- `bgp_generate_update_labeled_ipv4(...)`
- `bgp_generate_update_labeled_ipv6(...)`
- `bgp_generate_update_vpnv4(...)`
- `bgp_generate_update_vpnv6(...)`
- `bgp_generate_update_evpn_type1(...)`
- `bgp_generate_update_evpn_type2(...)`
- `bgp_generate_update_evpn_type3(...)`
- `bgp_generate_update_evpn_type4(...)`
- `bgp_generate_update_evpn_type5(...)`
- `bgp_generate_update_srpolicy(...)`
- `bgp_generate_update_rtc(...)`
- `bgp_generate_update_vpls(...)`
- `bgp_generate_update_mvpn_type1(...)` through `bgp_generate_update_mvpn_type7(...)`
- `bgp_generate_update_flowspec(...)` (SAFI 133 or 134, optional next hop)
- `bgp_generate_update_bgpls(...)`

These generators:

- build owned wire-format message buffers
- split messages when needed for the configured max PDU size
- return `bgp_update_result_t`

## Next-Hop And Transport Notes

- plain IPv4 unicast uses the normal IPv4 NEXT_HOP path attribute
- IPv4 unicast over IPv6 next hop uses the MP path
- IPv6 unicast and IPv6 labeled-unicast use the AFI 2 next-hop rules
- labeled IPv4 may use IPv4 next hop or IPv6 next hop where the wire format
  allows it
- VPNv4 and VPNv6 take an explicit `bgp_vpn_transport_t transport` argument
- passing `NULL` next hop encodes an all-zero next hop in the selected transport
  family
- VPNv4 and VPNv6 can encode either IPv4 or IPv6 transport next hops, as
  selected by `bgp_vpn_transport_t`
- EVPN route types 1-5 use the EVPN MP path and the typed next-hop container
- SR Policy carries AFI 1 or AFI 2 NLRI under SAFI 73, but the next hop is AFI
  independent and may still be IPv4 or IPv6
- RTC, VPLS, and BGP-LS use standard IPv4/IPv6 next-hop encoding without VPN
  RD padding
- FlowSpec uses zero-length next hop in MP_REACH_NLRI (RFC 8955 section 4).
  `bgp_generate_update_flowspec(...)` can set a 4, 16, or 32-octet next
  hop; use it only for the redirect-to-next-hop community, which reads the
  target from that field

## Extended Communities

VPN, EVPN, and the other MP families generally combine their NLRI with the same
standard attribute helpers used by the base families, including:

- ORIGIN
- AS_PATH
- LOCAL_PREF
- MED
- extended community RT helpers

Then add family-specific attributes where needed:

- EVPN MAC Mobility and ESI Label extended communities
- SR Policy Tunnel Encapsulation
- FlowSpec action communities (traffic rate, action, redirect, marking,
  redirect-to-IP, interface-set) and Color communities for SR-TE steering
- VPLS Layer2 Info
- MVPN PMSI Tunnel
- BGP-LS Attribute 29 TLVs

## Cleanup

Use:

- `bgp_path_attr_list_free(...)`
- `ipv4_nlri_list_free(...)`
- `ipv6_nlri_list_free(...)`
- `labeled_ipv4_nlri_list_free(...)`
- `labeled_ipv6_nlri_list_free(...)`
- `vpnv4_nlri_list_free(...)`
- `vpnv6_nlri_list_free(...)`
- `evpn_type1_nlri_list_free(...)`
- `evpn_type2_nlri_list_free(...)`
- `evpn_type3_nlri_list_free(...)`
- `evpn_type4_nlri_list_free(...)`
- `evpn_type5_nlri_list_free(...)`
- `srpolicy_nlri_list_free(...)`
- `flowspec_nlri_list_free(...)`
- `rtc_nlri_list_free(...)`
- `vpls_nlri_list_free(...)`
- `mvpn_type1_nlri_list_free(...)` through `mvpn_type7_nlri_list_free(...)`
- `bgpls_nlri_list_free(...)`
- `bgp_update_result_free(...)`

Single-node cleanup is also available via `bgp_path_attr_free(...)`.

## Utility Encoders

The public header also exposes low-level utility encoders:

- `bgp_encode_ipv4_prefix(...)`
- `bgp_encode_ipv6_prefix(...)`
- `bgp_encode_labeled_ipv4_prefix(...)`
- `bgp_encode_labeled_ipv6_prefix(...)`
- `bgp_encode_vpnv4_prefix(...)`
- `bgp_encode_vpnv6_prefix(...)`
- `bgp_encode_evpn_type2_prefix(...)`
- `bgp_encode_evpn_type5_prefix(...)`
- `bgp_encode_srpolicy_prefix(...)`
- `bgp_encode_flowspec_rule_afi(...)`
- `bgp_encode_flowspec_nlri_entry(...)` (one NLRI entry: optional path ID,
  RFC 8955 length, optional RD, components; ribout encodes FlowSpec with it)
- `bgp_encode_rtc_prefix(...)`
- `bgp_encode_vpls_prefix(...)`
- `bgp_encode_mvpn_type1_prefix(...)` through `bgp_encode_mvpn_type7_prefix(...)`
- `bgp_encode_bgpls_prefix(...)`
- `bgp_serialize_path_attributes(...)`

## Testing

Relevant tests:

- `$BUILD_DIR/test_bgp_update`
- `$BUILD_DIR/test_bgp_update_vpn`
- `$BUILD_DIR/test_bgp_update_evpn`
- `$BUILD_DIR/test_bgp_update_sr`
- `$BUILD_DIR/test_bgp_update_flowspec`
- `$BUILD_DIR/test_bgp_update_rtc`
- `$BUILD_DIR/test_bgp_update_vpls`
- `$BUILD_DIR/test_bgp_update_mvpn`
- `$BUILD_DIR/test_bgp_update_ls`
- split-message coverage inside `$BUILD_DIR/test_bgp_update_vpn`
- `$BUILD_DIR/test_ribout_update_generation`

Those cover:

- UPDATE encoding
- VPNv4 / VPNv6 / EVPN / SR Policy / FlowSpec / RTC / VPLS / MVPN / BGP-LS encoding
- withdrawals
- split-message behavior
- RFC 8950 paths
- RFC 8277 labeled-unicast encoding
- ADD-PATH behavior
- transport-specific VPN next-hop cases
- ribout end-to-end config to encoded wire bytes for the currently shipped
  ribout families
