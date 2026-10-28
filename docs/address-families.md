# BGP Address Family Support Matrix

This document tracks address-family support in three layers:

- `OPEN wire`: MP-BGP capability and related OPEN capability encoding/parsing
- `neighbor CLI`: neighbor submode config commands
- `UPDATE / ribout`: low-level UPDATE generation and ribout end-to-end config
  to encoded UPDATE bytes

## Support Matrix

| Family | AFI/SAFI | OPEN wire | Neighbor CLI | `ext-nh` OPEN | UPDATE encoding | Ribout e2e | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| IPv4 unicast | `1/1` | yes | yes | yes | yes | yes | RFC 8950 IPv6 next hop supported |
| IPv6 unicast | `2/1` | yes | yes | n/a | yes | yes | IPv4 next hop encoding supported on UPDATE side |
| IPv4 labeled-unicast | `1/4` | yes | yes | yes | yes | yes | single-label RFC 8277 path only |
| IPv6 labeled-unicast | `2/4` | yes | yes | n/a | yes | yes | single-label RFC 8277 path only |
| VPNv4 | `1/128` | yes | yes | yes | yes | yes | IPv6 next hop via RFC 8950 |
| VPNv6 | `2/128` | yes | yes | no | yes | yes | IPv4 or IPv6 transport per RFC 4659 |
| L2VPN EVPN | `25/70` | yes | yes | no | yes | yes | route types 1-5; types 1/3/4 use typed templates |
| IPv4 SR Policy | `1/73` | yes | yes | no | yes | yes | ribout uses IPv4-address RT signaling today |
| IPv6 SR Policy | `2/73` | yes | yes | no | yes | yes | endpoint AF is part of the NLRI |
| IPv4 FlowSpec | `1/133` | yes | yes | no | yes | yes | RFC 8955 actions, redirects, Color/CO, SR-TE steer |
| IPv6 FlowSpec | `2/133` | yes | yes | no | yes | yes | RFC 8956 offsets, Flow Label, attribute 25 |
| IPv4 VPN FlowSpec | `1/134` | yes | yes | no | yes | yes | RFC 8955 section 8; ribout `rd` selects SAFI 134 |
| IPv6 VPN FlowSpec | `2/134` | yes | yes | no | yes | yes | RFC 8955 section 8 with RFC 8956 components |
| BGP-LS | `16388/71` | yes | yes | no | yes | yes | typed node/link/prefix descriptors; opaque attribute TLV |
| IPv4 MVPN | `1/5` | yes | yes | no | yes | yes | typed templates for route types 1-7, PMSI attribute |
| IPv6 MVPN | `2/5` | yes | yes | no | yes | yes | typed templates for route types 1-7, PMSI attribute |
| IPv4 RTC | `1/132` | yes | yes | no | yes | yes | default or full membership templates |
| L2VPN VPLS | `25/65` | yes | yes | no | yes | yes | VE/label-block template, Layer 2 Info community |

## Notes by Layer

### OPEN Wire Support

The OPEN builder/parser supports:

- MP-BGP capability for the families listed above
- route-refresh
- 4-octet AS numbers (RFC 6793)
- graceful restart, including AFI/SAFI tuples
- add-path capability tuples for supported generated families
- extended next-hop capability tuples where applicable

### Neighbor CLI Commands

Neighbor submode configs:

- `address-family ipv4`
- `address-family ipv6`
- `address-family ipv4 labels`
- `address-family ipv6 labels`
- `address-family vpnv4`
- `address-family vpnv6`
- `address-family l2vpn evpn`
- `address-family ipv4 flowspec`
- `address-family ipv6 flowspec`
- `address-family ipv4 flowspec-vpn`
- `address-family ipv6 flowspec-vpn`
- `address-family ipv4 srpolicy`
- `address-family ipv6 srpolicy`
- `address-family bgp-ls`
- `address-family ipv4 mvpn`
- `address-family ipv6 mvpn`
- `address-family ipv4 rtc`
- `address-family l2vpn vpls`
- `capability add-path`
- `capability add-path <af>`
- `capability ext-nh`
- `capability ext-nh <af>`

`capability add-path <af>` is currently valid for:

- `ipv4`
- `ipv6`
- `ipv4 labels`
- `ipv6 labels`
- `vpnv4`
- `vpnv6`
- `l2vpn evpn`
- `ipv4 flowspec`
- `ipv6 flowspec`
- `ipv4 flowspec-vpn`
- `ipv6 flowspec-vpn`
- `ipv4 srpolicy`
- `ipv6 srpolicy`
- `bgp-ls`
- `ipv4 mvpn`
- `ipv6 mvpn`
- `ipv4 rtc`
- `l2vpn vpls`

`capability ext-nh <af>` is currently valid for:

- `ipv4`
- `ipv4 labels`
- `vpnv4`

### UPDATE and Ribout Coverage

Low-level UPDATE encoding covers:

- announcements
- withdrawals
- ADD-PATH
- split-message generation
- applicable cross-family next-hop variants

Ribout end-to-end coverage currently includes:

- IPv4 / IPv6 unicast
- IPv4 / IPv6 labeled-unicast
- VPNv4 / VPNv6
- EVPN Types 1-5
- SR Policy IPv4 / IPv6
- FlowSpec IPv4 / IPv6 and VPN FlowSpec IPv4 / IPv6
- RTC, VPLS, IPv4 / IPv6 MVPN Types 1-7, and BGP-LS node/link/prefix templates

These paths include immutable snapshots, ADD-PATH, message splitting, live
advertisement, and withdrawal. Socket tests check independently specified wire
bytes; this does not establish acceptance by every receiver release.

## Cross-Family Next-Hop Notes

### RFC 8950 `ext-nh`

The current code uses RFC 8950-style extended next-hop support for:

- IPv4 unicast over IPv6 next hop
- IPv4 labeled-unicast over IPv6 next hop
- VPNv4 over IPv6 next hop

### IPv6-Family Next Hops over IPv4 Underlay

IPv6-family support is different:

- IPv6 unicast and IPv6 labeled-unicast support IPv4 next-hop encoding on the
  UPDATE side
- this is not modeled as RFC 8950 `ext-nh`
- VPNv6 over IPv4 transport is supported per RFC 4659

## EVPN Scope

EVPN support is split by layer:

- AFI/SAFI `25/70`
- low-level UPDATE encoding for route types 1-5
- ribout end-to-end support for route types 1-5
- Type 1 templates currently encode MPLS labels, not VXLAN VNIs

## Practical Summary

If you are testing from the CLI today:

- IPv4 and IPv6 unicast are fully usable
- all listed families are usable from ribout and neighbor AF config, subject
  to the template and attribute limits in [configuration.md](configuration.md)
- ADD-PATH and RFC 8950 ext-nh now have explicit neighbor CLI knobs

If you are testing from the low-level API:

- use the API docs for exact constructor and generator coverage across EVPN,
  FlowSpec, RTC, VPLS, MVPN, and BGP-LS
