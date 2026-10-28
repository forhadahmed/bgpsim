# Typed NLRI Templates

RTC, VPLS, MVPN, EVPN Types 1, 3 and 4, and BGP-LS routes are written as one
`nlri` line. This page describes that line for RTC, VPLS, MVPN and EVPN, and
the attributes those families add. BGP-LS has its own page:
[BGP-LS](bgp-ls.md).

## The `nlri` Line

Each block accepts one `nlri` line. Enter the fields in the order shown below.
Append `[step <field>] [x <count>]` to select one scaled identity field and
the number of routes. Without `step`, the default axis applies. Different
route types or shapes belong in separate ribout blocks.

```text
nlri rtc default
nlri rtc origin-as <asn> target <route-target>
nlri vpls rd <rd> ve-id <id> offset <offset> size <size> label-base <label>
nlri evpn type1 rd <rd> esi <esi> ethernet-tag <tag> label <label>
nlri evpn type3 rd <rd> ethernet-tag <tag> router <ip>
nlri evpn type4 rd <rd> esi <esi> router <ip>
nlri mvpn4 type1 rd <rd> router <ip>
nlri mvpn4 type2 rd <rd> source-as <asn>
nlri mvpn4 type3 rd <rd> source <ip> group <ip> router <ip>
nlri mvpn4 type4 route-key <hex> router <ip>
nlri mvpn4 type5 rd <rd> source <ip> group <ip>
nlri mvpn4 type6 rd <rd> source-as <asn> source <ip> group <ip>
nlri mvpn4 type7 rd <rd> source-as <asn> source <ip> group <ip>
nlri bgp-ls <node|link|ipv4-prefix|ipv6-prefix|srv6-sid|sr-policy> ...
```

The `nlri bgp-ls` lines are described on the [BGP-LS](bgp-ls.md) page.

Use `mvpn6` for the same seven route types in IPv6 MVPN. MVPN addresses must
match the selected AF, and groups must be multicast. EVPN Types 3/4 accept
IPv4 or IPv6 originating-router addresses.
The Leaf A-D Route Key is the complete encoded Type 2 or Type 3 NLRI,
including its type and length, without an ADD-PATH Path ID.

## Step Axes

| Template | Default step | Other accepted steps |
| --- | --- | --- |
| RTC membership | `target` assigned number | none |
| RTC default | none, count 1 | none |
| VPLS | `ve-id` | `rd` assigned number |
| EVPN Type 1 | `rd` assigned number | `ethernet-tag`, `esi` |
| EVPN Type 3 | `router` | `rd`, `ethernet-tag` |
| EVPN Type 4 | `router` | `rd`, `esi` |
| MVPN Types 1/2/3/5/6/7 | `rd` assigned number | `source`, `group` for Types 3/5/6/7 |
| MVPN Type 4 | `router` | none |
| BGP-LS | `identifier` | see [Identities and Scale](bgp-ls.md#identities-and-scale); up to three steps |

Counts are positive 32-bit values. Generation rejects numeric overflow,
address overflow, group ranges leaving multicast space, and invalid label
blocks. A template count multiplies with the existing `path-id` dimension;
common attributes still rotate normally. These templates do not change the
existing prefix/rotator/multiplier semantics.

## Family Attributes

```text
pmsi flags <0-255> type <0-255> label <label|vni> id <hex|ip|none>
l2-info encap <0-255> flags <0-255> mtu <0-65535>
esi-label [flags <0|1> | single-active] label <20-bit-label>
es-import mac <mac> | esi <esi>
ls <tlv-name> <fields> [x <count>] [per <axis>]
```

PMSI applies to MVPN and EVPN Type 3; `id none` encodes an empty tunnel ID,
and an IPv4 or IPv6 address encodes its 4 or 16 octets.
Layer 2 Info applies to VPLS. `esi-label` applies to EVPN Type 1: it adds the
ESI Label community that RFC 7432 requires on an Ethernet A-D per ES route
(`single-active` is `flags 1`; without either it is all-active). `es-import`
applies to EVPN Type 4: it adds the ES-Import Route Target that RFC 7432
requires on an Ethernet Segment route. `es-import esi <esi>` takes the six
high-order octets of that ESI's value, as the RFC derives it. `step esi`
makes one route per Ethernet segment.
`ls` adds one TLV to the BGP-LS Attribute; see
[Attribute Lines](bgp-ls.md#attribute-lines). Each has a matching `no` form;
`no nlri` removes the template.
Common `rt`, `soo`, communities, AS path, origin, next hop, and other
attribute commands remain available. An optional `address-family` must agree
with the template.

## Limits

RTC templates encode full memberships or the default, not partial
memberships. BGP-LS exposes typed node, link, prefix, SRv6 SID and SR Policy
descriptors, not arbitrary NLRI TLV chains. Each block has at most one PMSI
value and one family community (`l2-info`, `esi-label` or `es-import`), beside the
extended community lines of any family (`link-bandwidth`, `ext-community`). PMSI
storage is bounded at 512 bytes; CLI line/token limits also apply. IPv6 link-local companion next hops are
not accepted for templates. Source/group addresses are full-width hosts,
not multicast aggregate prefixes.

## Examples

EVPN inclusive multicast routes with a PMSI tunnel:

```text
ribout inclusive-multicast
  nlri evpn type3 rd 65000:1 ethernet-tag 1 router 192.0.2.1 x 1000
  pmsi flags 0 type 6 label 1000 id c0000201
  rt 65000:100
  next-hop 192.0.2.1
!
```

EVPN multihoming over VXLAN, for one Ethernet segment and one VNI. A second
bgpsim router that shares the ESI uses the same blocks with its own RD, router
address and next hop:

```text
ribout ad-per-es
  nlri evpn type1 rd 192.0.2.1:1 esi 00:aa:00:00:00:00:00:00:00:01 ethernet-tag max label 0
  esi-label label 0
  encap vxlan
  rt 65000:100
  next-hop 192.0.2.1
!
ribout ad-per-evi
  nlri evpn type1 rd 192.0.2.1:100 esi 00:aa:00:00:00:00:00:00:00:01 ethernet-tag 0 label 50001
  encap vxlan
  rt 65000:100
  next-hop 192.0.2.1
!
ribout segment
  nlri evpn type4 rd 192.0.2.1:1 esi 00:aa:00:00:00:00:00:00:00:01 router 192.0.2.1
  es-import esi 00:aa:00:00:00:00:00:00:00:01
  encap vxlan
  next-hop 192.0.2.1
!
```

`update generate`, `show ribout <name>`, `show ribout <name> preview`,
`advertise ribout <name> peer <ip>`, `withdraw ribout <name> peer <ip>`, and
`withdraw all peer <ip>` use the common snapshot/TX path.
