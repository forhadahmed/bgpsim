# Ribout Configuration

This page describes ribout blocks and the tokens that every family shares.
Unicast, labeled unicast and VPN routes use only these tokens. A family with
tokens of its own has its own page:

- [EVPN](ribout-evpn.md)
- [SR Policy](ribout-sr-policy.md)
- [FlowSpec](ribout-flowspec.md)
- [RTC, VPLS and MVPN templates](ribout-templates.md)
- [BGP-LS](bgp-ls.md)

For the exact generation and packing model, see [bgp-ribout.md](bgp-ribout.md).

Ribout blocks generate synthetic route sets and encode them into UPDATE
snapshots with `update generate`; [Sending UPDATEs](sending-updates.md) covers
how snapshots reach peers.

Names use letters, digits, dots, underscores, or hyphens, up to 31 characters.
Rejected edits leave the block and its cached snapshot unchanged. Accepted
edits make the snapshot stale (`show ribout <name>` prints `Status: stale`)
until the next `update generate`, which reports failure if any resolved block
fails generation and preserves its last successful snapshot.

Common shape, with the shared tokens:

```text
ribout <name>
  [address-family ...]
  prefix ...
  [rd ...]
  [label ...]
  [path-id ...]
  [next-hop ...]
  [as-path ...]
  [localpref ...]
  [med ...]
  [origin ...]
  [rt ... | rt-set ...]
  [soo ...]
  [link-bandwidth ... | mac-mobility ... | default-gateway | ext-community ...]
  [community ... | large-community ...]
  [color ...]
  [aggregator ... | atomic-aggregate | originator-id ... | cluster-list ... | aigp ... | otc ...]
  [prefix-sid ...]
  [attribute type ...]
!
```

A family page shows the shape of its own blocks.

## Family Inference

Ribout family is inferred from the configured tokens:

| Effective family | Shape |
| --- | --- |
| IPv4 unicast | IPv4 `prefix`, no `label`, no `rd` |
| IPv6 unicast | IPv6 `prefix`, no `label`, no `rd` |
| IPv4 labeled-unicast | IPv4 `prefix` plus `label`, no `rd` |
| IPv6 labeled-unicast | IPv6 `prefix` plus `label`, no `rd` |
| VPNv4 | IPv4 `prefix` plus `rd` |
| VPNv6 | IPv6 `prefix` plus `rd` |
| EVPN Type 2 | `rd` plus `mac`; optional `ip`, `label2`, `ethernet-tag`, `esi` |
| EVPN Type 5 | IPv4 or IPv6 `prefix` plus `rd` and EVPN NLRI fields such as `ethernet-tag`, `gateway-ip`, or `esi` |
| SR Policy IPv4 | `distinguisher` plus `color` plus IPv4 `endpoint` |
| SR Policy IPv6 | `distinguisher` plus `color` plus IPv6 `endpoint` |
| IPv4 FlowSpec | FlowSpec `address-family` or a FlowSpec line (`src-prefix`, component, `action`); IPv4; no `rd` |
| IPv6 FlowSpec | the same with IPv6 prefixes |
| IPv4 FlowSpec VPN | the same plus `rd`, IPv4 prefixes |
| IPv6 FlowSpec VPN | the same plus `rd`, IPv6 prefixes |

`color` does not select a family: it is the SR Policy color in a block with
`endpoint`, and a Color community in any other family. `rt`, `rt-set` and `soo`
do not select one either: an IPv4 `prefix` with `rt` and no `rd` is IPv4
unicast with a route target. A `prefix` with only
attribute lines is unicast; a FlowSpec block with only `prefix` needs
`address-family`, and so does a FlowSpec block without a prefix, for example
`address-family ipv6 flowspec`.

A block with an `nlri` line is a [typed template](ribout-templates.md): the
line names its family (RTC, VPLS, MVPN, EVPN Types 1, 3 and 4, BGP-LS).

### `address-family <family>`

Optional. Names the ribout family with the neighbor family names (for example
`ipv4`, `vpnv4`, `l2vpn evpn`, `ipv6 flowspec-vpn`, `ipv4 srpolicy`). The
configured tokens must agree with it; otherwise generation stops with an
error. A name that is not a neighbor family is rejected.

## Token Reference

Numbers are plain decimal digits within their field: no sign (`+5`, `-1`), no
spaces or other text inside them, and a count after `x` is 1 or more (`x 0`
is an error rather than an empty list). A line must end where its syntax
ends; text after the last value is an error, never ignored. A rejected line
leaves the ribout as it was.

### `prefix <ip-prefix> [x <count>]`

Generate one or more IPv4 or IPv6 prefixes. Each next prefix is the next
whole block of the same length, so `10.0.0.0/24 x 3` gives `10.0.0.0/24`,
`10.0.1.0/24`, and `10.0.2.0/24`. The last prefix must fit in the address
space; `255.255.255.0/24 x 2` is an error.

In a FlowSpec block, `prefix` is the destination prefix (component type 1).
An IPv6 FlowSpec destination can use the RFC 8956 offset form
`<ip>/<offset>-<length>`, for example `2001:db8::/8-64`; the offset must be
less than the length. Other families reject an offset. Only the bits from the
offset to the length are on the wire, so they alone make the route key: two
prefixes that differ only before the offset are the same route, and `x <count>`
may not exceed the 2^(length - offset) values those bits have. A sequence that
steps past the last of them continues from the first.

Examples:

```text
prefix 10.0.0.0/24
prefix 10.0.0.0/24 x 100
prefix 2001:db8:100::/64 x 50
```

### Randomness And `RANDSEED`

Ribout `rand(...)` and `randrange(...)` surfaces are deterministic by default.
If `RANDSEED` is unset, each ribout derives its random stream from the ribout
name, so the same config produces the same sequence across preview and
generation.

To perturb all ribout random surfaces reproducibly for one process run, start
`bgpsim` with `RANDSEED=<u32>` in the environment. The generator still derives
an independent stream per ribout from the ribout name, so ribout ordering does
not affect the produced values.

Example:

```text
RANDSEED=424242 ./bgpsim config.txt
```

### Rotating key lists

The lists that make route keys (`prefix` aside) multiply the routes: each
route is generated once per value. With `rotate` after the keyword such a list
gives each route one value in turn instead: rotation step i takes value
i mod n, in step with `rt-set`, the communities and the other rotations (see
`rotate-every`, `rotate-period`), and the route count no longer counts it.
The keys stay distinct, because the lists that do not rotate still tell the
routes apart. `rd`, `label` (outside EVPN Type 2, where labels always rotate),
`ethernet-tag`, `path-id`, `distinguisher`, `color` and `endpoint` (SR Policy)
and the FlowSpec operator components take `rotate`. Write `rotate` right after
the keyword: `color 100 rotate` is rejected.

```text
distinguisher 1 x 4
endpoint 10.0.0.1 x 1000
color rotate 100 x 10
```

makes 4000 SR Policies, policy i with color 100 + i mod 10, instead of 40000.

### `rd [rotate] <values>`

Set one or more route distinguishers for VPN or EVPN routes. Several RDs
multiply the routes: each prefix is generated once per RD. With `rotate` they
go one per rotation step instead (see `rotate-every`), like `rt-set`, so each
VRF's routes can carry an RD of their own. A sequence stores its base and
count; an explicit list grows as it is written.

Examples:

```text
rd 65000:100
rd 65000:100 65000:101
rd 65000:100 x 64
rd rotate 65551:1 x 100
```

### `label <values>`

Set MPLS labels (0-1048575). Presence of `label` without `rd` infers labeled-unicast.

On EVPN ribouts the label field carries the VNI instead when the path's `encap` is a VXLAN-like tunnel (see `encap`),
and then values up to 16777215 are allowed, provided every `encap` value of the ribout is such a tunnel.

Several labels multiply the routes: each prefix is generated once per label.
With `rotate` they go one per path in turn instead, like `rt-set`, and the route
count stays the same. Path i then carries label i mod n, so with as many
`rt-set` sets as labels, each label goes with one route target: per-VRF labels
or VNIs.

Examples:

```text
label 16000
label 16000 16001 16002
label 16000 x 32
label rotate 24001 x 100
```

### `path-id [rotate] <ids>`

Set one or more ADD-PATH identifiers: each prefix is sent once per ID, or with
`rotate` once, with ID i mod n.

Examples:

```text
path-id 1
path-id 1 2 3 4
path-id rotate 1 x 4
```

### `next-hop <ip-prefix> [x <count>] [link-local <ipv6>]`

Set the next-hop rotation.

Examples:

```text
next-hop 192.0.2.1
next-hop 192.0.2.1 x 8
next-hop 2001:db8:ffff::1
next-hop 2001:db8:ffff::1 x 4 link-local fe80::1
```

Notes:

- IPv4 and IPv6 next hops are both supported where the target family allows it
- the optional `link-local` companion is for IPv6-family MP_REACH next hops

### `as-path <segments>`

Set the AS_PATH spec. `<asn> x <count>` repeats one AS number, for
prepending: `as-path 65001 x 3 65002`.

| Form | Segment |
| --- | --- |
| `65001 65002` | AS sequence |
| `{ 65002 65003 }` | AS set |
| `( 64512 64513 )` | confederation sequence (RFC 5065) |
| `[ 64514 64515 ]` | confederation set (RFC 5065) |
| `[rand(<max>) x <count>]`, `rand(<max>)` | AS sequence of random AS numbers |

A segment holds up to 100 AS numbers, and a bracketed one at least one. bgpsim
sends the segments as written: it does not check that a confederation segment
goes only to a peer of the same confederation.

Examples:

```text
as-path 65001 65002 65003
as-path 65001 { 65002 65003 } 65004
as-path 65001 [rand(65000) x 4]
as-path ( 64512 64513 ) 65001
```

#### `as-path two-byte [<segments>]`

AS numbers take four octets on a session where both sides have
`capability four-byte-asn`, and two octets on any other session (RFC 6793).
A ribout is encoded once, in one of the two forms. `two-byte` before the
segments selects the second form:

```text
as-path two-byte 65001 70000
```

- AS_PATH has two octets for each AS number. An AS number above 65535 goes
  out as AS_TRANS (23456).
- AS4_PATH carries the path with four octets for each AS number. It is left
  out when every AS number fits two octets, and it never holds the
  confederation segments.
- `as-path two-byte` alone is an empty path in this form, for an internal
  session.

Such a ribout goes only to a session without 4-octet AS numbers; any other
session has it withheld, and a ribout without `two-byte` is withheld from a
session without them. `show bgp neighbors` gives the reason either way. To
get such a session, enter `no capability four-byte-asn` on the neighbor, or
peer with a speaker that does not have the capability.

The `aggregator` line of such a block follows the same rule: AGGREGATOR has
its AS number in two octets, AS_TRANS when it is above 65535, and
AS4_AGGREGATOR then carries the real number. A raw `attribute type 7` line is
sent as written.

### `localpref <value>`

Set LOCAL_PREF. The default is 100, and every UPDATE carries the attribute.
`localpref none` sends no LOCAL_PREF at all, which is what a speaker sends to
an external peer (RFC 4271 section 5.1.5). `no localpref` returns to 100.

Examples:

```text
localpref 100
localpref rand(300)
localpref range(100,110)
localpref randrange(100,110)
localpref none
```

### `med <value>`

Set MED.

Examples:

```text
med 50
med rand(25)
med range(10,25)
med randrange(10,25)
```

### `origin <igp|egp|incomplete>`

Set ORIGIN.

### `rt <values>`

Build one fixed route-target set by repeating `rt` lines. `<base> x <count>`
adds consecutive route targets: `rt 65000:1 x 4` is `65000:1` to `65000:4`.

`rt`, `rt-set` and `soo` are extended communities and do not select a family:
without `rd` the block stays unicast or labeled unicast and its routes carry
them.

Example:

```text
rt 65000:100
rt 65000:101
```

### `rt-set <sets>`

Rotate whole RT sets across the generated path stream: path i carries set
i mod n (see `rotate-every`). `rt-set` lines append, so a long
list takes several lines (a command holds at most 32 tokens; a bracketed set
is one token, whatever its length); running-config splits it the same way.
`<set> x <count>` adds count sets, each route target's local administrator one
larger each time, so `[65551:1,65551:1001] x 100` is
`[65551:1,65551:1001] [65551:2,65551:1002] ... [65551:100,65551:1100]`; it
must fit the field (four octets after a two-octet AS, two after an IPv4
address or a four-octet AS). Sequences retain their base and count rather
than an expanded array; mixed explicit sets and sequences remain compact.
The total logical set count cannot exceed `UINT32_MAX`.

Example:

```text
rt-set [65000:100] [65000:200,65000:201]
rt-set [65000:300]
rt-set [65551:1,65551:1001] x 100
```

`rt` and `rt-set` are mutually exclusive.

### `community <sets>` and `large-community <sets>`

COMMUNITIES (attribute 8, RFC 1997) and LARGE_COMMUNITY (attribute 32,
RFC 8092), both optional transitive, in the `rt-set` style: a set is
`[v,v,...]` or one value, several sets rotate per path (path i carries set
i mod n, see `rotate-every`), and `<set> x <count>` adds count sets. Lines
append, so a long list takes several lines; running-config prints the sets as
written and splits them the same way. A line with an invalid set adds none of
its sets. `no community` / `no large-community` remove every set.

- A community is `<0-65535>:<0-65535>` or a well-known name: `no-export`,
  `no-advertise`, `no-export-subconfed`, `no-peer`, `blackhole`,
  `graceful-shutdown`, `accept-own`, `llgr-stale`, `no-llgr`. In a sequence
  each community's low half steps by one per set and must stay within 65535;
  well-known values (65535:x, by name or number) stay as they are.
- A large community is `<global>:<data1>:<data2>`, three 32-bit values. In a
  sequence data2 steps by one per set and must stay within 4294967295.
- A set holds up to 16 values and lists each value once (RFC 8092 forbids
  sending duplicate large communities). The inventory of written sets grows
  on demand; a sequence occupies one entry. Total logical sets per keyword
  cannot exceed `UINT32_MAX`.

```text
community [65000:1,no-export] 65000:100 x 2
community [blackhole,65001:7]
large-community [65551:1:1,65551:2:1] x 100
```

The first two lines make four sets: `[65000:1,no-export]`, `[65000:100]`,
`[65000:101]` and `[blackhole,65001:7]`. Community sets take part in
`rotate-every` and `rotate-period` like `rt-set`; the bracketed form is one
token, so a set of 16 large communities fits on one line.

### `rotate-every <n>`

Advance the rotations once every n paths instead of every path, so blocks of
n consecutive paths share them: `rt-set`, `community`, `large-community`,
`rd rotate`, `label rotate`,
`next-hop` lists, `soo`, `encap`, `router-mac`, `color` (outside SR Policy),
EVPN Type 2 `label`, `label2` and `esi`, ranges such as `med range(...)`,
FlowSpec action lists, and random values. Route i then carries entry
(i / n) mod count of each, so with `prefix ... x 10000`, `rt-set ... x 100` and
`rotate-every 100` each VRF gets a contiguous block of 100 prefixes. NLRI keys
still change every path.

### `rotate-period <n>`

Require every rotating list (`rt-set`, `community`, `large-community`,
`rd rotate`, `label rotate`,
`next-hop`, `soo`, `encap`, `router-mac`, `color`, EVPN Type 2 `label`,
`label2`, `esi`) to have n values, or one. They then advance in step: rotation
step r takes entry r mod n of each, the route target, RD, label and next hop
of one VRF. A list of another length fails generation with its name.

```text
rd rotate 65551:1 x 100
label rotate 24001 x 100
rt-set [65551:1] x 100
rotate-period 100
```

### `message-size <octets>`

Set the largest UPDATE the ribout packs, from 64 to 65535 octets. The default
is 4096, the limit of RFC 4271. The withdrawal of the ribout is packed to the
same size.

- Above 4096 the UPDATEs are Extended Messages (RFC 8654). The ribout is then
  sent only on a session where both sides advertised the capability: enter
  `capability extended-message` on the neighbor. Other sessions have it
  withheld, with the reason shown.
- A larger size means fewer UPDATEs when many routes share their attributes:
  20000 IPv4 prefixes of one attribute group are 20 UPDATEs at 4096 octets and
  2 at 65535.
- A smaller size means more UPDATEs for the same routes, down to a few routes
  in each.
- When the path attributes and one route do not fit, `update generate` fails
  for the ribout and says so.
- `show ribout <name>` prints the size, and the snapshot line ends in
  `extended-message` when it is above 4096.

```text
ribout bulk
  prefix 10.0.0.0/24 x 100000
  next-hop 192.0.2.1
  message-size 65535
!
router bgp 65001
  neighbor 192.0.2.2 remote-as 65002
    capability extended-message
    advertise bulk
!
```

### `soo <values>`

Set one or more site-of-origin values. `<base> x <count>` adds consecutive
values, as for `rt`.

Example:

```text
soo 65000:9
```

### Other extended communities

Each of these lines adds its extended communities to every route of the
block. A line of the same keyword replaces the earlier one, and
`no <keyword>` removes it.

```text
link-bandwidth <asn> <bits-per-second>[k|m|g] [transitive]
mac-mobility <sequence> [sticky]
default-gateway
ext-community <16 hex digits> ...
```

| Line | Community | Notes |
| --- | --- | --- |
| `link-bandwidth` | Link Bandwidth (sub-type `0x04`) | a 2-octet AS number and a rate, written as for `ls max-bandwidth`: `10g` is 10 Gbit/s |
| `mac-mobility` | EVPN MAC Mobility, RFC 7432 section 7.7 | the sequence number; `sticky` marks a static MAC |
| `default-gateway` | EVPN Default Gateway, RFC 7432 section 7.8 | no value |
| `ext-community` | any | each value is its eight octets as hex; at most 8 values |

The rate of `link-bandwidth` goes out in octets per second as an IEEE
floating-point number, so `10g` is `0x4e9502f9`. The community is of the type
that does not cross an AS boundary (`0x40`); `transitive` makes it type
`0x00`.

`mac-mobility` and `default-gateway` belong to MAC/IP Advertisement routes:
a block of another family with one of them does not generate. To move a MAC,
enter a larger sequence number, then generate and advertise again.

`ext-community` is for a community bgpsim has no line for, on any family.
The first octet is the type and the second the sub-type:

```text
link-bandwidth 65001 10g
mac-mobility 5 sticky
ext-community 0004fde94cee6b28 8f991234deadbeef
```

`show ribout <name>` prints each of these lines with the octets it adds.

### Other path attributes

Each of these lines adds one path attribute to every route of the block. A
line of the same attribute replaces the earlier one, and `no <keyword>`
removes it. bgpsim sends them as written, to any peer.

```text
aggregator <asn> <ipv4>
atomic-aggregate
originator-id <ipv4>
cluster-list <ipv4|number> ...
aigp <metric>
otc <asn>
attribute type <0-255> value <hex> [flags <hex>]
```

| Line | Attribute | Notes |
| --- | --- | --- |
| `aggregator` | AGGREGATOR (7) | a 4-octet AS number and the aggregator address |
| `atomic-aggregate` | ATOMIC_AGGREGATE (6) | no value |
| `originator-id` | ORIGINATOR_ID (9), RFC 4456 | |
| `cluster-list` | CLUSTER_LIST (10), RFC 4456 | one or more cluster ids, as addresses or numbers |
| `aigp` | AIGP (26), RFC 7311 | one AIGP TLV with a 64-bit metric |
| `otc` | Only-to-Customer (35), RFC 9234 | the AS number |
| `attribute` | any other type | the value as hex; `flags` defaults to optional transitive (`0xc0`) |

`attribute` is for an attribute bgpsim has no line for. It is refused for the
types bgpsim builds from their own lines (ORIGIN, AS_PATH, NEXT_HOP, MED,
LOCAL_PREF, the community attributes, MP_REACH_NLRI and the rest). A raw line
with the type of a named line replaces it. `no attribute` removes every raw
line.

The value of `aggregator` (its AS number), `originator-id`, `aigp` and `otc`
can vary from route to route. `x <count>` makes a sequence over the routes of
the block, as on a BGP-LS line. On a block with an `nlri` template,
`per <step-field>` makes the value follow that field instead:

```text
aigp 1000 x 16
originator-id 10.0.0.1 per router
```

Attributes are sent in type order, whatever the order of the lines.

### `prefix-sid <tlv> ...`

Each `prefix-sid` line adds one TLV to the BGP Prefix-SID attribute (type 40).
A line of the same TLV replaces the earlier one; `no prefix-sid` removes them
all.

```text
prefix-sid index <index>
prefix-sid srgb range <first-label> <size> [<first-label> <size> ...]
prefix-sid srv6-l3 <sid>[/<bits>] behavior <name|number> [flags <n>] [structure <block> <node> <function> <argument> [transposition <length> <offset>]]
prefix-sid srv6-l2 <sid>[/<bits>] behavior <name|number> [flags <n>] [structure ...]
```

- `index` is the Label-Index TLV and `srgb` the Originator SRGB TLV (RFC 8669),
  for labeled unicast routes.
- `srv6-l3` and `srv6-l2` are the SRv6 L3 and L2 Service TLVs (RFC 9252), for
  VPN and EVPN routes: one SRv6 SID with its endpoint behavior and, with
  `structure`, its SID structure. `behavior` takes the names of the BGP-LS
  lines (`end.dt4`, `end.dt6`, `end.dx2`, ...) or a number.

The index and the SID can vary from route to route with `x <count>` or
`per <step-field>`. `/<bits>` says where a sequence adds to the SID:

```text
ribout sr-labels
  prefix 10.0.0.0/24 x 1000
  label 16000 x 1000
  prefix-sid index 0 x 1000
  prefix-sid srgb range 16000 8000
  next-hop 192.0.2.1
!
ribout srv6-vpn
  prefix 10.1.0.0/24 x 1000
  rd 65000:1
  label 3
  rt 65000:1
  prefix-sid srv6-l3 fc00:0:1:1::/64 behavior end.dt4 structure 32 16 16 0 transposition 16 48 x 1000
  next-hop 192.0.2.1
!
```

bgpsim does not check the family: a Prefix-SID line is sent on any block that
has it.

### `color [rotate|set] <c> [co <bits>] ... | [rotate|set] <base> x <count> [co <bits>]`

The family gives the meaning of `color`:

- SR Policy (a block with `endpoint`): the Policy Color of the NLRI
  (RFC 9830 section 2.1). Each value is a different policy, so the values
  multiply the paths; with `color rotate ...` each policy takes one color in
  turn instead. `co` is an error here.
- Any other family: one Color Extended Community (type 0x030b, RFC 9012
  section 4.3) on each path. The values rotate, one per path, in step with
  `next-hop` and the FlowSpec `action` values. `rotate` changes nothing.

`color set ...` carries every listed Color community on each advertised path,
in the configured order. It accepts the same values, sequences, ranges, and
per-value CO bits. It does not multiply paths or participate in `rotate-period`.
For example, `color set 100 300 200` sends all three Colors together, allowing
the receiver's largest-Color selection to be tested from wire attributes.
The generator preserves the values and does not select a winner.

Set mode is rejected for SR Policy NLRIs and cannot be combined with `rotate`.
A new `color` line replaces the previous mode and values; `no color` clears
both. The current per-path budget is 76 extended communities, shared with
route targets, FlowSpec actions, and other extended communities. A set that
exceeds that total fails generation without replacing the previous snapshot.

`co <bits>` sets the RFC 9830 Color-Only type in the two high bits of the
Color flags: `00` specific endpoint (the default), `01` specific or null
endpoint, `10` specific, null, or any endpoint, `11` reserved (accepted so a
test can send it). After a value it sets that value; at the end of a
sequence or `range(a,b)` it sets every value.

Examples:

```text
color 200
color 200 201 202
color 200 x 64
color 1 x 3 co 01
color 4 co 10 7
color set 100 300 200
color set 100 co 01 300 co 10 200
color set 100 x 3
```

Steer prefix i into the policy (endpoint .201 + i mod 3, color 1 + i mod 3):

```text
ribout colored-v4
  prefix 10.1.0.0/24 x 6
  next-hop 10.255.0.201 x 3
  color 1 x 3
!
```

## Examples

IPv4 unicast:

```text
ribout demo-v4
  prefix 10.0.0.0/24 x 100
  path-id 1 2
  next-hop 192.0.2.1 x 2
  as-path 65001 65002
  localpref 150
  origin igp
!
```

IPv6 unicast:

```text
ribout demo-v6
  prefix 2001:db8:100::/64 x 100
  next-hop 2001:db8:ffff::1 x 2 link-local fe80::1
  as-path 65010 65020
  localpref 200
  origin igp
!
```

IPv4 labeled-unicast:

```text
ribout demo-lu4
  prefix 10.10.0.0/24 x 100
  label 16000 x 4
  path-id 100 200
  next-hop 192.0.2.1
  as-path 65100 65200
  localpref 100
  origin igp
!
```

VPNv4:

```text
ribout demo-vpn4
  prefix 10.20.0.0/24 x 100
  rd 65000:100 x 8
  label 24000 x 4
  rt-set [65000:100] [65000:200,65000:201]
  soo 65000:9
  next-hop 192.0.2.1
  med 50
  as-path 65300 65400
  localpref 175
  origin igp
!
```

## Important Notes

- `preview` shows the generated path stream, not final UPDATE packing
- FlowSpec route scale comes from the `prefix` / `src-prefix` counts, the
  component generators (`x <count>`, `each(...)`), `rd`, and `path-id`; action
  lines with several values and `color` lists rotate and split attribute groups
- route scale comes from family-owned NLRI-side dimensions such as `prefix`,
  `rd`, `label`, `path-id`, `mac`, `ip`, `distinguisher`, `color` (SR Policy
  only), and `endpoint`
- some family-specific NLRI fields still rotate over the emitted stream instead
  of multiplying total path count; EVPN Type 2 `label`, `label2`, and `esi` are
  the main current examples
- attribute fragmentation comes from tokens such as `next-hop`, `rt-set`,
  `soo`, `encap`, `router-mac`, `color` (outside SR Policy), `localpref`,
  `med`, `as-path`, `enlp`, `priority`, `preference`, `binding-sid`, and
  FlowSpec `action` lines with several values

See [bgp-ribout.md](bgp-ribout.md#exact-generator-order) for the exact rotation
order and grouping rules.
