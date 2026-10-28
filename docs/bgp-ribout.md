# RIB-OUT Implementation Guide

This document explains the current ribout generation model as implemented in
`bgpsim`. [configuration.md](configuration.md) is the syntax reference. This document is the
focused model document: how a ribout block turns into a generated path stream,
how that stream is grouped into a canonical ribout map, and how the map is
encoded into BGP UPDATE messages.

## Why This Matters

Ribout is intentionally a low-friction route generator for interactive testing.
That only works if the rotation rules are predictable.

The important point is:

- Ribout is **not** a full Cartesian product over every configured token.
- Some tokens increase the number of generated paths.
- Some tokens only rotate over that generated path stream and change grouping.

That distinction is what makes ribout practical for scale testing.

## Pipeline

The full pipeline is:

```text
ribout config
  -> generated path stream
  -> grouped ribout map
  -> encoded UPDATE messages
```

Each stage has a different purpose:

- `ribout config`
  - The desired generation recipe.
- `generated path stream`
  - One logical path record per emitted route variant, in deterministic order.
- `grouped ribout map`
  - The canonical grouped form used for UPDATE packing.
- `encoded UPDATE messages`
  - Wire-format messages split to fit BGP message size limits.

## Family Inference

The effective family is inferred from the configured tokens. The optional
`address-family` line (neighbor family names, for example `vpnv4` or
`ipv6 flowspec-vpn`) names the family; the tokens must agree with it, or
generation stops with an error.

| Effective family | Required shape |
| --- | --- |
| `ipv4-unicast` | IPv4 `prefix`, no `label`, no `rd` |
| `ipv6-unicast` | IPv6 `prefix`, no `label`, no `rd` |
| `ipv4-labeled-unicast` | IPv4 `prefix` plus `label`, no `rd` |
| `ipv6-labeled-unicast` | IPv6 `prefix` plus `label`, no `rd` |
| `vpnv4` | IPv4 `prefix` plus `rd` |
| `vpnv6` | IPv6 `prefix` plus `rd` |
| `evpn-type2` | `rd` plus `mac`; optional `ip`, `label2`, `ethernet-tag`, or `esi` |
| `evpn-type5-ipv4` | IPv4 `prefix` plus `rd` and any EVPN token such as `ethernet-tag`, `gateway-ip`, or `esi` |
| `evpn-type5-ipv6` | IPv6 `prefix` plus `rd` and any EVPN token such as `ethernet-tag`, `gateway-ip`, or `esi` |
| `ipv4-sr-policy` | IPv4 `endpoint` plus `distinguisher` and `color` |
| `ipv6-sr-policy` | IPv6 `endpoint` plus `distinguisher` and `color` |
| `ipv4-flowspec` | FlowSpec `address-family` or FlowSpec lines, IPv4 `prefix` / `src-prefix`, no `rd` |
| `ipv6-flowspec` | FlowSpec `address-family` or FlowSpec lines, IPv6 `prefix` / `src-prefix`, no `rd` |
| `ipv4-flowspec-vpn` | the same plus `rd`, IPv4 prefixes |
| `ipv6-flowspec-vpn` | the same plus `rd`, IPv6 prefixes |
| RTC / VPLS | `nlri rtc ...` / `nlri vpls ...` |
| EVPN Types 1/3/4 | `nlri evpn type1 ...`, `type3 ...`, or `type4 ...` |
| MVPN IPv4 / IPv6 | `nlri mvpn4 type1 ...` through `type7 ...`, or `mvpn6` |
| BGP-LS | `nlri bgp-ls node`, `link`, `ipv4-prefix`, or `ipv6-prefix` |

Notes:

- `label` without `rd` means labeled-unicast, not VPN.
- `rd` is what moves a block into VPN/EVPN space.
- EVPN Type 2 is inferred from `rd` plus `mac`.
- EVPN Type 5 is inferred from `prefix` plus `rd` and EVPN-specific NLRI
  fields such as `ethernet-tag`, `gateway-ip`, or `esi`.
- SR Policy is inferred from `endpoint` (with `distinguisher` and `color`).
  `color` alone does not select SR Policy: outside SR Policy it is a Color
  community.
- FlowSpec is selected by a FlowSpec line (`src-prefix`, an operator
  component, an `action`) or a FlowSpec `address-family`. `prefix` (the
  destination) and `src-prefix` give the AFI; a block without them, or with
  only `prefix`, needs `address-family`. `rd` selects SAFI 134.

## Typed Templates

Each template-backed block has one pointer-free typed NLRI recipe. An optional
`step <field> x <count>` varies one identity field; `x <count>` uses the
family's default axis. Only the template count and the existing `path-id`
dimension multiply paths. Common next-hop and attribute rotators retain their
normal semantics. The template cannot be mixed with another NLRI model's
prefix, RD, label, EVPN, FlowSpec, or SR Policy tokens.

The grouped map stores a compact instance index and Path ID, rather than a
heap-allocated protocol object per route. The family encoder materializes
typed NLRIs from that index. Existing low-level codecs own all wire layouts.
Optional PMSI, VPLS Layer 2 Info, and BGP-LS attributes join the common
attribute path; there is no separate transmit engine.

Snapshots own independent copies of the recipe and attributes. Regeneration
does not mutate an outstanding advertisement's withdrawal data. Peer ownership
checks compare identity ranges, not labels: EVPN Type 1 labels and VPLS label
base/block size are forwarding information, not route keys.

The files, in call order:

```text
CLI / config / control API
  -> bgp_ribout_edit.c: atomic configuration edits
  -> bgp_ribout_template.c: typed recipe, validation, one-axis generation
  -> bgp_ribout.c: common attributes and grouped map
  -> bgp_update_<family>.c: canonical wire encoders
  -> bgp_ribout_snapshot.c: immutable advertisement stream; withdrawals are
     derived from it on demand
  -> bgp_peer_tx.c: common peer ownership and TX
```

See [configuration.md](configuration.md#typed-nlri-templates) for the grammar,
default axes, and supported scope.

## Token Classes

The easiest way to understand ribout is to split tokens into two classes.

### NLRI-Side Tokens

These tokens define route identity. For the original unicast / labeled / VPN /
EVPN Type 5 families, they also increase the number of generated paths:

- `prefix`
- `rd`
- `ethernet-tag`
- `gateway-ip`
- `esi`
- `label`
- `path-id`

Family-specific additions:

- EVPN Type 2 introduces `mac`, optional `ip`, and optional `label2`
- SR Policy introduces `distinguisher`, `color`, and `endpoint`
- FlowSpec uses `prefix` as the destination and adds `src-prefix` and the
  operator components (`protocol`, `dst-port`, ...); the prefix counts and
  the component generators (`<cmp> x <count>`, `each(...)`) multiply paths

These tokens stay on the NLRI side of the ribout map. They do not create new
attribute groups by themselves, but not every NLRI-side token is necessarily a
path-count multiplier in every family.

### Attribute-Side Tokens

These tokens do **not** increase `total_paths`. They are overlaid onto the
generated stream and mostly affect grouping and message count:

- `next-hop`
- `as-path`
- `localpref`
- `med`
- `origin`
- `rt`
- `rt-set`
- `community`, `large-community`
- `soo`
- `encap`
- `router-mac`
- `color` (outside SR Policy: one rotating Color community, or `color set` for all values on every path)

FlowSpec `action` lines are attribute-side. A line with one value goes on
every path; a line with several values rotates them, one value per path, in
step with `next-hop` and `color`. Paths with different values land in
different attribute groups.

SR Policy-specific attribute-side rotators also include:

- `enlp`
- `priority`
- `preference`
- `binding-sid`
- `segment-list`

Important differences:

- repeated `rt` lines build one fixed RT set for the whole ribout
- `rt-set` rotates whole RT sets across emitted paths
- `rt` and `rt-set` are mutually exclusive

`rt-set` syntax uses comma-separated values inside each bracketed set:

```text
rt-set [65000:100] [65000:200,65000:201]
```

`community` and `large-community` use the same set syntax and rotate the same
way: path i carries set i mod n, in step with `rt-set` (COMMUNITIES, attribute
8, after LOCAL_PREF; LARGE_COMMUNITY, attribute 32, last). Paths with different
sets land in different attribute groups.

```text
community [65000:1,no-export] 65000:100 x 2
large-community 65551:0:1 x 3
```

## Total Path Count

The path-count formula is family-specific.

For IPv4 / IPv6 unicast, labeled-unicast, VPN, and EVPN Type 5:

```text
total_paths =
  prefix_count
  * max(rd_count, 1)            (1 with `rd rotate`)
  * max(ethernet_tag_count, 1)
  * max(gateway_ip_count, 1)
  * max(esi_count, 1)
  * max(label_count, 1)        (1 with `label rotate`)
  * max(path_id_count, 1)
```

For SR Policy:

```text
total_paths =
  distinguisher_count
  * color_count
  * endpoint_count
  * max(path_id_count, 1)
```

For EVPN Type 2:

```text
total_paths =
  rd_count                     (1 with `rd rotate`)
  * max(ethernet_tag_count, 1)
  * mac_count
  * max(ip_count, 1)           (per address family: the IP count, or 1 with
                                `ip rotate`; the two families add up)
  * max(path_id_count, 1)
```

For FlowSpec:

```text
total_paths =
  sum over rules of (max(dst_prefix_count, 1) * max(src_prefix_count, 1))
  * max(rd_count, 1)
  * max(path_id_count, 1)
```

`bgp_ribout_total_paths()` owns these formulas; the CLI summary and the
benchmarks call it.

This means:

- `next-hop x 8` does not multiply path count
- `rt-set [...] [...]` does not multiply path count
- `community` and `large-community` sets do not multiply path count
- `soo a b c` does not multiply path count
- `localpref rand(200)` does not multiply path count
- EVPN Type 2 `label`, `label2`, and `esi` do not multiply path count
- `label rotate` does not multiply path count: path i carries label
  i mod label_count, in step with `rt-set` and the other per-path rotations
- EVPN Type 2 `ip rotate` does not multiply path count: MAC i is bound to IP
  i mod ip_count (per address family; with both, two routes per MAC)
- `rd rotate` does not multiply path count: rotation step r carries RD
  r mod rd_count
- `ethernet-tag rotate`, `path-id rotate`, `distinguisher rotate`, SR Policy
  `color rotate`, `endpoint rotate` and a rotating FlowSpec component do not
  multiply path count either: each counts as 1 in the formulas here, and
  rotation step r carries value r mod count
- `rotate-every n` changes no count: the rotations advance once every n paths,
  so rotation step r = path / n
- EVPN `encap` and `router-mac` do not multiply path count
- SR Policy `enlp`, `priority`, `preference`, `binding-sid`, and
  `segment-list` do not multiply path count

Those tokens change the attributes attached to each emitted path, not the
number of emitted paths.

## Exact Generator Order

The generator order is family-specific.

For IPv4 / IPv6 unicast, labeled-unicast, VPN, and EVPN Type 5:

```text
prefix -> rd -> ethernet-tag -> gateway-ip -> esi -> label -> path-id
```

This means:

- `prefix` changes slowest
- `path-id` changes fastest
- `label` changes faster than `rd`
- `gateway-ip` changes faster than `ethernet-tag`

The equivalent loop shape is:

```text
for each prefix
  for each rd
    for each ethernet-tag
      for each gateway-ip
        for each esi
          for each label
            for each path-id
              emit one path
```

For SR Policy:

```text
distinguisher -> color -> endpoint -> path-id
```

For EVPN Type 2:

```text
rd -> ethernet-tag -> mac -> ip -> path-id
```

For FlowSpec (the components in type order, `protocol` first):

```text
prefix -> src-prefix -> protocol -> ... -> flow-label -> rd -> path-id
```

So:

- SR Policy `path-id` changes fastest and `distinguisher` changes slowest
- EVPN Type 2 `path-id` changes fastest and `rd` changes slowest
- FlowSpec `path-id` changes fastest and the destination prefix changes
  slowest; a component counts only when it has a generator (`x <count>`,
  `each(...)`)
- EVPN Type 2 `label`, `label2`, `esi`, `next-hop`, RT/SoO, `encap`, and
  `router-mac` state rotate across the emitted stream after those NLRI
  multipliers are chosen

## Overlay Rotation Rules

After one logical path is emitted from the nested NLRI loops, the generator
applies attribute-side rotators.

These rotate on **every emitted path**:

- `next-hop`
- `rt-set`
- `soo`
- `encap`
- `router-mac`

These also rotate on every emitted path for specific families:

- EVPN Type 2 `label`
- EVPN Type 2 `label2`
- EVPN Type 2 `esi`
- SR Policy `enlp`
- SR Policy `priority`
- SR Policy `preference`
- SR Policy `binding-sid`

These are also evaluated per emitted path:

- `localpref rand(N)`
- `med rand(N)`
- `localpref range(A,B)`
- `localpref randrange(A,B)`
- `med range(A,B)`
- `med randrange(A,B)`
- `ASPATH_RANDOM` segments inside `as-path`

Two important consequences:

- `next-hop x 2` stripes over the emitted stream; it does not create two paths
  per prefix
- `rt-set` changes grouping aggressively because whole RT sets rotate per path

## Preview Semantics

`show ribout <name> preview <N>` shows the **generated path stream**, not final
UPDATE packing.

Preview is the right tool for verifying:

- family inference
- loop order
- per-path rotation
- which fields are changing fast or slow

Preview is **not** the right tool for predicting final UPDATE count directly,
because final UPDATE count depends on:

1. grouping into the ribout map
2. BGP message size splitting

Preview columns are shown only when they are meaningful for the current block.
For example:

- `label` appears only when labels are configured
- `path-id` appears only when `path-id` is configured
- `rd` appears only for VPN/EVPN families
- `eth-tag`, `gateway-ip`, and `esi` appear for EVPN
- `med`, `rt`, and `soo` appear only when configured
- FlowSpec shows the NLRI as `prefix <dst> <component> <args> ...` in the
  `nlri` column, an `actions` column with the action values of that path, and
  `-` for `next-hop` when the NLRI goes with a zero-length next hop
- a `color` column shows the Color communities outside SR Policy

Random-field caveat:

- `preview` and `update generate` both start from the same deterministic seed
- if `RANDSEED` is unset, the default seed is derived from the ribout name
- if `RANDSEED` is set, each ribout derives its own stream from that process
  seed plus the ribout name
- so the same ribout config produces the same random sequence across preview and
  generation unless `RANDSEED` or the ribout name changes

## Grouping Semantics

The grouped ribout map is the canonical form used for packing UPDATE messages.

Routes are grouped by the effective attribute tuple, broadly:

- NLRI type
- next-hop and next-hop AF
- optional IPv6 link-local next-hop
- concrete AS_PATH bytes
- extended-community bytes for RT / RT-set / SoO / Color
- local-pref
- MED
- origin
- optional SR Policy tunnel-encapsulation payload when present
- FlowSpec action communities of the path: 8-octet ones in attribute 16 and
  IPv6-address-specific ones (rt-redirect-ipv6, IPv6 redirect-to-IP) in
  attribute 25
- EVPN attr-side extended communities such as `encap` and `router-mac` when
  configured

These fields stay on the NLRI side and do **not** split groups by themselves:

- prefix
- RD
- label
- label2
- path-id
- ethernet-tag
- MAC
- IP
- gateway-ip
- ESI
- SR Policy distinguisher
- SR Policy color
- SR Policy endpoint
- FlowSpec NLRI instance (destination, `src-prefix`, and component values)

In other words:

- NLRI-side tokens control route scale
- attribute-side tokens control fragmentation into attribute buckets

## Message Packing Semantics

Each attribute bucket becomes one or more UPDATE messages.

Message count is therefore driven by two things:

1. how many distinct attribute buckets exist
2. how many NLRIs fit in each UPDATE before size splitting

So a block can still generate many UPDATEs even if it has only one attribute
group. Large NLRI lists are split by BGP message size limits.

## Worked Examples

The examples below are real preview outputs captured from the current CLI.

### Basic IPv4 Unicast

Config:

```text
ribout basic-v4
  prefix 10.0.0.0/24 x 2
  path-id 100 200
  next-hop 192.0.2.1 x 2
  as-path 65001 65002
  localpref 150
  origin igp
```

Preview:

```text
ribout preview: basic-v4 (showing first 4 paths)
===============================================
family: ipv4-unicast

#     nlri         path-id  next-hop   lp   origin  as-path
----  -----------  -------  ---------  ---  ------  -------
1     10.0.0.0/24  100      192.0.2.1  150  igp     65001 65002
2     10.0.0.0/24  200      192.0.2.2  150  igp     65001 65002
3     10.0.1.0/24  100      192.0.2.1  150  igp     65001 65002
4     10.0.1.0/24  200      192.0.2.2  150  igp     65001 65002

total paths in block: 4
```

What this shows:

- `prefix x 2` and `path-id 100 200` produce `2 x 2 = 4` paths
- `next-hop 192.0.2.1 x 2` stripes across those four paths
- next-hop is not a multiplicative dimension

### Basic IPv6 Unicast

Config:

```text
ribout basic-v6
  prefix 2001:db8:100::/64 x 2
  path-id 1 2
  next-hop 2001:db8:ffff::1 x 2 link-local fe80::1
  as-path 65010 65020
  localpref 200
  origin igp
```

Preview:

```text
ribout preview: basic-v6 (showing first 4 paths)
===============================================
family: ipv6-unicast

#     nlri                 path-id  next-hop          ll-nh    lp   origin  as-path
----  -------------------  -------  ----------------  -------  ---  ------  -------
1     2001:db8:100::/64    1        2001:db8:ffff::1  fe80::1  200  igp     65010 65020
2     2001:db8:100::/64    2        2001:db8:ffff::2  fe80::1  200  igp     65010 65020
3     2001:db8:100:1::/64  1        2001:db8:ffff::1  fe80::1  200  igp     65010 65020
4     2001:db8:100:1::/64  2        2001:db8:ffff::2  fe80::1  200  igp     65010 65020

total paths in block: 4
```

What this shows:

- IPv6 next-hop rotation works the same way as IPv4
- the optional link-local companion is carried alongside the global IPv6
  next-hop
- `path-id` is still the fastest-changing NLRI-side field

### IPv4 Labeled-Unicast

Config:

```text
ribout lu4-demo
  prefix 192.0.2.0/24 x 2
  label 16000 16001
  path-id 10 20
  next-hop 198.51.100.1
  as-path 65030
  localpref 100
  origin igp
```

Preview:

```text
ribout preview: lu4-demo (showing first 6 paths)
===============================================
family: ipv4-labeled-unicast

#     nlri          label  path-id  next-hop      lp   origin  as-path
----  ------------  -----  -------  ------------  ---  ------  -------
1     192.0.2.0/24  16000  10       198.51.100.1  100  igp     65030
2     192.0.2.0/24  16000  20       198.51.100.1  100  igp     65030
3     192.0.2.0/24  16001  10       198.51.100.1  100  igp     65030
4     192.0.2.0/24  16001  20       198.51.100.1  100  igp     65030
5     192.0.3.0/24  16000  10       198.51.100.1  100  igp     65030
6     192.0.3.0/24  16000  20       198.51.100.1  100  igp     65030

total paths in block: 8
```

What this shows:

- `label` is an NLRI-side multiplier
- labeled-unicast is inferred from `label` without `rd`
- the nested order is `prefix -> label -> path-id`

### VPNv4 With RT-Set and SoO Rotation

Config:

```text
ribout vpn4-demo
  prefix 10.10.0.0/24 x 2
  rd 65000:100 65000:101
  label 24000 24001
  path-id 1 2
  next-hop 192.0.2.9 x 2
  rt-set [65000:100] [65000:200,65000:201]
  soo 65000:9 65000:10
  as-path 65100 65200
  localpref 175
  med 50
  origin igp
```

Preview:

```text
ribout preview: vpn4-demo (showing first 8 paths)
===============================================
family: vpnv4

#     nlri          rd         label  path-id  next-hop    lp   med  origin  rt                   soo       as-path
----  ------------  ---------  -----  -------  ----------  ---  ---  ------  -------------------  --------  -------
1     10.10.0.0/24  65000:100  24000  1        192.0.2.9   175  50   igp     65000:100            65000:9   65100 65200
2     10.10.0.0/24  65000:100  24000  2        192.0.2.10  175  50   igp     65000:200,65000:201  65000:10  65100 65200
3     10.10.0.0/24  65000:100  24001  1        192.0.2.9   175  50   igp     65000:100            65000:9   65100 65200
4     10.10.0.0/24  65000:100  24001  2        192.0.2.10  175  50   igp     65000:200,65000:201  65000:10  65100 65200
5     10.10.0.0/24  65000:101  24000  1        192.0.2.9   175  50   igp     65000:100            65000:9   65100 65200
6     10.10.0.0/24  65000:101  24000  2        192.0.2.10  175  50   igp     65000:200,65000:201  65000:10  65100 65200
7     10.10.0.0/24  65000:101  24001  1        192.0.2.9   175  50   igp     65000:100            65000:9   65100 65200
8     10.10.0.0/24  65000:101  24001  2        192.0.2.10  175  50   igp     65000:200,65000:201  65000:10  65100 65200

total paths in block: 16
```

What this shows:

- NLRI-side product is `prefix x rd x label x path-id`
- `next-hop`, `rt-set`, and `soo` rotate per emitted path
- `rt-set` rotates whole RT sets, not individual RTs

### EVPN Type 5 IPv4

Config:

```text
ribout evpn4-demo
  prefix 192.168.0.0/24 x 2
  rd 65000:300 65000:301
  label 30000
  ethernet-tag 0 100
  gateway-ip 10.255.0.1 x 2
  next-hop 203.0.113.1 x 2
  rt 65000:300
  rt 65000:301
  as-path 65500
  localpref 250
  med 10
  origin igp
```

Preview:

```text
ribout preview: evpn4-demo (showing first 8 paths)
===============================================
family: evpn-type5-ipv4

#     nlri            rd         label  eth-tag  gateway-ip  next-hop     lp   med  origin  rt                   as-path
----  --------------  ---------  -----  -------  ----------  -----------  ---  ---  ------  -------------------  -------
1     192.168.0.0/24  65000:300  30000  0        10.255.0.1  203.0.113.1  250  10   igp     65000:300,65000:301  65500
2     192.168.0.0/24  65000:300  30000  0        10.255.0.2  203.0.113.2  250  10   igp     65000:300,65000:301  65500
3     192.168.0.0/24  65000:300  30000  100      10.255.0.1  203.0.113.1  250  10   igp     65000:300,65000:301  65500
4     192.168.0.0/24  65000:300  30000  100      10.255.0.2  203.0.113.2  250  10   igp     65000:300,65000:301  65500
5     192.168.0.0/24  65000:301  30000  0        10.255.0.1  203.0.113.1  250  10   igp     65000:300,65000:301  65500
6     192.168.0.0/24  65000:301  30000  0        10.255.0.2  203.0.113.2  250  10   igp     65000:300,65000:301  65500
7     192.168.0.0/24  65000:301  30000  100      10.255.0.1  203.0.113.1  250  10   igp     65000:300,65000:301  65500
8     192.168.0.0/24  65000:301  30000  100      10.255.0.2  203.0.113.2  250  10   igp     65000:300,65000:301  65500

total paths in block: 16
```

What this shows:

- EVPN Type 5 is inferred from `rd` plus EVPN-specific NLRI fields
- `ethernet-tag` and `gateway-ip` are NLRI-side multipliers
- repeated `rt` lines form one fixed RT set for the whole block

### FlowSpec Match And Actions

Config:

```text
ribout fs-demo
  address-family ipv4 flowspec
  prefix 10.0.0.0/8 x 2
  protocol each(6, 17)
  dst-port 80
  path-id 1 2
  as-path 65001
  action redirect-ip 192.0.2.1 192.0.2.2
  color 1 co 01
```

Preview:

```text
ribout preview: fs-demo (showing first 8 paths)
===============================================
family: ipv4-flowspec

#     nlri                                       path-id  next-hop  actions                lp   origin  color    as-path
----  -----------------------------------------  -------  --------  ---------------------  ---  ------  -------  -------
1     prefix 10.0.0.0/8 protocol 6 dst-port 80   1        -         redirect-ip 192.0.2.1  100  igp     1 co 01  65001
2     prefix 10.0.0.0/8 protocol 6 dst-port 80   2        -         redirect-ip 192.0.2.2  100  igp     1 co 01  65001
3     prefix 10.0.0.0/8 protocol 17 dst-port 80  1        -         redirect-ip 192.0.2.1  100  igp     1 co 01  65001
4     prefix 10.0.0.0/8 protocol 17 dst-port 80  2        -         redirect-ip 192.0.2.2  100  igp     1 co 01  65001
5     prefix 11.0.0.0/8 protocol 6 dst-port 80   1        -         redirect-ip 192.0.2.1  100  igp     1 co 01  65001
6     prefix 11.0.0.0/8 protocol 6 dst-port 80   2        -         redirect-ip 192.0.2.2  100  igp     1 co 01  65001
7     prefix 11.0.0.0/8 protocol 17 dst-port 80  1        -         redirect-ip 192.0.2.1  100  igp     1 co 01  65001
8     prefix 11.0.0.0/8 protocol 17 dst-port 80  2        -         redirect-ip 192.0.2.2  100  igp     1 co 01  65001

total paths in block: 8
```

What this shows:

- the block is one rule template: `prefix x 2` and `each(6, 17)` multiply
  into four NLRIs, and `path-id 1 2` doubles them
- `path-id` changes fastest, then `protocol`, then the destination prefix
- the redirect-ip line has two values, so they rotate per path: path-id 1
  gets 192.0.2.1 and path-id 2 gets 192.0.2.2, and the two values land in two
  attribute groups
- `color` outside SR Policy is a Color community, here with CO bits 01
- the `next-hop` column is `-`: RFC 8955 FlowSpec goes with a zero-length
  next hop unless a redirect-to-next-hop action is configured

## Practical Testing Rules

If the goal is to increase route scale, change NLRI-side dimensions:

- `prefix`
- `rd`
- `ethernet-tag`
- `mac`
- `ip`
- `gateway-ip`
- `esi`
- `label`
- `path-id`
- `distinguisher`
- `color` (SR Policy)
- `endpoint`
- FlowSpec `prefix` / `src-prefix` counts and component generators

If the goal is to increase attribute fragmentation and message count, rotate
attribute-side dimensions:

- `next-hop`
- `rt-set`
- `soo`
- random `localpref`
- random `med`
- randomized `as-path`
- EVPN Type 2 `label`, `label2`, and `esi`
- SR Policy `enlp`, `priority`, `preference`, and `binding-sid`
- `color` outside SR Policy, and FlowSpec `action` lines with several values

If the goal is to understand why an UPDATE count changed:

1. inspect `preview` to verify stream order and per-path rotation
2. inspect ribout summary after `update generate` to see grouping and packed
   message counts

## Current Scope

The model above describes the current ribout generation path for:

- IPv4 unicast
- IPv6 unicast
- IPv4 labeled-unicast
- IPv6 labeled-unicast
- VPNv4
- VPNv6
- EVPN Type 2
- EVPN Type 5
- SR Policy IPv4
- SR Policy IPv6
- FlowSpec IPv4 and IPv6 (SAFI 133)
- VPN FlowSpec IPv4 and IPv6 (SAFI 134)
- the typed templates: RTC, VPLS, EVPN Types 1/3/4, IPv4 / IPv6 MVPN Types
  1-7, and BGP-LS

This document is intentionally about generation, grouping, and packing. It does
not describe neighbor-specific policy, pacing, or peer-specific wire rendering.

## See Also

- [configuration.md](configuration.md) for command syntax
- [bgp-update-api.md](bgp-update-api.md) for low-level UPDATE encoding
