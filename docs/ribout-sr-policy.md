# SR Policy Ribouts

An SR Policy block is a route of the SR Policy address family, which installs
policies on a headend. It has a `distinguisher`, a `color` and an `endpoint`.
An IPv4 or IPv6 endpoint selects the family, and the route count is the
product of the three.

[`color`](ribout-configuration.md#color-rotateset-c-co-bits---rotateset-base-x-count-co-bits)
is described with the shared tokens, because outside this family it is a
Color community. The other shared tokens
([`next-hop`](ribout-configuration.md#next-hop-ip-prefix-x-count-link-local-ipv6),
[`rt`](ribout-configuration.md#rt-values), the AS path and the rest) work as
on every family.

To report the state of policies with BGP-LS (RFC 9857), see
[SR Policy Candidate Paths](bgp-ls.md#sr-policy-candidate-paths).

## Tokens

### `distinguisher [rotate] <values>`

Set SR Policy distinguisher values.

Examples:

```text
distinguisher 100
distinguisher 100 101 102
distinguisher 100 x 64
distinguisher rotate 100 x 4
```

### `endpoint [rotate] <ip> [x <count>]`

Set SR Policy endpoint values. The endpoint address family determines whether
the ribout resolves to SR Policy IPv4 or SR Policy IPv6.

Examples:

```text
endpoint 10.0.0.1 x 128
endpoint 2001:db8:100::1 x 128
endpoint rotate 10.0.0.1 x 4
```

### `preference <value>`

Set SR Policy preference values.

Examples:

```text
preference 100
preference rand(4096)
preference range(100,115)
preference randrange(100,115)
```

### `enlp <value>`

Set SR ENLP values. Valid values are `1..4`.

Examples:

```text
enlp 3
enlp 1 2 3 4
enlp randrange(1,4)
```

### `priority <value>`

Set SR priority values. Valid values are `0..255`.

Examples:

```text
priority 7
priority range(7,15)
priority randrange(0,255)
```

### `binding-sid <mpls|srv6> <value>`

Set SR Binding SID values. `mpls` uses label values; `srv6` uses IPv6 SIDs.

Examples:

```text
binding-sid mpls 16000
binding-sid mpls range(16000,16031)
binding-sid mpls randrange(16,1048575)
binding-sid srv6 fc00:0:70::1
binding-sid srv6 fc00:0:70::1 x 16
```

### `segment-list <id> weight <weight> <mpls|srv6> <segments...>`

Define one SR Policy segment-list. Segment-lists do not multiply route count;
they stay block-wide and are attached through the SR tunnel-encapsulation
attribute. SRv6 segment entries can optionally carry `behavior <u16>` and
`structure <locator-block> <locator-node> <function> <argument>`.
`<segment> x <count>` adds consecutive labels or SIDs; consecutive SIDs keep
the behavior of the first: `srv6 2001:db8:1::1 behavior 4660 x 6`.

Examples:

```text
segment-list 1 weight 10 mpls 16010 16011
segment-list 2 weight 20 srv6 2001:db8:1::1 2001:db8:1::2
segment-list 3 weight 30 srv6 2001:db8:3::1 behavior 4660 structure 48 16 16 48 2001:db8:3::2
```

## Example

```text
ribout demo-sr4
  distinguisher 100 x 16
  color 200 201
  endpoint 10.0.0.1 x 512
  enlp 1 2
  priority range(7,8)
  path-id 1 2
  rt 192.0.2.1:200
  preference randrange(100,115)
  binding-sid mpls randrange(16,1048575)
  segment-list 1 weight 10 mpls 16010 16011
  segment-list 2 weight 20 srv6 2001:db8:1::1 behavior 4660 structure 48 16 16 48 2001:db8:1::2
  next-hop 192.0.2.10 x 4
  as-path 65001 65002
  origin igp
!
```
