# FlowSpec Ribouts

A FlowSpec ribout (RFC 8955, RFC 8956) is one rule template. `prefix` is the
destination prefix (component 1); `src-prefix` and the operator components
are block lines. Value generators make many NLRIs from the template: prefix
counts, component sequences and `each(...)` multiply, then `rd` and
`path-id`. Use one block for each set of attributes that does not rotate.

```text
ribout <name>
  [address-family ipv4 flowspec | ipv6 flowspec | ipv4 flowspec-vpn | ipv6 flowspec-vpn]
  [prefix ...]
  [src-prefix ...]
  [<component> <expression>]
  [rd ...]
  [path-id ...]
  [next-hop ...]
  [as-path ...]
  [localpref ...]
  [color ...]
  [action ...]
!
```

`prefix`, `rd`, `path-id`, `next-hop`, the AS path and `color` are
[shared tokens](ribout-configuration.md#token-reference). The lines below
belong to FlowSpec.

## `src-prefix <ip/len> [x <count>]`

Component type 2. It steps like `prefix`, and an IPv6 source prefix can use
the RFC 8956 offset form `<ip>/<offset>-<length>`.

## Operator components

| Keyword | Type | Kind |
| --- | --- | --- |
| `protocol` | 3 | numeric (IPv6: upper-layer protocol) |
| `port` | 4 | numeric |
| `dst-port` | 5 | numeric |
| `src-port` | 6 | numeric |
| `icmp-type` | 7 | numeric |
| `icmp-code` | 8 | numeric |
| `tcp-flags` | 9 | bitmask: `fin syn rst psh ack urg ece cwr` |
| `packet-length` | 10 | numeric |
| `dscp` | 11 | numeric |
| `fragment` | 12 | bitmask: `df isf ff lf` (IPv6 has no `df`) |
| `flow-label` | 13 | numeric, IPv6 only |

Expression syntax:

- a space between terms means OR; `&` between comparisons means AND
- numeric comparison: a bare value means equal; `!=`, `<`, `<=`, `>`, `>=`
  and a decimal value, or `true` / `false`
- bitmask comparison: flag names joined by `+`, or a decimal value; bare
  bits mean all of them are set (the RFC 8955 match bit), `any(<bits>)` means
  at least one is set, and `!` negates
- `:<width>` (1, 2, 4, 8) forces the value width; the default is the
  smallest width that holds the value
- at most 8 comparisons per expression

Value generators (each value makes its own NLRI):

- `<comparison> x <count>`: one numeric comparison, its value steps by 1
- `each(<expr>, <expr>, ...)`: one NLRI per expression, 2 to 16 of them
- `rotate` before either (`dst-port rotate 80 x 3`, `protocol rotate
  each(6, 17)`): the values go one per rule in turn instead, rule i taking
  value i mod n, and the rule count does not count them. The instance space,
  every component's values multiplied whether they rotate or not, must stay
  below 2^32.

The last component changes fastest, then `src-prefix`, then the destination
prefix; `rd` and `path-id` change faster than all of them.

Examples:

```text
protocol 6 17
dst-port >=1024&<=2048 8080
tcp-flags syn+ack !rst
tcp-flags any(fin+rst)
packet-length <1500
fragment any(isf) ff+lf
flow-label 12345:4
dst-port 1000 x 64
protocol each(6, 17)
dst-port rotate 80 x 3
```

The library encoder checks every component against the RFC rules (operator
bits, widths, IPv4-only and IPv6-only components). `no <keyword>` removes one
component.

## `action <action>`

Each `action` line adds one extended community to every path. A line with
several values rotates them, one value per path, in step with `next-hop` and
`color`. `no action` removes all action lines.

| Action | Encoding |
| --- | --- |
| `redirect-ip <addr>... [copy]` or `<addr> x <n> [copy]` | 0x010c; IPv6: 0x000c in attribute 25 (redirect-ip draft) |
| `redirect-vrf <rt>...` | 0x8008 / 0x8108 / 0x8208; `<ipv6>:<nn>`: 0x000d in attribute 25 (RFC 8956 6.1) |
| `mark <dscp>...`, `mark <dscp> x <count>` | 0x8009 (RFC 8955 7.5), DSCP 0-63 |
| `traffic-rate bytes\|packets <rate> [as <asn16>]` | 0x8006 / 0x800c (RFC 8955 7.1, 7.2); rate 0 discards |
| `traffic-action [terminal] [sample]` | 0x8007 |
| `redirect-next-hop [copy]` | 0x0800, target in the MP_REACH next hop (draft-simpson-idr-flowspec-redirect) |
| `interface-set <asn>:<group> [in] [out] [non-transitive]` | 0x0702 / 0x4702 |

A Color community is the `color` line. SR-TE steering
(draft-ietf-idr-ts-flowspec-srv6-policy mode 1) is a redirect plus a Color:
`action redirect-ip <endpoint>` with `color <c>`, or `next-hop <endpoint>`,
`action redirect-next-hop` and `color <c>`.

Next-hop rules (RFC 8955 section 4 sends FlowSpec with a zero-length next
hop):

- `next-hop` is valid only with a `redirect-next-hop` action
- a `redirect-next-hop` action needs `next-hop`

## Examples

FlowSpec redirect to SR-TE: rule i steers into the policy (endpoint
192.0.2.1 + i mod 3, color 100 + i mod 3):

```text
ribout fsc1
  address-family ipv4 flowspec
  prefix 10.1.0.0/24 x 6
  protocol 6
  dst-port 80 443
  as-path 65001
  action redirect-ip 192.0.2.1 x 3
  color 100 x 3 co 01
!
```

VPN FlowSpec IPv6 steered through the next hop:

```text
ribout fsc2
  address-family ipv6 flowspec-vpn
  prefix 2001:db8::/8-64 x 2
  flow-label 12345
  rd 65000:1 x 2
  path-id 7 8
  next-hop 2001:db8::99
  action redirect-vrf 2001:db8::1:300
  action redirect-next-hop
  color 7
!
```
