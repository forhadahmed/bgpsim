# BGP-LS Ribouts

A BGP-LS ribout describes a topology: one block for the nodes, one for the
links, one for the prefixes, and so on. bgpsim sends what the blocks say. It
does not run an IGP and does not compute paths.

A block has one `nlri bgp-ls` line, which is a
[typed NLRI template](ribout-templates.md), and `ls` lines for the BGP-LS
Attribute. The shared attribute tokens of
[Ribout Configuration](ribout-configuration.md) (next hop, AS path,
communities and the rest) apply as on every family.

## NLRI

```text
nlri bgp-ls node protocol <p> identifier <id> <local-node>
nlri bgp-ls link protocol <p> identifier <id> <local-node> <remote-node> <link>
nlri bgp-ls ipv4-prefix protocol <p> identifier <id> <local-node> [mt-id <id>] [ospf-route-type <1-6>] prefix <prefix/len>
nlri bgp-ls ipv6-prefix protocol <p> identifier <id> <local-node> [mt-id <id>] [ospf-route-type <1-6>] prefix <prefix/len>
nlri bgp-ls srv6-sid protocol <p> identifier <id> <local-node> [mt-id <id>] sid <ipv6>[/<bits>]
nlri bgp-ls sr-policy protocol sr identifier <id> <local-node> origin <pcep|bgp|config|n> endpoint <ip> color <n> originator-as <asn> originator <ip> discriminator <n>
```

Enter the fields in the order shown. `protocol` is `isis-l1`, `isis-l2`,
`ospfv2`, `direct`, `static`, `ospfv3`, `bgp`, `sr` or a number. `identifier`
is the 64-bit instance identifier.

### Nodes

A node is written in TLV order. `<side>` is `local` or `remote`:

```text
<side>-as <asn> [<side>-bgp-ls-id <n>] [<side>-ospf-area <n|a.b.c.d>] <side>-router <id> [<side>-member-as <asn>] [<side>-te-router-id <ip>]
```

| Field | Meaning |
| --- | --- |
| `<side>-as` | the AS number |
| `<side>-bgp-ls-id` | the BGP-LS Identifier |
| `<side>-ospf-area` | the OSPF Area-ID, as a number or in dotted form |
| `<side>-router` | the Router-ID of the protocol |
| `<side>-member-as` | the confederation Member-AS (RFC 9086) |
| `<side>-te-router-id` | the IPv4 or IPv6 Router-ID that names the headend of an SR Policy (RFC 9857) |

`<side>-router` is dotted IPv4, hex octets, or hex in dotted groups as IS-IS
writes it (`0000.0000.0001`). The protocol sets its kind and length:

- IS-IS: the IGP Router-ID, 6 octets, or 7 for a pseudonode
- OSPF: the IGP Router-ID, 4 octets, or 8 for a pseudonode
- `direct` and `static`: the IGP Router-ID, 4 or 16 octets
- `bgp` and `sr`: the BGP Router-ID, 4 octets and not zero

The AS number and the router are required, except with `protocol sr`.

### Links

A link has a local and a remote node. It is named by identifiers, by
addresses, or (for `protocol bgp`) by both:

```text
[local-id <n> remote-id <n>] [local-ip <ip> remote-ip <ip>] [mt-id <id>]
```

With `protocol bgp` a link is a BGP peering session (RFC 9086), and its
attribute lines can carry the peering SIDs.

### Prefixes and SRv6 SIDs

`mt-id` is the Multi-Topology ID and `ospf-route-type` the OSPF route type of
the prefix.

`sid <ipv6>/<bits>` sets where a sequence of SIDs adds its number, as a prefix
length does for a prefix: `sid fc00:0:1:1::/64 step sid x 4` gives
`fc00:0:1:1::` to `fc00:0:1:4::`.

### SR Policy Candidate Paths

An `sr-policy` NLRI reports one candidate path of an SR Policy (RFC 9857). Its
protocol is always `sr`. The local node is the headend: `local-te-router-id` is
required, and `local-as` and `local-router` are given when the headend itself
reports the policy. `origin` is the protocol that created the path: `pcep`,
`bgp`, `config`, or a number from the RFC 9857 registry.

This is the state of a policy as BGP-LS reports it. The SR Policy address
family, which installs policies, is a separate family:
[SR Policy Ribouts](ribout-sr-policy.md).

## Identities and Scale

A step moves one identity field. Related blocks that use the same base value and
the same step describe the same objects:

| Step | Moves | Use |
| --- | --- | --- |
| `identifier` | the instance identifier | separate topologies |
| `node` | the Router-ID, local and remote together | node i; a link from node i to node i + 1 |
| `remote` | the remote Router-ID only | the neighbors, or BGP peers, of one node |
| `link` | the link identifiers or addresses | parallel links |
| `prefix` | the prefix | prefixes of a node |
| `sid` | the SRv6 SID | SIDs of a node |
| `color` | the color of the SR Policy | policies of a headend |
| `endpoint` | the endpoint of the SR Policy | policies to several endpoints |
| `discriminator` | the discriminator of the candidate path | candidate paths of one policy |

A block can have up to three steps. Each further step is an inner axis: every
value of an axis has every value of the next one. The count of the block is the
product.

```text
ribout nodes
  nlri bgp-ls node protocol isis-l2 identifier 0 local-as 65000 local-router 0000.0000.0001 step node x 1000
ribout prefixes
  nlri bgp-ls ipv4-prefix protocol isis-l2 identifier 0 local-as 65000 local-router 0000.0000.0001 prefix 10.0.0.0/24 step node x 1000 step prefix x 64
```

The second block has 64 prefixes for each of the 1000 nodes of the first. With
three axes, `step node x 250 step color x 64 step discriminator x 4` on an
`sr-policy` NLRI gives 250 headends, 64 policies on each, and 4 candidate paths
of each policy.

## Attribute Lines

Each `ls` line adds one TLV to the BGP-LS Attribute of the block. A block can
have up to 64 lines and 2048 octets; the same TLV can be given more than once
where the RFC allows it. `no ls` removes all the lines.

```text
ls <tlv-name> <values> [<keyword> <value> ...] [x <count>] [per <axis>[/<bits>]] ... [sub <tlv-name> ...]
```

Values without a keyword come first, then keyword fields in any order. `sub`
nests a TLV inside this one. `flags` takes a number, or the flag names of the
TLV separated by commas; for TLVs whose flags differ between IS-IS and OSPF,
the protocol of the NLRI picks the layout.

### TLV Names

The NLRI type of the block decides which TLVs it can carry:

| Carried by | TLV names |
| --- | --- |
| Node | `node-flags`, `node-opaque`, `node-name`, `isis-area`, `ipv4-router-id`, `ipv6-router-id`, `node-msd`, `mt-id`, `sr-capabilities`, `sr-algorithm`, `sr-local-block`, `srms-preference`, `srv6-capabilities`, `flex-algo` |
| Link | `admin-group`, `extended-admin-group`, `max-bandwidth`, `max-reservable-bandwidth`, `unreserved-bandwidth`, `te-metric`, `link-protection`, `mpls-protocols`, `igp-metric`, `srlg`, `link-opaque`, `link-name`, `link-msd`, `ipv4-router-id`, `ipv6-router-id`, `remote-ipv4-router-id`, `remote-ipv6-router-id`, `link-delay`, `min-max-link-delay`, `delay-variation`, `link-loss`, `residual-bandwidth`, `available-bandwidth`, `utilized-bandwidth`, `adj-sid`, `lan-adj-sid`, `l2-bundle-member`, `srv6-endx-sid`, `isis-srv6-lan-endx-sid`, `ospfv3-srv6-lan-endx-sid`, `peer-node-sid`, `peer-adj-sid`, `peer-set-sid` |
| Prefix | `igp-flags`, `route-tag`, `extended-route-tag`, `prefix-metric`, `igp-metric`, `ospf-forwarding-address`, `prefix-opaque`, `prefix-sid`, `range`, `prefix-attr-flags`, `source-router-id`, `source-ospf-router-id`, `srv6-locator`, `flex-algo-prefix-metric` |
| SRv6 SID | `srv6-endpoint-behavior`, `srv6-bgp-peer-node-sid`, `srv6-sid-structure` |
| SR Policy candidate path | `cp-state`, `policy-name`, `cp-name`, `sr-binding-sid`, `srv6-binding-sid`, `cp-constraints`, `segment-list` |
| Nested only (`sub`) | in `flex-algo`: `exclude-any`, `include-any`, `include-all`, `fad-flags`, `exclude-srlg`, `fad-unsupported`; in `cp-constraints`: `cp-srlg`, `cp-bandwidth`, `cp-metric`, `disjoint-group`, `bidirectional-group`; in `segment-list`: `segment`, `srv6-segment`, `segment-list-metric`, `segment-list-bandwidth`, `segment-list-id` |
| Any | `raw type <0-65535> value <hex>` |

Common forms:

```text
ls sr-capabilities flags i,v range <first-label> <size> [range ...]
ls sr-algorithm <algorithm> ...
ls node-msd <type> <value> ...
ls flex-algo <128-255> [metric-type <n>] [calc-type <n>] [priority <n>] [sub exclude-any <group> ...] [sub include-any ...] [sub include-all ...] [sub fad-flags <flags>] [sub exclude-srlg <srlg> ...]
ls max-bandwidth <bits-per-second, with k, m or g>
ls igp-metric <metric> [width <1|2|3>]
ls adj-sid [flags <f>] [weight <n>] label <label> | index <index>
ls lan-adj-sid [flags <f>] [weight <n>] neighbor <system-id|router-id> label <label> | index <index>
ls srv6-endx-sid <sid>[/<bits>] behavior <name|number> [flags <f>] [algorithm <n>] [weight <n>] [structure <block> <node> <function> <argument>]
ls isis-srv6-lan-endx-sid <sid> behavior <b> neighbor <system-id> ...
ls prefix-sid [flags <f>] [algorithm <n>] label <label> | index <index>
ls srv6-locator [flags d] [algorithm <n>] metric <metric>
ls flex-algo-prefix-metric <128-255> [flags <f>] metric <metric>
ls srv6-endpoint-behavior <name|number> [flags <f>] [algorithm <n>]
ls srv6-sid-structure <block> <node> <function> <argument>
ls peer-node-sid [flags v,l,b,p] [weight <n>] label <label> | index <index>
ls cp-state [priority <n>] [flags s,a,b,e,v,o,d,c,i,t,u] preference <n>
ls sr-binding-sid [flags d,b,u,l,f] label <label> [specified <label>]
ls srv6-binding-sid <sid> [flags b,u,f] specified <sid|::>
ls cp-constraints [flags <f>] [mt-id <n>] [algorithm <n>] [sub cp-srlg <srlg> ...] [sub cp-bandwidth <bw>] [sub cp-metric <type> [flags o,m,a,b] [margin <n>] [bound <n>]] [sub disjoint-group <id> [request <f>] [status <f>]] [sub bidirectional-group <id> [flags r,c]]
ls segment-list [flags <f>] [mt-id <n>] [algorithm <n>] [weight <n>] sub segment <type> [flags s,e,v,r,a] label <label> [descriptor <hex>] | sub srv6-segment <type> [flags <f>] sid <sid> [descriptor <hex>] ... [sub segment-list-metric <type> [flags m,a,b,v] [margin <n>] [bound <n>] [value <n>]] [sub segment-list-bandwidth <bw>] [sub segment-list-id <n>]
```

A segment's `descriptor` is the Segment Descriptor of its type as hex (RFC 9857
section 5.7.1.1): for types 1 and 2 it is one algorithm octet. The affinity
constraint (TLV 1208) has no name yet; give it as `sub raw type 1208 value <hex>`.

`ls-attribute type <n> value <hex>` is the old spelling of `ls raw type <n> value <hex>`.

### Sequences

Some TLVs have a sequence field: a field whose value can differ from route to
route. It is the SID, label or index of a SID TLV, a metric, a Router-ID, or
the preference of `cp-state`. In nested TLVs it is the label or SID of a
segment and the identifier of `segment-list-id`, `disjoint-group` and
`bidirectional-group`. A TLV without such a field, for example `node-name` or
`max-bandwidth`, is the same on every route of the block.

A sequence is written in one of two ways:

- `x <count>` makes a sequence over the routes of the block: route i gets the
  value plus `i mod count`. The number of different attribute sets is then
  under your control and does not depend on the number of routes.
- `per <axis>` makes the value follow one axis of the `nlri` line: the route
  gets the value plus the index it has on that axis. `adj-sid label 24000 per
  link` gives the links of every node the labels 24000, 24001, and so on. For
  an SRv6 SID, `per <axis>/<bits>` says where that axis adds, and `per` can be
  given once for each axis: `srv6-endx-sid fc00:0:1:e000::/64 ... per node/48
  per link` builds the SID from the node (at /48) and the link (at /64).

Both follow the fields of the TLV they belong to. In a nested TLV they come
before the next `sub`, so each nested TLV can have its own:

```text
ls segment-list weight 1 sub segment 1 flags s,v label 16000 per node sub segment 1 flags s,v label 20000 per color
```

A line holds up to six sequences.

An example with both kinds:

```text
ribout links
  nlri bgp-ls link protocol isis-l2 identifier 0 local-as 65000 local-router 0000.0000.0001 remote-as 65000 remote-router 0000.0000.0002 local-ip 10.0.0.1 remote-ip 10.0.0.2 step node x 999
  ls igp-metric 10
  ls te-metric 100 x 16
  ls max-bandwidth 10g
  ls adj-sid flags v,l label 24001 x 999
  ls srv6-endx-sid fc00:0:1:e001::/64 behavior end.x flags b structure 32 16 16 0 per node/48
```

Every link has its own adjacency SID, its End.X SID is function `e001` in the
/48 of its node, and the links share 16 TE metrics.

### What Is Checked

A line that cannot be read is refused and changes nothing. Some rules need the
`nlri` line, which can be entered after the `ls` lines, so they are checked by
`update generate`: a TLV that the NLRI type of the block does not carry, a
neighbor or metric of the wrong size for the protocol, a Flexible Algorithm
below 128, a peering SID outside `protocol bgp`, and a `per` whose axis the
`nlri` line does not step or whose last value does not fit its field. Such a
line stops the
generation of that block, with the line named in the error; the previous
snapshot stays in use.

## Churn

BGP-LS blocks use the same commands as every other family; see
[Sending UPDATEs](sending-updates.md).

To change attributes without changing the routes, edit the `ls` lines, run
`update generate`, and advertise the ribout again. The route keys are the
same, so the new attributes replace the old ones and nothing is withdrawn.
Attribute lines are not part of a route key. `update generate ribout <name>`
rebuilds only that block, and `update generate changed` only the edited ones.

```text
config
ribout links
  no ls
  ls igp-metric 10
  ls te-metric 999
end
update generate changed
advertise ribout links peer all
```

A script sends several changes in one run. It advertises and withdraws; it
does not edit, so make the edits and generate before the run:

```text
script churn
  advertise ribout links peer all
  advertise ribout prefixes peer all
  withdraw ribout sids peer 192.0.2.2
exit
```

Two ribouts with the same routes cannot be advertised to one peer; see
[Route-Key Overlap](sending-updates.md#route-key-overlap).
