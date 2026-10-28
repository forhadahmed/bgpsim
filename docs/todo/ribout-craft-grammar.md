# Ribout Craft Grammar Proposal

## Status

Phase P1 is implemented for FlowSpec; [configuration.md](../configuration.md#flowspec)
is the reference for the syntax that exists. P2-P4 (mutation, relax gates,
`attr` lines, raw forms) are still proposals.

The implemented P1 differs from this proposal in these points:

- A FlowSpec block is one rule template. There is no `rule` mode: `prefix` is
  the destination prefix, and `src-prefix` and the operator components are
  block lines. Use one block for each set of attributes.
- Component generators make many NLRIs from the template:
  `<comparison> x <count>` and `each(<expr>, ...)`. They multiply like
  `prefix x N` (the last component changes fastest).
- Expressions use a bare value for equality (no `=`). For bitmasks, bare bits
  mean "all set" (the match bit) and `any(<bits>)` means "at least one set".
- Actions use `action <action>` lines, not `attr ext-community` lines. A line
  with several values (`redirect-ip`, `redirect-vrf`, `mark`, or
  `<value> x <count>`) rotates them, one per path, in step with `next-hop`
  and `color`. An IPv6 `redirect-vrf` / `redirect-ip` goes to attribute 25
  automatically. There is no `discard` (use `traffic-rate bytes 0`).
- There is no `steer` short form: SR-TE steering is `action redirect-ip` plus
  `color`, or `next-hop` plus `action redirect-next-hop` plus `color`.
- `color` is the SR Policy NLRI color in an SR Policy block and a Color
  community (with per-value `co <bits>`) in every other family.
- Not implemented yet: `attr ...` lines, `component <type> raw`,
  `ext-community raw`, Color `flags <hex>`, `pick(...)`, `step <n>`.
- `address-family` is optional when the prefixes and FlowSpec lines give the
  family. It is required for a FlowSpec block without a prefix, or with only
  `prefix`. All ribout families accept it, with the neighbor family names
  from `bgp_families[]`.
- There is no `relax flowspec-next-hop` gate yet. `next-hop` is accepted only
  with a `redirect-next-hop` action, and that action needs `next-hop`.
- The prefix-step defect (prefixes advanced by one address, not one block) is
  fixed by `bgp_ribout_prefix_advance()`; `step <n>` is still open.

## Goal

Ribout must let a user build any UPDATE from config, without C code:

- correct, RFC-shaped UPDATEs at scale (the default)
- UPDATEs that break one specific rule, on purpose
- UPDATEs with corrupt bytes at a named field

The same grammar must do all three. A fuzz case is a normal ribout block plus
a few extra lines. It is not a separate tool.

## Design Rules

1. Strict by default. A block without `raw`, `relax`, or `mutate` lines must
   encode only RFC-correct UPDATEs, as today.
2. Typed first, raw second. Every field has a typed form. Every typed form has
   a raw escape (`raw <hex>`). The encoder does not check raw bytes, because a
   raw form is also the way to send a type that bgpsim does not know yet.
3. One value-generator syntax for every field. `x N`, `rand()`, `range()`,
   and the new generators work on any typed field, not on a fixed token list.
4. Every fuzz point has a name. A `TODO(WIRE_MUTATION)` marker in the encoders
   becomes a named field. A `TODO(FUZZ_GATE)` marker becomes a named relax gate.
5. Deterministic. The same config and `RANDSEED` give the same bytes, the same
   mutations, and the same message order.
6. The block records the expected peer reaction for each mutation. The test
   harness compares it with the real reaction.
7. Existing ribout blocks keep working. The current tokens stay, as short forms
   of the new `attr` lines.

## Three Fuzz Depths

```text
  depth 1: typed value fuzz      valid encoding, unusual values
           attr ext-community color edge(u32) co pick(00,01,10,11)

  depth 2: semantic relaxation   encodable, but breaks an RFC rule
           relax flowspec-component-order          (TODO(FUZZ_GATE) sites)

  depth 3: wire mutation         any byte, after a normal encode
           mutate ext-comm[color].flags or 0x3fff  (TODO(WIRE_MUTATION) sites)
```

Use the lowest depth that reaches the test case. A depth-1 case still gives a
well-formed UPDATE, so the peer reaction is easier to predict.

## Pipeline

The current pipeline gets two new stages. Both are inactive when the block has
no `mutate` lines.

```text
ribout config
  -> generated path stream          (dimensions, rotators, generators)
  -> grouped ribout map             (attribute buckets)
  -> encode                         (strict, or relaxed by 'relax' gates)
       + field map                  (new: name, offset, length of each field)
  -> mutate                         (new: apply 'mutate' rules to the bytes)
  -> encoded UPDATE messages        (+ per-message 'expect' record)
```

## Block Layout

```text
ribout <name>
  address-family <afi> <safi> [route-type <type>]   # optional; inference stays
  <NLRI dimensions>                                 # prefix, rd, FlowSpec components
  <attributes>                                      # attr ..., or short forms
  [packing ...]
  [encode-policy strict|relaxed|fuzz]
  [relax <gate> ...]
  [mutate <selector> <op> ... [expect <outcome>]]
!
```

## Value Generators

A value spec is accepted in every place where a typed value is accepted.

| Form | Meaning | Status |
| --- | --- | --- |
| `V` | one literal value (number, hex, address, RT, ...) | exists |
| `V x N` | V, V+1, ... V+N-1; rotates per route | exists |
| `V xx N` | same values; multiplies routes (Cartesian) | proposed in [update-generation-rotators.md](update-generation-rotators.md) |
| `V x N step S` | step size S instead of 1 | new |
| `rand(N)`, `range(A,B)`, `randrange(A,B)` | as today | exists |
| `pick(a,b,c)` | rotate over a list | new |
| `each(a,b,c)` | list; multiplies routes | exists for FlowSpec components |
| `randpick(a,b,c)` | random member per route | new |
| `edge(u8\|u16\|u32\|u64)` | boundary values: 0, 1, 2^(n-1)-1, 2^(n-1), max-1, max | new |
| `bytes(<hex>)` | literal bytes | new |
| `randbytes(N)`, `randbytes(A,B)` | random bytes, fixed or random length | new |

Modifier `per-update` makes a rotator advance once per UPDATE, not once per
route. This is useful for mutations: each UPDATE gets a different value.

Prefix sequences step by one prefix block (`bgp_ribout_prefix_advance()`);
`step S` is the open part.

## Explicit Address Family

`address-family` is optional when the prefixes and FlowSpec lines give the
family and required otherwise; [configuration.md](../configuration.md#family-inference)
has the rule and the family names.

## FlowSpec Rule Grammar

Implemented (P1): [configuration.md](../configuration.md#flowspec) owns the component
lines, the numeric and bitmask expressions, `x <count>`, `each(...)`, and the
RFC 8956 `addr/offset-length` prefix form. The Status section lists where
that differs from this proposal.

Still proposed:

- `component <type> raw <hex>`: any component type, also unknown types, with
  unchecked bytes.

### FlowSpec next hop

RFC 8955 section 4 says the MP_REACH next-hop length MUST be 0. Only the
redirect-to-next-hop action (draft-simpson-idr-flowspec-redirect, type 0x08,
an expired draft that some receivers accept) reads a next hop. Today `next-hop`
in a FlowSpec block is accepted only with that action (`src/bgp_ribout.c`
rejects either without the other). A next hop without the action is the
`relax flowspec-next-hop` gate, which does not exist yet.

## Attribute Grammar

`attr` lines give a typed form for every path attribute bgpsim can encode.
Lines of the same attribute type merge into one attribute, in config order.

```text
attr origin igp|egp|incomplete|<0-255>
attr as-path <segments>                   # current as-path syntax
attr next-hop <ipv4>                      # classic NEXT_HOP (type 3)
attr med <value>
attr local-pref <value>
attr atomic-aggregate
attr aggregator <asn> <ipv4>
attr community <c> ...                    # aa:nn, or no-export, no-advertise, ...
attr large-community <a:b:c> ...
attr originator-id <ipv4>
attr cluster-list <ipv4> ...
attr ext-community <ec> ...               # see the table below
attr ipv6-ext-community <ec6> ...         # attribute 25 (RFC 5701)
attr raw type <code> value <blob> [flags <hex>] [length <n>]
```

`attr raw` always makes its own attribute. `flags` defaults to the flags of the
known type, or to optional+transitive. `length` overrides the length field
only; the value bytes do not change. A value longer than 255 octets gets the
extended-length flag, unless `flags` sets it differently.

The current tokens become short forms: `localpref` is `attr local-pref`, `med`
is `attr med`, `rt` is `attr ext-community rt`, and so on.

### Extended communities

The FlowSpec rows exist today as `action` lines and `rt`, `soo`, `encap`, and
`color` as block lines ([configuration.md](../configuration.md#flowspec)). The `attr ext-community`
spelling and the `raw` row are the proposal.

| `<ec>` form | Wire type | Source |
| --- | --- | --- |
| `rt <asn:nn \| ip:nn \| asn4:nn>` | 0x0002 / 0x0102 / 0x0202 | RFC 4360, RFC 5668 |
| `soo <...>` | 0x0003 / 0x0103 / 0x0203 | RFC 4360 |
| `encap <tunnel-type>` | 0x030c | RFC 9012 |
| `color <value> [co 00\|01\|10\|11] [flags <hex>]` | 0x030b | RFC 9012 section 4.3, RFC 9830 section 3 |
| `traffic-rate bytes <float> [as <asn16>]` | 0x8006 | RFC 8955 section 7.1 |
| `traffic-rate packets <float> [as <asn16>]` | 0x800c | RFC 8955 section 7.2 |
| `traffic-action [terminal] [sample]` | 0x8007 | RFC 8955 section 7.3 |
| `redirect-vrf <asn:nn \| ip:nn \| asn4:nn>` | 0x8008 / 0x8108 / 0x8208 | RFC 8955 section 7.4 |
| `mark <dscp>` | 0x8009 | RFC 8955 section 7.5 |
| `redirect-ip <ipv4> [copy]` | 0x010c | draft-ietf-idr-flowspec-redirect-ip |
| `redirect-next-hop [copy]` | 0x0800 | draft-simpson-idr-flowspec-redirect |
| `interface-set <asn>:<group> [in] [out] [non-transitive]` | 0x0702 / 0x4702 | draft-ietf-idr-flowspec-interfaceset |
| `raw <16 hex digits>` | any | - |

`<ec6>` forms: `rt <ipv6>:<nn>` (0x0002), `redirect-vrf <ipv6>:<nn>` (0x000d,
RFC 8956 section 6.1), `redirect-ip <ipv6> [copy]` (0x000c), `raw <40 hex
digits>`.

`redirect-ip` with an IPv6 address moves to attribute 25 automatically.

### Color and the CO bits

`co` sets bits 0-1 of the Color flags field (the Color-Only type, RFC 9830
section 3):

| `co` | Type | RFC 9830 meaning |
| --- | --- | --- |
| `00` | 0 | specific endpoint match (the default) |
| `01` | 1 | specific or null endpoint |
| `10` | 2 | specific, null, or any endpoint |
| `11` | 3 | reserved; sender SHOULD NOT use it; receiver MUST treat it as type 0 |

`co 11` is accepted on purpose, because a test tool must be able to send it.
`flags <hex>` sets the whole 16-bit field. Bits 2-15 are unassigned: the
originator MUST send zero and the receiver MUST ignore them (RFC 9012
section 4.3).

## SR-TE Steering

`steer` was dropped. Steering is `action redirect-ip <endpoint>` plus
`color`, or `next-hop <endpoint>` plus `action redirect-next-hop` plus
`color`; `copy` on the action sets the C bit ([configuration.md](../configuration.md#flowspec)). Still open:

- Mode 2 (an SRv6 egress service SID in a BGP Prefix-SID attribute) needs a
  Prefix-SID encoder first. Reserve `prefix-sid srv6 ...` for that.

## Packing

```text
packing max-size 4096|65535               # 65535 needs RFC 8654 on the session
packing routes-per-update <n>|max         # default max
packing withdraw separate|mixed           # mixed breaks RFC 7606 section 5.1
packing mp-position first|last|<n>        # default first (RFC 7606 section 5.1)
packing attr-order type|config            # default type
packing mutated-alone                     # put each mutated route in its own UPDATE
```

`withdraw mixed`, `mp-position` other than `first`, and `attr-order config`
are relax gates. They need `encode-policy relaxed` or `fuzz`.

`mutated-alone` limits the damage. A session reset then removes only the
routes in that UPDATE from the test result, and the oracle stays simple.

## Encode Policy And Relax Gates

```text
encode-policy strict|relaxed|fuzz
relax <gate> ...
```

- `strict` (the default): today's behavior. `relax` lines are a config error.
- `relaxed`: only the gates in `relax` lines are bypassed.
- `fuzz`: every gate is bypassed.

`encode-policy` controls the relax gates only. `mutate` and `raw` lines work
with every policy, because `mutate` acts after the encode and `raw` bytes are
not checked.

`packing withdraw mixed`, `packing mp-position` other than `first`, and
`packing attr-order config` are also gates (`withdraw-mixed`,
`mp-position`, `attr-order`).

Gate names come from the `TODO(FUZZ_GATE)` markers. Examples:

| Gate | Allows |
| --- | --- |
| `flowspec-component-order` | components in config order, duplicates |
| `flowspec-op-list` | missing or extra end-of-list bit, AND bit on the first pair |
| `flowspec-ipv6-only-component` | flow-label (type 13) in an IPv4 rule |
| `flowspec-nlri-length` | NLRI body longer than 4095 octets |
| `flowspec-next-hop` | a non-zero MP_REACH next hop without `redirect-next-hop` (RFC 8955 section 4; a ribout check, not an encoder marker) |
| `srpolicy-afi-endpoint-mismatch` | SR Policy endpoint AF different from AFI |
| `rtc-extended-ipv6-nh` | 32-octet RTC next hop |
| `withdraw-mixed` | announce and withdraw in one UPDATE |

`show ribout gates` lists every gate with its source location.

### Candidate gates by family

Strict checks that are candidates for named gates. Most carry
`TODO(FUZZ_GATE)` markers; the MVPN checks carry none.

- Unicast, labeled-unicast, VPN: next-hop family and encoding-form
  restrictions; label semantic checks; AFI-specific next-hop gates.
- SR Policy: MP_REACH AFI versus endpoint AF; mixed SR-MPLS / SRv6 segment
  lists; reserved MPLS labels in Binding SID and MPLS segments.
- RTC and VPLS: the 32-octet IPv6 global-plus-link-local next hop.
- EVPN: route-type invariants (mutually exclusive fields; ESI, gateway and
  label combinations that encode but are invalid for the type); next-hop
  forms per route type.
- MVPN: per-route-type AF consistency; Route Key structure; PMSI constraints.
- FlowSpec: component order; IPv6 prefix offsets; component-family
  consistency; action-community semantics.
- BGP-LS: descriptor and TLV structure; protocol-ID versus NLRI type;
  attribute versus NLRI cross-checks.

## Mutation Grammar

```text
mutate <selector> <op> [<arg>] [reframe|keep-lengths] [on <schedule>]
       [expect <outcome>]
```

### Selectors

A selector names one field, or a set of fields, in the encoded message. The
names follow the wire nesting.

```text
selector := segment { "." segment }
segment  := name [ "[" filter "]" ] [ "@" instance ]
instance := <index> | first | last | all | rand
```

| Selector | Field |
| --- | --- |
| `msg.marker`, `msg.length`, `msg.type` | BGP header |
| `update.withdrawn-length`, `update.attrs-length` | UPDATE framing |
| `attr[<name\|code>].flags` / `.type` / `.length` / `.value` | one path attribute |
| `mp-reach.afi` / `.safi` / `.nh-length` / `.next-hop` / `.reserved` / `.nlri` | MP_REACH_NLRI |
| `mp-unreach.afi` / `.safi` / `.nlri` | MP_UNREACH_NLRI |
| `nlri@<i>.length` / `.prefix` / `.path-id` / `.label` / `.rd` | one NLRI |
| `flowspec@<i>.length` | FlowSpec NLRI length (1 or 2 octets) |
| `flowspec@<i>.component[dst-port].type` / `.op@<j>` / `.value@<j>` | FlowSpec component |
| `flowspec@<i>.component[prefix].length` / `.offset` / `.pattern` | prefix component |
| `ext-comm[color].type` / `.flags` / `.co` / `.value` | one Color community (an entry in attribute 16) |
| `ext-comm[redirect-ip].address` / `.local-admin` / `.copy` | Redirect-to-IP |
| `ext-comm[0x8006].value` | any community, by wire type |
| `ipv6-ext-comm[redirect-ip].address` / `.copy` | attribute 25 entry |
| `tunnel-encap.tlv[sr-policy].sub-tlv[segment-list]@0.length` | SR Policy TLVs |
| `bgp-ls.tlv[263].length` | BGP-LS attribute TLV |

`attr[...]` names a whole path attribute. Attribute names: `origin`,
`as-path`, `next-hop`, `med`, `local-pref`, `atomic-aggregate`, `aggregator`,
`community`, `originator-id`, `cluster-list`, `mp-reach`, `mp-unreach`,
`ext-community`, `ipv6-ext-community`, `large-community`, `tunnel-encap`,
`prefix-sid`, `bgp-ls`, or a type code. `ext-comm[...]` and
`ipv6-ext-comm[...]` name one 8-octet or 20-octet entry inside attribute 16 or
25.

A bit field (`co`, `copy`) is a named part of its byte. `set` on it changes
only those bits.

`show ribout <name> fields [message <n>]` prints the field map: selector,
offset, length, and current value. Use it to find selectors.

### Operations

| Op | Effect |
| --- | --- |
| `set <value\|hex>` | replace the value; width stays the same |
| `add <n>`, `sub <n>` | arithmetic in the field width, with wrap |
| `xor <mask>`, `or <mask>`, `and <mask>`, `flip <bit>` | bit operations |
| `random` | random bytes of the same width |
| `edge` | next boundary value for the field width (rotates) |
| `truncate <n>` | remove the last n octets of the field |
| `extend <n> [fill <byte>\|random]` | add n octets after the field |
| `insert-before <hex>`, `insert-after <hex>` | add bytes |
| `delete` | remove the field |
| `duplicate [<n>]` | repeat the field n times (default 1) |
| `swap <selector>` | exchange two fields |

### Reframe

A length-changing op (`truncate`, `extend`, `insert-*`, `delete`,
`duplicate`) changes the size of every structure that contains the field.

- `reframe` (the default): the mutator updates every enclosing length field.
  The outer framing stays correct. Use this to test one inner parser.
- `keep-lengths`: no length field changes. Use this to test framing.

A mutation on a length field itself never reframes that field.

### Schedule

```text
on all | first | last | message <n> | messages <a>-<b> | every <n>
   | chance <percent> [max <count>]
```

The default is `all`. `chance` uses the ribout random stream, so the result is
deterministic.

### Expected outcome

```text
expect accept | treat-as-withdraw | attribute-discard
     | afi-safi-disable | session-reset [notification <code>/<subcode>]
     | session-reset|afi-safi-disable | auto
expect-all <outcome>                     # block level: every UPDATE
```

The UPDATE metadata keeps the outcome. The Python API and `show ribout <name>
mutations` show it. The tool does not check the outcome against the RFCs; it
is the claim of the block author. `expect auto` uses the table below and fails
at config time for a case with no table entry.

| Case | Outcome | Source |
| --- | --- | --- |
| Withdrawn Routes Length + Total Attribute Length + 23 > message length | session-reset, 3/1 | RFC 7606 section 3 (b) |
| Optional or Transitive flag wrong on a known attribute | treat-as-withdraw | RFC 7606 section 3 (c) |
| Well-known mandatory attribute missing | treat-as-withdraw | RFC 7606 section 3 (d) |
| ORIGIN, AS_PATH, NEXT_HOP, MED, or LOCAL_PREF malformed | treat-as-withdraw | RFC 7606 section 3 (e), 7.1-7.5 |
| ATOMIC_AGGREGATE or AGGREGATOR malformed | attribute-discard | RFC 7606 section 3 (f) |
| Duplicate attribute, not MP_REACH or MP_UNREACH | accept (first copy kept) | RFC 7606 section 3 (g) |
| Duplicate MP_REACH_NLRI or MP_UNREACH_NLRI | session-reset, 3/1 | RFC 7606 section 3 (g) |
| Attribute length runs past Total Attribute Length | treat-as-withdraw | RFC 7606 section 4 |
| MP_REACH next-hop length not as expected | session-reset or afi-safi-disable | RFC 7606 section 7.11 |
| MP_REACH or MP_UNREACH NLRI cannot be parsed | session-reset or afi-safi-disable | RFC 7606 section 3 (j), 5.3 |
| Extended Community length not a non-zero multiple of 8 | treat-as-withdraw | RFC 7606 section 7.14 |
| IPv6 Extended Community length not a non-zero multiple of 20 | treat-as-withdraw | RFC 7606 section 7.15 |
| Unassigned Color flag bits set | accept | RFC 9012 section 4.3 |
| Redirect-to-IP reserved local-admin bits set | accept | draft-ietf-idr-flowspec-redirect-ip section 2 |

Two rules change these outcomes:

- RFC 7606 section 5.2: an UPDATE that has path attributes but no reachable
  NLRI gets session-reset for every error that is not attribute-discard.
- RFC 7606 section 3 (h): with more than one error, the strongest action
  applies.

## Worked Examples

### 1. FlowSpec SR-TE steering (ExaBGP replacement)

Implemented syntax ([configuration.md](../configuration.md#flowspec)):

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

This makes 6 rules. Rule i has one Redirect-to-IPv4 community
(192.0.2.1 + i mod 3) and one Color community (100 + i mod 3, CO 01).

### 2. CO-bit and multi-Color sweep

Proposed: `pick(...)` is open; `color set` and per-value `co` exist today.

```text
ribout co-sweep
  address-family ipv4 flowspec
  prefix 10.2.0.0/24 x 4
  action redirect-ip 192.0.2.1
  color set 100 co pick(00,01,10,11) pick(50,200)
!
```

Rule n gets CO type n on Color 100. The second Color alternates between 50
and 200, so the largest Color alternates between 100 and 200. This tests
"largest Color wins" and "all CO bits are treated as 00".

### 3. Unassigned Color flag bits (depth 3)

```text
  mutate ext-comm[color].flags or 0x3fff expect accept
```

RFC 9012 section 4.3: the receiver ignores unassigned flags. The route must
stay, with the same Color and CO type.

### 4. Extended Community attribute length not a multiple of 8

```text
  mutate attr[ext-community].value truncate 1 reframe expect treat-as-withdraw
```

RFC 7606 section 7.14. `reframe` keeps the attribute, UPDATE, and message
lengths correct, so only the Extended Community rule is broken. The routes in
the UPDATE must be withdrawn. The session must stay up.

### 5. Reserved bits in the Redirect-to-IP local administrator field

```text
  mutate ext-comm[redirect-ip].local-admin or 0xfffe expect accept
```

The draft says these bits MUST be zero on send and ignored on receipt. The copy
bit does not change.

### 6. Duplicate attributes

```text
  mutate attr[med] duplicate expect accept
  mutate attr[mp-reach] duplicate expect session-reset notification 3/1
```

RFC 7606 section 3 (g): a duplicate of any attribute other than MP_REACH_NLRI
or MP_UNREACH_NLRI is discarded (the first one stays). A duplicate
MP_REACH_NLRI gives a NOTIFICATION with "Malformed Attribute List" (3/1).

### 7. FlowSpec end-of-list bit cleared (raw component)

Proposed: `component ... raw` and `expect-all` are open.

```text
ribout eol-cleared
  address-family ipv4 flowspec
  component 5 raw 0150          # dst-port: op 0x01 (=, 1 octet, no end bit), 80
  src-port 443                  # 06 91 01 bb
  action traffic-rate bytes 0
  expect-all session-reset|afi-safi-disable
!
```

The NLRI body is `05 01 50 06 91 01 bb`. The receiver reads the `dst-port`
list and does not stop after `01 50`. It reads `06` as an operator (`!=`, 1
octet) with value `91`, then `01` as an operator (`=`, 1 octet) with value
`bb`. No end bit is found before the end of the NLRI, so the rule cannot be
parsed. RFC 8955 section 4.2 calls the NLRI malformed. RFC 7606 section 3 (j)
then requires session reset or AFI/SAFI disable, because treat-as-withdraw
needs a parsed NLRI.

Other bytes can give a different result. For example, a list can parse as a
different, valid rule. So the block author must work out the bytes before
writing `expect`.

`expect-all <outcome>` is the block-level form of `expect`, for a block whose
every UPDATE is malformed by construction.

### 8. BGP message length (framing)

```text
  packing mutated-alone
  mutate msg.length add 1 on first keep-lengths expect session-reset
```

BGP does not resynchronize: a message error ends the session (RFC 4271
section 6). The peer reads one extra octet, the first `0xff` of the next
marker. In an UPDATE with only MP_REACH_NLRI, that octet becomes a classic NLRI
with prefix length 255. That is an invalid NLRI (RFC 4271 section 6.3, RFC 7606
section 5.3), so the peer sends a NOTIFICATION (3/10, Invalid Network Field)
and closes the session. If no message follows, the peer waits for the octet,
and the session ends when the hold timer expires.

## Discovery And Inspection

```text
show ribout <name> fields [message <n>]     # field map with selectors
show ribout <name> mutations                # per message: rule, field, old -> new, expect
show ribout <name> hex [message <n>]        # hex dump with field labels
show ribout gates                           # all relax gates
```

## Implementation Notes

### Field map

- The builder gets an optional field map. It is NULL unless the block has a
  `mutate` line, so strict generation has no extra cost.
- Each `TODO(WIRE_MUTATION)` marker becomes a `BGP_FIELD(map, id, off, len)`
  call at the same place.
- Many encoders write into a scratch buffer and copy it later (FlowSpec rules,
  serialized attribute groups). Field spans are relative to their blob. The
  builder rebases them when it copies the blob into a message.
- Each length field records the span that it covers. `reframe` uses this to
  find the length fields to update.
- One attribute group is serialized once and copied into many UPDATEs. Its
  field spans are recorded once and rebased for each UPDATE.

### Mutator

- `bgp_mutate_message(msg, map, rules, rng)` runs after the encode of each
  UPDATE.
- The random stream is seeded from `RANDSEED`, the ribout name, and the
  message index.
- Each applied mutation is recorded: rule, selector, offset, old bytes, new
  bytes, expected outcome.

### Parser

- Selectors are single tokens. The current tokenizer already accepts `[` and
  `]` inside tokens (`rt-set`).

### Markers

- `TODO(FUZZ_GATE)`: a strict validation or encode-decision boundary. A
  relax gate may bypass it; tests keep checking the strict default until a
  policy changes it.
- `TODO(WIRE_MUTATION)`: a concrete serialized field or byte region that a
  mutator can corrupt after a normal encode. It is not a reason to weaken
  the typed encoder.
- Markers are local signposts at exact validation branches or field-write
  sites, not design notes.

## Phases

- P1 (done): `address-family ... flowspec`, FlowSpec component and `action`
  lines, prefix-step fix. `rule`, `attr ext-community` and `steer` were
  dropped (see Status); `attr raw` is still open. Unblocked the FlowSpec
  SR-TE scale test without ExaBGP.
- P2: field map, `mutate` with value ops, `reframe`, `expect`,
  `show ribout fields/mutations`. Unblocks depth-3 fuzz of fixed-size fields.
- P3: structural ops, `packing` controls, duplicate attributes. Unblocks
  framing and list fuzz.
- P4: `encode-policy`, `relax` gates wired to the `TODO(FUZZ_GATE)` sites.
  Unblocks depth-2 fuzz.

## Out Of Scope

- Session timing, message order across ribouts, and per-peer send. See
  [peer-ribout-send.md](peer-ribout-send.md).
- Non-UPDATE messages (OPEN, NOTIFICATION, ROUTE-REFRESH). The same selector
  and op grammar can apply to them later.

## See Also

- [update-generation-rotators.md](update-generation-rotators.md): `x` versus `xx`
- [update-generation-revisit.md](update-generation-revisit.md): open encoder items, including the MVPN
  marker gap
- [bgp-ribout.md](../bgp-ribout.md#typed-templates): family-owned generators and the
  grouped map
