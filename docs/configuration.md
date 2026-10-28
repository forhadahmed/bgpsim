# BGP Simulator Configuration Guide

This document is the syntax reference for `bgpsim` configuration files and
interactive config mode.

For the exact ribout generation and packing model, see [bgp-ribout.md](bgp-ribout.md).

## File Format

- `#` and `!` start comments
- blank lines are ignored
- indentation is for readability only
- the same command set is used by config files and the live CLI

## Parser Behavior

The same token parser is shared by:

- exec mode
- config mode
- config-file command processing
- control-server command execution
- the foreground auto-attached CLI client

So the same command tables drive the interactive CLI, startup config loading,
the foreground and attached control paths, and the Python client.

Complete commands are limited to 1023 bytes, excluding the line ending, and to
32 whitespace-separated tokens. Matched keywords and individual typed
arguments are limited to 63 bytes; free-form command tails, including NLRI
hex payloads and attribute sets, can contain longer tokens within the overall
line limit. Oversized input is rejected as a whole, never executed as a
truncated prefix or as multiple configuration commands. Long value lists, such
as an `as-path` with more than 31 ASNs, do not fit on one line.

The parser supports:

- fixed keywords
- typed arguments such as integers, strings, and IP addresses
- optional tokens
- router-style abbreviations when the prefix is unambiguous

Exact keyword matches beat prefix matches. For example, `rt` resolves as `rt`
instead of colliding with `rt-set`.

## Configuration Modes

The CLI uses these hierarchical modes:

- exec mode
- global config mode
- router mode
- neighbor mode
- ribout mode
- script mode

Enter config mode from exec mode with:

```text
config
configure terminal
```

Leave config mode with:

```text
exit
end
```

Most config commands also support a `no` form to remove or reset the property.

## Router and Neighbor Configuration

### Router Block

```text
router bgp <as>
  router-id <ipv4>
  update-source <ipv4>
  neighbor <ip> remote-as <as>
!
```

Commands:

- `router bgp <as>`
- `router-id <ipv4>`
- `update-source <ipv4>`
- `neighbor <ip> remote-as <as>`
- `no neighbor <ip> remote-as <as>`
- `no router bgp <as>`

### Neighbor Submode

After `neighbor <ip> remote-as <as>`, the CLI enters neighbor mode.

Commands:

- `advertise <ribout>`
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
- `capability graceful-restart`
- `capability graceful-restart restart-time <seconds>`
- `capability route-refresh`
- `capability four-byte-asn`
- `capability add-path`
- `capability add-path <af>`
- `capability ext-nh`
- `capability ext-nh <af>`

Matching `no` forms are supported.

Notes:

- `advertise <ribout>` adds a standing advertisement: the neighbor sends the
  ribout's current snapshot whenever its session is Established. A neighbor
  keeps them in config order, each on its own running-config line.
  `no advertise <ribout>` removes one without withdrawing what was sent. See
  [Standing Advertisements](#standing-advertisements).
- `address-family ipv4` and `address-family ipv6` are enabled by default for
  new neighbors, so they are optional boilerplate
- `capability four-byte-asn` (RFC 6793) is on by default; `no capability
  four-byte-asn` is rejected while the local or remote AS exceeds 65535
- `capability add-path` enables ADD-PATH for all supported neighbor families
- `capability add-path <af>` enables ADD-PATH for one address family
- `capability ext-nh` enables RFC 8950 extended next-hop for all eligible
  neighbor families
- `capability ext-nh <af>` enables RFC 8950 extended next-hop for one eligible
  family

Supported `<af>` values:

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

### Router Example

```text
router bgp 65001
  router-id 10.0.0.1
  update-source 10.0.0.1
  neighbor 192.0.2.2 remote-as 65002
    address-family ipv4
    address-family ipv4 labels
    address-family vpnv4
    capability route-refresh
    capability graceful-restart restart-time 180
    capability add-path
    capability ext-nh
    advertise cust-a-vpn4
!
```

## Sending UPDATEs

`update generate` encodes each ribout into an UPDATE snapshot (see
[Ribout Configuration](#ribout-configuration)). Snapshots reach peers in three
ways: standing advertisements, exec commands, and script runs. All three run
on the runtime's event loop and send only to Established sessions. Without
the runtime (for example while a configuration file loads), nothing is sent
and the exec commands report `sending UPDATEs needs the running runtime`.

Generation can be scoped to avoid rebuilding unrelated workloads:

```text
update generate ribout rules-v4 rules-v6
update generate changed
update generate
```

The first command regenerates only the named blocks, including clean ones.
Names are validated before generation starts; a missing name rejects the
command without changing any snapshot. Repeated names are generated once.
`changed` generates dirty blocks and blocks without a snapshot. If everything
is current, it performs no generation. Bare `update generate` regenerates all
blocks. Unselected blocks keep their snapshots, dirty flags, timings, and peer
bindings. Each successfully regenerated standing advertisement follows the
normal send behavior below.

Generation is synchronous. Publication is atomic per block: a failed block
keeps its previous snapshot and remains dirty, while other selected blocks can
succeed. Incomplete blocks are reported as skipped and remain dirty.

### Snapshots

A snapshot is immutable. It holds the UPDATE messages, a snapshot id that is
unique across the simulator, and the wire profile they were encoded for:
family, ADD-PATH, classic or MP encoding, and whether an IPv4 family has an
IPv6 next hop (RFC 8950). Peers share snapshots. `update generate` publishes a
new snapshot and keeps the old one while a peer still has it bound.
`show ribout <name>` prints the snapshot, whether later edits made it stale,
and each peer that has it or had it withheld:

```text
  Snapshot:          1 (ipv4-unicast, add-path off, classic)
  Status:            current

Peers:
  127.0.0.2 (router 65001): snapshot 1 (ipv4-unicast), advertised
```

Advertising needs a current snapshot: a ribout that was edited after its last
`update generate` is reported as `changed since its snapshot (run update
generate)`. Withdraw and replay use the snapshot bound to the peer, so they
keep working after edits and after `no ribout <name>`. Deleting a ribout does
not withdraw its routes.

### Standing Advertisements

`advertise <ribout>` in neighbor mode keeps the ribout's current snapshot on
the neighbor's session:

- At Established, every standing ribout is queued in config order, followed
  by End-of-RIB for every negotiated family.
- `advertise <ribout>` on a live session sends it at once (no End-of-RIB).
- After `update generate`, the new snapshot is sent to every Established
  neighbor that has the ribout standing. A snapshot with the same bytes as the
  bound one is rebound without sending.
- `no advertise <ribout>` affects later sessions only; it does not withdraw.
- A standing ribout that cannot be sent (not configured, no snapshot, stale,
  or withheld for the session) is recorded with the reason and shown by
  `show bgp neighbors` and `show ribout <name>`.

### Exec Commands

```text
advertise ribout <name> peer <ip|all> [router <local-as>]
withdraw ribout <name> peer <ip|all> [router <local-as>]
replay ribout <name> peer <ip|all> [router <local-as>]
withdraw all peer <ip|all> [router <local-as>]
```

| Command | Bound snapshot afterwards | UPDATEs queued |
| --- | --- | --- |
| `advertise`, same route keys as the bound snapshot (or none bound) | the current snapshot | the current snapshot (replaces the routes in place) |
| `advertise`, route keys changed | the current snapshot | withdrawal of the bound snapshot, then the current snapshot |
| `withdraw` | none | withdrawal of the bound snapshot |
| `withdraw all` | none | one withdrawal per bound ribout |
| `replay` | unchanged | the bound snapshot again |

Withdrawals are derived from the advertisement bytes: every advertised NLRI
(with its path identifier when ADD-PATH is on) is listed in MP_UNREACH_NLRI,
or in the withdrawn routes of classic IPv4 unicast UPDATEs. Labeled-unicast
and VPN labels are written as 0x800000 (RFC 8277); other NLRI, including EVPN
labels and ESI, are copied as advertised. Withdrawals are built when first
needed and shared by peers.

`router` picks the local router when several routers have the peer; it can be
omitted when exactly one has it. Each peer gets one line: queued (with the
UPDATE count and bytes), withheld, or skipped (`peer all` only: the session is
not Established). Nothing is queued for any peer when one peer rejects the
operation: the named peer is not Established, the ribout is not bound
(withdraw, replay), its route keys overlap another ribout bound or queued for
the peer, or the peer's queue is full.

```text
bgpsim# withdraw ribout blue peer 127.0.0.2
withdraw ribout blue: queued to 127.0.0.2 (router 65001): 1 UPDATEs, 4023 bytes
bgpsim# advertise ribout blue peer all
advertise ribout blue: queued to 127.0.0.2 (router 65001): 1 UPDATEs, 4054 bytes
bgpsim# advertise ribout red-vpn peer 127.0.0.2
advertise ribout red-vpn: withheld from 127.0.0.2: VPNv4 Unicast not negotiated
bgpsim# replay ribout blue peer 127.0.0.2
Error: replay ribout blue: rejected by 127.0.0.2: ribout blue is not advertised to this peer
```

A withheld advertisement is reported but is not an error.

### Withheld Advertisements

A snapshot is sent as encoded, never re-encoded per peer. bgpsim withholds it
from a peer whose negotiated session could not parse it, and records why.
Remote peers must be configured to accept what the ribouts carry. Other
attributes (for example LOCAL_PREF to an eBGP peer, or the first AS of the
AS_PATH) are sent as configured.

| Rule | Reason shown |
| --- | --- |
| The family is listed in both OPENs; for IPv4 unicast, an OPEN without any Multiprotocol capability counts as listing it (RFC 4760) | `<family> not negotiated` |
| Both sides support 4-octet AS numbers (AS_PATH is always encoded with 4-octet ASNs) | `4-octet AS not negotiated (AS_PATH is 4-octet)` |
| The ribout has `path-id` only if ADD-PATH send is negotiated for the family | `ribout has path-id but ADD-PATH send is not negotiated for <family>` |
| The ribout has no `path-id` only if ADD-PATH send is not negotiated | `ADD-PATH is negotiated for <family> but the ribout has no path-id` |
| IPv4 unicast, labeled unicast or VPNv4 over an IPv6 next hop needs extended next hop (RFC 8950) for the family, advertised by both sides | `extended next hop for <family> over IPv6 not negotiated` |

### Route-Key Overlap

Two ribouts bound to one peer must not advertise the same route: the receiver
would see one ribout's routes replaced by the other's, and a later withdraw of
either would remove both. A route key is the NLRI without its labels: prefix,
RD, Ethernet tag and path identifier (with ADD-PATH) for prefix families; RD,
Ethernet tag, MAC and IP for EVPN Type 2; distinguisher, color and endpoint
for SR Policy; the component set and RD for FlowSpec. ESI and the EVPN gateway
IP are not keys. An advertise that would overlap a bound or queued ribout is
rejected with `route keys overlap ribout <name> on this peer`.

### End-of-RIB and ROUTE-REFRESH

End-of-RIB (RFC 4724) is sent once per session for every negotiated family,
after the standing advertisements (at once when there are none): an empty
23-byte UPDATE for IPv4 unicast, and an UPDATE with an empty MP_UNREACH_NLRI
otherwise. Later sends get no End-of-RIB.

A ROUTE-REFRESH (RFC 2918) for a negotiated family queues a replay of every
snapshot bound to the peer in that family, then End-of-RIB when both sides
negotiated graceful restart. A refresh that arrives before an identical
queued replay starts is merged with it. Refreshes for families that are not
negotiated, and enhanced route refresh markers (RFC 7313 subtypes), are
ignored.

### Write Path and Show Output

Each peer writes its queue in order, in batches of up to 256 UPDATEs or
64 KiB. KEEPALIVE and NOTIFICATION messages go out between batches, never
inside an UPDATE. A session reset drops the peer's bindings, queue and
withheld records, since the receiver drops the routes too; standing
advertisements are sent again at the next Established. Queues and binding
tables grow on demand, subject to per-peer admission budgets: 1,024 queued
operations, 1,024 bound ribouts, and 1 GiB of retained-reference charges by
default. Set `BGPSIM_TX_MAX_JOBS`, `BGPSIM_TX_MAX_BINDINGS`, and
`BGPSIM_TX_MAX_RETAINED_BYTES` before starting the process to override them.
Values must be positive decimal integers; invalid values use the defaults.
Job and binding budgets cannot exceed `INT_MAX`.

The retained-memory budget conservatively charges every snapshot/stream
reference, including queued old generations and an in-flight write. Shared
objects can be charged more than once; this is not an RSS limit. Storage for
all selected peers is reserved before any queue or binding is committed, so
an admission failure does not partially enqueue the operation.

`show bgp neighbors` adds an `Outbound ribouts` block per peer. The sent
`Updates` count includes End-of-RIB markers:

```text
  Message statistics:    Sent       Rcvd
    Opens:                  1          1
    Notifications:          0          0
    Updates:                4          0
    Keepalives:             1          1
  ...
  Outbound ribouts: OutQ 0 UPDATEs
    blue: snapshot 1 (ipv4-unicast), advertised
    red-vpn: snapshot 2 (vpnv4), advertised
  End-of-RIB sent: IPv4 Unicast, VPNv4 Unicast
```

A ribout still being written shows `sending 120/400 UPDATEs` (or `replaying`),
a queued one `advertisement queued (400 UPDATEs)`, a pending withdrawal
`withdrawing snapshot 3 (vpnv4), 10/50 UPDATEs`, and a withheld one its
reason:

```text
    blue: withheld: 4-octet AS not negotiated (AS_PATH is 4-octet)
    red-vpn: withheld: VPNv4 Unicast not negotiated
```

`show bgp summary` reports the queued UPDATEs of each peer in `OutQ`.

## Scripts and Runs

A **script** is an ordered definition. A **run** owns a frozen copy of that
definition, a repeat count, state, and progress/timing observations. Editing
or deleting a script does not change an existing run.

### Script Configuration

```text
script churn
  advertise ribout blue peer 192.0.2.2 router 65001
  sleep 30s
  withdraw ribout blue peer 192.0.2.2 router 65001
  sleep 5s
exit
```

Script mode accepts:

```text
advertise ribout <name> peer <ip|all> [router <local-as>]
withdraw ribout <name> peer <ip|all> [router <local-as>]
replay ribout <name> peer <ip|all> [router <local-as>]
sleep <duration>
no step <number>
```

Steps append in command order. Step numbers are one-based; removing a step
renumbers subsequent steps. `no script <name>` removes the definition.
Script names contain letters, digits, dots, underscores, or hyphens, up to 63 characters.
Ribout references use the ribout name limit of 31 characters and the same character set.
Peer addresses are canonicalized. `all` and an omitted router are selectors,
not eagerly resolved lists of live peers. Ribout and peer references may be
defined later in a configuration file.

Durations are nonnegative integers with `ms`, `s`, `m`, or `h` suffixes. Bare
integers mean seconds. Running-config emits durations in milliseconds for
exact round trips. No commands, script definitions, or configuration loads
implicitly start a run.

### Run and Show Commands

```text
run script churn
run script churn repeat 100
run script churn repeat forever
show scripts [color]
show script churn [color]
show runs [color]
show run 1 [color]
run script churn json [repeat <count|forever>]
show run 1 json
cancel run 1
clear run 1
```

Repeat defaults to one; a numeric count must be positive. `forever` is
explicit. Runs have monotonically increasing IDs, independent of script
names. `cancel` stops a pending or running run; UPDATEs already queued for
its current step are still written, unobserved, and nothing is withdrawn.
`clear` removes only terminal records; pending/running runs must first be
cancelled. The model retains at most 64 scripts, 256 steps per script, and
128 runs. Clearing terminal records frees run slots without reusing IDs.

The `json` forms serialize the same run model for automation, including the ID,
state, error, current-step peer counters, and completed-step timing aggregates.
They do not parse display text or change script execution. See the
[Python API](python-api.md) for checked commands and bounded run waits.

### Execution

With the runtime running, `run script` starts the run on the event loop:

```text
bgpsim# run script churn repeat 2
Run 1: script churn started.
```

Each advertise, withdraw or replay step is admitted exactly like the exec
command of the same name (see [Sending UPDATEs](#sending-updates)), then
waits until every planned peer has written all of its UPDATEs. A peer whose
session cannot parse the snapshot is withheld, and a `peer all` peer whose
session is not Established is skipped; both send nothing, count as done, and
are listed with the reason in `show run`. Sleep steps wait on a timer. A step
with nothing to send completes on the next loop iteration, so a run of
withheld steps with `repeat forever` does not block the loop.

The run fails, with the reason in `show run`, when a step is rejected (for
example withdrawing a ribout the peer does not have, or a route-key overlap),
when a step names a peer that is not Established, or when a peer's session
resets while the step is sending to it.

Without the runtime (for example from a configuration file, before the loop
starts), `run script` creates a pending record only. There is no autostart.
Standalone script-file execution and semicolon chains are not implemented.

`show runs` displays state, iteration, phase, run/phase elapsed time and TX
message progress. `show run` adds the frozen script revision, current step,
per-peer snapshot id (Export), message/byte progress, individual TX durations,
withheld and skipped peers with their reasons, and completed-step timing
aggregates. Unknown measurements display `-`. Progress comes only from write
completions; nothing is fabricated.

```text
Router     Peer                                    State      Export       TX messages        TX bytes               TX time
65001      127.0.0.2                               complete   1            1/1                4054/4054              0ms
TX completion is local socket-write completion, not TCP acknowledgment or receiver installation.
```

Timings use the monotonic clock in milliseconds: preparation, time queued
before the first write completion, transmission through the final write
completion, and sleep. TX ends at the last peer's write completion, even if
step bookkeeping happens later. Per-peer TX starts are independent. A step
cannot complete until every resolved peer completes, and a sleep cannot
complete before its requested duration. Local write completion does not
establish TCP acknowledgment or receiver route installation.

Only current/last-step peer details and per-step timing count/total/min/max
are retained; repeating forever does not grow iteration history. Failed or
cancelled partial steps are not recorded as successful timing samples.

Colors highlight headings, run states and active phases. Output is plain by
default for Python/control clients; add `color` for an attached interactive
terminal. Direct TTY output uses color automatically. `NO_COLOR` or
`TERM=dumb` suppresses color. Running-config never contains ANSI escapes or
run records.

## Ribout Configuration

Ribout blocks generate synthetic route sets and encode them into UPDATE
snapshots with `update generate`; [Sending UPDATEs](#sending-updates) covers
how snapshots reach peers.

Names use letters, digits, dots, underscores, or hyphens, up to 31 characters.
Rejected edits leave the block and its cached snapshot unchanged. Accepted
edits make the snapshot stale (`show ribout <name>` prints `Status: stale`)
until the next `update generate`, which reports failure if any resolved block
fails generation and preserves its last successful snapshot.

Common shape:

```text
ribout <name>
  [address-family ...]
  prefix ...
  [rd ...]
  [label ...]
  [label2 ...]
  [mac ...]
  [ip ...]
  [distinguisher ...]
  [color ...]
  [endpoint ...]
  [path-id ...]
  [next-hop ...]
  [as-path ...]
  [localpref ...]
  [med ...]
  [enlp ...]
  [priority ...]
  [preference ...]
  [binding-sid ...]
  [segment-list ...]
  [origin ...]
!
```

A FlowSpec ribout is one rule template. `prefix` is its destination prefix,
and the other match components are block lines too:

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

### Family Inference

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
`endpoint`, and a Color community in any other family. A `prefix` with only
attribute lines is unicast; a FlowSpec block with only `prefix` needs
`address-family`, and so does a FlowSpec block without a prefix, for example
`address-family ipv6 flowspec`.

#### `address-family <family>`

Optional. Names the ribout family with the neighbor family names (for example
`ipv4`, `vpnv4`, `l2vpn evpn`, `ipv6 flowspec-vpn`, `ipv4 srpolicy`). The
configured tokens must agree with it; otherwise generation stops with an
error. A name that is not a neighbor family is rejected.

### Token Reference

Numbers are plain decimal digits within their field: no sign (`+5`, `-1`), no
spaces or other text inside them, and a count after `x` is 1 or more (`x 0`
is an error rather than an empty list). A line must end where its syntax
ends; text after the last value is an error, never ignored. A rejected line
leaves the ribout as it was.

#### `prefix <ip-prefix> [x <count>]`

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

#### Randomness And `RANDSEED`

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

#### Rotating key lists

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

#### `rd [rotate] <values>`

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

#### `label <values>`

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

#### `label2 <values>`

Set EVPN Type 2 optional Label2 values: MPLS labels, or VNIs up to 16777215 with a VXLAN-like `encap`, as for `label`.

Examples:

```text
label2 40000
label2 40000 40001
label2 40000 x 8
```

#### `path-id [rotate] <ids>`

Set one or more ADD-PATH identifiers: each prefix is sent once per ID, or with
`rotate` once, with ID i mod n.

Examples:

```text
path-id 1
path-id 1 2 3 4
path-id rotate 1 x 4
```

#### `ethernet-tag [rotate] <values>`

Set EVPN Ethernet Tag values (Type 5, and Type 2). With `rotate` route i takes
tag i mod n; with `rd rotate` of the same length each VRF's RD and tag go
together. A Type 2 `ip rotate` counts MACs without the tag dimension then, so
MAC i still binds IP i.

Examples:

```text
ethernet-tag 0
ethernet-tag 0 100 200
ethernet-tag 0 x 16
ethernet-tag rotate 100 x 16
```

#### `mac <mac|u64> [x <count>]`

Set EVPN Type 2 MAC-address values. Decimal `u64` shorthand is zero-extended
into the 48-bit MAC field.

Examples:

```text
mac 00:11:22:33:44:00
mac 1
mac 00:11:22:33:44:00 x 1024
mac 1 x 1024
```

#### `ip [rotate] <ip> [x <count>]`

Set EVPN Type 2 optional IP-binding values. Several IPs multiply the routes:
each MAC is generated with each IP. With `rotate` MAC i is bound to IP i
instead (mod the IP count; MACs counted over the RD, Ethernet tag and MAC
tuples): one MAC/IP binding per host.

A ribout holds one `ip` line per address family: a line of the other family
adds a second, so every MAC is generated with an IPv4 and an IPv6 binding
(dual-stack hosts, two routes per MAC, IPv4 first); a line of a family already
set replaces it, and `no ip` removes both. Type 2 `label`, `label2` and
`rt-set` rotate per path, so add `rotate-every 2` to give a dual-stack host's
two routes the same labels and route targets.

Examples:

```text
ip 10.0.0.1
ip 10.0.0.1 x 256
ip 2001:db8:10::1 x 256
ip rotate 10.1.0.1 x 1024
ip rotate 2001:db8:20::1 x 1024
```

#### `gateway-ip <ip-prefix> [x <count>]`

Set EVPN Type 5 gateway IP values.

Examples:

```text
gateway-ip 10.255.0.1
gateway-ip 10.255.0.1 x 8
gateway-ip 2001:db8:ffff::10
```

#### `esi <esi|hex|u64> [x <count>] | <esi|hex|u64>...`

Set EVPN ESI values. Accepted forms are canonical `aa:bb:...` 10-octet ESI,
compact 20-digit hex without separators, or decimal `u64` shorthand
zero-extended into the 80-bit ESI field.

Examples:

```text
esi 00:00:00:00:00:00:00:00:00:01
esi 00112233445566778899
esi 0 x 16
```

#### `next-hop <ip-prefix> [x <count>] [link-local <ipv6>]`

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

#### `as-path <segments>`

Set the AS_PATH spec.

Examples:

```text
as-path 65001 65002 65003
as-path 65001 { 65002 65003 } 65004
as-path 65001 [rand(65000) x 4]
```

#### `localpref <value>`

Set LOCAL_PREF.

Examples:

```text
localpref 100
localpref rand(300)
localpref range(100,110)
localpref randrange(100,110)
```

#### `med <value>`

Set MED.

Examples:

```text
med 50
med rand(25)
med range(10,25)
med randrange(10,25)
```

#### `origin <igp|egp|incomplete>`

Set ORIGIN.

#### `rt <values>`

Build one fixed route-target set by repeating `rt` lines.

Example:

```text
rt 65000:100
rt 65000:101
```

#### `rt-set <sets>`

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

#### `community <sets>` and `large-community <sets>`

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

#### `rotate-every <n>`

Advance the rotations once every n paths instead of every path, so blocks of
n consecutive paths share them: `rt-set`, `community`, `large-community`,
`rd rotate`, `label rotate`,
`next-hop` lists, `soo`, `encap`, `router-mac`, `color` (outside SR Policy),
EVPN Type 2 `label`, `label2` and `esi`, ranges such as `med range(...)`,
FlowSpec action lists, and random values. Route i then carries entry
(i / n) mod count of each, so with `prefix ... x 10000`, `rt-set ... x 100` and
`rotate-every 100` each VRF gets a contiguous block of 100 prefixes. NLRI keys
still change every path.

#### `rotate-period <n>`

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

#### `soo <values>`

Set one or more site-of-origin values.

Example:

```text
soo 65000:9
```

#### `encap <values>`

Set EVPN Encapsulation extended-community values. Common names such as
`vxlan`, `nvgre`, `gre`, `mpls-in-gre`, and `l2tpv3` are accepted, or a raw
numeric tunnel type can be used.

The encap also sets the form of the EVPN label fields (`label`, `label2`). With
`vxlan`, `nvgre`, `12` (VXLAN-GPE) or `19` (Geneve) they carry the 24-bit VNI
itself (RFC 8365 section 5.1.3): `label 30000` goes on the wire as `00 75 30`.
With any other encap, or none, they carry MPLS labels: `07 53 01`. Several
values rotate per path, and each path's labels follow its own encap.

Examples:

```text
encap vxlan
encap vxlan nvgre
encap 8 9
```

#### `router-mac <mac|u64> [x <count>]`

Set EVPN Router's MAC extended-community values. These are attr-side rotators;
they do not change route identity, but they do split attribute groups. Decimal
`u64` shorthand is zero-extended into the 48-bit MAC field.

Examples:

```text
router-mac 02:00:00:00:00:01
router-mac 1
router-mac 02:00:00:00:00:01 02:00:00:00:00:02
router-mac 1 2
router-mac 02:00:00:00:00:01 x 16
```

#### `distinguisher [rotate] <values>`

Set SR Policy distinguisher values.

Examples:

```text
distinguisher 100
distinguisher 100 101 102
distinguisher 100 x 64
distinguisher rotate 100 x 4
```

#### `color [rotate|set] <c> [co <bits>] ... | [rotate|set] <base> x <count> [co <bits>]`

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

#### `endpoint [rotate] <ip> [x <count>]`

Set SR Policy endpoint values. The endpoint address family determines whether
the ribout resolves to SR Policy IPv4 or SR Policy IPv6.

Examples:

```text
endpoint 10.0.0.1 x 128
endpoint 2001:db8:100::1 x 128
endpoint rotate 10.0.0.1 x 4
```

#### `preference <value>`

Set SR Policy preference values.

Examples:

```text
preference 100
preference rand(4096)
preference range(100,115)
preference randrange(100,115)
```

#### `enlp <value>`

Set SR ENLP values. Valid values are `1..4`.

Examples:

```text
enlp 3
enlp 1 2 3 4
enlp randrange(1,4)
```

#### `priority <value>`

Set SR priority values. Valid values are `0..255`.

Examples:

```text
priority 7
priority range(7,15)
priority randrange(0,255)
```

#### `binding-sid <mpls|srv6> <value>`

Set SR Binding SID values. `mpls` uses label values; `srv6` uses IPv6 SIDs.

Examples:

```text
binding-sid mpls 16000
binding-sid mpls range(16000,16031)
binding-sid mpls randrange(16,1048575)
binding-sid srv6 fc00:0:70::1
binding-sid srv6 fc00:0:70::1 x 16
```

#### `segment-list <id> weight <weight> <mpls|srv6> <segments...>`

Define one SR Policy segment-list. Segment-lists do not multiply route count;
they stay block-wide and are attached through the SR tunnel-encapsulation
attribute. SRv6 segment entries can optionally carry `behavior <u16>` and
`structure <locator-block> <locator-node> <function> <argument>`.

Examples:

```text
segment-list 1 weight 10 mpls 16010 16011
segment-list 2 weight 20 srv6 2001:db8:1::1 2001:db8:1::2
segment-list 3 weight 30 srv6 2001:db8:3::1 behavior 4660 structure 48 16 16 48 2001:db8:3::2
```

### Typed NLRI Templates

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
nlri bgp-ls node protocol <id> identifier <id> local-as <asn> local-router <id>
nlri bgp-ls link protocol <id> identifier <id> local-as <asn> local-router <id> remote-as <asn> remote-router <id> local-id <id> remote-id <id>
nlri bgp-ls ipv4-prefix protocol <id> identifier <id> local-as <asn> local-router <id> prefix <prefix/len>
nlri bgp-ls ipv6-prefix protocol <id> identifier <id> local-as <asn> local-router <id> prefix <prefix/len>
```

Use `mvpn6` for the same seven route types in IPv6 MVPN. MVPN addresses must
match the selected AF, and groups must be multicast. EVPN Types 3/4 accept
IPv4 or IPv6 originating-router addresses. A BGP-LS router ID is dotted IPv4
or hex octets; the selected protocol determines the valid router-ID length.
The Leaf A-D Route Key is the complete encoded Type 2 or Type 3 NLRI,
including its type and length, without an ADD-PATH Path ID.

| Template | Default step | Other accepted steps |
| --- | --- | --- |
| RTC membership | `target` assigned number | none |
| RTC default | none, count 1 | none |
| VPLS | `ve-id` | `rd` assigned number |
| EVPN Type 1 | `rd` assigned number | `ethernet-tag` |
| EVPN Type 3 | `router` | `rd`, `ethernet-tag` |
| EVPN Type 4 | `router` | `rd` |
| MVPN Types 1/2/3/5/6/7 | `rd` assigned number | `source`, `group` for Types 3/5/6/7 |
| MVPN Type 4 | `router` | none |
| BGP-LS | `identifier` | none |

Counts are positive 32-bit values. Generation rejects numeric overflow,
address overflow, group ranges leaving multicast space, and invalid label
blocks. A template count multiplies with the existing `path-id` dimension;
common attributes still rotate normally. These templates do not change the
existing prefix/rotator/multiplier semantics.

Family-specific attributes:

```text
pmsi flags <0-255> type <0-255> label <20-bit-label> id <hex>
l2-info encap <0-255> flags <0-255> mtu <0-65535>
ls-attribute type <0-65535> value <hex>
```

PMSI applies to MVPN and EVPN Type 3; `id none` encodes an empty tunnel ID.
Layer 2 Info applies to VPLS. `ls-attribute` supplies one opaque BGP-LS
attribute TLV. Each has a matching `no` form; `no nlri` removes the template.
Common `rt`, `soo`, communities, AS path, origin, next hop, and other
attribute commands remain available. An optional `address-family` must agree
with the template.

Scope limits: RTC templates encode full memberships or the default, not
partial memberships. EVPN Type 1 templates encode MPLS labels, not VNIs.
BGP-LS exposes typed node/link/reachability descriptors, not arbitrary NLRI
TLV chains. Each block has at most one PMSI or BGP-LS attribute value and one
VPLS Layer 2 Info community. Attribute storage is bounded at 512 bytes;
CLI line/token limits also apply. IPv6 link-local companion next hops are
not accepted for templates. Source/group addresses are full-width hosts,
not multicast aggregate prefixes.

Example:

```text
ribout inclusive-multicast
  nlri evpn type3 rd 65000:1 ethernet-tag 1 router 192.0.2.1 x 1000
  pmsi flags 0 type 6 label 1000 id c0000201
  rt 65000:100
  next-hop 192.0.2.1
!
```

`update generate`, `show ribout <name>`, `show ribout <name> preview`,
`advertise ribout <name> peer <ip>`, `withdraw ribout <name> peer <ip>`, and
`withdraw all peer <ip>` use the common snapshot/TX path.

### FlowSpec

A FlowSpec ribout (RFC 8955, RFC 8956) is one rule template. `prefix` is the
destination prefix (component 1); `src-prefix` and the operator components
are block lines. Value generators make many NLRIs from the template: prefix
counts, component sequences and `each(...)` multiply, then `rd` and
`path-id`. Use one block for each set of attributes that does not rotate.

#### `src-prefix <ip/len> [x <count>]`

Component type 2. It steps like `prefix`, and an IPv6 source prefix can use
the RFC 8956 offset form `<ip>/<offset>-<length>`.

#### Operator components

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

#### `action <action>`

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

### Basic Ribout Examples

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

EVPN Type 5:

```text
ribout demo-evpn5
  prefix 192.168.0.0/24 x 100
  rd 65000:300
  label 30000
  ethernet-tag 0
  gateway-ip 10.255.0.1 x 2
  rt-set [65000:300] [65000:301,65000:302]
  encap vxlan
  router-mac 02:aa:bb:cc:dd:ee
  next-hop 192.0.2.10
  med rand(25)
  origin igp
!
```

EVPN Type 2:

```text
ribout demo-evpn2
  rd 65000:400 x 8
  ethernet-tag 100 200
  mac 00:11:22:33:44:00 x 1024
  ip 10.0.0.1 x 2
  label 30000 30001
  label2 40000 40001
  esi 00:11:22:33:44:55:66:77:88:99
  rt-set [65000:400] [65000:401,65000:402]
  encap vxlan nvgre
  router-mac 02:00:00:00:00:01 02:00:00:00:00:02
  next-hop 192.0.2.10 x 4
  localpref range(150,153)
  origin igp
!
```

SR Policy:

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

## Useful Exec Commands

After configuring ribouts and neighbors:

- `update generate`
- `show ribout`
- `show ribout <name> preview <count>`
- `show ribout-map <name>`
- `show running-config`
- `advertise ribout <name> peer <ip|all>` and the other
  [send commands](#exec-commands)
- `show bgp neighbors` for the outbound state of each peer

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

See [bgp-ribout.md](bgp-ribout.md#exact-generator-order) for the exact rotation order and grouping rules.
