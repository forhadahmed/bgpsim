# Sending UPDATEs

`update generate` encodes each ribout into an UPDATE snapshot (see
[Ribout Configuration](ribout-configuration.md)). Snapshots reach peers in three
ways: standing advertisements, exec commands, and script runs. All three run
on the runtime's event loop and send only to Established sessions. Without
the runtime (for example while a configuration file loads), nothing is sent
and the exec commands report `sending UPDATEs needs the running runtime`.

Loading a configuration file runs this generation automatically once the whole
file is read (the `update generate changed` set), so a config file needs no
explicit `update generate` at its end: every ribout has a snapshot ready before
the runtime starts and any session establishes. Editing a ribout afterwards
still needs an explicit `update generate`.

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

## Snapshots

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

## Standing Advertisements

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

## Exec Commands

```text
advertise ribout <name> [router <local-as> | vrf <name|all|default>] {peer|neighbor} <ip|all>
withdraw ribout <name> [router <local-as> | vrf <name|all|default>] {peer|neighbor} <ip|all>
replay ribout <name> [router <local-as> | vrf <name|all|default>] {peer|neighbor} <ip|all>
withdraw all [router <local-as> | vrf <name|all|default>] {peer|neighbor} <ip|all>
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

`router` selects one local router. `vrf <name>` selects every router in that VRF,
`vrf all` selects every router, and `vrf default` selects the routers with no
VRF. Without a scope the command must resolve to one router: `peer all` needs
exactly one router, and `peer <ip>` needs exactly one router with that address.
`neighbor` is another word for `peer`; output always prints `peer`.

Each peer gets one line: queued (with the
UPDATE count and bytes), withheld, or skipped (`peer all` only: the session is
not Established). A peer in a VRF that cannot be opened is skipped this way.
Nothing is queued for any peer, on any selected router, when one peer rejects the
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

## Withheld Advertisements

A snapshot is sent as encoded, never re-encoded per peer. bgpsim withholds it
from a peer whose negotiated session could not parse it, and records why.
Remote peers must be configured to accept what the ribouts carry. Other
attributes (for example LOCAL_PREF to an eBGP peer, or the first AS of the
AS_PATH) are sent as configured.

| Rule | Reason shown |
| --- | --- |
| The family is listed in both OPENs; for IPv4 unicast, an OPEN without any Multiprotocol capability counts as listing it (RFC 4760) | `<family> not negotiated` |
| Both sides support 4-octet AS numbers, unless the ribout has `as-path two-byte` | `4-octet AS not negotiated (AS_PATH is 4-octet)` |
| A ribout with `as-path two-byte` goes only to a session without 4-octet AS numbers | `ribout has a two-byte as-path but 4-octet AS is negotiated` |
| The ribout has `path-id` only if ADD-PATH send is negotiated for the family | `ribout has path-id but ADD-PATH send is not negotiated for <family>` |
| The ribout has no `path-id` only if ADD-PATH send is not negotiated | `ADD-PATH is negotiated for <family> but the ribout has no path-id` |
| IPv4 unicast, labeled unicast or VPNv4 over an IPv6 next hop needs extended next hop (RFC 8950) for the family, advertised by both sides | `extended next hop for <family> over IPv6 not negotiated` |
| A ribout with `message-size` above 4096 needs Extended Message (RFC 8654), advertised by both sides | `ribout has message-size above 4096 but Extended Message is not negotiated` |

## Route-Key Overlap

Two ribouts bound to one peer must not advertise the same route: the receiver
would see one ribout's routes replaced by the other's, and a later withdraw of
either would remove both. A route key is the NLRI without its labels: prefix,
RD, Ethernet tag and path identifier (with ADD-PATH) for prefix families; RD,
Ethernet tag, MAC and IP for EVPN Type 2; distinguisher, color and endpoint
for SR Policy; the component set and RD for FlowSpec. ESI and the EVPN gateway
IP are not keys. An advertise that would overlap a bound or queued ribout is
rejected with `route keys overlap ribout <name> on this peer`.

## End-of-RIB and ROUTE-REFRESH

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

## Write Path and Show Output

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
  advertise ribout blue router 65001 peer 192.0.2.2
  sleep 30s
  withdraw ribout blue vrf all peer all
  sleep 5s
exit
```

Script mode accepts:

```text
advertise ribout <name> [router <local-as> | vrf <name|all|default>] {peer|neighbor} <ip|all>
withdraw ribout <name> [router <local-as> | vrf <name|all|default>] {peer|neighbor} <ip|all>
replay ribout <name> [router <local-as> | vrf <name|all|default>] {peer|neighbor} <ip|all>
sleep <duration>
no step <number>
```

Steps append in command order. Step numbers are one-based; removing a step
renumbers subsequent steps. `no script <name>` removes the definition.
Script names contain letters, digits, dots, underscores, or hyphens, up to 63 characters.
Ribout references use the ribout name limit of 31 characters and the same character set.
Peer addresses are canonicalized. `all`, a scope, and an omitted scope are
selectors, not eagerly resolved lists of live peers. Ribout and peer references
may be defined later in a configuration file. A step with a `vrf` scope can reach
several routers: they start together, and the step has one timing. For separate
timings, write one step per router. To overlap with separate results, start one
script per router.

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
