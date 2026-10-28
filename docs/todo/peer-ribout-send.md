# Script/Run and RIBOUT TX Design

## Status and Scope

The outbound engine is implemented: shared advertisement snapshots, on-demand
withdrawals, per-peer job queues writing batches on the runtime loop, exec
commands, standing advertisements with End-of-RIB, ROUTE-REFRESH replay, and
script execution. [configuration.md](../configuration.md#sending-updates) is
the user reference. This document keeps the design rationale and the
measurements behind it; the table records where the implementation differs
from the design below.

| Area | Implemented | Difference from the design |
| --- | --- | --- |
| Snapshots | `bgp_ribout_snapshot_t`: immutable, loop-owned refcount, simulator-wide id, wire profile, frozen config clone (for key checks), advertisement `bgp_msg_stream_t` | The stream takes over the generated `bgp_msg_t` list (one buffer per UPDATE) instead of chunked arenas with descriptors |
| Wire profile | Frozen at generation from the ribout: family, ADD-PATH, classic or MP, next-hop family, RFC 8950 need; AS_PATH always 4-octet | Not resolved per peer: a peer whose negotiated capabilities do not match is withheld with a reason instead of failing preparation |
| Withdrawals | Derived from advertisement bytes on first use and cached weakly on the snapshot; the probe in Measured Costs found them byte-identical to map-encoded withdrawals for the fifteen cases it measured | As designed |
| Generation | All blocks, named blocks, or only changed blocks on the loop; failure keeps the previous snapshot | Synchronous; no build worker, revision-checked asynchronous publication, or snapshot memory budget |
| Peer TX | `bgp_peer_tx_t`: growable bindings, withheld records and FIFO; configurable job/binding/retained-reference budgets; batches of at most 256 UPDATEs or 64 KiB; reserve on every peer, then commit only if none rejects | No fair ready queue across peers: each peer pumps its own queue after every write callback; bindings change at admission (intended state), so `withdraw all` expands into withdraw jobs behind the queued work instead of cancelling it |
| Overlap | Rejected at admission from the frozen configs' key space (per-family interval intersection) | No admission index; a conservative equality test chooses replace in place versus withdraw then advertise |
| Write path | Control messages before UPDATE batches; writes gated on `closing`, deferred while reading; epoch-checked callbacks release references, including on cancellation | As designed |
| Reset | Bindings, queue and withheld records dropped; observed script steps fail | Standing advertisements (`neighbor ... advertise`) are the explicit automatic-replay policy for new sessions |
| Additions | Standing advertisements, End-of-RIB after the initial update, ROUTE-REFRESH replay (End-of-RIB with graceful restart) | Not part of the original design |
| Scripts | Steps admitted like exec commands with an observer; uv timers for sleeps and deferred transitions; withheld and skipped peers recorded with reasons | `cancel run` lets admitted jobs finish unobserved and withdraws nothing |

There is no RIB-IN or best-path selection in this design. It does not introduce
a second event loop, a separate socket owner, or a parallel wire encoder.

Open:

- a fair ready queue across peers (Peer TX row)
- asynchronous builds with a snapshot memory budget (Generation row)
- cumulative message offsets for constant-time progress accounting
- the realistic-packing cases of Measured Costs in `bench_ribout_pipeline`
- step 5 of the verification sequence: an independent receiver and
  multi-peer measurements

## Script/Run Model

[configuration.md](../configuration.md#scripts-and-runs) documents the script
grammar, run states, limits, and the timing columns. The design points that
the user reference does not state:

- A run owns a frozen copy of the definition's steps and revision, with
  selectors, not frozen RIBOUT configuration or resolved peers; `peer all` and
  an omitted router are resolved at each step.
- `script.c` owns validation, storage, state transitions, and timing
  observations; `script_cli.c` owns command integration and rendering;
  `script_exec.c` drives the observation APIs from tx admission, write
  callbacks and uv timers. The model has no sockets or timers of its own, so
  unit tests drive it directly.
- Local write completion is neither a TCP acknowledgment nor proof of receiver
  route installation. Failed or cancelled partial steps contribute no timing
  samples.

## Configuration and Generation Boundaries

Working configuration and published wire output are separate objects.

1. A successful attribute edit updates working configuration and makes the
   current snapshot stale.
2. Explicit generation captures a coherent input revision and wire profile.
3. Build advertisement output privately. Withdrawal output is derived later
   from the published advertisement bytes ([Withdrawal Streams](#withdrawal-streams)).
4. Publish the complete snapshot on the event loop only after the build succeeds.
5. Keep the previous snapshot usable if validation, allocation, or encoding fails.

Attribute edits do **not** create snapshot generations.
Individual commands are failure-atomic; there is no multi-command transaction
or receiver-visible atomic switch for an entire RIBOUT. Explicit generation is
the commit boundary for wire output.

`bgp_ribout_edit()` owns the common CLI/config edit operation.
`bgp_ribout_generate_messages()` publishes the encoded `bgp_msg_t` list as a
new reference-counted snapshot and frees the temporary map; the block's
`messages` and `message_count` are views of its current snapshot. Peers,
queued jobs and in-flight batches hold their own references, so the next
generation never frees bytes that are still being written.

Generation runs synchronously on the event loop today, so it stalls every
session's timers and writes while it runs. At realistic packing it costs
0.28-0.57 s per million NLRI ([Measured Costs](#measured-costs)); multi-million
NLRI ribouts stall the loop for seconds. Neither a synchronous limit nor the
bounded worker below exists yet (the Generation row above).

For asynchronous builds (open), assign input revisions and build-request IDs
on the loop. A worker receives a deep-frozen configuration/profile, never live
mutable objects. Its completion may publish only while the ribout identity,
revision, and latest request still match. A superseded result is discarded and
reported as such; it must not silently become the output of a newer
configuration.

## Shared Snapshot Architecture

```text
  working RIBOUT configuration
             |
       explicit generation
             v
  frozen inputs + wire profile
             |
       build (on the loop today; bounded worker open)
       temporary RIBOUT map
             |
       loop validates/publishes
             v
  registry --> tx_snapshot <---------------------+
               |                                |
               +--> advertisement msg_stream    | retained references
               |                                |
               +..> withdrawal msg_stream       |
                    (derived on demand)         |
                                                |
  peer A: bindings + job FIFO --> tx_batch ------+
                                   |            |
                                TCP socket A    |
                                                |
  peer B: bindings + job FIFO --> tx_batch ------+
                                   |
                                TCP socket B
```

Structure names below are design names, not declarations already present in
the repository.

| Structure | Responsibility |
| --- | --- |
| `tx_snapshot` | Immutable generation, stable RIBOUT ID, wire profile, loop-owned reference count, and the advertisement message stream |
| `wire_profile` | Canonical key for all encoding-relevant choices; only identical wire encodings share a snapshot |
| `msg_stream` | Chunked byte arenas and compact message descriptors containing location, length, and cumulative byte counts |
| `tx_job` | One advertise/withdraw/replay operation with a snapshot reference, message cursor, and run/step identity |
| `peer_tx` | Session epoch, bounded job FIFO, active batch, advertised-RIBOUT bindings, and ready-queue links |
| `tx_batch` | Reusable `uv_write_t` and bounded `uv_buf_t` array pointing into pinned snapshot arenas |

RIBOUT IDs must survive array compaction and distinguish deletion/recreation
under the same name. Peer callbacks likewise need stable lifetime ownership;
an epoch number does not make a dangling peer pointer safe.

Bindings are a growable vector. Do not allocate a per-peer route hashmap merely
to remember which complete RIBOUTs were advertised. Per-route ownership is a
separate requirement if arbitrary overlapping RIBOUTs become supported.

### Wire Profiles

The profile (`bgp_tx_profile_t`) is frozen at generation: AFI/SAFI, the ribout
family, ADD-PATH, classic versus MP encoding, next-hop family, and the RFC 8950
need. AS_PATH is always 4-octet, so ASN encoding is not a profile field. A peer
whose negotiated capabilities do not match is withheld with a reason; it never
receives incompatible bytes. The current 4096-byte message limit remains in
force unless extended-message support is implemented.

### Withdrawal Streams

Generation builds only the advertisement stream and then discards the map.
Steady-state TX needs neither mutable generator state nor a map walk for every
peer. A withdrawal stream is derived on demand, in withdraw Prepare, from the
advertisement bytes of the snapshot bound to the peer:

1. Find the NLRI of each UPDATE: the NLRI field of `MP_REACH_NLRI`, or the
   classic NLRI field after the path attributes.
2. Walk NLRI boundaries with a per-family length rule. This is not a full
   decode: prefix families read a length octet, EVPN and MVPN a route type
   plus body length, SR Policy and RTC a bit length, VPLS and BGP-LS a
   two-octet length, and FlowSpec its one- or two-octet length.
3. Copy runs of NLRI into full UPDATEs without path attributes, rewriting
   labels where the family requires it.

Withdrawals carry route identity and, where negotiated, the original Add-Path
ID; they do not require advertisement path attributes or a next hop:

- Classic IPv4 uses Withdrawn Routes and an empty path-attribute section.
- MP families use `MP_UNREACH_NLRI` with AFI, SAFI, and family-specific NLRI.
- Labeled-unicast and VPN withdrawals use the compatibility label bytes
  `80 00 00`, rather than blindly copying the advertised label stack.
- Other families retain their own route-identity encoding rules.

Frame withdrawal UPDATEs with the existing builders: `bgp_builder_append()`
for classic IPv4 and `bgp_builder_append_mp()` with `is_reach = 0`. The
per-family length rule is the only new wire knowledge; it must agree with the
family encoders in `bgp_update*.c` and `bgp_ribout.c`.

Deriving from the bound advertisement bytes gives these properties:

- The withdrawal uses the wire profile and Add-Path IDs that the routes were
  advertised with, because it is made from those bytes.
- It needs neither the map nor frozen generator inputs. Compact FlowSpec map
  entries need their rule template to encode, but the advertised bytes already
  hold the materialized rules.
- Edited live configuration is never a source for withdrawing an older
  snapshot.
- Withdrawal memory exists only while a withdraw is pending. Peers bound to
  the same snapshot share one derived stream; it is freed when the last
  withdraw job that uses it completes, not kept for later withdrawals.

Building withdrawal streams eagerly at generation was measured and rejected:
it is slower than deriving them later and holds 25-74% more memory per
advertisement stream ([Measured Costs](#measured-costs)).

## Operation Semantics

Exec commands and script steps share one admission path (`tx_admit()`):

```text
advertise ribout blue peer 192.0.2.2 router 65001
withdraw ribout blue peer 192.0.2.2 router 65001
replay ribout blue peer 192.0.2.2 router 65001
withdraw all peer 192.0.2.2 router 65001
```

Resolve selectors once per step, rejecting ambiguous routers, unavailable peers,
and missing/incompatible snapshots explicitly. Pin the selected generations and
session identities before queue admission. A queued job must not change meaning
because another client edits configuration or publishes a newer snapshot.
If generation is needed, make it an explicit prepare operation; never transmit
the last successful snapshot as though it represented newer dirty inputs.

### Advertise and Replay

Advertise selects a generated snapshot for that RIBOUT/profile. Replay explicitly
resends the currently bound snapshot; it is not a request to generate from
working configuration. A FIFO preserves deliberate repeated actions and timed
cycles; do not silently coalesce script steps.

An attribute-only advertisement with identical route keys and Add-Path IDs
replaces those routes at the receiver. Generations are local lifetime objects,
not extra receiver paths. After a complete replacement, release superseded
bindings rather than retaining every past generation.

The initial safe policy for a changed route-key set is withdraw-old, then
advertise-new. This avoids a route-diff engine but creates a deliberate
withdrawal interval. If identity equivalence has not been established, take
that conservative path rather than assume the change was attribute-only.

### Withdraw One or All

`withdraw ribout` uses the snapshot associated with advertisements on that peer
and session, not the latest configuration or registry entry. Its withdrawal
stream is derived from that snapshot in Prepare.

`withdraw all peer` expands into one ordinary withdraw job per binding, queued
behind the work already admitted; it cancels nothing, and each binding is
cleared when its job commits (the Peer TX row above). No BGP wildcard-withdraw
message exists.

Do not erase evidence of a partial advertisement on cancellation. Retain the
touched snapshot until cleanup can withdraw it; a whole-snapshot withdrawal
can conservatively cover a partly sent disjoint RIBOUT. Serialization must also
prevent a cancelled older job's cleanup from withdrawing a newer advertisement.

### Overlapping RIBOUTs

Snapshot references alone cannot make selective withdrawal correct when two
RIBOUTs advertise the same family-specific route key and Add-Path ID on one
session. Withdrawing one may remove the other's route.

The initial executor must validate and reject overlapping ownership, including
across queued replacements, or implement explicit route-key ownership before
supporting it. Validation may need a temporary build/admission index; do not
claim this is free. Arbitrary overlap support requires a defined winner and
restoration policy, with a per-peer ownership index or an equivalent mechanism.

## Scheduler and Write Ownership

Keep one peer-owned write scheduler in the existing libuv runtime. Today
`runtime_peer_queue_message()` allocates and copies each payload. Keep that
small-control-message facility where useful, but do not fan out bulk UPDATEs
through a per-message, per-peer copy queue.

1. Queue one bounded job per operation, not one node per UPDATE.
2. Place eligible peers on a fair ready queue with per-turn byte budgets.
3. Build one bounded scatter/gather batch from complete messages in shared arenas.
4. Permit at most one in-flight batch per peer; wait for its callback before reuse.
5. Advance message/byte progress only on successful local write completion.
6. Resume scheduling after callbacks; do not poll or busy-spin blocked sockets.

Control writes and UPDATE batches share the same serialization owner. Give
NOTIFICATION and keepalives priority at batch boundaries; OPEN follows session
establishment rules, not the established-only UPDATE gate. A fatal notification
stops further UPDATE scheduling and uses the central notification/reset path.
Never truncate or interleave bytes inside a BGP message. Batch byte/descriptor
limits bound control latency and must be benchmarked, not guessed from message
count alone.

The event loop owns peer state, job queues, publication, reference counts, and
run observations. Workers only build private products from frozen inputs.
No worker touches a socket, live peer binding, or mutable configuration.

### Failure, Reset, and Lifetime

A registry slot, binding, queued job, and in-flight batch each retain the
snapshot they need. A derived withdrawal stream is retained the same way by
the withdraw jobs and batches that use it. Replacement drops only the
registry's reference. Cancel and reset release unsent work, but submitted
buffers remain pinned until the write callback returns, including
error/cancellation callbacks.

Callbacks carry session epoch and operation identity. An old completion may
release its own resources, but cannot advance a new session's cursor, clear its
active batch, or mark another run successful. Peer lifetime must extend through
these callbacks or use a stable runtime-owned indirection.

A write failure may follow partial delivery. Mark the operation failed and
use the central peer reset path rather than guessing receiver state. Session
reset invalidates local bindings; receiver graceful-restart retention is a
separate protocol concern and is not proof of immediate route removal. Initial
recovery should fail the interrupted run, not silently replay it on a new
session. Any future automatic replay needs an explicit policy.

## Resource Bounds and Cost

Cap queued jobs per peer, outstanding bytes, concurrent builds, and total live
snapshot memory. Account for retired generations pinned by slow peers. Refuse
or backpressure new work before allocating beyond those budgets; never let a
slow receiver force unlimited historical snapshot retention. Multi-peer queue
admission needs rollback of reservations before any transmission if a required
peer cannot be admitted.

```text
memory ~= shared live snapshots for distinct wire profiles
        + withdrawal streams of pending withdraw jobs
        + bounded temporary maps and frozen build inputs
        + per-peer bindings, job cursors, and one batch
        + kernel socket buffers
```

A temporary map is the peak term today: 2.9-8.3 times its advertisement
stream at realistic packing ([Measured Costs](#measured-costs)).

Encoding cost is paid per snapshot/profile, not per peer. Transmission still
costs per-peer bytes and callbacks. Scatter/gather removes application-level
fanout copies; it is not a claim of kernel zero-copy. Cumulative message offsets
would make progress accounting constant-time; today the cursor walks the
message list.

## Measured Costs

Measured with a temporary probe built on `tests/bench_ribout_pipeline.c`
(Intel Xeon Gold 5318Y, `-O2`, one thread, mean of three runs). Each family
has about one million NLRI: 1.00M for unicast, labeled-unicast, VPN, and EVPN
Type 5, and 1.05M for EVPN Type 2, SR Policy, and FlowSpec. `localpref
range(...)` sets the attribute-group count so that each advertisement UPDATE
carries 5-10 NLRI, a realistic packing for attribute-diverse tables. The
attributes are a four-AS path plus the usual attributes of the family: RT and
SoO, EVPN encapsulation and Router's MAC, SR segment lists, FlowSpec actions.
Add-Path is off.

Memory is the heap held by a stream stored as a `bgp_msg_t` list, as
advertisement streams are stored today: message buffers, list nodes, and
allocator headers. "From map" encodes withdrawals with the family chunk
encoders on the warm map right after generation. "From UPDATEs" derives them
from the advertisement bytes after a 512 MB cache flush, as a later withdraw
would. "From config" is the map build plus "from map". Both derivations
produced byte-identical withdrawal streams for every family.

| Family | NLRI per UPDATE | Advertisement stream | Withdrawal stream | Withdrawal / advertisement | From map | From UPDATEs | From config |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| IPv4 unicast | 10 | 15.3 MB | 3.9 MB | 25% | 19 ms | 7 ms | 279 ms |
| IPv6 unicast | 8 | 24.8 MB | 8.8 MB | 35% | 20 ms | 8 ms | 264 ms |
| IPv4 labeled-unicast | 8 | 21.0 MB | 6.8 MB | 32% | 26 ms | 13 ms | 277 ms |
| IPv6 labeled-unicast | 6 | 30.5 MB | 11.6 MB | 38% | 30 ms | 14 ms | 281 ms |
| VPNv4 | 7 | 34.9 MB | 14.6 MB | 42% | 28 ms | 15 ms | 372 ms |
| VPNv6 | 5 | 48.8 MB | 19.5 MB | 40% | 35 ms | 16 ms | 326 ms |
| EVPN Type 5 IPv4 | 8 | 51.5 MB | 35.0 MB | 68% | 38 ms | 13 ms | 386 ms |
| EVPN Type 5 IPv6 | 6 | 78.8 MB | 58.3 MB | 74% | 61 ms | 20 ms | 445 ms |
| EVPN Type 2 | 10 | 48.0 MB | 35.7 MB | 74% | 33 ms | 14 ms | 406 ms |
| SR Policy IPv4 | 5 | 51.2 MB | 13.2 MB | 26% | 27 ms | 12 ms | 312 ms |
| SR Policy IPv6 | 5 | 73.6 MB | 25.5 MB | 35% | 29 ms | 15 ms | 334 ms |
| IPv4 FlowSpec | 8 | 28.0 MB | 13.2 MB | 47% | 127 ms | 9 ms | 445 ms |
| IPv6 FlowSpec | 6 | 40.0 MB | 19.4 MB | 48% | 140 ms | 11 ms | 504 ms |
| IPv4 FlowSpec VPN | 7 | 38.9 MB | 21.4 MB | 55% | 135 ms | 11 ms | 488 ms |
| IPv6 FlowSpec VPN | 5 | 51.2 MB | 27.5 MB | 54% | 148 ms | 13 ms | 520 ms |

Findings:

- Deriving withdrawals from UPDATE bytes takes 7-20 ms per million NLRI. It
  is faster than encoding them from the map in every family: about 2-3 times
  for most families and 12-15 times for FlowSpec, whose map encoder
  materializes every rule.
- Withdrawal UPDATEs are full 4096-octet messages regardless of attribute
  groups: 1k-15k withdrawal UPDATEs against 100k-210k advertisement UPDATEs.
- Keeping withdrawal streams from generation would hold 25-74% of each
  advertisement stream, 314 MB across these fifteen cases beside 637 MB of
  advertisement streams, for no speed gain. The share is highest for EVPN,
  where the NLRI is most of each UPDATE.
- Rebuilding withdrawals from configuration costs 264-520 ms, dominated by the
  map build.
- `update generate` (map build plus advertisement encode) costs 280-571 ms per
  family here, of which the map build is 244-384 ms. The 1M-path benchmark
  cases in [testing.md](../testing.md) (100 and 1,000 groups) build maps 3-4
  times faster: grouping cost grows with the group count.
- The map peaks at 127-268 MB per million NLRI, 2.9-8.3 times its
  advertisement stream. The first NLRI chunk of an entry holds one record and
  later chunks hold about 1 KB (`BGP_RIBOUT_NLRI_CHUNK_TARGET_SIZE`), so a
  group of 5-10 NLRI leaves most of its second chunk empty. Growing chunk
  capacity gradually would cut peak generation memory, independently of TX.
- Retaining the map in place of wire bytes would cost more memory, and
  encoding from it on every send would cost 31-200 ms per million NLRI per
  peer (the advertisement encode times here), where shared bytes cost only
  the socket writes.

With Add-Path, Path IDs add four octets per NLRI to both streams. EVPN
withdrawals kept the advertised label and ESI bytes, which are outside the
EVPN route key.

## Implementation and Verification Sequence

1. Add immutable advertisement snapshot ownership around existing encoders and
   the on-demand withdrawal derivation. Check derived withdrawals byte for byte
   against withdrawals encoded from the map, for all supported families and
   negotiated Add-Path variants, and add the realistic-packing cases above to
   `bench_ribout_pipeline`.
2. Test executor admission, bindings, FIFO ordering, partial cancellation,
   withdraw-all barriers, overlap rejection, and revision checks using fake writes.
3. Connect bounded batches to the existing runtime; test slow readers, disconnects,
   notification priority, resets, stale callbacks, and snapshot reclamation.
4. Drive the existing run observation API from real callbacks and nonblocking
   timers; keep prepare, queue, and TX timing distinct.
5. Verify receiver RIB state and actual withdrawals with FRR or another independent
   peer; benchmark multi-peer CPU, peak memory, throughput, and loop responsiveness.

Status: steps 1-4 are done, with two gaps. `test_ribout_withdrawal` checks the
derived withdrawals key for key against the advertisements for every family,
plus the literal template vectors in `tests/test_nlri_templates.h`, not byte
for byte against map encoding; and the realistic-packing cases above are not
in `bench_ribout_pipeline`, which reports the derivation time per case
(`wdr(ms)`). `test_peer_tx` covers admission, FIFO order, overlap,
withdraw-all, partial progress, reset and refresh merging with fake writes.
`test_runtime_tx` checks the bytes on real sockets against independently
decoded keys, slow readers, NOTIFICATION placement, resets, End-of-RIB,
ROUTE-REFRESH and script runs.
Step 5 is open: no test runs against an independent receiver, and
`bench_scale` measures only bgpsim's own sessions and RSS, not multi-peer
CPU, throughput, or loop responsiveness. Those environment-dependent
workloads stay separate from `all-test`.
