# Testing Guide

[`tests/suites.json`](../tests/suites.json) is the authoritative test inventory:
it defines suite names, commands, profiles, platform restrictions, timeouts,
wall-time budgets, and background scheduling. This guide explains how to run
those suites and what their scenarios exercise, rather than duplicating the
inventory.

## Build And Run

Run commands from the repository root. The default build directory is
`/tmp/bgpsim`; set `BUILD_DIR` to use another directory. Capture build and test
output with `tee` and enable Bash `pipefail` so a failing command is not hidden
by a successful logger:

```bash
export BUILD_DIR="${BUILD_DIR:-/tmp/bgpsim}"
set -o pipefail
make 2>&1 | tee /tmp/bgpsim-build.log
```

For an optimized build:

```bash
set -o pipefail
make RELEASE=1 2>&1 | tee /tmp/bgpsim-release-build.log
```

The product Makefile loads `tests/Makefile` only for explicit test targets.
Test rules build their prerequisites and use the same `tests/run_tests.py`
runner:

| Target | Runner Profile | Scope |
| --- | --- | --- |
| `make unit-test` | `unit` | In-memory encoders, decoders, generators, models, and local parser/CLI checks |
| `make all-test` | `all` | Unit suites plus live socket/peering, Python API, smoke, stress, harness, and performance gates |
| `make bench` | None | Encoder and ribout measurements, separate from correctness results |

```bash
set -o pipefail
make unit-test 2>&1 | tee /tmp/bgpsim-unit-test.log
make all-test 2>&1 | tee /tmp/bgpsim-all-test.log
```

List a profile without executing tests:

```bash
set -o pipefail
python3 tests/run_tests.py --list all 2>&1 | tee /tmp/bgpsim-suite-list.log
```

For a focused protocol/ribout slice, select manifest suite names with repeated
`--suite` arguments. The direct runner does not build missing binaries; build
the selected targets first or use the Make targets above:

```bash
set -o pipefail
make "$BUILD_DIR/test_bgp_open" "$BUILD_DIR/test_bgp_update_flowspec" \
  "$BUILD_DIR/test_ribout_update_generation" 2>&1 | tee /tmp/bgpsim-focused-build.log
python3 tests/run_tests.py --profile unit --build-dir "$BUILD_DIR" \
  --suite test_bgp_open --suite test_bgp_update_flowspec \
  --suite test_ribout_update_generation 2>&1 | tee /tmp/bgpsim-focused-test.log
```

Use the same selection mechanism for the generator, constraints, map, CLI
round-trip, snapshot, withdrawal, or runtime suites described below. Running a
binary directly is useful for debugging, but bypasses runner timeouts, budget
policy, and stored summaries.

Live BGP sessions, socket error tests, and runtime/control-socket fixtures belong
to `all`, not the packaging unit gate. Mixed OPEN and CLI binaries expose
`--unit` and `--sessions` selections in the manifest, so in-memory protocol
coverage stays in `unit` and `all` executes both selections without duplication.

The Python API suite runs under `all-test`. It tests framed protocol errors,
readiness and operation deadlines, checked command status, configuration context,
and script run identity/failure/timeout handling. Python parses JSON emitted by
the real executable, checks phase timings, and independently decodes advertised
and withdrawn NLRI on a loopback BGP session. It uses only the standard library
and built binaries; no device under test, external service, or Python test package
is needed.

## Typed NLRI And Encoder Checks

`test_nlri_templates.h` owns 28 literal RFC-layout vectors shared by pipeline
and socket tests: RTC/default, VPLS, EVPN Types 1/3/4 with both router AFs,
all seven MVPN types for each AF (including both Leaf A-D Route Key forms),
and four BGP-LS NLRI shapes. Expected bytes are hand-assembled, not generated
with product codecs.

`test_ribout_update_generation` checks each shape with and without ADD-PATH,
scales identities across message boundaries, checks immutable withdrawal
snapshots, rejects invalid grammar/ranges, and inspects family attributes.
Under `all-test`, `test_runtime_tx` negotiates real loopback BGP sessions and checks exact
advertisement/withdraw-all bytes and session continuity. Separate peer-owner
checks reject overlapping template keys while allowing disjoint blocks.
`test_ribout_keyspace` compares semantic range checks against independently
decoded wire identities. CLI suites check configuration round-trips and
detail/preview output.

Codec suites cover malformed addresses, length/label bounds, ADD-PATH error
propagation, RTC partial-byte masking, PMSI overflow, oversized BGP-LS
payloads, and UPDATE/MP-attribute length overflow. These are local wire and
memory-safety checks, not a claim that every new family is accepted by every
receiver version.

## Scale And Ownership

Routers, peers and ribouts are individually allocated. Their registries grow
as pointer tables, so moving a registry does not invalidate libuv handles,
callback data or a selected ribout. Deleted router/peer slots are reusable
only after their close callbacks finish. Simulator shutdown releases the
retained slot storage.

Ribout attribute inventories own their storage. One inventory schema drives
clone, release, configuration transfer and retained-memory accounting.
Scalar/RD sequences store a base/count/step; RT and community sets store
compact groups. Explicit inventories use growable vectors. Immutable
snapshots deep-copy configuration; edits do not create wire generations.
Rotator/multiplier ordering and repeated-route semantics are unchanged.

Per-peer standing advertisements, bindings and job rings also grow on demand.
TX plans reserve replacement tables without mutating live queues, then commit
without allocating after every selected peer accepts. In-flight writes pin
their message stream independently of queue storage. Admission budgets are
documented in [configuration.md](configuration.md#write-path-and-show-output).
They are retained-reference limits, not process-wide RSS limits.

Scale correctness checks cover stable addresses during registry growth,
500 routers, 1,000 peers per router, 500 ribouts, 640 standing exports,
wrapped/growing job rings with an outstanding write, exact admission limits,
allocation failures and rollback, and million-value compact inventories.
Live socket tests exercise exec and script selection across 1,501 configured
peers and compare exact advertisement/withdrawal keys on the original socket.
The script model separately completes observations for 10,240 peers.
Keyspace tests compare every IPv6 mask interval against a per-bit oracle and
compare sequence overlap/equality against independently decoded wire keys.
ASan/UBSan runs retain leak detection; fixture cleanup is part of ownership
verification, not suppressed sanitizer output.

### Benchmarks

`make bench` includes `bench_scale` alongside the encoder and ribout-pipeline
benchmarks. Its default sweep measures 1x and 10x counts in fresh child
processes, isolating peak RSS per workload. It asserts actual created/found
counts, drained jobs, and exact received route bytes; reporting a requested
count alone is not success. Focused runs are available after `make bench-build`:

```bash
set -o pipefail
"$BUILD_DIR/bench_scale" model 50 1000 2>&1 | tee /tmp/bgpsim-scale-model.log
"$BUILD_DIR/bench_scale" exports 640 2>&1 | tee /tmp/bgpsim-scale-exports.log
"$BUILD_DIR/bench_scale" sessions 1000 2>&1 | tee /tmp/bgpsim-scale-sessions.log
"$BUILD_DIR/bench_scale" attributes 10 2>&1 | tee /tmp/bgpsim-scale-attributes.log
```

Representative x86-64 Xeon Gold 5318Y, GCC `-O2` measurements:

| Workload | 1x | 10x |
| --- | --- | --- |
| Routers without peers | 50: create 0.2 ms | 500: create 1.8 ms |
| Configured peers on 50 routers | 5,000: create 21.6 ms, lookup 2.1 ms, peak RSS 13.0 MiB | 50,000: create 277.4 ms, lookup 78.3 ms, peak RSS 113.5 MiB |
| Ribouts/bindings/queued advertisements | 64: generate 0.5 ms, admit/drain 0.2 ms, peak RSS 2.6 MiB | 640: generate 5.2 ms, admit/drain 16.2 ms, peak RSS 10.5 MiB |
| Actual loopback BGP sessions | 100: establish 164 ms, advertise/receive 39.8 ms, withdraw/receive 0.7 ms | 1,000: establish 1,286 ms, advertise/receive 42.2 ms, withdraw/receive 7.4 ms |
| Attribute inventories | 256 RDs, 100 labels, 2,048 Colors, 256 RT sets, 64 community/large-community groups and SR lists: edit 0.5 ms | 2,560 RDs, 1,000 labels, 20,480 Colors, 2,560 RT sets, 640 groups/lists: edit 28.8 ms |

Attribute measurements generate the VPN workload; the large SR-list inventory
is configuration/clone coverage, not a claim that all lists fit in one UPDATE.
Session measurements use one route per peer and include loopback TCP behavior;
the roughly 40 ms advertisement time is not a throughput estimate. Configured
peers are not established sessions. These are single-run observations on a
shared host, not supported maxima or statistically controlled performance gates.
The empty configuration structure is 5,704 bytes; the paired 10x VPN/policy
configurations occupy 1,221,056 bytes, including owned inventory capacities.

Profiling the initial growable implementation identified per-bit keyspace
masking and oversized configuration copies. Byte masks and compact owned
inventories reduced its 640-export sample from 101.6 ms generation / 216 MiB
peak RSS to 5.2 ms / 10.5 MiB. That comparison is within the scale refactor;
the fixed-cap implementation cannot execute the 640-export workload.

Remaining limits are intentional or operational: file descriptors and socket
buffers for live sessions; checked 16-bit listener ports (`base + router slot`);
per-route AS-path/community/SR segment bounds; command sizes; wire message
limits; and configured TX budgets. Peer lookup/free-slot scans, many-binding
overlap/admission checks and script duplicate-peer validation remain linear
or quadratic across repeated operations. Incremental attribute edits deep-copy
existing inventories. Synchronous generation still occupies the event loop.
Indexing, bulk edits and asynchronous generation are separate optimizations,
not implied by removing fixed arrays.

## Runner And Results

`tests/run_tests.py` supplies common selection, bounded execution, result
collection, and reporting for `unit` and `all`. Suites marked
`background` in the manifest use one background lane; the remaining suites run
serially. Peer stress can therefore overlap the serial suites without making
all listener/control tests concurrent.

### Logs

By default each run creates:

```text
$BUILD_DIR/<profile>-test-logs/<run-id>/
  manifest.json
  <group>/<suite>.log
  <group>/<suite>.results.jsonl
  <profile>-test.log
  summary.json
  summary.txt
  exit-code
$BUILD_DIR/<profile>-test-logs/latest -> <run-id>/
```

`manifest.json` records the selected suites; each suite has its own raw log
and structured results. The aggregate log retains suite output, and the
summaries include outcomes, durations, budget verdicts, and log paths. For a
chosen output directory use `--run-dir`; `make all-test` also accepts
`ALL_TEST_RUN_DIR`. An explicit run directory does not update `latest`.

### Cases And Checks

Result records have a suite-scoped stable `id`, descriptive `name`, `kind`
(`case` or `check`), and `pass`, `fail`, or `skip` status. IDs derive from the
suite, result kind, semantic key, and occurrence of that key, not from log
line numbers. Keep keys stable when extending a scenario.

A case is an explicitly reported scenario, such as a C `TEST()` case or a
Python unittest method. A check is an assertion or evidence gate reported by
`test_result()` or the Python result helpers. Plain pass/fail badges are
imported as checks, not promoted to independently runnable cases. Structured
records and their paired human-readable badges are counted only once;
summary banners and embedded badges are not additional results.

`summary.json` and `summary.txt` distinguish case and check totals. Their
pass/fail/skip counts are reported result records, not a count of unique
behaviors, assertions within every case, or correctness coverage. Benchmark
rows do not contribute to these totals.

Missing result evidence, malformed records, unsuccessful suite exits, and
timeouts fail the run even if earlier checks passed. Exit 77 denotes an
unavailable optional suite, not a successful test; reporting success and then
exiting 77 is invalid. Platform-restricted suites are selected only on their
supported platform. The default suite timeout is 120 seconds unless overridden
by the manifest; `--timeout` or `TEST_TIMEOUT_SECONDS` overrides that limit.
Timeouts and cancellation terminate the suite's process group.

### Timing Policy

Suite `budget_ms` and whole-profile `profile_budgets_ms` live in the manifest.
A profile budget applies only to its complete selection, not a focused slice.
`tests/test_timing.py` shares measurement parsing and CPU-pressure policy
between the runner and workload gates.

An over-budget wall time fails only when CPU pressure was measurable and
CPU wait was below 10%. With greater pressure or no counter, it is a warning,
not evidence of a timing pass. The counter comes from
`/sys/fs/cgroup/cpu.pressure`, falling back to `/proc/pressure/cpu`. Suite
summaries retain the duration, budget, CPU wait, and verdict. The hard suite
timeout still applies under load.

`tests/ribout_performance.py` is the quick generation performance gate in
`all`. Its generation CPU-time limits always apply; elapsed-time limits use
the same pressure-aware policy. Measurements come from `show ribout`
(`Generation CPU:` and `Generation Time:`). Missing, malformed, or nonfinite
measurements and unsuccessful generator exits fail closed. Do not mix these
timing checks with benchmark throughput rows or claim they verify protocol
correctness.

## Shared Test Infrastructure

### C Fixtures And Evidence

- `tests/test_result.h` owns pass/fail counters and structured result emission;
  `test_result()` reports a check. `tests/test_case.h` supplies
  `TEST()` / `PASS()` / `FAIL()` / `ASSERT()` for case-level reporting.
- `tests/test_helpers.h` supplies config helpers, `test_capture_output()`
  for stdout/stderr capture without a pipe-size limit, and the next-hop and
  attribute builders the encoder suites share.
- `tests/test_wire.h` is the shared independent UPDATE/attribute/NLRI reader.
  Protocol tests keep family-specific assertions but reuse this reader rather
  than copying walkers or treating the production encoder as their oracle.
- `tests/test_runtime.h` shares simulator creation, runtime startup,
  state-based listener/finalization waits, and teardown. `tests/test_session.h`
  adds raw-peer sessions, framed BGP reads, and ordering barriers for live TX
  scenarios.

### Python Ownership And Evidence

`test_common.ProcessFixture` in `tests/test_common.py` is the process/session
owner for Python tests: use it for launch, readiness, shutdown, escalation,
and artifact cleanup. Cleanup must be limited to processes and artifacts the
fixture created; an occupied port or an unowned session socket is not
permission to kill or replace its owner. Smoke, peer-stress, and generation
performance scenarios are Python suites (`test_shell_smoke.py`,
`test_peer_stress.py`, and `ribout_performance.py`).

`tests/bgp_wire.py` is the shared independent BGP framing and NLRI/key reader.
`tests/bgp_capture.py` adapts live pcap/TCP evidence to it. Keep capture parsing
and TCP stream handling in that adapter and BGP decoding in the shared module. These readers
do not import production encoders or simulator models as an oracle.

### Waiting And Ports

Wait for observable state instead of sleeping a fixed time and asserting.
Check immediately, then back off until a deadline: a loaded machine needs a
generous failure deadline, not an unconditional pause on every successful run.
Use `tests/test_wait.h` (`wait_until()`, `wait_backoff()`) in C and
`tests/test_common.py` (`wait_until()`) in Python.

Check "nothing happened" after an event that orders after the operation:

- From the peer, `peer_barrier()` in `tests/test_session.h` sends a KEEPALIVE
  and waits until bgpsim processes it. The session handles messages in order,
  so earlier input and its reactions precede the barrier.
- From bgpsim, `test_runtime_tx` waits for the UPDATE queue to become idle and
  reads exactly as many UPDATEs as `tx_update` reports. No transmission means
  an idle queue, an unchanged count, and no UPDATE in the socket.

The C peer reader (`recv_bgp_message_with_timeout()`) drains available kernel
bytes into its own buffer and returns complete messages from there. Peeking
until a complete message is available can deadlock: a partial segment can hold
the receive window at zero, preventing the rest from arriving.

For listener fixtures, use a free port band below the kernel's ephemeral range
(`/proc/sys/net/ipv4/ip_local_port_range`) so outgoing sockets do not take test
listener ports. Peer stress probes for such a band. Concurrent runs need
disjoint bands, not process killing.
The runner has group-specific port-base overrides (`UNIT_PORT_BASE`,
`CONTROL_PORT_BASE`, `PEER_STRESS_PORT_BASE`). Port probing does not reserve a
port against races; tests must check readiness and report bind failures. See
[`bgp-fsm.md`](bgp-fsm.md) for runtime listener retry behavior.

## Scenario And Coverage Guide

### Script/Run Models

`test_script_model` uses a fake monotonic clock and mock writes. It exercises
strict step/duration validation, frozen definitions, bounded storage, finite
and forever repeats, slow-peer completion, independent peer TX starts, exact
phase boundaries, stale/invalid callbacks, failure, and cancellation.
Deterministic schedules vary timing, iteration totals, peer completion order,
and definition removal. These are model checks; `test_runtime_tx` checks the
transmitted advertisements and withdrawals.

`test_script_cli` exercises shared CLI/config parsing, mode navigation,
running-config round trips, pending run creation, show output, mock progress,
stale sessions, and color/plain output. Neither suite needs a live peer or
starts the runtime. The standalone model target links only `script.o` and
`util.o` and can be built without libuv headers.

### UPDATE Encoding

The low-level encoder tests and `test_ribout_update_generation` cover different
layers; low-level support alone does not imply ribout support. Consult
[`address-families.md`](address-families.md) for the support matrix.

| Test Area | Scenarios |
| --- | --- |
| Base UPDATE | IPv4/IPv6 unicast, IPv4 NLRI over an IPv6 next hop, labeled-unicast, withdrawals, ADD-PATH, and message splits |
| VPN/EVPN | VPNv4/VPNv6, transport-specific next hops, EVPN Types 1-5, withdrawals, ADD-PATH, and splits |
| BGP-LS | MP_REACH/MP_UNREACH and descriptor/attribute wire layouts |
| SR Policy | IPv4/IPv6 NLRI and Tunnel Encapsulation encoding |
| FlowSpec | IPv4/IPv6 rules, including IPv6 prefix offsets |
| RTC/VPLS/MVPN | Family-specific NLRI, withdrawals, and MVPN Types 1-7 with PMSI Tunnel attributes |
| Ribout UPDATE generation | Config to stream to grouped map to UPDATEs, including preview/wire order |

Across these tests, retain checks for BGP headers, path attributes,
MP_REACH/MP_UNREACH, OPEN capability packing/parsing and RFC 9072 extended
optional parameters, RFC 8950 next hops, RFC 8277 labels, ADD-PATH, and
attribute preservation across message splits. Decode generated bytes with the
independent test readers rather than just comparing encoder return codes.

### Ribout Generation And Configuration

Generator, constraints, map, CLI, and UPDATE-generation suites exercise:

- Generated path-stream expansion, total-path math, multiple ribouts, and block
  independence.
- Validation and failure-atomic rejection: signs, trailing text, `x 0`, field
  overflow, invalid AS-path text, and valid boundary forms.
- Map insert/find/clear, attribute grouping, family inference, preview order,
  `show ribout`, and end-to-end UPDATE encoding.
- Community/large-community sets and `rotate` on key lists: decoded per-path
  values, `rotate-every` / `rotate-period`, limits, rejected lines, and
  running-config round trips judged by regenerated bytes.

`test_ribout_churn` starts from complex VPN, SR Policy, EVPN Type 2 dual-stack,
EVPN Type 5, FlowSpec, and unicast-with-path-ID configurations. Seeded edits
swap plain/rotating lists, change counts, append/clear/reorder lines, alter
rotation controls, and attempt invalid edits. Rejections must leave config
bytes unchanged; successful generation must send each path once and reload
to the same bytes. Reverting edits must reproduce the original UPDATEs,
keyspace, and a freshly built block. Use `CHURN_SEED` and `CHURN_ROUNDS` to
widen the workload; sanitizer or valgrind execution is separate evidence, not
implied by a normal suite result.

### Outbound TX

- `test_ribout_snapshot`: references across regeneration and `no ribout`, frozen
  config, moves, and family wire profiles (including IPv6 next hops/path IDs).
- `test_ribout_withdrawal`: hand-written withdrawals and End-of-RIB per family,
  with/without ADD-PATH, long FlowSpec NLRI and splits, generated advertised
  versus withdrawn keys in order, shared withdrawal caching, and malformed
  advertisements.
- `test_ribout_keyspace`: overlap/equality checked against decoded route keys,
  IPv6 FlowSpec prefix-offset wrap, and plain/rotating lists shifted by other
  dimensions or rotation controls. Whole-list comparison is conservative:
  disjoint emitted keys may still require the safe "overlap" answer.
- `test_tx_policy`: withholding rules in both directions, RFC 4760 IPv4
  unicast default, local Multiprotocol gating, and reason text.
- `test_peer_tx`: fake-write FIFO ordering and bindings, replacement versus
  withdraw/advertise, queued-work overlap, withdraw-all/replay, batching and
  partial progress, reset in flight, queue cap, refresh merging, and End-of-RIB
  ordering.
- `test_runtime_tx`: raw-peer bytes matching snapshots and keys; same/changed
  key regeneration; overlap rejection including IPv6 FlowSpec offsets;
  withheld reasons; `no ribout` then withdraw; slow readers and clear/removal
  with queued work; NOTIFICATION only between UPDATEs; negotiated End-of-RIB;
  reconnects; ROUTE-REFRESH replay with graceful restart; script order/timing,
  repeats, reset failure, cancel/shutdown, withheld/skipped peers, and errors
  without an established session or runtime.

### Input, Ownership, And Failure Paths

- Script/CLI tests check complete-command limits, shared ribout identifiers,
  failure-atomic edits (including FlowSpec), generation failure status, and
  preservation of the last successful UPDATE snapshot.
- Control tests check script context, oversized/NUL commands over real
  sockets, rejection recovery,
  fragmented/pipelined frames, complete multi-frame output, socket cleanup,
  and overlapping clients with independent contexts.
- PTY and Python smoke tests check oversized interactive/piped input and NUL
  input so a truncated prefix cannot execute. Neighbor-state tests check
  canonical IPv6 identity through creation, lookup, source changes, and removal.
- `test_wire_reader` checks literal vectors and malformed/truncated inputs for
  the shared C reader. Keep protocol-specific expectations in the family suites.
- On Linux, `test_allocation_failures` uses linker wrapping to fail ribout
  generation allocations and edit-copy allocations. Failure must preserve the
  previous config/wire snapshot and permit retry without changing the
  production allocator. Use an ASan/UBSan build to check allocation lifetimes.
- Control edge cases abandon large queued responses, require a second client
  to remain responsive with exact output, and check descriptor recovery on
  Linux. Sanitizer runs are needed for queued-write lifetime diagnostics.
- Harness/infrastructure tests supply broken peer evidence, absent/invalid
  measurements, failed subprocesses, and hangs. Hand-built wire evidence
  includes retransmitted/out-of-order segments, gaps, bad markers, cut files,
  NLRI variants, End-of-RIB-only refreshes, missing/wrong-session withdrawals,
  unsupported attribute evidence, and resets on either end. These must fail,
  not turn missing evidence into success.

An undersized-buffer API-contract case and shutdown `EXEC_DONE` delivery are
explicit skips, not verified coverage. Shutdown success-path coverage needs
response draining before it can be asserted reliably.

PTY suites require local pseudo-terminals; control suites use real Unix
sockets; network/error-path suites depend on socket permissions; smoke and
stress suites use real listeners and reconnects. A `unit` profile therefore
includes environment-sensitive C fixtures as well as pure protocol tests.

## Product Packaging Checks

`test_packaging.py` exports an allowlisted product archive, unpacks it without
`tests/`, and builds it with a failing Python executable on PATH. It checks
exact installation payloads and modes, independent executable/module targets,
prefix and staging overrides, interpreter-specific purelib selection, and
scoped uninstall. An isolated Python process imports the installed client and
changes live configuration in the installed executable; source-tree imports
and setup-seeded state cannot satisfy that check. See
[packaging.md](packaging.md) for the product boundary.

## Benchmarks

Benchmarks are measurements, not correctness suites. They run outside the
common test profiles and do not emit correctness case/check counts. The quick
`ribout_performance.py` gate remains in `all`; the full pipeline benchmark
does not.

```bash
set -o pipefail
make bench 2>&1 | tee /tmp/bgpsim-bench.log
make RELEASE=1 bench 2>&1 | tee /tmp/bgpsim-release-bench.log
```

The default debug build uses `-O0`; use an optimized build for throughput
comparisons and retain the command, build flags, host/load context, seed, and
raw output with each measurement.

`bench_update_generation` measures base-family encoder throughput: IPv4/IPv6,
labeled-unicast, VPNv4/VPNv6, IPv4 labeled-unicast over an IPv6 next hop, and
IPv4/IPv6/VPN FlowSpec (one rule per path). Dedicated protocol suites, not
benchmark rows, establish low-level family correctness.

`bench_ribout_pipeline` measures generated paths, map grouping, encoded
messages, retained map/message memory, and each case's incremental peak RSS
(`peak(+)`). Each case runs in its own child so allocator retention from
another case does not distort its peak. Withdrawal derivation from snapshot
bytes (`wdr(ms)`) is reported separately, outside the generation total.
It exercises families wired end to end through ribout, not low-level-only
encoders.

Workload shapes serve different purposes:

- `multi-attr`: controlled group diversity.
- `scale-attr`: high cardinality and UPDATE fanout, including seeded random
  EVPN Type 2 and SR Policy cases that approach one NLRI per group.
- `vrf`: million-route VPN tables across 100 VRFs using `rd rotate`, `rt-set`,
  and `label rotate`; block variants use `rotate-every`; dual-stack Type 2
  uses paired MAC/IP bindings; tagged variants add community sets per VRF.
- `tagged`: an Internet-table shape with 1,000 community/large-community
  groups over a million IPv4 prefixes.
- `rotate`: `rotate` on key lists, so SR Policy colors and FlowSpec ports
  turn with the rotation step instead of multiplying the routes.

SR Policy/SRv6 cases stress endpoint/service cardinality, ENLP, priority,
preference, Binding SIDs, bounded segment lists, and larger tunnel payloads.
SR-MPLS random Binding SIDs stay in the non-reserved label range. EVPN Type 2
cases vary MAC/IP cardinality, RD/Ethernet Tag, next hops/RTs, labels, and ESI.
These are static grouping/packing workloads, not MAC mobility, SID mutation,
or locator-wide withdraw/re-advertise tests; those need runtime/send scenarios.

FlowSpec workloads use rotating actions, color, and next hops for controlled
fragmentation: `multi-attr-fs4-*` / `multi-attr-fs6-*` rotate marks;
`scale-attr-fs4-srte-*` rotates redirect IP/color with ADD-PATH;
`scale-attr-fsv6-srte-*` combines VPN IPv6 offsets/flow labels with rotating
redirect next hops/color. The harness sets `RANDSEED=<u32>` per case for
reproducibility. The quick Python performance gate uses smaller static EVPN,
SRv6, random-fragmentation, and FlowSpec redirect-to-SR-TE workloads without
replacing the full benchmark.
