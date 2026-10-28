# BGP FSM Implementation

This document describes the current BGP finite state machine, timer ownership,
and OPEN-message handling in `bgpsim`.

## Scope

`bgpsim` is an outbound/testing-focused simulator. Its FSM is intended to make
the outbound side of the session look real enough for peering and protocol
testing.

It is not a full inbound routing stack.

The current FSM is event-driven. Live peer sockets, passive listeners, and FSM
timers are owned by the libuv runtime in `src/runtime.c`. `src/bgp_neighbor.c`
and `src/bgp_router.c` are now primarily config/model management helpers rather
than the hot runtime path.

At runtime:

- one dedicated `uv_loop_t` owns all live peer state
- each neighbor has loop-owned timers for reconnect, connect timeout, OPEN
  timeout, hold time, and keepalive
- active connects and passive accepts both feed the same per-neighbor FSM
- control sessions and `terminal monitor` events share that same runtime thread

## Session States

The peer FSM defines the usual session-establishment states:

- `Idle`
- `Connect`
- `Active`
- `OpenSent`
- `OpenConfirm`
- `Established`

In current code, the hot paths are mostly:

- `Idle`
- `Connect`
- `OpenSent`
- `OpenConfirm`
- `Established`

`Active` exists in the state enum, but it is not a significant runtime path
today.

The practical transitions are:

- active peering:
  `Idle -> Connect -> OpenSent -> OpenConfirm -> Established`
- passive peering:
  `Idle -> OpenSent -> OpenConfirm -> Established`
- reset / clear / timer expiry:
  `... -> Idle`, usually followed by a scheduled reconnect for active peers

Passive mode only exists when `--passive` is enabled. Otherwise the runtime stays
in active-connect mode only.

Router slot `i` listens on `BGPSIM_LISTEN_BASE_PORT + i` (default base 20000).
Allocation rejects exhausted or duplicate listener ports instead of wrapping the port number.
When that port cannot be bound, for example because another process holds it or
an outgoing connection uses it as its local port (a port in the kernel's ephemeral
range can be taken that way at any moment, and stays taken for a minute in
TIME_WAIT), the router keeps no listener but is not given up on:

- the log says why, once per new error:
  `BGP router 65080 cannot listen on port 39400: address already in use; retrying`
- `show bgp summary` shows it under the router:
  `Listener on port 39400 is not open (address already in use), retrying`
- the runtime tries again after 100 ms, doubling up to every 5 s, and logs
  `BGP router 65080 listening on port 39400` once it opens.

## Runtime Ownership

The runtime now has one authoritative live owner:

- `bgpsim_runtime_t` owns the `uv_loop_t`
- `bgp_neighbor_t` stores the per-peer live handles and counters
- `bgp_router_t` stores the passive listener handle when passive mode is enabled

There is no separate peer thread and no separate listener thread anymore.

This matters because socket I/O, timer callbacks, and state transitions all run
on one loop thread instead of crossing peer-local locks.

## Timers

Each neighbor carries these loop-owned timers:

- reconnect timer
- connect timeout timer
- OPEN timeout timer
- hold timer
- keepalive timer

The runtime uses them for:

- active retry pacing
- outbound connect timeout
- OPEN/KEEPALIVE progress
- hold-time expiry in `Established`

## OPEN Handling

The OPEN layer in `src/bgp.c` is real, not stubbed. Runtime orchestration lives
in `src/runtime.c`, while the encode/parse helpers live in `src/bgp.c`.

Current handling covers:

- base BGP OPEN encoding and parsing
- MP-BGP capability advertisement and parsing
- route-refresh
- graceful-restart
- add-path
- extended next-hop
- outbound 4-byte-AS capability advertisement

For the exact family matrix and the current neighbor CLI surface, see
[address-families.md](address-families.md).

## Intentional Asymmetry

The receive side is intentionally thinner than the outbound feature surface.

That means:

- UPDATE snapshots are encoded once from the ribout configuration, not per
  session; a session whose negotiated capabilities cannot parse a snapshot
  has it withheld, with the reason in `show bgp neighbors`
- the simulator prioritizes outbound protocol shape over full routing behavior

## Established State

In `Established`, the current implementation supports:

- periodic keepalives
- outbound UPDATEs from ribout snapshots: standing advertisements, exec
  commands and script runs, End-of-RIB after the initial update, and replays
  for ROUTE-REFRESH (see "Sending UPDATEs" in [configuration.md](configuration.md#sending-updates))
- received message counters
- thin inbound UPDATE handling
- hold-timer refresh on received traffic
- `%BGP-5-ADJCHANGE` style runtime events for `terminal monitor`

The simulator does not implement:

- RIB-IN
- best-path selection
- policy application

## NOTIFICATION Reasons

Every NOTIFICATION received or sent is reported with its error code and
subcode, by number and by registry name. A Cease with Administrative Shutdown
or Administrative Reset also shows its RFC 9003 Shutdown Communication, and
other data shows its length. The report is a `%BGP-3-NOTIFICATION` event line,
written to the log and shown to `terminal monitor` sessions:

```text
%BGP-3-NOTIFICATION: received from neighbor 10.1.0.2 6/5 (Cease/Connection Rejected)
%BGP-3-NOTIFICATION: sent to neighbor 10.1.0.2 1/3 (Message Header Error/Bad Message Type), data length 1
```

`show bgp neighbors` keeps the last one in each direction:

```text
  Last notification sent: 4/0 (Hold Timer Expired/Unspecific), 02:15 ago
  Last notification received: 6/2 (Cease/Administrative Shutdown), shutdown communication "maintenance", 00:03 ago
```

## Testing

Relevant tests:

- `$BUILD_DIR/test_bgp_open`
- `tests/test_shell_smoke.py`
- `tests/test_peer_stress.py`

`tests/suites.json` defines the suite inventory. Both broad targets use
`tests/run_tests.py`. See [testing.md](testing.md) for selection and results.

Broad runs:

```bash
set -o pipefail
make unit-test 2>&1 | tee /tmp/bgpsim-fsm-unit-test.log
make all-test 2>&1 | tee /tmp/bgpsim-fsm-all-test.log
```

## Practical Summary

For protocol testing, the FSM and OPEN layer are good for:

- real session establishment
- capability exchange
- outbound UPDATE generation experiments
- active peering and optional passive peering on one event loop

They are not intended to emulate a full router control plane.
