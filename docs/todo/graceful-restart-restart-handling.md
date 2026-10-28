# Graceful Restart: Restart Handling

Date: 2026-11-06

Two RFC 4724 gaps remain after the 2026-11-06 Graceful Restart review.
Both concern a session across a restart. The rest of bgpsim's Graceful Restart behavior matches RFC 4724 and
RFC 8538.

## 1. Restart State bit after a bgpsim restart

RFC 4724 section 4.1 requires a Restarting Speaker to set the Restart State (R) bit in the OPEN that re-establishes
the session.

bgpsim never sets R. It keeps no state across process restarts, so it cannot tell a restart from a first start.
Its Graceful Restart capability lists every enabled family, so a peer keeps bgpsim's routes as stale after an
unexpected exit. bgpsim sends End-of-RIB after its initial update, and the stale routes are then cleared. What the
missing R bit loses is its deadlock protection: a peer that restarted at the same time can wait for bgpsim's
End-of-RIB before it advertises to bgpsim.

Design first: decide how bgpsim learns that it restarted, for example an explicit configuration or CLI setting.

Acceptance:

- After a restart, the first OPEN to each peer has R set. After a first start, R is clear.
- A check pins both cases. Write it together with the mechanism.

## 2. Passive-mode handover (RFC 4724 section 4.2)

When a peer that advertised Graceful Restart opens a new connection while bgpsim still has the old session, bgpsim
MUST close the old TCP session without a NOTIFICATION and keep the new one.

Today `runtime_listener_on_connection()` in `src/runtime.c` drops any inbound connection while the neighbor has an
open stream. The old session lingers until its hold timer expires: 180 seconds by default, longer than the default
120-second restart time.

The gap applies only with `--passive`, and only when bgpsim did not see the old TCP session end. A normal restart of
the peer's BGP process closes its socket, bgpsim reads EOF, and the reconnect is accepted.

`test_session_gr_peer_reconnect()` in `tests/test_bgp_open.c` is a strict expected failure (`test_xfail()`). It
reports `xfail` while the new connection is refused and the old session stays Established. It fails once the product
replaces the session (an unexpected pass), or if the product fails in any other way.

Acceptance:

- That check becomes a regular check and passes: the old connection ends with EOF and no NOTIFICATION, and the new
  connection receives bgpsim's OPEN and reaches Established.
- A peer that did not advertise Graceful Restart keeps the existing RFC 4271 behavior.

## Checked And Not Gaps

These were examined on 2026-11-06. They are recorded so that they are not investigated again.

- bgpsim's Graceful Restart capability lists every enabled family, with the Forwarding State bit clear. RFC 4724
  allows this. There is no setting for the form with no families, which only supports peers that restart.
- bgpsim sends End-of-RIB after a refresh replay when both sides negotiated Graceful Restart. No RFC forbids it.
  `test_route_refresh()` and `test_route_refresh_eor_with_gr()` in `tests/test_runtime_tx.c` pin both cases.
