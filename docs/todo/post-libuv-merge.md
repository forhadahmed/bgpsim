# Post-Merge Follow-Ups

This note captures the best ideas worth carrying forward after the libuv merge.
It intentionally avoids referring to old worktrees or prototype branch names.

The goal is not to reopen the merge decision. The goal is to preserve the good
architectural intent that showed up elsewhere, while also collecting the
explicit follow-up items still visible in the current implementation.

## Priorities

Use this order:

1. fix correctness gaps at control-session and runtime-lifecycle boundaries
2. borrow ideas that improve runtime responsiveness without changing peer
   ownership rules
3. borrow ideas that improve module boundaries and maintainability
4. avoid protocol churn or peer-lifecycle rewrites unless a concrete bug forces
   it

## Immediate Correctness Follow-Ups

### 1. Final control responses must drain before close or shutdown

Some command paths can queue `EXEC_DONE` or `ERROR` and then immediately close
the control session or begin runtime shutdown. That risks giving the client EOF
instead of the final response.

#### Target outcome

Make session close and runtime shutdown follow one ordered path:

1. queue the final frame
2. drain the queued control writes
3. close the session only after the final write completes

#### Suggested implementation

1. Mark control sessions that are in "final frame pending close" state.
2. Teach the control write-completion path to own the final transition to
   session close.
3. Route runtime shutdown through the same drain-aware path for any session
   that still has a final response queued.
4. Keep forced shutdown as an explicit separate path for fatal process-exit
   cases only.

#### Tests to add

- `shutdown` returns a final response before the socket closes
- command errors return `ERROR` before EOF
- repeated attach/exec/disconnect cycles do not leak sessions in pending-close
  state

The `shutdown` case already exists in `tests/test_control_edge_cases.c` as a
`TEST_PRINT_SKIP` until this lands; [testing.md](../testing.md) records the skip.

## Higher-Priority Runtime / Control Ideas

### 2. Offload expensive read-only exec commands from the runtime thread

This is the highest-value architectural improvement still worth borrowing.

Today, control requests execute directly on the runtime thread. That keeps the
implementation simple, but it means large `show` paths can temporarily stall:

- peer FSM progress
- listener handling
- monitor event fanout
- other control sessions waiting behind the current command

#### Target outcome

Keep config-mutating commands serialized on the runtime thread, but allow
expensive read-only commands to run on libuv workers.

#### Suggested implementation

1. Add an internal exec-job struct in `src/runtime.c`.
2. Snapshot these fields when `EXEC_REQ` arrives:
   - command string
   - `cli_mode_t`
   - `cli_session_t`
   - any output-capture state needed by the worker
3. Add a small command classifier in `src/cli.c` or `src/commands.c` that can
   answer:
   - definitely read-only
   - definitely mutating
   - unknown, keep on runtime thread
4. Start conservative. Only offload obvious read-only exec commands first:
   - `show bgp ...`
   - `show log`
   - `show running-config`
   - other pure render / inspection commands
5. Keep these on the runtime thread for the first pass:
   - `config`
   - `clear bgp ...`
   - anything that changes mode or mutates simulator state
6. In the worker completion callback, send stdout/stderr chunks and the final
   `EXEC_DONE` frame back from the runtime thread.
7. Copy the returned mode/session state back into the live control session only
   after the command is complete.

#### File touches

- `src/runtime.c`
- `src/cli.c`
- `src/commands.c`
- possibly `src/control.h` if the framing helpers need a clearer split

#### Tests to add

- `terminal monitor` stays responsive during `show log all`
- repeated large `show` commands do not stall peer keepalives
- mode/session persistence is unchanged after offloaded commands
- multi-session control clients still behave deterministically

### 3. Make command mutability explicit instead of inferred ad hoc

Worker offload becomes much safer if command mutability is represented
explicitly.

#### Suggested implementation

1. Introduce a small command classification enum:
   - read-only
   - mutating
   - local-client-only
2. Start with a helper in the CLI / command layer instead of baking this into
   parser tables immediately.
3. Once the first worker-offload pass is stable, move that metadata closer to
   command definitions.

#### Why this matters

- it reduces accidental offloading of mutating commands
- it makes future background rendering work easier
- it keeps concurrency rules visible instead of implicit

### 4. If the client wrapper grows further, split the attached REPL out of `bgpsim.c`

The current interactive path is serviceable, but the client-side control flow
is now substantial enough to deserve its own unit if it keeps growing.

#### Suggested implementation

1. Extract the attached REPL and socket/stdin multiplexing helpers from
   `src/bgpsim.c` into `src/client.c` / `src/client.h`.
2. Keep the behavior the same:
   - same control protocol
   - same local prompt rendering
   - same monitor event printing
3. Treat this as a pure module-cut change first. Do not mix it with protocol or
   runtime behavior changes.

#### Why this is worth doing

- the process wrapper gets smaller
- interactive-client changes become easier to test and reason about
- control protocol code stops bleeding into process startup / daemon logic

## Lower-Risk Cleanup / Module-Cut Ideas

### 5. Introduce an explicit event module and keep monitor fanout behind it

One alternate implementation had the right instinct here: event formatting and
listener dispatch deserve their own small module.

#### Target outcome

Move `%BGP-5-ADJCHANGE` style emission behind a stable event API, instead of
letting runtime, logging, and control-session fanout stay tightly coupled.

#### Suggested implementation

1. Add `src/events.c` / `src/events.h`.
2. Give it a minimal API:
   - init
   - subscribe
   - unsubscribe
   - emit
3. Keep the event payload small:
   - severity
   - code
   - router AS
   - neighbor IP
   - formatted text
4. Register monitor/control fanout as one subscriber.
5. Register any foreground TTY-specific renderer as a separate subscriber.
6. Keep `terminal monitor` semantics unchanged. This is a module cleanup, not a
   feature expansion.

#### Why this is useful

- event formatting becomes testable in isolation
- monitor delivery stops being hardwired into one runtime path
- future non-control consumers can subscribe without touching peer FSM code

### 6. Make runtime thread join discipline explicit

`bgpsim_runtime_join()` should join any successfully created runtime thread
exactly once, even on early startup failure or fast exit. It should not infer
"thread exists" from a transient `running` flag.

Today `running` is set and cleared inside the thread (`src/runtime.c`), so a
thread whose `uv_loop_init()` fails, or that exits before the caller joins, is
never joined; `bgpsim_runtime_start()` takes that path on startup failure.

#### Suggested implementation

1. Track thread creation with an explicit `thread_started` or equivalent field.
2. Clear that field only after a successful join.
3. Keep startup failure, fast-exit, and normal shutdown paths all using the
   same join logic.
4. Preserve idempotence so repeated cleanup calls remain safe.

#### Tests to add

- startup failure after thread create still joins cleanly
- fast runtime exit does not leave a joinable thread behind
- repeated shutdown/cleanup calls remain harmless

### 7. Continue splitting `runtime.c` by responsibility, but only after behavior is stable

The current runtime file owns several different concerns:

- control session lifecycle
- control write queue
- peer FSM
- listener setup
- reconcile
- shutdown

That is workable today, but it is a maintenance drag. Peer TX batching already
moved to `src/bgp_peer_tx.c`; the rest is still in `src/runtime.c`.

#### Suggested implementation

Land this as a file-boundary cleanup in phases:

1. extract control-session framing / write-queue code
2. extract peer/listener runtime code
3. keep one thin runtime root for thread startup, reconcile entrypoints, and
   shutdown

Possible shape:

- `src/runtime.c`
  thread lifecycle, top-level reconcile/shutdown
- `src/control_server.c`
  accepted control sessions, frame queueing, exec dispatch
- `src/runtime_peer.c`
  peer FSM, reconnect, passive listeners

#### Rule

Do not mix this with peer-ownership or protocol changes. Keep it as a file move
plus small helper extraction.

### 8. Keep the Python client intentionally thin, but expose command status cleanly

The Python surface should remain a request/response control client, not a
second interactive frontend.

#### Suggested implementation

1. Keep `src/bgpsim.py` limited to:
   - connect
   - execute one CLI command
   - preserve session context across calls
   - disconnect
2. Done: `cli()` in `src/bgpsim.py` returns a `Reply` whose `ok` and
   `status` come from the `EXEC_DONE` status (`bgpsim_exec_done_t.status` in
   `src/control.h`), with the collected stdout/stderr text as its value.
3. If the control protocol changes, update these together in one patch:
   - `src/control.c`
   - `src/control.h`
   - `src/bgpsim.py`
4. Preserve the integration coverage in `tests/test_python_api.py` and
   `tests/test_multi_session.py` (default session, named session, reconnect
   after restart, multi-session isolation). The rejected-command cases in
   `tests/test_python_api.py` assert non-zero status propagation.

#### Why this matters

The Python client is most valuable when it stays boring and protocol-aligned.
It should not reimplement interactive help, completion, or monitor behavior.

## Things Not To Borrow Blindly

These ideas looked attractive in isolation but are not good default follow-ups
for the merged branch:

- simplifying the control protocol by removing version gating
- replacing queued control writes with best-effort `uv_try_write`
- rewriting peer/socket ownership without first reproducing a concrete bug
- combining module cleanup with runtime correctness changes in one patch

## Recommended Order

If post-merge work starts soon, use this order:

1. final control-frame drain before close/shutdown
2. command mutability classification
3. worker-offload for large read-only exec commands
4. runtime thread join cleanup
5. event module extraction
6. client / runtime file boundary cleanup
7. Python command status propagation
8. only then consider deeper runtime ownership changes
