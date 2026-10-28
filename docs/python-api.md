# BGPSim Python API

`src/bgpsim.py` controls bgpsim over its Unix socket using the same parser and
per-connection CLI context as the interactive client. It requires only Python's
standard library. Start the server separately; the client does not own its
process, network namespace, or receiving device.

```bash
bgpsim -s lab lab.conf
```

```python
import bgpsim  # Or: from src import bgpsim, from a source checkout.

with bgpsim.connect("lab", timeout=120) as client:
    reply = client.configure([
        "config",
        "ribout demo",
        "prefix 10.0.0.0/24 x 100",
        "next-hop 192.0.2.1",
        "script churn",
        "advertise ribout demo peer all",
        "sleep 1s",
        "withdraw ribout demo peer all",
        "end",
    ])
    if not reply:
        sys.exit(f"{reply.command}: {reply.error}")
    client.cli("update generate changed")
    result = client.run_script("churn", timeout=120)
    if result["state"] != "complete":
        sys.exit(f"run {result['id']} {result['state']}: {result['error']}")
    print(result["stats"])
```

Every call returns a value. The one exception, `bgpsim.Error`, means that no
control session exists and none could be made within the deadline.

Peers must already be configured and Established for this workload to transmit.
A completed run is not proof that the receiving device has installed routes.

## Connection And Deadlines

`bgpsim.connect(session=None, socket_path=None, *, timeout=30)` creates and
connects a `BGPSimClient`. The constructor accepts the same arguments if
deferred connection is needed.

- The default socket is `/tmp/bgpsim.sock`; named sessions use
  `/tmp/bgpsim_<session>.sock`. An explicit `socket_path` takes precedence.
- `connect()` waits up to `timeout` seconds for a missing or refused socket,
  polling every 50 ms, then completes the SYN/ACK handshake within the same
  deadline. If no session results, it raises `bgpsim.Error`. `Error` exposes
  `socket_path` and `reason`: `missing after 30s`, `refused after 30s`,
  `handshake timeout`, `protocol version 3, expected 4`, or the operating
  system's text, such as `Permission denied`. A stalled, incompatible,
  malformed, or permission-denied connection is not retried.
- `timeout` also bounds each later operation and can be overridden per call. A
  deadline is total, not renewed by each output frame or polling iteration.
- A lost connection is reconnected by the next call, within that call's
  deadline, with the same wait and the same `Error` when no session results.
  The server keeps the CLI mode per connection, so a reconnected client is
  back in exec mode. The first `Reply` after a reconnect has `reconnected`
  set.
- Leaving a context or calling `disconnect()` closes only the client socket.
  It does not stop bgpsim, cancel a run, or withdraw routes.

Timeouts and polling intervals must be finite positive numbers. One client is
synchronous and should not be shared between concurrent callers. Separate
clients have independent CLI contexts. A wrong argument type or value raises
`ValueError`, which is a coding error rather than a runtime condition.

## Commands

`client.cli(command, *, timeout=None)` returns a `Reply`: a `str` holding the
combined stdout/stderr in arrival order, with these attributes:

| Attribute | Meaning |
| --- | --- |
| `ok` | True when the server's `EXEC_DONE` status is zero or positive. `bool(reply)` is `ok`, so `if not reply:` detects a failure even when the output is empty |
| `status` | The server's status, or `None` when the connection failed before a complete response |
| `error` | Empty when `ok`; otherwise the rejection text, or the transport reason |
| `command` | The command that was sent |
| `reconnected` | True when the client reconnected before this command |

A rejected command leaves the connection usable because its complete response
has been consumed. The client does not search output for words such as `Error`
or `Warning`.

If the connection fails while a command is in flight, the server may already
have applied it. A `show` command is replayed once over a new connection. Any
other command returns a `Reply` whose `status` is `None` and whose `error` ends
in `outcome unknown; not replayed`; inspect server state before sending it
again. A deadline that expires mid-command is reported the same way, and the
next call reconnects.

`client.configure(commands, *, timeout=None)` executes an iterable of command
strings sequentially, with one deadline for the batch. It returns the first
rejected `Reply`, or the last `Reply` when every command succeeded, so one
`if not reply:` covers the batch and `reply.command` names the culprit. It
stops at the first failure. Include `config`, `end`, and other mode changes
explicitly. Earlier successful commands remain applied; there is no
transaction, rollback, implicit mode change, or replay. This method changes
the bgpsim tool's configuration.

```python
with bgpsim.connect("lab") as client:
    reply = client.configure(["config", "ribout demo", "no rt", "rt 65000:102", "end"])
    if not reply:
        print(reply.command, "rejected:", reply.error)
    client.cli("update generate changed")
```

Commands must be single strings without NUL or line separators. As in the
interactive CLI, mode-stack rewinding and exec-mode fallback are handled by
the server, not reimplemented in Python.

## Scripts And Runs

- `start_script(name, *, repeat=1, timeout=None)` starts once and returns the
  initial run snapshot, including its ID and any immediate execution failure.
  `repeat` is a positive uint32 or `"forever"`. When no run was created (an
  unknown script, or a connection lost before the response), it returns a
  failed snapshot whose `id` is `None` and whose `error` holds the rejection
  text or the transport reason. If that reason says the outcome is unknown,
  check `show runs` before starting again.
- `run_status(run_id, *, timeout=None)` returns the snapshot for that exact ID,
  or `None` when the ID is unknown or no valid snapshot could be read.
- `wait_run(run_id, *, timeout=None, poll_interval=0.05)` polls until the run
  is `complete`, `failed`, or `cancelled` and returns that snapshot. When the
  deadline passes, or the run can no longer be observed, it returns the last
  snapshot read (`None` if there was none). The run is not cancelled. Check
  `state == "complete"`, not merely `state != "failed"`.
- `run_script(name, *, repeat=1, timeout=None, poll_interval=0.05)` combines
  starting and waiting under one deadline, without starting a second run.

Waiting on an already completed run returns its snapshot immediately. To cancel
explicitly, use `cli(f"cancel run {run_id}")`.

The CLI provides the same structured output:

```text
run script churn json [repeat <count|forever>]
show run 7 json
```

These are JSON objects serialized directly from the existing run model. Python
returns dictionaries, not a parallel model or parsed human-readable tables.

| Fields | Meaning |
| --- | --- |
| `schema_version` | JSON schema version, currently 1 |
| `id`, `script`, `revision` | Run ID and frozen script identity |
| `state`, `error`, `engine_connected` | Execution state and failure detail |
| `repeat`, `iteration`, `step_index`, `step_count`, `phase` | Repeat count (0 means forever), current iteration and zero-based step index |
| `elapsed_ms`, `phase_elapsed_ms`, `current_ms` | Run and current/last-step phase durations |
| `peers` | Current/last-step peer, router AS, state, export version, message/byte totals and progress, elapsed time, reason |
| `stats` | One object per step, with phase samples and total/min/max milliseconds across completed iterations |

Run states are `pending`, `running`, `complete`, `failed`, and `cancelled`.
TX completion means **local socket-write completion**, not TCP acknowledgment
or receiver installation. As with the CLI, withheld/skipped peers can count as
done without transmitting. Inspect their states/reasons and verify the receiving
device independently. Peer counters describe the current/last step, not every
step's traffic summed together. Timings are monotonic milliseconds.

## Errors

`bgpsim.Error` is raised only when no control session exists and none could be
made: the socket is missing or refused for the whole deadline, the server
stalls or answers another protocol version during the handshake, or the
operating system refuses the connection. Everything that happens inside a live
session is reported as a value: a falsy `Reply`, a snapshot `state`, or `None`.

Malformed, truncated, or timed-out command responses close the connection so
late frames cannot be mistaken for another command's result. The next call
reconnects. The client never replays a command other than `show`: the server
may already have applied it.

From the shell, `python3 src/bgpsim.py [-s session] [-t seconds] '<command>'`
prints the output and exits 0 when the command was accepted, prints the
rejection or the transport reason to stderr and exits 1 when it was not, and
exits 2 when there is no session. `-t` sets the wait for the session and the
command deadline.

## Control Protocol

The client speaks the same framed protocol as the built-in `bgpsim -c` client.
Each frame is an 8-byte big-endian header, type then payload length, followed
by the payload. A payload is at most 1 MiB. The protocol version is `4`.

- The client sends `SYN` (1). The server replies `ACK` (2) with the version
  string as its payload.
- The client sends `EXEC_REQ` (3) with one command line as its payload.
- The server streams `STDOUT_CHUNK` (4) and `STDERR_CHUNK` (5) frames.
- The server ends the command with `EXEC_DONE` (6). Its payload starts with the
  signed 32-bit command status, followed by the CLI mode and session context,
  so an attached client keeps its config mode between commands.
- `EVENT` (7) frames carry `terminal monitor` output. The client ignores them.
- `ERROR` (8) reports a malformed request. The client closes the connection
  and reports the command as lost.

The server keeps the CLI mode and context for each live connection. The field
order of `EXEC_DONE` is defined by `exec_done_fields[]` in `src/control.c`.

## Testing

`tests/test_python_api.py` covers connections, framed error/deadline cases,
command status, and the run API against the real executable. It parses the
binary's JSON in Python and independently decodes a peer's UPDATE/withdrawal
bytes. These checks run under `all-test`, outside the packaging unit gate.

```bash
set -o pipefail
make all-test 2>&1 | tee /tmp/bgpsim-all-test.log
```

See [configuration.md](configuration.md) for CLI semantics and
[testing.md](testing.md) for focused suite selection.
