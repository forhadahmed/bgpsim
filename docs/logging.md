# Logging

This document describes the current logging behavior of `bgpsim`.

## Summary

Logging behavior is centered on the configured log file.

In normal operation:

- `bgpsim` chooses a log-file path at startup unless `-l <file>` overrides it
- `log_write()` writes protocol/runtime logs to that file
- `show log` and `show log all` read from that same file on the server side
- `terminal monitor` is separate from the log file and only affects live event
  delivery to an interactive control session

## Default Log Paths

If `-l <file>` is not used:

- interactive/default session: `/tmp/bgpsim.log`
- named server session: `/tmp/bgpsim_<session>.log`

You can override the path with:

```bash
$BUILD_DIR/bgpsim -l /tmp/custom.log
```

## Interactive TTY Mode

Example:

```bash
$BUILD_DIR/bgpsim bgpsim.conf
```

Behavior:

- CLI output stays on the terminal
- protocol log messages are written to the configured log file
- `%BGP-5-ADJCHANGE` and `%BGP-3-NOTIFICATION` style monitor events print on
  the terminal only when the session enables `terminal monitor`; the log file
  gets them too
- `show log` reads from that configured log file

Useful command:

```bash
tail -f /tmp/bgpsim.log
```

## Non-Interactive Foreground Mode

Examples:

```bash
echo "show bgp summary" | $BUILD_DIR/bgpsim
$BUILD_DIR/bgpsim < commands.txt
```

Behavior:

- protocol logs still go to the configured log file
- there is no TTY redraw behavior for async monitor output

## Server Mode

Example:

```bash
$BUILD_DIR/bgpsim -s lab bgpsim.conf
```

Current behavior:

- the parent process prints the chosen socket path and log path
- the child daemon redirects stdio to the chosen log file when possible
- `log_init()` also opens that same file directly for protocol/runtime logging

So server mode does write protocol logs to the configured log file, and `show
log`/`show log all` use that same file.

## Log Format

Protocol log entries are timestamped:

```text
[YYYY-MM-DD HH:MM:SS] message
```

Typical entries include:

- peer connection attempts
- FSM transitions
- OPEN / KEEPALIVE / NOTIFICATION events
- retry / reset events

## Terminal Output vs Log Output

`show ...` commands and CLI prompts are not the same thing as protocol logs.

- CLI output is user-facing command output
- protocol logs are background events emitted through the logging layer
- `terminal monitor` events are unsolicited control-session output, not log-file
  lines

## Practical Recommendation

- for protocol debugging, use `show log`, `show log all`, and `terminal monitor`
  together
- for automation, use the control server for command execution and treat the log
  file as a shared runtime record
