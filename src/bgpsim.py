#!/usr/bin/env python3
"""
BGPSim Python client.

This client speaks the same framed control protocol as the interactive `bgpsim`
frontend. It keeps one control connection open so CLI mode and config context
persist across calls.

Every call returns a value: a `Reply` for a command, a run snapshot for the run
API. The one exception, `Error`, means that no control session exists and none
could be made.
"""

import os
import json
import math
import re
import socket
import struct
import sys
import time
from pathlib import Path


BGPSIM_CONTROL_VERSION = b"4"
BGPSIM_CONTROL_HEADER_LEN = 8
BGPSIM_CONTROL_MAX_PAYLOAD = 1024 * 1024
# Version 4's field-wise encoding, not a native C struct (no padding).
_EXEC_DONE_SIZE = struct.calcsize("!7I64sI32sI8I64s")

BGPSIM_CTRL_SYN = 1
BGPSIM_CTRL_ACK = 2
BGPSIM_CTRL_EXEC_REQ = 3
BGPSIM_CTRL_STDOUT_CHUNK = 4
BGPSIM_CTRL_STDERR_CHUNK = 5
BGPSIM_CTRL_EXEC_DONE = 6
BGPSIM_CTRL_EVENT = 7
BGPSIM_CTRL_ERROR = 8

_RUN_STATES = ('pending', 'running', 'complete', 'failed', 'cancelled')
_RUN_ENDED = ('complete', 'failed', 'cancelled')


def build_dir_candidates():
    """Build directories to search, in order: $BUILD_DIR, then the defaults."""
    project_root = Path(__file__).resolve().parent.parent
    candidate_dirs = []
    build_dir = os.environ.get("BUILD_DIR")

    if build_dir:
        candidate_dirs.append(Path(build_dir))

    candidate_dirs.extend([
        project_root / "build",
        project_root / ".build",
        Path("/tmp/bgpsim"),
        Path("/bld/bgpsim"),
        Path("/tmp/bgpsim-build"),
        Path("/tmp/bgpsim-prod"),
    ])
    return candidate_dirs


def find_binary(name="bgpsim", env_var="BGPSIM"):
    """Return the path of a built program.

    The environment variable wins when it names an existing file. Otherwise
    the first build directory that holds the program is used, and the first
    candidate path is returned when none does.
    """
    env_path = os.environ.get(env_var)
    if env_path and os.path.exists(env_path):
        return env_path

    candidate_dirs = build_dir_candidates()
    for build_dir in candidate_dirs:
        candidate = build_dir / name
        if candidate.exists():
            return str(candidate)

    return str(candidate_dirs[0] / name)


class Error(Exception):
    """No control session: the server is absent, incompatible, or unreachable."""

    def __init__(self, socket_path, reason):
        super().__init__(f"no bgpsim at {socket_path}: {reason}")
        self.socket_path = socket_path
        self.reason = reason


class Reply(str):
    """A command's combined stdout/stderr. Truthy when the command succeeded.

    `status` is the server's CLI status, or None when the connection failed
    before a complete response arrived. `error` is empty when `ok`, else the
    rejection text or the transport reason. `reconnected` is True when the
    client had to reconnect before this command.
    """

    def __new__(cls, output='', *, command='', status=0, error='', reconnected=False):
        reply = super().__new__(cls, output)
        reply.command = command
        reply.status = status
        reply.ok = status is not None and status >= 0
        reply.error = error
        reply.reconnected = reconnected
        return reply

    def __bool__(self):
        return self.ok


class _Lost(Exception):
    """A command's connection failed; `sent` says whether the request may have reached the server."""

    def __init__(self, reason, sent):
        super().__init__(reason)
        self.sent = sent


def _seconds(value, name):
    if (isinstance(value, bool) or not isinstance(value, (int, float)) or
            not math.isfinite(value) or value <= 0):
        raise ValueError(f"{name} must be finite and positive")
    return value


def _uint32(value, name):
    if type(value) is not int or not 0 < value <= 0xffffffff:
        raise ValueError(f"{name} must be a positive uint32")
    return value


class BGPSimClient:
    """Client for controlling bgpsim over its Unix control socket."""

    def __init__(self, session=None, socket_path=None, *, timeout=30):
        self.sock = None
        self.connected = False
        self.timeout = _seconds(timeout, 'timeout')
        self._had_session = False
        self._reconnected = False
        if socket_path:
            self.socket_path = socket_path
        elif session and session != "bgpsim":
            self.socket_path = f"/tmp/bgpsim_{session}.sock"
        else:
            self.socket_path = "/tmp/bgpsim.sock"

    @staticmethod
    def build_frame(msg_type, payload=b""):
        if payload is None:
            payload = b""
        header = struct.pack("!II", msg_type, len(payload))
        return header + payload

    def _deadline(self, timeout):
        return time.monotonic() + _seconds(
            self.timeout if timeout is None else timeout, 'timeout')

    def _arm(self, deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("operation deadline expired")
        self.sock.settimeout(remaining)

    def recv_exactly(self, size, deadline=None):
        deadline = self._deadline(None) if deadline is None else deadline
        data = bytearray()

        while len(data) < size:
            self._arm(deadline)
            chunk = self.sock.recv(size - len(data))
            if not chunk:
                raise ConnectionError("Connection closed by bgpsim")
            data.extend(chunk)

        return bytes(data)

    def recv_frame(self, deadline=None):
        deadline = self._deadline(None) if deadline is None else deadline
        header = self.recv_exactly(BGPSIM_CONTROL_HEADER_LEN, deadline)
        msg_type, payload_len = struct.unpack("!II", header)
        if not BGPSIM_CTRL_SYN <= msg_type <= BGPSIM_CTRL_ERROR:
            raise ConnectionError(f"Unknown control frame type {msg_type}")
        if payload_len > BGPSIM_CONTROL_MAX_PAYLOAD:
            raise ConnectionError(f"Oversized control frame: {payload_len} bytes")
        payload = self.recv_exactly(payload_len, deadline) if payload_len else b""
        return msg_type, payload

    def connect(self, deadline=None):
        """Wait for the socket and complete the handshake; raise Error when no session results."""
        if self.connected:
            return self
        deadline = self._deadline(None) if deadline is None else deadline
        started = time.monotonic()
        state = None
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise Error(self.socket_path,
                            f"{state or 'connect timeout'} after {time.monotonic() - started:.3g}s")
            try:
                self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self.sock.settimeout(remaining)
                self.sock.connect(self.socket_path)
            except (FileNotFoundError, ConnectionRefusedError) as exc:
                # Only an absent or refused listener is worth waiting for.
                self.disconnect()
                state = 'missing' if isinstance(exc, FileNotFoundError) else 'refused'
                time.sleep(min(0.05, max(deadline - time.monotonic(), 0)))
                continue
            except (TimeoutError, socket.timeout) as exc:
                self.disconnect()
                raise Error(self.socket_path, 'connect timeout') from exc
            except OSError as exc:
                self.disconnect()
                raise Error(self.socket_path, exc.strerror or str(exc) or type(exc).__name__) from exc
            except BaseException:
                self.disconnect()
                raise

            # An accepted but stalled, incompatible, or malformed server is not retried.
            try:
                self._arm(deadline)
                self.sock.sendall(self.build_frame(BGPSIM_CTRL_SYN))
                msg_type, payload = self.recv_frame(deadline)
            except (TimeoutError, socket.timeout) as exc:
                self.disconnect()
                raise Error(self.socket_path, 'handshake timeout') from exc
            except OSError as exc:
                self.disconnect()
                raise Error(self.socket_path, f"handshake failed: {exc}") from exc
            except BaseException:
                self.disconnect()
                raise
            if msg_type != BGPSIM_CTRL_ACK:
                self.disconnect()
                raise Error(self.socket_path, f"unexpected handshake frame {msg_type}")
            if payload != BGPSIM_CONTROL_VERSION:
                self.disconnect()
                raise Error(self.socket_path,
                            f"protocol version {payload.decode('utf-8', errors='replace')}, "
                            f"expected {BGPSIM_CONTROL_VERSION.decode()}")
            self.connected = True
            self._had_session = True
            return self

    def _session(self, deadline):
        """Make sure a session exists; connecting again after a loss counts as a reconnect."""
        if not self.connected:
            reconnect = self._had_session
            self.connect(deadline)
            self._reconnected = reconnect

    @staticmethod
    def _replayable(command):
        """Only a show command is safe to send twice."""
        return command.split(None, 1)[:1] == ['show']

    def _execute(self, command, deadline):
        """Run one command and return its Reply; raise Error only when no session can be made."""
        if not isinstance(command, str) or any(c in command for c in '\x00\r\n'):
            raise ValueError("command must be a single string without NUL or newlines")
        payload = command.encode("utf-8")
        if len(payload) > BGPSIM_CONTROL_MAX_PAYLOAD:
            raise ValueError("command exceeds the control frame limit")
        for attempt in (1, 2):
            if deadline - time.monotonic() <= 0:
                return Reply(command=command, status=None, error="deadline expired; not sent",
                             reconnected=self._reconnected)
            self._session(deadline)
            reconnected, self._reconnected = self._reconnected, False
            try:
                return self._exchange(command, payload, deadline, reconnected)
            except _Lost as lost:
                # The server may have applied the command; only a show is replayed.
                self.disconnect()
                if attempt == 1 and self._replayable(command) and deadline - time.monotonic() > 0:
                    continue
                outcome = "outcome unknown; not replayed" if lost.sent else "not sent"
                return Reply(command=command, status=None, error=f"{lost}; {outcome}",
                             reconnected=reconnected)
            except BaseException:
                self.disconnect()
                raise

    def _exchange(self, command, payload, deadline, reconnected):
        """Send one command and collect its response; raise _Lost on any transport failure."""
        output_chunks = []
        sent = False
        try:
            self._arm(deadline)
            # sendall can fail after a partial write: the outcome is then unknown.
            sent = True
            self.sock.sendall(self.build_frame(BGPSIM_CTRL_EXEC_REQ, payload=payload))
            while True:
                msg_type, frame_payload = self.recv_frame(deadline)
                if msg_type in (BGPSIM_CTRL_STDOUT_CHUNK, BGPSIM_CTRL_STDERR_CHUNK):
                    output_chunks.append(frame_payload)
                elif msg_type == BGPSIM_CTRL_EXEC_DONE:
                    if len(frame_payload) != _EXEC_DONE_SIZE:
                        raise ConnectionError("Malformed EXEC_DONE payload")
                    status, = struct.unpack_from('!i', frame_payload)
                    output = b''.join(output_chunks).decode('utf-8', errors='replace')
                    return Reply(output, command=command, status=status,
                                 error='' if status >= 0 else output.strip(),
                                 reconnected=reconnected)
                elif msg_type == BGPSIM_CTRL_ERROR:
                    raise ConnectionError(frame_payload.decode('utf-8', errors='replace'))
                elif msg_type != BGPSIM_CTRL_EVENT:
                    raise ConnectionError(f"Unexpected command frame {msg_type}")
        except (TimeoutError, socket.timeout) as exc:
            raise _Lost("deadline expired", sent) from exc
        except OSError as exc:
            raise _Lost(str(exc) or type(exc).__name__, sent) from exc

    def cli(self, command, *, timeout=None):
        """Return the command's Reply: its output, truthy when the server accepted it."""
        return self._execute(command, self._deadline(timeout))

    def configure(self, commands, *, timeout=None):
        """Run commands in order under one deadline; return the first rejected Reply, else the last."""
        if isinstance(commands, (str, bytes)):
            raise ValueError("commands must be an iterable of command strings")
        deadline = self._deadline(timeout)
        reply = Reply()
        for command in commands:
            reply = self._execute(command, deadline)
            if not reply:
                break
        return reply

    def _run(self, reply, *, run_id=None, name=None):
        """Return the validated run snapshot in reply, or None when it holds none."""
        if not reply:
            return None
        try:
            result = json.loads(reply)
            if (not isinstance(result, dict) or result.get('schema_version') != 1 or
                    result.get('state') not in _RUN_STATES or
                    not isinstance(result.get('script'), str) or
                    not isinstance(result.get('error'), str)):
                raise ValueError("invalid run schema")
            _uint32(result.get('id'), 'id')
            if run_id is not None and result['id'] != run_id:
                raise ValueError("run ID does not match request")
            if name is not None and result['script'] != name:
                raise ValueError("script name does not match request")
            return result
        except (ValueError, TypeError):
            # The stream is no longer trusted; the next call reconnects.
            self.disconnect()
            return None

    def _start_script(self, name, repeat, deadline):
        if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,63}', name):
            raise ValueError("invalid script name")
        if repeat != 'forever':
            _uint32(repeat, 'repeat')
        reply = self._execute(f"run script {name} json repeat {repeat}", deadline)
        result = self._run(reply, name=name)
        if result is None:
            # No run was created, or none can be confirmed: a failed snapshot without an ID.
            return {'schema_version': 1, 'id': None, 'script': name, 'state': 'failed',
                    'error': reply.error or 'invalid run response', 'peers': [], 'stats': []}
        return result

    def start_script(self, name, *, repeat=1, timeout=None):
        """Start once; return the run snapshot, or a failed snapshot with id None when no run started."""
        return self._start_script(name, repeat, self._deadline(timeout))

    def run_status(self, run_id, *, timeout=None):
        """Return the run snapshot, or None when the ID is unknown or no snapshot could be read."""
        run_id = _uint32(run_id, 'run_id')
        return self._run(self._execute(f"show run {run_id} json", self._deadline(timeout)),
                         run_id=run_id)

    def _wait_run(self, run_id, deadline, poll_interval, result=None):
        while True:
            if result is not None:
                if result['state'] in _RUN_ENDED:
                    return result
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return result
                time.sleep(min(poll_interval, remaining))
            latest = self._run(self._execute(f"show run {run_id} json", deadline), run_id=run_id)
            if latest is None:
                return result
            result = latest

    def wait_run(self, run_id, *, timeout=None, poll_interval=0.05):
        """Wait for the run to end and return its last snapshot; never cancels the run."""
        return self._wait_run(_uint32(run_id, 'run_id'), self._deadline(timeout),
                              _seconds(poll_interval, 'poll_interval'))

    def run_script(self, name, *, repeat=1, timeout=None, poll_interval=0.05):
        """Start and wait under one deadline; return the last snapshot, never a second start."""
        poll_interval = _seconds(poll_interval, 'poll_interval')
        deadline = self._deadline(timeout)
        result = self._start_script(name, repeat, deadline)
        if result['id'] is None:
            return result
        return self._wait_run(result['id'], deadline, poll_interval, result)

    def disconnect(self):
        """Disconnect from bgpsim."""
        if self.sock is not None:
            try:
                self.sock.close()
            finally:
                self.sock = None
        self.connected = False

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()
        return False

    def __del__(self):
        self.disconnect()


def connect(session=None, socket_path=None, *, timeout=30):
    """Create and connect a `BGPSimClient`; raise Error when no session results within timeout."""
    client = BGPSimClient(session=session, socket_path=socket_path, timeout=timeout)
    client.connect()
    return client


def _usage():
    print("Usage: python3 bgpsim.py [-s session] [-t seconds] '<command>'")


if __name__ == "__main__":
    session = None
    timeout = 30
    command = None
    index = 1

    while index < len(sys.argv):
        if sys.argv[index] == "-s" and index + 1 < len(sys.argv):
            session = sys.argv[index + 1]
            index += 2
        elif sys.argv[index] == "-t" and index + 1 < len(sys.argv):
            try:
                timeout = float(sys.argv[index + 1])
            except ValueError:
                print(f"Error: -t needs a number of seconds, not {sys.argv[index + 1]!r}", file=sys.stderr)
                sys.exit(2)
            index += 2
        elif sys.argv[index] in ("-h", "--help"):
            _usage()
            print()
            print("Options:")
            print("  -s session   Connect to named session (default: 'bgpsim')")
            print("  -t seconds   Wait this long for the session, and for the command (default: 30)")
            print("  -h, --help   Show this help message")
            print()
            print("Exit status: 0 command accepted, 1 command rejected or lost, 2 no session.")
            print()
            print("Examples:")
            print("  python3 bgpsim.py 'show bgp summary'")
            print("  python3 bgpsim.py -s mysession 'show bgp summary'")
            sys.exit(0)
        else:
            command = sys.argv[index]
            index += 1

    if not command:
        _usage()
        print("Use -h for help")
        sys.exit(2)

    try:
        with connect(session=session, timeout=timeout) as client:
            reply = client.cli(command)
    except (Error, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(2)
    if reply:
        print(reply, end="")
        sys.exit(0)
    print(reply if reply.status is not None else f"Error: {reply.error}\n", end="", file=sys.stderr)
    sys.exit(1)
