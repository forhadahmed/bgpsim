#!/usr/bin/env python3
"""Explicit resource ownership and check reporting for executable tests."""

import os
from pathlib import Path
import re
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

from test_results import emit, terminate_group

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'src'))
import bgpsim


class TestRunner:
    """Track checks; only individual checks emit result records."""

    def __init__(self):
        self.passed = self.failed = self.tests = 0

    def test_pass(self, msg):
        self.tests += 1
        self.passed += 1
        emit('pass', msg)

    def test_fail(self, msg, detail=None):
        self.tests += 1
        self.failed += 1
        emit('fail', msg, detail=str(detail) if detail is not None else None)
        if detail is not None:
            print(detail)

    def summary(self):
        print(f'Test Results: {self.passed} passed, {self.failed} failed (Total: {self.tests})')
        return int(self.failed != 0)


def _session_name(name):
    name = name or 'bgpsim'
    if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,63}', name):
        raise ValueError(f'Invalid session name: {name!r}')
    return name


def session_socket_path(session_name='bgpsim'):
    name = _session_name(session_name)
    return '/tmp/bgpsim.sock' if name == 'bgpsim' else f'/tmp/bgpsim_{name}.sock'


def session_log_path(session_name='bgpsim', log_path=None):
    if log_path is not None:
        return str(log_path)
    name = _session_name(session_name)
    return '/tmp/bgpsim.log' if name == 'bgpsim' else f'/tmp/bgpsim_{name}.log'


def wait_until(condition, timeout_secs=30):
    """Check immediately, then back off up to 200 ms using a monotonic deadline."""
    deadline = time.monotonic() + timeout_secs
    delay = 0.01
    while True:
        result = condition()
        if result or time.monotonic() >= deadline:
            return result
        time.sleep(min(delay, max(0.0, deadline - time.monotonic())))
        delay = min(delay * 2, 0.2)


def find_bgpsim_binary():
    return str(Path(bgpsim.find_binary('bgpsim', 'BGPSIM')).resolve())


def find_test_client_binary():
    return str(Path(bgpsim.find_binary('bgp_test_client', 'TEST_CLIENT')).resolve())


def _pid_state(pid):
    if not sys.platform.startswith('linux'):
        result = subprocess.run(['ps', '-p', str(pid), '-o', 'stat=', '-o', 'lstart='],
                                capture_output=True, text=True, timeout=2)
        fields = result.stdout.strip().split(None, 1)
        return (fields[0][0], fields[1]) if len(fields) == 2 else None
    try:
        fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
        return fields[0], fields[19]  # State and start time, not just a reusable PID.
    except FileNotFoundError:
        return None


def _identity(path):
    try:
        stat = Path(path).lstat()
        return stat.st_dev, stat.st_ino
    except FileNotFoundError:
        return None


class ProcessFixture:
    """Own detached daemons, separate child process groups, logs, and tempfiles.

    Signal handlers exist only inside the context (install_signals=False opts
    out). env is fixture-local; per-call env values override it. start_process
    keeps binary stdin open and writes combined output to log_path. run returns
    exact, separate text stdout/stderr for short bounded commands.
    """

    def __init__(self, *, install_signals=True, env=None):
        self._temp = tempfile.TemporaryDirectory(prefix='bgpsim-test-')
        self.root = Path(self._temp.name)
        self.env = dict(os.environ)
        self.env.update(env or {})
        self._install_signals = install_signals
        self._handlers = {}
        self._sessions = {}
        self._processes = {}
        self._foreground = {}
        self._artifacts = {}
        self._pending_logs = set()
        self._session_logs = set()
        self._entered = self._closing = self._closed = False

    def __enter__(self):
        if self._entered or self._closed:
            raise RuntimeError('ProcessFixture contexts cannot be reused')
        self._entered = True
        if self._install_signals and threading.current_thread() is threading.main_thread():
            for sig in (signal.SIGINT, signal.SIGTERM):
                self._handlers[sig] = signal.signal(sig, self._handle_signal)
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            if exc is not None:
                print(self.diagnostics(), file=sys.stderr)
            self.close()
        finally:
            for sig, handler in self._handlers.items():
                signal.signal(sig, handler)
            self._handlers.clear()
        return False

    def _handle_signal(self, signum, frame):
        if not self._closing:
            raise SystemExit(128 + signum)

    def _require_context(self):
        if not self._entered or self._closed:
            raise RuntimeError('Use ProcessFixture inside a with statement')

    def _reserve_socket(self, name):
        path = Path(session_socket_path(name))
        if os.path.lexists(path):
            raise FileExistsError(f'Refusing to replace an unowned session socket: {path}')
        return path

    def _claim_log(self, path):
        path = Path(path).absolute()
        if not os.path.lexists(path):
            self._artifacts.pop(path, None)
            self._pending_logs.add(path)
        return path

    def _capture_logs(self):
        for path in list(self._pending_logs):
            identity = _identity(path)
            if identity is not None:
                self._artifacts[path] = identity
                self._pending_logs.remove(path)

    def _prepare_process(self, argv):
        self._require_context()
        argv = [os.fspath(arg) for arg in argv]
        if self._is_foreground(argv):
            self._reserve_socket('bgpsim')
            log_path = argv[argv.index('-l') + 1] if '-l' in argv else session_log_path()
            self._claim_log(log_path)
        return argv

    def start_process(self, argv, log_path=None, env=None):
        """Start a child in its own process group; return its binary-mode Popen."""
        argv = self._prepare_process(argv)
        path = Path(log_path or self.root / f'process-{len(self._processes)}.log').absolute()
        with path.open('xb') as output:
            self._artifacts[path] = _identity(path)
            process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=output,
                                       stderr=subprocess.STDOUT, start_new_session=True,
                                       env=self.env | (env or {}))
        self._processes[process] = path
        self._register_foreground(process, argv)
        return process

    @staticmethod
    def _is_foreground(argv):
        return (Path(argv[0]).resolve() == Path(find_bgpsim_binary()) and
                not any(arg in argv for arg in ('-c', '-s', '-h', '--help')))

    def _register_foreground(self, process, argv):
        if self._is_foreground(argv):
            self._foreground[process] = Path(session_socket_path())

    def _capture_socket(self, path, pid):
        identity = _identity(path)
        if identity is None:
            return None
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                probe.settimeout(0.2)
                probe.connect(str(path))
                if hasattr(socket, 'SO_PEERCRED'):
                    credentials = probe.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
                    if struct.unpack('3i', credentials)[0] != pid:
                        return None
            return identity if _identity(path) == identity else None
        except OSError:
            return None

    def stop_process(self, process):
        """Stop only a group created by this fixture, including leftover children."""
        if process not in self._processes:
            raise ValueError('Refusing to stop an unowned process')
        if process in self._foreground and process.poll() is None:
            path = self._foreground[process]
            identity = self._capture_socket(path, process.pid)
            if identity is not None:
                self._artifacts.setdefault(path, identity)
        terminate_group(process)
        self._capture_logs()
        if process.stdin is not None:
            process.stdin.close()

    def stop_processes(self, processes):
        """Signal an owned batch before waiting, then reap every process group."""
        processes = list(processes)
        if any(process not in self._processes for process in processes):
            raise ValueError('Refusing to stop an unowned process')
        for process in processes:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
        for process in processes:
            self.stop_process(process)

    def run(self, argv, *, input=None, env=None, timeout=10):
        argv = self._prepare_process(argv)
        path = self.root / f'process-{len(self._processes)}.log'
        process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True, start_new_session=True,
                                   env=self.env | (env or {}))
        self._processes[process] = path
        self._register_foreground(process, argv)
        try:
            stdout, stderr = process.communicate(input=input, timeout=timeout)
        except BaseException:
            self.stop_process(process)
            stdout, stderr = process.communicate()
            path.write_text(stdout + stderr)
            raise
        path.write_text(stdout + stderr)
        self._capture_logs()
        return subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)

    @staticmethod
    def _alive(entry):
        state = _pid_state(entry['pid'])
        return state is not None and state[0] not in ('Z', 'X') and state[1] == entry['start']

    def start_session(self, name='bgpsim', config=None, log_path=None, *, passive=False, env=None):
        """Launch, parse the daemon PID, then verify a real control handshake."""
        self._require_context()
        name = _session_name(name)
        self.stop_session(name)
        launcher = None
        launch_log = self.root / f'start-{name}-{len(self._processes)}.log'
        try:
            socket_path = self._reserve_socket(name)
            config_path = Path(config or os.devnull).absolute()
            if not config_path.is_file() and config_path != Path(os.devnull):
                raise FileNotFoundError(config_path)
            daemon_log = self._claim_log(session_log_path(name, log_path))
            self._session_logs.add(daemon_log)
            argv = [find_bgpsim_binary(), '-s', name]
            if passive:
                argv.append('--passive')
            if log_path is not None:
                argv.extend(['-l', str(daemon_log)])
            argv.append(str(config_path))
            launcher = self.start_process(argv, log_path=launch_log, env=env)
            try:
                launcher.communicate(timeout=10)
            finally:
                # Interrupted/unsuccessful launchers can also have forked a daemon.
                output = launch_log.read_text(errors='replace')
                match = re.search(r'^pid:\s*([1-9][0-9]*)\s*$', output, re.MULTILINE)
                if match:
                    pid = int(match[1])
                    state = _pid_state(pid)
                    if pid <= 1 or pid == os.getpid():
                        raise RuntimeError(f'Invalid daemon PID: {pid}')
                    if state is not None:
                        pidfd = os.pidfd_open(pid) if hasattr(os, 'pidfd_open') else None
                        self._sessions[name] = dict(pid=pid, start=state[1], pidfd=pidfd,
                                                    socket=socket_path, identity=None, log=daemon_log)
            if launcher.returncode != 0 or name not in self._sessions:
                raise RuntimeError('Launcher failed or did not report a live daemon PID')

            def ready():
                if not self._alive(self._sessions[name]):
                    raise RuntimeError('Daemon exited before control readiness')
                try:
                    return 'BGP' in self.cli('show bgp summary', session=name)
                except (OSError, ConnectionError):
                    return False

            if not wait_until(ready, 10):
                raise RuntimeError('Daemon control socket did not become ready')
            self._capture_logs()
            return True
        except Exception as exc:
            print(f'Session {name} startup failed: {exc}\n{self.diagnostics()}', file=sys.stderr)
            if launcher is not None and launcher.poll() is None:
                self.stop_process(launcher)
            self.stop_session(name)
            return False

    def cli(self, command, session=None):
        name = _session_name(session)
        entry = self._sessions.get(name)
        if entry is None or not self._alive(entry):
            raise ValueError(f'Refusing to connect to an unowned/inactive session: {name}')
        client = bgpsim.BGPSimClient(socket_path=str(entry['socket']))
        try:
            client.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.sock.settimeout(2)
            client.sock.connect(str(entry['socket']))
            identity = _identity(entry['socket'])
            if entry['identity'] is not None and identity != entry['identity']:
                raise ConnectionError('Control socket identity changed')
            if hasattr(socket, 'SO_PEERCRED'):
                credentials = client.sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
                if struct.unpack('3i', credentials)[0] != entry['pid']:
                    raise ConnectionError('Control socket belongs to a different process')
            client.sock.sendall(client.build_frame(bgpsim.BGPSIM_CTRL_SYN))
            kind, version = client.recv_frame()
            if kind != bgpsim.BGPSIM_CTRL_ACK or version != bgpsim.BGPSIM_CONTROL_VERSION:
                raise ConnectionError('Invalid daemon control handshake')
            if _identity(entry['socket']) != identity:
                raise ConnectionError('Control socket changed during handshake')
            entry['identity'] = identity
            client.connected = True
            return client.cli(command)
        finally:
            client.disconnect()

    def stop_session(self, name):
        name = _session_name(name)
        entry = self._sessions.get(name)
        if entry is None:
            return
        for sig, grace in ((signal.SIGTERM, 3), (signal.SIGKILL, 2)):
            if not self._alive(entry):
                break
            try:
                if entry['pidfd'] is not None:
                    signal.pidfd_send_signal(entry['pidfd'], sig)
                else:
                    os.kill(entry['pid'], sig)
            except ProcessLookupError:
                break
            if wait_until(lambda: not self._alive(entry), grace):
                break
        if self._alive(entry):
            raise RuntimeError(f'Owned daemon {name} (PID {entry["pid"]}) did not exit')
        if entry['pidfd'] is not None:
            os.close(entry['pidfd'])
        if entry['identity'] is not None and _identity(entry['socket']) == entry['identity']:
            entry['socket'].unlink()
        del self._sessions[name]

    def diagnostics(self):
        paths = set(self._processes.values()) | self._session_logs
        sections = [f'Fixture diagnostics ({self.root}):']
        for path in sorted(paths):
            try:
                sections.append(f'--- {path} ---\n{path.read_text(errors="replace")[-12000:]}')
            except OSError as exc:
                sections.append(f'{path}: {exc}')
        return '\n'.join(sections)

    def close(self):
        if self._closed:
            return
        self._closing = True
        errors = []
        for name in list(self._sessions):
            try:
                self.stop_session(name)
            except Exception as exc:
                errors.append(str(exc))
        for process in self._processes:
            try:
                self.stop_process(process)
            except Exception as exc:
                errors.append(str(exc))
        for path, identity in self._artifacts.items():
            if _identity(path) == identity:
                path.unlink(missing_ok=True)
        if errors:
            raise RuntimeError('\n'.join(errors) + '\n' + self.diagnostics())
        self._temp.cleanup()
        self._closed = True
