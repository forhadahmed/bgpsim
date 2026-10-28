#!/usr/bin/env python3
"""Executable CLI, daemon, passive-listener, and generation smoke coverage."""

from pathlib import Path
import random
import re
import socket
import sys
import unittest

from test_common import (ProcessFixture, bgpsim, find_bgpsim_binary,
                         find_test_client_binary, session_log_path,
                         session_socket_path, wait_until)
from test_results import run_unittest


def available_port():
    """Choose below the ephemeral range; outgoing connections cannot steal it."""
    limit = 32768
    if sys.platform.startswith('linux'):
        limit = int(Path('/proc/sys/net/ipv4/ip_local_port_range').read_text().split()[0])
    for _ in range(200):
        port = random.SystemRandom().randrange(10000, limit)
        with socket.socket() as probe:
            try:
                probe.bind(('127.0.0.1', port))
                return port
            except OSError:
                continue
    raise RuntimeError('No free listener port below the ephemeral range')


def listener_closed(port):
    # Do not connect to a one-shot peer merely to probe its listener.
    with socket.socket() as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind(('127.0.0.1', port))
            return True
        except OSError:
            return False


class ShellSmokeTests(unittest.TestCase):
    def setUp(self):
        self.fixture = ProcessFixture()
        self.fixture.__enter__()
        self.addCleanup(self.fixture.__exit__, None, None, None)
        self.binary = find_bgpsim_binary()
        self.session = f'smoke_{self.fixture.root.name.rsplit("-", 1)[-1]}'

    def config(self, text, name='test.conf'):
        path = self.fixture.root / name
        path.write_text(text)
        return path

    def run_cli(self, argv, commands):
        result = self.fixture.run([self.binary, *argv], input=commands, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout + result.stderr

    def foreground(self, config, commands, *, default_log=False):
        args = [] if default_log else ['-l', str(self.fixture.root / 'foreground.log')]
        return self.run_cli([*args, str(config)], commands)

    def test_foreground_cli(self):
        config = self.config('# Comments and blank lines should be ignored.\n\n'
                             'router   bgp   100\n  neighbor 127.0.0.1 remote-as 200\n\n'
                             'router bgp 200\n  neighbor 127.0.0.1 remote-as 100\n')
        output = self.foreground(config, 'show bgp summary\nshow bgp neighbors\n?\nconfig\nend\nquit\n')
        self.assertIn('local AS number 100', output)
        self.assertIn('local AS number 200', output)
        self.assertEqual(len(re.findall(r'^BGP neighbor is 127\.0\.0\.1', output, re.MULTILINE)), 2)
        self.assertRegex(output, r'(?m)^\s+show\s+show commands$')
        self.assertIn('Entering configuration mode', output)
        self.assertIn('Exiting configuration mode', output)

    def test_missing_config(self):
        output = self.foreground(self.fixture.root / 'missing.conf', 'show bgp summary\nquit\n')
        self.assertRegex(output, r'not found.*Use .config. to get started')
        self.assertIn('No BGP routers configured', output)

    def test_invalid_foreground_commands(self):
        config = self.config('router bgp 100\n  neighbor 127.0.0.1 remote-as 200\n')
        output = self.foreground(config, '\nSHOW BGP SUMMARY\nshow bgp neighbors abc\nshow bgp summary\nquit\n')
        self.assertIn('Unknown Command', output)
        self.assertIn('BGP router identifier', output)

    def test_oversized_and_nul_rejection_recovery(self):
        config = self.config('router bgp 65001\n')
        commands = ('config\nscript oversized' + ' ' * 1100 + '\nscript hidden\0ignored\n'
                    'end\nshow scripts\nconfig\nscript recovered\nsleep 2s\nend\n'
                    'show script recovered\nquit\n')
        output = self.foreground(config, commands)
        self.assertEqual(output.count('Error: invalid command input or command too long'), 2, output)
        self.assertIn('No scripts configured.', output)
        self.assertIn('Script recovered (revision 1, 1 steps)', output)
        self.assertIn('sleep 2000ms', output)

    def test_foreground_default_log(self):
        config = self.config('router bgp 65001\n')
        logfile = Path(session_log_path())
        # Never delete or rotate an unrelated user's default logfile.
        self.assertFalse(logfile.exists(), f'Unowned default logfile already exists: {logfile}')
        output = self.foreground(config, 'show bgp summary\nquit\n', default_log=True)
        self.assertIn('local AS number 65001', output)
        self.assertIn('Added router BGP 65001', logfile.read_text())
        logfile.unlink()  # The fixture owns this file; test actual recreation too.
        self.foreground(config, 'quit\n', default_log=True)
        self.assertIn('Added router BGP 65001', logfile.read_text())

    def test_default_daemon_attach_disconnect_reconnect(self):
        config = self.config('router bgp 65001\n')
        logfile = Path(session_log_path())
        self.assertFalse(logfile.exists(), f'Unowned default logfile already exists: {logfile}')
        self.assertTrue(self.fixture.start_session(config=config))
        self.assertIn('Added router BGP 65001', logfile.read_text())
        # Omit the session name in both native-client invocations.
        attached = self.run_cli(['-c'], 'show bgp summary\nquit\n')
        self.assertIn('local AS number 65001', attached)
        self.assertTrue(Path(session_socket_path()).is_socket())
        reconnected = self.run_cli(['-c', '-e', 'show bgp summary'], None)
        self.assertIn('local AS number 65001', reconnected)
        self.assertTrue(Path(session_socket_path()).is_socket())

    def test_named_daemon_socket_log_and_attach(self):
        config = self.config('router bgp 65001\n')
        self.assertTrue(self.fixture.start_session(self.session, config=config))
        self.assertTrue(Path(session_socket_path(self.session)).is_socket())
        self.assertIn('Added router BGP 65001', Path(session_log_path(self.session)).read_text())
        output = self.run_cli(['-c', self.session, '-e', 'show bgp summary'], None)
        self.assertIn('local AS number 65001', output)

    def test_four_byte_asn_live_toggles_with_fresh_clients(self):
        port = available_port()
        config = self.config('router bgp 100\n  neighbor 127.0.0.1 remote-as 200\n')
        client_binary = find_test_client_binary()

        def start_client(phase):
            logfile = self.fixture.root / f'peer-{phase}.log'
            process = self.fixture.start_process(
                [client_binary, '--passive', '127.0.0.1', str(port), '200', '2.2.2.2', '15'],
                log_path=logfile)

            def listening():
                if process.poll() is not None:
                    self.fail(f'Peer {phase} exited before listening: {logfile.read_text()}')
                return f'Listening on 127.0.0.1:{port}' in logfile.read_text()

            self.assertTrue(wait_until(listening, 10), self.fixture.diagnostics())
            return process

        client = start_client(0)  # Avoid the daemon's initial connection retry backoff.
        self.assertTrue(self.fixture.start_session(
            self.session, config, self.fixture.root / 'daemon.log',
            env={'BGPSIM_LISTEN_BASE_PORT': str(port)}))
        latest = ''
        for phase in range(3):
            if phase:
                toggle = 'no capability four-byte-asn' if phase == 1 else 'capability four-byte-asn'
                self.run_cli(['-c', self.session],
                             f'config\nrouter bgp 100\nneighbor 127.0.0.1 remote-as 200\n{toggle}\nend\nquit\n')
                self.assertTrue(wait_until(lambda: client.poll() is not None, 10),
                                self.fixture.diagnostics())
                self.fixture.stop_process(client)
                self.assertTrue(wait_until(lambda: listener_closed(port), 5), self.fixture.diagnostics())
                client = start_client(phase)

            def established():
                nonlocal latest
                latest = self.fixture.cli('show bgp neighbors', self.session)
                resets = re.search(r'Session resets:\s*(\d+)', latest)
                capability = ('4-byte ASN:' not in latest if phase == 1 else
                              '4-byte ASN: advertised' in latest)
                return ('BGP state = Established' in latest and capability and
                        (phase == 0 or resets is not None and int(resets[1]) >= phase))

            self.assertTrue(wait_until(established, 15), f'phase {phase}: {latest}\n{self.fixture.diagnostics()}')
            self.assertTrue(wait_until(lambda: listener_closed(port), 5), self.fixture.diagnostics())
        self.fixture.stop_process(client)

    def test_passive_raw_tcp_accept(self):
        port = available_port()
        config = self.config('router bgp 100\n  neighbor 127.0.0.1 remote-as 200\n')
        logfile = self.fixture.root / 'passive.log'
        process = self.fixture.start_process(
            [self.binary, '--passive', '-l', str(logfile), str(config)],
            env={'BGPSIM_LISTEN_BASE_PORT': str(port)})

        def listening():
            if process.poll() is not None:
                self.fail(f'Passive process exited: {self.fixture.diagnostics()}')
            return logfile.exists() and f'listening on port {port}' in logfile.read_text()

        self.assertTrue(wait_until(listening, 10), self.fixture.diagnostics())
        with socket.create_connection(('127.0.0.1', port), timeout=2) as connection:
            connection.sendall(b'smoke\n')
        self.assertTrue(wait_until(lambda: 'Accepted connection from 127.0.0.1' in logfile.read_text(), 5),
                        self.fixture.diagnostics())

    def test_generation_smoke(self):
        """Standalone real generation; missing/empty summaries must never pass."""
        name = 'generation_smoke'
        config = self.config(f'ribout {name}\n'
                             '  prefix 10.0.0.0/24 x 1000\n'
                             '  next-hop 192.168.1.1 x 5\n'
                             '  as-path 100 200 300\n'
                             '  localpref 100\n'
                             '  origin igp\n')
        summaries = []
        for _ in range(2):
            output = self.foreground(config, f'update generate\nshow ribout {name}\nquit\n')
            fields = []
            for label, pattern in (('Total Paths', r'([0-9]+)'),
                                   ('Message Count', r'([0-9]+)'),
                                   ('Total Size', r'([0-9]+(?:\.[0-9]+)?)\s+(bytes|KB|MB)')):
                values = re.findall(r'(?m)^\s*' + label + r':\s*' + pattern + r'\s*$', output)
                self.assertEqual(len(values), 1, f'Missing/duplicate {label}: {output!r}')
                fields.append(values[0])
            self.assertEqual(int(fields[0]), 1000, output)
            self.assertGreater(int(fields[1]), 0, output)
            self.assertGreater(float(fields[2][0]), 0, output)
            summaries.append(fields)
        self.assertEqual(summaries[0], summaries[1], 'Repeated generation summaries differ')


if __name__ == '__main__':
    sys.exit(run_unittest())
