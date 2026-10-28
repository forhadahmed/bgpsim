#!/usr/bin/env python3
"""
Python API Test Suite
Comprehensive testing of bgpsim.py Python client library
"""

import itertools
import time
import sys
import os
import json
import socket
import struct
import tempfile
import unittest
from unittest.mock import Mock, patch
from contextlib import ExitStack

# Import common test utilities
from test_common import (
    ProcessFixture, TestRunner, bgpsim, wait_until
)
from test_results import run_unittest
from bgp_wire import update_nlri

DEFAULT_SESSION = 'bgpsim'
NAMED_SESSION = f"test_python_api_named_{os.getpid()}"

def main():
    with ProcessFixture() as fixture:
        result = run_tests(fixture)
    return result | run_unittest()


def frame(kind, payload=b''):
    return struct.pack('!II', kind, len(payload)) + payload


def reply(output='', status=0):
    # Independent v4 wire fixture: signed status followed by CLI session fields.
    return (frame(4, output.encode()) +
            frame(6, struct.pack('!i', status) + bytes(224)))


def snapshot(state='complete', run_id=7):
    return dict(schema_version=1, id=run_id, script='churn', state=state,
                error='', stats=[], peers=[])


class WireSocket:
    """A fragmented control stream; records sends, timeouts and ownership."""

    def __init__(self, data=b'', fragment=4096):
        self.data = data
        self.fragment = fragment
        self.sent = []
        self.closed = False
        self.timeouts = []

    def connect(self, path):
        pass

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

    def recv(self, size):
        size = min(size, self.fragment)
        data, self.data = self.data[:size], self.data[size:]
        return data

    def sendall(self, data):
        self.sent.append(data)

    def close(self):
        self.closed = True


class CheckedClientTests(unittest.TestCase):
    def client(self, *streams, fragment=4096, timeout=30):
        """A client over mocked sockets; each stream is one connection's data after its ACK."""
        socks = [WireSocket(frame(2, b'4') + data, fragment) for data in (streams or (b'',))]
        factory = patch.object(bgpsim.socket, 'socket', side_effect=socks)
        factory.start()
        self.addCleanup(factory.stop)
        client = bgpsim.connect(timeout=timeout)
        self.addCleanup(client.disconnect)
        return client, socks

    def test_reply_carries_status_not_output_words(self):
        client, (sock,) = self.client(frame(7, b'event') + reply('Error: benign text') +
                                      frame(5, b'rejected') + reply('', -2) +
                                      reply('raw rejection', -1) + reply(''), fragment=1)
        benign = client.cli('show log')
        self.assertIsInstance(benign, str)
        self.assertEqual((str(benign), benign.ok, benign.status, benign.error, benign.command,
                          benign.reconnected), ('Error: benign text', True, 0, '', 'show log', False))
        self.assertTrue(benign)
        rejected = client.cli('bad')
        self.assertEqual((str(rejected), rejected.ok, rejected.status, rejected.error,
                          rejected.command), ('rejected', False, -2, 'rejected', 'bad'))
        self.assertFalse(rejected)
        raw = client.cli('bad')
        self.assertEqual((raw.status, str(raw)), (-1, 'raw rejection'))
        empty = client.cli('config')
        self.assertEqual((str(empty), bool(empty), empty.ok, empty.status), ('', True, True, 0))
        self.assertFalse(sock.closed)
        self.assertEqual([f[8:] for f in sock.sent], [b'', b'show log', b'bad', b'bad', b'config'])

    def test_configure_returns_the_first_rejection_or_the_last_reply(self):
        client, (sock,) = self.client(reply() + reply('denied', -1) + reply('done'))
        rejected = client.configure(['config', 'bad', 'router bgp 65001'])
        self.assertEqual((rejected.command, rejected.status, str(rejected), bool(rejected)),
                         ('bad', -1, 'denied', False))
        self.assertEqual([f[8:] for f in sock.sent], [b'', b'config', b'bad'])
        self.assertTrue(client.connected)
        last = client.configure(['end'])
        self.assertEqual((last.command, str(last), bool(last)), ('end', 'done', True))
        self.assertTrue(client.configure([]))
        with self.assertRaises(ValueError):
            client.configure('config')

    def test_bad_frames_lose_the_command_and_the_next_call_reconnects(self):
        for data in (b'', frame(2), frame(6, b'\0'), frame(8, b'bad request'),
                     struct.pack('!II', 99, 0), struct.pack('!II', 4, 1048577),
                     frame(4, b'partial')[:-2]):
            with self.subTest(data=data):
                client, (sock, again) = self.client(data, reply() + reply())
                lost = client.cli('run script churn')
                self.assertEqual((str(lost), lost.ok, lost.status, lost.reconnected),
                                 ('', False, None, False))
                self.assertTrue(lost.error.endswith('; outcome unknown; not replayed'), lost.error)
                self.assertTrue(sock.closed)
                self.assertFalse(client.connected)
                self.assertEqual(len(sock.sent), 2)  # SYN and exactly one command.
                self.assertEqual(again.sent, [])     # No reconnect until the next call.
                after = client.cli('config')
                self.assertEqual((bool(after), after.reconnected), (True, True))
                self.assertEqual([f[8:] for f in again.sent], [b'', b'config'])
                self.assertFalse(client.cli('config').reconnected)

    def test_lost_show_is_replayed_once_on_a_new_connection(self):
        client, (first, second) = self.client(frame(4, b'partial')[:-2], reply('after'))
        got = client.cli('show log')
        self.assertEqual((str(got), got.ok, got.reconnected), ('after', True, True))
        self.assertEqual([f[8:] for f in first.sent], [b'', b'show log'])
        self.assertEqual([f[8:] for f in second.sent], [b'', b'show log'])
        self.assertTrue(first.closed)
        self.assertFalse(second.closed)
        self.assertTrue(client.connected)
        client, (first, second) = self.client(b'', b'')
        lost = client.cli('show log')
        self.assertEqual((lost.status, lost.reconnected), (None, True))
        self.assertTrue(lost.error.endswith('; outcome unknown; not replayed'), lost.error)
        self.assertEqual([len(first.sent), len(second.sent)], [2, 2])
        self.assertTrue(first.closed and second.closed)

    def test_partial_send_is_not_replayed(self):
        client, (sock, again) = self.client(b'', reply())
        sock.sendall = Mock(side_effect=BrokenPipeError('partial write'))
        lost = client.cli('config')
        self.assertEqual((lost.status, lost.error),
                         (None, 'partial write; outcome unknown; not replayed'))
        sock.sendall.assert_called_once()
        self.assertTrue(sock.closed)
        self.assertEqual(again.sent, [])

    def test_lost_show_without_a_server_is_an_error(self):
        first = WireSocket(frame(2, b'4'))
        def gone():
            sock = WireSocket()
            sock.connect = Mock(side_effect=FileNotFoundError())
            return sock
        now = [0.0]
        def sleep(seconds):
            now[0] += seconds
        with patch.object(bgpsim.socket, 'socket', side_effect=[first] + [gone() for _ in range(10)]), \
                patch.object(bgpsim.time, 'monotonic', side_effect=lambda: now[0]), \
                patch.object(bgpsim.time, 'sleep', side_effect=sleep):
            client = bgpsim.connect(timeout=.12)
            with self.assertRaises(bgpsim.Error) as caught:
                client.cli('show log')
        self.assertEqual((caught.exception.socket_path, caught.exception.reason),
                         ('/tmp/bgpsim.sock', 'missing after 0.12s'))
        self.assertEqual([f[8:] for f in first.sent], [b'', b'show log'])
        self.assertTrue(first.closed)
        self.assertFalse(client.connected)

    def test_only_absent_or_refused_sockets_are_waited_for(self):
        sockets = [WireSocket(), WireSocket(), WireSocket(frame(2, b'4'))]
        sockets[0].connect = Mock(side_effect=FileNotFoundError())
        sockets[1].connect = Mock(side_effect=ConnectionRefusedError())
        with patch.object(bgpsim.socket, 'socket', side_effect=sockets), \
                patch.object(bgpsim.time, 'sleep'):
            with bgpsim.connect(timeout=1) as client:
                self.assertTrue(client.connected)
        self.assertTrue(all(sock.closed for sock in sockets))
        for failure, reason in ((PermissionError(13, 'Permission denied'), 'Permission denied'),
                                (OSError('bad path'), 'bad path')):
            sock = WireSocket()
            sock.connect = Mock(side_effect=failure)
            with patch.object(bgpsim.socket, 'socket', return_value=sock) as factory:
                with self.assertRaises(bgpsim.Error) as caught:
                    bgpsim.connect(timeout=1)
            self.assertEqual((caught.exception.socket_path, caught.exception.reason),
                             ('/tmp/bgpsim.sock', reason))
            factory.assert_called_once()
            self.assertTrue(sock.closed)

    def test_handshake_failures_are_errors_and_not_retried(self):
        for data, reason in ((frame(2, b'3'), 'protocol version 3, expected 4'),
                             (frame(4, b'4'), 'unexpected handshake frame 4'),
                             (b'', 'handshake failed: Connection closed by bgpsim'),
                             (None, 'handshake timeout')):
            sock = WireSocket(data or b'')
            if data is None:
                sock.recv = Mock(side_effect=TimeoutError())
            with self.subTest(data=data), \
                    patch.object(bgpsim.socket, 'socket', return_value=sock) as factory:
                with self.assertRaises(bgpsim.Error) as caught:
                    bgpsim.connect(timeout=1)
                self.assertEqual(caught.exception.reason, reason)
                factory.assert_called_once()
                self.assertTrue(sock.closed)

    def test_missing_socket_is_an_error_naming_the_path(self):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        path = os.path.join(root.name, 'missing.sock')
        with self.assertRaises(bgpsim.Error) as caught:
            bgpsim.connect(socket_path=path, timeout=.05)
        self.assertEqual(caught.exception.socket_path, path)
        self.assertRegex(caught.exception.reason, r'^missing after 0\.\d+s$')
        self.assertIn(path, str(caught.exception))

    def test_wait_deadline_is_total(self):
        sock = WireSocket()
        sock.connect = Mock(side_effect=FileNotFoundError())
        now = [0.0]
        def sleep(seconds):
            now[0] += seconds
        with patch.object(bgpsim.socket, 'socket', return_value=sock), \
                patch.object(bgpsim.time, 'monotonic', side_effect=lambda: now[0]), \
                patch.object(bgpsim.time, 'sleep', side_effect=sleep):
            with self.assertRaises(bgpsim.Error) as caught:
                bgpsim.connect(timeout=.12)
        self.assertEqual((now[0], caught.exception.reason), (.12, 'missing after 0.12s'))
        self.assertTrue(sock.closed)

    def test_wait_budget_includes_fragmented_handshake(self):
        absent, ready = WireSocket(), WireSocket(frame(2, b'4'), 1)
        absent.connect = Mock(side_effect=FileNotFoundError())
        now = [0.0]
        def advance(seconds):
            now[0] += seconds
        read = ready.recv
        def slow_read(size):
            advance(.02)
            return read(size)
        ready.recv = slow_read
        with patch.object(bgpsim.socket, 'socket', side_effect=[absent, ready]) as factory, \
                patch.object(bgpsim.time, 'monotonic', side_effect=lambda: now[0]), \
                patch.object(bgpsim.time, 'sleep', side_effect=advance):
            with self.assertRaises(bgpsim.Error) as caught:
                bgpsim.connect(timeout=.08)
        self.assertEqual(caught.exception.reason, 'handshake timeout')
        self.assertEqual(factory.call_count, 2)
        self.assertTrue(absent.closed and ready.closed)

    def test_total_deadline_not_reset_by_fragments(self):
        client, (sock,) = self.client(reply('lots of output'), fragment=1)
        with patch.object(bgpsim.time, 'monotonic', side_effect=[0, 0, 0, .04, .08, .12, .12, .12]):
            lost = client.cli('show log', timeout=.1)
        self.assertEqual((lost.status, lost.error),
                         (None, 'deadline expired; outcome unknown; not replayed'))
        self.assertTrue(sock.closed)
        self.assertFalse(client.connected)
        self.assertAlmostEqual(sock.timeouts[-1], .02)

    def test_configure_has_one_deadline_for_all_commands(self):
        client, (sock,) = self.client(reply() * 3)
        clock = itertools.count(0, .01)
        with patch.object(bgpsim.time, 'monotonic', side_effect=lambda: next(clock)):
            lost = client.configure(['config', 'end', 'show log'], timeout=.15)
        self.assertEqual((lost.command, lost.status), ('show log', None))
        self.assertIn('deadline expired', lost.error)
        self.assertEqual([f[8:] for f in sock.sent], [b'', b'config', b'end', b'show log'])
        self.assertTrue(sock.closed)

    def test_real_socket_timeout_is_a_lost_reply(self):
        left, right = socket.socketpair()
        with right:
            client = bgpsim.BGPSimClient(socket_path='/nonexistent/bgpsim.sock', timeout=.02)
            client.sock, client.connected = left, True
            start = time.monotonic()
            lost = client.cli('config')
            self.assertLess(time.monotonic() - start, 1)
            self.assertEqual((lost.status, lost.error),
                             (None, 'deadline expired; outcome unknown; not replayed'))
            self.assertEqual(left.fileno(), -1)
            self.assertFalse(client.connected)

    def test_run_once_and_poll_exact_id(self):
        running, done = snapshot('running'), snapshot()
        done['stats'] = [{'transmit': {'samples': 1, 'total_ms': 17}}]
        client, (sock,) = self.client(reply(json.dumps(running)) + reply(json.dumps(done)))
        self.assertEqual(client.run_script('churn', poll_interval=.001), done)
        self.assertEqual([f[8:] for f in sock.sent[1:]],
                         [b'run script churn json repeat 1', b'show run 7 json'])
        client, (sock,) = self.client(reply(json.dumps(done)))
        self.assertEqual(client.run_script('churn'), done)
        self.assertEqual(len(sock.sent), 2)  # Already complete: no poll.

    def test_run_failure_and_cancel_are_returned_not_raised(self):
        for state in ('failed', 'cancelled'):
            result = snapshot(state)
            result['error'] = 'peer reset' if state == 'failed' else ''
            client, (sock,) = self.client(reply(json.dumps(result)))
            self.assertEqual(client.wait_run(7), result)
            self.assertEqual(len(sock.sent), 2)

    def test_run_schema_and_identity(self):
        invalid = ['not JSON', '[]', json.dumps(snapshot(run_id=8)),
                   json.dumps(dict(snapshot(), state='unknown')),
                   json.dumps(dict(snapshot(), schema_version=2))]
        for output in invalid:
            client, (sock,) = self.client(reply(output))
            self.assertIsNone(client.run_status(7))
            self.assertTrue(sock.closed)
        client, (sock,) = self.client(reply('no such run', -1))
        self.assertIsNone(client.run_status(999))
        self.assertFalse(sock.closed)  # A rejection keeps the connection.

    def test_rejected_or_lost_start_is_a_failed_snapshot_without_id(self):
        client, (sock,) = self.client(reply('Error: unknown script\n', -1))
        failed = client.run_script('bad')
        self.assertEqual(failed, dict(schema_version=1, id=None, script='bad', state='failed',
                                      error='Error: unknown script', peers=[], stats=[]))
        self.assertEqual([f[8:] for f in sock.sent], [b'', b'run script bad json repeat 1'])
        client, (sock, again) = self.client(frame(4, b'{')[:-1], reply())
        lost = client.start_script('churn')
        self.assertEqual((lost['id'], lost['state'], lost['script']), (None, 'failed', 'churn'))
        self.assertTrue(lost['error'].endswith('; outcome unknown; not replayed'), lost['error'])
        self.assertEqual(again.sent, [])

    def test_run_wait_deadline_returns_the_last_snapshot(self):
        running = snapshot('running')
        client, (sock,) = self.client(reply(json.dumps(running)) * 10)
        now = [0.0]
        def sleep(seconds):
            now[0] += seconds
        with patch.object(bgpsim.time, 'monotonic', side_effect=lambda: now[0]), \
                patch.object(bgpsim.time, 'sleep', side_effect=sleep):
            self.assertEqual(client.run_script('churn', timeout=.12, poll_interval=.05), running)
        self.assertEqual(now[0], .12)
        self.assertEqual([f[8:] for f in sock.sent[1:]],
                         [b'run script churn json repeat 1',
                          b'show run 7 json', b'show run 7 json'])
        self.assertTrue(client.connected)  # The unsent third poll did not cost the session.

    def test_stalled_run_poll_returns_the_last_snapshot(self):
        running = snapshot('running')
        client, (first, second) = self.client(reply(json.dumps(running)), b'')
        for sock in (first, second):
            def recv(size, sock=sock, read=sock.recv):
                if not sock.data:
                    raise socket.timeout('stalled poll')
                return read(size)
            sock.recv = recv
        self.assertEqual(client.run_script('churn', poll_interval=.001), running)
        self.assertEqual([f[8:] for f in first.sent[1:]],
                         [b'run script churn json repeat 1', b'show run 7 json'])
        self.assertEqual([f[8:] for f in second.sent], [b'', b'show run 7 json'])
        self.assertTrue(first.closed and second.closed)
        self.assertFalse(client.connected)

    def test_invalid_options_do_not_send(self):
        for value in (-1, 0, float('nan'), float('inf'), True):
            with self.assertRaises(ValueError):
                bgpsim.BGPSimClient(timeout=value)
        client, (sock,) = self.client()
        for name in ('a b', 'x\nconfig', 'a' * 64):
            with self.assertRaises(ValueError):
                client.start_script(name)
        for run_id in (0, -1, True, 2**32, '7'):
            with self.assertRaises(ValueError):
                client.run_status(run_id)
        with self.assertRaisesRegex(ValueError, 'repeat'):
            client.start_script('churn', repeat=0)
        for command in (None, 'config\nend', 'quit\x00config'):
            with self.assertRaises(ValueError):
                client.cli(command)
        self.assertEqual(len(sock.sent), 1)


class LiveClientTests(unittest.TestCase):
    def setUp(self):
        self.resources = ExitStack()
        self.addCleanup(self.resources.close)
        self.fixture = self.resources.enter_context(ProcessFixture())
        self.session = f'client_contract_{os.getpid()}'
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            self.port = probe.getsockname()[1]
        self.assertTrue(self.start_server('server.log'))
        self.client = self.resources.enter_context(bgpsim.connect(self.session, timeout=2))

    def start_server(self, log_name):
        return self.fixture.start_session(
            self.session, passive=True, log_path=self.fixture.root / log_name,
            env={'BGPSIM_LISTEN_BASE_PORT': str(self.port)})

    def test_config_context_partial_failure_and_generation(self):
        c = self.client
        rejected = c.configure(['config', 'ribout blue', 'prefix 10.0.0.0/24',
                                'invalid-command', 'next-hop 192.0.2.9'])
        self.assertEqual((rejected.command, rejected.ok), ('invalid-command', False))
        self.assertLess(rejected.status, 0)
        self.assertIn('Unknown', rejected.error)
        self.assertTrue(c.cli('next-hop 192.0.2.1'))  # Still in the same ribout context.
        config = c.cli('show running-config')
        self.assertIn('prefix 10.0.0.0/24', config)
        self.assertIn('next-hop 192.0.2.1', config)
        self.assertNotIn('192.0.2.9', config)
        self.assertTrue(c.configure(['rd 65000:1', 'end']))  # VPN needs a label.
        generate = c.cli('update generate')
        self.assertFalse(generate)
        self.assertLess(generate.status, 0)
        self.assertTrue(generate.error)
        self.assertTrue(c.configure(['config', 'ribout blue', 'label 100', 'end']))
        self.assertTrue(c.cli('update generate changed'))

    def test_server_restart_reconnects_and_resets_the_cli_mode(self):
        c = self.client
        self.assertTrue(c.configure(['config', 'router bgp 65001']))
        self.fixture.stop_session(self.session)
        self.assertTrue(self.start_server('restart.log'))
        summary = c.cli('show bgp summary')
        self.assertEqual((summary.ok, summary.reconnected), (True, True), summary.error)
        self.assertIn('BGP', summary)
        neighbor = c.cli('neighbor 192.0.2.2 remote-as 65002')  # Exec mode again.
        self.assertEqual((neighbor.ok, neighbor.reconnected), (False, False))
        self.assertLess(neighbor.status, 0)
        self.assertNotIn('router bgp 65001', c.cli('show running-config').splitlines())

    def test_real_json_run_lifecycle_and_timing(self):
        c = self.client
        self.assertTrue(c.configure(['config', 'script short', 'sleep 1ms', 'script long',
                                     'sleep 10s', 'script bad',
                                     'advertise ribout missing peer all', 'end']))
        long = c.start_script('long')
        done = c.run_script('short', repeat=2, poll_interval=.001)
        self.assertNotEqual(long['id'], done['id'])
        self.assertEqual((done['script'], done['state'], done['iteration'],
                          done['repeat']), ('short', 'complete', 2, 2))
        self.assertTrue(done['engine_connected'])
        self.assertEqual(done['peers'], [])
        self.assertEqual(done['stats'][0]['sleep']['samples'], 2)
        self.assertGreaterEqual(done['stats'][0]['sleep']['total_ms'], 2)
        self.assertEqual(done, c.wait_run(done['id']))
        # Parse the binary's JSON directly, independently of the client helper.
        self.assertEqual(done, json.loads(c.cli(f"show run {done['id']} json")))
        still = c.wait_run(long['id'], timeout=.01)
        self.assertEqual((still['id'], still['state']), (long['id'], 'running'))
        with bgpsim.connect(self.session) as other:
            self.assertEqual(other.run_status(long['id'])['state'], 'running')
            self.assertTrue(other.cli(f"cancel run {long['id']}"))
            self.assertEqual(other.wait_run(long['id'])['state'], 'cancelled')
            bad = other.run_script('bad', poll_interval=.001)
            self.assertEqual((bad['state'], bad['script']), ('failed', 'bad'))
            self.assertIsInstance(bad['id'], int)
            self.assertTrue(bad['error'])
            missing = other.run_script('nonexistent')
            self.assertEqual((missing['id'], missing['state']), (None, 'failed'))
            self.assertTrue(missing['error'])
            self.assertIsNone(other.run_status(4294967295))

    def test_run_completion_matches_real_update_and_withdrawal(self):
        c = self.client
        self.assertTrue(c.configure(['config', 'router bgp 65001', 'router-id 192.0.2.1',
                                     'neighbor 127.0.0.1 remote-as 65002', 'ribout blue',
                                     'prefix 10.0.0.0/24', 'next-hop 192.0.2.1',
                                     'script announce', 'advertise ribout blue peer all',
                                     'script remove', 'withdraw ribout blue peer all', 'end']))
        self.assertTrue(c.cli('update generate'))
        wire = self.resources.enter_context(
            socket.create_connection(('127.0.0.1', self.port), 2))
        def read(size):
            data = b''
            while len(data) < size:
                part = wire.recv(size - len(data))
                self.assertTrue(part, 'BGP connection closed')
                data += part
            return data
        def message():
            header = read(19)
            return header + read(struct.unpack_from('!H', header, 16)[0] - 19)
        self.assertEqual(message()[18], 1)  # OPEN from the real simulator.
        # The generator uses a four-octet AS_PATH; negotiate that capability.
        caps = bytes([2, 6, 65, 4]) + struct.pack('!I', 65002)
        wire.sendall(b'\xff' * 16 + struct.pack('!HB', 29 + len(caps), 1) +
                     struct.pack('!BHH4sB', 4, 65002, 90,
                                b'\xc0\x00\x02\x02', len(caps)) + caps)
        self.assertEqual(message()[18], 4)
        wire.sendall(b'\xff' * 16 + struct.pack('!HB', 19, 4))
        self.assertTrue(wait_until(
            lambda: 'BGP state = Established' in c.cli('show bgp neighbors'), 2))
        self.assertEqual(update_nlri(message()), ({}, {}))  # Initial IPv4 EOR.
        for script, expected in [('announce', ({(1, 1): [b'\x18\x0a\x00\x00']}, {})),
                                 ('remove', ({}, {(1, 1): [b'\x18\x0a\x00\x00']}))]:
            done = c.run_script(script, poll_interval=.001)
            self.assertEqual(done['state'], 'complete')
            self.assertEqual(len(done['peers']), 1)
            peer = done['peers'][0]
            self.assertEqual((peer['state'], peer['messages_done'], peer['messages_total']),
                             ('complete', 1, 1), peer)
            update = message()
            self.assertEqual(update_nlri(update), expected)
            self.assertEqual(peer['bytes_done'], len(update))
            self.assertEqual(peer['bytes_total'], len(update))
            self.assertEqual(done['stats'][0]['transmit']['samples'], 1)


def run_tests(fixture):
    # Initialize test runner
    runner = TestRunner()

    default_log = fixture.root / 'default.log'
    named_log = fixture.root / 'named.log'

    # Start test session
    if not fixture.start_session(DEFAULT_SESSION, log_path=default_log):
        runner.test_fail("Failed to start test session")
        return 1

    # ==========================================
    # TEST GROUP 1: Connection Methods
    # ==========================================

    # Test 1.1: Default connection
    try:
        client = bgpsim.connect()
        assert client.connected
        assert client.socket_path == '/tmp/bgpsim.sock'
        client.disconnect()
        runner.test_pass("connect() with no args connects to default session")
    except Exception as e:
        runner.test_fail("Default connection failed", str(e))

    # Test 1.2: Named session connection
    assert fixture.start_session(NAMED_SESSION, log_path=named_log)
    try:
        client = bgpsim.connect(NAMED_SESSION)
        assert client.connected
        assert client.socket_path == f'/tmp/bgpsim_{NAMED_SESSION}.sock'
        client.disconnect()
        runner.test_pass("connect('test') connects to named session")
    except Exception as e:
        runner.test_fail("Named session connection failed", str(e))

    # Test 1.3: Explicit socket path
    try:
        client = bgpsim.connect(socket_path='/tmp/bgpsim.sock')
        assert client.connected
        client.disconnect()
        runner.test_pass("connect(socket_path=...) uses explicit path")
    except Exception as e:
        runner.test_fail("Explicit socket path failed", str(e))

    # Test 1.4: Invalid session
    try:
        bgpsim.connect(f'{NAMED_SESSION}_missing', timeout=.2)
        runner.test_fail("Should raise bgpsim.Error for non-existent session")
    except bgpsim.Error as e:
        if (e.socket_path == f'/tmp/bgpsim_{NAMED_SESSION}_missing.sock' and
                e.reason.startswith('missing after') and e.socket_path in str(e)):
            runner.test_pass("Non-existent session raises bgpsim.Error naming the socket")
        else:
            runner.test_fail("bgpsim.Error without the socket path and reason", str(e))
    except Exception as e:
        runner.test_fail("Wrong exception type", str(e))

    # ==========================================
    # TEST GROUP 2: CLI Command Execution
    # ==========================================

    client = bgpsim.connect(DEFAULT_SESSION)

    # Test 2.1: Show commands
    try:
        output = client.cli("show bgp summary")
        if isinstance(output, str) and 'BGP' in output:
            runner.test_pass("cli() returns string output")
        else:
            runner.test_fail("cli() returned non-string", type(output))
    except Exception as e:
        runner.test_fail("Show command failed", str(e))

    # Test 2.2: Configuration commands (stateful)
    try:
        client.cli("config")
        client.cli("router bgp 65100")
        client.cli("exit")
        assert 'router bgp 65100' in client.cli('show running-config').splitlines()
        runner.test_pass("Configuration commands execute")
    except Exception as e:
        runner.test_fail("Configuration commands failed", str(e))

    # Test 2.3: Verify configuration persists
    try:
        output = client.cli("show running-config")
        if '65100' in output:
            runner.test_pass("Configuration persists across commands")
        else:
            runner.test_fail("Configuration not persisted", output)
    except Exception as e:
        runner.test_fail("Config verification failed", str(e))

    # Test 2.4: Multiple commands in sequence (mode stack rewinding)
    try:
        client.cli("config")
        client.cli("router bgp 65101")  # Enters router mode
        client.cli("router bgp 65102")  # Rewinds and enters new router mode
        client.cli("router bgp 65103")  # Rewinds and enters new router mode
        client.cli("exit")  # Exit to exec mode
        output = client.cli("show running-config")
        if '65101' in output and '65102' in output and '65103' in output:
            runner.test_pass("Multiple sequential commands work")
        else:
            runner.test_fail("Sequential commands incomplete")
    except Exception as e:
        runner.test_fail("Sequential commands failed", str(e))

    # Test 2.5: Empty command
    try:
        before = client.cli('show running-config')
        output = client.cli("")
        assert output == '' and client.cli('show running-config') == before
        runner.test_pass("Empty command handled gracefully")
    except Exception as e:
        runner.test_fail("Empty command crashed", str(e))

    # Unsupported punctuation is a rejection, not an accepted comment command.
    try:
        before = client.cli('show running-config')
        rejected = client.cli("! This is a comment")
        assert not rejected and rejected.status < 0 and 'Unknown' in rejected.error
        assert client.cli('show running-config') == before
        runner.test_pass("Unsupported punctuation reports rejection without changing configuration")
    except Exception as e:
        runner.test_fail("Special chars crashed", str(e))

    # Disconnect client before context manager tests (server handles one client at a time)
    client.disconnect()

    # ==========================================
    # TEST GROUP 3: Context Manager
    # ==========================================

    # Test 3.1: Basic context manager
    try:
        with bgpsim.connect(DEFAULT_SESSION) as ctx_client:
            output = ctx_client.cli("show bgp summary")
            if output and 'BGP' in output:
                runner.test_pass("Context manager __enter__ works")
            else:
                runner.test_fail("Context manager returned no output")
    except Exception as e:
        runner.test_fail("Context manager failed", str(e))

    # Test 3.2: Context manager cleanup
    try:
        with bgpsim.connect(DEFAULT_SESSION) as ctx_client:
            sock = ctx_client.sock
            assert sock.fileno() >= 0
        assert not ctx_client.connected and ctx_client.sock is None and sock.fileno() == -1
        runner.test_pass("Context manager __exit__ works")
    except Exception as e:
        runner.test_fail("Context manager exit failed", str(e))

    # Test 3.3: Exception in context manager
    try:
        exception_raised = False
        with bgpsim.connect(DEFAULT_SESSION) as ctx_client:
            raise ValueError("Test exception")
    except ValueError:
        exception_raised = True
        assert not ctx_client.connected and ctx_client.sock is None
        runner.test_pass("Context manager propagates exceptions")

    if not exception_raised:
        runner.test_fail("Context manager swallowed exception")

    # ==========================================
    # TEST GROUP 4: Output Handling
    # ==========================================

    # Create new connection for output tests
    client = bgpsim.connect(DEFAULT_SESSION)

    # Test 4.1: Large output
    try:
        # Cross multiple control frames; verify every record, not a size heuristic.
        client.cli("config")
        for i in range(10):
            client.cli(f"router bgp {65000 + i}")  # Auto-rewinds
            for peer in range(1, 13):
                client.cli(f"neighbor 192.0.{i}.{peer} remote-as {66000 + i}")
        client.cli("exit")

        output = client.cli("show running-config")
        expected = {f'neighbor 192.0.{i}.{peer} remote-as {66000 + i}'
                    for i in range(10) for peer in range(1, 13)}
        actual = {line.strip() for line in output.splitlines()}
        if len(output) > 4096 and expected <= actual:
            runner.test_pass("Large output handled correctly")
        else:
            runner.test_fail("Large output truncated", f"Length: {len(output)}")
    except Exception as e:
        runner.test_fail("Large output failed", str(e))

    # Test 4.2: Empty output
    try:
        output = client.cli("show log")  # May have empty output
        if isinstance(output, str):
            runner.test_pass("Empty output handled as string")
        else:
            runner.test_fail("Empty output wrong type")
    except Exception as e:
        runner.test_fail("Empty output crashed", str(e))

    # Test 4.3: Output with newlines
    try:
        output = client.cli("show running-config")
        if len(output.splitlines()) > 10 and all(
                f'router bgp {65000 + i}' in output.splitlines() for i in range(10)):
            runner.test_pass("Multi-line output preserved")
        else:
            runner.test_fail("Expected multiline running-config with every configured router", output)
    except Exception as e:
        runner.test_fail("Multi-line output failed", str(e))

    # Disconnect before new connection tests
    client.disconnect()

    # ==========================================
    # TEST GROUP 5: Connection State
    # ==========================================

    # Test 5.1: Multiple commands on same connection (mode rewinding)
    try:
        client = bgpsim.connect(DEFAULT_SESSION)
        client.cli("config")
        client.cli("router bgp 65200")  # Enters router mode
        client.cli("router bgp 65201")  # Rewinds and enters new router mode
        client.cli("exit")
        output = client.cli("show running-config")
        if '65200' in output and '65201' in output:
            runner.test_pass("Connection state maintained across calls")
        else:
            runner.test_fail("Connection state lost")
    except Exception as e:
        runner.test_fail("Connection state test failed", str(e))

    # Test 5.2: Reconnection after server restart
    client.disconnect()
    fixture.stop_session(DEFAULT_SESSION)
    fixture.stop_session(NAMED_SESSION)
    assert fixture.start_session(DEFAULT_SESSION, log_path=default_log)

    try:
        with bgpsim.connect(DEFAULT_SESSION) as new_client:
            output = new_client.cli("show bgp summary")
            assert 'BGP' in output and new_client.connected
            assert 'router bgp 65200' not in new_client.cli('show running-config').splitlines()
        runner.test_pass("Reconnection after restart works")
    except Exception as e:
        runner.test_fail("Reconnection failed", str(e))

    # ==========================================
    # TEST GROUP 6: Command-Line Interface
    # ==========================================

    # Test 6.1: CLI with default session
    try:
        bgpsim_py = bgpsim.__file__

        result = fixture.run(
            [sys.executable, bgpsim_py, 'show bgp summary'],
            timeout=5
        )
        if result.returncode == 0 and 'BGP' in result.stdout and not result.stderr:
            runner.test_pass("CLI with default session works")
        else:
            runner.test_fail("CLI default session failed", result.stderr)
    except Exception as e:
        runner.test_fail("CLI execution failed", str(e))

    # Test 6.2: CLI with named session
    assert fixture.start_session(NAMED_SESSION, log_path=named_log)
    try:
        bgpsim_py = bgpsim.__file__

        result = fixture.run(
            [sys.executable, bgpsim_py, '-s', NAMED_SESSION, 'show bgp summary'],
            timeout=5
        )
        if result.returncode == 0 and 'BGP' in result.stdout and not result.stderr:
            runner.test_pass("CLI with named session works")
        else:
            runner.test_fail("CLI named session failed", result.stderr)
    except Exception as e:
        runner.test_fail("CLI named session execution failed", str(e))

    # Test 6.3: CLI with non-existent session
    try:
        bgpsim_py = bgpsim.__file__

        result = fixture.run(
            [sys.executable, bgpsim_py, '-s', f'{NAMED_SESSION}_missing', '-t', '1',
             'show bgp summary'],
            timeout=5
        )
        if (result.returncode == 2 and not result.stdout and
                f'/tmp/bgpsim_{NAMED_SESSION}_missing.sock' in result.stderr):
            runner.test_pass("CLI exits 2 for a non-existent session and names the socket")
        else:
            runner.test_fail("CLI non-existent session handling", f"{result.returncode} {result.stderr}")
    except Exception as e:
        runner.test_fail("CLI error handling failed", str(e))

    # Test 6.4: CLI with a rejected command
    try:
        result = fixture.run(
            [sys.executable, bgpsim_py, '-s', NAMED_SESSION, 'invalid_command_xyz'],
            timeout=5
        )
        if result.returncode == 1 and not result.stdout and 'Unknown' in result.stderr:
            runner.test_pass("CLI exits 1 for a rejected command with the text on stderr")
        else:
            runner.test_fail("CLI rejected command handling", f"{result.returncode} {result.stderr}")
    except Exception as e:
        runner.test_fail("CLI rejected command execution failed", str(e))

    # ==========================================
    # TEST GROUP 7: Performance
    # ==========================================

    # Create new connection for performance tests
    client = bgpsim.connect(DEFAULT_SESSION)

    # Test 7.1: Rapid sequential commands
    try:
        start = time.monotonic()
        for i in range(50):
            assert 'BGP' in client.cli("show bgp summary")
        elapsed = time.monotonic() - start

        if elapsed < 10:  # Should complete quickly
            runner.test_pass(f"50 commands in {elapsed:.2f}s")
        else:
            runner.test_fail(f"Performance slow: {elapsed:.2f}s")
    except Exception as e:
        runner.test_fail("Rapid commands failed", str(e))

    # Rejection must leave configuration intact and the same socket usable.
    try:
        before = client.cli('show running-config')
        rejected = client.cli('invalid_command_xyz')
        assert not rejected and rejected.status < 0 and 'Unknown' in rejected.error
        assert client.cli('show running-config') == before
        assert 'BGP' in client.cli('show bgp summary')
        runner.test_pass('Invalid command reports rejection, preserves state and allows recovery')
    except Exception as e:
        runner.test_fail('Invalid command rejection/recovery failed', str(e))

    client.disconnect()

    return runner.summary()

if __name__ == '__main__':
    sys.exit(main())
