#!/usr/bin/env python3
"""
Router and VRF command scopes against the real executable, on every system.

The peers are bgp_test_client processes: their logs are independent evidence of which router reached them and which
UPDATEs arrived. VrfTestCase is also the base of the namespace cases in test_vrf_namespaces.py, which run in a lane
of their own.
"""

from contextlib import ExitStack
import os
import re
import sys
import time

from test_common import ControlCase, ProcessFixture, available_port, bgpsim, peer_listening, read_log
from test_results import run_unittest

EOR_BYTES = 23  # An End-of-RIB UPDATE: every longer UPDATE carries routes.
PEER_AS = 65100
LINUX = sys.platform.startswith('linux')


class Peer:
    def __init__(self, process, log):
        self.process = process
        self.log = log

    def text(self):
        return read_log(self.log)

    def routes(self):
        """How many UPDATEs with routes arrived."""
        sizes = re.findall(r'Received UPDATE: (\d+) bytes', self.text())
        return sum(int(size) > EOR_BYTES for size in sizes)


class VrfTestCase(ControlCase):
    WAIT_SECS = 30  # Longer than the longest reconnect interval (16 s).
    passive = False
    ports = 3

    def setUp(self):
        self.resources = ExitStack()
        self.addCleanup(self.resources.close)
        self.fixture = self.resources.enter_context(ProcessFixture())
        self.peers = 0
        self.session = f'vrf_{os.getpid()}'
        self.port = available_port(self.ports)
        self.server_log = self.fixture.root / 'server.log'
        self.assertTrue(self.fixture.start_session(
            self.session, passive=self.passive, log_path=self.server_log,
            env={'BGPSIM_LISTEN_BASE_PORT': str(self.port)}))
        self.client = self.resources.enter_context(bgpsim.connect(self.session, timeout=60))

    def generate_blue(self):
        self.configure('ribout blue', 'prefix 10.0.0.0/24', 'next-hop 192.0.2.1')
        self.assertTrue(self.client.cli('update generate'))

    def start_peer(self, address, port, namespace=None, active=False, wait=True):
        self.peers += 1
        log = self.fixture.root / f'peer-{self.peers}.log'
        process = self.fixture.start_peer(address, port, PEER_AS, log, active=active, four_octet=True,
                                          namespace=namespace)
        peer = Peer(process, log)
        if wait and not active:
           self.wait_listening(peer)
        return peer

    def wait_listening(self, peer):
        self.assertTrue(peer_listening(peer.process, peer.log), peer.text())

    def established(self, count):
        def reached():
            return self.client.cli('show bgp neighbors').count('BGP state = Established') == count
        self.reaches(reached, lambda: self.client.cli('show bgp neighbors'))

    def opened_by(self, peer, local_as):
        """The peer received the OPEN of this router: nothing else can have reached its namespace."""
        self.reaches(lambda: 'Received OPEN: ' in peer.text(), peer.text)
        self.assertEqual(re.findall(r'Received OPEN: AS=(\d+)', peer.text()), [str(local_as)])

    def expect_routes(self, *expected):
        """Exact counts per peer. The counts accumulate, so a stray UPDATE fails this or a later check."""
        self.reaches(lambda: all(peer.routes() >= count for peer, count in expected),
                     lambda: [peer.routes() for peer, _ in expected], within=10)
        self.assertEqual([peer.routes() for peer, _ in expected], [count for _, count in expected])

    def rejected(self, command, text):
        reply = self.client.cli(command)
        self.assertFalse(reply, command)
        self.assertIn(text, reply.error)
        return reply


class ScopeTests(VrfTestCase):
    """Runs everywhere: every router here stays in bgpsim's own namespace, or cannot open its VRF."""

    def two_routers(self):
        first = self.start_peer('127.0.0.1', self.port)
        second = self.start_peer('127.0.0.1', self.port + 1)
        self.configure(
            'router bgp 65001',
                f'neighbor 127.0.0.1 remote-as {PEER_AS}',
            'router bgp 65002',
                f'neighbor 127.0.0.1 remote-as {PEER_AS}')
        self.generate_blue()
        self.established(2)
        self.opened_by(first, 65001)
        self.opened_by(second, 65002)
        return first, second

    def test_scope_selects_routers_and_one_operation_spans_them(self):
        first, second = self.two_routers()

        reply = self.cli('advertise ribout blue router 65001 peer all')
        self.assertIn('(router 65001)', reply)
        self.assertNotIn('(router 65002)', reply)
        self.expect_routes((first, 1), (second, 0))

        # All or nothing across routers: the second peer never had the ribout, so the first stays bound.
        self.rejected('withdraw ribout blue vrf default peer 127.0.0.1', 'rejected by 127.0.0.1')
        self.cli('withdraw ribout blue router 65001 neighbor 127.0.0.1')
        self.expect_routes((first, 2), (second, 0))

        reply = self.cli('advertise ribout blue vrf all peer all')
        self.assertIn('(router 65001)', reply)
        self.assertIn('(router 65002)', reply)
        self.expect_routes((first, 3), (second, 1))

        self.configure('script span', 'withdraw ribout blue vrf default neighbor 127.0.0.1')
        done = self.client.run_script('span', timeout=10, poll_interval=.01)
        self.assertEqual(done['state'], 'complete', done)
        self.assertEqual(sorted((p['router_as'], p['peer'], p['messages_done']) for p in done['peers']),
                         [(65001, '127.0.0.1', 1), (65002, '127.0.0.1', 1)])
        self.assertEqual([step['transmit']['samples'] for step in done['stats']], [1])
        self.expect_routes((first, 4), (second, 2))

        self.rejected('advertise ribout blue peer all',
                      'several routers are configured: name a scope, router <AS> or vrf <name|all|default>')
        self.rejected('advertise ribout blue neighbor 127.0.0.1',
                      'neighbor 127.0.0.1 is on several routers: name a scope, router <AS> or vrf <name|all|default>')
        self.rejected('advertise ribout blue vrf NOPE peer all', 'no router is in vrf NOPE')
        self.assertFalse(self.client.cli('advertise ribout blue peer all router 65001'))
        self.cli('advertise ribout blue vrf default peer all')
        self.expect_routes((first, 5), (second, 3))
        self.cli('withdraw all vrf all neighbor all')
        self.expect_routes((first, 6), (second, 4))

    def test_unavailable_vrf_keeps_its_peers_down_and_says_why(self):
        first = self.start_peer('127.0.0.1', self.port)
        missing = f'bgpsim-missing-{os.getpid()}'
        error = 'no such file or directory' if LINUX else 'operation not supported on socket'
        self.configure(
            'router bgp 65001',
                f'neighbor 127.0.0.1 remote-as {PEER_AS}',
            'router bgp 65002',
                f'vrf {missing}',
                f'neighbor 127.0.0.1 remote-as {PEER_AS}')
        self.generate_blue()
        line = f'VRF {missing} is not available ({error}), retrying'
        self.reaches(lambda: line in self.client.cli('show bgp summary'), lambda: self.client.cli('show bgp summary'),
                     within=10)
        self.assertIn(f'local AS number 65002, VRF {missing}\n', self.client.cli('show bgp summary'))
        self.established(1)
        self.opened_by(first, 65001)

        # The first retry comes 4 s after the first failure: the error must still be logged only once.
        retried = time.monotonic() + 4.5
        self.reaches(lambda: time.monotonic() >= retried, 'the time of the first retry did not come', within=6)
        self.assertEqual(read_log(self.server_log).count(f'cannot open a socket in VRF {missing}'), 1)

        reply = self.cli(f'advertise ribout blue vrf {missing} peer all')
        self.assertIn('skipped 127.0.0.1: session not established', reply)
        self.rejected(f'advertise ribout blue vrf {missing} peer 127.0.0.1', 'session not established')
        self.cli('advertise ribout blue vrf default peer all')
        self.expect_routes((first, 1))

        # Leaving the VRF clears the error, and the peer connects from the own namespace.
        second = self.start_peer('127.0.0.1', self.port + 1)
        self.configure('router bgp 65002', 'no vrf')
        self.established(2)
        self.opened_by(second, 65002)
        summary = self.client.cli('show bgp summary')
        self.assertNotIn('is not available', summary)
        self.assertNotIn(', VRF ', summary)

    def test_update_source_failure_is_visible_and_recovers(self):
        peer = self.start_peer('127.0.0.1', self.port)
        self.configure('router bgp 65001', 'update-source 192.0.2.77', f'neighbor 127.0.0.1 remote-as {PEER_AS}')
        line = 'Update-source 192.0.2.77 is not usable (address not available), retrying'
        self.reaches(lambda: line in self.client.cli('show bgp neighbors'),
                     lambda: self.client.cli('show bgp neighbors'), within=10)
        self.assertEqual(read_log(self.server_log).count('cannot bind update-source'), 1)
        self.assertNotIn('Accepted connection', peer.text())

        self.configure('router bgp 65001', 'no update-source 192.0.2.77')
        self.established(1)
        self.opened_by(peer, 65001)
        self.assertNotIn('is not usable', self.client.cli('show bgp neighbors'))


if __name__ == '__main__':
   raise SystemExit(run_unittest())
