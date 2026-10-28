#!/usr/bin/env python3
"""
VRFs and command scopes against the real executable.

The peers are bgp_test_client processes: their logs are independent evidence of which router reached which namespace
and which UPDATEs arrived. bgpsim only opens namespaces, so this test creates them, as a lab would.
"""

from contextlib import ExitStack
import os
import re
import shutil
import socket
import subprocess
import sys
import time

from test_common import (
    ControlCase, ProcessFixture, available_port, bgpsim, peer_listening, read_log, wait_until,
)
from test_results import run_unittest

EOR_BYTES = 23  # An End-of-RIB UPDATE: every longer UPDATE carries routes.
PEER_AS = 65100
VRF_COUNT = 300
FIRST_VRF_AS = 61000  # Two-octet, so a peer's OPEN log shows the AS itself.
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


class NamespaceTestCase(VrfTestCase):
    def setUp(self):
        if not LINUX:
           self.skipTest('network namespaces need Linux')
        if os.geteuid() != 0 or not shutil.which('ip'):
           self.skipTest('needs root and the ip command to create namespaces')
        super().setUp()
        self.namespaces = self.fixture.namespaces()

    def name(self, label):
        return f'bgpsim-{os.getpid()}-{label}'

    def add_namespace(self, name, *addresses):
        self.namespaces.add(name, *addresses)


class NamespaceTests(NamespaceTestCase):
    def test_same_address_reaches_a_different_peer_in_each_namespace(self):
        blue, red = self.name('blue'), self.name('red')
        self.add_namespace(blue, '10.99.0.2')
        self.add_namespace(red, '10.99.0.2')
        own = self.start_peer('127.0.0.1', self.port + 2)
        in_blue = self.start_peer('10.99.0.2', 179, blue)
        in_red = self.start_peer('10.99.0.2', 179, red)
        # The own router comes last: its socket must land back in bgpsim's namespace after the VRF sockets.
        self.configure(
            'router bgp 65002',
                f'vrf {blue}',
                f'neighbor 10.99.0.2 remote-as {PEER_AS}',
            'router bgp 65003',
                f'vrf {red}',
                f'neighbor 10.99.0.2 remote-as {PEER_AS}',
            'router bgp 65001',
                f'neighbor 127.0.0.1 remote-as {PEER_AS}')
        self.generate_blue()
        self.established(3)
        self.opened_by(own, 65001)
        self.opened_by(in_blue, 65002)
        self.opened_by(in_red, 65003)
        summary = self.client.cli('show bgp summary')
        self.assertIn('local AS number 65001\n', summary)
        self.assertIn(f'local AS number 65002, VRF {blue}\n', summary)
        self.assertIn(f'local AS number 65003, VRF {red}\n', summary)
        self.assertNotIn('is not available', summary)

        reply = self.cli(f'advertise ribout blue vrf {blue} peer all')
        self.assertIn('(router 65002)', reply)
        self.assertNotIn('(router 65003)', reply)
        self.expect_routes((own, 0), (in_blue, 1), (in_red, 0))
        self.cli('advertise ribout blue vrf default peer all')
        self.expect_routes((own, 1), (in_blue, 1), (in_red, 0))
        self.cli('advertise ribout blue router 65003 neighbor 10.99.0.2')
        self.expect_routes((own, 1), (in_blue, 1), (in_red, 1))
        self.cli('withdraw ribout blue vrf all peer all')
        self.expect_routes((own, 2), (in_blue, 2), (in_red, 2))

        self.configure('script span', 'advertise ribout blue vrf all peer all')
        done = self.client.run_script('span', timeout=10, poll_interval=.01)
        self.assertEqual(done['state'], 'complete', done)
        self.assertEqual(sorted((p['router_as'], p['peer']) for p in done['peers']),
                         [(65001, '127.0.0.1'), (65002, '10.99.0.2'), (65003, '10.99.0.2')])
        self.expect_routes((own, 3), (in_blue, 3), (in_red, 3))

        self.cli(f'clear bgp vrf {blue} 10.99.0.2')
        self.assertIn('Session resets: 1', self.client.cli('show bgp neighbors 65002'))
        self.assertNotIn('Session resets', self.client.cli('show bgp neighbors 65003'))
        self.assertIn('BGP state = Established', self.client.cli('show bgp neighbors 65003'))

    def test_namespace_created_later_is_picked_up_by_the_retry(self):
        late = self.name('late')
        self.configure('router bgp 65001', f'vrf {late}', f'neighbor 10.99.0.2 remote-as {PEER_AS}')
        line = f'VRF {late} is not available (no such file or directory), retrying'
        self.reaches(lambda: line in self.client.cli('show bgp summary'), lambda: self.client.cli('show bgp summary'),
                     within=10)
        self.add_namespace(late, '10.99.0.2')
        peer = self.start_peer('10.99.0.2', 179, late)
        self.established(1)
        self.opened_by(peer, 65001)
        self.assertNotIn('is not available', self.client.cli('show bgp summary'))

    def test_recreated_namespace_is_opened_again_by_name(self):
        name = self.name('again')
        self.add_namespace(name, '10.99.0.2')
        first = self.start_peer('10.99.0.2', 179, name)
        self.configure('router bgp 65001', f'vrf {name}', f'neighbor 10.99.0.2 remote-as {PEER_AS}')
        self.established(1)
        self.opened_by(first, 65001)

        self.fixture.stop_process(first.process)
        self.established(0)
        self.namespaces.delete(name)
        self.add_namespace(name, '10.99.0.2')
        second = self.start_peer('10.99.0.2', 179, name)
        self.established(1)
        self.opened_by(second, 65001)

    def test_no_vrf_moves_live_sessions_to_the_own_namespace(self):
        name = self.name('move')
        self.add_namespace(name)
        in_vrf = self.start_peer('127.0.0.1', self.port, name)
        self.generate_blue()
        self.configure('router bgp 65001', f'vrf {name}', f'neighbor 127.0.0.1 remote-as {PEER_AS}', 'advertise blue')
        self.established(1)
        self.opened_by(in_vrf, 65001)
        self.expect_routes((in_vrf, 1))

        # A refused command changes nothing: same VRF, same session.
        refused = self.client.configure(['config', 'router bgp 65001', f'no vrf {name}-other'])
        self.assertFalse(refused)
        self.assertIn('not in VRF', refused.error)
        self.cli('end')
        self.assertIn(f'  vrf {name}\n', self.client.cli('show running-config'))
        neighbors = self.client.cli('show bgp neighbors')
        self.assertIn(f', VRF {name}\n', neighbors)
        self.assertEqual(neighbors.count('BGP state = Established'), 1)
        self.assertNotIn('Session resets', neighbors)
        self.assertIsNone(in_vrf.process.poll())

        # A socket cannot change namespace: the session resets, and the same address now answers in the own namespace.
        own = self.start_peer('127.0.0.1', self.port)
        self.configure('router bgp 65001', f'no vrf {name}')
        self.reaches(lambda: in_vrf.process.poll() is not None, in_vrf.text, within=10)
        self.established(1)
        self.opened_by(own, 65001)
        config = self.client.cli('show running-config')
        self.assertNotIn('  vrf ', config)
        self.assertIn(f'neighbor 127.0.0.1 remote-as {PEER_AS}', config)
        self.assertIn('advertise blue', config)
        neighbors = self.client.cli('show bgp neighbors')
        self.assertNotIn(', VRF ', neighbors)
        self.assertIn('Session resets: 1', neighbors)
        # The standing ribout follows the neighbor.
        self.expect_routes((own, 1), (in_vrf, 1))

    def test_changing_vrf_moves_live_sessions_between_namespaces(self):
        foo, bar = self.name('foo'), self.name('bar')
        self.add_namespace(foo)
        self.add_namespace(bar)
        own = self.start_peer('127.0.0.1', self.port)
        in_foo = self.start_peer('127.0.0.1', self.port, foo)
        in_bar = self.start_peer('127.0.0.1', self.port, bar)
        self.generate_blue()
        self.configure('router bgp 65001', f'neighbor 127.0.0.1 remote-as {PEER_AS}', 'advertise blue')
        self.established(1)
        self.opened_by(own, 65001)
        self.expect_routes((own, 1), (in_foo, 0), (in_bar, 0))

        def moved(left, joined, resets):
            self.reaches(lambda: left.process.poll() is not None, left.text, within=10)
            self.established(1)
            self.opened_by(joined, 65001)
            self.assertIn(f'Session resets: {resets}', self.client.cli('show bgp neighbors'))

        # Into a VRF, with a live session: the same address now answers in that namespace.
        self.configure('router bgp 65001', f'vrf {foo}')
        moved(own, in_foo, 1)
        self.expect_routes((own, 1), (in_foo, 1), (in_bar, 0))

        # The same name is not a change: no reset.
        self.configure('router bgp 65001', f'vrf {foo}')
        self.assertIn('Session resets: 1', self.client.cli('show bgp neighbors'))
        self.assertIsNone(in_foo.process.poll())

        # From one VRF to another.
        self.configure('router bgp 65001', f'vrf {bar}')
        moved(in_foo, in_bar, 2)
        self.expect_routes((own, 1), (in_foo, 1), (in_bar, 1))
        config = self.client.cli('show running-config')
        self.assertIn(f'  vrf {bar}\n', config)
        self.assertNotIn(f'  vrf {foo}\n', config)
        self.assertIn('advertise blue', config)

        # To a VRF that does not exist yet: the peer goes down and says why.
        missing = self.name('missing')
        self.configure('router bgp 65001', f'vrf {missing}')
        self.reaches(lambda: in_bar.process.poll() is not None, in_bar.text, within=10)
        line = f'VRF {missing} is not available (no such file or directory), retrying'
        self.reaches(lambda: line in self.client.cli('show bgp summary'), lambda: self.client.cli('show bgp summary'))
        self.established(0)

    def test_update_source_binds_in_the_vrf_of_the_router(self):
        blue, red = self.name('blue'), self.name('red')
        self.add_namespace(blue, '10.99.0.1', '10.99.0.2')
        self.add_namespace(red, '10.99.0.2')
        in_blue = self.start_peer('10.99.0.2', 179, blue)
        in_red = self.start_peer('10.99.0.2', 179, red)
        self.configure(
            'router bgp 65002',
                f'vrf {blue}',
                'update-source 10.99.0.1',
                f'neighbor 10.99.0.2 remote-as {PEER_AS}',
            'router bgp 65003',
                f'vrf {red}',
                'update-source 10.99.0.1',
                f'neighbor 10.99.0.2 remote-as {PEER_AS}')
        self.established(1)
        self.opened_by(in_blue, 65002)
        self.assertRegex(in_blue.text(), r'Accepted connection from 10\.99\.0\.1:')
        line = 'Update-source 10.99.0.1 is not usable (address not available), retrying'
        self.assertIn(line, self.client.cli('show bgp neighbors 65003'))
        self.assertNotIn(line, self.client.cli('show bgp neighbors 65002'))
        self.assertNotIn('Accepted connection', in_red.text())


class ManyVrfTests(NamespaceTestCase):
    ports = VRF_COUNT + 1

    def vrfs(self, *addresses):
        names = [self.name(f'v{index}') for index in range(VRF_COUNT)]
        for name in names:
            self.add_namespace(name, *addresses)
        return names

    def test_hundreds_of_vrfs_hold_the_same_address_apart(self):
        names = self.vrfs('10.99.0.2')
        in_vrf = [self.start_peer('10.99.0.2', 179, name, wait=False) for name in names]
        for peer in in_vrf:
            self.wait_listening(peer)
        own = self.start_peer('127.0.0.1', self.port + VRF_COUNT)

        # The own router comes last: the loop thread must be back in its namespace after every VRF socket.
        commands = []
        for index, name in enumerate(names):
            commands += [
                f'router bgp {FIRST_VRF_AS + index}',
                    f'vrf {name}',
                    f'neighbor 10.99.0.2 remote-as {PEER_AS}']
        self.configure(
            *commands,
            'router bgp 65001',
                f'neighbor 127.0.0.1 remote-as {PEER_AS}')
        self.generate_blue()
        self.established(VRF_COUNT + 1)

        for index, peer in enumerate(in_vrf):
            self.opened_by(peer, FIRST_VRF_AS + index)
        self.opened_by(own, 65001)
        summary = self.client.cli('show bgp summary')
        self.assertEqual(summary.count(', VRF '), VRF_COUNT)
        self.assertNotIn('is not available', summary)

        everyone = [*in_vrf, own]

        def expect_every(counts):
            self.expect_routes(*zip(everyone, counts))

        counts = [0] * (VRF_COUNT + 1)
        picked = 15  # Its name is a prefix of the names of 150 to 159: only an exact match selects one VRF.
        reply = self.cli(f'advertise ribout blue vrf {names[picked]} peer all')
        self.assertEqual(reply.count('queued to'), 1)
        self.assertIn(f'(router {FIRST_VRF_AS + picked})', reply)
        counts[picked] += 1
        expect_every(counts)

        self.cli(f'withdraw ribout blue router {FIRST_VRF_AS + picked} neighbor 10.99.0.2')
        counts[picked] += 1
        expect_every(counts)

        reply = self.cli('advertise ribout blue vrf default peer all')
        self.assertEqual(reply.count('queued to'), 1)
        counts[VRF_COUNT] += 1
        expect_every(counts)
        self.cli('withdraw ribout blue vrf default neighbor 127.0.0.1')
        counts[VRF_COUNT] += 1
        expect_every(counts)

        reply = self.cli('advertise ribout blue vrf all peer all')
        self.assertEqual(reply.count('queued to'), VRF_COUNT + 1)
        counts = [count + 1 for count in counts]
        expect_every(counts)

        # One script step spans every VRF: one run, one timing, one plan per router for the same address.
        self.configure('script span', 'withdraw ribout blue vrf all neighbor 10.99.0.2')
        done = self.client.run_script('span', timeout=30, poll_interval=.05)
        self.assertEqual(done['state'], 'complete', done['error'])
        self.assertEqual(sorted(p['router_as'] for p in done['peers']),
                         [FIRST_VRF_AS + index for index in range(VRF_COUNT)])
        self.assertEqual({(p['peer'], p['messages_done']) for p in done['peers']}, {('10.99.0.2', 1)})
        self.assertEqual([step['transmit']['samples'] for step in done['stats']], [1])
        counts = [count + 1 for count in counts[:-1]] + counts[-1:]
        expect_every(counts)

        # Clearing one VRF out of hundreds resets that session and no other.
        self.cli(f'clear bgp vrf {names[picked]} 10.99.0.2')
        neighbors = self.client.cli('show bgp neighbors')
        self.assertEqual(neighbors.count('Session resets: 1'), 1)
        self.assertIn('Session resets: 1', self.client.cli(f'show bgp neighbors {FIRST_VRF_AS + picked}'))
        self.assertEqual(neighbors.count('BGP state = Established'), VRF_COUNT)

        # One router leaving its VRF touches no other session; its peer is left behind in the namespace.
        leaving = picked + 1
        self.configure(f'router bgp {FIRST_VRF_AS + leaving}', 'no vrf')
        self.reaches(lambda: in_vrf[leaving].process.poll() is not None, in_vrf[leaving].text, within=10)
        neighbors = self.client.cli('show bgp neighbors')
        self.assertEqual(neighbors.count('BGP state = Established'), VRF_COUNT - 1)
        self.assertEqual(self.client.cli('show bgp summary').count(', VRF '), VRF_COUNT - 1)


class ManyListenerTests(NamespaceTestCase):
    passive = True
    ports = VRF_COUNT

    def test_hundreds_of_listeners_each_open_in_their_vrf(self):
        names = [self.name(f'l{index}') for index in range(VRF_COUNT)]
        for name in names:
            self.add_namespace(name)
        config = self.fixture.root / 'listeners.conf'
        config.write_text(''.join(f'router bgp {FIRST_VRF_AS + index}\n  vrf {name}\n'
                                  f'  neighbor 127.0.0.1 remote-as {PEER_AS}\n!\n'
                                  for index, name in enumerate(names)))
        self.fixture.stop_session(self.session)
        self.assertTrue(self.fixture.start_session(
            self.session, config=config, passive=True, log_path=self.fixture.root / 'listeners.log',
            env={'BGPSIM_LISTEN_BASE_PORT': str(self.port)}))
        self.assertIn(', VRF ', self.client.cli('show bgp summary'))

        # Nothing listens in bgpsim's own namespace: a client there is refused.
        with self.assertRaises(ConnectionRefusedError):
            socket.create_connection(('127.0.0.1', self.port), 1)

        peers = [self.start_peer('127.0.0.1', self.port + index, name, active=True)
                 for index, name in enumerate(names)]
        self.established(VRF_COUNT)
        for index, peer in enumerate(peers):
            self.opened_by(peer, FIRST_VRF_AS + index)
        self.assertNotIn('is not open', self.client.cli('show bgp summary'))


class PassiveNamespaceTests(NamespaceTestCase):
    passive = True

    def can_connect(self, namespace=None):
        probe = f"import socket; socket.create_connection(('127.0.0.1', {self.port}), 1).close()"
        argv = [sys.executable, '-c', probe]
        if namespace:
           argv = ['ip', 'netns', 'exec', namespace, *argv]
        return subprocess.run(argv, capture_output=True).returncode == 0

    def listens(self, in_namespace, namespace):
        return lambda: self.can_connect(namespace) == in_namespace and self.can_connect() != in_namespace

    def test_listener_opens_in_the_vrf_and_follows_it(self):
        name = self.name('listen')
        self.add_namespace(name)
        self.configure('router bgp 65001')
        self.reaches(self.listens(False, name), 'listener in the own namespace', within=10)

        self.configure('router bgp 65001', f'vrf {name}')
        self.reaches(self.listens(True, name), 'listener moved to the VRF', within=10)

        self.configure('router bgp 65001', f'no vrf {name}')
        self.reaches(self.listens(False, name), 'listener moved back', within=10)

        self.configure('router bgp 65001', f'vrf {name}')
        self.reaches(self.listens(True, name), 'listener moved again', within=10)
        self.configure('router bgp 65001', f'neighbor 127.0.0.1 remote-as {PEER_AS}')
        peer = self.start_peer('127.0.0.1', self.port, name, active=True)
        self.established(1)
        self.opened_by(peer, 65001)
        self.assertFalse(self.can_connect())

        # Leaving the VRF with a live session: the session resets and the listener moves to the own namespace.
        self.configure('router bgp 65001', 'no vrf')
        self.reaches(lambda: peer.process.poll() is not None, peer.text, within=10)
        attempts = []

        def connected(namespace):
            attempts.append(self.start_peer('127.0.0.1', self.port, namespace, active=True))
            return wait_until(lambda: attempts[-1].process.poll() is not None or
                              'Received OPEN: ' in attempts[-1].text(), 5) and attempts[-1].process.poll() is None

        self.reaches(lambda: connected(None), 'no listener in the own namespace', within=15)
        self.established(1)
        self.opened_by(attempts[-1], 65001)
        self.assertFalse(self.can_connect(name))

        # Entering a VRF with a live session moves the session and the listener the same way.
        self.configure('router bgp 65001', f'vrf {name}')
        self.reaches(lambda: attempts[-1].process.poll() is not None, attempts[-1].text, within=10)
        self.reaches(lambda: connected(name), 'no listener in the VRF', within=15)
        self.established(1)
        self.opened_by(attempts[-1], 65001)
        self.assertFalse(self.can_connect())


if __name__ == '__main__':
   raise SystemExit(run_unittest())
