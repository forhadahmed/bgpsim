#!/usr/bin/env python3
"""
One session to a real FRR speaker: `ttl-security`, `password`, Extended Message (RFC 8654), and AS4_PATH (RFC 6793).

bgpsim connects to one FRR speaker in its own namespace. The cases run in order on that one session.

Transport options. Each option is first set on bgpsim alone, and the session must stay down: FRR's kernel drops what
does not match, and so does bgpsim's. Then FRR gets the matching option and the session must come up. tshark reads a
capture of the same connections: the TTL of what bgpsim sent, and the TCP MD5 option on its segments. For the
password, a second round with another text shows that the key is the text.

Extended Message, on the session the transport cases leave up (signed, with TTL security). A ribout of 10000 IPv4
routes with `message-size 65535` is one UPDATE of about 40 KB. Without `capability extended-message` on the neighbor
it is withheld and FRR holds no route. With the capability, FRR must hold every route, and the capture must show
capability 6 in bgpsim's last OPEN only, one UPDATE of more than 4096 octets with all the routes, and one withdrawal
of 40023 octets. Three readers that share no code with bgpsim look at it. FRR decodes the UPDATEs into its table.
tshark 4.4 decodes the OPEN, but of a message above 4096 octets it reads only the header: it gives the length. The
capture reader of these tests (bgp_capture.py, bgp_wire.py) rebuilds the TCP stream and splits each UPDATE into its
routes.

AS4_PATH and AS4_AGGREGATOR (RFC 6793), last. A ribout with `as-path two-byte` and an aggregator, both with an AS
above 65535, is withheld while the session has 4-octet AS numbers. With `no capability four-byte-asn` on the neighbor
the two forms change places: FRR must rebuild the real path and aggregator, and tshark must show AS_TRANS in the
two-octet attributes and the real numbers in AS4_PATH and AS4_AGGREGATOR.
"""

from ipaddress import ip_network
import re
import sys

import frr_peer
from frr_peer import FrrPeer
from bgp_capture import read_capture
from bgp_wire import UPDATE, update_nlri
from interop import InteropTest
from test_results import run_unittest

LOCAL_AS, PEER_AS = 65001, 65002
# After `shutdown` and `no shutdown` bgpsim dials at once. A session that can come up must do so within this bound
# (the positive controls), so a neighbor that is still down after it is held down by the option under test.
DIAL_SECS = 4
ROUTES = 10000
MINE, THEIRS = '172.30.3.1', '172.30.3.2'
REASON = 'ribout has message-size above 4096 but Extended Message is not negotiated'
TWO_BYTE_REASON = 'ribout has a two-byte as-path but 4-octet AS is negotiated'
FOUR_OCTET_REASON = '4-octet AS not negotiated (AS_PATH is 4-octet)'
# tshark filters: the OPENs and the connection attempts of bgpsim, the OPENs of FRR, and the TCP MD5 option.
MY_OPENS, FRR_OPENS = f'ip.src == {MINE} && bgp.type == 1', f'ip.src == {THEIRS} && bgp.type == 1'
MY_SYNS = f'ip.src == {MINE} && tcp.flags.syn == 1 && tcp.flags.ack == 0'
MD5 = 'tcp.options.md5.digest'


class InteropFrrTests(InteropTest):
    NEIGHBOR = (f'router bgp {LOCAL_AS}', 'router-id 192.0.2.1', f'neighbor {THEIRS} remote-as {PEER_AS}')
    quiet = 0  # NOTIFICATIONs in FRR's log when the transport cases ended: their resets put some there

    @classmethod
    def setUpClass(cls):
        cls.prepare('fr', 'one session against FRR', frr_peer.missing)
        namespace = cls.namespace()
        cls.link(namespace, MINE, THEIRS)
        cls.frr = FrrPeer(cls.fixture, 'r1', namespace, PEER_AS, '10.0.0.9', {MINE: (LOCAL_AS, False)})
        cls.start([cls.frr], [
            'ribout big',
                f'prefix 10.0.0.0/24 x {ROUTES}',
                f'next-hop {MINE}',
                'message-size 65535',
                'exit',
            'ribout wide',
                'prefix 10.9.0.0/24 x 2',
                f'next-hop {MINE}',
                f'as-path {LOCAL_AS} 70000',
                'exit',
            'ribout old',
                'prefix 10.8.0.0/24 x 2',
                f'next-hop {MINE}',
                f'as-path two-byte {LOCAL_AS} 70000 {{ 80000 65010 }}',
                'aggregator 80000 192.0.2.9',
                'exit',
            *cls.NEIGHBOR])

    def opens_read(self):
        """How many OPENs bgpsim has read from the neighbor, by its own count."""
        return int(re.search(r'Opens:\s+\d+\s+(\d+)', self.cli('show bgp neighbors'))[1])

    def dial(self):
        """Make bgpsim dial now, instead of at its next retry: hold the neighbor down and release it."""
        self.neighbor('shutdown')
        self.neighbor('no shutdown')

    def comes_up(self, what):
        self.dial()
        self.reaches(self.established, f'the session did not come up {what}', within=DIAL_SECS)

    def stays_down(self):
        """The session is down, and a new connection does not bring it up in the time the controls need."""
        self.reaches(lambda: not self.established(), 'the session did not go down')
        self.dial()
        self.never(self.established, DIAL_SECS, 'the session came up')
        self.assertNotIn('BGP state = Established', self.cli('show bgp neighbors'))

    def held(self):
        return self.frr.routes(MINE)

    def complaints(self):
        """
        (NOTIFICATIONs in FRR's log since the transport cases, its lines about malformed UPDATEs): both empty when
        FRR accepted everything it read since.
        """
        notifications, errors = self.frr.log_events()
        return notifications[self.quiet:], errors

    def updates(self):
        """
        (message length, announced IPv4 routes, withdrawn IPv4 routes) of each UPDATE with routes that bgpsim sent,
        as the capture reader of the tests splits them. A message still arriving when the capture is read is left
        for the next call.
        """
        found = []
        for flow, stream in read_capture(self.capture.path.read_bytes(), partial=True).items():
            if flow[0] != MINE or flow[3] != 179:
               continue
            for kind, message in stream['messages']:
                if kind == UPDATE:
                   announced, withdrawn = update_nlri(message)
                   counts = (len(announced.get((1, 1), [])), len(withdrawn.get((1, 1), [])))
                   if any(counts):
                      found.append((len(message), *counts))
        return found

    def lengths(self):
        """The length of every BGP message bgpsim sent, as tshark reads the header."""
        return [int(length) for length in self.capture.values(f'ip.src == {MINE} && bgp', 'bgp.length')]

    def test_1_ttl_security(self):
        values = self.capture.values
        self.captured(lambda: values(MY_OPENS, 'ip.ttl'), 'no OPEN in the capture')
        default = values(MY_OPENS, 'ip.ttl')
        self.assertEqual(len(default), 1)
        self.assertNotEqual(default, ['255'])
        self.neighbor('ttl-security hops 1')
        self.assertIn('  TTL security: 1 hop, sends TTL 255, accepts 255 or more\n', self.cli('show bgp neighbors'))
        self.assertEqual(self.opens_read(), 1)
        self.stays_down()
        self.assertEqual(values(MY_SYNS, 'ip.ttl')[-1], '255')

        # FRR's listener answers the SYN with TTL 255, so the connection is made. Its OPEN then comes with the TTL
        # of its session socket, under 255: it is on the wire, and bgpsim's socket drops it.
        def low_opens():
            return [ttl for ttl in values(FRR_OPENS, 'ip.ttl')[1:] if ttl != '255']

        self.captured(low_opens, 'FRR sent no OPEN on the new connections')
        self.assertEqual(self.opens_read(), 1, 'bgpsim read an OPEN that came with a TTL under 255')
        # Positive control: FRR now sends TTL 255, and accepts 255 only.
        self.frr.configure(f'neighbor {MINE} ttl-security hops 1')
        self.comes_up('with TTL security on both sides')
        self.assertEqual(self.opens_read(), 2)
        # Every OPEN bgpsim sent since the command went out with TTL 255.
        self.captured(lambda: len(values(MY_OPENS, 'ip.ttl')) >= 2, 'no OPEN of the new session in the capture')
        opens = values(MY_OPENS, 'ip.ttl')
        self.assertEqual((opens[0], set(opens[1:])), (default[0], {'255'}))
        self.assertIn(f'  neighbor {THEIRS} remote-as {PEER_AS}\n    ttl-security hops 1\n',
                      self.cli('show running-config'))

    def test_2_password(self):
        values = self.capture.values
        # Every connection bgpsim has opened so far is unsigned. Only a SYN is checked: the capture can also hold
        # segments of an earlier run of this test, whose kernel still retransmits the close of a session that the
        # peer stopped answering, and the last of those sessions was signed.
        self.assertTrue(values(MY_SYNS, 'ip.ttl'))
        self.assertEqual(values(f'{MY_SYNS} && {MD5}', MD5), [], 'a connection was signed before any password was set')
        self.neighbor('password s3cret-key')
        self.assertIn('  TCP MD5 password is set\n', self.cli('show bgp neighbors'))
        # FRR has no key for bgpsim: its kernel drops the signed SYN.
        self.stays_down()
        self.captured(lambda: values(f'{MY_SYNS} && {MD5}', MD5), 'bgpsim sent no signed SYN')
        opens = len(values(MY_OPENS, 'ip.ttl'))
        # Positive control: the same text on FRR.
        self.frr.configure(f'neighbor {MINE} password s3cret-key')
        self.comes_up('with the password on both sides')
        self.captured(lambda: len(values(MY_OPENS, 'ip.ttl')) == opens + 1, 'no OPEN of the signed session in the capture')
        self.assertEqual(len(values(f'{MY_OPENS} && {MD5}', MD5)), 1)
        # The key is the text: FRR with another text drops what bgpsim signs, until bgpsim has that text too.
        self.frr.configure(f'neighbor {MINE} password another-key')
        self.stays_down()
        self.neighbor('password another-key')
        self.comes_up('with the new password on both sides')
        self.assertIn('    ttl-security hops 1\n    password another-key\n', self.cli('show running-config'))

    def test_3_large_ribout_is_withheld_without_the_capability(self):
        type(self).quiet = len(self.frr.log_events()[0])
        # FRR advertises Extended Message; this neighbor of bgpsim does not.
        self.assertIn('    Extended message: received\n', self.cli('show bgp neighbors'))
        self.assertIn(f'withheld from {THEIRS}: {REASON}', self.cli(f'advertise ribout big peer {THEIRS}'))
        self.assertIn(f'big: withheld: {REASON}', self.cli('show bgp neighbors'))
        # In-order barrier: a small ribout sent after it is held by FRR, and nothing of the large one is.
        self.configure('ribout small', 'prefix 192.168.0.0/24 x 3', f'next-hop {MINE}')
        self.cli('update generate ribout small')
        self.assertIn('queued', self.cli(f'advertise ribout small peer {THEIRS}'))
        self.reaches(lambda: len(self.held()) == 3, lambda: f'FRR holds {len(self.held())} routes')
        self.assertEqual(set(self.held()), {ip_network(f'192.168.{n}.0/24') for n in range(3)})
        self.assertIn('queued', self.cli(f'withdraw ribout small peer {THEIRS}'))
        self.reaches(lambda: not self.held(), lambda: f'FRR still holds {len(self.held())} routes')

    def test_4_one_update_carries_every_route(self):
        self.neighbor('capability extended-message')
        self.reaches(lambda: 'Extended message: advertised and received' in self.cli('show bgp neighbors') and
                     self.established(), 'the session did not come back with the capability on both sides')
        self.assertIn('queued', self.cli(f'advertise ribout big peer {THEIRS}'))
        self.reaches(lambda: len(self.held()) == ROUTES, lambda: f'FRR holds {len(self.held())} routes')
        held = set(self.held())
        self.assertEqual((ip_network('10.0.0.0/24') in held, ip_network('10.39.15.0/24') in held, len(held)),
                         (True, True, ROUTES))
        self.assertEqual(self.complaints(), ([], []))
        # tcpdump hands packets over in blocks: wait for the UPDATE with the routes.
        def big():
            return [update for update in self.updates() if update[1] == ROUTES]

        self.captured(big, lambda: f'the capture does not hold the UPDATE: {self.updates()}')
        # One UPDATE carries every route. The small ribout of the case before is the only other one with routes.
        (length, announced, withdrawn), = big()
        self.assertEqual((announced, withdrawn), (ROUTES, 0))
        self.assertEqual(sorted(update[1:] for update in self.updates()), [(0, 3), (3, 0), (ROUTES, 0)])
        # RFC 4271 section 4.3: header, two length fields, the path attributes, then four octets for each /24.
        self.assertGreater(length, 19 + 4 + ROUTES * 4)
        self.assertLess(length, 19 + 4 + ROUTES * 4 + 100)
        # tshark reads the same length from the header, and no other message bgpsim sent is above 4096 octets.
        self.assertEqual([seen for seen in self.lengths() if seen > 4096], [length])
        # Only the OPEN of this session carries capability 6: none of the sessions of the earlier cases did.
        capabilities = ['6' in packet['codes'] for packet in self.capture.dissect(MY_OPENS, {'codes': 'bgp.cap.type'})]
        self.assertGreater(len(capabilities), 1)
        self.assertEqual(capabilities, [False] * (len(capabilities) - 1) + [True])

    def test_5_the_withdrawal_is_one_update(self):
        self.assertIn('queued', self.cli(f'withdraw ribout big peer {THEIRS}'))
        self.reaches(lambda: not self.held(), lambda: f'FRR still holds {len(self.held())} routes')
        def gone():
            return [update for update in self.updates() if update[2] == ROUTES]

        self.captured(gone, lambda: f'the capture does not hold the withdrawal: {self.updates()}')
        # Header (19), Withdrawn Routes Length (2), 10000 prefixes of four octets, Total Path Attribute Length (2).
        self.assertEqual(gone(), [(19 + 2 + ROUTES * 4 + 2, 0, ROUTES)])
        self.captured(lambda: 19 + 2 + ROUTES * 4 + 2 in self.lengths(), lambda: f'tshark sees lengths {self.lengths()}')
        self.assertEqual(len([seen for seen in self.lengths() if seen > 4096]), 2)
        self.assertTrue(self.established())
        self.assertEqual(self.complaints(), ([], []))

    def test_6_two_byte_ribout_is_withheld_while_the_session_has_four_octet_as(self):
        # Both sides have 4-octet AS: the ribout in that form goes out, with the AS above 65535 as it is.
        self.assertIn('queued', self.cli(f'advertise ribout wide peer {THEIRS}'))
        self.reaches(lambda: len(self.held()) == 2, lambda: f'FRR holds {sorted(self.held())}')
        self.assertEqual(self.frr.paths('10.9.0.0/24'), [(f'{LOCAL_AS} 70000', None, None)])
        self.assertIn(f'withheld from {THEIRS}: {TWO_BYTE_REASON}', self.cli(f'advertise ribout old peer {THEIRS}'))
        self.assertIn(f'old: withheld: {TWO_BYTE_REASON}', self.cli('show bgp neighbors'))
        # In-order barrier: once the withdrawal that follows has emptied FRR's table, nothing of `old` came before.
        self.assertIn('queued', self.cli(f'withdraw ribout wide peer {THEIRS}'))
        self.reaches(lambda: not self.held(), lambda: f'FRR still holds {sorted(self.held())}')

    def test_7_as4_path_and_as4_aggregator_on_a_session_without_four_octet_as(self):
        self.neighbor('no capability four-byte-asn')
        self.reaches(lambda: '    4-byte ASN: received\n' in self.cli('show bgp neighbors') and self.established(),
                     'the session did not come back without the capability on the side of bgpsim')
        # Now the forms change places: the four-octet ribout is withheld and the two-byte one goes out.
        self.assertIn(f'withheld from {THEIRS}: {FOUR_OCTET_REASON}', self.cli(f'advertise ribout wide peer {THEIRS}'))
        self.assertIn('queued', self.cli(f'advertise ribout old peer {THEIRS}'))
        self.reaches(lambda: len(self.held()) == 2, lambda: f'FRR holds {sorted(self.held())}')
        # FRR read AS_PATH with two octets for each AS, as it does for a peer without the capability, and rebuilt the
        # path and the aggregator from AS4_PATH and AS4_AGGREGATOR (RFC 6793 section 4.2.3). It prints a set in order.
        for prefix in ('10.8.0.0/24', '10.8.1.0/24'):
            self.assertEqual(self.frr.paths(prefix), [(f'{LOCAL_AS} 70000 {{65010,80000}}', 80000, '192.0.2.9')])
        self.assertEqual(self.complaints(), ([], []))
        # tshark: AS_TRANS (23456) in each two-octet place of an AS above 65535, the real numbers in types 17 and 18.
        update = f'ip.src == {MINE} && bgp.nlri_prefix == 10.8.0.0'
        self.captured(lambda: self.capture.values(update, 'bgp.type'), 'the capture does not hold the UPDATE')
        self.assertEqual(self.capture.values(update, {'types': 'bgp.update.path_attribute.type_code',
                                                      'as2': 'bgp.update.path_attribute.as_path_segment.as2',
                                                      'as4': 'bgp.update.path_attribute.as_path_segment.as4',
                                                      'aggregator': 'bgp.update.path_attribute.aggregator_as',
                                                      'address': 'bgp.update.path_attribute.aggregator_origin'}),
                         {'types': ['1', '2', '3', '5', '7', '17', '18'],
                          'as2': [str(LOCAL_AS), '23456', '23456', '65010'],
                          'as4': [str(LOCAL_AS), '70000', '80000', '65010'],
                          'aggregator': ['23456', '80000'], 'address': ['192.0.2.9', '192.0.2.9']})
        self.assertTrue(self.established())
        self.assertEqual(self.capture.stop()[1], 0, 'tcpdump dropped packets')


if __name__ == '__main__':
   sys.exit(run_unittest())
