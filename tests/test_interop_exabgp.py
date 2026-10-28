#!/usr/bin/env python3
"""
One session to a real ExaBGP speaker: path attribute lines, then session control. Two independent decoders read it.

bgpsim peers with one ExaBGP speaker in its own namespace, as an internal peer so ORIGINATOR_ID and CLUSTER_LIST are
legal. The cases run in order on that one session; ExaBGP decodes what it receives and tshark decodes a capture of
the same session. Neither shares code with bgpsim.

Path attributes. One ribout of IPv4 unicast routes carries AGGREGATOR, ATOMIC_AGGREGATE, ORIGINATOR_ID,
CLUSTER_LIST, AIGP, Only-to-Customer, a BGP Prefix-SID with a Label-Index and an Originator SRGB, and an attribute
bgpsim has no name for. One ribout of VPNv4 routes carries an SRv6 L3 Service TLV (RFC 9252). Others carry
confederation segments, no LOCAL_PREF, a route target and Site of Origin, and a Link Bandwidth community beside
extended communities entered as octets. ExaBGP 5 decodes most of them and reports the rest as raw octets.

Session control. The neighbor has `hold-time 30`. The session is reset with `clear bgp <neighbor> cease <text>`,
held down with `shutdown <text>` and brought back with `no shutdown`. ExaBGP reports the NOTIFICATIONs it received;
tshark reads the Hold Time of each OPEN, each Cease with its subcode and Shutdown Communication (RFC 9003), and
every connection bgpsim opened.
"""

import struct
import sys

import exa_peer
from exa_peer import ExaPeer
from interop import InteropTest
from test_results import run_unittest

LOCAL_AS = 65001
ROUTES = 4
MINE, THEIRS = '172.30.5.1', '172.30.5.2'
# bgpsim dials again 2 seconds after a session that was up goes down. The reset case must see that connection
# within this bound; the shutdown case must see none for as long.
RETRY_SECS = 6
RESET_TEXT, SHUTDOWN_TEXT = 'link upgrade', 'maintenance window'
# tshark filters: everything sent to the peer, and the OPENs and connection attempts of each side.
TO_PEER = f'ip.dst == {THEIRS}'
MY_OPENS, PEER_OPENS = f'ip.src == {MINE} && bgp.type == 1', f'ip.src == {THEIRS} && bgp.type == 1'
MY_SYNS = f'ip.src == {MINE} && tcp.flags.syn == 1 && tcp.flags.ack == 0 && tcp.dstport == 179'
HOLD_TIME = 'bgp.open.holdtime'


# How ExaBGP 5.0 reports the segments of the confederation path: the AS numbers of each segment in order, but both
# confederation segments under the name of a plain sequence. tshark gives the segment types.
CONFED_AS_PATH = {'0': {'element': 'as-sequence', 'value': [64512, 64513]},
                  '1': {'element': 'as-sequence', 'value': [64514, 64515]},
                  '2': {'element': 'as-sequence', 'value': [65010]},
                  '3': {'element': 'as-set', 'value': [65011, 65012]}}


def ribouts():
    return [
        'ribout plain',
            f'prefix 10.0.0.0/24 x {ROUTES}',
            f'next-hop {MINE}',
            'aggregator 65010 192.0.2.9',
            'atomic-aggregate',
            'originator-id 10.0.0.1',
            'cluster-list 10.0.0.2 10.0.0.3',
            f'aigp 1000 x {ROUTES}',
            'otc 65001',
            f'prefix-sid index 100 x {ROUTES}',
            'prefix-sid srgb range 16000 8000',
            'attribute type 99 value dead',
            'exit',
        'ribout service',
            f'prefix 10.1.0.0/24 x {ROUTES}',
            'rd 65000:1',
            'label 3',
            'rt 65000:1',
            f'next-hop {MINE}',
            f'prefix-sid srv6-l3 fc00:0:1:1::/64 behavior end.dt4 structure 32 16 16 0 transposition 16 48 x {ROUTES}',
            'exit',
        'ribout confed',
            'prefix 10.2.0.0/24 x 2',
            f'next-hop {MINE}',
            'as-path ( 64512 64513 ) [ 64514 64515 ] 65010 { 65011 65012 }',
            'exit',
        'ribout nolp',
            'prefix 10.3.0.0/24 x 2',
            f'next-hop {MINE}',
            'localpref none',
            'exit',
        'ribout tagged',
            'prefix 10.4.0.0/24 x 2',
            f'next-hop {MINE}',
            'rt 65000:77',
            'soo 65000:9',
            'exit',
        'ribout weighted',
            'prefix 10.5.0.0/24 x 2',
            f'next-hop {MINE}',
            'link-bandwidth 65001 10g',
            'ext-community 0004fde94cee6b28 8f991234deadbeef',
            'exit']



class InteropExabgpTests(InteropTest):
    NEIGHBOR = (f'router bgp {LOCAL_AS}', 'router-id 192.0.2.1', f'neighbor {THEIRS} remote-as {LOCAL_AS}')
    dialed = 0  # Connections bgpsim had opened when the session control cases began

    @classmethod
    def setUpClass(cls):
        cls.prepare('ex', 'one session against ExaBGP', exa_peer.missing)
        namespace = cls.namespace()
        cls.link(namespace, MINE, THEIRS)
        cls.peer = ExaPeer(cls.fixture, 'p1', namespace, LOCAL_AS, '10.0.0.9', {MINE: (LOCAL_AS, False)},
                           {MINE: THEIRS}, families=('ipv4 mpls-vpn',))
        cls.start([cls.peer], [
            *ribouts(),
            *cls.NEIGHBOR,  # router bgp, router-id, neighbor: the lines below are in neighbor mode
                'hold-time 30',
                'address-family vpnv4',
                'exit',
            'exit'])

    def dials(self):
        """How many TCP connections bgpsim has opened since the session control cases began, as the capture has them."""
        return len(self.capture.values(MY_SYNS, 'tcp.srcport')) - self.dialed

    def ceases(self):
        """Every NOTIFICATION bgpsim sent, as tshark decodes it: (code, Cease subcode, Shutdown Communication)."""
        return [(packet['code'], packet['subcode'], packet['text'])
                for packet in self.capture.dissect(f'ip.src == {MINE} && bgp.type == 3',
                                                   {'code': 'bgp.notify.major_error',
                                                    'subcode': 'bgp.notify.minor_error_cease',
                                                    'text': 'bgp.notify.communication'})]

    def received(self):
        """The NOTIFICATIONs ExaBGP says it received from bgpsim: (code, subcode)."""
        notifications, failures = self.peer.log_events()
        self.assertEqual(failures, [])
        return [(code, subcode) for _, direction, address, code, subcode, _ in notifications
                if direction == 'received from' and address == MINE]

    def test_1_path_attributes_as_exabgp_decodes_them(self):
        for name in ('plain', 'service'):
            self.assertIn('queued', self.cli(f'advertise ribout {name} peer {THEIRS}'))

        def held():
            return self.peer.replay(MINE, 'ipv4 unicast', lambda nlri: nlri['nlri'])

        self.reaches(lambda: len(held()) == ROUTES, lambda: f'ExaBGP holds {sorted(held())}')
        for n in range(ROUTES):
            attributes = held()[f'10.0.{n}.0/24']
            self.assertIs(attributes['atomic-aggregate'], True)
            self.assertEqual(attributes['aggregator'], '65010:192.0.2.9')
            self.assertEqual((attributes['originator-id'], attributes['cluster-list']),
                             ('10.0.0.1', ['10.0.0.2', '10.0.0.3']))
            # The Label-Index follows the prefix; every route has the same Originator SRGB.
            self.assertEqual(attributes['bgp-prefix-sid'], {'sr-label-index': 100 + n, 'sr-srgbs': [[16000, 8000]]})
            # ExaBGP 5 has no name for Only-to-Customer (35) or for attribute 99: it reports their octets.
            self.assertEqual(attributes['attribute-0x23-0xE0'], '0x0000fde9')
            self.assertEqual(attributes['attribute-0x63-0xE0'], '0xdead')
        # The VPN routes carry an SRv6 L3 Service TLV. ExaBGP 5.0 decodes its SID structure but prints the SID and
        # the behavior as unfilled format marks, so those lines are not JSON; tshark checks the SID and behavior.
        def services():
            return [message['raw'] for message in self.peer.messages()
                    if message.get('type') == 'unparsed' and '"l3-service"' in message['raw']]

        self.reaches(lambda: len(services()) == ROUTES, lambda: f'ExaBGP reports {len(services())} VPN UPDATEs')
        for raw in services():
            self.assertIn('"locator-block-length": 32, "locator-node-length": 16, "function-length": 16, '
                          '"argument-length": 0, "transposition-length": 16, "transposition-offset": 48', raw)
        # RFC 5065: an AS_PATH with a confederation sequence and set before the sequence and set of RFC 4271.
        self.assertIn('queued', self.cli(f'advertise ribout confed peer {THEIRS}'))
        self.reaches(lambda: '10.2.1.0/24' in held(), lambda: f'ExaBGP holds {sorted(held())}')
        for prefix in ('10.2.0.0/24', '10.2.1.0/24'):
            self.assertEqual(held()[prefix]['as-path'], CONFED_AS_PATH, held()[prefix])
        # `localpref none`: no LOCAL_PREF. The routes of the other ribouts carry the default of 100.
        self.assertIn('queued', self.cli(f'advertise ribout nolp peer {THEIRS}'))
        self.reaches(lambda: '10.3.1.0/24' in held(), lambda: f'ExaBGP holds {sorted(held())}')
        self.assertEqual([held()[prefix].get('local-preference') for prefix in
                          ('10.2.0.0/24', '10.3.0.0/24', '10.3.1.0/24')], [100, None, None])
        # A route target and a Site of Origin on plain IPv4 unicast routes, with no RD.
        self.assertIn('queued', self.cli(f'advertise ribout tagged peer {THEIRS}'))
        self.reaches(lambda: '10.4.1.0/24' in held(), lambda: f'ExaBGP holds {sorted(held())}')
        for prefix in ('10.4.0.0/24', '10.4.1.0/24'):
            # ExaBGP writes the number of a Site of Origin as a dotted quad.
            self.assertEqual([community['string'] for community in held()[prefix]['extended-community']],
                             ['target:65000:77', 'origin:65000:0.0.0.9'], held()[prefix])
        self.assertNotIn('extended-community', held()['10.3.0.0/24'])
        # Link Bandwidth, and two values entered as octets. ExaBGP gives each community as the number its eight
        # octets make, smallest first: type 0x40 (0x00: transitive), sub-type 4, the AS, and the rate in octets per
        # second as an IEEE single, which struct packs here; then a value of a type that has no assigned meaning.
        self.assertIn('queued', self.cli(f'advertise ribout weighted peer {THEIRS}'))
        self.reaches(lambda: '10.5.1.0/24' in held(), lambda: f'ExaBGP holds {sorted(held())}')
        for prefix in ('10.5.0.0/24', '10.5.1.0/24'):
            self.assertEqual([community['value'] for community in held()[prefix]['extended-community']],
                             [int.from_bytes(struct.pack('>BBHf', 0x00, 4, 65001, 1e9 / 8), 'big'),
                              int.from_bytes(struct.pack('>BBHf', 0x40, 4, 65001, 10e9 / 8), 'big'),
                              0x8F991234DEADBEEF], held()[prefix])
        self.cli(f'withdraw all peer {THEIRS}')
        self.reaches(lambda: not held(), lambda: f'ExaBGP still holds {sorted(held())}')
        self.assertEqual(self.peer.downs(), 0)
        self.assertEqual(self.peer.log_events(), ([], []))

    def test_2_path_attributes_as_tshark_decodes_them(self):
        """Runs after the first case: the capture holds its UPDATEs, decoded by Wireshark's dissector."""
        # The last thing sent was `withdraw all`: the capture is complete when it holds the withdrawal of every
        # route of every ribout. An MP_UNREACH_NLRI attribute alone is not that: the End-of-RIB of the VPN family
        # at session start is one too, of three octets (AFI and SAFI).
        def withdrawn():
            sent = self.capture.dissect(f'{TO_PEER} && bgp.type == 2',
                                        {'gone': 'bgp.withdrawn_prefix', 'kind': 'bgp.update.path_attribute.type_code',
                                         'size': 'bgp.update.path_attribute.length'})
            unicast = {prefix for packet in sent for prefix in packet['gone']}
            vpn = any(kind == '15' and int(size) > 3 for packet in sent
                      for kind, size in zip(packet['kind'], packet['size']))
            return vpn and unicast >= {'10.0.0.0', '10.2.1.0', '10.3.1.0', '10.4.1.0', '10.5.1.0'}

        self.captured(withdrawn, 'the capture does not hold the withdrawals')
        values = self.capture.values
        seen = values(f'{TO_PEER} && bgp',
                      {'malformed': '_ws.malformed', 'aggregator_as': 'bgp.update.path_attribute.aggregator_as',
                       'aggregator': 'bgp.update.path_attribute.aggregator_origin',
                       'originator': 'bgp.update.path_attribute.originator_id', 'otc': 'bgp.update.path_attribute.otc',
                       'aigp_type': 'bgp.update.attribute.aigp.type', 'aigp_length': 'bgp.update.attribute.aigp.length',
                       'aigp': 'bgp.update.attribute.aigp.accu_igp_metric',
                       'index': 'bgp.prefix_sid.label_index.value', 'srgb_base': 'bgp.prefix_sid.originator_srgb_base',
                       'srgb_range': 'bgp.prefix_sid.originator_srgb_range'})
        self.assertEqual(seen['malformed'], [])
        self.assertEqual((seen['aggregator_as'], seen['aggregator'], seen['originator'], seen['otc']),
                         (['65010'] * ROUTES, ['192.0.2.9'] * ROUTES, ['10.0.0.1'] * ROUTES, ['65001'] * ROUTES))
        # One AIGP TLV of type 1 and length 11 on each route; the metric and the Label-Index are sequences in step.
        self.assertEqual((seen['aigp_type'], seen['aigp_length']), (['1'] * ROUTES, ['11'] * ROUTES))
        self.assertEqual(sorted(zip(map(int, seen['aigp']), map(int, seen['index']))),
                         [(1000 + n, 100 + n) for n in range(ROUTES)])
        self.assertEqual((seen['srgb_base'], seen['srgb_range']), (['16000'] * ROUTES, ['8000'] * ROUTES))
        # RFC 9252: the SRv6 L3 Service TLV of each VPN route: its own SID at /64, behavior End.DT4 (19), and the
        # SID structure with a transposition.
        service = values(f'{TO_PEER} && bgp.prefix_sid.srv6_l3vpn',
                         {'sid': 'bgp.prefix_sid.srv6_l3vpn.sid_value',
                          'behavior': 'bgp.prefix_sid.srv6_l3vpn.srv6_endpoint_behavior',
                          'block': 'bgp.prefix_sid.srv6_l3vpn.sid.locator_block_len',
                          'node': 'bgp.prefix_sid.srv6_l3vpn.sid.locator_node_len',
                          'function': 'bgp.prefix_sid.srv6_l3vpn.sid.func_len',
                          'argument': 'bgp.prefix_sid.srv6_l3vpn.sid.arg_len',
                          'length': 'bgp.prefix_sid.srv6_l3vpn.sid.trans_len',
                          'offset': 'bgp.prefix_sid.srv6_l3vpn.sid.trans_offset'})
        self.assertEqual(sorted(service['sid']), [f'fc00:0:1:{n}::' for n in range(1, ROUTES + 1)])
        self.assertEqual(set(service['behavior']), {'0x0013'})
        self.assertEqual([set(service[name]) for name in ('block', 'node', 'function', 'argument', 'length', 'offset')],
                         [{'32'}, {'16'}, {'16'}, {'0'}, {'16'}, {'48'}])
        # RFC 5065 section 3: segment types 3 (confederation sequence) and 4 (confederation set), then 2 and 1.
        confed = values(f'{TO_PEER} && bgp.nlri_prefix == 10.2.0.0',
                        {'kind': 'bgp.update.path_attribute.as_path_segment.type',
                         'count': 'bgp.update.path_attribute.as_path_segment.length',
                         'asn': 'bgp.update.path_attribute.as_path_segment.as4'})
        self.assertEqual((confed['kind'], confed['count']), (['3', '4', '2', '1'], ['2', '2', '1', '2']),
                         # What the capture holds, for a failure: each packet to the peer with its routes.
                         self.capture.dissect(f'{TO_PEER} && tcp.len > 0',
                                              {'frame': 'frame.number', 'len': 'tcp.len', 'type': 'bgp.type',
                                               'nlri': 'bgp.nlri_prefix', 'gone': 'bgp.withdrawn_prefix',
                                               'info': '_ws.col.Info'}))
        self.assertEqual(confed['asn'], ['64512', '64513', '64514', '64515', '65010', '65011', '65012'])
        # RFC 4360: the unicast routes carry a route target (subtype 2) and a route origin (subtype 3), both of
        # the two-octet AS type, with their AS and number.
        tagged = values(f'{TO_PEER} && bgp.nlri_prefix == 10.4.0.0',
                        {'subtype': 'bgp.ext_com.stype_tr_as2', 'asn': 'bgp.ext_com.value_as2',
                         'number': 'bgp.ext_com.value_an4'})
        self.assertEqual(tagged, {'subtype': ['0x02', '0x03'], 'asn': ['65000', '65000'], 'number': ['77', '9']})
        # Link Bandwidth: sub-type 4 of the two-octet AS type, once not transitive (`link-bandwidth`) and once
        # transitive (entered as octets), each with the AS. tshark 4.4 reads the rate of the first as octets per
        # second and shows the four octets of the second as a number. Then the value of the unassigned type 0x8f.
        weighted = values(f'{TO_PEER} && bgp.nlri_prefix == 10.5.0.0',
                          {'local': 'bgp.ext_com.stype_ntr_as2', 'transitive': 'bgp.ext_com.stype_tr_as2',
                           'asn': 'bgp.ext_com.value_as2', 'rate': 'bgp.ext_com.value_link_bw',
                           'number': 'bgp.ext_com.value_an4', 'unknown': 'bgp.ext_com.stype_unknown',
                           'raw': 'bgp.ext_com.value_raw'})
        self.assertEqual(weighted, {'local': ['0x04'], 'transitive': ['0x04'], 'asn': ['65001', '65001'],
                                    'rate': ['1.25e+09'],
                                    'number': [str(struct.unpack('>I', struct.pack('>f', 1e9 / 8))[0])],
                                    # The six value octets, which tshark prints as a 64-bit number.
                                    'unknown': ['0x99'], 'raw': ['0x00001234deadbeef']})
        # The UPDATE of the `localpref none` ribout has no LOCAL_PREF attribute; the one before it has.
        local_pref = 'bgp.update.path_attribute.local_pref'
        self.assertEqual((values(f'{TO_PEER} && bgp.nlri_prefix == 10.3.0.0',
                                 {'lp': local_pref, 'origin': 'bgp.update.path_attribute.origin'}),
                          values(f'{TO_PEER} && bgp.nlri_prefix == 10.2.0.0', {'lp': local_pref})),
                         ({'lp': [], 'origin': ['0']}, {'lp': ['100']}))

    def test_3_hold_time_is_proposed_and_negotiated(self):
        values = self.capture.values
        # The OPEN of bgpsim on the session that is up.
        self.captured(lambda: '30' in values(MY_OPENS, HOLD_TIME), 'the capture holds no OPEN with 30')
        # The neighbor line dials at once, and `hold-time 30` then starts that session again. Whether bgpsim had
        # already sent an OPEN with the default of 180 on the first connection depends on how fast it got there;
        # every OPEN from the command on proposes 30. ExaBGP proposes 90 on each connection.
        proposed = [int(hold) for hold in values(MY_OPENS, HOLD_TIME)]
        self.assertEqual(proposed, sorted(proposed, reverse=True), 'an OPEN with 180 followed one with 30')
        self.assertEqual((set(proposed) - {180}, proposed[-1], set(values(PEER_OPENS, HOLD_TIME))), ({30}, 30, {'90'}))
        # The later cases count connections from here: the SYN of this session is before its OPEN in the capture.
        type(self).dialed = self.dials()
        shown = self.cli('show bgp neighbors')
        self.assertIn('  Hold time is 30, keepalive interval is 10 seconds\n  Configured hold time is 30 seconds\n',
                      shown)
        self.assertIn(f'  neighbor {THEIRS} remote-as {LOCAL_AS}\n    hold-time 30\n', self.cli('show running-config'))

    def test_4_clear_with_cease_resets_the_session(self):
        self.assertEqual((self.dials(), self.peer.downs(), self.received()), (0, 0, []))
        self.assertIn('Cleared 1 BGP session', self.cli(f'clear bgp {THEIRS} cease {RESET_TEXT}'))
        # Positive control of the next case: bgpsim dials again, within RETRY_SECS.
        self.captured(lambda: self.dials() == 1, lambda: f'{self.dials()} connections', within=RETRY_SECS)
        self.reaches(lambda: self.peer.downs() == 1 and self.established(), 'the session did not come back after the reset')
        # RFC 4486 subcode 4, Administrative Reset.
        self.assertEqual(self.received(), [(6, 4)])
        self.captured(lambda: len(self.ceases()) == 1, 'the capture does not hold the Cease of the reset')
        self.assertEqual(self.ceases(), [(['6'], ['4'], [RESET_TEXT])])
        self.assertIn(f'  Last notification sent: 6/4 (Cease/Administrative Reset), shutdown communication '
                      f'"{RESET_TEXT}"', self.cli('show bgp neighbors'))

    def test_5_shutdown_holds_the_neighbor_down(self):
        self.assertEqual((self.dials(), self.peer.downs()), (1, 1))
        self.neighbor(f'shutdown {SHUTDOWN_TEXT}')
        self.reaches(lambda: self.peer.downs() == 2, 'the session did not go down on shutdown')
        # RFC 4486 subcode 2, Administrative Shutdown.
        self.assertEqual(self.received(), [(6, 4), (6, 2)])
        self.captured(lambda: len(self.ceases()) == 2, 'the capture does not hold the Cease of the shutdown')
        self.assertEqual(self.ceases()[1], (['6'], ['2'], [SHUTDOWN_TEXT]))
        shown = self.cli('show bgp neighbors')
        self.assertIn('  BGP state = Idle (administratively shut down)\n', shown)
        self.assertIn(f'    shutdown {SHUTDOWN_TEXT}\n', self.cli('show running-config'))
        # No connection for as long as the reset needed to make one.
        self.assertFalse(self.capture.wait_for(lambda: self.dials() > 1, RETRY_SECS), 'bgpsim dialed a shut down neighbor')
        self.assertFalse(self.established())
        self.neighbor('no shutdown')
        self.reaches(self.established, 'the session did not come back after no shutdown')
        self.captured(lambda: self.dials() == 2, 'the capture does not hold the connection after no shutdown')
        self.assertNotIn('shutdown', self.cli('show running-config'))
        self.assertEqual((self.peer.downs(), self.received()), (2, [(6, 4), (6, 2)]))
        self.assertEqual(self.capture.stop()[1], 0, 'tcpdump dropped packets')


if __name__ == '__main__':
   sys.exit(run_unittest())
