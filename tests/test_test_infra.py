#!/usr/bin/env python3
"""Failure-sensitivity checks for evidence collection and test harnesses."""

from ipaddress import ip_address
import struct
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import bgp_capture
import bgp_wire
from stress_harness import Capture, Churn, Findings, CaptureRecords
from test_results import run_unittest
from evidence_fixtures import (attr, bgp_message, mp_reach, mp_unreach,
                               pcap, tcp_packet, update, v4_prefix)

class WireEvidenceTests(unittest.TestCase):
    SIM, RCV = '10.1.0.1', '10.1.0.2'

    def stream(self, payload, seq=1000):
        return tcp_packet(self.SIM, self.RCV, 40000, 179, seq, payload)

    def test_streams_reassemble_in_order_and_drop_retransmissions(self):
        first = update(nlri=v4_prefix('100.64.0.0/24') + v4_prefix('100.64.1.0/24'))
        second = bgp_message(4)
        data = first + second
        packets = [self.stream(data[10:], 1010), self.stream(data[:10], 1000), self.stream(data[5:20], 1005)]
        streams = bgp_capture.read_capture(pcap(packets))
        messages = streams[(self.SIM, 40000, self.RCV, 179)]['messages']
        self.assertEqual([kind for kind, _ in messages], [2, 4])
        announced, withdrawn = bgp_wire.update_nlri(messages[0][1])
        self.assertEqual([bgp_wire.prefix_key(n, 1, 1) for n in announced[(1, 1)]],
                         ['100.64.0.0/24', '100.64.1.0/24'])
        self.assertEqual(withdrawn, {})

    def test_a_gap_a_bad_marker_and_a_cut_file_fail(self):
        data = update(nlri=v4_prefix('100.64.0.0/24')) + bgp_message(4)
        with self.assertRaisesRegex(bgp_wire.IncompleteEvidence, 'missed'):
            bgp_capture.read_capture(pcap([self.stream(data[:10], 1000), self.stream(data[20:], 1020)]))
        with self.assertRaisesRegex(AssertionError, 'marker'):
            bgp_capture.read_capture(pcap([self.stream(b'\0' * 19)]))
        cut = pcap([self.stream(data)])[:-3]
        with self.assertRaises(bgp_wire.IncompleteEvidence):
            bgp_capture.read_capture(cut)
        self.assertEqual(bgp_capture.read_capture(cut, partial=True), {})

    def test_stress_reports_bad_or_missing_wire_evidence_as_failure_not_pass(self):
        valid = pcap([self.stream(bgp_message(4))])
        cases = ((valid, 'pass', None),
                 (pcap([tcp_packet(self.SIM, self.RCV, 40000, 179, 1000,
                                   bgp_message(4) + update()[:-1], flags=0x19)]), 'pass', None),
                 (pcap([self.stream(bytes(19))]), 'fail', 'marker'),
                 (valid[:-3], 'fail', 'incomplete evidence'))
        for data, status, detail in cases:
            with self.subTest(status=status, detail=detail):
                churn = Churn.__new__(Churn)
                churn.findings = Findings()
                churn.failed = False
                churn.latency = 0.0
                CaptureRecords(None, {self.SIM}).feed(data, churn.findings)
                with patch.object(churn, 'peer_logs'), patch('stress_harness.emit') as emit:
                    churn.report_findings('sensitivity')
                wire = [call for call in emit.call_args_list if 'the wire shows' in call.args[1]]
                self.assertEqual(len(wire), 1)
                self.assertEqual(wire[0].args[0], status)
                self.assertEqual(churn.failed, status == 'fail')
                self.assertFalse(any(call.args[0] == 'skip' for call in emit.call_args_list))
                if detail:
                   self.assertIn(detail, wire[0].kwargs['detail'])

    def test_conflicting_retransmissions_and_invalid_tcp_bounds_fail(self):
        message = update(nlri=v4_prefix('100.64.0.0/24'))
        bad_retransmission = bytes([message[5] ^ 1]) + message[6:10]
        with self.assertRaisesRegex(AssertionError, 'conflicting TCP'):
            bgp_capture.read_capture(pcap([self.stream(message), self.stream(bad_retransmission, 1005)]))
        for offset in (0, 15):
            packet = bytearray(self.stream(message))
            packet[20 + 20 + 12] = offset << 4
            if offset == 15:
               packet = packet[:60]
            with self.subTest(offset=offset), self.assertRaises(AssertionError):
                bgp_capture.read_capture(pcap([packet]))

    def test_every_family_form_decodes(self):
        label = b'\x00\x3e\x81'  # 1000, bottom of stack
        rd = struct.pack('!HIH', 2, 65551, 1)  # 65551 needs the 4-octet AS form, type 2
        lu4 = bytes([24 + 24]) + label + bytes([10, 40, 0])
        vpn6 = bytes([88 + 64]) + label + rd + ip_address('2001:db8:200::').packed[:8]
        evpn = bytes([5, 34]) + bytes(34)
        flow_short = bytes([3, 1, 24, 10])  # destination 10.0.0.0/24, written short
        flow_long = bytes([0xf0, 3]) + bytes([1, 24, 10])  # the same rule with a two-octet length
        message = update(withdrawn=v4_prefix('100.64.9.0/24'),
                         attrs=mp_reach(1, 4, lu4) + mp_unreach(2, 128, vpn6))
        announced, withdrawn = bgp_wire.update_nlri(message)
        self.assertEqual([bgp_wire.prefix_key(n, 1, 4) for n in announced[(1, 4)]], ['10.40.0.0/24'])
        self.assertEqual([bgp_wire.prefix_key(n, 2, 128) for n in withdrawn[(2, 128)]],
                         ['65551:1 2001:db8:200::/64'])
        self.assertEqual([bgp_wire.prefix_key(n, 1, 1) for n in withdrawn[(1, 1)]], ['100.64.9.0/24'])
        announced, withdrawn = bgp_wire.update_nlri(update(
            attrs=mp_reach(25, 70, evpn) + mp_unreach(1, 133, flow_short + flow_long)))
        self.assertEqual(len(announced[(25, 70)]), 1)
        self.assertEqual(len(withdrawn[(1, 133)]), 2)

    def test_bgp_framing_and_attribute_bounds_fail_closed(self):
        valid = update(nlri=v4_prefix('100.64.0.0/24'))
        bad = [valid[:18], valid[:-1], bytes(16) + valid[16:], bgp_message(4),
               update(attrs=b'\x80\x0e'), update(attrs=b'\x90\x0e\x00'),
               update(attrs=b'\x80\x0e\x09\x00'),
               update(attrs=mp_reach(1, 1, b'') * 2),
               update(attrs=mp_unreach(1, 1, b'') * 2),
               update(attrs=attr(14, b'\x00\x01\x01\xff\x00')),
               update(attrs=attr(15, b'\x00\x01')),
               update(withdrawn=b'\x21' + bytes(5))]
        for message in bad:
            with self.subTest(message=message.hex()), self.assertRaises(AssertionError):
                bgp_wire.update_nlri(message)
        for afi, safi, nlri in ((1, 1, b'\x21' + bytes(5)), (2, 1, b'\x81' + bytes(17)),
                               (1, 128, b'\x40' + bytes(8)), (1, 133, b'\xf0'),
                               (1, 133, b'\x04\x01'), (25, 70, b'\x05')):
            with self.subTest(afi=afi, safi=safi), self.assertRaises(AssertionError):
                bgp_wire.split_nlri(nlri, afi, safi)

    def test_open_stream_requires_live_capture_for_partial_final_messages(self):
        first = bgp_message(4)
        for incomplete in (b'\xff', update()[:-1]):
            with self.subTest(incomplete=incomplete):
                self.assertEqual(bgp_wire.bgp_messages(first + incomplete, partial=True), [(4, first)])
                with self.assertRaises(AssertionError):
                    bgp_wire.bgp_messages(first + incomplete)
                live = bgp_capture.read_capture(pcap([self.stream(first + incomplete)]), partial=True)
                self.assertEqual(live[(self.SIM, 40000, self.RCV, 179)]['messages'], [(4, first)])
                with self.assertRaises(AssertionError):
                    bgp_capture.read_capture(pcap([self.stream(first + incomplete)]))

    def test_observed_tcp_close_allows_only_a_valid_interrupted_final_message(self):
        first = bgp_message(4)
        tail = update()[:-1]
        data = first + tail
        endings = (
            [tcp_packet(self.SIM, self.RCV, 40000, 179, 1000, data, flags=0x19)],
            [self.stream(data), tcp_packet(self.SIM, self.RCV, 40000, 179, 1000 + len(data), b'', flags=0x11)],
            [self.stream(data), tcp_packet(self.SIM, self.RCV, 40000, 179, 1000 + len(data), b'', flags=0x14)],
            [self.stream(data), tcp_packet(self.RCV, self.SIM, 179, 40000, 2000, b'', flags=0x14)],
        )
        for index, packets in enumerate(endings):
            with self.subTest(ending=index):
                stream = bgp_capture.read_capture(pcap(packets))[self.SIM, 40000, self.RCV, 179]
                self.assertEqual(stream['messages'], [(4, first)])
                self.assertEqual(stream['interrupted_bytes'], len(tail))
        # A reverse FIN is only a half-close; this sender's missing tail is still incomplete evidence.
        missing = ([self.stream(data)],
                   [self.stream(data), tcp_packet(self.RCV, self.SIM, 179, 40000, 2000, b'', flags=0x11)],
                   [self.stream(data), tcp_packet(self.SIM, self.RCV, 40000, 179, 1005 + len(data), b'', flags=0x11)],
                   [self.stream(data[:10]),
                    tcp_packet(self.SIM, self.RCV, 40000, 179, 1020, data[20:], flags=0x19)])
        for index, packets in enumerate(missing):
            with self.subTest(missing=index), self.assertRaises(bgp_wire.IncompleteEvidence):
                bgp_capture.read_capture(pcap(packets))
        for bad in (bytes(5), bytes(19), bgp_wire.MARKER + bytes(3)):
            with self.subTest(bad=bad.hex()), self.assertRaises(AssertionError) as caught:
                bgp_capture.read_capture(pcap([
                    tcp_packet(self.SIM, self.RCV, 40000, 179, 1000, first + bad, flags=0x19)]))
            self.assertNotIsInstance(caught.exception, bgp_wire.IncompleteEvidence)

    def test_rotated_captures_preserve_only_the_pending_message_and_sequence(self):
        flow = self.SIM, 40000, self.RCV, 179
        first, second = bgp_message(4), update()
        initial = first + second[:10]
        state = {}
        syn = tcp_packet(self.SIM, self.RCV, 40000, 179, 999, b'', flags=0x02)
        streams = bgp_capture.read_capture(pcap([syn]), partial=True, state=state)
        self.assertEqual(streams[flow]['messages'], [])
        self.assertEqual(state[flow]['base'], 1000)
        with self.assertRaises(bgp_wire.IncompleteEvidence):
            bgp_capture.read_capture(pcap([self.stream(initial, 1005)]), state=state)
        streams = bgp_capture.read_capture(pcap([self.stream(initial)]), partial=True, state=state)
        self.assertEqual(streams[flow]['messages'], [(4, first)])
        before = dict(state)
        with self.assertRaises(bgp_wire.IncompleteEvidence):
            bgp_capture.read_capture(pcap([]), state=state)
        self.assertEqual(state, before)
        with self.assertRaises(bgp_wire.IncompleteEvidence):
            bgp_capture.read_capture(pcap([self.stream(second[10:], 1001 + len(initial))]), state=state)
        self.assertEqual(state, before)
        # Replay the earlier packet too: complete messages must not be delivered twice across capture boundaries.
        packets = [self.stream(initial), tcp_packet(self.SIM, self.RCV, 40000, 179, 1000 + len(initial),
                                                    second[10:], flags=0x19)]
        streams = bgp_capture.read_capture(pcap(packets), state=state)
        self.assertEqual(streams[flow]['messages'], [(2, second)])
        self.assertEqual(streams[flow]['interrupted_bytes'], 0)
        self.assertEqual(state[flow]['tail'], b'')

    def test_reset_in_the_next_capture_ends_the_pending_transport_tail(self):
        flow = self.SIM, 40000, self.RCV, 179
        tail = update()[:-1]
        state = {}
        bgp_capture.read_capture(pcap([self.stream(bgp_message(4) + tail)]), partial=True, state=state)
        reset = tcp_packet(self.RCV, self.SIM, 179, 40000, 2000, b'', flags=0x14)
        streams = bgp_capture.read_capture(pcap([reset]), state=state)
        self.assertEqual(streams[flow]['messages'], [])
        self.assertEqual(streams[flow]['interrupted_bytes'], len(tail))
        self.assertEqual(state[flow]['tail'], b'')

    def test_reused_tcp_tuple_does_not_inherit_the_old_connections_reset(self):
        flow = self.SIM, 40000, self.RCV, 179
        first = bgp_message(4)
        state = {}
        packets = [self.stream(first), tcp_packet(self.RCV, self.SIM, 179, 40000, 2000, first),
                   tcp_packet(self.RCV, self.SIM, 179, 40000, 2000 + len(first), b'', flags=0x14)]
        bgp_capture.read_capture(pcap(packets), state=state)
        packets = [tcp_packet(self.SIM, self.RCV, 40000, 179, 5000, b'', flags=0x02),
                   self.stream(first[:5], 5001)]
        bgp_capture.read_capture(pcap(packets), partial=True, state=state)
        self.assertEqual(state[flow]['tail'], first[:5])
        self.assertFalse(state[flow].get('reset'))
        with self.assertRaises(bgp_wire.IncompleteEvidence):
            bgp_capture.read_capture(pcap([]), state=state)

    def test_continuous_capture_cursor_never_consumes_a_partial_pcap_record(self):
        first = pcap([self.stream(bgp_message(4))])
        second = pcap([self.stream(update(), 1019)])
        with tempfile.TemporaryDirectory() as directory:
            capture = Capture(None, Path(directory))
            capture.path = Path(directory) / 'wire.pcap'
            capture.path.write_bytes(first[:-3])
            data, end = capture.read()
            self.assertEqual((data, end, capture.offset), (pcap([]), 24, 24))
            with self.assertRaises(bgp_wire.IncompleteEvidence):
                capture.read(final=True)
            capture.path.write_bytes(first)
            data, end = capture.read()
            self.assertEqual((data, end), (first, len(first)))
            capture.offset = end
            with capture.path.open('ab') as output:
                output.write(second[24:])
            data, end = capture.read(final=True)
            self.assertEqual((data, end), (second, len(first) + len(second) - 24))
            capture.offset = end
            self.assertEqual(capture.read(final=True), (pcap([]), end))

    def test_capture_route_identity_ignores_label_changes(self):
        key = bytes.fromhex('58 0002 0001000f 0001 0a1400')
        for label in (bytes.fromhex('05dc01'), bytes.fromhex('800000')):
            nlri = bytes([key[0] + 24]) + label + key[1:]
            self.assertEqual(bgp_wire.route_key(nlri, 1, 128), key)
            streams = bgp_capture.read_capture(pcap([self.stream(update(attrs=mp_reach(1, 128, nlri)))]))
            message = streams[(self.SIM, 40000, self.RCV, 179)]['messages'][0][1]
            routes, _ = bgp_wire.update_nlri(message)
            self.assertEqual([bgp_wire.route_key(n, 1, 128) for n in routes[1, 128]], [key])

    def test_ipv6_transport_and_syn(self):
        packets = [tcp_packet('fd00:2::1', 'fd00:2::2', 40001, 179, 99, b'', flags=0x02),
                   tcp_packet('fd00:2::1', 'fd00:2::2', 40001, 179, 100, bgp_message(1, bytes(10)))]
        stream = bgp_capture.read_capture(pcap(packets))[('fd00:2::1', 40001, 'fd00:2::2', 179)]
        self.assertTrue(stream['syn'])
        self.assertEqual([kind for kind, _ in stream['messages']], [1])


if __name__ == '__main__':
   sys.exit(run_unittest())
