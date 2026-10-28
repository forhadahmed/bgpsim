"""BGP on the wire, read from a tcpdump capture: independent evidence for receiver checks.

read_capture() takes a pcap written by `tcpdump -i any` (Linux cooked capture, SLL or SLL2; Ethernet also works),
reassembles every TCP stream in sequence order and splits it into BGP messages. BGP framing, UPDATE decoding and
route identity belong to bgp_wire. Nothing here uses bgpsim's encoder or its view: truncated or malformed evidence
raises AssertionError.
"""

from ipaddress import ip_address
import struct

from bgp_wire import bgp_messages, u16 as _u16


def _packets(data, partial=False):
    """(link type, packet) of every record of a pcap file. partial: the file is still being written, so a cut
    last record ends it instead of failing."""
    if len(data) < 24:
        raise AssertionError('truncated pcap header')
    magic = data[:4]
    order = {b'\xd4\xc3\xb2\xa1': '<', b'\xa1\xb2\xc3\xd4': '>', b'\x4d\x3c\xb2\xa1': '<',
             b'\xa1\xb2\x3c\x4d': '>'}.get(magic)
    if order is None:
        raise AssertionError('not a pcap file')
    link = struct.unpack_from(order + 'I', data, 20)[0]
    offset = 24
    while offset < len(data):
        if offset + 16 > len(data):
            if partial:
                return
            raise AssertionError('truncated pcap record header')
        caplen, origlen = struct.unpack_from(order + 'II', data, offset + 8)
        if offset + 16 + caplen > len(data):
            if partial:
                return
            raise AssertionError('truncated pcap record')
        if caplen != origlen:
            raise AssertionError('pcap record cut by the snapshot length')
        yield link, data[offset + 16:offset + 16 + caplen]
        offset += 16 + caplen


def _network_layer(link, packet):
    """(ethertype, network-layer bytes) of a captured packet."""
    minimum = {113: 16, 276: 20, 1: 14}.get(link)
    if minimum is not None and len(packet) < minimum:
        raise AssertionError('truncated link-layer header')
    if link == 113:  # LINUX_SLL: 16-octet header, protocol last
        return _u16(packet, 14), packet[16:]
    if link == 276:  # LINUX_SLL2: 20-octet header, protocol first
        return _u16(packet, 0), packet[20:]
    if link == 1:  # Ethernet
        return _u16(packet, 12), packet[14:]
    raise AssertionError(f'unsupported pcap link type {link}')


def _tcp_segment(ethertype, data):
    """((src, sport, dst, dport), seq, flags, payload) of a TCP segment, or None for other traffic."""
    if ethertype == 0x0800 and len(data) >= 20 and data[9] == 6:
        header, total = (data[0] & 0x0f) * 4, _u16(data, 2)
        if data[0] >> 4 != 4 or header < 20 or total < header or total > len(data):
            raise AssertionError('invalid or truncated IPv4 packet')
        if _u16(data, 6) & 0x3fff:
            raise AssertionError('fragmented IPv4 TCP evidence is unsupported')
        src, dst, tcp = str(ip_address(data[12:16])), str(ip_address(data[16:20])), data[header:total]
    elif ethertype == 0x86dd and len(data) >= 40 and data[6] == 6:
        if data[0] >> 4 != 6 or 40 + _u16(data, 4) > len(data):
            raise AssertionError('invalid or truncated IPv6 packet')
        src, dst, tcp = str(ip_address(data[8:24])), str(ip_address(data[24:40])), data[40:40 + _u16(data, 4)]
    else:
        return None
    if len(tcp) < 20:
        raise AssertionError('truncated TCP header')
    sport, dport, seq = struct.unpack_from('!HHI', tcp)
    offset = (tcp[12] >> 4) * 4
    if offset < 20 or offset > len(tcp):
        raise AssertionError('invalid or truncated TCP options')
    return (src, sport, dst, dport), seq, tcp[13], tcp[offset:]


def read_capture(data, partial=False):
    """{(src, sport, dst, dport): {'syn': bool, 'messages': [(type, message)]}} of every TCP stream in a pcap.

    Each stream's payload is rebuilt in sequence order (retransmissions overlap and are dropped); a gap means the
    capture missed data and raises. A stream the capture joined mid-way starts at its first captured segment, which
    must begin a BGP message.
    """
    segments = {}
    for link, packet in _packets(data, partial):
        segment = _tcp_segment(*_network_layer(link, packet))
        if segment:
            flow, seq, flags, payload = segment
            entry = segments.setdefault(flow, {'syn': False, 'segments': []})
            if flags & 0x02:
                entry['syn'] = True
                entry['isn'] = seq
            if payload:
                entry['segments'].append(((seq + bool(flags & 0x02)) % 2**32, payload))
    streams = {}
    for flow, entry in segments.items():
        if not entry['segments']:
            streams[flow] = {'syn': entry['syn'], 'messages': []}
            continue
        if 'isn' in entry:
            base = entry['isn'] + 1
        else:
            # Joined mid-stream: start at the earliest sequence number captured (segments can arrive out of order;
            # compare in modulo-2^32 sequence space around the first one captured).
            first = entry['segments'][0][0]
            base = first + min(((seq - first + 2**31) % 2**32) - 2**31 for seq, _ in entry['segments'])
        relative = sorted(((seq - base) % 2**32, payload) for seq, payload in entry['segments'])
        stream, next_byte = bytearray(), 0
        for start, payload in relative:
            if start > next_byte:
                raise AssertionError(f'capture missed {start - next_byte} octets of {flow}')
            overlap = min(len(payload), next_byte - start)
            if stream[start:start + overlap] != payload[:overlap]:
                raise AssertionError(f'conflicting TCP retransmission in {flow}')
            if start + len(payload) > next_byte:
                stream += payload[next_byte - start:]
                next_byte = start + len(payload)
        streams[flow] = {'syn': entry['syn'], 'messages': bgp_messages(bytes(stream), partial=partial)}
    return streams
