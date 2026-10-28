"""Independent, bounded BGP evidence readers shared by MRT and pcap adapters.

This module never imports the simulator's encoders or models. Container formats
and TCP reassembly belong to their adapters; BGP framing and route keys live here.
"""

from ipaddress import ip_address
import struct

MARKER = b'\xff' * 16
OPEN, UPDATE = 1, 2
PREFIX_SAFIS = {1, 2, 4, 73, 128, 129}
FLOWSPEC_SAFIS = {133, 134}


def u16(data, offset=0):
    if offset < 0 or offset + 2 > len(data):
        raise AssertionError('truncated 16-bit field')
    return struct.unpack_from('!H', data, offset)[0]


def bgp_messages(stream, partial=False):
    """Split a TCP payload; only live captures may end in an incomplete message."""
    messages, offset = [], 0
    while offset < len(stream):
        if len(stream) - offset < 19:
            if partial:
                break
            raise AssertionError('truncated BGP header')
        if stream[offset:offset + 16] != MARKER:
            raise AssertionError(f'no BGP marker at octet {offset}')
        length = u16(stream, offset + 16)
        if length < 19:
            raise AssertionError(f'invalid BGP message length {length}')
        if offset + length > len(stream):
            if partial:
                break
            raise AssertionError('truncated BGP message')
        messages.append((stream[offset + 18], stream[offset:offset + length]))
        offset += length
    return messages


def split_nlri(data, afi, safi):
    """Return whole non-Add-Path NLRIs, rejecting unsupported or invalid lengths."""
    out = []
    while data:
        if safi in PREFIX_SAFIS:
            if afi not in (1, 2):
                raise AssertionError(f'unsupported prefix AFI {afi}')
            bits = data[0]
            overhead = 88 if safi in (128, 129) else 24 if safi == 4 else 0
            maximum = 96 if afi == 1 else 192
            if safi == 73:
                valid = bits == maximum
            else:
                valid = overhead <= bits <= overhead + (32 if afi == 1 else 128)
            if not valid:
                raise AssertionError(f'invalid NLRI length ({afi}/{safi})')
            size = 1 + (bits + 7) // 8
        elif (afi, safi) == (25, 70):
            if len(data) < 2:
                raise AssertionError('truncated EVPN NLRI')
            size = 2 + data[1]
        elif safi in FLOWSPEC_SAFIS and afi in (1, 2):
            if data[0] >= 0xf0:
                if len(data) < 2:
                    raise AssertionError('truncated FlowSpec length')
                size = 2 + (((data[0] & 0x0f) << 8) | data[1])
            else:
                size = 1 + data[0]
        else:
            raise AssertionError(f'unsupported family {afi}/{safi}')
        if size > len(data):
            raise AssertionError(f'truncated NLRI ({afi}/{safi})')
        out.append(bytes(data[:size]))
        data = data[size:]
    return out


def update_nlri(message):
    """Return announced and withdrawn NLRI encodings indexed by (AFI, SAFI)."""
    if (len(message) < 23 or message[:16] != MARKER or
            u16(message, 16) != len(message) or message[18] != UPDATE):
        raise AssertionError('invalid BGP UPDATE framing')
    end = 21 + u16(message, 19)
    if end + 2 > len(message):
        raise AssertionError('truncated Withdrawn Routes')
    attr_end = end + 2 + u16(message, end)
    if attr_end > len(message):
        raise AssertionError('truncated path attributes')
    announced, withdrawn = {}, {}
    if end > 21:
        withdrawn[(1, 1)] = split_nlri(message[21:end], 1, 1)
    if attr_end < len(message):
        announced[(1, 1)] = split_nlri(message[attr_end:], 1, 1)
    offset, seen = end + 2, set()
    while offset < attr_end:
        if attr_end - offset < 3:
            raise AssertionError('truncated attribute header')
        flags, kind = message[offset:offset + 2]
        width = 2 if flags & 0x10 else 1
        if offset + 2 + width > attr_end:
            raise AssertionError('truncated attribute length')
        size = u16(message, offset + 2) if width == 2 else message[offset + 2]
        offset += 2 + width
        if size > attr_end - offset or kind in seen:
            raise AssertionError('truncated or duplicate attribute')
        seen.add(kind)
        value = message[offset:offset + size]
        offset += size
        if kind not in (14, 15):
            continue
        if size < (5 if kind == 14 else 3):
            raise AssertionError('truncated MP attribute')
        start = 5 + value[3] if kind == 14 else 3
        if start > size:
            raise AssertionError('truncated MP next hop')
        afi, safi = u16(value), value[2]
        keys = split_nlri(value[start:], afi, safi)
        if keys:
            (announced if kind == 14 else withdrawn).setdefault((afi, safi), []).extend(keys)
    return announced, withdrawn


def route_key(nlri, afi, safi):
    """Canonical binary identity; a VPN's label is forwarding data, not its key."""
    if split_nlri(nlri, afi, safi) != [nlri]:
        raise AssertionError('expected one NLRI')
    if safi == 4:
        return bytes([nlri[0] - 24]) + nlri[4:]
    if safi in (128, 129):
        return bytes([nlri[0] - 24]) + nlri[4:]
    return nlri


def _rd_text(rd):
    if len(rd) != 8:
        raise AssertionError('invalid route distinguisher')
    kind = u16(rd)
    if kind == 0:
        return f'{u16(rd, 2)}:{struct.unpack_from("!I", rd, 4)[0]}'
    if kind == 1:
        return f'{ip_address(rd[2:6])}:{u16(rd, 6)}'
    if kind == 2:
        return f'{struct.unpack_from("!I", rd, 2)[0]}:{u16(rd, 6)}'
    raise AssertionError(f'unsupported RD type {kind}')


def prefix_key(nlri, afi, safi):
    """The receiver's printable prefix identity, including the RD for VPN routes."""
    key = route_key(nlri, afi, safi)
    bits, body = key[0], key[1:]
    rd = ''
    if safi in (128, 129):
        rd, bits, body = _rd_text(body[:8]) + ' ', bits - 64, body[8:]
    elif safi not in (1, 2, 4):
        raise AssertionError(f'no prefix key for family {afi}/{safi}')
    address = ip_address(body.ljust(4 if afi == 1 else 16, bytes(1)))
    return f'{rd}{address}/{bits}'
