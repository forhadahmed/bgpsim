"""Hand-serialized evidence and receiver fixtures, independent of simulator encoders."""

from ipaddress import ip_address
import struct


def bgp_message(kind, body=b''):
    return b'\xff' * 16 + struct.pack('!HB', 19 + len(body), kind) + body


def update(withdrawn=b'', attrs=b'', nlri=b''):
    return bgp_message(2, struct.pack('!H', len(withdrawn)) + withdrawn + struct.pack('!H', len(attrs)) + attrs + nlri)


def attr(kind, value, flags=0x80):
    if len(value) > 255:
        return bytes([flags | 0x10, kind]) + struct.pack('!H', len(value)) + value
    return bytes([flags, kind, len(value)]) + value


def mp_reach(afi, safi, nlri, next_hop=bytes(4)):
    return attr(14, struct.pack('!HB', afi, safi) + bytes([len(next_hop)]) + next_hop + b'\0' + nlri)


def mp_unreach(afi, safi, nlri):
    return attr(15, struct.pack('!HB', afi, safi) + nlri)


def v4_prefix(text):
    address, bits = text.split('/')
    return bytes([int(bits)]) + ip_address(address).packed[:(int(bits) + 7) // 8]


def tcp_packet(src, dst, sport, dport, seq, payload, flags=0x18):
    """A Linux cooked (SLL2) IPv4 or IPv6 TCP packet."""
    tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, 0, 5 << 4, flags, 65535, 0, 0) + payload
    if ip_address(src).version == 4:
        network = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 0, 0, 64, 6, 0, ip_address(src).packed,
                              ip_address(dst).packed) + tcp
        protocol = 0x0800
    else:
        network = struct.pack('!IHBB16s16s', 6 << 28, len(tcp), 6, 64, ip_address(src).packed,
                              ip_address(dst).packed) + tcp
        protocol = 0x86dd
    return struct.pack('!HHIHBB8s', protocol, 0, 1, 1, 0, 6, bytes(8)) + network


def pcap(packets):
    out = struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 276)
    for packet in packets:
        out += struct.pack('<IIII', 0, 0, len(packet), len(packet)) + packet
    return out
