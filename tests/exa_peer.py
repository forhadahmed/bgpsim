"""
ExaBGP as the remote BGP peer: one process in its own network namespace.

ExaBGP is independent evidence: it decodes bgpsim's UPDATEs with its own code and writes each one as a JSON line. It
keeps no table, so routes() and ls_routes() replay those lines per neighbor. Each neighbor is passive and ExaBGP
announces nothing: bgpsim connects, and ExaBGP only receives. Its configuration is static, so it supports the
process triggers (stall, crash, restart) and no remote configuration triggers.
"""

from datetime import datetime
from ipaddress import ip_network
import json
import os
import re
import shutil
import subprocess
import sys
import threading

from bgp_peer import BgpPeer

FAMILIES = ('ipv4 unicast', 'ipv6 unicast')

# ExaBGP 5 decodes the SRv6 BGP-LS TLVs and the SRv6 SID NLRI, and keeps a session up through NLRI types, node
# descriptors and TLVs it does not know, reporting them as raw octets. ExaBGP 4.2 closes the session on some of them.
MINIMUM_MAJOR = 5
NOTIFIED = re.compile(r'notification (sent|received) \((\d+),(\d+)\)')
INTERNAL_ERROR = 'peer reset, message () error()'


def missing():
    """Why ExaBGP peers cannot run here, or None."""
    if not sys.platform.startswith('linux'):
       return 'ExaBGP peers need Linux network namespaces'
    if os.geteuid() != 0:
       return 'ExaBGP peers need root to create namespaces'
    for tool in ('ip', 'exabgp'):
        if not shutil.which(tool):
           return f'ExaBGP peers need the {tool} command'
    found = re.search(r'ExaBGP (\d+)', version())
    if not found or int(found[1]) < MINIMUM_MAJOR:
       return f'ExaBGP peers need ExaBGP {MINIMUM_MAJOR} or newer (found {version()})'
    return None


def version():
    """'ExaBGP 5.0.15'. ExaBGP 5 has a version command; ExaBGP 4 only the option."""
    for argument in ('version', '--version'):
        result = subprocess.run(['exabgp', argument], capture_output=True, text=True, timeout=20)
        found = re.search(r'ExaBGP\s*:\s*(\S+)', result.stdout)
        if found:
           return f'ExaBGP {found[1]}'
    return 'ExaBGP unknown'


class ExaPeer(BgpPeer):
    """
    One ExaBGP. local maps each bgpsim address to the address ExaBGP answers on; families lists the families it
    negotiates beside the neighbor's own IPv4/IPv6 unicast choice, as ExaBGP names them ('bgp-ls bgp-ls').
    """

    def __init__(self, fixture, name, namespace, asn, router_id, neighbors, local, families=()):
        super().__init__(fixture, name, namespace, asn, router_id, neighbors)
        self.local = dict(local)
        self.families = tuple(families)
        self.updates = self.directory / 'updates.json'
        self.stdout = self.log = self.directory / 'exabgp.log'
        self.read = 0
        self.lines = []
        self.reading = threading.Lock()
        self.harvested = 0
        self.events = ([], [])

    def config(self):
        sink = self.directory / 'sink.py'
        sink.write_text('import sys\n'
                        f'out = open({str(self.updates)!r}, "a")\n'
                        'for line in sys.stdin:\n'
                        '    out.write(line)\n'
                        '    out.flush()\n')
        blocks = [f'process sink {{\n    run {sys.executable} {sink};\n    encoder json;\n}}']
        for address, (remote_as, ipv6) in self.neighbors.items():
            families = [family for family in FAMILIES if ipv6 or family == 'ipv4 unicast'] + list(self.families)
            blocks.append(f'neighbor {address} {{\n'
                          f'    router-id {self.router_id};\n'
                          f'    local-address {self.local[address]};\n'
                          f'    local-as {self.asn};\n'
                          f'    peer-as {remote_as};\n'
                          '    passive;\n'
                          '    hold-time 90;\n'
                          '    family {\n' + ''.join(f'        {family};\n' for family in families) + '    }\n'
                          '    api {\n        processes [ sink ];\n        neighbor-changes;\n'
                          '        receive { parsed; update; notification; }\n'
                          '    }\n}')
        return '\n'.join(blocks) + '\n'

    def start(self):
        if self.running():
           return
        config = self.directory / 'exabgp.conf'
        config.write_text(self.config())
        # A restart is a new speaker: what the old one received is gone.
        self.harvest()
        with self.reading:
            self.updates.write_text('')
            self.read, self.lines, self.harvested = 0, [], 0
        # One pair of logs for each start: readiness is read from the speaker that is running now. ExaBGP reports
        # its start in its log file.
        stamp = f'{datetime.now():%H%M%S%f}'
        self.stdout = self.directory / f'stdout-{stamp}.log'
        self.log = self.directory / f'exabgp-{stamp}.log'
        settings = {'tcp.bind': ' '.join(sorted(set(self.local.values()))), 'tcp.port': '179', 'daemon.user': 'root',
                    'daemon.daemonize': 'false', 'log.destination': str(self.log), 'log.level': 'INFO',
                    'api.ack': 'false', 'api.cli': 'false'}
        self.process = self.fixture.start_process(
            ['ip', 'netns', 'exec', self.namespace, 'env', *[f'exabgp.{key}={value}' for key, value in settings.items()],
             'exabgp', config],
            log_path=self.stdout, cwd=self.directory)
        self.paused = False

    def ready(self):
        return (self.running() and self.log.exists() and
                'loaded new configuration successfully' in self.log.read_text(errors='replace'))

    def messages(self):
        """Every JSON message ExaBGP has written since it started; a partly written last line waits for its end."""
        # Checks read several peers, and one peer's sessions, from threads: one reader moves the cursor at a time.
        with self.reading:
            if not self.updates.exists():
               return self.lines
            with self.updates.open('rb') as stream:
                stream.seek(self.read)
                data = stream.read()
            whole = data[:data.rfind(b'\n') + 1]
            self.read += len(whole)
            for line in whole.splitlines():
                if not line.strip():
                   continue
                # ExaBGP can write a line that is not JSON (5.0 does for an SRv6 service TLV): keep its text.
                try:
                    self.lines.append(json.loads(line))
                except ValueError:
                    self.lines.append({'type': 'unparsed', 'raw': line.decode(errors='replace')})
            return self.lines

    def states(self):
        states = dict.fromkeys(self.neighbors, 'Idle')
        for message in self.messages():
            if message.get('type') == 'state':
               peer = message['neighbor']['address']['peer']
               states[peer] = 'Established' if message['neighbor']['state'] == 'up' else 'Idle'
        return states

    def downs(self):
        """How many times an Established session of this speaker went down."""
        up, count = set(), 0
        for message in self.messages():
            if message.get('type') != 'state':
               continue
            peer, state = message['neighbor']['address']['peer'], message['neighbor']['state']
            if state == 'up':
               up.add(peer)
            elif state == 'down' and peer in up:
                up.discard(peer)
                count += 1
        return count

    def replay(self, address, family, key):
        """
        {key(nlri): the attributes of its last announcement} for one neighbor and family, after every announcement
        and withdrawal in order. A session that went down takes its routes with it.
        """
        held = {}
        for message in self.messages():
            neighbor = message.get('neighbor', {})
            if neighbor.get('address', {}).get('peer') != address:
               continue
            if message.get('type') == 'state' and neighbor['state'] != 'up':
               held.clear()
            update = neighbor.get('message', {}).get('update', {})
            for nlri in update.get('withdraw', {}).get(family, ()):
                held.pop(key(nlri), None)
            for nlris in update.get('announce', {}).get(family, {}).values():
                for nlri in nlris:
                    held[key(nlri)] = update.get('attribute', {})
        return held

    def routes(self, address):
        found = {}
        for family in FAMILIES:
            for network, attributes in self.replay(address, family, lambda nlri: nlri['nlri']).items():
                found[ip_network(network)] = attributes.get('med')
        return found

    def ls_routes(self, address):
        """
        {BGP-LS NLRI as ExaBGP decodes it (JSON text, without the next hop): its decoded BGP-LS Attribute}. An NLRI
        type ExaBGP does not know stays in the key as raw hex.
        """
        def key(nlri):
            return json.dumps({name: value for name, value in nlri.items() if name != 'nexthop'}, sort_keys=True)

        return {nlri: attributes.get('bgp-ls', {}) for nlri, attributes in self.replay(address, 'bgp-ls bgp-ls', key).items()}

    def harvest(self):
        """
        Move the session-down events not yet seen into self.events: a restart empties the JSON stream, and the
        events must outlive it. ExaBGP gives the reason of every session down: a NOTIFICATION it sent or received
        with its code and subcode, a closed connection, or an error of its own with an empty text.
        """
        lines = self.messages()
        for message in lines[self.harvested:]:
            neighbor = message.get('neighbor', {})
            if message.get('type') != 'state' or neighbor.get('state') != 'down':
               continue
            reason = neighbor.get('reason', '')
            match = NOTIFIED.search(reason)
            if match:
               self.events[0].append((float(message['time']), 'sent to' if match[1] == 'sent' else 'received from',
                                      neighbor['address']['peer'], int(match[2]), int(match[3]), reason))
            elif reason == INTERNAL_ERROR:
                self.events[1].append(f'{neighbor["address"]["peer"]}: ExaBGP failed on a message: {reason}')
        self.harvested = len(lines)

    def log_events(self):
        """(NOTIFICATIONs as (time, direction, neighbor, code, subcode, text), ExaBGP's own failures on a message)."""
        self.harvest()
        return self.events
