"""
A real FRR bgpd as the remote BGP peer: one process in its own network namespace.

FRR is independent evidence: it decodes bgpsim's UPDATEs with its own code and keeps its own table. bgpd runs without
zebra (-Z), so it installs nothing in the kernel, and with -x, so IPv6 unicast works over an IPv4 session without the
interface addresses that zebra would supply. Each neighbor is passive and denies every route out: bgpsim connects, and
FRR only receives.

With vxlan=(VNI, local address) the peer is a VXLAN tunnel endpoint instead: zebra runs too, the namespace gets a
bridge and a VXLAN device for that VNI, and FRR imports bgpsim's EVPN routes into its own EVPN state and the kernel.
"""

from datetime import datetime
from ipaddress import ip_network
import json
import os
import re
import shutil
import subprocess
import sys

from bgp_peer import BgpPeer, PeerUnavailable, proc_resources  # noqa: F401 (proc_resources: re-exported)
from test_common import wait_until

BGPD = '/usr/lib/frr/bgpd'
ZEBRA = '/usr/lib/frr/zebra'


class VtyshUnavailable(PeerUnavailable):
    """
    A vtysh command hit a transient from the test's own churn (bgpd being bounced, or a neighbor a concurrent
    trigger just removed): not a real command error.
    """
FAMILIES = ('ipv4', 'ipv6')
NOTIFICATION = re.compile(r'^(\S+ \S+) .*%NOTIFICATION: (sent to|received from) neighbor (\S+) (\d+)/(\d+) \(([^)]*)\)')
PARSE_ERROR = re.compile(r'(?i)malformed|parse error|treat-as-withdraw|treating as withdraw')
# vtysh prints these when bgpd is not answering (being crashed, restarted or still coming up): a transient, not a
# command error.
# vtysh failures that are transient under this test's own churn, not real command errors: bgpd being bounced, or a
# neighbor/config that a concurrent trigger just removed.
UNREACHABLE = re.compile(r'(?i)error reading from bgpd|connection refused|not running|failed to connect|no such file|'
                         r'broken pipe|cannot connect|specify remote-as|peer-group|does not exist|no such neighbor')


def missing():
    """Why FRR peers cannot run here, or None."""
    if not sys.platform.startswith('linux'):
       return 'FRR peers need Linux network namespaces'
    if os.geteuid() != 0:
       return 'FRR peers need root to create namespaces'
    for tool in ('ip', 'vtysh', 'tcpdump'):
        if not shutil.which(tool):
           return f'FRR peers need the {tool} command'
    for daemon in (BGPD, ZEBRA):
        if not os.access(daemon, os.X_OK):
           return f'FRR peers need {daemon} (the frr package)'
    return None


def version():
    result = subprocess.run([BGPD, '--version'], capture_output=True, text=True, timeout=10)
    return result.stdout.splitlines()[0] if result.stdout else 'unknown'


class FrrPeer(BgpPeer):
    """One bgpd. neighbors maps a bgpsim address to (its AS, whether IPv6 unicast is activated)."""

    TRIGGERS = ('clear', 'shutdown', 'refresh', 'delete', 'family')

    def __init__(self, fixture, name, namespace, asn, router_id, neighbors, vxlan=None):
        super().__init__(fixture, name, namespace, asn, router_id, neighbors)
        self.vxlan = vxlan
        self.zebra = None
        self.log = self.directory / 'bgpd.log'

    def neighbor_lines(self, address):
        """The configuration of one neighbor under router bgp: applying it again changes nothing."""
        remote_as, ipv6 = self.neighbors[address]
        lines = [f'neighbor {address} remote-as {remote_as}', f'neighbor {address} passive',
                 f'no neighbor {address} shutdown']
        for family in FAMILIES:
            active = family == 'ipv4' or ipv6
            lines += [f'address-family {family} unicast',
                      f'{"" if active else "no "}neighbor {address} activate']
            if active:
               lines.append(f'neighbor {address} route-map DENY out')
            lines.append('exit-address-family')
        if self.vxlan:
           lines += ['address-family l2vpn evpn', f'neighbor {address} activate', 'exit-address-family']
        return lines

    def config(self):
        lines = [
            'frr defaults datacenter',
            f'hostname {self.name}',
            '!',
            f'router bgp {self.asn}',
                f' bgp router-id {self.router_id}',
                ' no bgp ebgp-requires-policy',
                ' no bgp enforce-first-as',
                ' no bgp default ipv4-unicast',
                # A realistic hold time (datacenter defaults to 9s): the test's brief peer pauses must not trip it.
                ' timers bgp 30 90']
        lines += [f' {line}' for address in self.neighbors for line in self.neighbor_lines(address)]
        if self.vxlan:
           lines += [
               ' address-family l2vpn evpn',
                   '  advertise-all-vni',
               ' exit-address-family']
        return '\n'.join(lines + ['exit', '!', 'route-map DENY deny 10', 'exit', '']) + '\n'

    def start(self):
        if self.running():
           return
        config = self.directory / 'bgpd.conf'
        config.write_text(self.config())
        zebra = ['-z', self.start_zebra()] if self.vxlan else ['-Z']
        self.process = self.fixture.start_process(
            ['ip', 'netns', 'exec', self.namespace, BGPD, *zebra, '-S', '-x', '--limit-fds', '4096', '-f', config,
             '-i', self.directory / 'bgpd.pid', '--vty_socket', self.directory, '--log', f'file:{self.log}'],
            log_path=self.directory / f'stdout-{datetime.now():%H%M%S%f}.log')
        self.paused = False

    def start_zebra(self):
        """
        The VXLAN device of the VNI on a bridge, then zebra; returns zebra's API socket once it exists. zebra has no -S:
        it runs as root with the vty group that the FRR build requires of its user.
        """
        socket_path = self.directory / 'zserv.api'
        if self.zebra is not None and self.zebra.poll() is None:
           return socket_path
        vni, local = self.vxlan
        ip = ['ip', '-n', self.namespace, 'link']
        if self.zebra is None:
           for command in (['add', f'br{vni}', 'type', 'bridge'],
                           ['add', f'vxlan{vni}', 'type', 'vxlan', 'id', str(vni), 'local', local, 'dstport', '4789',
                            'nolearning'],
                           ['set', f'vxlan{vni}', 'master', f'br{vni}'], ['set', f'br{vni}', 'up'],
                           ['set', f'vxlan{vni}', 'up']):
               subprocess.run(ip + command, check=True, capture_output=True)
        config = self.directory / 'zebra.conf'
        config.write_text(f'hostname {self.name}\n')
        self.zebra = self.fixture.start_process(
            ['ip', 'netns', 'exec', self.namespace, ZEBRA, '-u', 'root', '-g', 'frrvty', '--limit-fds', '4096',
             '-f', config, '-i', self.directory / 'zebra.pid', '--vty_socket', self.directory, '-z', socket_path,
             '--log', f'file:{self.directory / "zebra.log"}'],
            log_path=self.directory / f'zebra-stdout-{datetime.now():%H%M%S%f}.log')
        wait_until(lambda: socket_path.exists() or self.zebra.poll() is not None, 10)
        if not socket_path.exists():
           raise RuntimeError(f'{self.name}: zebra did not open {socket_path}')
        return socket_path

    def ready(self):
        return self.running() and subprocess.run(self.vtysh_argv('show bgp summary'), capture_output=True,
                                                 timeout=10).returncode == 0

    def vtysh_argv(self, *commands, daemon='bgpd'):
        argv = ['vtysh', '--vty_socket', str(self.directory), '-d', daemon]
        for command in commands:
            argv += ['-c', command]
        return argv

    def vtysh(self, *commands, daemon='bgpd'):
        """
        Output of the commands. Raises VtyshUnavailable when bgpd is not answering (transient), RuntimeError on a
        real command error.
        """
        result = subprocess.run(self.vtysh_argv(*commands, daemon=daemon), capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
           output = f'{result.stdout}{result.stderr}'
           problem = f'{self.name}: vtysh {commands!r} failed ({result.returncode}): {output}'
           raise (VtyshUnavailable if UNREACHABLE.search(output) else RuntimeError)(problem)
        return result.stdout

    def configure(self, *lines):
        return self.vtysh('configure terminal', f'router bgp {self.asn}', *lines)

    # --- Remote-side triggers ------------------------------------------------------------------------------------

    def clear(self, address=None):
        self.vtysh(f'clear bgp {address or "*"}')

    def refresh(self, address=None):
        """Ask for the routes again: a ROUTE-REFRESH to one neighbor or to all."""
        self.vtysh(f'clear bgp {address or "*"} soft in')

    def shutdown(self, address):
        self.configure(f'neighbor {address} shutdown')

    def remove(self, address):
        self.configure(f'no neighbor {address}')

    def set_ipv6(self, address, active):
        self.configure('address-family ipv6 unicast', f'{"" if active else "no "}neighbor {address} activate')

    def restore(self, address=None):
        addresses = [address] if address else list(self.neighbors)
        self.configure(*[line for one in addresses for line in self.neighbor_lines(one)])

    def json(self, command, daemon='bgpd'):
        text = self.vtysh(command, daemon=daemon)
        try:
            return json.loads(text)
        except ValueError:
            raise RuntimeError(f'{self.name}: {command}: not JSON: {text[:200]!r}') from None

    def states(self):
        """{bgpsim address: FRR's BGP state}."""
        return {address: info.get('bgpState') for address, info in self.json('show bgp neighbors json').items()
                if address in self.neighbors}

    def routes(self, address):
        """
        {network: MED} of every route FRR holds from that neighbor, both families; None as the MED when the route
        has none.
        """
        found = {}
        for family in FAMILIES:
            data = self.json(f'show bgp {family} unicast neighbors {address} routes json')
            for prefix, paths in (data.get('routes') or {}).items():
                mine = [path for path in paths if path.get('peerId') == address]
                if len(mine) != 1:
                   raise AssertionError(f'{self.name}: {len(mine)} paths for {prefix} from {address}')
                found[ip_network(prefix)] = mine[0].get('metric')
        return found

    def paths(self, prefix):
        """
        (AS path, aggregator AS, aggregator address) of each path FRR holds for one IPv4 prefix, as FRR prints them;
        None where a path has no aggregator.
        """
        data = self.json(f'show bgp ipv4 unicast {prefix} json')
        return [(path['aspath']['string'], path.get('aggregatorAs'), path.get('aggregatorId'))
                for path in data.get('paths', ())]

    def evpn_routes(self):
        """
        {(RD, route as FRR prints it): (extended communities, VNI, PMSI label)} of every EVPN path received from a
        neighbor, each value as FRR decodes it; None where the route has no such field.
        """
        found = {}
        for entry in self.vtysh('show bgp l2vpn evpn route detail').split('BGP routing table entry for ')[1:]:
            rd, route = entry.splitlines()[0].split(':[', 1)
            peer = re.search(r'^\s+\S+ from (\S+) ', entry, re.MULTILINE)
            if not peer or peer[1] not in self.neighbors:
               continue
            communities = re.search(r'Extended Community: (.*)', entry)
            vni = re.search(r'^\s+Route \S+ VNI (\d+)', entry, re.MULTILINE)
            pmsi = re.search(r'PMSI Tunnel Type: .*label: (\d+)', entry)
            found[rd, '[' + route] = (communities[1].strip() if communities else '', int(vni[1]) if vni else None,
                                      int(pmsi[1]) if pmsi else None)
        return found

    def evpn_state(self, mac):
        """
        What FRR and the kernel hold for one MAC of the VNI: the VTEPs of each remote Ethernet segment (zebra), each
        VTEP's A-D flags per segment (bgpd), the segment the MAC is bound to, its MAC Mobility sequence number (zebra;
        None without the MAC), whether its kernel FDB entry is sticky, the VTEPs of the kernel next-hop group that
        entry points at (or its one VTEP), and the VTEPs of the kernel flood list.
        """
        vni = self.vxlan[0]

        def kernel(tool, *arguments):
            result = subprocess.run([tool, '-n', self.namespace, '-j', *arguments], check=True, capture_output=True,
                                    text=True)
            return json.loads(result.stdout or '[]')

        hops = kernel('ip', 'nexthop', 'show')
        gateway = {hop['id']: hop.get('gateway') for hop in hops}
        groups = {hop['id']: sorted(gateway.get(member['id']) for member in hop['group']) for hop in hops
                  if 'group' in hop}
        fdb = [entry for entry in kernel('bridge', 'fdb', 'show', 'dev', f'vxlan{vni}') if 'self' in entry['flags']]
        macs = self.json(f'show evpn mac vni {vni} json', daemon='zebra').get('macs', {})
        return dict(
            segments={es['esi']: sorted(vtep['vtep'] for vtep in es.get('vteps', ()))
                      for es in self.json('show evpn es json', daemon='zebra')},
            flags={(es['esi'], vtep['vtep_ip']): sorted(vtep.get('flags', ()))
                   for es in self.json('show bgp l2vpn evpn es-evi json') for vtep in es.get('vteps', ())},
            mac_segment=macs.get(mac, {}).get('remoteEs'),
            mac_sequence=macs.get(mac, {}).get('remoteSequence'),
            mac_sticky=any('sticky' in entry['flags'] for entry in fdb if entry['mac'] == mac),
            mac_next_hops=[groups.get(entry.get('nhid'), entry.get('dst')) for entry in fdb if entry['mac'] == mac],
            flood=sorted(entry['dst'] for entry in fdb if entry['mac'] == '00:00:00:00:00:00'))

    def log_events(self):
        """(NOTIFICATIONs as (time, direction, neighbor, code, subcode, text), lines reporting malformed UPDATEs)."""
        notifications, errors = [], []
        try:
            text = self.log.read_text(errors='replace')
        except FileNotFoundError:
            return notifications, errors
        for line in text.splitlines():
            match = NOTIFICATION.match(line)
            if match:
               when = datetime.strptime(match[1], '%Y/%m/%d %H:%M:%S').timestamp()
               notifications.append((when, match[2], match[3], int(match[4]), int(match[5]), match[6]))
            elif PARSE_ERROR.search(line):
               errors.append(line)
        return notifications, errors
