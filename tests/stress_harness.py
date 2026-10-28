"""
Shared harness for heavy_stress.py: bgpsim against real peers, each in its own network namespace.

Both modes of heavy_stress.py, live and forced, share everything here: the topology, the triggers, the model and the
checks. They differ only in how they schedule triggers. Everything goes through bgpsim's control socket, the peer's
own interface and the wire (a tcpdump capture); nothing reads bgpsim's memory.

The peers are FRR by default, or ExaBGP with --peer exa. Both are driven through the BgpPeer interface. A speaker
lists the remote-side triggers it can perform; ExaBGP has a static configuration, so its runs keep the process and
link triggers (stall, crash, restart, link) and all of bgpsim's own, and leave out clear, shutdown, refresh,
neighbor removal and family changes.

Topology: R bgpsim routers and P peers, every router peering with every peer over its own veth link, so the kernel
picks each session's source address and one link can fail alone. Odd peers activate IPv6 unicast, so the IPv6 ribout
is withheld from even ones; even peers have small TCP receive buffers, so their queues back up even while they read.

Every ribout edit sets a MED no other edit used (a tag). A route's MED then names the configuration it came from, so
peer's table shows whether a regenerated snapshot really reached the peer, without asking bgpsim.
"""

import argparse
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from ipaddress import ip_network
import itertools
import json
import os
from pathlib import Path
import random
import re
import signal
import subprocess
import threading
import time
import traceback

from bgp_capture import capture_packets, read_capture
from bgp_wire import IncompleteEvidence, UPDATE, prefix_key, update_fields, update_nlri
import exa_peer
import frr_peer
from bgp_peer import PeerUnavailable, proc_resources
from exa_peer import ExaPeer
from frr_peer import FrrPeer
from test_common import bgpsim, find_bgpsim_binary, wait_until
from test_results import emit

ROUTER_AS = 65000                 # Router r is AS 65000 + r
PEER_AS = 65100                   # peer peer k is AS 65100 + k
COMMAND_TIMEOUT = 40              # Client deadline of one control command (also bounds how fast a crash is seen)
SLOW_REPLY = 10.0                 # A reply slower than this is reported: the runtime loop stalled
SETTLE_SECONDS = 120              # Reconnect backoff reaches 16 s; queues drain; peer catches up
HOLD_GRACE = 15                   # A Hold Timer Expired this long after an impairment of that peer is expected
MAX_RUNS = 24                     # Unfinished runs a script actor keeps; terminal ones are cleared

# Rejections bgpsim documents for TX commands and script steps. Any other error text is a finding.
TX_REJECTIONS = re.compile('|'.join([
    r'session not established', r'is not advertised to this peer', r'route keys overlap ribout',
    r'has no UPDATE snapshot', r'changed since its snapshot', r'ribout \S+ is not configured',
    r'neighbor \S+ is not configured', r'router bgp \d+ is not configured', r'no router bgp is configured',
    r'not sent: another peer rejected the operation', r'too many operations queued for this peer',
    r'retained-snapshot budget exceeded', r'reset during the step', r'^no neighbors$', r'no router is in vrf',
]))
RUN_LIMIT = re.compile(r'model capacity or counter limit reached')
# Another control session can remove the router, neighbor or ribout a session is configuring.
GONE = (r'No router configured for|No neighbor context for|No ribout context|script context no longer exists|'
        r'Unknown Command: (no )?advertise')  # advertise needs neighbor mode; a raced router/neighbor removal
                                               # can drop the configure sequence out of it
CONFIG_RACES = re.compile(GONE)
SCRIPT_RACES = re.compile(r'^Error: not found$|script context no longer exists')
NEIGHBOR_GONE = re.compile(GONE + r'|Neighbor \S+ not found in router BGP')
ROUTER_GONE = re.compile(r'Router BGP \d+ not found')
CLEAR_MISSES = re.compile(r'No router matches this scope|No BGP neighbor \S+ found')
RIBOUT_GONE = re.compile(r"ribout \S+ is not configured|ribout '\S+' not found")
RUN_GONE = re.compile(r'run \d+ not found|operation is not valid in the current state')

# The speakers a run can peer with (--peer): each module has missing(), version() and its BgpPeer class.
PEER_KINDS = {'frr': frr_peer, 'exa': exa_peer}


def bgpsim_address(r, k):
    return f'172.{20 + r}.{k}.1'


def peer_address(r, k):
    return f'172.{20 + r}.{k}.2'


def prefixes(first, count):
    """The first count prefixes of a ribout's prefix line: each the next whole block of the same length."""
    net = ip_network(first)
    return [type(net)((int(net.network_address) + i * net.num_addresses, net.prefixlen)) for i in range(count)]


@dataclass(frozen=True)
class Spec:
    name: str
    first: str        # First prefix
    limit: int        # The most prefixes it ever has: its key universe
    count: int        # Prefixes at the baseline
    split: bool       # localpref range(...): one attribute group, so one UPDATE, per prefix
    next_hop: str


# Each ribout gets its own /8 so scaling route counts (up to --scale 100) never makes one spill into another's prefix
# space; shadow deliberately shares r4a's /8 to test route-key overlap.
SPECS = (
    Spec('r4a', '10.0.0.0/24', 250, 200, True, '192.0.2.1'),
    Spec('r4b', '20.0.0.0/24', 250, 100, False, '192.0.2.1'),
    Spec('r4c', '30.0.0.0/24', 250, 50, False, '192.0.2.1 x 4'),
    Spec('big', '11.0.0.0/30', 6000, 4000, True, '192.0.2.1'),
    Spec('six', '2001:db8:6::/64', 300, 150, True, '2001:db8:ffff::1'),
    Spec('std', '40.0.0.0/24', 100, 30, False, '192.0.2.1'),
    Spec('shadow', '10.0.0.0/24', 40, 20, False, '192.0.2.1'),   # Overlaps r4a: one peer can hold only one of them
)
def scaled_spec(spec, factor):
    """
    A copy of spec with its route counts multiplied by factor (>=1 each), keeping the prefix shape. factor 1.0 is
    the spec as written; larger factors scale route-table size (and so UPDATE volume and memory) without touching the
    topology.
    """
    count = max(1, round(spec.count * factor))
    limit = max(count, round(spec.limit * factor))
    return replace(spec, count=count, limit=limit)


BASELINE_ADVERTISED = ('r4a', 'r4b', 'r4c', 'big', 'six')
STANDING = 'std'


class Ribout:
    """
    What the test configured for one ribout. Only its config actor edits it, so its history is linear; a global
    update generate can still publish any state in that history, so every state is kept by tag.
    """

    def __init__(self, spec, model):
        self.spec = spec
        self.model = model
        self.all = prefixes(spec.first, spec.limit)
        self.universe = frozenset(self.all)
        self.counts = defaultdict(set)      # Tag -> prefix counts the ribout had with that tag
        self.tag = self.count = None
        self.split = spec.split
        self.exists = False

    def keys(self, count):
        return frozenset(self.all[:count])

    def record(self, tag=None, count=None, split=None):
        with self.model.lock:
            self.tag = self.tag if tag is None else tag
            self.count = self.count if count is None else count
            self.split = self.split if split is None else split
            self.counts[self.tag].add(self.count)

    def med_line(self, tag):
        return f'med {tag}'

    def localpref_line(self, split):
        return f'localpref {"range(1,6000)" if split else 100}'

    def prefix_line(self, count):
        return f'prefix {self.spec.first} x {count}'

    def lines(self, tag, count, split):
        """
        A whole block. The prefix comes last: before it the block is incomplete, so no generation can publish a
        state without this tag.
        """
        return [self.med_line(tag), self.localpref_line(split), 'as-path 64512 64513',
                f'next-hop {self.spec.next_hop}', self.prefix_line(count)]


class Model:
    def __init__(self, scale=1.0):
        self.lock = threading.Lock()
        self.tags = {}                      # Tag -> ribout name
        self.next_tag = itertools.count(1000)
        self.ribouts = {spec.name: Ribout(scaled_spec(spec, scale), self) for spec in SPECS}

    def new_tag(self, name):
        with self.lock:
            tag = next(self.next_tag)
            self.tags[tag] = name
            return tag


class Findings:
    """Thread-safe list of what went wrong, per check name, plus counters of what happened."""

    def __init__(self):
        self.lock = threading.Lock()
        self.items = defaultdict(list)
        self.counts = Counter()

    def add(self, check, text):
        with self.lock:
            if len(self.items[check]) < 50:
               self.items[check].append(text)
            self.counts[f'finding: {check}'] += 1

    def count(self, what, n=1):
        with self.lock:
            self.counts[what] += n

    def take(self):
        with self.lock:
            items, self.items = self.items, defaultdict(list)
            counts, self.counts = self.counts, Counter()
        return items, counts


class Undo:
    """
    Restorations that triggers schedule (resume a peer, bring a link up, re-add a neighbor). flush() runs every
    pending one at once and waits for those already running.
    """

    def __init__(self, findings):
        self.findings = findings
        self.cond = threading.Condition()
        self.pending = {}
        self.running = 0

    def later(self, delay, name, action):
        key = object()

        def fire():
            with self.cond:
                if self.pending.pop(key, None) is None:
                   return
                self.running += 1
            try:
                action()
            except Exception:
                self.findings.add('harness', f'undo {name}: {traceback.format_exc(limit=3)}')
            finally:
                with self.cond:
                    self.running -= 1
                    self.cond.notify_all()

        timer = threading.Timer(delay, fire)
        timer.daemon = True
        with self.cond:
            self.pending[key] = timer
        timer.start()

    def flush(self):
        with self.cond:
            timers = list(self.pending.items())
        for key, timer in timers:
            timer.cancel()
            timer.function()
        with self.cond:
            self.cond.wait_for(lambda: not self.pending and self.running == 0, timeout=SETTLE_SECONDS)


class Actors:
    """Threads that each fire one family of triggers, all at once. pause() returns once none is inside a trigger."""

    def __init__(self, findings, seed):
        self.findings = findings
        self.seed = seed
        self.go = threading.Event()
        self.stop = threading.Event()
        self.cond = threading.Condition()
        self.busy = 0
        self.threads = []

    def spawn(self, name, step, gap):
        rng = random.Random(f'{self.seed}:{name}')
        thread = threading.Thread(target=self.loop, args=(name, step, gap, rng), name=name, daemon=True)
        self.threads.append(thread)
        thread.start()

    def loop(self, name, step, gap, rng):
        while not self.stop.is_set():
            with self.cond:
                if not self.go.is_set():
                   self.cond.wait(0.2)
                   continue
                self.busy += 1
            try:
                step(rng)
            except Exception:
                self.findings.add('harness', f'{name}: {traceback.format_exc(limit=4)}')
            finally:
                with self.cond:
                    self.busy -= 1
                    self.cond.notify_all()
            self.stop.wait(rng.uniform(*gap))

    def resume(self):
        with self.cond:
            self.go.set()
            self.cond.notify_all()

    def pause(self):
        with self.cond:
            self.go.clear()
            if not self.cond.wait_for(lambda: self.busy == 0, timeout=SETTLE_SECONDS):
               self.findings.add('harness', f'{self.busy} triggers still running {SETTLE_SECONDS}s after pause')

    def close(self):
        self.pause()
        self.stop.set()
        for thread in self.threads:
            thread.join(10)


NEIGHBOR = re.compile(r'^BGP neighbor is (\S+), remote AS (\d+), local AS (\d+)')
BOUND = re.compile(r'^    (\S+): snapshot (\d+) \(([^)]*)\), (.+)$')
WITHDRAWING = re.compile(r'^    (\S+): withdrawing snapshot (\d+) ')
WITHHELD = re.compile(r'^    (\S+): withheld: (.+)$')


def parse_neighbors(text):
    """{(local AS, peer address): state, OutQ, bound {name: (snapshot, status)}, withdrawing, withheld, IPv6}."""
    found, current = {}, None
    for line in text.splitlines():
        match = NEIGHBOR.match(line)
        if match:
           current = dict(state=None, outq=0, bound={}, withdrawing=[], withheld={}, ipv6=False)
           found[(int(match[3]), match[1])] = current
           continue
        if current is None:
           continue
        if line.startswith('  BGP state = '):
           current['state'] = line.split('=', 1)[1].split(',')[0].strip()
        elif line.startswith('  Outbound ribouts: OutQ '):
            current['outq'] = int(line.split()[3])
        elif line.strip() == 'Multiprotocol IPv6 Unicast: advertised and received':
            current['ipv6'] = True
        elif (match := WITHDRAWING.match(line)):
            current['withdrawing'].append(match[1])
        elif (match := WITHHELD.match(line)):
            current['withheld'][match[1]] = match[2]
        elif (match := BOUND.match(line)):
            current['bound'][match[1]] = (int(match[2]), match[4])
    return found


class CaptureRecords:
    """
    Every UPDATE bgpsim sent, read back from tcpdump captures, per TCP session in send order.

    A withdrawn route must have been announced earlier on the same session and not withdrawn since; an announced route
    must lie in a ribout's prefix range and carry a MED that ribout really had; End-of-RIB comes at most once per
    family per session. TCP framing state persists across reads of the continuous capture.
    """

    def __init__(self, model, sources):
        self.model = model
        self.sources = sources
        self.flows = {}
        self.networks = {}
        self.parsed = {}
        self.capture_state = {}

    def network(self, nlri, afi, safi):
        key = (nlri, afi, safi)
        if key not in self.networks:
           self.networks[key] = ip_network(prefix_key(nlri, afi, safi))
        return self.networks[key]

    def feed(self, data, findings, *, final=True):
        try:
            streams = read_capture(data, partial=not final, state=self.capture_state)
        except IncompleteEvidence as exc:
            findings.add('wire evidence incomplete', str(exc))
            return False
        except AssertionError as exc:
            findings.add('wire', str(exc))
            return False
        for flow, stream in streams.items():
            if flow[0] not in self.sources or flow[3] != 179:
               continue
            if flow not in self.flows or stream['syn']:
               self.flows[flow] = dict(announced={}, eor=Counter(), known=stream['syn'])
               findings.count('wire sessions')
            state = self.flows[flow]
            findings.count('wire messages', len(stream['messages']))
            if stream['interrupted_bytes']:
               findings.count('wire interrupted messages')
               findings.count('wire interrupted bytes', stream['interrupted_bytes'])
            for kind, message in stream['messages']:
                if kind == UPDATE:
                   self.update(flow, state, message, findings)
        self.parsed.clear()
        return True

    def parse(self, message):
        """
        (announced networks, withdrawn networks, MED, End-of-RIB family or None, problem), cached by the bytes:
        one snapshot reaches every session, so most UPDATEs repeat.
        """
        if message in self.parsed:
           return self.parsed[message]
        withdrawn_routes, attrs, nlri = update_fields(message)
        announced, withdrawn = update_nlri(message)
        eor = bad = None
        if not announced and not withdrawn:
           if not withdrawn_routes and not nlri and not attrs:
              eor = (1, 1)
           elif set(attrs) == {15} and len(attrs[15]) == 3:
               eor = (int.from_bytes(attrs[15][:2], 'big'), attrs[15][2])
           else:
               bad = 'an UPDATE with attributes but no routes'
        result = ([self.network(n, *family) for family, keys in announced.items() for n in keys],
                  [self.network(n, *family) for family, keys in withdrawn.items() for n in keys],
                  int.from_bytes(attrs[4], 'big') if 4 in attrs else None, eor, bad)
        self.parsed[message] = result
        return result

    def update(self, flow, state, message, findings):
        findings.count('wire UPDATEs')
        announced, withdrawn, med, eor, bad = self.parse(message)
        where = f'{flow[0]}:{flow[1]} -> {flow[2]}'
        if bad:
           findings.add('wire', f'{where}: {bad}')
        if eor:
           state['eor'][eor] += 1
           if state['eor'][eor] > 1:
              findings.add('wire', f'{where}: End-of-RIB for {eor} sent twice on one session')
           return
        findings.count('wire withdrawn routes', len(withdrawn))
        findings.count('wire announced routes', len(announced))
        for network in withdrawn:
            if state['announced'].pop(network, None) is None and state['known']:
               findings.add('wire', f'{where}: withdrew {network}, which this session never announced')
        owner = self.model.tags.get(med)
        for network in announced:
            if owner is None:
               findings.add('wire', f'{where}: {network} carries MED {med}, which no ribout edit set')
            elif network not in self.model.ribouts[owner].universe:
                findings.add('wire', f'{where}: {network} carries the MED of {owner} but is outside its range')
            state['announced'][network] = med


class Capture:
    """
    One continuous tcpdump, with a cursor over complete records. Stopping/restarting between checks loses packets
    even when BGP's application queues are idle: old TCP sockets can still drain or retransmit during teardown.

    It records the sessions of its own test only: start() takes bgpsim's address of each. Other lanes run their tests
    on the same host at the same time, and a reader that met one of their streams mid-message would fail on it.
    """

    def __init__(self, fixture, directory):
        self.fixture = fixture
        self.directory = directory
        self.process = self.path = None
        self.offset = 24

    def start(self, hosts):
        self.directory.mkdir(parents=True, exist_ok=True)
        self.path = self.directory / 'wire.pcap'
        log = self.directory / 'tcpdump.log'
        mine = ' or '.join(f'host {host}' for host in sorted(hosts))
        self.process = self.fixture.start_process(
            ['tcpdump', '-i', 'any', '-s', '0', '-B', '65536', '-U', '-n', '-w', self.path,
             f'tcp port 179 and ({mine})'],
            log_path=log, retain_logs=True)
        self.log = log
        if not wait_until(lambda: 'listening on' in log.read_text(errors='replace') or self.process.poll() is not None,
                          10) or self.process.poll() is not None:
           raise RuntimeError(f'tcpdump did not start: {log.read_text(errors="replace")}')

    def read(self, final=False):
        """New whole records and their next file offset; commit that offset only after the record reader accepts them."""
        with self.path.open('rb') as capture:
            header = capture.read(24)
            capture.seek(self.offset)
            data = header + capture.read()
        end = 24
        # The shared framing walker stops before a partial record; that record remains for the next read.
        for _, _, end in capture_packets(data, partial=not final):
            pass
        return data[:end], self.offset + end - 24

    def wait_for(self, check, timeout):
        """
        check() once it is true, or its last false value after timeout seconds.

        The one way to wait for the capture. tcpdump hands packets over in blocks, so a packet is in the file some
        time after it was on the wire, and stop() loses whatever tcpdump has not been handed. Before a test reads
        the capture as complete or stops it, it waits here for the last thing it caused, by content: a filter that
        an earlier packet also matches (an End-of-RIB is an MP_UNREACH_NLRI too) waits for nothing.
        """
        return wait_until(check, timeout)

    def dissect(self, display_filter, fields):
        """One {name: [values]} per matching packet, as tshark decodes the capture; fields is {name: tshark field}."""
        argv = ['tshark', '-r', str(self.path), '-Y', display_filter, '-T', 'fields', '-E', 'separator=|',
                '-E', 'aggregator=,', '-E', 'occurrence=a']
        for field in fields.values():
            argv += ['-e', field]
        output = subprocess.run(argv, check=True, capture_output=True, text=True).stdout
        return [{name: [value for value in column.split(',') if value] for name, column in zip(fields, line.split('|'))}
                for line in output.splitlines()]

    def values(self, display_filter, fields):
        """
        Every value of each field over the matching packets, in capture order: {name: [values]} for fields given as
        {name: tshark field}, or the list alone for one field given by its tshark name. One TCP segment can hold
        several messages and one message several values, so this is the way to read a field; dissect() is for
        fields that must stay together packet by packet.
        """
        named = {'value': fields} if isinstance(fields, str) else fields
        found = {name: [] for name in named}
        for packet in self.dissect(display_filter, named):
            for name, column in packet.items():
                found[name] += column
        return found['value'] if isinstance(fields, str) else found

    def stop(self):
        """The capture file and how many packets the kernel dropped."""
        self.fixture.stop_process(self.process)
        text = self.log.read_text(errors='replace')
        dropped = re.search(r'(\d+) packets? dropped by kernel', text)
        return self.path, int(dropped[1]) if dropped else None


class Churn:
    """
    The shared harness. Drivers call setup(), then fire triggers and call settle(), check_bound() and
    reset_baseline(), then finish().
    """

    def __init__(self, fixture, args):
        self.fixture = fixture
        self.args = args
        self.seed = args.seed
        self.routers = range(1, args.routers + 1)
        self.peers = range(1, args.peers + 1)
        self.sessions = [(r, k) for r in self.routers for k in self.peers]
        self.model = Model(args.scale)
        self.findings = Findings()
        self.undo = Undo(self.findings)
        self.actors = Actors(self.findings, self.seed)
        self.namespaces = None
        self.peer = {}
        self.records = CaptureRecords(self.model, {bgpsim_address(r, k) for r, k in self.sessions})
        self.session = f'stress_{os.getpid()}'
        self.socket_path = None   # launch_daemon sets a private socket; attach mode connects by session name
        self.local = threading.local()
        self.runs = set()
        self.runs_lock = threading.Lock()
        self.impaired = defaultdict(list)    # Peer -> (start, end) of stalls, link failures and crashes
        self.peer_busy = defaultdict(threading.Lock)  # Per peer: one actor at a time may stop/resume its process
        self.forced_races = 0   # Observed mid-send races over the whole run (findings counters reset per report)
        self.notifications_seen = Counter()
        self.measurements = []
        self.evidence = Path(os.environ.get('BUILD_DIR', '/tmp')) / 'heavy-stress-evidence' / self.session
        self.capture = Capture(fixture, self.evidence)
        self.asan_dir = self.evidence / 'sanitizer'
        self.latency = 0.0
        self.failed = False
        self.crashed = False
        self.daemon = None          # The daemon as a direct child, so its exit signal is visible
        self.daemon_log = self.evidence / 'bgpsim.log'
        self.signal = None
        self.shutting_down = False  # set in finish(): the daemon closing the control link is then expected

    # --- Topology and configuration lines ---------------------------------------------------------------------

    def ipv6(self, k):
        return k % 2 == 1

    def router_lines(self, r):
        return [f'router bgp {ROUTER_AS + r}', f'router-id 10.255.0.{r}']

    def neighbor_lines(self, r, k, standing=()):
        lines = [f'neighbor {peer_address(r, k)} remote-as {PEER_AS + k}', 'address-family ipv4', 'address-family ipv6',
                 'capability route-refresh']
        return lines + [f'advertise {name}' for name in standing]

    def ribout_block(self, name, tag, count, split):
        ribout = self.model.ribouts[name]
        return [f'ribout {name}', *ribout.lines(tag, count, split), 'exit']

    def script_lines(self, name, rng):
        lines = [f'script {name}']
        for _ in range(rng.randint(2, 8)):
            if rng.random() < 0.25:
               lines.append(f'sleep {rng.randint(0, 40)}ms')
            else:
                verb = rng.choice(('advertise', 'advertise', 'withdraw', 'replay'))
                lines.append(f'{verb} ribout {self.pick_ribout(rng)} {self.target(rng)}')
        return lines + ['exit']

    def setup(self):
        self.namespaces = self.fixture.namespaces()
        for k in self.peers:
            namespace = f'bgpsim-{os.getpid()}-p{k}'
            self.namespaces.add(namespace)
            for r in self.routers:
                self.namespaces.link(namespace, self.link(r, k), [bgpsim_address(r, k)], [peer_address(r, k)],
                                     device=f'e{r}')
            if not self.ipv6(k):
                # Containers can mount /proc/sys read-only; ip netns exec has its own mount namespace to fix that in.
               subprocess.run(['ip', 'netns', 'exec', namespace, 'sh', '-c', 'mount -o remount,rw /proc/sys 2>/dev/null; '
                                'echo 4096 8192 16384 > /proc/sys/net/ipv4/tcp_rmem'], check=True, capture_output=True)
            neighbors = {bgpsim_address(r, k): (ROUTER_AS + r, self.ipv6(k)) for r in self.routers}
            if self.args.peer == 'exa':
               self.peer[k] = ExaPeer(self.fixture, f'p{k}', namespace, PEER_AS + k, peer_address(1, k), neighbors,
                                      {bgpsim_address(r, k): peer_address(r, k) for r in self.routers})
            else:
                self.peer[k] = FrrPeer(self.fixture, f'p{k}', namespace, PEER_AS + k, peer_address(1, k), neighbors)
        for peer in self.peer.values():
            peer.start()
        if not wait_until(lambda: all(peer.ready() for peer in self.peer.values()), 30):
           raise RuntimeError('peers did not start')
        self.capture.start(self.records.sources)
        self.asan_dir.mkdir(parents=True)
        lines = self.config_lines()
        if self.args.attach:
            # A daemon the caller already launched (under gdb or valgrind, in the foreground): we only drive it.
           self.session = self.args.attach
           self.pid = self.args.daemon_pid
           self.control = self.client()
           self.configure(lines)
        else:
            self.launch_daemon(lines)

    def launch_daemon(self, lines):
        """
        Run bgpsim as a direct, non-daemonized foreground child (plain `bgpsim <config>` does not fork), so its
        exit signal is visible and it can dump a core. stdin is a pipe we keep open so its CLI does not read EOF and
        exit; stdout/stderr and any sanitizer report land in the persistent evidence directory.
        """
        config = self.evidence / 'bgpsim.conf'
        config.write_text('\n'.join(lines) + '\n')
        # A private control socket per run, so this daemon has its own lane and never collides with other foreground
        # daemons (other stress lanes, the Python-API suite) on the shared default socket.
        self.socket_path = f'/tmp/{self.session}.sock'
        env = dict(self.fixture.env)
        env['BGPSIM_CONTROL_SOCKET'] = self.socket_path
        env['ASAN_OPTIONS'] = (f'log_path={self.asan_dir}/asan:abort_on_error=1:detect_leaks=1:handle_segv=1:'
                               'handle_abort=1:handle_sigfpe=1:print_stacktrace=1:disable_coredump=0')
        env['UBSAN_OPTIONS'] = f'log_path={self.asan_dir}/ubsan:print_stacktrace=1:halt_on_error=1'
        env.setdefault('BGPSIM_TX_MAX_JOBS', '1024')
        # -l keeps bgpsim's own log in the evidence directory, never the shared default /tmp/bgpsim.log that
        # concurrent lanes (test_shell_smoke) guard against.
        argv = [find_bgpsim_binary(), '-l', str(self.evidence / 'daemon.log'), str(config)]
        ready_timeout = 30
        wrapper = []
        if os.environ.get('BGPSIM_VALGRIND') == '1':
            # Run the daemon under valgrind to check the churn for memory errors and leaks. Much slower, so give it a
            # long startup budget; its report lands beside the other evidence.
           wrapper = ['valgrind', '--leak-check=full', '--show-leak-kinds=definite,possible', '--track-origins=yes',
                       '--error-exitcode=99', f'--log-file={self.evidence}/valgrind.log']
           ready_timeout = 180
        self.daemon = self.fixture.start_process(argv, log_path=self.daemon_log, cwd=self.evidence, env=env,
                                                 wrapper=wrapper, core_dump=True, retain_logs=True)
        self.pid = self.daemon.pid
        self.fixture.wait_ready(self.daemon, ready_timeout)
        self.control = self.client()

    def daemon_exit_signal(self):
        """The signal that killed the direct-child daemon, or None if it is alive or exited normally."""
        if self.daemon is None:
           return None
        code = self.daemon.poll()
        if code is not None and code < 0:
           return -code
        return None

    def link(self, r, k):
        return f't{os.getpid() % 100000}r{r}p{k}'

    def config_lines(self):
        """The baseline routers, neighbors, ribouts and scripts, as config-mode command lines."""
        lines = []
        for r in self.routers:
            lines += self.router_lines(r)
            for k in self.peers:
                lines += self.neighbor_lines(r, k, [STANDING])
            lines.append('exit')
        for name, ribout in self.model.ribouts.items():
            tag = self.model.new_tag(name)
            ribout.record(tag, ribout.spec.count, ribout.spec.split)
            ribout.exists = True
            lines += self.ribout_block(name, tag, ribout.spec.count, ribout.spec.split)
        rng = random.Random(f'{self.seed}:scripts')
        for index in range(self.args.scripts):
            lines += self.script_lines(f's{index}', rng)
        return lines

    # --- Control socket ---------------------------------------------------------------------------------------

    def client(self):
        return bgpsim.connect(self.session, self.socket_path, timeout=COMMAND_TIMEOUT)

    def my_client(self):
        """Each thread has its own control connection, so triggers run at once instead of queueing behind one."""
        if getattr(self.local, 'client', None) is None:
           self.local.client = self.client()
        return self.local.client

    def alive(self):
        """Whether the daemon this run started is still running."""
        if self.daemon is not None:
           return self.daemon.poll() is None
        return proc_resources(self.pid) is not None

    def check_alive(self, command):
        """
        Once per run, when a control call cannot reach the daemon: if its process is gone, that is a crash. Record
        it with whatever the sanitizer and the daemon log hold, and stop the run.
        """
        if self.crashed or self.shutting_down or self.alive():
           return
        self.crashed = True
        self.signal = self.daemon_exit_signal()
        named = f' (killed by SIG{signal.Signals(self.signal).name[3:]} = {self.signal})' if self.signal else ''
        notes = [f'bgpsim (pid {self.pid}) is gone{named}; {command!r} could not reach it']
        for report in sorted(self.asan_dir.glob('*')):
            notes.append(f'--- {report.name} ---\n{report.read_text(errors="replace")[:4000]}')
        log = self.evidence / 'daemon.log'
        if log.exists():
           try:
               notes.append('daemon log tail:\n' + '\n'.join(log.read_text(errors='replace').splitlines()[-15:]))
           except OSError:
               pass
        self.findings.add('crash', '\n'.join(notes))
        self.actors.stop.set()

    def cli(self, command, allowed=TX_REJECTIONS, client=None):
        """Run one command; report a lost connection, a slow reply or an undocumented rejection."""
        client = client or self.my_client()
        started = time.monotonic()
        try:
            reply = client.cli(command)
        except bgpsim.Error as exc:
            self.check_alive(command)
            if not self.shutting_down:
               self.findings.add('control', f'{command}: {exc}')
            return bgpsim.Reply(command=command, status=None, error=str(exc))
        elapsed = time.monotonic() - started
        with self.findings.lock:
            self.latency = max(self.latency, elapsed)
        self.findings.count('command: ' + ' '.join(command.split()[:2]))
        if reply.status is None:
           self.check_alive(command)
           if not self.crashed and not self.shutting_down:
              self.findings.add('control', f'{command}: {reply.error}')
        elif elapsed > SLOW_REPLY:
            self.findings.add('control', f'{command}: reply took {elapsed:.1f}s')
        if not reply and reply.status is not None:
           errors = [line for line in reply.splitlines() if line.startswith('Error')] or [reply.error]
           for error in errors:
               if allowed is None or not allowed.search(error):
                  self.findings.add('control', f'{command}: {error.strip()}')
               else:
                   self.findings.count('rejected as documented')
        return reply

    def configure(self, lines, allowed=None):
        """config ... end over this thread's connection; each line a separate command, so other threads interleave."""
        client = self.my_client()
        replies = [self.cli(line, allowed, client) for line in ['config', *lines]]
        self.cli('end', None, client)
        return all(replies)

    def neighbors(self):
        return parse_neighbors(self.cli('show bgp neighbors', None))

    # --- Picks ----------------------------------------------------------------------------------------------

    def pick_ribout(self, rng):
        names = [spec.name for spec in SPECS]
        return rng.choice(names + ['big', 'r4a', 'six'] + (['ghost'] if rng.random() < 0.05 else []))

    def target(self, rng):
        """A peer selector. A peer's address is on one router only, so it resolves with or without a scope."""
        r, k = rng.choice(self.routers), rng.choice(self.peers)
        roll = rng.random()
        if roll < 0.35:
           return f'router {ROUTER_AS + r} peer {peer_address(r, k)}'
        if roll < 0.55:
           return f'neighbor {peer_address(r, k)}'
        if roll < 0.70:
           return f'vrf default peer {peer_address(r, k)}'
        if roll < 0.85:
           return f'router {ROUTER_AS + r} peer all'
        return 'vrf all peer all'

    # --- bgpsim triggers -------------------------------------------------------------------------------------

    def tx_step(self, rng):
        """One advertise, withdraw, replay or withdraw-all to a random scope and peer."""
        verb = rng.choices(('advertise', 'withdraw', 'replay', 'withdraw all'), weights=(6, 3, 2, 1))[0]
        if verb == 'withdraw all':
           self.cli(f'withdraw all {self.target(rng)}')
        else:
            self.cli(f'{verb} ribout {self.pick_ribout(rng)} {self.target(rng)}')

    def edit_step(self, name):
        """
        One config actor per ribout: edits that change its keys, attributes or grouping, a delete and recreate,
        or nothing; then its own generation, or none, leaving the block to a global update generate.
        """
        ribout = self.model.ribouts[name]

        def create(rng):
            tag, count, split = self.model.new_tag(name), rng.randint(1, ribout.spec.limit), rng.random() < 0.5
            if self.configure([f'ribout {name}', *ribout.lines(tag, count, split)]):
               ribout.exists = True
               ribout.record(tag, count, split)

        def step(rng):
            roll = rng.random()
            if not ribout.exists:
               if roll < 0.5:
                  create(rng)
            elif roll < 0.08:
                self.configure([f'no ribout {name}'])
                ribout.exists = False
                self.findings.count('trigger: ribout deleted')
                if rng.random() < 0.7:
                   time.sleep(rng.uniform(0, 0.3))
                   create(rng)
            elif roll < 0.5:
                tag, count = self.model.new_tag(name), rng.randint(1, ribout.spec.limit)
                self.edit(ribout, [ribout.med_line(tag), ribout.prefix_line(count)], dict(tag=tag), dict(count=count))
                self.findings.count('trigger: keys changed')
            elif roll < 0.8:
                tag = self.model.new_tag(name)
                self.edit(ribout, [ribout.med_line(tag)], dict(tag=tag))
                self.findings.count('trigger: attributes changed')
            elif roll < 0.9:
                tag, split = self.model.new_tag(name), not ribout.split
                self.edit(ribout, [ribout.med_line(tag), ribout.localpref_line(split)], dict(tag=tag),
                          dict(split=split))
                self.findings.count('trigger: grouping changed')
            else:
                self.findings.count('trigger: unchanged')
            if rng.random() < 0.6:
               self.cli(f'update generate ribout {name}', RIBOUT_GONE)
        return step

    def edit(self, ribout, lines, *states):
        """Apply lines one at a time, recording the state the ribout is in after each."""
        client = self.my_client()
        self.cli('config', None, client)
        self.cli(f'ribout {ribout.spec.name}', None, client)
        for line, state in zip(lines, states):
            if self.cli(line, None, client):
               ribout.record(**state)
        self.cli('end', None, client)

    def generate_step(self, rng):
        roll = rng.random()
        if roll < 0.4:
           self.cli('update generate', None)
        elif roll < 0.8:
            self.cli('update generate changed', None)
        else:
            names = rng.sample([spec.name for spec in SPECS], rng.randint(1, 3))
            self.cli(f'update generate ribout {" ".join(names)}', RIBOUT_GONE)

    def standing_step(self, rng):
        r, k = rng.choice(self.routers), rng.choice(self.peers)
        name = rng.choice([spec.name for spec in SPECS])
        verb = '' if rng.random() < 0.55 else 'no '
        # Same commands fire (full churn), but only attempt advertise once the neighbor command actually entered
        # neighbor mode: a concurrent removal then yields the documented "No neighbor context", never a parser error.
        client = self.my_client()
        self.cli('config', None, client)
        for line in self.router_lines(r):
            self.cli(line, CONFIG_RACES, client)
        if self.cli(f'neighbor {peer_address(r, k)} remote-as {PEER_AS + k}', CONFIG_RACES, client):
           self.cli(f'{verb}advertise {name}', CONFIG_RACES, client)
        self.cli('end', None, client)
        self.findings.count(f'trigger: standing {verb.strip() or "added"}')

    def neighbor_step(self, rng):
        r, k = rng.choice(self.routers), rng.choice(self.peers)
        self.configure([*self.router_lines(r), f'no neighbor {peer_address(r, k)} remote-as {PEER_AS + k}'],
                       NEIGHBOR_GONE)
        self.findings.count('trigger: neighbor removed')
        standing = [STANDING] + rng.sample([spec.name for spec in SPECS], rng.randint(0, 2))
        self.undo.later(rng.uniform(0.05, 2.0), 'neighbor re-add',
                        lambda: self.configure([*self.router_lines(r), *self.neighbor_lines(r, k, standing)],
                                               CONFIG_RACES))

    def router_step(self, rng):
        r = rng.choice(self.routers)
        self.configure([f'no router bgp {ROUTER_AS + r}'], ROUTER_GONE)
        self.findings.count('trigger: router removed')

        def readd():
            self.configure(self.router_lines(r) + [line for k in self.peers for line in
                                                   self.neighbor_lines(r, k, [STANDING])], CONFIG_RACES)
        self.undo.later(rng.uniform(0.2, 2.0), 'router re-add', readd)

    def clear_step(self, rng):
        r, k = rng.choice(self.routers), rng.choice(self.peers)
        target = rng.choice([f'router {ROUTER_AS + r} {peer_address(r, k)}', peer_address(r, k),
                             f'router {ROUTER_AS + r} *', 'vrf all *'])
        self.cli(f'clear bgp {target}', CLEAR_MISSES)
        self.findings.count('trigger: bgpsim clear')

    def script_step(self, rng):
        mine = getattr(self.local, 'runs', None)
        if mine is None:
           mine = self.local.runs = []
        roll = rng.random()
        client = self.my_client()
        if roll < 0.55 and len(mine) < MAX_RUNS:
           repeat = 'forever' if rng.random() < 0.05 else rng.randint(1, 20)
           run = client.start_script(f's{rng.randrange(self.args.scripts)}', repeat=repeat)
           if run['id'] is not None:
              mine.append(run['id'])
              with self.runs_lock:
                  self.runs.add(run['id'])
              self.findings.count('trigger: run started')
           elif not RUN_LIMIT.search(run['error']):
               self.findings.add('control', f'run script: {run["error"]}')
        elif roll < 0.75 and mine:
            run_id = rng.choice(mine)
            self.cli(f'cancel run {run_id}', RUN_GONE)
            self.findings.count('trigger: run cancelled')
        elif roll < 0.9:
            self.collect_runs(mine)
        else:
            name = f's{rng.randrange(self.args.scripts)}'
            # Two actors can redefine one script at the same time: the other's `no script` then removes the script
            # this one is adding steps to, and bgpsim says so.
            self.configure([f'no script {name}', *self.script_lines(name, rng)], SCRIPT_RACES)
            self.findings.count('trigger: script redefined')

    def collect_runs(self, mine):
        """Check finished runs failed only for documented reasons, then clear them."""
        for run_id in list(mine):
            run = self.my_client().run_status(run_id)
            if run is None:
               mine.remove(run_id)
               continue
            if run['state'] in ('complete', 'failed', 'cancelled'):
               if run['state'] == 'failed' and not TX_REJECTIONS.search(run['error']):
                  self.findings.add('runs', f'run {run_id} failed: {run["error"]}')
               self.findings.count(f'run {run["state"]}')
               self.cli(f'clear run {run_id}', RUN_GONE)
               mine.remove(run_id)
               with self.runs_lock:
                   self.runs.discard(run_id)

    def show_step(self, rng):
        roll = rng.random()
        if roll < 0.15:
            # A client that leaves mid-command: the server must not care.
           client = bgpsim.connect(self.session, self.socket_path, timeout=COMMAND_TIMEOUT)
           client.sock.sendall(client.build_frame(bgpsim.BGPSIM_CTRL_EXEC_REQ, payload=b'show bgp neighbors'))
           client.disconnect()
           self.findings.count('trigger: control client dropped')
           return
        command = rng.choice(['show bgp neighbors', 'show bgp summary', 'show ribout', f'show ribout {rng.choice(SPECS).name}',
                              'show runs', 'show running-config', 'show scripts'])
        self.cli(command, None)

    # --- peer-side triggers -----------------------------------------------------------------------------------

    def peer_step(self, k):
        peer = self.peer[k]

        def mark(seconds):
            now = time.time()
            self.impaired[k].append((now, now + seconds))

        # Process and link triggers work on any speaker; the others only where the speaker can do them (TRIGGERS).
        weighted = {'clear': 10, 'clear all': 3, 'shutdown': 6, 'refresh': 10, 'refresh all': 3, 'stall': 6, 'crash': 2,
                    'restart': 2, 'delete': 3, 'family': 3, 'link': 5}
        kinds = [kind for kind in weighted
                 if kind in ('stall', 'crash', 'restart', 'link') or kind.split()[0] in peer.TRIGGERS]
        weights = [weighted[kind] for kind in kinds]

        def step(rng):
            r = rng.choice(self.routers)
            address = bgpsim_address(r, k)
            kind = rng.choices(kinds, weights=weights)[0]
            self.findings.count(f'trigger: peer {kind}')
            # Every peer perturbation can make this peer reconnect; record a window so a reconnect/collision NOTIFICATION
            # (Hold Timer or FSM error) around it is counted but not faulted. Off-window 4/5 still faults.
            mark(3)
            try:
                if kind == 'clear':
                   peer.clear(address)
                elif kind == 'clear all':
                    peer.clear()
                elif kind == 'shutdown':
                    peer.shutdown(address)
                    self.undo.later(rng.uniform(0.05, 2.0), 'peer no shutdown',
                                    lambda: self.peer_restore(peer, address))
                elif kind == 'refresh':
                    for _ in range(rng.randint(1, 5)):
                        peer.refresh(address)
                elif kind == 'refresh all':
                    peer.refresh()
                elif kind == 'stall':
                    if not self.peer_busy[k].acquire(blocking=False):
                       return  # another chaos action owns this peer's process right now
                    seconds = rng.uniform(0.05, 1.5)
                    mark(seconds)
                    peer.pause()
                    self.undo.later(seconds, 'peer resume', lambda: self.peer_resume(peer, k, peer.resume))
                elif kind in ('crash', 'restart'):
                    if not self.peer_busy[k].acquire(blocking=False):
                       return
                    seconds = rng.uniform(0, 2.0)
                    mark(seconds + 5)
                    peer.kill() if kind == 'crash' else peer.stop()
                    self.undo.later(seconds, 'peer start', lambda: self.peer_resume(peer, k, peer.start))
                elif kind == 'delete':
                    peer.remove(address)
                    self.undo.later(rng.uniform(0.05, 2.0), 'peer neighbor re-add',
                                    lambda: self.peer_restore(peer, address))
                elif kind == 'family':
                    peer.set_ipv6(address, not self.ipv6(k))
                    self.undo.later(rng.uniform(0.2, 3.0), 'peer family restore', lambda: self.peer_restore(peer, address))
                else:
                    seconds = rng.uniform(0.05, 2.0)
                    mark(seconds)
                    subprocess.run(['ip', 'link', 'set', self.link(r, k), 'down'], check=True, capture_output=True)
                    self.undo.later(seconds, 'link up', lambda: subprocess.run(
                        ['ip', 'link', 'set', self.link(r, k), 'up'], check=True, capture_output=True))
            except PeerUnavailable:
                pass  # The speaker is being bounced by a concurrent trigger; this perturbation simply did not land.
        return step

    def peer_resume(self, peer, k, action):
        """Run the deferred resume/start of a peer's process and always release its per-peer lock."""
        try:
            action()
        finally:
            self.peer_busy[k].release()

    def peer_restore(self, peer, address):
        # Best effort: a concurrent crash/restart trigger may be bouncing this speaker, so it can fail transiently.
        if peer.running() and not peer.paused:
           try:
               peer.restore(address)
           except PeerUnavailable:
               pass  # The speaker is being bounced by a concurrent trigger; restore will be retried next round.

    # --- Running the actors ----------------------------------------------------------------------------------

    def spawn_actors(self):
        """One thread per trigger family, one per ribout and one per peer: every family fires at the same time."""
        spawn = self.actors.spawn
        for index in range(self.args.tx_actors):
            spawn(f'tx-{index}', self.tx_step, (0, 0.01))
        overlay = self.args.mode == 'max'   # also run forced interleavings concurrently with the live chaos
        for spec in SPECS:
            # In overlay mode the forced actor owns 'big' config edits, so keep one editor per ribout.
            if overlay and spec.name == 'big':
               continue
            spawn(f'edit-{spec.name}', self.edit_step(spec.name), (0.02, 0.25))
        spawn('generate', self.generate_step, (0.03, 0.3))
        spawn('standing', self.standing_step, (0.02, 0.2))
        spawn('neighbor', self.neighbor_step, (0.3, 2.0))
        spawn('router', self.router_step, (3.0, 8.0))
        spawn('clear', self.clear_step, (0.2, 1.0))
        for index in range(2):
            spawn(f'script-{index}', self.script_step, (0.02, 0.3))
        spawn('show', self.show_step, (0, 0.05))
        if overlay:
           spawn('forced', self.forced_step, (0.1, 1.0))
        for k in self.peers:
            spawn(f'peer-{k}', self.peer_step(k), (0.1, 1.0))

    # --- Forced interleavings (reproducible: wait for an observed state, then act) ----------------------------

    def forced_step(self, rng):
        """
        One deterministic interleaving: back a peer up mid-send, then tear down or regenerate under it, then let
        it drain. Each sub-step waits for an observed state, so the ordering repeats without depending on timing.
        """
        if self.args.mode == 'max':
           # Under the live chaos a wait on one random session can use up the whole window: take a live one.
           states = self.neighbors()
           live = [(r, k) for r, k in self.sessions
                   if states.get((ROUTER_AS + r, peer_address(r, k)), {}).get('state') == 'Established']
           if not live:
              self.findings.count('forced setup failed: no established session')
              return
           r, k = rng.choice(live)
        else:
            r, k = rng.choice(self.routers), rng.choice(self.peers)
        peer = self.peer[k]
        # One actor at a time may stop/resume a peer's process: skip if another chaos action (a peer stall/crash/
        # restart) currently owns it, so pause/resume can't interleave on the same bgpd.
        if not self.peer_busy[k].acquire(blocking=False):
           return
        # 1. Pause the receiver so a large advertisement backs up in bgpsim's queue. While paused it cannot send
        #    keepalives, so record an impairment window: the Hold Timer / FSM reconnect NOTIFICATIONs around it are
        #    then counted, not faulted (an off-window one still faults).
        paused_at = time.time()
        try:
            # Max mode picked a session that was Established a moment ago: if the chaos has just dropped it, give
            # up at once and let the next step pick another, instead of spending the window on this one.
            if not wait_until(lambda: self.neighbors().get((ROUTER_AS + r, peer_address(r, k)), {}).get('state') ==
                                      'Established', 1 if self.args.mode == 'max' else 8):
               self.findings.count('forced setup failed: session not established')
               if self.args.mode == 'forced':
                  self.findings.add('harness', f'forced setup: router {ROUTER_AS + r} -> p{k} never established')
               return
            peer.pause()
            self.cli(f'advertise ribout big router {ROUTER_AS + r} peer {peer_address(r, k)}')
            # 2. Wait until bgpsim is mid-send to this peer (queue not drained). Capped short so the actor stays
            #    responsive when overlaid with the live chaos. An identical advertise is a no-op, so replay a bound
            #    snapshot until the stopped receiver's TCP buffers fill, and advertise again when a refusal or a
            #    concurrent withdraw left it unbound, rather than claiming a forced race after an idle timeout.
            seen = {}

            def backed_up():
                state = self.neighbors().get((ROUTER_AS + r, peer_address(r, k))) or {}
                seen.update(state=state.get('state') or 'session gone',
                            status=state.get('bound', {}).get('big', (None, ''))[1] or 'big not bound')
                if seen['state'] != 'Established' or state['outq']:
                   return True   # Backed up, or torn down under the stopped peer, where no backlog can build.
                verb = {'advertised': 'replay', 'big not bound': 'advertise'}.get(seen['status'])
                if verb:
                   self.cli(f'{verb} ribout big router {ROUTER_AS + r} peer {peer_address(r, k)}')
                return False

            if not wait_until(backed_up, 8) or seen['state'] != 'Established':
               self.findings.count(f"forced setup failed: queue never backed up ({seen['state']}, {seen['status']})")
               if self.args.mode == 'forced':
                  self.findings.add('harness', f'forced setup: router {ROUTER_AS + r} -> p{k} never backed up')
               return
            self.findings.count('forced interleavings')
            self.forced_races += 1
            # 3. Perform the racing operation while the write is in flight.
            race = rng.choice(('regenerate', 'no-neighbor', 'no-router', 'clear', 'no-ribout-big', 'withdraw'))
            if race == 'regenerate':
               tag = self.model.new_tag('big')
               self.edit(self.model.ribouts['big'], [self.model.ribouts['big'].med_line(tag)], dict(tag=tag))
               self.cli('update generate ribout big', RIBOUT_GONE)
            elif race == 'no-neighbor':
                # Re-add inline (same thread) right after the teardown, so the interleaving is reproducible.
                self.configure([*self.router_lines(r), f'no neighbor {peer_address(r, k)} remote-as {PEER_AS + k}'],
                               NEIGHBOR_GONE)
                self.configure([*self.router_lines(r), *self.neighbor_lines(r, k, [STANDING])], CONFIG_RACES)
            elif race == 'no-router':
                self.configure([f'no router bgp {ROUTER_AS + r}'], ROUTER_GONE)
                self.configure(self.router_lines(r) + [ln for j in self.peers
                               for ln in self.neighbor_lines(r, j, [STANDING])], CONFIG_RACES)
            elif race == 'clear':
                self.cli(f'clear bgp router {ROUTER_AS + r} {peer_address(r, k)}', CLEAR_MISSES)
            elif race == 'no-ribout-big':
                self.configure(['no ribout big'])
                self.model.ribouts['big'].exists = False
                self.recreate_big()
            else:
                self.cli(f'withdraw ribout big router {ROUTER_AS + r} peer {peer_address(r, k)}')
            self.findings.count(f'forced race: {race}')
        finally:
            peer.resume()
            # Cover the pause plus the reconnect backoff after resume.
            self.impaired[k].append((paused_at, time.time() + 30))
            self.peer_busy[k].release()

    def recreate_big(self):
        ribout = self.model.ribouts['big']
        tag = self.model.new_tag('big')
        if self.configure(['ribout big', *ribout.lines(tag, ribout.spec.count, ribout.spec.split)]):
           ribout.exists = True
           ribout.record(tag, ribout.spec.count, ribout.spec.split)
        self.cli('update generate ribout big', RIBOUT_GONE)

    def forced_background(self, rng):
        """A few ordinary triggers between forced interleavings, so the daemon is never quiescent."""
        for step in rng.sample([self.tx_step, self.generate_step, self.standing_step, self.script_step,
                                self.clear_step, self.show_step], rng.randint(1, 3)):
            step(rng)

    # --- Settling and checks ---------------------------------------------------------------------------------

    def restore(self):
        """
        Undo every impairment and put the configuration of both sides back to the baseline topology; standing
        advertisements and ribouts stay as the triggers left them.
        """
        self.undo.flush()
        for r, k in self.sessions:
            subprocess.run(['ip', 'link', 'set', self.link(r, k), 'up'], check=True, capture_output=True)
        for peer in self.peer.values():
            peer.resume()
            peer.start()
        if not wait_until(lambda: all(peer.ready() for peer in self.peer.values()), 30):
           self.findings.add('harness', 'peers did not come back')
        for peer in self.peer.values():
            peer.restore()
        present = self.neighbors()
        for r in self.routers:
            missing = [k for k in self.peers if (ROUTER_AS + r, peer_address(r, k)) not in present]
            lines = [line for k in self.peers for line in self.neighbor_lines(r, k)]
            self.configure(self.router_lines(r) + lines)
            self.findings.count('restored neighbors', len(missing))

    def finish_runs(self):
        with self.runs_lock:
            runs = sorted(self.runs)
        for run_id in runs:
            self.cli(f'cancel run {run_id}', RUN_GONE)
        for run_id in runs:
            run = self.my_client().wait_run(run_id, timeout=SETTLE_SECONDS)
            if run is not None and run['state'] not in ('complete', 'failed', 'cancelled'):
               self.findings.add('runs', f'run {run_id} still {run["state"]} after cancel')
            elif run is not None and run['state'] == 'failed' and not TX_REJECTIONS.search(run['error']):
                self.findings.add('runs', f'run {run_id} failed: {run["error"]}')
            self.cli(f'clear run {run_id}', RUN_GONE)
        with self.runs_lock:
            self.runs.clear()

    def idle(self):
        """Every session Established on both sides, and bgpsim has nothing queued for any."""
        neighbors = self.neighbors()
        for r, k in self.sessions:
            state = neighbors.get((ROUTER_AS + r, peer_address(r, k)))
            if not state or state['state'] != 'Established' or state['outq'] or state['withdrawing'] or \
                    any(status != 'advertised' for _, status in state['bound'].values()):
               return False
        peer_states = self.parallel(lambda peer: peer.states(), self.peer.values())
        return all(state == 'Established' for states in peer_states for state in states.values())

    def parallel(self, function, items):
        with ThreadPoolExecutor(max_workers=16) as pool:
            return list(pool.map(function, items))

    def settle(self):
        self.actors.pause()
        if self.crashed:
           return False
        self.restore()
        self.finish_runs()
        if not wait_until(self.idle, SETTLE_SECONDS):
           self.findings.add('settle', f'sessions not Established and idle after {SETTLE_SECONDS}s: '
                              f'{self.cli("show bgp summary", None)}')
           return False
        return True

    def peer_routes(self):
        """{(r, k): {network: MED}} from peer, every session at once."""
        def one(session):
            r, k = session
            return session, self.peer[k].routes(bgpsim_address(r, k))
        return dict(self.parallel(one, self.sessions))

    def bound_problems(self):
        """What disagrees between peer's tables, the ribout histories and what bgpsim says is bound."""
        neighbors = self.neighbors()
        routes = self.peer_routes()
        problems, by_snapshot = [], {}
        for (r, k), table in routes.items():
            where = f'router {ROUTER_AS + r} -> p{k}'
            state = neighbors.get((ROUTER_AS + r, peer_address(r, k)))
            bound = state['bound'] if state else {}
            groups = defaultdict(set)
            for network, med in table.items():
                groups[med].add(network)
            seen = {}
            for med, networks in groups.items():
                owner = self.model.tags.get(med)
                if owner is None:
                   problems.append(f'{where}: {len(networks)} routes with MED {med}, which no ribout edit set')
                   continue
                ribout = self.model.ribouts[owner]
                if not any(networks == ribout.keys(count) for count in ribout.counts[med]):
                   problems.append(f'{where}: {owner} holds {len(networks)} routes with MED {med}; that state had '
                                    f'{sorted(ribout.counts[med])} prefixes')
                if owner in seen:
                   problems.append(f'{where}: {owner} holds routes of two states (MED {seen[owner]} and {med})')
                seen[owner] = med
                if owner in bound:
                   by_snapshot.setdefault(bound[owner][0], set()).add((med, frozenset(networks)))
            if set(seen) != set(bound):
               problems.append(f'{where}: peer holds {sorted(seen)}, bgpsim reports {sorted(bound)} bound')
        for snapshot, contents in by_snapshot.items():
            if len(contents) > 1:
               problems.append(f'snapshot {snapshot} reached peers with different contents: '
                                f'{sorted((med, len(nets)) for med, nets in contents)}')
        return problems

    def poll(self, problems, timeout):
        """Recheck until problems() finds none or the time is up; the last problems found."""
        last = []

        def clean():
            last[:] = problems()
            return not last
        wait_until(clean, timeout)
        return last

    def check_bound(self, label):
        """Exact: every peer table equals what bgpsim reports bound, each ribout's share one whole state of it."""
        self.record(f'{label}: every peer session holds exactly the snapshots bgpsim reports bound',
                    self.poll(self.bound_problems, 30))

    def standing_now(self):
        """{(r, k): [standing ribouts]} from the running configuration."""
        standing, router, neighbor = defaultdict(list), None, None
        for line in self.cli('show running-config', None).splitlines():
            if line.startswith('router bgp '):
               router, neighbor = int(line.split()[2]), None
            elif line.startswith('  neighbor ') and router:
                neighbor = line.split()[1]
            elif line.startswith('    advertise ') and router and neighbor:
                standing[(router, neighbor)].append(line.split()[1])
        return standing

    def baseline_expected(self):
        expected = {}
        for r, k in self.sessions:
            table = {}
            for name in BASELINE_ADVERTISED + (STANDING,):
                if name == 'six' and not self.ipv6(k):
                   continue
                ribout = self.model.ribouts[name]
                table.update(dict.fromkeys(ribout.keys(ribout.count), ribout.tag))
            expected[(r, k)] = table
        return expected

    def table_problems(self, expected):
        problems = []
        for session, table in self.peer_routes().items():
            want = expected[session]
            if table != want:
               missing = len(set(want) - set(table))
               extra = len(set(table) - set(want))
               wrong = sum(1 for network in set(want) & set(table) if want[network] != table[network])
               problems.append(f'router {ROUTER_AS + session[0]} -> p{session[1]}: {missing} missing, {extra} '
                                f'extra, {wrong} with the wrong MED')
        return problems

    def wait_tables(self, expected, timeout=60):
        return self.poll(lambda: self.table_problems(expected), timeout)

    def reset_baseline(self, label):
        """
        From a settled state to the baseline, checked against the test's own model only: withdraw everything, then
        advertise every ribout at its baseline everywhere. Then measure the processes.
        """
        for (router, neighbor), names in self.standing_now().items():
            r = router - ROUTER_AS
            k = next(k for k in self.peers if peer_address(r, k) == neighbor)
            self.configure([*self.router_lines(r), f'neighbor {neighbor} remote-as {PEER_AS + k}',
                            *[f'no advertise {name}' for name in names]])
        self.cli('withdraw all vrf all peer all')
        self.record(f'{label}: withdraw all leaves every peer session empty',
                    self.wait_tables({session: {} for session in self.sessions}))
        lines = []
        for name, ribout in self.model.ribouts.items():
            tag = self.model.new_tag(name)
            lines += [f'ribout {name}', *ribout.lines(tag, ribout.spec.count, ribout.spec.split), 'exit']
            ribout.exists = True
            ribout.record(tag, ribout.spec.count, ribout.spec.split)
        self.configure(lines)
        self.cli('update generate', None)
        neighbors = self.neighbors()
        renegotiate = [(r, k) for r, k in self.sessions
                       if neighbors.get((ROUTER_AS + r, peer_address(r, k)), {}).get('ipv6') != self.ipv6(k)]
        for r, k in renegotiate:
            # A neighbor re-added by a trigger may have opened before its address-family lines arrived.
            self.cli(f'clear bgp router {ROUTER_AS + r} {peer_address(r, k)}', None)
        if renegotiate and not wait_until(self.idle, SETTLE_SECONDS):
           self.findings.add('settle', 'renegotiated sessions did not come back')
        for r in self.routers:
            self.configure([*self.router_lines(r), *[line for k in self.peers
                                                     for line in self.neighbor_lines(r, k, [STANDING])]])
        for name in BASELINE_ADVERTISED:
            self.cli(f'advertise ribout {name} vrf all peer all', None)
        overlap = self.cli('advertise ribout shadow vrf all peer all', re.compile(r'route keys overlap ribout r4a'))
        self.record(f'{label}: advertising shadow over r4a is refused for every peer',
                    [] if not overlap and 'route keys overlap ribout r4a' in overlap.error + overlap else
                    [f'advertise ribout shadow: {overlap.status}: {overlap.error or overlap}'])
        self.record(f'{label}: every peer session holds exactly the baseline the test predicts',
                    self.wait_tables(self.baseline_expected()))
        if not wait_until(self.idle, SETTLE_SECONDS):
           self.findings.add('settle', 'not idle after the baseline')
        self.measure(label)

    def measure(self, label):
        bgpsim_now = proc_resources(self.pid)
        peers = {f'p{k}': peer.resources() for k, peer in self.peer.items()}
        self.measurements.append(dict(label=label, time=time.time(), bgpsim=bgpsim_now, peers=peers))
        if bgpsim_now:
           print(f'{label}: bgpsim RSS {bgpsim_now["rss_kib"]} KiB (peak {bgpsim_now["peak_kib"]}), '
                  f'{bgpsim_now["fds"]} fds, {bgpsim_now["threads"]} threads; peer RSS KiB '
                  f'{ {name: (value or {}).get("rss_kib") for name, value in peers.items()} }', flush=True)
        if self.args.report:
           with open(self.args.report, 'a') as report:
               report.write(json.dumps(self.measurements[-1]) + '\n')

    def check_capture(self, label):
        """Validate the next complete records without interrupting capture; final verification resolves every tail."""
        if self.shutting_down:
           # Process exit can precede TCP's final queued bytes/FIN. Observe that evidence before stopping tcpdump;
           # carry-over tails from earlier files must also resolve. Malformed data fails feed(), without a retry.
           def complete():
               try:
                   data, _ = self.capture.read()
                   read_capture(data, state=dict(self.records.capture_state))
               except IncompleteEvidence:
                   return False
               except AssertionError:
                   return True
               return True

           wait_until(complete, 5)
           _, dropped = self.capture.stop()
           if dropped != 0:
              self.findings.add('wire evidence incomplete', f'tcpdump kernel packet-drop count: {dropped}')
        try:
            data, end = self.capture.read(final=self.shutting_down)
            if self.records.feed(data, self.findings, final=self.shutting_down):
               self.capture.offset = end
        except AssertionError as exc:
            self.findings.add('wire evidence incomplete', str(exc))

    def peer_logs(self):
        """
        NOTIFICATIONs other than Cease, and Hold Timer Expired away from an impairment of that peer, are findings;
        so is any line where peer reports a malformed UPDATE.
        """
        for k, peer in self.peer.items():
            notifications, errors = peer.log_events()
            for line in errors:
                self.findings.add('peer', f'p{k}: {line}')
            for event in notifications[self.notifications_seen[k]:]:
                when, direction, neighbor, code, subcode, text = event
                self.findings.count(f'NOTIFICATION {code}/{subcode} {text}')
                if code == 6:
                   continue
                near_impairment = any(start - 1 <= when <= end + HOLD_GRACE for start, end in self.impaired[k])
                # Hold Timer (4) and FSM errors (5) can occur as a reconnect/connection-collision artifact while this
                # peer is being bounced by the test's own churn. Count them, but only fault if they happen off-churn.
                if code in (4, 5) and near_impairment:
                   continue
                self.findings.add('peer', f'p{k}: NOTIFICATION {direction} {neighbor} {code}/{subcode} ({text})')
            self.notifications_seen[k] = len(notifications)

    def record(self, name, problems):
        if problems:
           emit('fail', name, detail='\n'.join(problems[:20]))
        else:
            emit('pass', name)
        self.failed = self.failed or bool(problems)

    def report_findings(self, label):
        """One check per finding category, with the counters of what happened in between."""
        self.peer_logs()
        items, counts = self.findings.take()
        incomplete = items.pop('wire evidence incomplete', [])
        if incomplete:
           items.setdefault('wire', []).extend(f'incomplete evidence: {text}' for text in incomplete)
        for check, title in (('crash', 'bgpsim stayed up (no crash)'),
                             ('control', 'every control reply was accepted or a documented rejection, in time'),
                             ('runs', 'every run ended, and failed only for documented reasons'),
                             ('wire', 'the wire shows no withdraw before an announce, no stray route or MED'),
                             ('peer', 'peers saw no malformed UPDATE and no NOTIFICATION other than Cease'),
                             ('settle', 'every session came back and drained'),
                             ('harness', 'the harness itself ran without errors')):
            self.record(f'{label}: {title}', items.pop(check, []))
        for check, texts in items.items():
            self.record(f'{label}: {check}', texts)
        width = max((len(name) for name in counts), default=0)
        print(f'{label}: what happened (longest reply {self.latency:.2f}s)', flush=True)
        for name, value in sorted(counts.items()):
            print(f'  {name:<{width}} {value}', flush=True)
        self.latency = 0.0
        return counts

    def finish(self, label):
        """Stop bgpsim the way an operator does and read its sanitizer report."""
        self.actors.close()
        if self.crashed:
           self.record(f'{label}: bgpsim stayed up for the whole run', ['bgpsim crashed during the run; see the '
                        f'crash finding and {self.evidence}'])
           return
        if self.args.mode == 'max':
           # Without one observed race the overlay never ran, and the run was only the live chaos.
           self.record(f'{label}: the max overlay forced at least one observed mid-send race',
                       [] if self.forced_races else ['no forced interleaving reached a backed-up outbound queue'])
        self.shutting_down = True   # from here the daemon closing the control connection is expected, not a fault
        if self.args.attach:
           self.cli('shutdown', None)  # The caller owns the process; just ask it to exit.
           return
        self.cli('shutdown', None)
        self.daemon.stdin.close()  # EOF the foreground CLI so it returns from its read and exits
        exited = wait_until(lambda: not self.alive(), 120)
        signal_note = f'exited on signal {self.daemon_exit_signal()}' if self.daemon_exit_signal() else ''
        self.record(f'{label}: bgpsim exits cleanly after shutdown',
                    [] if exited and not self.daemon_exit_signal() else [signal_note or 'still running 120s later'])
        reports = [path.read_text(errors='replace') for path in sorted(self.asan_dir.glob('*'))]
        self.record(f'{label}: bgpsim exits with no AddressSanitizer or LeakSanitizer report', reports)
        log = self.daemon_log.read_text(errors='replace') if self.daemon_log.exists() else ''
        sanitizer = [line for line in log.splitlines() if 'Sanitizer' in line or 'runtime error' in line]
        self.record(f'{label}: the bgpsim log has no sanitizer output', sanitizer)
        self.parallel(lambda peer: peer.stop(), self.peer.values())

    def leak_trend(self, label, warmup=2, minimum=10):
        """Steady state at the baseline: descriptors and threads equal, and RSS not growing over the run."""
        points = [m for m in self.measurements if m['bgpsim']][warmup:]
        if len(points) < 2:
           emit('skip', f'{label}: memory trend needs at least {warmup + 2} measured cycles')
           return
        first = points[0]['bgpsim']
        changed = [f'{m["label"]}: {m["bgpsim"]["fds"]} fds, {m["bgpsim"]["threads"]} threads' for m in points
                   if (m['bgpsim']['fds'], m['bgpsim']['threads']) != (first['fds'], first['threads'])]
        self.record(f'{label}: bgpsim descriptors and threads return to {first["fds"]} and {first["threads"]} at '
                    f'every baseline', changed)
        if len(points) < minimum:
           emit('skip', f'{label}: memory trend needs {minimum} measured cycles, have {len(points)}')
           return
        rss = [m['bgpsim']['rss_kib'] for m in points]
        third = max(len(rss) // 3, 1)
        early, late = sorted(rss[:third])[third // 2], sorted(rss[-third:])[third // 2]
        allowed = max(8192, early // 5)
        self.record(f'{label}: bgpsim RSS at the baseline grew {late - early} KiB over {len(rss)} cycles '
                    f'(limit {allowed})', [f'median RSS {early} -> {late} KiB'] if late - early > allowed else [])

    def close(self):
        """Stop what the harness drives. The fixture then stops the peers and, after them, removes the namespaces."""
        self.actors.close()
        self.undo.flush()
        for peer in self.peer.values():
            peer.resume()
        if self.daemon is not None:
           self.fixture.stop_process(self.daemon)



def arguments(description, **defaults):
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('--mode', choices=('live', 'forced', 'max'), default='live')
    parser.add_argument('--peer', choices=tuple(PEER_KINDS), default='frr', help='the BGP speaker bgpsim peers with')
    parser.add_argument('--seed', type=int, default=defaults.get('seed', random.SystemRandom().randrange(1 << 30)))
    parser.add_argument('--routers', type=int, default=3)
    parser.add_argument('--peers', type=int, default=6)
    parser.add_argument('--scripts', type=int, default=8)
    parser.add_argument('--tx-actors', type=int, default=3)
    parser.add_argument('--scale', type=float, default=1.0,
                        help='multiply every ribout\'s route counts (UPDATE volume and memory), 1.0 = as written')
    parser.add_argument('--report', help='append one JSON line of resource readings per baseline to this file')
    parser.add_argument('--attach', help='drive a daemon already running on this session instead of launching one')
    parser.add_argument('--daemon-pid', type=int, help='the pid of the --attach daemon, for liveness and resources')
    for name, value in defaults.items():
        if name != 'seed':
           parser.add_argument(f'--{name.replace("_", "-")}', type=type(value), default=value)
    args = parser.parse_args()
    if not 1 <= args.routers <= 9 or not 1 <= args.peers <= 250:
       parser.error('1-9 routers and 1-250 peers')
    if not 0 < args.scale <= 100:
       parser.error('scale must be in (0, 100]')
    return args


def unavailable(kind):
    """Why this kind of peer cannot run here, or None."""
    return PEER_KINDS[kind].missing()


def peer_version(kind):
    return PEER_KINDS[kind].version()
