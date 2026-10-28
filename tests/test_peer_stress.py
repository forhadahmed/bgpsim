#!/usr/bin/env python3
"""Stress the real daemon with a two-router matrix of real C BGP peers.

Each active router has ten IPv4 and, on Linux, ten distinct-loopback IPv6
peers. The active scenarios share a live matrix; passive FSM scenarios use a
separate daemon. Only processes and loopback aliases created here are cleaned
up, including when a phase fails.
"""

from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import subprocess
import time
import unittest
import uuid

from test_common import (
    ProcessFixture, bgpsim, find_bgpsim_binary, find_test_client_binary,
    wait_until,
)
from test_results import emit, run_unittest


ROUTER_COUNT = 2
PEERS_PER_ROUTER = 10
STRESS_WAIT_SECONDS = 60
PEER_KEEPALIVE_SECONDS = 90
PEER_DELAY_TAMPER_SECONDS = 1
PASSIVE_ROUTER_AS = 65080
PASSIVE_PEER_AS = 65180
PASSIVE_ROUTER_ID = "10.255.0.1"
PASSIVE_PEER_ROUTER_ID = "203.255.0.1"


def read_log(path):
    try:
        return path.read_text(errors="replace")
    except FileNotFoundError:
        return ""


def pick_listen_base():
    """Keep both router ports below ephemeral ports and outside live TCP bands."""
    override = os.environ.get("BGPSIM_LISTEN_BASE_PORT")
    if override:
        base = int(override)
        if not 1024 <= base <= 65534:
            raise ValueError("BGPSIM_LISTEN_BASE_PORT must be between 1024 and 65534")
        return base

    ephemeral_low = 32768
    try:
        ephemeral_low = int(Path("/proc/sys/net/ipv4/ip_local_port_range")
                            .read_text().split()[0])
    except OSError:
        pass
    used_ports = set()
    for path in (Path("/proc/net/tcp"), Path("/proc/net/tcp6")):
        try:
            for line in path.read_text().splitlines()[1:]:
                used_ports.add(int(line.split()[1].rsplit(":", 1)[1], 16))
        except FileNotFoundError:
            pass
    size, minimum = 200, 10000
    slots = (ephemeral_low - minimum) // size
    for offset in range(slots):
        base = minimum + ((os.getpid() + offset) % slots) * size
        if any(base <= port < base + size for port in used_ports):
            continue
        try:
            with socket.socket() as first, socket.socket() as second:
                first.bind(("0.0.0.0", base))
                second.bind(("0.0.0.0", base + 1))
            return base
        except OSError:
            continue
    raise RuntimeError("No free listener port band below the ephemeral port range")


@dataclass(frozen=True)
class Router:
    index: int
    asn: int
    port: int
    router_id: str
    ipv6_source: str


@dataclass
class Peer:
    slot: int
    family: int
    router: Router
    address: str
    asn: int
    router_id: str
    log: Path
    process: subprocess.Popen = None
    generation: int = 0


class PeerStressTest(unittest.TestCase):
    def setUp(self):
        self.aliases = []
        self.admin = []
        # Fixture teardown closes all sockets before aliases are removed.
        self.addCleanup(self.cleanup_aliases)
        self.resources = ExitStack()
        self.addCleanup(self.resources.close)
        self.fixture = self.resources.enter_context(ProcessFixture())
        self.session = f"peer_stress_{os.getpid()}_{uuid.uuid4().hex[:8]}"
        self.server_log = self.fixture.root / "server.log"
        self.client = None
        self.peers = []
        self.diagnostic_peers = []
        self.probe_number = 0
        self.bgpsim_binary = find_bgpsim_binary()
        self.peer_binary = find_test_client_binary()
        for binary in (self.bgpsim_binary, self.peer_binary):
            self.assertTrue(os.access(binary, os.X_OK), f"Executable missing: {binary}")
        self.base_port = pick_listen_base()
        self.env = dict(os.environ, BGPSIM_LISTEN_BASE_PORT=str(self.base_port))
        # A caller's tamper environment must not affect the normal/recovery peers.
        self.env["BGP_TEST_TAMPER"] = "none"
        self.env["BGP_TEST_TAMPER_DELAY"] = str(PEER_DELAY_TAMPER_SECONDS)
        print(f"[INFO] session={self.session} port_band={self.base_port} "
              f"artifacts={self.fixture.root}", flush=True)

    @contextmanager
    def phase(self, key, name, peers=()):
        self.diagnostic_peers = list(peers)
        started = time.monotonic()
        print(f"[INFO] START {name}", flush=True)
        try:
            yield
        except unittest.SkipTest:
            raise
        except Exception:
            print(f"[INFO] FAILED phase: {name}", flush=True)
            self.dump_diagnostics()
            raise
        else:
            counts = ""
            if self.client is not None:
                snapshot = self.cli("show bgp neighbors")
                counts = (f" established={snapshot.count('BGP state = Established')}"
                          f" configured={snapshot.count('BGP neighbor is ')}")
            print(f"[INFO] END {name} ({time.monotonic() - started:.3f}s){counts}",
                  flush=True)
            emit("pass", name, key=key)

    def cli(self, command):
        output = self.client.cli(command)
        self.assertNotRegex(output, r"(?im)^\s*(?:%\s*)?(?:Error:|Unknown command|Invalid command)",
                            f"CLI command failed: {command}\n{output}")
        return output

    def cli_sequence(self, commands):
        return "".join(self.cli(command) for command in commands)

    def connect_control(self):
        self.client = self.resources.enter_context(bgpsim.connect(session=self.session))
        self.client.sock.settimeout(STRESS_WAIT_SECONDS)

    def dump_diagnostics(self):
        if self.client is not None:
            for command in ("show bgp summary", "show bgp neighbors"):
                try:
                    print(f"\n=== {command} ===\n{self.client.cli(command)}", flush=True)
                except bgpsim.Error as error:
                    print(f"Control diagnostics unavailable: {error}", flush=True)
        paths = sorted(self.fixture.root.glob("start-*.log")) + [self.server_log]
        paths.extend(peer.log for peer in self.diagnostic_peers)
        paths.extend(self.fixture.root.glob("passive_client_*.log"))
        for path in paths:
            print(f"\n=== {path.name} (tail) ===\n" +
                  "\n".join(read_log(path).splitlines()[-40:]), flush=True)

    def wait_counts(self, established=None, configured=None):
        snapshot = ""

        def matches():
            nonlocal snapshot
            snapshot = self.cli("show bgp neighbors")
            return ((established is None or
                     snapshot.count("BGP state = Established") == established) and
                    (configured is None or
                     snapshot.count("BGP neighbor is ") == configured))

        self.assertTrue(wait_until(matches, STRESS_WAIT_SECONDS),
                        f"Expected established={established}, configured={configured}\n{snapshot}")
        return snapshot

    def wait_log(self, path, text, offset=0):
        self.assertTrue(wait_until(lambda: text in read_log(path)[offset:],
                                   STRESS_WAIT_SECONDS),
                        f"Missing log evidence: {text}\n{read_log(path)[-4000:]}")

    def probe_bind(self, address, port):
        self.probe_number += 1
        log = self.fixture.root / f"probe_{self.probe_number}.log"
        process = self.fixture.start_process(
            [self.peer_binary, "--passive", address, str(port), "65099", "203.0.113.1", "1"],
            log_path=log, env=self.env)
        try:
            ready = wait_until(lambda: "Listening on " in read_log(log) or
                               process.poll() is not None, STRESS_WAIT_SECONDS)
            return bool(ready and process.poll() is None and "Listening on " in read_log(log))
        finally:
            self.fixture.stop_process(process)

    def alias_command(self, address, add):
        ipv6 = ":" in address
        if platform.system() == "Darwin":
            if ipv6:
                args = (["inet6", address, "prefixlen", "128", "alias"] if add else
                        ["inet6", address, "delete"])
            else:
                args = ["alias", address, "up"] if add else ["-alias", address]
            return self.admin + ["ifconfig", "lo0"] + args
        if platform.system() == "Linux" and shutil.which("ip"):
            return (self.admin + ["ip"] + (["-6"] if ipv6 else []) +
                    ["addr", "add" if add else "del", f"{address}/{128 if ipv6 else 8}",
                     "dev", "lo"])
        return None

    def ensure_address(self, address, port):
        if self.probe_bind(address, port):
            return
        command = self.alias_command(address, add=True)
        if command is None:
            self.skipTest(f"Loopback alias unavailable for {address} on this host")
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        if result.returncode:
            self.skipTest(f"Cannot add required loopback alias {address}: {result.stderr.strip()}")
        self.aliases.append(address)
        self.assertTrue(self.probe_bind(address, port), f"C peer cannot bind added alias {address}")

    def cleanup_aliases(self):
        errors = []
        for address in reversed(self.aliases):
            command = self.alias_command(address, add=False)
            try:
                result = subprocess.run(command, capture_output=True, text=True, timeout=10)
                if result.returncode:
                    errors.append(f"Cannot remove owned alias {address}: {result.stderr}")
            except (OSError, subprocess.TimeoutExpired) as error:
                errors.append(f"Cannot remove owned alias {address}: {error}")
        self.assertFalse(errors, "\n".join(errors))

    def build_matrix(self):
        prefix = f"fd00:7f00:{os.getpid() % 65536:x}"
        self.routers = [Router(index, 65000 + index, self.base_port + index,
                               f"10.0.{index + 1}.1", f"{prefix}:{101 + index}::1")
                        for index in range(ROUTER_COUNT)]
        self.families = (4, 6) if platform.system() == "Linux" else (4,)
        if 6 not in self.families:
            emit("skip", "IPv6 active peers: distinct-loopback IPv6 topology requires Linux",
                 key="ipv6-topology")
        for family in self.families:
            family_index = 0 if family == 4 else 1
            for router in self.routers:
                for number in range(1, PEERS_PER_ROUTER + 1):
                    slot = family_index * 20 + router.index * PEERS_PER_ROUTER + number - 1
                    address = (f"127.{10 + router.index}.0.{number}" if family == 4 else
                               f"{prefix}:{router.index + 1}::{number}")
                    self.peers.append(Peer(
                        slot, family, router, address,
                        65100 + family_index * 20 + router.index * 100 + number,
                        f"203.{family_index + 1}.{router.index + 1}.{number}",
                        self.fixture.root / f"peer_{slot}.log"))
        self.total = ROUTER_COUNT * PEERS_PER_ROUTER * len(self.families)
        self.assertEqual(len(self.peers), self.total)

    def select_peers(self, router_numbers):
        selected = [peer for family in self.families
                    for router_index, number in router_numbers
                    for peer in self.peers
                    if peer.family == family and peer.router.index == router_index and
                    (peer.slot % PEERS_PER_ROUTER) == number - 1]
        self.assertEqual(len(selected), len(self.families) * len(router_numbers),
                         "Scenario must exercise every selected slot in every active family")
        return selected

    def write_matrix_config(self):
        lines = []
        for router in self.routers:
            lines.extend([f"router bgp {router.asn}", f"  router-id {router.router_id}"])
            for peer in self.peers:
                if peer.router == router:
                    lines.append(f"  neighbor {peer.address} remote-as {peer.asn}")
                    if peer.family == 6:
                        lines.append(f"    update-source {router.ipv6_source}")
            lines.append("!")
        config = self.fixture.root / "matrix.conf"
        config.write_text("\n".join(lines) + "\n")
        return config

    def start_peers(self, peers, tampers=None, short_lived=False):
        tampers = tampers or {}
        for peer in peers:
            self.assertTrue(peer.process is None or peer.process.poll() is not None,
                            f"Refusing to replace live owned peer {peer.slot}")
            peer.generation += 1
            peer.log = self.fixture.root / f"peer_{peer.slot}_{peer.generation}.log"
            env = dict(self.env)
            tamper = tampers.get(peer.slot)
            if tamper:
                env["BGP_TEST_TAMPER"] = tamper
                env["BGP_TEST_TAMPER_DELAY"] = str(PEER_DELAY_TAMPER_SECONDS)
            peer.process = self.fixture.start_process(
                [self.peer_binary, "--passive", peer.address, str(peer.router.port),
                 str(peer.asn), peer.router_id, str(PEER_KEEPALIVE_SECONDS)],
                log_path=peer.log, env=env)
        # Launch the entire group before checking readiness, as in the shell suite.
        for peer in peers:
            self.assertTrue(wait_until(lambda: "Listening on " in read_log(peer.log) or
                                       peer.process.poll() is not None, STRESS_WAIT_SECONDS),
                            f"Peer {peer.slot} did not listen: {read_log(peer.log)}")
            status = peer.process.poll()
            self.assertIn("Listening on ", read_log(peer.log))
            if status is not None:
                self.assertTrue(short_lived and status == 0,
                                f"Peer {peer.slot} exited early ({status}): {read_log(peer.log)}")

    def stop_peers(self, peers):
        self.fixture.stop_processes(peer.process for peer in peers if peer.process is not None)
        for peer in peers:
            peer.process = None

    def wait_peers_exit(self, peers, clean=False):
        self.assertTrue(wait_until(lambda: all(peer.process.poll() is not None for peer in peers),
                                   STRESS_WAIT_SECONDS),
                        "C peers did not close: " +
                        ", ".join(str(peer.slot) for peer in peers if peer.process.poll() is None))
        if clean:
            for peer in peers:
                self.assertEqual(peer.process.returncode, 0,
                                 f"Tamper peer {peer.slot} failed: {read_log(peer.log)}")

    def configure_peers(self, peers, remove=False):
        commands = ["configure terminal"]
        for router in self.routers:
            commands.append(f"router bgp {router.asn}")
            for peer in peers:
                if peer.router != router:
                    continue
                commands.append(f"{'no ' if remove else ''}neighbor {peer.address} remote-as {peer.asn}")
                if not remove:
                    if peer.family == 6:
                        commands.append(f"update-source {router.ipv6_source}")
                    commands.append("exit")
            commands.append("exit")
        commands.append("end")
        self.cli_sequence(commands)

    def assert_peer_counters(self, snapshot):
        for peer in self.peers:
            block = re.search(rf"(?ms)^BGP neighbor is {re.escape(peer.address)},.*?"
                              r"(?=^BGP neighbor is |\Z)", snapshot)
            self.assertIsNotNone(block, f"Missing neighbor {peer.address}")
            self.assertIn(f"remote AS {peer.asn}, local AS {peer.router.asn}", block[0])
            self.assertIn(f"remote router ID {peer.router_id}", block[0])
            for label in ("Opens", "Keepalives"):
                counts = re.search(rf"{label}:\s+(\d+)\s+(\d+)", block[0])
                self.assertIsNotNone(counts, f"Missing {label} counters for {peer.address}")
                self.assertTrue(all(int(value) >= 1 for value in counts.groups()),
                                f"Missing bidirectional {label} evidence for {peer.address}: {counts[0]}")

    def exercise_tampers(self, name, key, numbers, kinds, short_lived):
        peers = self.select_peers(numbers)
        tampers = {peer.slot: kinds[peer.router.index] for peer in peers}
        with self.phase(key, name, peers):
            self.stop_peers(peers)
            self.wait_counts(established=self.total - len(peers), configured=self.total)
            self.start_peers(peers, tampers, short_lived=short_lived)
            if short_lived:
                self.wait_peers_exit(peers, clean=True)
            else:
                self.wait_counts(established=self.total, configured=self.total)
            for peer in peers:
                self.wait_log(peer.log, f"Tamper {tampers[peer.slot]}:")
            if short_lived:
                self.wait_counts(established=self.total - len(peers), configured=self.total)
                self.start_peers(peers)
            self.wait_counts(established=self.total, configured=self.total)

    def test_active_peer_matrix(self):
        self.build_matrix()
        with self.phase("loopback-addresses", "Loopback peer addresses are available for active stress"):
            if shutil.which("sudo") and subprocess.run(
                    ["sudo", "-n", "true"], stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, timeout=10).returncode == 0:
                self.admin = ["sudo", "-n"]
            for peer in self.peers:
                self.ensure_address(peer.address, peer.router.port)
            if 6 in self.families:
                for router in self.routers:
                    self.ensure_address(router.ipv6_source, router.port)

        with self.phase("initial-matrix", "Initial active peer matrix reaches Established", self.peers):
            config = self.write_matrix_config()
            self.start_peers(self.peers)
            self.assertTrue(self.fixture.start_session(self.session, config=config,
                                                       log_path=self.server_log, env=self.env))
            self.connect_control()
            snapshot = self.wait_counts(established=self.total, configured=self.total)
            self.assert_peer_counters(snapshot)

        refused = self.select_peers([(0, 10), (1, 10)])
        with self.phase("connection-refusal", "Connection refusals trigger retry and recover when peers appear",
                        refused):
            log_offset = len(read_log(self.server_log))
            self.stop_peers(refused)
            self.wait_counts(established=self.total - len(refused), configured=self.total)
            for peer in refused:
                self.wait_log(self.server_log, f"Attempting connection to {peer.address} (retry 1", log_offset)
            self.start_peers(refused)
            self.wait_counts(established=self.total, configured=self.total)

        closed = self.select_peers([(0, 2), (1, 5)])
        with self.phase("socket-close", "Peer socket closes recover back to the full matrix", closed):
            self.stop_peers(closed)
            self.wait_counts(established=self.total - len(closed), configured=self.total)
            self.start_peers(closed)
            self.wait_counts(established=self.total, configured=self.total)

        cleared = self.select_peers([(0, 3), (1, 8)])
        with self.phase("clear-targeted-and-all", "Targeted clear and clear-all both recover cleanly", cleared):
            for peer in cleared:
                self.cli(f"clear bgp {peer.address}")
            self.wait_peers_exit(cleared)
            self.start_peers(cleared)
            self.wait_counts(established=self.total, configured=self.total)
            self.diagnostic_peers = self.peers
            self.cli("clear bgp *")
            self.wait_peers_exit(self.peers)
            self.start_peers(self.peers)
            self.wait_counts(established=self.total, configured=self.total)

        reconfigured = self.select_peers([(0, 1), (1, 1)])
        with self.phase("live-reconfiguration", "Live neighbor unconfigure and reconfigure recovers cleanly",
                        reconfigured):
            self.stop_peers(reconfigured)
            self.configure_peers(reconfigured, remove=True)
            self.wait_counts(established=self.total - len(reconfigured),
                             configured=self.total - len(reconfigured))
            self.start_peers(reconfigured)
            self.configure_peers(reconfigured)
            self.wait_counts(established=self.total, configured=self.total)

        original = next(peer for peer in self.peers if peer.slot == 0)
        filler = Peer(-1, 4, self.routers[0], "127.10.0.99", 65199, "203.1.1.99",
                      self.fixture.root / "unused-filler.log")
        with self.phase("neighbor-slot-reuse", "Neighbor slot reuse: filler takes freed slot, original lands elsewhere",
                        [original]):
            self.stop_peers([original])
            self.configure_peers([original], remove=True)
            self.wait_counts(configured=self.total - 1)
            self.configure_peers([filler])
            self.wait_counts(configured=self.total)
            self.start_peers([original])
            self.configure_peers([original])
            self.wait_counts(configured=self.total + 1)
            summary = self.cli("show bgp summary")
            addresses = [line.split()[0] for line in summary.splitlines() if line.split()]
            self.assertIn(filler.address, addresses)
            self.assertIn(original.address, addresses)
            self.assertLess(addresses.index(filler.address), addresses.index(original.address), summary)
            self.configure_peers([filler], remove=True)
            self.wait_counts(established=self.total, configured=self.total)

        scenarios = [
            ("Delayed OPEN and KEEPALIVE peers still establish cleanly", "delayed-handshake",
             [(0, 6), (1, 6)], ("delay_open", "delay_keepalive"), False),
            ("Connection-close FSM tampers are contained and the matrix recovers", "close-tampers",
             [(0, 7), (1, 7)], ("close_after_accept", "close_after_open"), True),
            ("OPEN message tampers are contained and the matrix recovers", "open-tampers",
             [(0, 9), (1, 9)], ("wrong_open_as", "bad_open_length"), True),
            ("Header and body corruption tampers are contained and the matrix recovers", "malformed-tampers",
             [(0, 4), (1, 4)], ("invalid_header", "partial_open"), True),
        ]
        for scenario in scenarios:
            self.exercise_tampers(*scenario)

        with self.phase("stress-log-retrieval", "show log all returns a stress-sized log with timing", self.peers):
            self.assert_peer_counters(self.wait_counts(established=self.total, configured=self.total))
            log_bytes = self.server_log.stat().st_size
            self.assertGreaterEqual(log_bytes, 1024, "Stress log unexpectedly small")
            started = time.perf_counter()
            output = self.cli("show log all")
            elapsed_ms = (time.perf_counter() - started) * 1000
            self.assertIn("=== All Log Entries", output)
            self.assertGreater(len(output.encode()), 0)
            print(f"[INFO] show log all timing: {elapsed_ms:.1f}ms "
                  f"output_bytes={len(output.encode())} output_lines={output.count(chr(10))} "
                  f"log_file_bytes={log_bytes}", flush=True)

    def start_passive_daemon(self):
        config = self.fixture.root / "passive.conf"
        config.write_text(f"router bgp {PASSIVE_ROUTER_AS}\n"
                          f"  router-id {PASSIVE_ROUTER_ID}\n"
                          f"  neighbor 127.0.0.1 remote-as {PASSIVE_PEER_AS}\n")
        self.assertTrue(self.fixture.start_session(self.session, config=config,
                                                   log_path=self.server_log, passive=True, env=self.env))
        self.connect_control()
        self.wait_log(self.server_log, f"BGP router {PASSIVE_ROUTER_AS} listening on port {self.base_port}")

    def passive_client(self, name, keepalive_seconds=0, tamper=None):
        log = self.fixture.root / f"passive_client_{name}.log"
        env = dict(self.env)
        if tamper:
            env["BGP_TEST_TAMPER"] = tamper
        process = self.fixture.start_process(
            [self.peer_binary, "--active", "127.0.0.1", str(self.base_port),
             str(PASSIVE_PEER_AS), PASSIVE_PEER_ROUTER_ID, str(keepalive_seconds)],
            log_path=log, env=env)
        self.assertTrue(wait_until(lambda: process.poll() is not None, STRESS_WAIT_SECONDS),
                        f"Passive client did not exit: {read_log(log)}")
        self.assertEqual(process.returncode, 0, read_log(log))
        output = read_log(log)
        self.assertIn("BGP Session ESTABLISHED", output)
        self.wait_counts(established=0, configured=1)
        return output

    def passive_counters(self):
        output = self.cli("show bgp neighbors")
        counters = {}
        for label in ("Opens", "Keepalives", "Notifications"):
            match = re.search(rf"{label}:\s+(\d+)\s+(\d+)", output)
            self.assertIsNotNone(match, output)
            counters[label] = tuple(map(int, match.groups()))
        resets = re.search(r"Session resets: (\d+)", output)
        counters["resets"] = int(resets[1]) if resets else 0
        return counters

    def test_passive_fsm(self):
        with self.phase("passive-establishment", "Passive mode establishes, advertises router ID, and exchanges KEEPALIVEs"):
            self.start_passive_daemon()
            output = self.passive_client("keepalive", keepalive_seconds=1)
            self.assertIn(f"Received OPEN: AS={PASSIVE_ROUTER_AS}, ID={PASSIVE_ROUTER_ID},", output)
            for evidence in ("Received KEEPALIVE", "Sending KEEPALIVE", "KEEPALIVE TEST: PASSED"):
                self.assertIn(evidence, output)
            before = self.passive_counters()
            for label in ("Opens", "Keepalives"):
                self.assertTrue(all(value >= 1 for value in before[label]), before)

        with self.phase("passive-reconnect", "Passive mode accepts clean reconnects"):
            self.passive_client("reconnect")
            reconnected = self.passive_counters()
            for label in ("Opens", "Keepalives"):
                for old, new in zip(before[label], reconnected[label]):
                    self.assertGreater(new, old, f"Reconnect counter did not advance: {label}")

        with self.phase("passive-notification", "Passive-mode NOTIFICATION resets preserve session counters"):
            offset = len(read_log(self.server_log))
            output = self.passive_client("notification", tamper="send_notification")
            self.assertIn("NOTIFICATION sent", output)
            self.assertIn("Session closed by bgpsim", output)
            self.wait_log(self.server_log, "BGP session reset: Received NOTIFICATION", offset)
            self.wait_log(self.server_log, "Session statistics preserved", offset)
            after = self.passive_counters()
            self.assertEqual(after["Notifications"][1], reconnected["Notifications"][1] + 1)
            self.assertGreater(after["resets"], reconnected["resets"])
            for label in ("Opens", "Keepalives"):
                for old, new in zip(reconnected[label], after[label]):
                    self.assertGreater(new, old, f"Notification reset lost counter evidence: {label}")
            print(f"[INFO] Counters before notification: {reconnected}; after reset: {after}", flush=True)


if __name__ == "__main__":
    raise SystemExit(run_unittest())
