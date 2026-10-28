"""
A real BGP speaker as the remote peer: one process in its own network namespace.

BgpPeer is what every speaker gives the tests: process control, the session states, the routes it holds from a
neighbor, and its NOTIFICATIONs. A speaker also lists the remote-side triggers it can perform (TRIGGERS), so a test
that runs against several speakers fires only what each one supports.
"""

import os
from pathlib import Path
import signal


class PeerUnavailable(RuntimeError):
    """The speaker did not answer because of the test's own churn (it is being bounced): a transient, not an error."""


def proc_resources(pid):
    """
    RSS and peak RSS in KiB, threads and open descriptors of a live process, from /proc; None once it is gone or a
    zombie. A dead-but-unreaped process keeps a status file with state Z and no VmRSS, so a missing VmRSS means gone.
    """
    try:
        status = Path(f'/proc/{pid}/status').read_text()
        fds = len(os.listdir(f'/proc/{pid}/fd'))
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        return None
    fields = dict(line.split(':', 1) for line in status.splitlines() if ':' in line)
    if fields.get('State', '').strip().startswith(('Z', 'X')) or 'VmRSS' not in fields:
       return None
    return dict(rss_kib=int(fields['VmRSS'].split()[0]), peak_kib=int(fields['VmHWM'].split()[0]),
                threads=int(fields['Threads']), fds=fds)


class BgpPeer:
    """neighbors maps a bgpsim address to (its AS, whether IPv6 unicast is activated)."""

    TRIGGERS = ()  # Of: clear, shutdown, refresh, delete, family. Process triggers (stall, crash, restart) always work.

    def __init__(self, fixture, name, namespace, asn, router_id, neighbors):
        self.fixture = fixture
        self.name = name
        self.namespace = namespace
        self.asn = asn
        self.router_id = router_id
        self.neighbors = dict(neighbors)
        self.directory = fixture.root / name
        self.directory.mkdir()
        self.process = None
        self.paused = False

    def running(self):
        return self.process is not None and self.process.poll() is None

    def pid(self):
        return self.process.pid if self.running() else None

    def signal(self, signum):
        if self.running():
           os.kill(self.process.pid, signum)

    def pause(self):
        self.signal(signal.SIGSTOP)
        self.paused = True

    def resume(self):
        self.signal(signal.SIGCONT)
        self.paused = False

    def kill(self):
        """A crash: no NOTIFICATION, the sockets just close."""
        self.resume()
        self.signal(signal.SIGKILL)
        if self.process is not None:
           self.fixture.stop_process(self.process)

    def stop(self):
        """A clean stop: bgpd sends Cease to every neighbor first."""
        self.resume()
        if self.process is not None:
           self.fixture.stop_process(self.process)

    def resources(self):
        return proc_resources(self.process.pid) if self.running() else None

    # --- What each speaker implements ---------------------------------------------------------------------------

    def start(self):
        raise NotImplementedError

    def ready(self):
        raise NotImplementedError

    def states(self):
        """{bgpsim address: 'Established' or another state name}."""
        raise NotImplementedError

    def routes(self, address):
        """{network: MED} of every unicast route held from that neighbor; None as the MED when the route has none."""
        raise NotImplementedError

    def log_events(self):
        """(NOTIFICATIONs as (time, direction, neighbor, code, subcode, text), lines reporting malformed UPDATEs)."""
        raise NotImplementedError

    def restore(self, address=None):
        """Put the configuration of one neighbor, or of all, back to the baseline; nothing for a static speaker."""
