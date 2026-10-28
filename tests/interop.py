"""
The topology of the interop tests: one bgpsim in this namespace, each peer in a namespace of its own on veth links,
one capture of port 179, and a control client.

InteropTest is the one owner of what every such test needs and of the waits that go with it:

- skipping when a peer or a capture tool is not installed;
- the order of teardown (the fixture stops its processes, then removes their namespaces and links);
- starting the peers, the capture and bgpsim, configuring bgpsim, and waiting for every session;
- a capture that holds the sessions of this topology only, whatever other tests run on the host at the same time;
- waiting for the capture to hold what a test caused before reading it as complete or stopping it;
- what both sides say when a session does not come up.
"""

import os
import shutil
import subprocess
import unittest

from stress_harness import Capture
from test_common import ControlCase, ProcessFixture, bgpsim, wait_until


class InteropTest(ControlCase):
    NEIGHBOR = ()  # A test with one neighbor sets the config lines that enter its mode, for neighbor()

    @classmethod
    def prepare(cls, tag, what, missing, capture=True):
        """
        The fixture and its namespaces, or SkipTest. tag is a short word that names the namespaces, links and
        session of this test; what names the test in the skip reason; missing() says why its peer cannot run, or
        nothing. Call namespace() and link() next, then start().
        """
        reason = missing() or (capture and next((f'needs the {tool} command' for tool in ('tcpdump', 'tshark')
                                                 if not shutil.which(tool)), None))
        if reason:
           raise unittest.SkipTest(f'{what}: {reason}')
        cls.fixture = ProcessFixture()
        cls.fixture.__enter__()
        cls.addClassCleanup(cls.fixture.__exit__, None, None, None)
        cls.namespaces = cls.fixture.namespaces()
        cls.tag = f'{tag}{os.getpid() % 100000}'
        cls.capture = Capture(cls.fixture, cls.fixture.root) if capture else None
        cls.speakers = []
        cls.addresses = []

    @classmethod
    def namespace(cls, name='', *addresses):
        """A namespace of this topology, with each address on its loopback; returns its full name."""
        full = f'{cls.tag}{name}'
        cls.namespaces.add(full, *addresses)
        return full

    @classmethod
    def link(cls, namespace, mine, theirs, device='eth0'):
        """A veth link from this namespace (address mine) to device in namespace (address theirs)."""
        cls.addresses.append(mine)
        cls.namespaces.link(namespace, f'{cls.tag}v{len(cls.addresses)}', [mine], [theirs], device=device)

    @classmethod
    def start(cls, peers, lines):
        """
        Start the peers and wait for them, start the capture and bgpsim, enter lines in config mode, generate, and
        wait until every neighbor of every peer is Established. Leaves cls.speakers (the peers) and cls.client.
        """
        cls.speakers = list(peers)
        for peer in cls.speakers:
            peer.start()
        if not wait_until(lambda: all(peer.ready() for peer in cls.speakers), cls.WAIT_SECS):
           raise RuntimeError(f'a peer did not start\n{cls.evidence()}')
        if cls.capture:
           cls.capture.start(cls.addresses)
        cls.session = f'{cls.tag}_{os.getpid()}'
        if not cls.fixture.start_session(cls.session, log_path=cls.fixture.root / 'bgpsim.log'):
           raise RuntimeError('bgpsim did not start')
        cls.client = bgpsim.connect(cls.session, timeout=60)
        cls.addClassCleanup(cls.client.disconnect)
        for reply in (cls.client.configure(['config', *lines, 'end']), cls.client.cli('update generate')):
            if not reply:
               raise RuntimeError(f'{reply.command}: {reply.error or reply}')
        if not wait_until(cls.established, cls.WAIT_SECS):
           raise RuntimeError(f'the sessions did not establish\n{cls.evidence()}')

    def neighbor(self, command):
        """Enter one command in the mode of the neighbor that NEIGHBOR leads to (the lines that enter it)."""
        self.configure(*self.NEIGHBOR, command)

    @classmethod
    def established(cls):
        """Every neighbor of every peer is Established, as the peers see it."""
        return all(state == 'Established' for peer in cls.speakers for state in peer.states().values())

    @classmethod
    def evidence(cls):
        """What bgpsim, the peers and the kernel say about sessions that are not there, for a failure message."""
        parts = []
        if getattr(cls, 'client', None):
           parts.append(('bgpsim: show bgp neighbors', str(cls.client.cli('show bgp neighbors'))))
        log = cls.fixture.root / 'bgpsim.log'
        parts.append(('bgpsim log', log.read_text(errors='replace')[-3000:] if log.exists() else 'no log'))
        for peer in cls.speakers:
            parts.append((f'{peer.name}: states', str(peer.states()) if peer.running() else 'not running'))
            parts.append((f'{peer.name}: log', peer.log.read_text(errors='replace')[-3000:] if peer.log.exists()
                          else 'no log'))
        for command in (['ip', '-br', 'addr'], ['ip', 'route'], ['ip', 'neigh']):
            done = subprocess.run(command, capture_output=True, text=True)
            parts.append((' '.join(command), done.stdout + done.stderr))
        return '\n'.join(f'--- {title} ---\n{text}' for title, text in parts)

    def captured(self, check, why, within=None):
        """
        Assert that the capture comes to hold what check() looks for, within WAIT_SECS or the given bound; see
        Capture.wait_for().
        """
        if not self.capture.wait_for(check, within or self.WAIT_SECS):
           self.fail(why() if callable(why) else why)
