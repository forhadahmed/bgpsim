#!/usr/bin/env python3
"""Live daemon isolation and overlapping control-client operations."""

from concurrent.futures import ThreadPoolExecutor
import os
import sys
import threading

from test_common import ProcessFixture, TestRunner, bgpsim

SESSIONS = [f'test_multi_session_{os.getpid()}_{i}' for i in range(3)]


def router_lines(client):
    return {line for line in client.cli('show running-config').splitlines()
            if line.startswith('router bgp ')}


def main():
    with ProcessFixture() as fixture:
        return run_tests(fixture)


def run_tests(fixture):
    runner = TestRunner()
    try:
        for session in SESSIONS:
            if not fixture.start_session(session, log_path=fixture.root / f'{session}.log'):
                raise AssertionError(f'Could not start {session}')

        # Release all clients together with persistent, different CLI contexts.
        barrier = threading.Barrier(len(SESSIONS))

        def configure(index):
            with bgpsim.connect(SESSIONS[index]) as client:
                client.sock.settimeout(5)
                client.cli('config')
                barrier.wait(timeout=5)
                for offset in range(8):
                    asn = 65000 + index * 100 + offset
                    client.cli(f'router bgp {asn}')
                    client.cli(f'neighbor 192.0.{index}.{offset + 1} remote-as 70000')
                return router_lines(client)

        with ThreadPoolExecutor(max_workers=3) as pool:
            results = list(pool.map(configure, range(3)))
        for index, lines in enumerate(results):
            expected = {f'router bgp {65000 + index * 100 + offset}' for offset in range(8)}
            if lines != expected:
                raise AssertionError(f'{SESSIONS[index]}: {lines} != {expected}')
            runner.test_pass(f'Session {index}: concurrent changes remain isolated')

        # One daemon must also keep simultaneous clients' router contexts apart.
        barrier = threading.Barrier(3)

        def same_daemon(index):
            with bgpsim.connect(SESSIONS[0]) as client:
                client.sock.settimeout(5)
                client.cli('config')
                client.cli(f'router bgp {68000 + index}')
                barrier.wait(timeout=5)
                for offset in range(8):
                    client.cli(f'neighbor 198.51.{index}.{offset + 1} remote-as 70001')
                return client.cli('show running-config')

        with ThreadPoolExecutor(max_workers=3) as pool:
            list(pool.map(same_daemon, range(3)))
        with bgpsim.connect(SESSIONS[0]) as client:
            config = client.cli('show running-config')
        sections = {}
        current = None
        for line in config.splitlines():
            if line.startswith('router bgp '):
                current = int(line.split()[-1])
                sections[current] = set()
            elif current is not None and line.strip().startswith('neighbor '):
                sections[current].add(line.strip())
        for index in range(3):
            expected = {f'neighbor 198.51.{index}.{offset + 1} remote-as 70001' for offset in range(8)}
            if sections.get(68000 + index) != expected:
                raise AssertionError(f'Client {index} router/neighbor context leaked: {sections}')
        runner.test_pass('Overlapping clients on one daemon retain independent CLI contexts')

        # Restart one daemon while the others remain live; no state may migrate.
        if not fixture.start_session(SESSIONS[0], log_path=fixture.root / f'{SESSIONS[0]}.log'):
            raise AssertionError('Could not restart session 0')
        for index, session in enumerate(SESSIONS):
            with bgpsim.connect(session) as client:
                expected = set() if index == 0 else results[index]
                if router_lines(client) != expected:
                    raise AssertionError(f'Session {index}: restart affected wrong state')
        runner.test_pass('Restart clears only the targeted daemon; other sessions retain exact state')
    except Exception as exc:
        runner.test_fail('Multi-session isolation/concurrency', f'{exc}\n{fixture.diagnostics()}')
    return runner.summary()


if __name__ == '__main__':
    sys.exit(main())
