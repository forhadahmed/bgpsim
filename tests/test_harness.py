#!/usr/bin/env python3
"""Failure sensitivity and ownership contracts of the common test infrastructure."""

from contextlib import redirect_stdout
import copy
import io
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from bgp_capture import read_capture
from bgp_wire import bgp_message
import ribout_performance
import run_tests
from stress_harness import Capture
from test_results import CaseResult, PREFIX, collect, emit, run_bounded, run_unittest, terminate_group
from test_timing import cpu_stall_pct, measurement_ms, walltime_verdict
import test_common
from test_common import NetworkNamespaces, ProcessFixture, find_bgpsim_binary, session_socket_path, wait_until

HERE = Path(__file__).resolve().parent


class ResultTests(unittest.TestCase):
    def test_native_record_is_not_counted_twice(self):
        output = io.StringIO()
        with redirect_stdout(output):
            emit('pass', 'escaped "name"\nsecond line', kind='case', key='stable-case')
        records = collect(output.getvalue(), 'suite', 0)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]['kind'], 'case')
        self.assertEqual(records[0]['name'], 'escaped "name"\nsecond line')

    def test_legacy_badges_are_checks_and_summaries_are_not_results(self):
        records = collect('noise [PASS] not a result\n  \x1b[32m[PASS]\x1b[0m first\n'
                          '[PASS] first\n[PASS] All tests passed!\n[SKIP] unavailable\n', 'suite', 0)
        self.assertEqual([r['status'] for r in records], ['pass', 'pass', 'skip'])
        self.assertEqual({r['kind'] for r in records}, {'check'})
        self.assertEqual(len({r['id'] for r in records}), 3)

    def test_identity_survives_inserting_unrelated_results(self):
        before = collect('[PASS] first\n[PASS] first\n', 'suite', 0)
        after = collect('[PASS] unrelated\n[PASS] first\n[PASS] first\n', 'suite', 0)
        self.assertEqual(before, after[1:])
        self.assertNotEqual(before[0]['id'], before[1]['id'])

    def test_unusual_native_names_cannot_create_phantom_legacy_records(self):
        for name in (' leading space', '\ttab', 'first\vsecond', 'first\fsecond', 'name\u0085next',
                     'name\u2028next', 'name\u2029next', 'name\x1b[32mcolor'):
            with self.subTest(name=name):
                output = io.StringIO()
                with redirect_stdout(output):
                    emit('pass', name)
                records = collect(output.getvalue(), 'suite', 0)
                self.assertEqual(len(records), 1)
                self.assertEqual(records[0]['name'], name)

    def test_c_protocol_matches_python_and_preserves_failure_identity(self):
        binary = Path(os.environ.get('BUILD_DIR', '/tmp/bgpsim')) / 'test_result_protocol'
        variants = []
        for detail in ('first failure', 'changed failure detail'):
            result = subprocess.run([str(binary), '--fixture', detail], capture_output=True,
                                    text=True, timeout=5)
            self.assertEqual(result.returncode, 1)
            records = collect(result.stdout, 'c-protocol', 1)
            self.assertEqual(len(records), 10, result.stdout)
            self.assertEqual(sum(r['kind'] == 'case' for r in records), 2)
            self.assertEqual(sum(r['kind'] == 'check' for r in records), 8)
            self.assertEqual(sum(r['status'] == 'fail' for r in records), 4)
            self.assertEqual(sum(r['status'] == 'xfail' for r in records), 1)
            variants.append(records)
        self.assertEqual(variants[0][0]['id'], variants[1][0]['id'])
        self.assertNotEqual(variants[0][0]['detail'], variants[1][0]['detail'])

    def test_exit_status_and_missing_evidence_cannot_pass(self):
        for text, rc in (('[PASS] first\n', 1), ('[PASS] first\n', 124),
                         ('[PASS] All tests passed!\n', 0), ('', 0),
                         ('[FAIL] Some tests failed\n', 0), ('[PASS] first\n', 77)):
            with self.subTest(text=text, rc=rc):
                self.assertTrue(any(r['status'] == 'fail' for r in collect(text, 'suite', rc)))
        self.assertEqual(collect('', 'suite', 77)[0]['status'], 'skip')

    def test_malformed_native_records_fail_closed(self):
        valid = dict(status='pass', name='case', key='case', kind='case')
        variants = ['{', '[]', 'null']
        for field, value in (('status', 'PASS'), ('kind', 'test'), ('name', ''), ('key', 1)):
            variants.append(json.dumps({**valid, field: value}))
        variants.append(json.dumps({k: v for k, v in valid.items() if k != 'key'}))
        for value in variants:
            with self.subTest(value=value):
                records = collect(PREFIX + value, 'suite', 0)
                self.assertEqual(records[0]['status'], 'fail')

    def test_unittest_subtest_failure_skip_and_unexpected_success(self):
        class Sample(unittest.TestCase):
            def test_success(self):
                pass

            def test_subtest_failure(self):
                with self.subTest(variant='failure'):
                    self.fail('intentional sensitivity probe')

            @unittest.skip('unavailable fixture')
            def test_skip(self):
                pass

            @unittest.expectedFailure
            def test_unexpected_success(self):
                pass

            @unittest.expectedFailure
            def test_expected_failure(self):
                self.fail('documented gap')

            def test_error(self):
                raise RuntimeError('intentional error probe')

        output = io.StringIO()
        with redirect_stdout(output):
            result = unittest.TextTestRunner(stream=io.StringIO(), resultclass=CaseResult).run(
                unittest.defaultTestLoader.loadTestsFromTestCase(Sample))
        self.assertFalse(result.wasSuccessful())
        records = collect(output.getvalue(), 'sample', 1)
        self.assertEqual([r['status'] for r in records].count('fail'), 3)
        self.assertEqual([r['status'] for r in records].count('skip'), 1)
        self.assertEqual([r['status'] for r in records].count('pass'), 1)
        self.assertEqual([r['status'] for r in records].count('xfail'), 1)


class SupervisionTests(unittest.TestCase):
    def test_timeout_and_exit_status(self):
        output = io.StringIO()
        with redirect_stdout(output):
            rc = run_bounded([sys.executable, '-c', 'import time; time.sleep(60)'], 0.05)
        self.assertEqual(rc, 124)
        self.assertIn('[FAIL] Suite exceeded', output.getvalue())
        self.assertEqual(run_bounded([sys.executable, '-c', 'raise SystemExit(7)'], 5), 7)

    def test_cancellation_terminates_the_process(self):
        cancel = threading.Event()
        timer = threading.Timer(0.05, cancel.set)
        timer.start()
        try:
            self.assertEqual(run_bounded([sys.executable, '-c', 'import time; time.sleep(60)'],
                                         5, cancel=cancel), 130)
        finally:
            timer.join()

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux process-state evidence')
    def test_timeout_kills_descendants_not_just_the_leader(self):
        with tempfile.TemporaryDirectory(prefix='bgpsim-supervision-') as tmp:
            pidfile = Path(tmp, 'child.pid')
            # The pid file appears whole, by a rename, once the descendant runs.
            code = ('import pathlib,subprocess,sys,time; '
                    'p=subprocess.Popen([sys.executable,"-c","import time;time.sleep(60)"]); '
                    f'pathlib.Path({str(pidfile) + ".new"!r}).write_text(str(p.pid)); '
                    f'pathlib.Path({str(pidfile) + ".new"!r}).rename({str(pidfile)!r}); time.sleep(60)')
            real_clock = time.monotonic
            give_up = real_clock() + 30

            def clock():
                """
                The clock of run_bounded: it stands still until the probe has started its descendant, then is past
                the deadline. The timeout cannot fire before there is a descendant to kill, however slowly the probe
                starts on a loaded machine. A probe that never starts one still times out, after 30 real seconds.
                """
                return 1e9 if pidfile.exists() or real_clock() > give_up else 0.0

            with redirect_stdout(io.StringIO()), patch('test_results.time.monotonic', clock):
                self.assertEqual(run_bounded([sys.executable, '-c', code], 0.3), 124)
            self.assertTrue(pidfile.exists(), 'Probe never started its descendant')
            child = int(pidfile.read_text())
            stat = Path(f'/proc/{child}/stat')

            def dead():
                try:
                    return stat.read_text().split(') ', 1)[1].startswith('Z')
                except FileNotFoundError:
                    return True

            # The group has been signalled when run_bounded returns; a signalled process dies when it next runs,
            # which on a loaded machine is not at once. A descendant that escaped the signal sleeps for a minute.
            self.assertTrue(wait_until(dead, 10), f'Live descendant {child} escaped the timeout')

    def test_invalid_timeout_never_starts_a_process(self):
        for seconds in (0, -1, float('nan'), float('inf')):
            with self.subTest(seconds=seconds), patch('test_results.subprocess.Popen') as launch:
                with self.assertRaises(ValueError):
                    run_bounded(['unreachable'], seconds)
                launch.assert_not_called()


@unittest.skipUnless(sys.platform.startswith('linux') and os.geteuid() == 0 and shutil.which('ip'),
                     'needs Linux, root and the ip command to create namespaces')
class NamespaceOwnershipTests(unittest.TestCase):
    def test_close_removes_the_host_end_of_a_link_while_its_namespace_is_still_in_use(self):
        """
        A namespace outlives its name for as long as something inside holds it: a process, or a socket that is still
        retransmitting after its process was killed, which a session with a minimum TTL or a TCP MD5 key can leave
        for a minute or more. The host end of a link must not live that long: it keeps its address, and the next
        test that uses the address sends into the dead namespace.
        """
        tag = os.getpid() % 100000
        name, host = f'own{tag}', f'own{tag}v'
        namespaces = NetworkNamespaces()
        holder = None
        try:
            namespaces.add(name)
            namespaces.link(name, host, ['10.99.8.1'], ['10.99.8.2'])
            holder = subprocess.Popen(['ip', 'netns', 'exec', name, 'sleep', '60'])
            inside = os.readlink(f'/proc/{holder.pid}/ns/net')
            # The holder is in the namespace once its own differs from this process's.
            self.assertTrue(wait_until(lambda: os.readlink(f'/proc/{holder.pid}/ns/net') != os.readlink('/proc/self/ns/net'),
                                       10), f'the holder did not enter the namespace ({inside})')
            self.assertEqual(subprocess.run(['ip', 'link', 'show', host], capture_output=True).returncode, 0)
            namespaces.close()
            gone = subprocess.run(['ip', 'link', 'show', host], capture_output=True, text=True)
            self.assertNotEqual(gone.returncode, 0, f'the host end outlived close(): {gone.stdout}')
            self.assertEqual(holder.poll(), None, 'the holder exited: the namespace was not in use')
        finally:
            if holder is not None:
               holder.kill()
               holder.wait()
            namespaces.close()
            subprocess.run(['ip', 'link', 'del', host], capture_output=True)


    def test_fixture_stops_its_processes_before_it_removes_their_network(self):
        """
        A session closes over its link while both ends still run. A fixture that removed the link first would leave
        each kernel retransmitting the close into the next test that uses the same addresses.
        """
        tag = os.getpid() % 100000
        name, host = f'ord{tag}', f'ord{tag}v'
        states = []
        try:
            with ProcessFixture() as fixture:
                namespaces = fixture.namespaces()
                namespaces.add(name)
                namespaces.link(name, host, ['10.99.9.1'], ['10.99.9.2'])
                process = fixture.start_process(['ip', 'netns', 'exec', name, 'sleep', '60'])
                remove = namespaces.close

                def close():
                    # What the process and the link look like at the moment the fixture removes the network.
                    states.append((process.poll() is not None,
                                   subprocess.run(['ip', 'link', 'show', host], capture_output=True).returncode == 0))
                    remove()

                namespaces.close = close
                self.assertIsNone(process.poll())
            self.assertEqual(states, [(True, True)], '(process has exited, link still exists) when the network closes')
            self.assertNotEqual(subprocess.run(['ip', 'link', 'show', host], capture_output=True).returncode, 0)
        finally:
            subprocess.run(['ip', 'link', 'del', host], capture_output=True)
            subprocess.run(['ip', 'netns', 'del', name], capture_output=True)


@unittest.skipUnless(sys.platform.startswith('linux') and os.geteuid() == 0 and shutil.which('ip') and
                     shutil.which('tcpdump'), 'needs Linux, root, and the ip and tcpdump commands')
class CaptureScopeTests(unittest.TestCase):
    def test_capture_holds_the_sessions_of_its_own_test_only(self):
        """
        The lanes run their tests on one host at the same time. A capture of every port-179 packet would hand its
        reader the streams of the other tests, some joined in the middle of a message, and the reader fails on those.
        Two links to one namespace stand for two tests: the capture is started for the first, the second carries
        octets that are not BGP, and then the first carries a KEEPALIVE. Once the capture holds the KEEPALIVE it
        must hold nothing of the second link, and the reader must accept all of it.
        """
        tag = os.getpid() % 100000
        name, hosts = f'cap{tag}', [f'cap{tag}a', f'cap{tag}b']
        mine, other = ('10.99.10.1', '10.99.10.2'), ('10.99.11.1', '10.99.11.2')
        listener = ('import socket, threading\n'
                    'server = socket.socket()\n'
                    'server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n'
                    'server.bind(("0.0.0.0", 179))\n'
                    'server.listen(4)\n'
                    'print("listening", flush=True)\n'
                    'def drain(peer):\n'
                    '    while peer.recv(65536):\n'
                    '        pass\n'
                    'while True:\n'
                    '    threading.Thread(target=drain, args=(server.accept()[0],), daemon=True).start()\n')

        def flows():
            return {(flow[0], flow[2]) for flow in read_capture(capture.path.read_bytes(), partial=True)}

        try:
            with ProcessFixture() as fixture:
                namespaces = fixture.namespaces()
                namespaces.add(name)
                for host, (here, there) in zip(hosts, (mine, other)):
                    namespaces.link(name, host, [here], [there], device=host)
                log = fixture.root / 'listener.log'
                fixture.start_process(['ip', 'netns', 'exec', name, sys.executable, '-u', '-c', listener], log_path=log)
                self.assertTrue(wait_until(lambda: log.exists() and 'listening' in log.read_text(), 10))
                capture = Capture(fixture, fixture.root / 'capture')
                capture.start([mine[0]])
                with socket.create_connection((other[1], 179), timeout=5) as foreign, \
                     socket.create_connection((mine[1], 179), timeout=5) as own:
                    foreign.sendall(b'not a BGP message ' * 8)
                    own.sendall(bgp_message(4))
                    self.assertTrue(capture.wait_for(lambda: any(
                        stream['messages'] for stream in
                        read_capture(capture.path.read_bytes(), partial=True).values()), 10),
                        'the capture does not hold the KEEPALIVE of its own test')
                    self.assertEqual(flows(), {mine, mine[::-1]})
        finally:
            for host in hosts:
                subprocess.run(['ip', 'link', 'del', host], capture_output=True)
            subprocess.run(['ip', 'netns', 'del', name], capture_output=True)


class ProcessOwnershipTests(unittest.TestCase):
    def test_context_is_required_and_signal_handlers_are_restored(self):
        previous = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
        fixture = ProcessFixture()
        with self.assertRaises(RuntimeError):
            fixture.start_process([sys.executable, '-c', 'pass'])
        with fixture:
            self.assertNotEqual(signal.getsignal(signal.SIGTERM), previous[signal.SIGTERM])
            self.assertEqual(fixture.run([sys.executable, '-c', 'print("owned")']).stdout.strip(), 'owned')
        for sig, handler in previous.items():
            self.assertEqual(signal.getsignal(sig), handler)
        self.assertFalse(fixture.root.exists())

    def test_unowned_socket_and_process_are_never_stopped(self):
        with tempfile.TemporaryDirectory(prefix='bgpsim-unowned-') as tmp:
            socket_path = Path(tmp, 'control.sock')
            socket_path.write_text('unrelated owner')
            with ProcessFixture() as fixture, \
                 patch('test_common.session_socket_path', return_value=str(socket_path)), \
                 patch('test_common.subprocess.Popen') as launch, patch('sys.stderr', io.StringIO()):
                self.assertFalse(fixture.start_session('unowned'))
                fixture.stop_session('unowned')
                launch.assert_not_called()
                with self.assertRaises(ValueError):
                    fixture.stop_process(object())
            self.assertEqual(socket_path.read_text(), 'unrelated owner')

    def test_missing_config_never_falls_back_to_empty(self):
        with ProcessFixture() as fixture, patch('test_common.subprocess.Popen') as launch:
            with patch('sys.stderr', io.StringIO()):
                self.assertFalse(fixture.start_session('missing-config', config=fixture.root / 'absent.conf'))
            launch.assert_not_called()

    def test_child_process_is_cleaned_on_exception(self):
        process = None
        try:
            with patch('sys.stderr', io.StringIO()), ProcessFixture() as fixture:
                process = fixture.start_process([sys.executable, '-c', 'import time;time.sleep(60)'])
                with self.assertRaises(ValueError):
                    fixture.stop_process(object())
                raise RuntimeError('intentional scope failure')
        except RuntimeError as exc:
            self.assertEqual(str(exc), 'intentional scope failure')
        self.assertIsNotNone(process)
        self.assertIsNotNone(process.poll())

    def test_batch_shutdown_validates_every_owner_before_signalling(self):
        with ProcessFixture() as fixture:
            process = fixture.start_process([sys.executable, '-c', 'import time;time.sleep(60)'])
            with patch('test_common.os.killpg') as send:
                with self.assertRaises(ValueError):
                    fixture.stop_processes([process, object()])
                send.assert_not_called()
            self.assertIsNone(process.poll())
            fixture.stop_processes([process])
            self.assertIsNotNone(process.poll())

    def test_foreground_timeout_preserves_diagnostics_and_cleans_children(self):
        with ProcessFixture() as fixture:
            with self.assertRaises(subprocess.TimeoutExpired):
                fixture.run([sys.executable, '-c',
                             'import time;print("before timeout",flush=True);time.sleep(60)'], timeout=0.1)
            self.assertIn('before timeout', fixture.diagnostics())

    def test_real_daemon_pid_handshake_cli_and_cleanup(self):
        name = f'ownership_{os.getpid()}'
        with ProcessFixture() as fixture:
            self.assertTrue(fixture.start_session(name, log_path=fixture.root / 'daemon.log'))
            socket_path = Path(session_socket_path(name))
            self.assertTrue(socket_path.exists())
            self.assertIn('BGP', fixture.cli('show bgp summary', session=name))
        self.assertFalse(socket_path.exists())

    def test_foreground_wrappers_private_socket_and_persistent_evidence(self):
        with tempfile.TemporaryDirectory(prefix='bgpsim-foreground-') as tmp:
            root = Path(tmp)
            socket_path = root / 'control.sock'
            output = root / 'foreground.log'
            with ProcessFixture() as fixture:
                process = fixture.start_process([find_bgpsim_binary(), '-l', 'daemon.log', '/dev/null'],
                                                 log_path=output, cwd=root, wrapper=['sh', '-c', 'exec "$@"', 'test'],
                                                 core_dump=True, retain_logs=True,
                                                 env={'BGPSIM_CONTROL_SOCKET': str(socket_path)})
                fixture.wait_ready(process)
                self.assertIn('BGP', fixture.cli('show bgp summary', process=process))
                self.assertTrue(socket_path.is_socket())
                self.assertTrue((root / 'daemon.log').is_file())
                self.assertIsNone(process.poll())
                # The foreground output is the prompt of the CLI, which its own thread prints: wait for it, so the
                # process is not stopped before it has written anything to keep.
                self.assertTrue(wait_until(output.read_bytes, 10), 'the foreground CLI printed no prompt')
                fixture.stop_process(process)
                captured = output.read_bytes()
                self.assertTrue(captured)
            self.assertIsNotNone(process.poll())
            self.assertFalse(socket_path.exists())
            self.assertTrue(output.is_file(), 'ProcessFixture removed retained foreground evidence')
            self.assertEqual(output.read_bytes(), captured)
            self.assertTrue((root / 'daemon.log').exists())

    def test_foreground_private_socket_never_replaces_another_owner(self):
        with ProcessFixture() as fixture:
            path = fixture.root / 'unowned.sock'
            path.write_text('another owner')
            with patch('test_common.subprocess.Popen', side_effect=AssertionError('attempted unowned launch')) as launch:
                with self.assertRaises(FileExistsError):
                    fixture.start_process([find_bgpsim_binary(), '/dev/null'],
                                          env={'BGPSIM_CONTROL_SOCKET': str(path)})
                launch.assert_not_called()
            self.assertEqual(path.read_text(), 'another owner')

    def test_empty_output_does_not_pass_generation_smoke(self):
        import test_shell_smoke
        with tempfile.TemporaryDirectory(prefix='bgpsim-empty-probe-') as tmp:
            fake = Path(tmp, 'bgpsim')
            fake.write_text('#!/bin/sh\nexit 0\n')
            fake.chmod(0o755)
            # Exercise the real smoke, not a copy of its leaf assertions.
            result = unittest.TestResult()
            with patch.dict(os.environ, BGPSIM=str(fake)), patch('sys.stderr', io.StringIO()):
                test_shell_smoke.ShellSmokeTests('test_generation_smoke').run(result)
            self.assertEqual(len(result.failures), 1)
            self.assertFalse(result.errors, result.errors)
            self.assertIn('Missing/duplicate Total Paths', result.failures[0][1])


class RunnerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='bgpsim-runner-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def suite(self, name='sample', code='print("[PASS] actual check")', **options):
        return dict(name=name, group='checks', profiles=['probe'],
                    command=[sys.executable, '-c', code], **options)

    def run_profile(self, suites):
        manifest = dict(suites=suites)
        with redirect_stdout(io.StringIO()):
            rc = run_tests.run_profile(manifest, suites, 'probe', self.root, self.root / 'logs')
        return rc, json.loads((self.root / 'logs' / 'summary.json').read_text())

    def test_failure_does_not_hide_later_suites_and_logs_are_complete(self):
        rc, summary = self.run_profile([
            self.suite('first', 'print("[PASS] assertion"); raise SystemExit(4)'),
            self.suite('later')])
        self.assertEqual(rc, 1)
        self.assertEqual(summary['suites'], 2)
        self.assertEqual(summary['counts'], {'pass': 2, 'fail': 1, 'skip': 0, 'xfail': 0})
        self.assertEqual(summary['results_by_kind'], dict(case=0, check=3))
        for result in summary['results']:
            self.assertTrue(Path(result['log']).is_file())
            self.assertTrue(Path(result['log']).with_suffix('.results.jsonl').is_file())
        self.assertIn('later', (self.root / 'logs' / 'probe-test.log').read_text())

    def test_launch_errors_and_empty_success_are_failures(self):
        missing = self.suite('missing')
        missing['command'] = [str(self.root / 'no-such-command')]
        rc, summary = self.run_profile([missing, self.suite('empty', 'pass')])
        self.assertEqual(rc, 1)
        self.assertEqual(summary['counts']['fail'], 2)

    def test_explicit_unavailable_suite_is_a_skip_not_a_pass(self):
        rc, summary = self.run_profile([self.suite(code='raise SystemExit(77)')])
        self.assertEqual(rc, 0)
        self.assertEqual(summary['counts'], {'pass': 0, 'fail': 0, 'skip': 1, 'xfail': 0})

    def test_expected_failure_is_counted_and_does_not_fail_the_run(self):
        record = '{"status": "xfail", "name": "documented gap", "kind": "check", "key": "documented gap"}'
        rc, summary = self.run_profile([self.suite(code=f'print({("@@BGPSIM_RESULT " + record)!r}); print("[XFAIL] documented gap")'),
                                        self.suite('other')])
        self.assertEqual(rc, 0)
        self.assertEqual(summary['counts'], {'pass': 1, 'fail': 0, 'skip': 0, 'xfail': 1})
        self.assertEqual(summary['results'][0]['status'], 'pass')
        self.assertIn('expected failures: 1', (self.root / 'logs' / 'summary.txt').read_text())

    def handshake(self, name, other):
        """A suite that passes only while the other suite runs: it announces itself and waits for the other."""
        mine, theirs = self.root / f'{name}.started', self.root / f'{other}.started'
        return (f'import pathlib, time\n'
                f'pathlib.Path({str(mine)!r}).touch()\n'
                f'end = time.monotonic() + 10\n'
                f'while not pathlib.Path({str(theirs)!r}).exists() and time.monotonic() < end:\n'
                f'    time.sleep(0.01)\n'
                f'print("[PASS] overlap" if pathlib.Path({str(theirs)!r}).exists() else "[FAIL] no overlap")\n')

    def test_lanes_run_at_the_same_time(self):
        rc, summary = self.run_profile([self.suite('first', self.handshake('first', 'second'), lane='one'),
                                        self.suite('second', self.handshake('second', 'first'), lane='two')])
        self.assertEqual(rc, 0, summary)
        self.assertEqual(summary['counts'], {'pass': 2, 'fail': 0, 'skip': 0, 'xfail': 0})

    def test_one_lane_runs_in_manifest_order_and_results_keep_it(self):
        done = self.root / 'first.done'
        first = (f'import pathlib, time\ntime.sleep(0.2)\npathlib.Path({str(done)!r}).touch()\n'
                 f'print("[PASS] first finished")\n')
        later = (f'import pathlib\n'
                 f'print("[PASS] in order" if pathlib.Path({str(done)!r}).exists() else "[FAIL] overlap")\n')
        rc, summary = self.run_profile([self.suite('elsewhere', lane='other'), self.suite('first', first, lane='one'),
                                        self.suite('later', later, lane='one')])
        self.assertEqual(rc, 0, summary)
        self.assertEqual([r['name'] for r in summary['results']], ['elsewhere', 'first', 'later'])
        self.assertEqual(set(summary['lane_duration_ms']), {'other', 'one'})
        for lane, names in (('other', {'elsewhere'}), ('one', {'first', 'later'})):
            suite_time = sum(r['duration_ms'] for r in summary['results'] if r['name'] in names)
            self.assertGreaterEqual(summary['lane_duration_ms'][lane], suite_time)
            self.assertLessEqual(summary['lane_duration_ms'][lane], summary['duration_ms'])

    def test_a_failing_lane_does_not_hide_the_other_lanes(self):
        rc, summary = self.run_profile([self.suite('bad', 'print("[FAIL] broken"); raise SystemExit(1)', lane='one'),
                                        self.suite('good', lane='two'), self.suite('after', lane='one')])
        self.assertEqual(rc, 1)
        self.assertEqual(summary['suites'], 3)
        self.assertEqual(summary['counts'], {'pass': 2, 'fail': 1, 'skip': 0, 'xfail': 0})

    def test_lanes_own_disjoint_port_bands(self):
        show = ('import os\nprint("[PASS] ports", os.environ["BGPSIM_LISTEN_BASE_PORT"],'
                ' os.environ["BGPSIM_TEST_PORT_BAND"])\n')
        rc, summary = self.run_profile([self.suite('first', show, lane='one'), self.suite('second', show, lane='two'),
                                        self.suite('third', show, lane='two')])
        self.assertEqual(rc, 0, summary)
        ports = {r['name']: tuple(map(int, re.search(r'ports (\d+) (\d+)-(\d+)', Path(r['log']).read_text()).groups()))
                 for r in summary['results']}
        self.assertEqual(ports['second'], ports['third'])
        one, two = ports['first'], ports['second']
        self.assertTrue(one[0] < one[1] < one[2] and two[0] < two[1] < two[2], ports)
        self.assertTrue(one[2] <= two[0] or two[2] <= one[0], ports)

    def test_port_finder_stays_in_the_band_of_its_lane(self):
        with patch.dict(os.environ, BGPSIM_TEST_PORT_BAND='15000-15400'):
            for _ in range(20):
                first = test_common.available_port(3)
                self.assertTrue(15000 <= first and first + 3 <= 15400, first)

    def test_executor_cancels_other_lanes_before_waiting_on_exception(self):
        started, cancelled = threading.Event(), threading.Event()

        def execute(suite, build, directory, cancel, timeout):
            if suite.get('lane') == 'other':
               started.set()
               if cancel.wait(1):
                  cancelled.set()
               return {}
            self.assertTrue(started.wait(1))
            raise RuntimeError('foreground failure')

        suites = [self.suite('other', lane='other'), self.suite('foreground')]
        with patch('run_tests.execute', side_effect=execute), self.assertRaisesRegex(RuntimeError, 'foreground failure'):
            self.run_profile(suites)
        self.assertTrue(cancelled.is_set(), 'Executor waited before requesting cancellation')

    def test_profile_manifest_owns_every_c_test_and_every_entrypoint_exists(self):
        manifest = run_tests.load_manifest(HERE / 'suites.json')
        c_tests = {p.stem for p in HERE.glob('test_*.c') if p.stem != 'test_helpers'}
        listed = {s['name'] for s in manifest['suites'] if 'unit' in s['profiles']}
        binaries = {Path(s['command'][0]).name for s in manifest['suites']
                    if s['command'][0].startswith('{build}/')}
        self.assertEqual(binaries, c_tests)
        self.assertTrue(all(s['group'] != 'network-tests' for s in manifest['suites']
                            if 'unit' in s['profiles']))
        self.assertTrue(listed <= {s['name'] for s in manifest['suites'] if 'all' in s['profiles']})
        for suite in manifest['suites']:
            command = suite['command']
            if command[0] == '{python}':
               script = next(argument for argument in command[1:] if not argument.startswith('-'))
               self.assertTrue((HERE / script).is_file(), command)

    def test_invalid_manifest_and_unknown_selection_fail_closed(self):
        valid = dict(suites=[self.suite()])
        variants = [[], {}, dict(suites=[self.suite(), self.suite()])]
        for field, value in (('name', '../escape'), ('group', '../escape'), ('profiles', []),
                             ('command', 'not-an-argv'), ('timeout', 0), ('timeout', float('nan')),
                             ('budget_ms', -1), ('lane', '../escape'), ('lane', 7)):
            bad = copy.deepcopy(valid)
            bad['suites'][0][field] = value
            variants.append(bad)
        path = self.root / 'manifest.json'
        for variant in variants:
            path.write_text(json.dumps(variant))
            with self.subTest(variant=variant), self.assertRaises((ValueError, KeyError)):
                run_tests.load_manifest(path)
        for profile, names in (('absent', ()), ('probe', ('absent',))):
            with self.assertRaises(ValueError):
                run_tests.select_suites(valid, profile, names)

    def test_signal_cancellation_produces_failed_summary(self):
        marker = self.root / 'started'
        manifest = self.root / 'manifest.json'
        manifest.write_text(
            json.dumps(dict(
                    suites=[self.suite(code=f'import pathlib,time;pathlib.Path({str(marker)!r}).touch();time.sleep(60)')]
            ))
        )
        process = subprocess.Popen([sys.executable, str(HERE / 'run_tests.py'), '--profile', 'probe',
                                    '--manifest', str(manifest), '--run-dir', str(self.root / 'cancelled')],
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                    start_new_session=True)
        try:
            deadline = time.monotonic() + 5
            while not marker.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(marker.exists(), 'Runner never started the probe')
            process.send_signal(signal.SIGTERM)
            output, _ = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 1, output)
            summary = json.loads((self.root / 'cancelled' / 'summary.json').read_text())
            self.assertEqual(summary['status'], 'fail')
            self.assertEqual(summary['results'][0]['returncode'], 130)
        finally:
            terminate_group(process)


class TimingTests(unittest.TestCase):
    def test_measurements_fail_closed_and_cpu_is_not_wall_time(self):
        for text, expected in (('Generation Time: 1.5 sec', 1500), ('Generation Time: 0.5 ms', 0.5)):
            self.assertEqual(measurement_ms(text, 'Generation Time:'), expected)
        for text in ('', 'Generation Time: nan ms', 'Generation Time: -1 ms',
                     'Generation Time: 2 unknown', 'Generation Time: 1 ms\nGeneration Time: 2 ms'):
            with self.subTest(text=text), self.assertRaises(AssertionError):
                measurement_ms(text, 'Generation Time:')
        both = '  Generation Time: 2.50 ms\n  Generation CPU: 1.250 ms'
        self.assertEqual(measurement_ms(both, 'Generation Time:'), 2.5)
        self.assertEqual(measurement_ms(both, 'Generation CPU:'), 1.25)
        with self.assertRaises(AssertionError):
            measurement_ms('Generation Time: 2 ms', 'Generation CPU:')

    def test_wall_gate_requires_idle_cpu_evidence(self):
        self.assertEqual(walltime_verdict(100, 100, 0), 'pass')
        self.assertEqual(walltime_verdict(101, 100, 0), 'fail')
        self.assertEqual(walltime_verdict(101, 100, 10), 'warn')
        self.assertEqual(walltime_verdict(101, 100, None), 'warn')
        self.assertEqual(cpu_stall_pct(100, 200, 10), 1)
        for args in ((None, 200, 10), (200, 100, 10), (100, 200, 0)):
            self.assertIsNone(cpu_stall_pct(*args))

    def test_performance_scale_is_positive_finite(self):
        for value in ('0', '-1', 'nan', 'inf', 'garbage'):
            with patch.dict(os.environ, RIBOUT_PERF_SCALE=value), self.assertRaises(ValueError):
                ribout_performance.performance_scale()
        with patch.dict(os.environ, RIBOUT_PERF_SCALE='2'):
            self.assertEqual(ribout_performance.performance_scale(), 2)

    def test_performance_failure_is_not_hidden_by_later_success(self):
        with tempfile.TemporaryDirectory(prefix='bgpsim-performance-probe-') as tmp:
            fake = Path(tmp, 'bgpsim')
            fake.write_text('#!/usr/bin/env python3\nimport sys\n'
                            'print("Generation Time: 0.001 ms")\n'
                            'print("Generation CPU: 0.001 ms")\n'
                            'print("Total Paths: 1")\n'
                            'if sys.argv[-1].endswith("test_quick_small.conf"): sys.exit(1)\n')
            fake.chmod(0o755)
            result = subprocess.run([sys.executable, str(HERE / 'ribout_performance.py')],
                                    env={**os.environ, 'BGPSIM': str(fake)},
                                    capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            records = collect(result.stdout, 'performance-probe', result.returncode)
            self.assertEqual(len(records), 12)
            self.assertEqual(sum(r['status'] == 'fail' for r in records), 1)
            self.assertEqual(sum(r['status'] == 'pass' for r in records), 11)

    def test_benchmark_target_propagates_failure(self):
        with tempfile.TemporaryDirectory(prefix='bgpsim-benchmark-probe-') as tmp:
            first, second = Path(tmp, 'first'), Path(tmp, 'second')
            first.write_text('#!/bin/sh\nexit 1\n')
            second.write_text('#!/bin/sh\necho later-benchmark-ran\n')
            first.chmod(0o755)
            second.chmod(0o755)
            result = subprocess.run(['make', '--no-print-directory', 'bench',
                                     f'BENCH_BINS={first} {second}'], cwd=HERE.parent,
                                    text=True, capture_output=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('later-benchmark-ran', result.stdout)


if __name__ == '__main__':
   sys.exit(run_unittest())
