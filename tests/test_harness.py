#!/usr/bin/env python3
"""Failure sensitivity and ownership contracts of the common test infrastructure."""

from contextlib import redirect_stdout
import copy
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import ribout_performance
import run_tests
from test_results import CaseResult, PREFIX, collect, emit, run_bounded, run_unittest, terminate_group
from test_timing import cpu_stall_pct, measurement_ms, walltime_verdict
from test_common import ProcessFixture, session_socket_path

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
            self.assertEqual(len(records), 7, result.stdout)
            self.assertEqual(sum(r['kind'] == 'case' for r in records), 2)
            self.assertEqual(sum(r['kind'] == 'check' for r in records), 5)
            self.assertEqual(sum(r['status'] == 'fail' for r in records), 2)
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
            code = ('import pathlib,subprocess,sys,time; '
                    'p=subprocess.Popen([sys.executable,"-c","import time;time.sleep(60)"]); '
                    f'pathlib.Path({str(pidfile)!r}).write_text(str(p.pid)); time.sleep(60)')
            with redirect_stdout(io.StringIO()):
                self.assertEqual(run_bounded([sys.executable, '-c', code], 0.3), 124)
            self.assertTrue(pidfile.exists(), 'Probe never started its descendant')
            child = int(pidfile.read_text())
            stat = Path(f'/proc/{child}/stat')
            self.assertTrue(not stat.exists() or stat.read_text().split(') ', 1)[1].startswith('Z'),
                            f'Live descendant {child} escaped the timeout')

    def test_invalid_timeout_never_starts_a_process(self):
        for seconds in (0, -1, float('nan'), float('inf')):
            with self.subTest(seconds=seconds), patch('test_results.subprocess.Popen') as launch:
                with self.assertRaises(ValueError):
                    run_bounded(['unreachable'], seconds)
                launch.assert_not_called()


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
        self.assertEqual(summary['counts'], {'pass': 2, 'fail': 1, 'skip': 0})
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
        self.assertEqual(summary['counts'], {'pass': 0, 'fail': 0, 'skip': 1})

    def test_executor_cancels_background_before_waiting_on_exception(self):
        started, cancelled = threading.Event(), threading.Event()

        def execute(suite, build, directory, cancel, timeout):
            if suite.get('background'):
                started.set()
                if cancel.wait(1):
                    cancelled.set()
                return {}
            self.assertTrue(started.wait(1))
            raise RuntimeError('foreground failure')

        suites = [self.suite('background', background=True), self.suite('foreground')]
        with patch('run_tests.execute', side_effect=execute), self.assertRaisesRegex(RuntimeError, 'foreground'):
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
                             ('budget_ms', -1), ('background', 'yes')):
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
        manifest.write_text(json.dumps(dict(suites=[self.suite(code=
            f'import pathlib,time;pathlib.Path({str(marker)!r}).touch();time.sleep(60)')])))
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
            self.assertEqual(len(records), 10)
            self.assertEqual(sum(r['status'] == 'fail' for r in records), 1)
            self.assertEqual(sum(r['status'] == 'pass' for r in records), 9)

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
