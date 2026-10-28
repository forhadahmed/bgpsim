"""Result protocol and bounded execution shared by every test profile.

Native cases/checks have explicit keys. Legacy badges are imported as checks,
never misreported as independently runnable test cases.
"""

from collections import Counter
import hashlib
import json
import math
import os
import re
import signal
import subprocess
import sys
import time
import unittest

PREFIX = '@@BGPSIM_RESULT '
ANSI = re.compile(r'\x1b\[[0-9;]*m')
RESULT = re.compile(r'^\s*(?:\[[0-9-]+ [0-9:]+\]\s*)?\[(PASS|FAIL|SKIP)\]\s+(.+)$')
SUMMARIES = {'All tests passed!', 'Some tests failed'}


def human_name(name):
    return name.replace('\n', '\\n').replace('\r', '\\r')


def emit(status, name, *, kind='check', key=None, detail=None):
    record = dict(status=status, name=name, kind=kind, key=key or name)
    if detail:
        record['detail'] = detail
    print(PREFIX + json.dumps(record), flush=True)
    color = {'pass': '32', 'fail': '31', 'skip': '33'}[status]
    badge = f'[{status.upper()}]'
    if sys.stdout.isatty():
        badge = f'\033[{color}m{badge}\033[0m'
    unusual = name[:1].isspace() or any((ord(c) < 32 and c not in '\n\r') or ord(c) >= 127 for c in name)
    print(f'{badge}: {json.dumps(name)}' if unusual else f'{badge} {human_name(name)}', flush=True)


def collect(text, suite, returncode, *, allow_empty=False):
    records, previous, failed_summary = [], None, False
    for line in ANSI.sub('', text).splitlines():
        if line.startswith(PREFIX):
            try:
                record = json.loads(line[len(PREFIX):])
                if (record['status'] not in ('pass', 'fail', 'skip') or
                        record['kind'] not in ('case', 'check') or
                        not isinstance(record['key'], str) or not record['key'] or
                        not isinstance(record['name'], str) or not record['name']):
                    raise ValueError('invalid result fields')
            except (ValueError, KeyError, TypeError):
                record = dict(status='fail', name='Malformed result record', kind='check', key='invalid-record')
            records.append(record)
            previous = (record['status'], human_name(record['name']))
            continue
        match = RESULT.match(line)
        if not match:
            previous = None
            continue
        status, name = match.groups()
        status = status.lower()
        if (status, name) == previous:
            previous = None
            continue
        previous = None
        if name in SUMMARIES:
            failed_summary |= status == 'fail'
            continue
        records.append(dict(status=status, name=name, key=name, kind='check'))
    if not records:
        status = 'skip' if returncode == 77 else 'pass' if allow_empty and returncode == 0 else 'fail'
        records.append(dict(status=status, name='Suite unavailable' if status == 'skip' else
                            'Suite completed' if status == 'pass' else 'Suite emitted no result records',
                            key='suite-outcome', kind='check'))
    if ((returncode not in (0, 77) or failed_summary) and
            not any(r['status'] == 'fail' for r in records)):
        records.append(dict(status='fail', name=f'Suite failed (exit {returncode})',
                            key='suite-exit', kind='check'))
    if returncode == 77 and any(r['status'] == 'pass' for r in records):
        records.append(dict(status='fail', name='Suite reported success before skipping',
                            key='invalid-skip', kind='check'))
    repeated = Counter()
    for record in records:
        key = record.pop('key')
        identity = f'{record["kind"]}:{key}'
        repeated[identity] += 1
        digest = hashlib.sha256(identity.encode()).hexdigest()[:16]
        record.update(id=f'{suite}:{digest}:{repeated[identity]}', suite=suite)
    return records


def terminate_group(process):
    for sig, grace in ((signal.SIGTERM, 3), (signal.SIGKILL, 1)):
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            return
        try:
            process.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            continue
        # The leader may exit before descendants; kill the remaining group too.
        if sig == signal.SIGTERM:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        return
    process.wait()


def run_bounded(command, seconds, *, stdout=None, cwd=None, env=None, cancel=None):
    if not math.isfinite(seconds) or seconds <= 0:
        raise ValueError('timeout must be positive')
    process = subprocess.Popen(command, start_new_session=True, stdout=stdout,
                               stderr=subprocess.STDOUT if stdout is not None else None, cwd=cwd, env=env)
    deadline = time.monotonic() + seconds
    try:
        while True:
            if cancel is not None and cancel.is_set():
                terminate_group(process)
                return 130
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                terminate_group(process)
                message = f'[FAIL] Suite exceeded {seconds:g}s timeout\n'
                if stdout is None:
                    print(message, end='', flush=True)
                else:
                    stdout.write(message)
                    stdout.flush()
                return 124
            try:
                return process.wait(timeout=min(remaining, 0.1))
            except subprocess.TimeoutExpired:
                pass
    except BaseException:
        terminate_group(process)
        raise


class CaseResult(unittest.TextTestResult):
    def addSuccess(self, test):
        super().addSuccess(test)
        emit('pass', test.id(), kind='case')

    def addFailure(self, test, err):
        super().addFailure(test, err)
        emit('fail', test.id(), kind='case', detail=self._exc_info_to_string(err, test))

    def addError(self, test, err):
        super().addError(test, err)
        emit('fail', test.id(), kind='case', detail=self._exc_info_to_string(err, test))

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        emit('skip', test.id(), kind='case', detail=reason)

    def addSubTest(self, test, subtest, err):
        super().addSubTest(test, subtest, err)
        if err is not None:
            emit('fail', subtest.id(), kind='case', detail=self._exc_info_to_string(err, test))

    def addExpectedFailure(self, test, err):
        super().addExpectedFailure(test, err)
        emit('skip', test.id(), kind='case', detail='Expected failure')

    def addUnexpectedSuccess(self, test):
        super().addUnexpectedSuccess(test)
        emit('fail', test.id(), kind='case', detail='Unexpected success')


def run_unittest(module='__main__'):
    result = unittest.TextTestRunner(resultclass=CaseResult, verbosity=0).run(
        unittest.defaultTestLoader.loadTestsFromModule(sys.modules[module]))
    return int(not result.wasSuccessful())
