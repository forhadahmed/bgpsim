#!/usr/bin/env python3
"""One suite manifest, execution policy, and result store for every test profile."""

import argparse
from concurrent.futures import FIRST_EXCEPTION, ThreadPoolExecutor, wait
from datetime import datetime
import json
import math
import os
from pathlib import Path
import platform
import signal
import sys
import threading
import time

from test_results import collect, run_bounded
from test_timing import cpu_stall_pct, cpu_stall_us, walltime_verdict

HERE = Path(__file__).resolve().parent

# Suites of one lane run in manifest order; lanes run at the same time. Each lane owns a band of ports below the
# ephemeral range, so no two lanes can meet: its first ports are the listen base, the rest are for port finders.
MAIN_LANE = 'main'
FIRST_LANE_PORT = 10000
LANE_BAND_PORTS = 3000
LANE_LISTEN_PORTS = 1000
SHOW_LOCK = threading.Lock()


def load_manifest(path):
    data = json.loads(Path(path).read_text())
    if not isinstance(data, dict) or not isinstance(data.get('suites'), list):
       raise ValueError('Manifest must contain a suites list')
    names = set()
    for suite in data['suites']:
        if not isinstance(suite, dict):
           raise ValueError('Suite entry must be an object')
        name = suite['name']
        if not isinstance(name, str) or not name or not all(c.isalnum() or c in '_-' for c in name) or name in names:
           raise ValueError(f'Invalid/duplicate suite name: {name}')
        names.add(name)
        if (not isinstance(suite['command'], list) or not suite['command'] or
                not all(isinstance(x, str) and x for x in suite['command'])):
           raise ValueError(f'Invalid command for {name}')
        if (not isinstance(suite['profiles'], list) or not suite['profiles'] or
                not all(isinstance(x, str) and x for x in suite['profiles'])):
           raise ValueError(f'Invalid profiles for {name}')
        group = suite['group']
        if not isinstance(group, str) or not group or not all(c.isalnum() or c in '_-' for c in group):
           raise ValueError(f'Invalid group for {name}')
        for field in ('budget_ms', 'timeout'):
            value = suite.get(field)
            if value is not None and (isinstance(value, bool) or not isinstance(value, (float, int)) or
                                      not math.isfinite(value) or value <= 0):
               raise ValueError(f'Invalid {field} for {name}')
        lane = suite.get('lane', MAIN_LANE)
        if not isinstance(lane, str) or not lane or not all(c.isalnum() or c in '_-' for c in lane):
           raise ValueError(f'Invalid lane for {name}')
        if 'allow_empty' in suite and not isinstance(suite['allow_empty'], bool):
           raise ValueError(f'Invalid allow_empty for {name}')
    for profile, value in data.get('profile_budgets_ms', {}).items():
        if (not isinstance(profile, str) or isinstance(value, bool) or not isinstance(value, (int, float)) or
                not math.isfinite(value) or value <= 0):
           raise ValueError(f'Invalid profile budget: {profile}')
    return data


def select_suites(manifest, profile, names=()):
    suites = [s for s in manifest['suites'] if profile in s['profiles'] and
              s.get('platform', platform.system()) == platform.system()]
    if names:
       missing = set(names) - {s['name'] for s in suites}
       if missing:
          raise ValueError(f'Suites unavailable in {profile}: {sorted(missing)}')
       suites = [s for s in suites if s['name'] in names]
    if not suites:
       raise ValueError(f'Empty profile: {profile}')
    return suites


def execute(suite, build, directory, cancel, timeout):
    name = suite['name']
    group = directory / suite['group']
    group.mkdir(parents=True, exist_ok=True)
    log = group / f'{name}.log'
    command = [arg.replace('{build}', str(build)).replace('{python}', sys.executable)
               for arg in suite['command']]
    env = dict(os.environ, BUILD_DIR=str(build), PYTHONDONTWRITEBYTECODE='1')
    band = suite.get('port_band')
    if band:
       env['BGPSIM_LISTEN_BASE_PORT'] = str(band)
       env['BGPSIM_TEST_PORT_BAND'] = f'{band + LANE_LISTEN_PORTS}-{band + LANE_BAND_PORTS}'
    before, started = cpu_stall_us(), time.monotonic()
    with log.open('w') as out:
        try:
            rc = run_bounded(command, timeout or suite.get('timeout', 120), stdout=out,
                             cwd=HERE, env=env, cancel=cancel)
        except OSError as exc:
            out.write(f'[FAIL] Could not execute suite: {exc}\n')
            rc = 1
    duration = round((time.monotonic() - started) * 1000, 3)
    stall = cpu_stall_pct(before, cpu_stall_us(), duration)
    records = collect(log.read_text(errors='replace'), name, rc, allow_empty=suite.get('allow_empty', False))
    result_path = log.with_suffix('.results.jsonl')
    result_path.write_text(''.join(json.dumps(record) + '\n' for record in records))
    status = 'fail' if any(r['status'] == 'fail' for r in records) else \
        'skip' if all(r['status'] == 'skip' for r in records) else 'pass'
    budget = suite.get('budget_ms')
    timing = walltime_verdict(duration, budget, stall) if budget is not None else 'pass'
    return dict(name=name, status=status, returncode=rc, duration_ms=duration, budget_ms=budget,
                cpu_wait_pct=stall, walltime=timing, log=str(log), records=records, command=command)


def lane_port_bands(manifest):
    """The first port of each lane's band: stable for a lane, whichever suites a run selects."""
    lanes = dict.fromkeys(suite.get('lane', MAIN_LANE) for suite in manifest['suites'])
    first = int(os.environ.get('TEST_PORT_BASE', FIRST_LANE_PORT))
    return {lane: first + index * LANE_BAND_PORTS for index, lane in enumerate(lanes)}


def run_profile(manifest, suites, profile, build, directory, *, timeout=None):
    directory.mkdir(parents=True, exist_ok=True)
    (directory / 'manifest.json').write_text(json.dumps(suites, indent=2) + '\n')
    cancel = threading.Event()
    handlers = {}
    if threading.current_thread() is threading.main_thread():
       for sig in (signal.SIGINT, signal.SIGTERM):
           handlers[sig] = signal.signal(sig, lambda *_: cancel.set())
    before, started = cpu_stall_us(), time.monotonic()
    results = {}
    lanes = {}
    for suite in suites:
        lanes.setdefault(suite.get('lane', MAIN_LANE), []).append(suite)
    try:
        with ThreadPoolExecutor(max_workers=max(len(lanes), 1)) as pool:
            try:
                return _run_profile(manifest, suites, profile, build, directory, timeout,
                                    cancel, before, started, results, pool, lanes)
            except BaseException:
                # Cancel before executor shutdown waits for the other lanes.
                cancel.set()
                raise
    finally:
        for sig, handler in handlers.items():
            signal.signal(sig, handler)


def _run_profile(manifest, suites, profile, build, directory, timeout,
                 cancel, before, started, results, pool, lanes):
    bands = lane_port_bands(manifest)

    def run_lane(lane, members):
        lane_started = time.monotonic()
        for suite in members:
            if cancel.is_set():
               break
            result = execute({**suite, 'port_band': bands[lane]}, build, directory, cancel, timeout)
            results[suite['name']] = result
            show_result(result)
        return lane, round((time.monotonic() - lane_started) * 1000, 3)

    done, _ = wait([pool.submit(run_lane, lane, members) for lane, members in lanes.items()],
                   return_when=FIRST_EXCEPTION)
    lane_durations = dict(future.result() for future in done)
    elapsed = round((time.monotonic() - started) * 1000, 3)
    ordered = [results[s['name']] for s in suites if s['name'] in results]
    records = [record for result in ordered for record in result['records']]
    counts = {status: sum(r['status'] == status for r in records) for status in ('pass', 'fail', 'skip', 'xfail')}
    kinds = {kind: sum(r['kind'] == kind for r in records) for kind in ('case', 'check')}
    budget = manifest.get('profile_budgets_ms', {}).get(profile) if len(suites) == len(
        select_suites(manifest, profile)) else None
    timing = walltime_verdict(elapsed, budget, cpu_stall_pct(before, cpu_stall_us(), elapsed)) if budget else 'pass'
    failed = (cancel.is_set() or len(ordered) != len(suites) or timing == 'fail' or
              any(r['status'] == 'fail' or r['walltime'] == 'fail' for r in ordered))
    summary = dict(profile=profile, suites=len(ordered), counts=counts, results_by_kind=kinds,
                   duration_ms=elapsed, lane_duration_ms=lane_durations, walltime=timing,
                   status='fail' if failed else 'pass', results=ordered)
    (directory / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    with (directory / f'{profile}-test.log').open('w') as aggregate:
        for result in ordered:
            aggregate.write(f'--- {result["name"]} ---\n')
            aggregate.write(Path(result['log']).read_text(errors='replace'))
    text = (f'Suites: {len(ordered)}; cases: {kinds["case"]}; checks: {kinds["check"]}\n'
            f'Passed: {counts["pass"]}; failed: {counts["fail"]}; skipped: {counts["skip"]}; '
            f'expected failures: {counts["xfail"]}\n'
            f'Duration: {elapsed / 1000:.3f}s; wall time: {timing}\nLogs: {directory}\n')
    text += 'Lane wall times: ' + ', '.join(f'{lane}={lane_durations[lane] / 1000:.3f}s' for lane in lanes) + '\n'
    (directory / 'summary.txt').write_text(text)
    (directory / 'exit-code').write_text(f'{int(failed)}\n')
    print(text, end='')
    return int(failed)


def show_result(result):
    status = 'FAIL' if result['status'] == 'fail' or result['walltime'] == 'fail' else result['status'].upper()
    with SHOW_LOCK:
        print(f'[{status}] {result["name"]}: {result["duration_ms"]:.0f}ms '
              f'(wall time: {result["walltime"]}; log: {result["log"]})', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', default='all')
    parser.add_argument('--list', dest='list_profile')
    parser.add_argument('--suite', action='append', default=[])
    parser.add_argument('--manifest', type=Path, default=HERE / 'suites.json')
    parser.add_argument('--build-dir', type=Path, default=Path(os.environ.get('BUILD_DIR', '/tmp/bgpsim')))
    parser.add_argument('--run-dir', type=Path)
    parser.add_argument('--timeout', type=float, default=os.environ.get('TEST_TIMEOUT_SECONDS'))
    args = parser.parse_args()
    try:
        manifest = load_manifest(args.manifest)
        suites = select_suites(manifest, args.list_profile or args.profile, args.suite)
        if args.list_profile:
           print(' '.join(s['name'] for s in suites))
           return 0
        if args.timeout is not None and (not math.isfinite(args.timeout) or args.timeout <= 0):
           parser.error('timeout must be positive')
        root = args.build_dir.resolve() / f'{args.profile}-test-logs'
        directory = args.run_dir or root / f'{datetime.now():%Y%m%d-%H%M%S-%f}-{os.getpid()}'
        directory.mkdir(parents=True, exist_ok=True)
        if not args.run_dir:
           latest = root / f'.latest-{os.getpid()}'
           latest.symlink_to(directory)
           latest.replace(root / 'latest')
        print(f'Test logs: {directory}', flush=True)
        return run_profile(manifest, suites, args.profile, args.build_dir.resolve(), directory.resolve(),
                           timeout=args.timeout)
    except (OSError, ValueError, KeyError) as exc:
        parser.error(str(exc))


if __name__ == '__main__':
   sys.exit(main())
