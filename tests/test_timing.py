"""Timing evidence and budget policy for suite and workload gates."""

import math
from pathlib import Path
import re

MAX_STALL_PCT = 10


def cpu_stall_us():
    for file in ('/sys/fs/cgroup/cpu.pressure', '/proc/pressure/cpu'):
        try:
            text = Path(file).read_text()
        except OSError:
            continue
        match = re.search(r'^some .*total=(\d+)', text, re.MULTILINE)
        if match:
            return int(match[1])
    return None


def cpu_stall_pct(before, after, elapsed_ms):
    if before is None or after is None or after < before or elapsed_ms <= 0:
        return None
    return (after - before) / (10 * elapsed_ms)


def measurement_ms(text, label):
    matches = re.findall(r'^\s*' + re.escape(label) + r'\s*([^\n]+)$', text, re.MULTILINE)
    if len(matches) != 1:
        raise AssertionError(f'Expected one {label} measurement')
    match = re.fullmatch(r'(\d+(?:\.\d+)?)\s+(ms|sec)\s*', matches[0])
    if not match:
        raise AssertionError(f'Invalid {label} measurement: {matches[0]}')
    value = float(match[1]) * (1000 if match[2] == 'sec' else 1)
    if not math.isfinite(value):
        raise AssertionError(f'Nonfinite {label} measurement')
    return value


def walltime_verdict(elapsed_ms, budget_ms, stall_pct):
    if elapsed_ms <= budget_ms:
        return 'pass'
    return 'fail' if stall_pct is not None and stall_pct < MAX_STALL_PCT else 'warn'
