#!/usr/bin/env python3
"""Executable generation workloads; CPU gates plus pressure-aware wall-time gates."""

import math
import os
import platform
import re
import sys
import time
import unittest

from test_common import ProcessFixture, find_bgpsim_binary
from test_results import run_unittest
from test_timing import cpu_stall_pct, cpu_stall_us, measurement_ms, walltime_verdict


# Each workload is one independently named case; configuration is the actual CLI input.
WORKLOADS = [
    ("small", "Small workload (1k paths)", 100, None, """\
ribout quick_small
  prefix 10.0.0.0/24 x 1000
  next-hop 192.168.1.1 x 1
  as-path [ rand(1000) x 5 ]
  localpref 100
  origin igp
"""),
    ("medium", "Medium workload (10k paths)", 100, None, """\
ribout quick_medium
  prefix 10.0.0.0/24 x 10000
  next-hop 192.168.1.1 x 1
  as-path [ rand(1000) x 5 ]
  localpref 100
  origin igp
"""),
    ("large", "Large workload (100k paths)", 1200, None, """\
ribout quick_large
  prefix 10.0.0.0/24 x 100000
  next-hop 192.168.1.1 x 1
  as-path [ rand(1000) x 5 ]
  localpref 100
  origin igp
"""),
    ("groups", "Multiple attribute groups (10)", 1200, None, """\
ribout quick_groups
  prefix 10.0.0.0/24 x 100000
  next-hop 192.168.1.1 x 10
  as-path [ rand(1000) x 5 ]
  localpref 100
  origin igp
"""),
    ("heap", "Heap allocation (20 segments)", 100, None, """\
ribout quick_heap
  prefix 10.0.0.0/24 x 10000
  next-hop 192.168.1.1 x 1
  as-path [ rand(1000) x 20 ]
  localpref 100
  origin igp
"""),
    ("sr6_scale", "SRv6 static scale (16k paths)", 100, None, """\
ribout quick_sr6_scale
  distinguisher 100 x 16
  color 200 201
  endpoint 2001:db8:100::1 x 500
  enlp 3
  priority 7
  next-hop 2001:db8:feed::1 x 8
  rt-set [192.0.2.10:100] [192.0.2.11:101]
  preference 500 501
  binding-sid srv6 fc00:0:70::1
  segment-list 7 weight 70 srv6 2001:db8:7::1 behavior 4660 structure 48 16 16 48 2001:db8:7::2 2001:db8:7::3 2001:db8:7::4 2001:db8:7::5 2001:db8:7::6
  localpref 100
  origin igp
"""),
    ("evpn2_scale", "EVPN Type 2 static scale (16k host bindings)", 100, None, """\
ribout quick_evpn2_scale
  rd 65000:320 x 8
  ethernet-tag 10 11
  mac 00:11:22:44:00:00 x 512
  ip 192.0.2.1 x 2
  label 30000 30001
  label2 40000 40001
  esi 00:00:00:00:00:00:00:00:00:00 00:00:00:00:00:00:00:00:00:01
  next-hop 192.0.2.10 x 8
  rt-set [65000:320] [65000:321]
  localpref 100
  origin igp
"""),
    ("sr6_rand_scale", "SRv6 seeded-random static attr spray (8k paths)", 100, 6001, """\
ribout quick_sr6_rand_scale
  distinguisher 500 x 8
  color 900 901
  endpoint 2001:db8:201::1 x 512
  enlp randrange(1,4)
  priority randrange(0,255)
  next-hop 2001:db8:feed::1 x 16
  rt-set [192.0.2.30:100] [192.0.2.31:101]
  preference rand(4096)
  binding-sid srv6 fc00:0:99::1 x 64
  segment-list 9 weight 90 srv6 2001:db8:9::1 behavior 4660 structure 48 16 16 48 2001:db8:9::2 2001:db8:9::3 2001:db8:9::4 2001:db8:9::5 2001:db8:9::6
  as-path 65001 [ rand(64512) x 3 ]
  localpref rand(512)
  origin igp
"""),
    ("evpn2_rand_scale", "EVPN Type 2 seeded-random static attr spray (8k host bindings)", 100, 3202, """\
ribout quick_evpn2_rand_scale
  rd 65000:320 x 4
  ethernet-tag 10 11
  mac 00:11:22:45:00:00 x 512
  ip 192.0.2.1 x 2
  label 30000 30001
  label2 40000 40001
  esi 00:00:00:00:00:00:00:00:00:00 x 4
  next-hop 192.0.2.10 x 64
  rt-set [65000:320] [65000:321]
  as-path 65001 [ rand(64512) x 3 ]
  med rand(1024)
  localpref rand(512)
  origin igp
"""),
    ("fs_srte_scale", "FlowSpec redirect to SR-TE (16k paths)", 100, None, """\
ribout quick_fs_srte_scale
  address-family ipv4 flowspec
  path-id 1 2
  as-path 65001
  localpref 100
  origin igp
  prefix 10.0.0.0/32 x 4096
  protocol each(6, 17)
  dst-port >=1024&<=65535
  action redirect-ip 192.0.2.1 x 4
  color 100 x 4 co 01
"""),
]


def performance_scale():
    value = float(os.environ.get('RIBOUT_PERF_SCALE',
                  os.environ.get('RIBOUT_QUICK_PERF_SCALE', '1' if platform.system() == 'Linux' else '3')))
    if not math.isfinite(value) or value <= 0:
        raise ValueError('Performance scale must be finite and positive')
    return value


class GenerationPerformance(unittest.TestCase):
    def run_workload(self, name, description, budget, seed, config):
        limit = min(3000, max(100, budget * performance_scale()))
        with ProcessFixture() as fixture:
            path = fixture.root / f'test_quick_{name}.conf'
            path.write_text(config)
            env = dict(os.environ)
            if seed is not None:
                env['RANDSEED'] = str(seed)
            before, started = cpu_stall_us(), time.monotonic()
            result = fixture.run(
                [find_bgpsim_binary(), '-l', str(fixture.root / 'bgpsim.log'), str(path)],
                input=f'update generate\nshow ribout quick_{name}\nquit\n',
                env=env, timeout=30)
            elapsed = (time.monotonic() - started) * 1000
            stall = cpu_stall_pct(before, cpu_stall_us(), elapsed)
            print(result.stdout, end='', flush=True)
            self.assertEqual(result.returncode, 0, description)
            wall = measurement_ms(result.stdout, 'Generation Time:')
            cpu = measurement_ms(result.stdout, 'Generation CPU:')
            paths = re.findall(r'^\s*Total Paths:\s*(\d+)\s*$', result.stdout, re.MULTILINE)
            self.assertEqual(len(paths), 1, 'Missing/ambiguous generated path count')
            self.assertGreater(int(paths[0]), 0)
            self.assertLess(cpu, limit, f'{description}: CPU {cpu}ms >= {limit}ms')
            verdict = walltime_verdict(wall, limit, stall)
            print(f'{description}: CPU {cpu:.3f}ms; elapsed {wall:.3f}ms; '
                  f'budget {limit:g}ms; CPU wait {stall}; wall time {verdict}', flush=True)
            self.assertNotEqual(verdict, 'fail', description)


def workload_case(workload):
    def test(self):
        self.run_workload(*workload)
    test.__doc__ = workload[1]
    return test


for _workload in WORKLOADS:
    setattr(GenerationPerformance, f'test_{_workload[0]}', workload_case(_workload))


if __name__ == '__main__':
    sys.exit(run_unittest())
