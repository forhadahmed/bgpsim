#!/usr/bin/env python3
"""
Heavy stress: bgpsim's TX path under every kind of churn at once, against real peers (black box).

--mode live (the default): every trigger family fires at once, in real time, nothing ordered. On bgpsim: TX commands,
ribout edits and generations, standing advertisements, neighbor and router removal, scripts, clears and shows. On the
peer side: clears, shutdowns, ROUTE-REFRESH bursts, stalls, crashes, restarts, neighbor and address-family changes, and
link failures. Each cycle fires for --window seconds, then settles, checks every peer table against what bgpsim reports
bound, reads the wire capture back, resets to the baseline, checks that against the test's own model, and measures
bgpsim. The run ends after --cycles cycles or --seconds seconds, whichever comes first; 0 means no bound. A long run is
the soak: descriptors and threads must return to their baseline values, RSS must not keep growing, and an
AddressSanitizer build must exit with no report. --seed fixes which triggers each actor picks, not when they land.

--mode forced: a single-threaded, seeded, reproducible sequence of forced interleavings (back a peer up mid-send, then
tear down or regenerate under it) — the red-first debugger.

--mode max: the live run with the forced interleavings folded in as one more concurrent actor, on one shared topology
and daemon. More stress than either alone (forced teardown-under-load races overlap the live chaos on shared sessions)
and one topology setup; it drops forced's reproducibility, so keep --mode forced for that.
"""

import sys
import time

import stress_harness
from test_common import ProcessFixture
from test_results import emit


def live(churn, args):
    churn.spawn_actors()
    started, cycle = time.monotonic(), 0
    while True:
        cycle += 1
        label = f'cycle {cycle}'
        churn.actors.resume()
        churn.actors.stop.wait(args.window)
        settled = churn.settle()
        if churn.crashed:
           churn.report_findings(label)
           return
        if settled:
           churn.check_bound(label)
        churn.check_capture(label)
        churn.reset_baseline(label)
        churn.report_findings(label)
        if (args.cycles and cycle >= args.cycles) or (args.seconds and time.monotonic() - started >= args.seconds):
           return


def forced(churn, args):
    """
    Single-threaded, seeded sequence: each cycle runs forced interleavings and background triggers, then settles and
    checks exactly. Reproducible for a given --seed because each sub-step waits on an observed state, not the clock.
    """
    import random
    rng = random.Random(f'{args.seed}:forced')
    started, cycle = time.monotonic(), 0
    while True:
        cycle += 1
        label = f'forced {cycle}'
        for _ in range(args.window_steps):
            churn.forced_step(rng)
            churn.forced_background(rng)
            if churn.crashed:
               break
        if churn.settle():
           churn.check_bound(label)
        if churn.crashed:
           churn.report_findings(label)
           return
        churn.check_capture(label)
        churn.reset_baseline(label)
        churn.report_findings(label)
        if (args.cycles and cycle >= args.cycles) or (args.seconds and time.monotonic() - started >= args.seconds):
           return


def main():
    args = stress_harness.arguments(__doc__.strip().splitlines()[0], cycles=1, seconds=0.0, window=8.0, window_steps=12)
    reason = stress_harness.unavailable(args.peer)
    if reason:
       emit('skip', f'heavy stress ({args.mode}) against peers: {reason}')
       return 0
    print(f'{args.mode}: seed {args.seed}; {stress_harness.peer_version(args.peer)}; {args.routers} routers x {args.peers} peers',
          flush=True)
    with ProcessFixture() as fixture:
        churn = stress_harness.Churn(fixture, args)
        try:
            churn.setup()
            churn.reset_baseline('baseline')
            churn.report_findings('baseline')
            (forced if args.mode == 'forced' else live)(churn, args)
            churn.finish('end')
            churn.check_capture('end')
            churn.report_findings('end')
            churn.leak_trend('soak')
        finally:
            churn.close()
    return 1 if churn.failed else 0


if __name__ == '__main__':
   sys.exit(main())
