#!/usr/bin/env python3
"""
Focused reproducer: a control client that disconnects while the daemon is writing a large reply kills the daemon.

Before the fix, bgpsim's libuv control writes did not ignore SIGPIPE. When the client had closed its end and the daemon
wrote the reply, the write raised
SIGPIPE and its default action terminates the whole daemon. A backtrace captured during the heavy-stress churn showed
exactly this path: uv_write2 <- output_write <- cli_show_neighbors <- cli_process_command_with_output.

This drives it deterministically, black-box, with no peers: configure many neighbors so `show bgp neighbors` produces a
reply larger than the socket buffer, send that command, then reset the control socket (RST) without reading the reply.
The daemon's write to the reset socket raises SIGPIPE.

  - Before the fix the daemon dies with SIGPIPE.
  - After it (SIGPIPE ignored), the write fails for that one client and the daemon stays up.

Linux-only: it reads the daemon's exit signal from a direct child and uses several 127/8 addresses for the neighbors.
"""

import select
import signal
import socket
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_common import ProcessFixture, find_bgpsim_binary, wait_until  # noqa: E402
from test_results import emit  # noqa: E402
import bgpsim  # noqa: E402

NEIGHBORS = 800


def config_text():
    lines = ['router bgp 65001', '  router-id 10.0.0.1']
    for i in range(NEIGHBORS):
        lines.append(f'  neighbor 127.{(i >> 8) & 255}.{(i >> 0) & 255}.2 remote-as {65100 + i}')
    return '\n'.join(lines) + '\n'


def hit_once(socket_path):
    """Send `show bgp neighbors` and reset the control socket without reading the reply."""
    client = bgpsim.BGPSimClient(socket_path=socket_path, timeout=2)
    try:
        client.connect()
        s = client.sock
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2048)   # fill fast so the daemon's write backs up
        s.sendall(bgpsim.BGPSimClient.build_frame(bgpsim.BGPSIM_CTRL_EXEC_REQ, b'show bgp neighbors'))
        if not select.select([s], [], [], 2)[0]:  # wait for the reply to begin, without consuming it
           raise TimeoutError('daemon did not start the large reply')
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        return True
    except (bgpsim.Error, OSError):
        return False
    finally:
        client.disconnect()                       # RST: the daemon's queued/next write hits a dead socket


def run(fixture):
    workdir = fixture.root
    config = Path(workdir) / 'repro.conf'
    config.write_text(config_text())
    # A private control socket, so this reproducer has its own lane and never collides with other foreground daemons.
    socket_path = str(workdir / 'control.sock')
    # -l keeps bgpsim's own log out of the default /tmp/bgpsim.log.
    daemon = fixture.start_process([find_bgpsim_binary(), '-l', str(workdir / 'daemon.log'), str(config)],
                                    cwd=workdir, env={'BGPSIM_CONTROL_SOCKET': socket_path})
    try:
        fixture.wait_ready(daemon, 20)
    except RuntimeError as exc:
        return str(exc), daemon.poll()
    for _ in range(500):
        if daemon.poll() is not None:
           break
        if not hit_once(socket_path):
           # A daemon killed mid-loop refuses the next connect before it is reaped: wait for its exit status, so the
           # signal is reported instead of a setup failure.
           wait_until(lambda: daemon.poll() is not None, 2)
           return 'could not drive a disconnect during a large reply', daemon.poll()
    if daemon.poll() is None:
       # A successful fresh control command is the positive control after all resets, not a quiet-time guess.
       try:
           if 'BGP' not in fixture.cli('show bgp summary', process=daemon):
              return 'daemon did not answer after resets', daemon.poll()
       except (OSError, ConnectionError) as exc:
           return str(exc), daemon.poll()
    return None, daemon.poll()


def available_signal(code):
    try:
        return signal.Signals(code).name
    except ValueError:
        return f'signal {code}'


def main():
    if not sys.platform.startswith('linux'):
       emit('skip', 'SIGPIPE reproducer: reads a direct child exit signal and uses 127/8 neighbor addresses (Linux)')
       return 0
    with ProcessFixture() as fixture:
        error, code = run(fixture)
    if code is not None and code < 0 and -code == signal.SIGPIPE:
       emit('fail', 'bgpsim is killed by SIGPIPE when a control client disconnects while it writes a large reply',
             detail='The daemon must ignore SIGPIPE; a client that closes mid-reply should fail that write, not the '
                    'process.')
       return 1
    if code is not None:
       reason = available_signal(-code) if code < 0 else f'exit code {code}'
       emit('fail', f'bgpsim died on {reason} when a control client disconnected mid-reply')
       return 1
    if error:
       emit('fail', f'SIGPIPE reproducer could not run: {error}')
       return 1
    emit('pass', 'bgpsim survives a control client that disconnects while it writes a large reply')
    return 0


if __name__ == '__main__':
   sys.exit(main())
