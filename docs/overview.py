#!/usr/bin/env python3
"""Generate docs/overview.svg, the topology figure in README.md.

    python3 docs/overview.py

Three columns: the blocks of one config file (two ``router bgp`` blocks
and the ``ribout`` blocks they advertise), the single bgpsim process that
hosts one BGP instance per router block plus one UPDATE snapshot per
ribout, and the devices under test each instance peers with.  Under the
process sits the CLI or Python client that drives it over the control
socket.

Light colors sit on the elements as attributes and the dark set is a
prefers-color-scheme override in the style block, so the figure follows
the viewer's scheme on GitHub and stays readable in viewers without CSS.
"""

import html
import os

# Which ribout each enumerated neighbor of a router advertises, and the
# ribout blocks themselves.  The ellipsis rows stand for more of each.
ROUTERS = [('demo-v4', 'demo-v6'), ('demo-v6', 'demo-v4')]
RIBOUTS = [
    ('demo-v4', ['  prefix 172.16.0.0/24 x 1000', '  next-hop 192.0.2.1 x 2']),
    ('demo-v6', ['  prefix 2001:db8::/48 x 1000', '  next-hop 2001:db8::1 x 2']),
]

PITCH = 144                      # router row height = one BGPSIM segment
SNAP_H = 108                     # snapshot row height = one BGPSIM strip
ELL_H = 28                       # ellipsis row under the snapshots
LINE = 18                        # line height inside config blocks
TOP = 20                         # top of the BGPSIM rectangle
HEAD = 40                        # title strip above the segments
SEG_TOP = TOP + HEAD
SNAP_TOP = SEG_TOP + len(ROUTERS) * PITCH
ELL_TOP = SNAP_TOP + len(RIBOUTS) * SNAP_H
SIM_BOTTOM = ELL_TOP + ELL_H

CONF_X, CONF_W = 24, 304
SIM_X, SIM_W = 404, 160
SIM_MID = SIM_X + SIM_W // 2
PEER_X, PEER_W, PEER_H = 694, 140, 60
LINK_MID = (SIM_X + SIM_W + PEER_X) // 2
LINK_YS = (-24, -2)              # peering lines per row, offset from the center
DOT_YS = (12, 18, 24)            # vertical ellipsis below them: more peers
CLIENT_W, CLIENT_H, CLIENT_GAP = 210, 54, 44
WIDTH = PEER_X + PEER_W + 24
HEIGHT = SIM_BOTTOM + CLIENT_GAP + CLIENT_H + 20

MONO = 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace'
SANS = '-apple-system, "Segoe UI", Helvetica, Arial, sans-serif'

LIGHT = {
    'text': '#1f2328', 'muted': '#59636e', 'line': '#d1d9e0', 'code': '#f6f8fa',
    'sim': '#ddf4ff', 'sim_line': '#0969da', 'peer': '#dafbe1', 'peer_line': '#1a7f37',
}
DARK = {
    'text': '#e6edf3', 'muted': '#9198a1', 'line': '#3d444d', 'code': '#161b22',
    'sim': '#0c2a4d', 'sim_line': '#58a6ff', 'peer': '#132a1e', 'peer_line': '#3fb950',
}

# class -> (css property, palette key); the same table emits the light
# attributes and the dark override.
STYLE = {
    't':     [('fill', 'text')],
    'm':     [('fill', 'muted')],
    'code':  [('fill', 'code'), ('stroke', 'line')],
    'sim':   [('fill', 'sim'), ('stroke', 'sim_line')],
    'acc-s': [('stroke', 'sim_line')],
    'acc-f': [('fill', 'sim_line')],
    'peer':  [('fill', 'peer'), ('stroke', 'peer_line')],
}


def attrs(cls, **extra):
    parts = [f'class="{cls}"']
    parts += [f'{prop}="{LIGHT[key]}"' for prop, key in STYLE[cls]]
    parts += [f'{k.replace("_", "-")}="{v}"' for k, v in extra.items()]
    return ' '.join(parts)


def dark_css():
    rules = []
    for cls, props in STYLE.items():
        body = '; '.join(f'{prop}: {DARK[key]}' for prop, key in props)
        rules.append(f'      .{cls} {{ {body} }}')
    return '    @media (prefers-color-scheme: dark) {\n' + '\n'.join(rules) + '\n    }'


def rect(cls, x, y, w, h, **extra):
    return f'<rect {attrs(cls, x=x, y=y, width=w, height=h, **extra)}/>'


def line(cls, x1, y1, x2, y2, **extra):
    return f'<line {attrs(cls, x1=x1, y1=y1, x2=x2, y2=y2, **extra)}/>'


def text(cls, x, y, s, **extra):
    s = html.escape(s, quote=False).replace(' ', ' ')
    return f'<text {attrs(cls, x=x, y=y, **extra)}>{s}</text>'


def dots(x, cy):
    """Vertical ellipsis centered on (x, cy)."""
    return [f'<circle {attrs("m", cx=x, cy=cy + dy, r=1.5)}/>' for dy in (-6, 0, 6)]


def arrow_path(points):
    """Polyline whose middle vertex carries the arrowhead."""
    d = ' '.join(f'{"M" if i == 0 else "L"}{x} {y}' for i, (x, y) in enumerate(points))
    return f'<path {attrs("acc-s", fill="none", stroke_width=1, marker_mid="url(#arrow)")} d="{d}"/>'


def config_block(cy, lines):
    """A config excerpt centered on cy; returns its top, bottom and elements."""
    h = (len(lines) - 1) * LINE + 40
    top = cy - h // 2
    items = [rect('code', CONF_X, top, CONF_W, h, rx=6, stroke_width=1.5)]
    for n, s in enumerate(lines):
        cls = 'm' if s.strip() == '...' else 't'
        items.append(text(cls, CONF_X + 14, top + 24 + LINE * n, s,
                          font_size=13, font_family=MONO))
    return top, top + h, items


def callout(box_top, box_bot, part_top, part_bot):
    """Zoom lens from a config block to the BGPSIM part it configures."""
    right = CONF_X + CONF_W
    points = f'{right},{box_top} {SIM_X},{part_top} {SIM_X},{part_bot} {right},{box_bot}'
    items = [f'<polygon {attrs("acc-f", fill_opacity=0.07)} points="{points}"/>']
    for y1, y2 in ((box_top, part_top), (box_bot, part_bot)):
        items.append(line('acc-s', right, y1, SIM_X, y2,
                          stroke_dasharray='4 3', stroke_opacity=0.7))
    return items


def divider(y, **extra):
    return line('acc-s', SIM_X, y, SIM_X + SIM_W, y, stroke_opacity=0.5, **extra)


def part_label(c, title, sub, size=15):
    return [text('t', SIM_MID, c - 3, title, text_anchor='middle', font_size=size, font_weight=600),
            text('m', SIM_MID, c + 17, sub, text_anchor='middle', font_size=11, font_family=MONO)]


def router_row(i, ribouts):
    part_top = SEG_TOP + i * PITCH
    part_bot = part_top + PITCH
    c = part_top + PITCH // 2
    asn, peer_as = 10 * (i + 1), 100 * (i + 1)
    lines = [f'router bgp {asn}']
    for n, ribout in enumerate(ribouts, 1):
        lines += [f'  neighbor {asn}.0.0.{n} remote-as {peer_as}', f'    advertise {ribout}']
    lines.append('  ...')
    box_top, box_bot, config = config_block(c, lines)
    zoom = callout(box_top, box_bot, part_top, part_bot)
    segment = [divider(part_top)] + part_label(c, f'AS {asn}', f'router bgp {asn}')

    # One peering line per enumerated neighbor, named after what it carries,
    # and an ellipsis for the rest.
    sim_right = SIM_X + SIM_W
    link = []
    for dy, ribout in zip(LINK_YS, ribouts):
        link.append(arrow_path([(sim_right, c + dy), (LINK_MID, c + dy), (PEER_X, c + dy)]))
        link.append(text('m', sim_right + 6, c + dy - 4, ribout, font_size=10, font_family=MONO))
    link += dots(LINK_MID, c + DOT_YS[1])

    peer = [
        rect('peer', PEER_X, c - PEER_H // 2, PEER_W, PEER_H, rx=6, stroke_width=1.5),
        text('t', PEER_X + PEER_W // 2, c - 2, f'AS {peer_as}',
             text_anchor='middle', font_size=15, font_weight=600),
        text('m', PEER_X + PEER_W // 2, c + 16, 'BGP DUT',
             text_anchor='middle', font_size=11),
    ]
    return zoom, segment, config, link, peer


def ribout_row(k, name, body):
    part_top = SNAP_TOP + k * SNAP_H
    part_bot = part_top + SNAP_H
    c = part_top + SNAP_H // 2
    box_top, box_bot, config = config_block(c, [f'ribout {name}'] + body + ['  ...'])
    zoom = callout(box_top, box_bot, part_top, part_bot)
    # The first strip is cut off from the segments by a dashed divider.
    segment = [divider(part_top, stroke_dasharray='4 3') if k == 0 else divider(part_top)]
    segment += part_label(c, 'UPDATE snapshot', f'ribout {name}', size=14)
    return zoom, segment, config, [], []


def ellipsis_row():
    c = ELL_TOP + ELL_H // 2
    return [], [divider(ELL_TOP)] + dots(SIM_MID, c), dots(CONF_X + CONF_W // 2, c), [], []


def client():
    x = SIM_MID - CLIENT_W // 2
    top = SIM_BOTTOM + CLIENT_GAP
    mid = SIM_BOTTOM + CLIENT_GAP // 2
    return [
        rect('code', x, top, CLIENT_W, CLIENT_H, rx=6, stroke_width=1.5),
        text('t', SIM_MID, top + 23, 'CLI / Python client',
             text_anchor='middle', font_size=14, font_weight=600),
        text('m', SIM_MID, top + 41, 'advertise, withdraw, scripts',
             text_anchor='middle', font_size=11, font_family=MONO),
        arrow_path([(SIM_MID, top), (SIM_MID, mid), (SIM_MID, SIM_BOTTOM)]),
        text('m', SIM_MID + 10, mid + 4, 'control socket', font_size=11, font_style='italic'),
    ]


def render():
    layers = [[] for _ in range(5)]
    rows = [router_row(i, ribouts) for i, ribouts in enumerate(ROUTERS)]
    rows += [ribout_row(k, name, body) for k, (name, body) in enumerate(RIBOUTS)]
    rows.append(ellipsis_row())
    for parts in rows:
        for layer, items in zip(layers, parts):
            layer.extend(items)
    zoom, segment, config, link, peer = layers

    body = zoom
    body.append(rect('sim', SIM_X, TOP, SIM_W, SIM_BOTTOM - TOP, rx=8, stroke_width=1.5))
    body.append(text('t', SIM_MID, TOP + 26, 'BGPSIM',
                     text_anchor='middle', font_size=16, font_weight=700, letter_spacing=2))
    first_link = SEG_TOP + PITCH // 2 + LINK_YS[0]
    body.append(text('m', LINK_MID, first_link - 20, 'Route Injection',
                     text_anchor='middle', font_size=12, font_style='italic'))
    body += segment + config + link + peer + client()

    marker = (f'<marker id="arrow" viewBox="0 0 10 10" refX="5" refY="5" markerWidth="8" '
              f'markerHeight="8" markerUnits="userSpaceOnUse" orient="auto">'
              f'<path {attrs("acc-f")} d="M0 0 L10 5 L0 10 Z"/></marker>')
    title = ('One bgpsim process hosting two router bgp instances that peer with devices '
             'under test and send each neighbor the UPDATE snapshot of the ribout it '
             'advertises; a CLI or Python client drives the process over its control socket')
    head = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {WIDTH} {HEIGHT}" '
        f'width="{WIDTH}" height="{HEIGHT}" role="img" aria-labelledby="title" '
        f'font-family=\'{SANS}\'>',
        f'  <title id="title">{title}</title>',
        '  <style>', dark_css(), '  </style>',
        f'  <defs>{marker}</defs>',
    ]
    return '\n'.join(head + ['  ' + item for item in body] + ['</svg>', ''])


def main():
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'overview.svg')
    with open(out, 'w', encoding='utf-8') as fh:
        fh.write(render())
    print(f'wrote {out}')


if __name__ == '__main__':
    main()
