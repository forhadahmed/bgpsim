#!/usr/bin/env python3
"""
Build the GitHub wiki from README.md and docs/*.md.

    python3 docs/wiki.py <output-directory>

GitHub shows a wiki with a rail on the right: the contents of the open page, then the sidebar written here. The
files under docs/ stay the source: this script only copies them, under wiki page names, and rewrites the links
between them. Nothing here talks to GitHub; the output directory is a checkout of the wiki repository
(<repository>.wiki.git), or any directory to look at the result.

The sidebar groups every document under a heading (SECTIONS). A document that is in docs/ but in no group stops the
build, so a new document cannot be left out of the rail.
"""

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parent.parent
REPOSITORY = 'https://github.com/forhadahmed/bgpsim'
# The rail, top to bottom: (heading, [(document under docs/, page name)]). The page name is the title in the rail
# and, with dashes for spaces, the name of the wiki page.
SECTIONS = [
    ('Getting Started', [('packaging.md', 'Build and Packaging')]),
    ('Configuration', [('configuration.md', 'Configuration Guide'), ('ribout-configuration.md', 'Ribout Configuration'),
                       ('sending-updates.md', 'Sending UPDATEs'), ('logging.md', 'Logging')]),
    ('Address Families', [('address-families.md', 'Support Matrix'), ('ribout-evpn.md', 'EVPN'),
                          ('ribout-sr-policy.md', 'SR Policy'), ('ribout-flowspec.md', 'FlowSpec'),
                          ('ribout-templates.md', 'RTC VPLS and MVPN Templates'), ('bgp-ls.md', 'BGP-LS')]),
    ('Design', [('bgp-fsm.md', 'BGP FSM'), ('bgp-ribout.md', 'RIB-OUT Generation'), ('bgp-tx.md', 'Scripts and TX')]),
    ('APIs', [('python-api.md', 'Python API'), ('bgp-update-api.md', 'BGP UPDATE API')]),
    ('Development', [('testing.md', 'Testing Guide')]),
]
PAGES = {document: title.replace(' ', '-') for _, documents in SECTIONS for document, title in documents}
LINK = re.compile(r'(!?)\[([^\]]*)\]\(([^)\s]+)\)')


def rewrite(text, directory):
    """
    The same Markdown with links that work in the wiki. A link to a document becomes a link to its page; any other
    file of the repository is linked on GitHub, and an image by its raw address. `directory` is where the links of
    this text start from, relative to the repository.
    """
    def link(match):
        image, label, target = match.groups()
        if re.match(r'[a-z]+:|#', target):
           return match[0]
        path, _, anchor = target.partition('#')
        path = (directory / path).as_posix()
        document = path.removeprefix('docs/')
        if document in PAGES:
           return f'[{label}]({PAGES[document]}{"#" + anchor if anchor else ""})'
        kind = 'raw' if image else 'tree' if (ROOT / path).is_dir() else 'blob'
        return f'{image}[{label}]({REPOSITORY}/{kind}/main/{path.rstrip("/")})'

    return LINK.sub(link, text)


def build(output):
    documents = sorted(path.name for path in (ROOT / 'docs').glob('*.md'))
    if documents != sorted(PAGES):
       raise SystemExit(f'docs/wiki.py: SECTIONS and docs/*.md differ: {sorted(set(documents) ^ set(PAGES))}')
    output.mkdir(parents=True, exist_ok=True)
    # Pages of an earlier build whose document is gone must not stay in the wiki.
    for old in output.glob('*.md'):
        old.unlink()
    (output / 'Home.md').write_text(rewrite((ROOT / 'README.md').read_text(), Path('.')))
    for document, page in PAGES.items():
        (output / f'{page}.md').write_text(rewrite((ROOT / 'docs' / document).read_text(), Path('docs')))
    rail = ['**[bgpsim](Home)**', '']
    for heading, entries in SECTIONS:
        rail += [f'**{heading}**', '', *[f'- [{title}]({PAGES[document]})' for document, title in entries], '']
    rail += ['**Project**', '', f'- [Source]({REPOSITORY})', f'- [Issues]({REPOSITORY}/issues)', '']
    (output / '_Sidebar.md').write_text('\n'.join(rail))
    (output / '_Footer.md').write_text(f'Generated from [docs/]({REPOSITORY}/tree/main/docs) by `make wiki`. '
                                       'Edit the files there, not these pages.\n')
    return sorted(path.name for path in output.glob('*.md'))


if __name__ == '__main__':
   if len(sys.argv) != 2:
      raise SystemExit(__doc__.strip().splitlines()[2].strip())
   for name in build(Path(sys.argv[1])):
       print(name)
