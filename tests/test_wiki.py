#!/usr/bin/env python3
"""
The wiki that docs/wiki.py builds: every document has a page, and every link between pages lands on a real heading.
"""

from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

from test_results import run_unittest

ROOT = Path(__file__).resolve().parent.parent
LINK = re.compile(r'(?<!!)\[[^\]]*\]\(([^)\s]+)\)')


def anchors(text):
    """The anchors GitHub gives the headings of a page: lower case, spaces to dashes, punctuation dropped."""
    found = set()
    for heading in re.findall(r'^#+ +(.+?) *$', re.sub(r'```.*?```', '', text, flags=re.S), re.M):
        slug = re.sub(r'[^\w\- ]', '', heading.lower()).replace(' ', '-')
        found.add(slug)
    return found


class WikiTests(unittest.TestCase):
    def test_pages_sidebar_and_links(self):
        with tempfile.TemporaryDirectory(prefix='bgpsim-wiki-') as directory:
            # A page left by an earlier build must go: the wiki would keep serving it.
            Path(directory, 'Stale-Page.md').write_text('old')
            listed = subprocess.run([sys.executable, str(ROOT / 'docs' / 'wiki.py'), directory], check=True,
                                    capture_output=True, text=True).stdout.split()
            pages = {path.stem: path.read_text() for path in Path(directory).glob('*.md')}
        documents = sorted(path.name for path in (ROOT / 'docs').glob('*.md'))
        self.assertEqual(sorted(listed), sorted(f'{name}.md' for name in pages))
        self.assertEqual(len(pages), len(documents) + 3, 'one page for each document, Home, the sidebar and the footer')
        self.assertNotIn('Stale-Page', pages)
        # The rail lists every document page once, and nothing that is not a page.
        rail = [target for target in LINK.findall(pages['_Sidebar']) if not target.startswith('https:')]
        self.assertEqual(sorted(rail), sorted(set(pages) - {'_Sidebar', '_Footer'}))
        # A page keeps the text of its document: only links change.
        source = (ROOT / 'docs' / 'configuration.md').read_text()
        self.assertEqual(LINK.sub('', pages['Configuration-Guide']), LINK.sub('', source))
        checked = 0
        for name, text in pages.items():
            for target in LINK.findall(text):
                if re.match(r'[a-z]+:', target):
                   continue
                page, _, anchor = target.partition('#')
                self.assertNotIn('.md', page, f'{name}: {target} still names a file')
                self.assertIn(page or name, pages, f'{name}: {target} is not a page')
                if anchor:
                   self.assertIn(anchor, anchors(pages[page or name]), f'{name}: {target} is not a heading')
                checked += 1
        self.assertGreater(checked, 40)
        # Files of the repository that are not documents are linked on GitHub; the figure by its raw address.
        self.assertIn('](https://github.com/forhadahmed/bgpsim/raw/main/docs/overview.svg)', pages['Home'])


if __name__ == '__main__':
   sys.exit(run_unittest())
