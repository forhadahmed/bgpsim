#!/usr/bin/env python3
"""Build and exercise the exported product, without a test checkout or Python tooling."""

import os
from pathlib import Path, PurePosixPath
import stat
import sys
import sysconfig
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from test_common import ProcessFixture
from test_results import run_unittest

ROOT = Path(__file__).resolve().parent.parent


class ProductPackagingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix='bgpsim-package-')
        cls.addClassCleanup(temporary.cleanup)
        cls.root = Path(temporary.name)
        cls.build = cls.root / 'build'
        cls.stage = cls.root / 'stage'
        cls.python_marker = cls.root / 'python-invoked'
        tools = cls.root / 'tools'
        tools.mkdir()
        poison = tools / 'python3'
        poison.write_text(f'#!/bin/sh\necho invoked >> "{cls.python_marker}"\nexit 99\n')
        poison.chmod(0o755)
        cls.env = dict(os.environ, PATH=f'{tools}{os.pathsep}{os.environ["PATH"]}',
                       MAKEFLAGS='', MFLAGS='')
        cls.source = ROOT
        cls.make('dist', DIST_DIR=cls.root / 'export')
        cls.archive = cls.root / 'export' / 'bgpsim.tar.gz'
        with tarfile.open(cls.archive) as archive:
            for member in archive.getmembers():
                path = PurePosixPath(member.name)
                if (path.is_absolute() or '..' in path.parts or path.parts[0] != 'bgpsim' or
                        not (member.isfile() or member.isdir())):
                    raise AssertionError(f'Unsafe product archive member: {member.name}')
            archive.extractall(cls.root / 'source')
        cls.source = cls.root / 'source' / 'bgpsim'
        cls.make('-j4', 'all')
        cls.make('install', DESTDIR=cls.stage)
        cls.binary = cls.stage / 'opt/bgpsim/bin/bgpsim'
        cls.module_dir = cls.stage / 'opt/bgpsim/python'

    @classmethod
    def make(cls, *goals, **variables):
        settings = dict(BUILD_DIR=cls.build, PREFIX='/opt/bgpsim', PYTHONDIR='/opt/bgpsim/python')
        settings.update({name: os.environ[name] for name in ('CC', 'CFLAGS', 'LDFLAGS') if name in os.environ})
        settings.update(variables)
        command = ['make', '--no-print-directory', '-C', str(cls.source), *goals]
        command.extend(f'{name}={value}' for name, value in settings.items() if value is not None)
        with ProcessFixture(env=cls.env, install_signals=False) as fixture:
            result = fixture.run(command, timeout=90)
        print(' '.join(command), flush=True)
        print(result.stdout + result.stderr, end='', flush=True)
        if result.returncode:
            raise AssertionError(f'Make failed ({result.returncode}): {result.stdout}{result.stderr}')
        return result

    def payload(self, stage):
        return {str(path.relative_to(stage)) for path in stage.rglob('*') if path.is_file()}

    def test_archive_contains_only_product_sources_and_documentation(self):
        with tarfile.open(self.archive) as archive:
            files = {str(PurePosixPath(m.name).relative_to('bgpsim'))
                     for m in archive.getmembers() if m.isfile()}
        sources = {str(path.relative_to(ROOT)) for pattern in ('*.c', '*.h', '*.py')
                   for path in (ROOT / 'src').glob(pattern)}
        docs = {'README.md', 'docs/packaging.md', 'docs/configuration.md', 'docs/python-api.md',
                'docs/address-families.md', 'docs/bgp-ribout.md', 'docs/bgp-update-api.md',
                'docs/bgp-fsm.md', 'docs/logging.md', 'docs/overview.svg'}
        self.assertEqual(files, sources | docs | {'Makefile', 'LICENSE', 'LICENSE-linenoise'})
        self.assertFalse((self.source / 'tests').exists())
        self.assertFalse((self.source / 'src/format').exists())

    def test_product_build_and_export_do_not_execute_python_or_build_tests(self):
        self.assertFalse(self.python_marker.exists(), 'A product target invoked Python')
        self.assertTrue((self.build / 'bgpsim').is_file())
        self.assertFalse(list(self.build.glob('test*')))
        self.assertFalse(list(self.build.glob('*.test.o')))
        self.assertFalse(list(self.build.glob('bench*')))
        with ProcessFixture(install_signals=False) as fixture:
            result = fixture.run([str(self.binary), '--help'])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Usage:', result.stdout)

    def test_install_payload_and_modes(self):
        self.assertEqual(self.payload(self.stage), {'opt/bgpsim/bin/bgpsim', 'opt/bgpsim/python/bgpsim.py'})
        self.assertEqual(stat.S_IMODE(self.binary.stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE((self.module_dir / 'bgpsim.py').stat().st_mode), 0o644)
        self.assertEqual(self.binary.read_bytes(), (self.build / 'bgpsim').read_bytes())
        self.assertEqual((self.module_dir / 'bgpsim.py').read_bytes(), (ROOT / 'src/bgpsim.py').read_bytes())

    def test_individual_install_targets_and_scoped_uninstall(self):
        stage = self.root / 'individual-stage'
        self.make('install-bin', DESTDIR=stage, BINDIR='/custom/bin')
        self.assertEqual(self.payload(stage), {'custom/bin/bgpsim'})
        self.make('install-python', DESTDIR=stage)
        self.assertEqual(self.payload(stage), {'custom/bin/bgpsim', 'opt/bgpsim/python/bgpsim.py'})
        sentinel = stage / 'opt/bgpsim/python/keep.py'
        sentinel.write_text('unrelated\n')
        self.make('uninstall', DESTDIR=stage, BINDIR='/custom/bin')
        self.assertEqual(self.payload(stage), {'opt/bgpsim/python/keep.py'})
        self.assertEqual(sentinel.read_text(), 'unrelated\n')

    def test_default_python_directory_uses_selected_interpreter_and_prefix(self):
        stage = self.root / 'default-python-stage'
        prefix = '/opt/selected'
        self.make('install-python', DESTDIR=stage, PREFIX=prefix,
                  PYTHONDIR=None, PYTHON=sys.executable)
        purelib = sysconfig.get_path('purelib', vars={'base': prefix, 'platbase': prefix})
        self.assertEqual(self.payload(stage), {str(Path(purelib).relative_to('/') / 'bgpsim.py')})

    def test_installed_client_controls_installed_runtime_outside_checkout(self):
        with ProcessFixture() as fixture, patch('test_common.find_bgpsim_binary', return_value=str(self.binary)):
            config = fixture.root / 'installed.conf'
            config.write_text('router bgp 65291\n  router-id 192.0.2.91\n!\n')
            session = f'package_{os.getpid()}'
            self.assertTrue(fixture.start_session(session, config=config, log_path=fixture.root / 'daemon.log'))
            script = '''
import os
from pathlib import Path
import sys
os.chdir(sys.argv[3])
sys.path.insert(0, sys.argv[1])
import bgpsim
assert Path(bgpsim.__file__).resolve() == Path(sys.argv[1], 'bgpsim.py').resolve()
with bgpsim.connect(sys.argv[2]) as client:
    client.sock.settimeout(2)
    assert client.connected
    assert 'router bgp 65291' in client.cli('show running-config').splitlines()
    client.cli('config')
    client.cli('router bgp 65292')
    client.cli('exit')
    assert 'router bgp 65292' in client.cli('show running-config').splitlines()
print('installed client changed live runtime state')
'''
            result = fixture.run([sys.executable, '-I', '-B', '-S', '-c', script,
                                  str(self.module_dir), session, str(fixture.root)])
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('installed client changed live runtime state', result.stdout)
            self.assertIn('router bgp 65292', fixture.cli('show running-config', session=session).splitlines())


if __name__ == '__main__':
    sys.exit(run_unittest())
