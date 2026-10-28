# Product Build And Packaging

The product is the `bgpsim` executable and `src/bgpsim.py`, a standard-library-only
Python control client. The client talks to the executable's Unix socket; no
in-process C library or test harness is required by consumers.

## Build Boundary

The root `Makefile` owns product compilation, installation, and source export.
`make` / `make all` compile only the executable, using a C compiler, POSIX
threads, and libuv headers and libraries. They do not invoke Python or read
anything under `tests/`.

`tests/Makefile` owns test-only objects, test executables, benchmarks, and suite
execution. It is loaded only for explicit test targets. Existing root targets
(`unit-test`, `all-test`, `bench`, `bench-build`, `test-objs`)
and direct test-binary targets remain available in a full checkout.

## Staged Installation

```bash
set -o pipefail
make RELEASE=1 2>&1 | tee /tmp/bgpsim-build.log
make install PREFIX=/usr DESTDIR=/tmp/bgpsim-root \
  2>&1 | tee /tmp/bgpsim-install.log
```

Installation writes only the executable and Python module:

- `$(DESTDIR)$(BINDIR)/bgpsim`, mode 755.
- `$(DESTDIR)$(PYTHONDIR)/bgpsim.py`, mode 644.

`PREFIX` defaults to `/usr/local`; `BINDIR` defaults to `$(PREFIX)/bin`.
`PYTHONDIR` defaults to the selected interpreter's `sysconfig` purelib path
under `PREFIX`. Override `PYTHON` to choose that interpreter, or set
`PYTHONDIR` explicitly for the consuming package's layout. `DESTDIR` is a
staging root, not part of the final installed paths.

`install-bin` installs only the executable; `install-python` installs only
the module and does not compile C. With an explicit `PYTHONDIR`, installation
does not invoke Python. `uninstall` removes the same two files using the same
path variables; it does not remove unrelated files or directories.

The executable needs libuv at runtime. The Python module needs Python 3 and a
running simulator, but no third-party Python dependencies. The installation
targets do not install tests, benchmarks, configurations, or development tools.

## Product Source Archive

```bash
set -o pipefail
make dist DIST_DIR=/tmp/bgpsim-export 2>&1 | tee /tmp/bgpsim-dist.log
```

`bgpsim.tar.gz` contains a `bgpsim/` directory with the product Makefile,
license files, C sources and headers, Python client, and product documentation. Its allowlist
excludes tests, benchmarks, topology fixtures, Git metadata,
credentials, and generated files. Export does not compile anything.

An external package can unpack this archive, build with `make all`, and stage
its runtime payload with `make install`. Neither operation needs the test
tree. The full checkout is required to run the test targets.

An importing package chooses `PREFIX`, `BINDIR`, and `PYTHONDIR` and declares
the runtime dependencies in its own packaging. The upstream simulator remains
independent of any consumer's build and test libraries.
