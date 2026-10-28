# Quiet by default; use V=1 for full command output.
# QCMD wraps echo+command into one shell invocation so parallel make
# output stays atomic per target.
ifdef V
    QCMD =
else
    QCMD = @printf "  %-4s %s\n" $(1) $(2) &&
endif

CC = gcc
DEPFLAGS = -MMD -MP

# Build mode: default is debug, use RELEASE=1 for optimized build
ifdef RELEASE
    # Release build: optimized, no debug symbols
    OPT_FLAGS = -O2
    DEBUG_FLAGS =
else
    # Debug build: debug symbols, no optimization (default)
    OPT_FLAGS = -O0
    DEBUG_FLAGS = -g
endif

CFLAGS = -Wall -Wextra -Werror -Wno-missing-field-initializers -pthread $(DEBUG_FLAGS) $(OPT_FLAGS) $(DEPFLAGS) -Isrc
LDFLAGS = -luv

# macOS: Homebrew's libuv lives outside the default search paths.
ifeq ($(shell uname -s),Darwin)
    BREW_PREFIX := $(shell brew --prefix 2>/dev/null)
    CFLAGS += -I$(BREW_PREFIX)/include
    LDFLAGS += -L$(BREW_PREFIX)/lib
endif

# Build directory
BUILD_DIR ?= /tmp/bgpsim

# Target executables
TARGET = $(BUILD_DIR)/bgpsim
# Object files
OBJS :=
OBJS += $(BUILD_DIR)/bgpsim.o
OBJS += $(BUILD_DIR)/bgp.o
OBJS += $(BUILD_DIR)/bgp_family.o
OBJS += $(BUILD_DIR)/bgp_router.o
OBJS += $(BUILD_DIR)/bgp_neighbor.o
OBJS += $(BUILD_DIR)/log.o
OBJS += $(BUILD_DIR)/config.o
OBJS += $(BUILD_DIR)/cli.o
OBJS += $(BUILD_DIR)/output.o
OBJS += $(BUILD_DIR)/linenoise.o
OBJS += $(BUILD_DIR)/bgp_ribout_config.o
OBJS += $(BUILD_DIR)/bgp_ribout_edit.o
OBJS += $(BUILD_DIR)/bgp_ribout_template.o
OBJS += $(BUILD_DIR)/bgp_ribout.o
OBJS += $(BUILD_DIR)/bgp_ribout_snapshot.o
OBJS += $(BUILD_DIR)/bgp_ribout_keyspace.o
OBJS += $(BUILD_DIR)/bgp_tx.o
OBJS += $(BUILD_DIR)/bgp_peer_tx.o
OBJS += $(BUILD_DIR)/bgp_update.o
OBJS += $(BUILD_DIR)/bgp_update_vpn.o
OBJS += $(BUILD_DIR)/bgp_update_evpn.o
OBJS += $(BUILD_DIR)/bgp_update_ls.o
OBJS += $(BUILD_DIR)/bgp_update_sr.o
OBJS += $(BUILD_DIR)/bgp_update_flowspec.o
OBJS += $(BUILD_DIR)/bgp_update_rtc.o
OBJS += $(BUILD_DIR)/bgp_update_vpls.o
OBJS += $(BUILD_DIR)/bgp_update_mvpn.o
OBJS += $(BUILD_DIR)/parser.o
OBJS += $(BUILD_DIR)/commands.o
OBJS += $(BUILD_DIR)/util.o
OBJS += $(BUILD_DIR)/control.o
OBJS += $(BUILD_DIR)/runtime.o
OBJS += $(BUILD_DIR)/script.o
OBJS += $(BUILD_DIR)/script_cli.o
OBJS += $(BUILD_DIR)/tx_exec.o
OBJS += $(BUILD_DIR)/tx_cli.o
OBJS += $(BUILD_DIR)/script_exec.o

.DEFAULT_GOAL := all
.PHONY: all clean install install-bin install-python uninstall dist help

PYTHON ?= python3
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
PYTHONDIR ?= $(shell $(PYTHON) -c 'import sysconfig; print(sysconfig.get_path("purelib", vars={"base": "$(PREFIX)", "platbase": "$(PREFIX)"}))')
DESTDIR ?=
DIST_DIR ?= $(BUILD_DIR)/dist

# Export only product inputs, never the checkout or test/developer tooling.
DIST_FILES = Makefile LICENSE LICENSE-linenoise README.md docs/overview.svg docs/packaging.md \
    docs/configuration.md docs/python-api.md docs/address-families.md \
    docs/bgp-ribout.md docs/bgp-update-api.md docs/bgp-fsm.md docs/logging.md \
    $(patsubst $(BUILD_DIR)/%.o,src/%.c,$(OBJS)) $(wildcard src/*.h) src/bgpsim.py

all: $(TARGET)

$(BUILD_DIR):
	@mkdir -p "$@"

$(TARGET): $(OBJS) | $(BUILD_DIR)
	$(call QCMD,"LD",$@)$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

$(BUILD_DIR)/%.o: src/%.c | $(BUILD_DIR)
	$(call QCMD,"CC",$<)$(CC) $(CFLAGS) -c $< -o $@

install: install-bin install-python

install-bin: $(TARGET)
	install -d "$(DESTDIR)$(BINDIR)"
	install -m 755 "$(TARGET)" "$(DESTDIR)$(BINDIR)/bgpsim"

install-python:
	@test -n "$(PYTHONDIR)" || { echo "Cannot determine PYTHONDIR; set it explicitly" >&2; exit 1; }
	install -d "$(DESTDIR)$(PYTHONDIR)"
	install -m 644 src/bgpsim.py "$(DESTDIR)$(PYTHONDIR)/bgpsim.py"

uninstall:
	@test -n "$(PYTHONDIR)" || { echo "Cannot determine PYTHONDIR; set it explicitly" >&2; exit 1; }
	rm -f "$(DESTDIR)$(BINDIR)/bgpsim" "$(DESTDIR)$(PYTHONDIR)/bgpsim.py"

dist: $(DIST_FILES)
	@set -e; stage=$$(mktemp -d); trap 'rm -rf "$$stage"' EXIT HUP INT TERM; \
	for file in $(DIST_FILES); do \
	    install -d "$$stage/bgpsim/$$(dirname "$$file")"; \
	    install -m 644 "$$file" "$$stage/bgpsim/$$file"; \
	done; \
	mkdir -p "$(DIST_DIR)"; \
	COPYFILE_DISABLE=1 tar -czf "$(DIST_DIR)/bgpsim.tar.gz" -C "$$stage" bgpsim
	@printf "  DIST %s/bgpsim.tar.gz\n" "$(DIST_DIR)"

clean:
	rm -rf $(BUILD_DIR)

# Product builds never evaluate the test manifest or require a test checkout.
ifneq ($(filter unit-test all-test all-test-run bench bench-build test-objs $(BUILD_DIR)/test_% $(BUILD_DIR)/bench_% $(BUILD_DIR)/bgp_test_client $(BUILD_DIR)/%.test.o,$(MAKECMDGOALS)),)
include tests/Makefile
endif

help:
	@echo "Product targets (no test dependencies):"
	@echo "  all            - Build bgpsim (default; RELEASE=1 for optimized build)"
	@echo "  install        - Install executable and Python client"
	@echo "  install-bin    - Install executable only"
	@echo "  install-python - Install Python client only"
	@echo "  uninstall      - Remove installed executable and Python client"
	@echo "  dist           - Create product-only source archive in DIST_DIR"
	@echo "  clean          - Remove BUILD_DIR"
	@echo ""
	@echo "Installation: PREFIX=/usr/local, BINDIR=PREFIX/bin, PYTHONDIR=Python purelib"
	@echo "              DESTDIR stages files without changing their installed paths"
	@echo ""
	@echo "Test targets (full checkout required):"
	@echo "  unit-test, all-test, bench, bench-build, test-objs"

-include $(OBJS:.o=.d)
