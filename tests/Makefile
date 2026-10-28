# Test and benchmark rules, included only for explicit test/build goals.
# Invoke through the repository-root Makefile.
TEST_CFLAGS = $(CFLAGS) -I. -Itests -DBGPSIM_TEST
PTY_LIBS = $(if $(filter Linux,$(shell uname -s)),-lutil)
TEST_CLIENT = $(BUILD_DIR)/bgp_test_client

# The suite manifest owns the test inventory and execution profiles.
TESTS := $(filter $(basename $(notdir $(wildcard tests/test_*.c))),$(shell $(PYTHON) tests/run_tests.py --list all))
TEST_BINS = $(addprefix $(BUILD_DIR)/,$(TESTS))
UNIT_TESTS := $(filter $(TESTS),$(shell $(PYTHON) tests/run_tests.py --list unit))
BENCHMARKS = bench_update_generation bench_ribout_pipeline bench_scale
BENCH_TARGETS = $(addprefix $(BUILD_DIR)/,$(BENCHMARKS))
BENCH_BINS = $(BENCH_TARGETS)
LINK_TARGETS = $(TEST_BINS) $(BENCH_TARGETS) $(TEST_CLIENT)

# Packaging regressions rebuild the export with the same toolchain settings.
export CC CFLAGS LDFLAGS

# Derive fixture groups from the product inventory; list frontend support once.
RUNTIME_SUPPORT_OBJS :=
RUNTIME_SUPPORT_OBJS += $(BUILD_DIR)/config.o
RUNTIME_SUPPORT_OBJS += $(BUILD_DIR)/parser.o
RUNTIME_SUPPORT_OBJS += $(BUILD_DIR)/commands.o
RUNTIME_SUPPORT_OBJS += $(BUILD_DIR)/cli.o
RUNTIME_SUPPORT_OBJS += $(BUILD_DIR)/control.o
RUNTIME_SUPPORT_OBJS += $(BUILD_DIR)/runtime.o
RUNTIME_SUPPORT_OBJS += $(BUILD_DIR)/script_cli.o
RUNTIME_SUPPORT_OBJS += $(BUILD_DIR)/tx_exec.o
RUNTIME_SUPPORT_OBJS += $(BUILD_DIR)/tx_cli.o
RUNTIME_SUPPORT_OBJS += $(BUILD_DIR)/script_exec.o

CORE_OBJS := $(filter-out $(BUILD_DIR)/bgpsim.o $(RUNTIME_SUPPORT_OBJS),$(OBJS))

# Only these modules have test-specific variants. Never replace product objects.
TEST_OVERRIDE_OBJS :=
TEST_OVERRIDE_OBJS += $(BUILD_DIR)/bgp_router.test.o
TEST_OVERRIDE_OBJS += $(BUILD_DIR)/bgp_neighbor.test.o
TEST_RUNTIME_OBJS := $(filter-out $(TEST_OVERRIDE_OBJS:.test.o=.o),$(CORE_OBJS))
TEST_RUNTIME_OBJS += $(TEST_OVERRIDE_OBJS)
TEST_RUNTIME_OBJS += $(RUNTIME_SUPPORT_OBJS)

PIPELINE_OBJS := $(filter $(BUILD_DIR)/bgp_ribout%.o,$(CORE_OBJS))
PIPELINE_OBJS += $(BUILD_DIR)/bgp_family.o
PIPELINE_OBJS += $(BUILD_DIR)/bgp_update.o
PIPELINE_OBJS += $(BUILD_DIR)/bgp_update_evpn.o
PIPELINE_OBJS += $(BUILD_DIR)/bgp_update_flowspec.o
PIPELINE_OBJS += $(BUILD_DIR)/bgp_update_sr.o
PIPELINE_OBJS += $(BUILD_DIR)/bgp_update_vpn.o
PIPELINE_OBJS += $(BUILD_DIR)/bgp_update_rtc.o
PIPELINE_OBJS += $(BUILD_DIR)/bgp_update_vpls.o
PIPELINE_OBJS += $(BUILD_DIR)/bgp_update_mvpn.o
PIPELINE_OBJS += $(BUILD_DIR)/bgp_update_ls.o
PIPELINE_OBJS += $(BUILD_DIR)/output.o
PIPELINE_OBJS += $(BUILD_DIR)/util.o

PIPELINE_TESTS := $(addprefix test_ribout_,update_generation stress map snapshot withdrawal keyspace)
SMALL_TESTS := $(addprefix test_,script_model wire_reader result_protocol output_buffers peer_tx)
RUNTIME_BINS := $(addprefix $(BUILD_DIR)/,$(filter-out $(PIPELINE_TESTS) $(SMALL_TESTS),$(TESTS)))
HELPER_BINS := $(addprefix $(BUILD_DIR)/test_,cli_config cli_commands ribout_generator \
    cli_ribout ribout_constraints ribout_churn)

.PHONY: unit-test all-test all-test-run bench bench-build test-objs

$(BUILD_DIR)/%.test.o: src/%.c | $(BUILD_DIR)
	$(call QCMD,"CC",$<)$(CC) $(TEST_CFLAGS) -c $< -o $@

$(BUILD_DIR)/test_helpers.o: tests/test_helpers.c | $(BUILD_DIR)
	$(call QCMD,"CC",$<)$(CC) $(TEST_CFLAGS) -c $< -o $@

test-objs: $(TEST_OVERRIDE_OBJS)

# One link rule; fixture groups supply objects, and exceptions add only their delta.
$(LINK_TARGETS): LINK_CFLAGS = $(TEST_CFLAGS)
$(BENCH_TARGETS): LINK_CFLAGS = $(CFLAGS) -I.
$(LINK_TARGETS): $(BUILD_DIR)/%: tests/%.c | $(BUILD_DIR)
	$(call QCMD,"LD",$@)$(CC) $(LINK_CFLAGS) -o $@ $< $(filter %.o,$^) $(EXTRA_LIBS)

$(RUNTIME_BINS): $(TEST_RUNTIME_OBJS)
$(RUNTIME_BINS) $(BUILD_DIR)/test_output_buffers: EXTRA_LIBS = $(LDFLAGS)
$(HELPER_BINS): $(BUILD_DIR)/test_helpers.o
$(addprefix $(BUILD_DIR)/,$(PIPELINE_TESTS)) $(BUILD_DIR)/test_peer_tx: $(PIPELINE_OBJS)
$(BUILD_DIR)/test_peer_tx: $(BUILD_DIR)/bgp_peer_tx.o
$(BUILD_DIR)/test_script_model: $(addprefix $(BUILD_DIR)/,script.o util.o)
$(BUILD_DIR)/test_output_buffers: $(BUILD_DIR)/output.o
$(BUILD_DIR)/test_control_edge_cases: $(TEST_CLIENT)
$(BUILD_DIR)/test_cli_pty: EXTRA_LIBS += $(PTY_LIBS)
$(BUILD_DIR)/test_allocation_failures: EXTRA_LIBS += -Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc

$(BUILD_DIR)/bench_update_generation: $(CORE_OBJS) $(RUNTIME_SUPPORT_OBJS)
$(BUILD_DIR)/bench_update_generation: EXTRA_LIBS = $(LDFLAGS)
$(BUILD_DIR)/bench_scale: $(CORE_OBJS) $(RUNTIME_SUPPORT_OBJS)
$(BUILD_DIR)/bench_scale: EXTRA_LIBS = $(LDFLAGS)
$(BUILD_DIR)/bench_ribout_pipeline: $(PIPELINE_OBJS)

# Both profiles use the same bounded executor and result store.
unit-test: $(TARGET) $(addprefix $(BUILD_DIR)/,$(UNIT_TESTS))
all-test-run: $(TARGET) $(TEST_CLIENT) $(TEST_BINS)

unit-test:
	$(PYTHON) tests/run_tests.py --profile unit --build-dir "$(BUILD_DIR)"

all-test: all-test-run

all-test-run:
	$(PYTHON) tests/run_tests.py --profile all --build-dir "$(BUILD_DIR)" $(if $(ALL_TEST_RUN_DIR),--run-dir "$(ALL_TEST_RUN_DIR)")

bench-build: $(BENCH_BINS)

bench: bench-build
	@status=0; for bench in $(BENCH_BINS); do \
	    $$bench || status=1; printf '\n'; \
	done; exit $$status

-include $(wildcard $(BUILD_DIR)/*.d)
