#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "output.h"
#include "commands.h"
#include "test_result.h"

#define CHECK(expr) do {                                                                 \
    if (!(expr)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expr); exit(1); } \
} while (0)

typedef struct {
    bgp_sim_t       sim;
    cli_session_t   session;
    cli_mode_t      mode;
    output_t        output;
    output_buffer_t out;
    output_buffer_t err;
} fixture_t;

static void capture(void *opaque, output_stream_t stream, const char *data, size_t size) {
    fixture_t *f = opaque;
    output_buffer_write(stream == OUTPUT_STREAM_STDOUT ? &f->out : &f->err, data, size);
}

static void init(fixture_t *f) {
    memset(f, 0, sizeof(*f));
    bgp_init_simulator(&f->sim);
    cli_session_init(&f->session);
    f->mode = CLI_MODE_EXEC;
    f->output = (output_t){.write = capture, .opaque = f};
}

static int command(fixture_t *f, const char *line) {
    output_buffer_reset(&f->out);
    output_buffer_reset(&f->err);
    return cli_process_command_with_output(&f->session, &f->sim, &f->mode, line, &f->output);
}

static const char *text(const fixture_t *f) {
    return f->out.data ? f->out.data : "";
}

static void destroy(fixture_t *f) {
    bgp_shutdown_sim(&f->sim);
    output_buffer_free(&f->out);
    output_buffer_free(&f->err);
}

static void define_churn(fixture_t *f) {
    CHECK(command(f, "configure terminal") >= 0);
    CHECK(command(f, "script churn") >= 0);
    CHECK(command(f, "advertise ribout blue peer 192.0.2.2 router 65001") >= 0);
    CHECK(command(f, "sleep 30s") >= 0);
    CHECK(command(f, "withdraw ribout blue peer 192.0.2.2 router 65001") >= 0);
    CHECK(command(f, "sleep 5s") >= 0);
}

static void test_config_mode_and_shows(void) {
    fixture_t f;
    char      prompt[256];
    init(&f);
    define_churn(&f);
    CHECK(f.session.config_mode == CONFIG_MODE_SCRIPT && strcmp(f.session.current_script_name, "churn") == 0);
    cli_build_prompt(f.mode, &f.session, prompt, sizeof(prompt), 0);
    CHECK(strcmp(prompt, "bgpsim(config-script-churn)# ") == 0);
    CHECK(command(&f, "show scripts") >= 0 && strstr(text(&f), "churn"));
    CHECK(f.session.config_mode == CONFIG_MODE_SCRIPT && strcmp(f.session.current_script_name, "churn") == 0);
    CHECK(command(&f, "show script churn") >= 0 && strstr(text(&f), "sleep 30000ms"));
    CHECK(strstr(text(&f), "advertise ribout blue peer 192.0.2.2 router 65001"));
    CHECK(command(&f, "replay ribout blue peer 2001:0db8::1") >= 0);
    CHECK(script_find(&f.sim.scripts, "churn")->step_count == 5);
    CHECK(command(&f, "no step 5") >= 0 && script_find(&f.sim.scripts, "churn")->step_count == 4);
    CHECK(command(&f, "show scripts ?") >= 0 && strstr(text(&f), "color"));
    CHECK(command(&f, "exit") >= 0 && f.session.config_mode == CONFIG_MODE_GLOBAL);
    CHECK(f.session.current_script_name[0] == 0);
    CHECK(command(&f, "end") >= 0 && f.mode == CLI_MODE_EXEC);
    CHECK(f.sim.runtime == NULL && f.sim.router_count == 0 && f.sim.ribout_count == 0);
    destroy(&f);
    test_result(1, "Script config mode, prompt, editing, show/help and exec fallback use shared CLI paths");
}

static void test_rejects_invalid_steps(void) {
    fixture_t f;
    init(&f);
    define_churn(&f);
    const char *invalid[] = {
        "sleep -1", "sleep 1.5s", "sleep 18446744073709551616ms", "sleep 1s extra",
        "advertise ribout blue peer bad", "advertise ribout blue peer all router",
        "advertise ribout blue peer all router 0", "advertise ribout blue peer all router -1",
        "advertise ribout bad;name peer all", "withdraw ribout blue", "replay ribout blue peer",
        "no advertise ribout blue peer all", "step 1", "no step 0", "no step 5"
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(*invalid); i++) {
        CHECK(command(&f, invalid[i]) < 0);
        CHECK(script_find(&f.sim.scripts, "churn")->step_count == 4);
        CHECK(f.session.config_mode == CONFIG_MODE_SCRIPT);
    }
    CHECK(command(&f, "sleep 0") >= 0);
    CHECK(script_find(&f.sim.scripts, "churn")->steps[4].sleep_ms == 0);
    destroy(&f);
    test_result(1, "Malformed actions, optional clauses, durations and negations leave definitions unchanged");
}

static void test_rejects_truncated_inputs(void) {
    fixture_t f;
    char name[SCRIPT_NAME_SIZE + 1], line[256];
    memset(name, 'a', sizeof(name) - 1);
    name[sizeof(name) - 1] = '\0';
    init(&f);
    define_churn(&f);
    snprintf(line, sizeof(line), "script %s", name);
    CHECK(command(&f, line) < 0 && f.sim.scripts.script_count == 1);
    snprintf(line, sizeof(line), "advertise ribout %s peer all", name);
    CHECK(command(&f, line) < 0 && script_find(&f.sim.scripts, "churn")->step_count == 4);
    memset(name, '0', sizeof(name) - 1);
    snprintf(line, sizeof(line), "sleep %s1s", name);
    CHECK(command(&f, line) < 0 && script_find(&f.sim.scripts, "churn")->step_count == 4);
    name[SCRIPT_NAME_SIZE - 3] = '\0';
    snprintf(line, sizeof(line), "sleep %s1s", name);
    CHECK(command(&f, line) >= 0);
    CHECK(script_find(&f.sim.scripts, "churn")->steps[4].sleep_ms == 1000);
    memset(name, 'a', sizeof(name) - 2);
    name[sizeof(name) - 2] = '\0';
    snprintf(line, sizeof(line), "script %s", name);
    CHECK(command(&f, line) >= 0);
    CHECK(command(&f, "sleep 1ms") >= 0);
    snprintf(line, sizeof(line), "run script %sx", name);
    CHECK(command(&f, line) < 0 && f.sim.scripts.run_count == 0);
    snprintf(line, sizeof(line), "show script %sx", name);
    CHECK(command(&f, line) < 0);
    snprintf(line, sizeof(line), "no script %sx", name);
    CHECK(command(&f, line) < 0 && f.sim.scripts.script_count == 2);
    destroy(&f);
    test_result(1, "Overlong names cannot alias definitions; duration tokens are validated without truncation");
}

static void test_round_trip(void) {
    fixture_t f, restored;
    char path[] = "/tmp/bgpsim-script-roundtrip-XXXXXX";
    init(&f);
    init(&restored);
    define_churn(&f);
    CHECK(command(&f, "script v6") >= 0);
    CHECK(command(&f, "replay ribout vpn6 peer 2001:0db8::1") >= 0);
    CHECK(command(&f, "advertise ribout evpn peer all") >= 0);
    CHECK(command(&f, "run script churn repeat 100") >= 0);
    CHECK(command(&f, "show running-config") >= 0);
    CHECK(!strstr(text(&f), "\x1b[") && !strstr(text(&f), "run script"));
    int fd = mkstemp(path);
    CHECK(fd >= 0);
    FILE *file = fdopen(fd, "w");
    CHECK(file != NULL);
    CHECK(fputs(text(&f), file) >= 0 && fclose(file) == 0);
    CHECK(parse_config_file_with_output(path, &restored.sim, &restored.output) == 0);
    CHECK(unlink(path) == 0);
    CHECK(restored.err.len == 0 && restored.sim.scripts.script_count == 2 && restored.sim.scripts.run_count == 0);
    for (size_t i = 0; i < f.sim.scripts.script_count; i++) {
        const bgpsim_script_t *before = f.sim.scripts.scripts[i];
        const bgpsim_script_t *after = script_find(&restored.sim.scripts, before->name);
        CHECK(after && after->step_count == before->step_count);
        for (size_t j = 0; j < before->step_count; j++) {
            char a[256], b[256];
            script_format_step(&before->steps[j], a, sizeof(a));
            script_format_step(&after->steps[j], b, sizeof(b));
            CHECK(strcmp(a, b) == 0);
        }
    }
    CHECK(strcmp(script_find(&restored.sim.scripts, "v6")->steps[0].peer, "2001:db8::1") == 0);
    CHECK(command(&f, "end") >= 0);
    CHECK(command(&f, "no script churn") < 0); /* Config-only mutation. */
    destroy(&restored);
    destroy(&f);
    test_result(1, "Running-config round trips actions and durations, never execution records or ANSI escapes");
}

static void test_pending_runs_and_cancellation(void) {
    fixture_t f;
    init(&f);
    CHECK(command(&f, "show runs") >= 0 && strstr(text(&f), "No runs"));
    CHECK(command(&f, "show scripts") >= 0 && strstr(text(&f), "No scripts"));
    define_churn(&f);
    const char *invalid[] = {"run script missing", "run script churn repeat", "run script churn repeat 0",
                             "run script churn repeat -1", "run script churn repeat 4294967296"};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(*invalid); i++) CHECK(command(&f, invalid[i]) < 0);
    CHECK(f.sim.scripts.run_count == 0);
    CHECK(command(&f, "run script churn repeat 100") >= 0 && strstr(text(&f), "engine not connected"));
    script_run_t *first = script_run_find(&f.sim.scripts, 1);
    CHECK(first && first->state == RUN_PENDING && first->repeat == 100 && first->peer_count == 0);
    CHECK(command(&f, "run script churn repeat forever") >= 0);
    CHECK(script_run_find(&f.sim.scripts, 2)->repeat == 0);
    CHECK(command(&f, "run script churn") >= 0 && script_run_find(&f.sim.scripts, 3)->repeat == 1);
    CHECK(command(&f, "show runs") >= 0 && strstr(text(&f), "pending") && strstr(text(&f), "0/100"));
    CHECK(command(&f, "show run 1") >= 0 && strstr(text(&f), "No phase or peer observations"));
    CHECK(!strstr(text(&f), "(active)"));
    CHECK(command(&f, "clear run 1") < 0);
    CHECK(command(&f, "cancel run 1") >= 0 && first->state == RUN_CANCELLED);
    CHECK(command(&f, "cancel run 1") >= 0);
    CHECK(command(&f, "clear run 1") >= 0 && !script_run_find(&f.sim.scripts, 1));
    CHECK(command(&f, "show run 999") < 0 && f.err.len);
    CHECK(command(&f, "cancel run 999") < 0);
    CHECK(f.sim.runtime == NULL && f.sim.router_count == 0 && f.sim.ribout_count == 0);
    destroy(&f);
    test_result(1, "CLI runs stay pending, honor repeat settings and support cancel/clear without engine access");
}

static void test_deleted_context(void) {
    fixture_t     f;
    cli_session_t other;
    cli_mode_t    other_mode = CLI_MODE_CONFIG;
    init(&f);
    define_churn(&f);
    CHECK(command(&f, "run script churn") >= 0);
    cli_session_init(&other);
    CHECK(cli_process_command_with_output(&other, &f.sim, &other_mode, "no script churn", &f.output) >= 0);
    CHECK(command(&f, "sleep 1s") < 0 && f.err.len);
    CHECK(f.sim.scripts.script_count == 0 && script_run_find(&f.sim.scripts, 1)->script.step_count == 4);
    CHECK(command(&f, "show scripts") >= 0 && f.session.config_mode == CONFIG_MODE_SCRIPT);
    CHECK(command(&f, "script fresh") >= 0 && strcmp(f.session.current_script_name, "fresh") == 0);
    CHECK(command(&f, "sleep 1s") >= 0);
    destroy(&f);
    test_result(1, "Concurrent CLI sessions retain stable names across script deletion; frozen runs remain intact");
}

static void test_mock_progress_rendering(void) {
    fixture_t f;
    init(&f);
    define_churn(&f);
    CHECK(command(&f, "run script churn") >= 0);
    script_run_t *run = script_run_find(&f.sim.scripts, 1);
    uint64_t      start = run->created_ms;
    script_peer_plan_t plan = {.peer = "192.0.2.2", .router_as = 65001,
                               .export_version = 3, .messages_total = 600, .bytes_total = 2400};
    CHECK(script_run_start(run, start) == SCRIPT_OK);
    CHECK(script_run_set_peers(run, &plan, 1, start + 12) == SCRIPT_OK);
    CHECK(script_run_set_phase(run, RUN_PHASE_QUEUE, start + 12) == SCRIPT_OK);
    CHECK(script_run_set_phase(run, RUN_PHASE_TRANSMIT, start + 15) == SCRIPT_OK);
    CHECK(script_run_peer_start(run, 0, start + 15) == SCRIPT_OK);
    CHECK(script_run_tx_progress(run, 0, 600, 2400, start + 1115) == SCRIPT_OK);
    CHECK(script_run_fail(run, "mock completion failure", start + 1115) == SCRIPT_OK);
    CHECK(command(&f, "show run 1") >= 0);
    CHECK(strstr(text(&f), "192.0.2.2") && strstr(text(&f), "600/600") && strstr(text(&f), "2400/2400"));
    CHECK(strstr(text(&f), "12ms") && strstr(text(&f), "3ms") && strstr(text(&f), "1.100s"));
    CHECK(strstr(text(&f), "mock completion failure") && strstr(text(&f), "not TCP acknowledgment"));
    CHECK(strstr(text(&f), "No completed step timing samples"));
    CHECK(!strstr(text(&f), "\x1b["));
    CHECK(command(&f, "show runs") >= 0 && strstr(text(&f), "failed") && strstr(text(&f), "600/600"));
    destroy(&f);
    test_result(1, "Show commands render mock TX/failure timings without claiming receiver convergence");
}

static void test_color(void) {
    fixture_t f;
    init(&f);
    define_churn(&f);
    CHECK(command(&f, "run script churn") >= 0);
    CHECK(setenv("TERM", "xterm-256color", 1) == 0 && unsetenv("NO_COLOR") == 0);
    CHECK(command(&f, "show runs color") >= 0 && strstr(text(&f), "\x1b[33m"));
    CHECK(command(&f, "show run 1 color") >= 0 && strstr(text(&f), "\x1b[36m"));
    CHECK(command(&f, "show scripts color") >= 0 && strstr(text(&f), "\x1b[36m"));
    CHECK(command(&f, "show script churn color") >= 0 && strstr(text(&f), "\x1b[36m"));
    CHECK(command(&f, "show runs") >= 0 && !strstr(text(&f), "\x1b["));
    script_run_t *run = script_run_find(&f.sim.scripts, 1);
    CHECK(script_run_start(run, run->created_ms) == SCRIPT_OK);
    CHECK(command(&f, "show run 1 color") >= 0 && strstr(text(&f), "State: \x1b[36mrunning\x1b[0m"));
    CHECK(script_run_fail(run, "mock failure", run->updated_ms) == SCRIPT_OK);
    CHECK(command(&f, "show run 1 color") >= 0 && strstr(text(&f), "State: \x1b[31mfailed\x1b[0m"));
    CHECK(command(&f, "script short") >= 0 && command(&f, "sleep 0ms") >= 0);
    CHECK(command(&f, "run script short") >= 0);
    run = script_run_find(&f.sim.scripts, 2);
    CHECK(script_run_start(run, run->created_ms) == SCRIPT_OK);
    CHECK(script_run_finish_step(run, run->updated_ms) == SCRIPT_OK);
    CHECK(command(&f, "show run 2 color") >= 0 && strstr(text(&f), "State: \x1b[32mcomplete\x1b[0m"));
    CHECK(setenv("NO_COLOR", "1", 1) == 0);
    CHECK(command(&f, "show runs color") >= 0 && !strstr(text(&f), "\x1b["));
    CHECK(unsetenv("NO_COLOR") == 0 && setenv("TERM", "dumb", 1) == 0);
    CHECK(command(&f, "show runs color") >= 0 && !strstr(text(&f), "\x1b["));
    CHECK(command(&f, "show running-config") >= 0 && !strstr(text(&f), "\x1b["));
    destroy(&f);
    test_result(1, "State/heading colors are opt-in for attached clients and suppressed by NO_COLOR or dumb terminals");
}

static void test_complete_command_boundary(void) {
    fixture_t f;
    char      line[1200];
    init(&f);
    define_churn(&f);
    // The invalid suffix must not disappear in a shorter CLI input buffer.
    memset(line, ' ', sizeof(line));
    memcpy(line, "sleep 1s", 8);
    strcpy(line + 255, "unexpected");
    CHECK(command(&f, line) < 0);
    CHECK(script_find(&f.sim.scripts, "churn")->step_count == 4);
    memset(line, ' ', BGPSIM_COMMAND_SIZE - 1);
    memcpy(line, "sleep 1s", 8);
    line[BGPSIM_COMMAND_SIZE - 1] = 0;
    CHECK(command(&f, line) >= 0 && script_find(&f.sim.scripts, "churn")->step_count == 5);
    CHECK(command(&f, "no step 5") >= 0);
    line[BGPSIM_COMMAND_SIZE - 1] = ' ';
    line[BGPSIM_COMMAND_SIZE] = 0;
    CHECK(command(&f, line) < 0 && script_find(&f.sim.scripts, "churn")->step_count == 4);
    memset(line + 255, ' ', sizeof(line) - 255);
    strcpy(line + 1100, "unexpected");
    CHECK(command(&f, line) < 0);
    CHECK(script_find(&f.sim.scripts, "churn")->step_count == 4);

    char path[] = "/tmp/bgpsim-command-boundary-XXXXXX";
    int fd = mkstemp(path);
    CHECK(fd >= 0);
    FILE *file = fdopen(fd, "w");
    CHECK(file && fprintf(file, "script boundary\n%s\nsleep 2s\n", line) > 0 && fclose(file) == 0);
    CHECK(parse_config_file_with_output(path, &f.sim, &f.output) == 0);
    CHECK(unlink(path) == 0);
    bgpsim_script_t *script = script_find(&f.sim.scripts, "boundary");
    CHECK(script && script->step_count == 1 && script->steps[0].sleep_ms == 2000);
    destroy(&f);
    test_result(1, "CLI and config reject a complete oversized/invalid line without executing its fragments");
}

static void test_ribout_identity_contract(void) {
    fixture_t f;
    char name[41], line[160];
    init(&f);
    CHECK(command(&f, "configure terminal") >= 0);
    memset(name, 'a', sizeof(name) - 1);
    name[sizeof(name) - 1] = 0;
    snprintf(line, sizeof(line), "ribout %s", name);
    CHECK(command(&f, line) < 0 && f.sim.ribout_count == 0);
    CHECK(command(&f, "script names") >= 0);
    snprintf(line, sizeof(line), "advertise ribout %s peer all", name);
    CHECK(command(&f, line) < 0 && script_find(&f.sim.scripts, "names")->step_count == 0);
    name[31] = 0;
    snprintf(line, sizeof(line), "advertise ribout %s peer all", name);
    CHECK(command(&f, line) >= 0); /* Forward references remain legal. */
    snprintf(line, sizeof(line), "ribout %s", name);
    CHECK(command(&f, line) >= 0 && f.sim.ribout_count == 1);
    CHECK(bgp_sim_find_ribout(&f.sim, script_find(&f.sim.scripts, "names")->steps[0].ribout) != NULL);
    CHECK(command(&f, line) >= 0 && f.sim.ribout_count == 1);
    destroy(&f);
    test_result(1, "Ribout creation and script references share exact name bounds without truncation or aliasing");
}

static void test_ribout_edit_and_generation_ownership(void) {
    fixture_t f;
    init(&f);
    const char *setup[] = {"configure terminal", "ribout evpn", "prefix 10.0.0.0/24", "rd 65000:1",
                           "label 100", "gateway-ip 0.0.0.0", "next-hop 192.0.2.1", "update generate"};
    for (size_t i = 0; i < sizeof(setup) / sizeof(*setup); i++) CHECK(command(&f, setup[i]) >= 0);
    bgp_ribout_config_t *block = f.sim.ribouts[0];
    CHECK(block->dirty == 0 && block->messages && block->prefix_spec.af == AF_INET);
    bgp_msg_t *messages = block->messages;
    CHECK(command(&f, "prefix 2001:db8::/64") < 0);
    CHECK(block->prefix_spec.af == AF_INET && !block->dirty && block->messages == messages);
    CHECK(command(&f, "next-hop 192.0.2.9 link-local fe80::1") < 0);
    struct in_addr expected;
    CHECK(inet_pton(AF_INET, "192.0.2.1", &expected) == 1);
    CHECK(block->next_hop_spec.base_addr.ipv4.s_addr == expected.s_addr && !block->dirty);
    route_distinguisher_t original_rd = block->rds[0];
    CHECK(command(&f, "rd 65000:2 invalid") < 0);
    CHECK(block->rd_count == 1 && !block->dirty && block->messages == messages);
    CHECK(memcmp(&original_rd, &block->rds[0], sizeof(original_rd)) == 0);
    CHECK(command(&f, "next-hop 192.0.2.2") >= 0 && block->dirty);
    CHECK(command(&f, "no label") >= 0 && block->dirty);
    CHECK(command(&f, "update generate") < 0 && block->dirty);
    CHECK(block->messages == messages);
    CHECK(strstr(text(&f), "failed") && f.err.len);
    CHECK(command(&f, "label 100") >= 0);
    CHECK(command(&f, "update generate") >= 0 && !block->dirty && block->message_count > 0);

    const char *flowspec[] = {"ribout fs", "prefix 10.0.0.0/24", "protocol 6", "action mark 8", "update generate"};
    for (size_t i = 0; i < sizeof(flowspec) / sizeof(*flowspec); i++) CHECK(command(&f, flowspec[i]) >= 0);
    block = bgp_sim_find_ribout(&f.sim, "fs");
    CHECK(block && block->flowspec && !block->dirty);
    bgp_ribout_flowspec_t *fs = block->flowspec;
    messages = block->messages;
    CHECK(command(&f, "protocol =6 invalid") < 0 && block->flowspec == fs && !block->dirty);
    CHECK(command(&f, "action redirect-ip invalid") < 0 && block->flowspec == fs && !block->dirty);
    CHECK(block->messages == messages && fs->actions.line_count == 1);
    CHECK(command(&f, "no action") >= 0 && block->dirty && !block->flowspec->actions.line_count);
    destroy(&f);
    test_result(1, "Ribout edits are atomic and generation failures propagate to the command caller");
}

int main(void) {
    test_config_mode_and_shows();
    test_rejects_invalid_steps();
    test_rejects_truncated_inputs();
    test_round_trip();
    test_pending_runs_and_cancellation();
    test_deleted_context();
    test_mock_progress_rendering();
    test_color();
    test_complete_command_boundary();
    test_ribout_identity_contract();
    test_ribout_edit_and_generation_ownership();
    return tests_failed ? 1 : 0;
}
