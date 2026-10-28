#define OUTPUT_STDIO_REMAP

#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include "util.h"
#include "output.h"
#include "runtime.h"
#include "commands.h"
#include "script_exec.h"

static int script_engine_connected(const bgp_sim_t *sim) {
    return sim->runtime && bgpsim_runtime_is_loop_thread(sim->runtime);
}

static void show_run_json(const script_run_t *run, uint64_t now, int connected);

static int script_command_result(int result) {
    if (result != SCRIPT_OK) fprintf(stderr, "Error: %s\n", script_error(result));
    return result == SCRIPT_OK ? 0 : -1;
}

static int script_keyword(const match_result_t *result, const char *keyword) {
    for (int i = 0; i < result->token_count; i++) {
        if (result->tokens[i].type == TOKEN_KEYWORD && strcmp(result->tokens[i].value, keyword) == 0) return 1;
    }
    return 0;
}

/*
 * Attached clients request color explicitly because the daemon cannot infer
 * their terminal. Captures and Python/control output stay plain by default.
 */
static int script_use_color(const match_result_t *result) {
    return terminal_color_enabled(script_keyword(result, "color"),
                                   output_current() == output_default() && isatty(STDOUT_FILENO));
}

static const char *run_state_color(script_run_state_t state, int color) {
    if (!color) return "";
    switch (state) {
        case RUN_RUNNING: return CLR_CYAN;
        case RUN_COMPLETE: return CLR_GREEN;
        case RUN_FAILED: return CLR_RED;
        default: return CLR_YELLOW;
    }
}

static void format_ms(uint64_t ms, char *buffer, size_t size) {
    if (ms < 1000) snprintf(buffer, size, "%" PRIu64 "ms", ms);
    else snprintf(buffer, size, "%" PRIu64 ".%03" PRIu64 "s", ms / 1000, ms % 1000);
}

int cmd_handle_script(void *ctx, match_result_t *result) {
    cmd_ctx_t       *command = ctx;
    char             name[MAX_TOKEN_LEN];
    bgpsim_script_t *script;
    int              rc;

    if (!match_get_string(result, "name", name, sizeof(name))) return -1;
    if (command->is_no_command) {
        rc = script_remove(&command->sim->scripts, name);
        if (rc == SCRIPT_OK && strcmp(command->current_script_name, name) == 0)
            command->current_script_name[0] = '\0';
        return script_command_result(rc);
    }
    rc = script_create(&command->sim->scripts, name, &script);
    if (rc != SCRIPT_OK) return script_command_result(rc);
    snprintf(command->current_script_name, sizeof(command->current_script_name), "%s", script->name);
    if (command->config_mode != CONFIG_MODE_SCRIPT) cmd_push_mode(command, CONFIG_MODE_SCRIPT);
    return 0;
}

static int script_append_command(cmd_ctx_t *command, const script_step_t *step) {
    bgpsim_script_t *script = script_find(&command->sim->scripts, command->current_script_name);
    if (!script) {
        fprintf(stderr, "Error: script context no longer exists; select a script first\n");
        return -1;
    }
    return script_command_result(script_append(script, step));
}

int cmd_handle_script_action(void *ctx, match_result_t *result) {
    cmd_ctx_t    *command = ctx;
    script_step_t step;
    char ribout[MAX_TOKEN_LEN], peer[MAX_TOKEN_LEN];
    uint32_t router = 0;
    script_action_t action = script_keyword(result, "advertise") ? SCRIPT_ADVERTISE :
                             script_keyword(result, "withdraw") ? SCRIPT_WITHDRAW : SCRIPT_REPLAY;
    int has_router = match_get_uint32(result, "router", &router);

    if (!match_get_string(result, "ribout", ribout, sizeof(ribout)) ||
        !match_get_string(result, "peer", peer, sizeof(peer)) ||
        (script_keyword(result, "router") && (!has_router || !router))) {
        return script_command_result(SCRIPT_INVALID);
    }
    int rc = script_step_action(&step, action, ribout, peer, router);
    return rc == SCRIPT_OK ? script_append_command(command, &step) : script_command_result(rc);
}

int cmd_handle_script_sleep(void *ctx, match_result_t *result) {
    script_step_t step;
    char          duration[MAX_TOKEN_LEN];
    if (!match_get_string(result, "duration", duration, sizeof(duration))) return -1;
    int rc = script_step_sleep(&step, duration);
    return rc == SCRIPT_OK ? script_append_command(ctx, &step) : script_command_result(rc);
}

int cmd_handle_script_remove_step(void *ctx, match_result_t *result) {
    cmd_ctx_t       *command = ctx;
    uint32_t         number = 0;
    bgpsim_script_t *script = script_find(&command->sim->scripts, command->current_script_name);
    if (!script || !command->is_no_command || !match_get_uint32(result, "step", &number) || !number)
        return script_command_result(SCRIPT_INVALID);
    return script_command_result(script_remove_step(script, number - 1));
}

int cmd_handle_run_script(void *ctx, match_result_t *result) {
    cmd_ctx_t *command = ctx;
    char name[MAX_TOKEN_LEN], repeat_text[MAX_TOKEN_LEN];
    uint32_t      repeat = 1;
    script_run_t *run;

    if (!match_get_string(result, "name", name, sizeof(name))) return -1;
    if (script_keyword(result, "repeat")) {
        if (!match_get_string(result, "repeat", repeat_text, sizeof(repeat_text)))
            return script_command_result(SCRIPT_INVALID);
        if (strcmp(repeat_text, "forever") == 0) repeat = 0;
        else if (!is_uint32(repeat_text, &repeat) || !repeat) return script_command_result(SCRIPT_INVALID);
    }
    int rc = script_run_create(&command->sim->scripts, name, repeat, script_now_ms(), &run);
    if (rc != SCRIPT_OK) return script_command_result(rc);
    int connected = script_engine_connected(command->sim);
    int json = script_keyword(result, "json");
    // Without the runtime (a config file, or a test) a run is a plan only: no timers, peers or TX.
    if (connected && script_exec_start(command->sim, run) < 0) {
        script_run_fail(run, "cannot start the run", script_now_ms());
        if (!json) {
            fprintf(stderr, "Error: run %u: cannot start\n", run->id);
            return -1;
        }
    }
    // Creation succeeded even if execution failed synchronously. JSON must
    // retain that run's ID and failure, rather than inviting a second start.
    if (json) show_run_json(run, script_now_ms(), connected);
    else if (!connected)
        printf("Run %u: script %s, pending (execution engine not connected).\n", run->id, run->script.name);
    else printf("Run %u: script %s started.\n", run->id, run->script.name);
    return 0;
}

static script_run_t *script_command_run(cmd_ctx_t *command, match_result_t *result) {
    uint32_t      id = 0;
    script_run_t *run;
    if (!match_get_uint32(result, "id", &id) || !(run = script_run_find(&command->sim->scripts, id))) {
        fprintf(stderr, "Error: run %u not found\n", id);
        return NULL;
    }
    return run;
}

int cmd_handle_cancel_run(void *ctx, match_result_t *result) {
    cmd_ctx_t    *command = ctx;
    script_run_t *run = script_command_run(ctx, result);
    if (!run) return -1;
    int rc = script_run_cancel(run, script_now_ms());
    if (rc == SCRIPT_OK) {
        script_exec_stop(command->sim, run->id);
        printf("Run %u cancelled; no route withdrawal performed.\n", run->id);
    }
    return script_command_result(rc);
}

int cmd_handle_clear_run(void *ctx, match_result_t *result) {
    cmd_ctx_t *command = ctx;
    uint32_t   id = 0;
    if (!match_get_uint32(result, "id", &id)) return -1;
    return script_command_result(script_run_remove(&command->sim->scripts, id));
}

void script_print_config(const script_store_t *store) {
    for (size_t i = 0; i < store->script_count; i++) {
        const bgpsim_script_t *script = store->scripts[i];
        printf("script %s\n", script->name);
        for (size_t j = 0; j < script->step_count; j++) {
            char line[256];
            script_format_step(&script->steps[j], line, sizeof(line));
            printf("  %s\n", line);
        }
        printf("!\n");
    }
}

int cmd_handle_show_scripts(void *ctx, match_result_t *result) {
    cmd_ctx_t            *command = ctx;
    const script_store_t *store = &command->sim->scripts;
    char                  name[MAX_TOKEN_LEN];
    int                   color = script_use_color(result);
    const char           *heading = color ? CLR_CYAN : "", *reset = color ? CLR_RESET : "";

    if (match_get_string(result, "name", name, sizeof(name))) {
        bgpsim_script_t *script = script_find(store, name);
        if (!script) return script_command_result(SCRIPT_NOT_FOUND);
        printf("%sScript %s%s (revision %" PRIu64 ", %zu steps)\n", heading, name, reset,
               script->revision, script->step_count);
        for (size_t i = 0; i < script->step_count; i++) {
            char line[256];
            script_format_step(&script->steps[i], line, sizeof(line));
            printf("  %3zu  %s\n", i + 1, line);
        }
    } else {
        if (!store->script_count) printf("No scripts configured.\n");
        else {
            printf("%s%-24s %8s %8s%s\n", heading, "Script", "Steps", "Revision", reset);
            for (size_t i = 0; i < store->script_count; i++) {
                const bgpsim_script_t *script = store->scripts[i];
                printf("%-24s %8zu %8" PRIu64 "\n", script->name, script->step_count, script->revision);
            }
        }
    }
    return 0;
}

static void run_iteration(const script_run_t *run, char *buffer, size_t size) {
    if (run->repeat) snprintf(buffer, size, "%" PRIu64 "/%u", run->iteration, run->repeat);
    else snprintf(buffer, size, "%" PRIu64 "/forever", run->iteration);
}

static void run_tx_counts(const script_run_t *run, char *buffer, size_t size) {
    uint64_t done = 0, total = 0;
    if (!run->peer_count) {
        snprintf(buffer, size, "-");
        return;
    }
    for (size_t i = 0; i < run->peer_count; i++) {
        done += run->peers[i].messages_done;
        total += run->peers[i].plan.messages_total;
    }
    snprintf(buffer, size, "%" PRIu64 "/%" PRIu64, done, total);
}

static const char *run_peer_state(const script_run_t *run, const script_peer_progress_t *peer) {
    return peer->plan.status == SCRIPT_PEER_WITHHELD ? "withheld" :
           peer->plan.status == SCRIPT_PEER_SKIPPED ? "skipped" :
           peer->complete ? "complete" :
           run->state == RUN_FAILED ? "failed" : run->state == RUN_CANCELLED ? "cancelled" :
           peer->started ? "sending" : "pending";
}

static void json_string(const char *text) {
    printf("\"");
    for (const unsigned char *p = (const unsigned char *)text; *p; p++) {
        if (*p == '"' || *p == '\\') printf("\\%c", *p);
        else if (*p < 0x20) printf("\\u%04x", *p);
        else printf("%c", *p);
    }
    printf("\"");
}

/* Serialize the existing run model; the CLI and API share its state machine,
 * clock helpers and peer-state interpretation. No second progress model. */
static void show_run_json(const script_run_t *run, uint64_t now, int connected) {
    printf("{\"schema_version\":1,\"id\":%u,\"script\":", run->id);
    json_string(run->script.name);
    printf(",\"state\":\"%s\",\"revision\":%" PRIu64 ",\"repeat\":%u,\"iteration\":%" PRIu64,
            script_run_state_name(run->state), run->script.revision, run->repeat, run->iteration);
    printf(",\"step_index\":%zu,\"step_count\":%zu,\"phase\":\"%s\",\"elapsed_ms\":%" PRIu64,
            run->step_index, run->script.step_count, script_run_phase_name(run->phase),
            script_run_elapsed(run, now));
    printf(",\"phase_elapsed_ms\":%" PRIu64 ",\"engine_connected\":%s,\"error\":",
            script_run_phase_elapsed(run, now), connected ? "true" : "false");
    json_string(run->error);
    printf(",\"current_ms\":{");
    for (int phase = RUN_PHASE_PREPARE; phase < RUN_PHASE_COUNT; phase++) {
        printf("%s\"%s\":%" PRIu64, phase == RUN_PHASE_PREPARE ? "" : ",",
                script_run_phase_name(phase), phase == (int)run->phase ?
                script_run_phase_elapsed(run, now) : run->current_ms[phase]);
    }
    printf("},\"peers\":[");
    for (size_t i = 0; i < run->peer_count; i++) {
        const script_peer_progress_t *peer = &run->peers[i];
        printf("%s{\"peer\":", i ? "," : "");
        json_string(peer->plan.peer);
        printf(",\"router_as\":%u,\"state\":\"%s\",\"export_version\":%" PRIu64,
                peer->plan.router_as, run_peer_state(run, peer), peer->plan.export_version);
        printf(",\"messages_done\":%" PRIu64 ",\"messages_total\":%" PRIu64
               ",\"bytes_done\":%" PRIu64 ",\"bytes_total\":%" PRIu64 ",\"elapsed_ms\":%" PRIu64,
                peer->messages_done, peer->plan.messages_total, peer->bytes_done,
                peer->plan.bytes_total, script_run_peer_elapsed(run, i, now));
        printf(",\"reason\":");
        json_string(peer->plan.reason);
        printf("}");
    }
    printf("],\"stats\":[");
    for (size_t i = 0; i < run->script.step_count; i++) {
        printf("%s{", i ? "," : "");
        for (int phase = RUN_PHASE_PREPARE; phase < RUN_PHASE_COUNT; phase++) {
            const script_timing_t *timing = &run->stats[i].phases[phase];
            printf("%s\"%s\":{\"samples\":%" PRIu64 ",\"total_ms\":%" PRIu64
                   ",\"min_ms\":%" PRIu64 ",\"max_ms\":%" PRIu64 "}",
                    phase == RUN_PHASE_PREPARE ? "" : ",", script_run_phase_name(phase),
                    timing->samples, timing->total_ms, timing->min_ms, timing->max_ms);
        }
        printf("}");
    }
    printf("]}\n");
}

static void show_run_detail(const script_run_t *run, uint64_t now, int color, int connected) {
    char iteration[40], elapsed[40], line[256];
    const char *reset = color ? CLR_RESET : "", *heading = color ? CLR_CYAN : "";
    run_iteration(run, iteration, sizeof(iteration));
    format_ms(script_run_elapsed(run, now), elapsed, sizeof(elapsed));
    printf("%sRun %u: %s%s\n", heading, run->id, run->script.name, reset);
    printf("State: %s%s%s\n", run_state_color(run->state, color), script_run_state_name(run->state), reset);
    printf("Script revision: %" PRIu64 " (frozen)\nIteration: %s\nRun time: %s\n",
           run->script.revision, iteration, elapsed);
    if (!connected) printf("Execution engine: not connected; no live TX measurements.\n");
    if (run->error[0]) printf("%sError: %s%s\n", color ? CLR_RED : "", run->error, reset);
    if (!run->iteration) {
        printf("Step: -\nPhase: -\nNo phase or peer observations recorded.\n");
    } else {
        script_format_step(&run->script.steps[run->step_index], line, sizeof(line));
        printf("Step: %zu/%zu %s\nPhase: %s%s%s\n", run->step_index + 1, run->script.step_count, line,
               heading, script_run_phase_name(run->phase), reset);
        printf("\n%s%-12s %s%s\n", heading, "Phase", "Current/last step time", reset);
        for (int phase = RUN_PHASE_PREPARE; phase < RUN_PHASE_COUNT; phase++) {
            int is_sleep = run->script.steps[run->step_index].action == SCRIPT_SLEEP;
            if (is_sleep != (phase == RUN_PHASE_SLEEP)) continue;
            if (!is_sleep && phase > (int)run->phase) snprintf(elapsed, sizeof(elapsed), "-");
            else {
                uint64_t ms = phase == (int)run->phase ? script_run_phase_elapsed(run, now) : run->current_ms[phase];
                format_ms(ms, elapsed, sizeof(elapsed));
            }
            printf("%-12s %s%s\n", script_run_phase_name(phase), elapsed,
                   run->state == RUN_RUNNING && phase == (int)run->phase ? " (active)" : "");
        }
        if (run->phase == RUN_PHASE_SLEEP) printf("Requested sleep: %" PRIu64 "ms\n",
                                                 run->script.steps[run->step_index].sleep_ms);
    }
    if (run->peer_count) {
        printf("\n%s%-10s %-39s %-10s %-12s %-18s %-22s %s%s\n", heading,
               "Router", "Peer", "State", "Export", "TX messages", "TX bytes", "TX time", reset);
        for (size_t i = 0; i < run->peer_count; i++) {
            const script_peer_progress_t *peer = &run->peers[i];
            char messages[48], bytes[48];
            snprintf(messages, sizeof(messages), "%" PRIu64 "/%" PRIu64,
                     peer->messages_done, peer->plan.messages_total);
            snprintf(bytes, sizeof(bytes), "%" PRIu64 "/%" PRIu64, peer->bytes_done, peer->plan.bytes_total);
            if (!peer->started) snprintf(elapsed, sizeof(elapsed), "-");
            else {
                format_ms(script_run_peer_elapsed(run, i, now), elapsed, sizeof(elapsed));
            }
            const char *state = run_peer_state(run, peer);
            printf("%-10u %-39s %-10s %-12" PRIu64 " %-18s %-22s %s\n", peer->plan.router_as,
                   peer->plan.peer, state, peer->plan.export_version, messages, bytes, elapsed);
        }
        for (size_t i = 0; i < run->peer_count; i++) {
            const script_peer_progress_t *peer = &run->peers[i];
            if (peer->plan.status != SCRIPT_PEER_PLANNED)
                printf("  %s: %s: %s\n", peer->plan.peer,
                       peer->plan.status == SCRIPT_PEER_WITHHELD ? "withheld" : "skipped", peer->plan.reason);
        }
        printf("TX completion is local socket-write completion, not TCP acknowledgment or receiver installation.\n");
    }
    printf("\n%sCompleted step timing aggregates%s\n", heading, reset);
    printf("%-6s %-12s %-10s %-14s %-14s %s\n", "Step", "Phase", "Samples", "Total", "Min", "Max");
    int samples = 0;
    for (size_t i = 0; i < run->script.step_count; i++) {
        for (int phase = RUN_PHASE_PREPARE; phase < RUN_PHASE_COUNT; phase++) {
            const script_timing_t *timing = &run->stats[i].phases[phase];
            char total[40], min[40], max[40];
            if (!timing->samples) continue;
            samples = 1;
            format_ms(timing->total_ms, total, sizeof(total));
            format_ms(timing->min_ms, min, sizeof(min));
            format_ms(timing->max_ms, max, sizeof(max));
            printf("%-6zu %-12s %-10" PRIu64 " %-14s %-14s %s\n", i + 1, script_run_phase_name(phase),
                   timing->samples, total, min, max);
        }
    }
    if (!samples) printf("No completed step timing samples.\n");
}

int cmd_handle_show_runs(void *ctx, match_result_t *result) {
    cmd_ctx_t            *command = ctx;
    const script_store_t *store = &command->sim->scripts;
    uint64_t              now = script_now_ms();
    uint32_t              id;
    int                   color = script_use_color(result);
    const char           *heading = color ? CLR_CYAN : "", *reset = color ? CLR_RESET : "";

    if (match_get_uint32(result, "id", &id)) {
        script_run_t *run = script_command_run(command, result);
        if (!run) return -1;
        if (script_keyword(result, "json"))
            show_run_json(run, now, script_engine_connected(command->sim));
        else show_run_detail(run, now, color, script_engine_connected(command->sim));
    } else if (!store->run_count) printf("No runs recorded.\n");
    else {
        printf("%s%-6s %-24s %-11s %-16s %-11s %-14s %-14s %s%s\n", heading,
               "ID", "Script", "State", "Iteration", "Phase", "Run time", "Phase time", "TX messages", reset);
        for (size_t i = 0; i < store->run_count; i++) {
            const script_run_t *run = store->runs[i];
            char iteration[40], elapsed[40], phase_time[40], tx[48];
            run_iteration(run, iteration, sizeof(iteration));
            format_ms(script_run_elapsed(run, now), elapsed, sizeof(elapsed));
            if (run->phase == RUN_PHASE_NONE) snprintf(phase_time, sizeof(phase_time), "-");
            else format_ms(script_run_phase_elapsed(run, now), phase_time, sizeof(phase_time));
            run_tx_counts(run, tx, sizeof(tx));
            printf("%-6u %-24s %s%-11s%s %-16s %s%-11s%s %-14s %-14s %s\n", run->id, run->script.name,
                   run_state_color(run->state, color), script_run_state_name(run->state), reset, iteration,
                   color && run->state == RUN_RUNNING ? CLR_CYAN : "", script_run_phase_name(run->phase), reset,
                   elapsed, phase_time, tx);
        }
        if (!script_engine_connected(command->sim))
            printf("Execution engine not connected; pending runs do not send or withdraw routes.\n");
    }
    return 0;
}
