#include <time.h>
#include <ctype.h>
#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include "script.h"

const char *script_error(int error) {
    switch (error) {
        case SCRIPT_OK: return "success";
        case SCRIPT_NOT_FOUND: return "not found";
        case SCRIPT_LIMIT: return "model capacity or counter limit reached";
        case SCRIPT_STATE: return "operation is not valid in the current state";
        case SCRIPT_NOMEM: return "out of memory";
        default: return "invalid argument";
    }
}

const char *script_action_name(script_action_t action) {
    static const char *names[] = {"advertise", "withdraw", "replay", "sleep"};
    return action >= SCRIPT_ADVERTISE && action <= SCRIPT_SLEEP ? names[action] : "unknown";
}

const char *script_run_state_name(script_run_state_t state) {
    static const char *names[] = {"pending", "running", "complete", "failed", "cancelled"};
    return state >= RUN_PENDING && state <= RUN_CANCELLED ? names[state] : "unknown";
}

const char *script_run_phase_name(script_run_phase_t phase) {
    static const char *names[] = {"-", "prepare", "queue", "transmit", "sleep"};
    return phase >= RUN_PHASE_NONE && phase < RUN_PHASE_COUNT ? names[phase] : "unknown";
}

int script_name_valid(const char *name) {
    return config_name_valid(name, SCRIPT_NAME_SIZE);
}

int script_parse_duration(const char *text, uint64_t *ms) {
    uint64_t    value = 0;
    uint64_t    scale;
    const char *p = text;

    if (!p || !ms || !isdigit((unsigned char)*p)) return SCRIPT_INVALID;
    while (isdigit((unsigned char)*p)) {
        unsigned digit = (unsigned)(*p++ - '0');
        if (value > (UINT64_MAX - digit) / 10) return SCRIPT_INVALID;
        value = value * 10 + digit;
    }
    if (!*p || strcmp(p, "s") == 0) scale = 1000;
    else if (strcmp(p, "ms") == 0) scale = 1;
    else if (strcmp(p, "m") == 0) scale = 60000;
    else if (strcmp(p, "h") == 0) scale = 3600000;
    else return SCRIPT_INVALID;
    if (value > UINT64_MAX / scale) return SCRIPT_INVALID;
    *ms = value * scale;
    return SCRIPT_OK;
}

int script_step_action(script_step_t *step, script_action_t action,
                       const char *ribout, const char *peer, uint32_t router_as) {
    script_step_t parsed = {0};

    if (!step || action < SCRIPT_ADVERTISE || action > SCRIPT_REPLAY ||
        !bgp_ribout_name_valid(ribout) || !peer) return SCRIPT_INVALID;
    parsed.action = action;
    parsed.router_as = router_as;
    snprintf(parsed.ribout, sizeof(parsed.ribout), "%s", ribout);
    if (strcmp(peer, "all") == 0) {
        snprintf(parsed.peer, sizeof(parsed.peer), "all");
    } else {
        if (canonical_ip_address(peer, parsed.peer, sizeof(parsed.peer)) < 0) return SCRIPT_INVALID;
    }
    *step = parsed;
    return SCRIPT_OK;
}

int script_step_sleep(script_step_t *step, const char *duration) {
    script_step_t parsed = {.action = SCRIPT_SLEEP};
    if (!step || script_parse_duration(duration, &parsed.sleep_ms) != SCRIPT_OK) return SCRIPT_INVALID;
    *step = parsed;
    return SCRIPT_OK;
}

void script_format_step(const script_step_t *step, char *buffer, size_t size) {
    if (step->action == SCRIPT_SLEEP) {
        snprintf(buffer, size, "sleep %" PRIu64 "ms", step->sleep_ms);
    } else if (step->router_as) {
        snprintf(buffer, size, "%s ribout %s peer %s router %u",
                 script_action_name(step->action), step->ribout, step->peer, step->router_as);
    } else {
        snprintf(buffer, size, "%s ribout %s peer %s", script_action_name(step->action), step->ribout, step->peer);
    }
}

bgpsim_script_t *script_find(const script_store_t *store, const char *name) {
    if (!store || !name) return NULL;
    for (size_t i = 0; i < store->script_count; i++) {
        if (strcmp(store->scripts[i]->name, name) == 0) return store->scripts[i];
    }
    return NULL;
}

int script_create(script_store_t *store, const char *name, bgpsim_script_t **result) {
    bgpsim_script_t *script;
    if (!store || !result || !script_name_valid(name)) return SCRIPT_INVALID;
    script = script_find(store, name);
    if (!script) {
        if (store->script_count == SCRIPT_MAX_SCRIPTS) return SCRIPT_LIMIT;
        script = calloc(1, sizeof(*script));
        if (!script) return SCRIPT_NOMEM;
        snprintf(script->name, sizeof(script->name), "%s", name);
        store->scripts[store->script_count++] = script;
    }
    *result = script;
    return SCRIPT_OK;
}

static void script_free(bgpsim_script_t *script) {
    if (script) {
        free(script->steps);
        free(script);
    }
}

int script_remove(script_store_t *store, const char *name) {
    if (!store || !name) return SCRIPT_INVALID;
    for (size_t i = 0; i < store->script_count; i++) {
        if (strcmp(store->scripts[i]->name, name) == 0) {
            script_free(store->scripts[i]);
            memmove(store->scripts + i, store->scripts + i + 1,
                    (store->script_count - i - 1) * sizeof(*store->scripts));
            store->scripts[--store->script_count] = NULL;
            return SCRIPT_OK;
        }
    }
    return SCRIPT_NOT_FOUND;
}

int script_append(bgpsim_script_t *script, const script_step_t *step) {
    script_step_t  validated;
    script_step_t *steps;
    int            result;

    if (!script || !step || !memchr(step->ribout, 0, sizeof(step->ribout)) ||
        !memchr(step->peer, 0, sizeof(step->peer))) return SCRIPT_INVALID;
    if (script->step_count == SCRIPT_MAX_STEPS || script->revision == UINT64_MAX) return SCRIPT_LIMIT;
    if (step->action == SCRIPT_SLEEP) {
        validated = (script_step_t){.action = SCRIPT_SLEEP, .sleep_ms = step->sleep_ms};
    } else {
        result = script_step_action(&validated, step->action, step->ribout, step->peer, step->router_as);
        if (result != SCRIPT_OK) return result;
    }
    steps = realloc(script->steps, (script->step_count + 1) * sizeof(*steps));
    if (!steps) return SCRIPT_NOMEM;
    script->steps = steps;
    script->steps[script->step_count++] = validated;
    script->revision++;
    return SCRIPT_OK;
}

int script_remove_step(bgpsim_script_t *script, size_t index) {
    if (!script || index >= script->step_count) return SCRIPT_INVALID;
    if (script->revision == UINT64_MAX) return SCRIPT_LIMIT;
    memmove(script->steps + index, script->steps + index + 1,
            (script->step_count - index - 1) * sizeof(*script->steps));
    script->step_count--;
    script->revision++;
    return SCRIPT_OK;
}

script_run_t *script_run_find(const script_store_t *store, uint32_t id) {
    if (!store || !id) return NULL;
    for (size_t i = 0; i < store->run_count; i++) {
        if (store->runs[i]->id == id) return store->runs[i];
    }
    return NULL;
}

static void script_run_free(script_run_t *run) {
    if (!run) return;
    free(run->script.steps);
    free(run->stats);
    free(run->peers);
    free(run);
}

int script_run_create(script_store_t *store, const char *name, uint32_t repeat,
                       uint64_t now_ms, script_run_t **result) {
    bgpsim_script_t *script = script_find(store, name);
    script_run_t    *run;
    if (!store || !result) return SCRIPT_INVALID;
    if (!script) return SCRIPT_NOT_FOUND;
    if (!script->step_count) return SCRIPT_STATE;
    if (store->run_count == SCRIPT_MAX_RUNS || store->last_run_id == UINT32_MAX) return SCRIPT_LIMIT;
    run = calloc(1, sizeof(*run));
    if (!run) return SCRIPT_NOMEM;
    run->script = *script;
    run->script.steps = malloc(script->step_count * sizeof(*script->steps));
    run->stats = calloc(script->step_count, sizeof(*run->stats));
    if (!run->script.steps || !run->stats) {
        script_run_free(run);
        return SCRIPT_NOMEM;
    }
    memcpy(run->script.steps, script->steps, script->step_count * sizeof(*script->steps));
    run->id = ++store->last_run_id;
    run->repeat = repeat;
    run->created_ms = now_ms;
    run->updated_ms = now_ms;
    store->runs[store->run_count++] = run;
    *result = run;
    return SCRIPT_OK;
}

int script_run_remove(script_store_t *store, uint32_t id) {
    if (!store) return SCRIPT_INVALID;
    for (size_t i = 0; i < store->run_count; i++) {
        script_run_t *run = store->runs[i];
        if (run->id != id) continue;
        if (run->state == RUN_PENDING || run->state == RUN_RUNNING) return SCRIPT_STATE;
        script_run_free(run);
        memmove(store->runs + i, store->runs + i + 1, (store->run_count - i - 1) * sizeof(*store->runs));
        store->runs[--store->run_count] = NULL;
        return SCRIPT_OK;
    }
    return SCRIPT_NOT_FOUND;
}

void script_store_destroy(script_store_t *store) {
    if (!store) return;
    for (size_t i = 0; i < store->script_count; i++) script_free(store->scripts[i]);
    for (size_t i = 0; i < store->run_count; i++) script_run_free(store->runs[i]);
    memset(store, 0, sizeof(*store));
}

uint64_t script_now_ms(void) {
    struct timespec now;

    clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
}

static int run_observation_valid(const script_run_t *run, uint64_t now_ms) {
    return run && run->state == RUN_RUNNING && now_ms >= run->updated_ms;
}

static void run_begin_step(script_run_t *run, uint64_t now_ms) {
    free(run->peers);
    run->peers = NULL;
    run->peer_count = 0;
    memset(run->current_ms, 0, sizeof(run->current_ms));
    run->phase = run->script.steps[run->step_index].action == SCRIPT_SLEEP ? RUN_PHASE_SLEEP : RUN_PHASE_PREPARE;
    run->phase_started_ms = now_ms;
    run->updated_ms = now_ms;
}

int script_run_start(script_run_t *run, uint64_t now_ms) {
    if (!run || run->state != RUN_PENDING || now_ms < run->updated_ms) return SCRIPT_STATE;
    run->state = RUN_RUNNING;
    run->iteration = 1;
    run_begin_step(run, now_ms);
    return SCRIPT_OK;
}

int script_run_set_peers(script_run_t *run, const script_peer_plan_t *peers, size_t count, uint64_t now_ms) {
    script_peer_progress_t *progress;
    uint64_t                total_messages = 0, total_bytes = 0;
    if (!run_observation_valid(run, now_ms) || run->phase != RUN_PHASE_PREPARE || run->peers)
        return SCRIPT_STATE;
    // The router registry uses int counts; observations grow with the selected peers, not a separate fixed cap.
    if (!peers || !count || count > INT_MAX) return SCRIPT_INVALID;
    const script_step_t *step = &run->script.steps[run->step_index];
    if (strcmp(step->peer, "all") != 0 && count != 1) return SCRIPT_INVALID;
    progress = calloc(count, sizeof(*progress));
    if (!progress) return SCRIPT_NOMEM;
    for (size_t i = 0; i < count; i++) {
        progress[i].plan = peers[i];
        script_peer_plan_t *target = &progress[i].plan;
        int                 planned = peers[i].status == SCRIPT_PEER_PLANNED;
        if (!memchr(peers[i].peer, 0, sizeof(peers[i].peer)) ||
            !memchr(peers[i].reason, 0, sizeof(peers[i].reason)) || peers[i].status > SCRIPT_PEER_SKIPPED ||
            (!planned && (peers[i].messages_total || peers[i].bytes_total || !peers[i].reason[0])) ||
            !peers[i].router_as || (planned && !peers[i].export_version) ||
            canonical_ip_address(peers[i].peer, target->peer, sizeof(target->peer)) < 0 ||
            total_messages > UINT64_MAX - peers[i].messages_total ||
            total_bytes > UINT64_MAX - peers[i].bytes_total ||
            (!peers[i].messages_total != !peers[i].bytes_total) ||
            (step->router_as && step->router_as != target->router_as) ||
            (strcmp(step->peer, "all") != 0 && strcmp(step->peer, target->peer) != 0)) {
            free(progress);
            return SCRIPT_INVALID;
        }
        total_messages += peers[i].messages_total;
        total_bytes += peers[i].bytes_total;
        for (size_t j = 0; j < i; j++) {
            const script_peer_plan_t *previous = &progress[j].plan;
            if (previous->router_as == target->router_as && strcmp(previous->peer, target->peer) == 0) {
                free(progress);
                return SCRIPT_INVALID;
            }
        }
    }
    run->peers = progress;
    run->peer_count = count;
    run->updated_ms = now_ms;
    return SCRIPT_OK;
}

int script_run_set_phase(script_run_t *run, script_run_phase_t phase, uint64_t now_ms) {
    if (!run_observation_valid(run, now_ms)) return SCRIPT_STATE;
    if (!((run->phase == RUN_PHASE_PREPARE && phase == RUN_PHASE_QUEUE && run->peer_count) ||
          (run->phase == RUN_PHASE_QUEUE && phase == RUN_PHASE_TRANSMIT))) return SCRIPT_STATE;
    run->current_ms[run->phase] += now_ms - run->phase_started_ms;
    run->phase = phase;
    run->phase_started_ms = run->updated_ms = now_ms;
    if (phase == RUN_PHASE_TRANSMIT) {
        for (size_t i = 0; i < run->peer_count; i++) {
            if (!run->peers[i].plan.messages_total) {
                run->peers[i].complete = 1;
                run->peers[i].finished_ms = now_ms;
            }
        }
    }
    return SCRIPT_OK;
}

int script_run_peer_start(script_run_t *run, size_t peer_index, uint64_t now_ms) {
    if (!run_observation_valid(run, now_ms) || run->phase != RUN_PHASE_TRANSMIT) return SCRIPT_STATE;
    if (peer_index >= run->peer_count) return SCRIPT_INVALID;
    script_peer_progress_t *peer = &run->peers[peer_index];
    if (peer->started || peer->complete) return SCRIPT_STATE;
    peer->started = 1;
    peer->started_ms = now_ms;
    run->updated_ms = now_ms;
    return SCRIPT_OK;
}

int script_run_tx_progress(script_run_t *run, size_t peer_index, uint64_t messages, uint64_t bytes, uint64_t now_ms) {
    script_peer_progress_t *peer;
    if (!run_observation_valid(run, now_ms) || run->phase != RUN_PHASE_TRANSMIT) return SCRIPT_STATE;
    if (peer_index >= run->peer_count) return SCRIPT_INVALID;
    peer = &run->peers[peer_index];
    if (!peer->started) return SCRIPT_STATE;
    if (messages < peer->messages_done || messages > peer->plan.messages_total ||
        bytes < peer->bytes_done || bytes > peer->plan.bytes_total ||
        ((messages == peer->plan.messages_total) != (bytes == peer->plan.bytes_total))) return SCRIPT_INVALID;
    peer->messages_done = messages;
    peer->bytes_done = bytes;
    if (!peer->complete && messages == peer->plan.messages_total) {
        peer->complete = 1;
        peer->finished_ms = now_ms;
    }
    run->updated_ms = now_ms;
    return SCRIPT_OK;
}

static uint64_t saturated_add(uint64_t a, uint64_t b) {
    return a > UINT64_MAX - b ? UINT64_MAX : a + b;
}

static void run_record_step(script_run_t *run) {
    script_step_stats_t *stats = &run->stats[run->step_index];
    for (int i = RUN_PHASE_PREPARE; i < RUN_PHASE_COUNT; i++) {
        script_timing_t *timing = &stats->phases[i];
        if ((run->phase == RUN_PHASE_SLEEP) != (i == RUN_PHASE_SLEEP)) continue;
        if (!timing->samples || run->current_ms[i] < timing->min_ms) timing->min_ms = run->current_ms[i];
        if (run->current_ms[i] > timing->max_ms) timing->max_ms = run->current_ms[i];
        timing->total_ms = saturated_add(timing->total_ms, run->current_ms[i]);
        timing->samples = saturated_add(timing->samples, 1);
    }
}

int script_run_finish_step(script_run_t *run, uint64_t now_ms) {
    if (!run_observation_valid(run, now_ms)) return SCRIPT_STATE;
    if (run->phase == RUN_PHASE_SLEEP) {
        if (now_ms - run->phase_started_ms < run->script.steps[run->step_index].sleep_ms) return SCRIPT_STATE;
    } else if (run->phase == RUN_PHASE_TRANSMIT) {
        for (size_t i = 0; i < run->peer_count; i++) {
            if (!run->peers[i].complete) return SCRIPT_STATE;
        }
    } else return SCRIPT_STATE;
    if (run->step_index + 1 == run->script.step_count && run->iteration == UINT64_MAX && !run->repeat)
        return SCRIPT_LIMIT;
    run->current_ms[run->phase] = script_run_phase_elapsed(run, now_ms);
    run_record_step(run);
    run->updated_ms = now_ms;
    if (run->step_index + 1 == run->script.step_count) {
        if (run->repeat && run->iteration == run->repeat) {
            run->state = RUN_COMPLETE;
            run->finished_ms = now_ms;
            return SCRIPT_OK;
        }
        run->iteration++;
        run->step_index = 0;
    } else run->step_index++;
    run_begin_step(run, now_ms);
    return SCRIPT_OK;
}

static int run_stop(script_run_t *run, script_run_state_t state, uint64_t now_ms) {
    if (!run || (run->state != RUN_RUNNING && run->state != RUN_PENDING) || now_ms < run->updated_ms)
        return SCRIPT_STATE;
    if (run->state == RUN_RUNNING) run->current_ms[run->phase] = script_run_phase_elapsed(run, now_ms);
    run->state = state;
    run->finished_ms = run->updated_ms = now_ms;
    return SCRIPT_OK;
}

int script_run_fail(script_run_t *run, const char *reason, uint64_t now_ms) {
    int result;
    if (!reason || !*reason || strlen(reason) >= sizeof(run->error)) return SCRIPT_INVALID;
    result = run_stop(run, RUN_FAILED, now_ms);
    if (result == SCRIPT_OK) snprintf(run->error, sizeof(run->error), "%s", reason);
    return result;
}

int script_run_cancel(script_run_t *run, uint64_t now_ms) {
    if (run && run->state == RUN_CANCELLED) return SCRIPT_OK;
    return run_stop(run, RUN_CANCELLED, now_ms);
}

uint64_t script_run_phase_elapsed(const script_run_t *run, uint64_t now_ms) {
    if (!run || run->phase == RUN_PHASE_NONE) return 0;
    if (run->state != RUN_RUNNING) return run->current_ms[run->phase];
    if (now_ms < run->updated_ms) now_ms = run->updated_ms;
    /*
     * A delayed step-transition observation must not extend TX time past
     * the final successful write completion. A following sleep starts only
     * when the step transition is actually observed.
     */
    if (run->phase == RUN_PHASE_TRANSMIT && run->peer_count) {
        uint64_t finished = run->phase_started_ms;
        int      complete = 1;
        for (size_t i = 0; i < run->peer_count; i++) {
            complete &= run->peers[i].complete;
            if (run->peers[i].finished_ms > finished) finished = run->peers[i].finished_ms;
        }
        if (complete) now_ms = finished;
    }
    return now_ms >= run->phase_started_ms ? now_ms - run->phase_started_ms : 0;
}

uint64_t script_run_elapsed(const script_run_t *run, uint64_t now_ms) {
    uint64_t end;
    if (!run) return 0;
    end = run->state == RUN_PENDING || run->state == RUN_RUNNING ?
          (now_ms < run->updated_ms ? run->updated_ms : now_ms) : run->finished_ms;
    return end >= run->created_ms ? end - run->created_ms : 0;
}

uint64_t script_run_peer_elapsed(const script_run_t *run, size_t peer_index, uint64_t now_ms) {
    if (!run || peer_index >= run->peer_count) return 0;
    const script_peer_progress_t *peer = &run->peers[peer_index];
    if (!peer->started) return 0;
    uint64_t end = now_ms < run->updated_ms ? run->updated_ms : now_ms;
    if (peer->complete) end = peer->finished_ms;
    else if (run->state != RUN_RUNNING) end = run->finished_ms;
    return end >= peer->started_ms ? end - peer->started_ms : 0;
}
