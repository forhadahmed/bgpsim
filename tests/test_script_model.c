#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include "script.h"
#include "test_result.h"

static uint32_t test_seed;
#define CHECK(expr) do {                                                                                      \
    if (!(expr)) { fprintf(stderr, "%s:%d: %s (seed %u)\n", __FILE__, __LINE__, #expr, test_seed); exit(1); } \
} while (0)

static bgpsim_script_t *make_script(script_store_t *store, const char *name) {
    bgpsim_script_t *script = NULL;
    CHECK(script_create(store, name, &script) == SCRIPT_OK);
    return script;
}

static void append_action(bgpsim_script_t *script, script_action_t action) {
    script_step_t step;
    CHECK(script_step_action(&step, action, "blue", "all", 65001) == SCRIPT_OK);
    CHECK(script_append(script, &step) == SCRIPT_OK);
}

static void append_sleep(bgpsim_script_t *script, const char *duration) {
    script_step_t step;
    CHECK(script_step_sleep(&step, duration) == SCRIPT_OK);
    CHECK(script_append(script, &step) == SCRIPT_OK);
}

static script_run_t *make_run(script_store_t *store, uint32_t repeat) {
    script_run_t *run = NULL;
    CHECK(script_run_create(store, "churn", repeat, 100, &run) == SCRIPT_OK);
    return run;
}

static void test_step_validation(void) {
    script_step_t step, original;
    uint64_t ms = 17;
    const char *invalid[] = {"", "-1", "+1", "1.5s", "1msx", "1 s", "2d", "18446744073709551616ms",
                              "18446744073709552s"};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(*invalid); i++) {
        CHECK(script_parse_duration(invalid[i], &ms) == SCRIPT_INVALID && ms == 17);
    }
    CHECK(script_parse_duration("30", &ms) == SCRIPT_OK && ms == 30000);
    CHECK(script_parse_duration("0ms", &ms) == SCRIPT_OK && ms == 0);
    CHECK(script_parse_duration("2m", &ms) == SCRIPT_OK && ms == 120000);
    CHECK(script_parse_duration("1h", &ms) == SCRIPT_OK && ms == 3600000);
    CHECK(script_parse_duration("18446744073709551615ms", &ms) == SCRIPT_OK && ms == UINT64_MAX);
    CHECK(script_step_action(&step, SCRIPT_REPLAY, "blue.v4", "2001:0db8:0:0::1", 65001) == SCRIPT_OK);
    CHECK(strcmp(step.peer, "2001:db8::1") == 0);
    original = step;
    CHECK(script_step_action(&step, SCRIPT_SLEEP, "blue", "all", 0) == SCRIPT_INVALID);
    CHECK(script_step_action(&step, SCRIPT_ADVERTISE, "bad name", "all", 0) == SCRIPT_INVALID);
    CHECK(script_step_action(&step, SCRIPT_ADVERTISE, "blue", "not-an-ip", 0) == SCRIPT_INVALID);
    CHECK(memcmp(&step, &original, sizeof(step)) == 0);
    CHECK(!script_name_valid(""));
    CHECK(!script_name_valid("bad;name"));
    char formatted[256];
    script_format_step(&step, formatted, sizeof(formatted));
    CHECK(strcmp(formatted, "replay ribout blue.v4 peer 2001:db8::1 router 65001") == 0);
    test_result(1, "Strict durations, canonical targets and failure-atomic step validation");
}

static void test_definition_and_snapshot(void) {
    script_store_t   store = {0};
    bgpsim_script_t *script = make_script(&store, "churn");
    script_run_t    *run;
    CHECK(script_run_create(&store, "churn", 1, 100, &run) == SCRIPT_STATE);
    append_action(script, SCRIPT_ADVERTISE);
    append_sleep(script, "30s");
    run = make_run(&store, 100);
    CHECK(run->state == RUN_PENDING && run->phase == RUN_PHASE_NONE && run->iteration == 0);
    CHECK(run->repeat == 100 && run->script.step_count == 2 && run->script.revision == 2);
    CHECK(run->script.steps != script->steps);
    CHECK(script_remove_step(script, 0) == SCRIPT_OK);
    CHECK(script->steps[0].action == SCRIPT_SLEEP && run->script.steps[0].action == SCRIPT_ADVERTISE);
    CHECK(script_remove(&store, "churn") == SCRIPT_OK);
    CHECK(script_find(&store, "churn") == NULL && strcmp(run->script.name, "churn") == 0);
    CHECK(script_run_start(run, 110) == SCRIPT_OK);
    CHECK(run->phase == RUN_PHASE_PREPARE && run->script.steps[1].sleep_ms == 30000);
    CHECK(script_run_cancel(run, 111) == SCRIPT_OK);
    CHECK(script_run_remove(&store, run->id) == SCRIPT_OK);
    CHECK(store.run_count == 0);
    script_store_destroy(&store);
    test_result(1, "Run snapshots survive definition edits and deletion without executing");
}

static script_peer_plan_t plan(const char *ip) {
    script_peer_plan_t peer = {.router_as = 65001, .export_version = 3, .messages_total = 600, .bytes_total = 2400};
    snprintf(peer.peer, sizeof(peer.peer), "%s", ip);
    return peer;
}

/*
 * The mock submits observations, not sleeps or network calls. These times
 * distinguish first submission from completion and force a slow second peer.
 */
static void mock_tx(script_run_t *run, uint64_t start) {
    script_peer_plan_t peers[] = {plan("192.0.2.2"), plan("192.0.2.3")};
    CHECK(run->phase == RUN_PHASE_PREPARE);
    CHECK(script_run_set_peers(run, peers, 2, start + 12) == SCRIPT_OK);
    CHECK(script_run_set_phase(run, RUN_PHASE_QUEUE, start + 12) == SCRIPT_OK);
    CHECK(script_run_set_phase(run, RUN_PHASE_TRANSMIT, start + 15) == SCRIPT_OK);
    CHECK(script_run_peer_start(run, 0, start + 15) == SCRIPT_OK);
    CHECK(script_run_peer_start(run, 1, start + 25) == SCRIPT_OK);
    CHECK(script_run_tx_progress(run, 0, 600, 2400, start + 1115) == SCRIPT_OK);
    CHECK(script_run_tx_progress(run, 1, 220, 800, start + 1815) == SCRIPT_OK);
    CHECK(script_run_finish_step(run, start + 1815) == SCRIPT_STATE);
    CHECK(run->step_index == 0 || run->script.steps[run->step_index].action != SCRIPT_SLEEP);
    CHECK(script_run_tx_progress(run, 1, 600, 2400, start + 2015) == SCRIPT_OK);
    CHECK(run->peers[0].finished_ms - run->peers[0].started_ms == 1100);
    CHECK(run->peers[1].finished_ms - run->peers[1].started_ms == 1990);
    CHECK(script_run_finish_step(run, start + 2015) == SCRIPT_OK);
}

static void test_mock_cycle_timings(void) {
    script_store_t   store = {0};
    bgpsim_script_t *script = make_script(&store, "churn");
    append_action(script, SCRIPT_ADVERTISE);
    append_sleep(script, "30s");
    append_action(script, SCRIPT_WITHDRAW);
    append_sleep(script, "5s");
    script_run_t *run = make_run(&store, 2);
    CHECK(script_run_start(run, 100) == SCRIPT_OK);
    uint64_t now = 100;
    for (unsigned i = 0; i < 2; i++) {
        CHECK(run->iteration == i + 1);
        mock_tx(run, now);
        now += 2015;
        CHECK(run->phase == RUN_PHASE_SLEEP && run->phase_started_ms == now);
        CHECK(script_run_finish_step(run, now + 29999) == SCRIPT_STATE);
        now += 30000;
        CHECK(script_run_finish_step(run, now) == SCRIPT_OK);
        mock_tx(run, now);
        now += 2015 + 5000;
        CHECK(script_run_finish_step(run, now) == SCRIPT_OK);
    }
    CHECK(run->state == RUN_COMPLETE && run->iteration == 2);
    CHECK(run->stats[0].phases[RUN_PHASE_PREPARE].samples == 2);
    CHECK(run->stats[0].phases[RUN_PHASE_QUEUE].total_ms == 6);
    CHECK(run->stats[0].phases[RUN_PHASE_TRANSMIT].total_ms == 4000);
    CHECK(run->stats[0].phases[RUN_PHASE_TRANSMIT].min_ms == 2000);
    CHECK(run->stats[2].phases[RUN_PHASE_TRANSMIT].samples == 2);
    CHECK(run->stats[1].phases[RUN_PHASE_SLEEP].total_ms == 60000);
    CHECK(script_run_elapsed(run, now + 100000) == now - 100);
    CHECK(script_run_phase_elapsed(run, now + 100000) == 5000);
    CHECK(script_run_start(run, now) == SCRIPT_STATE);
    script_store_destroy(&store);
    test_result(1, "Mock advertise/sleep/withdraw cycles await every peer and record exact phase timings");
}

static void test_invalid_observations(void) {
    script_store_t store = {0};
    append_action(make_script(&store, "churn"), SCRIPT_ADVERTISE);
    script_run_t *run = make_run(&store, 1);
    script_peer_plan_t peers[] = {plan("192.0.2.2"), plan("192.0.2.2")};
    CHECK(script_run_start(run, 99) == SCRIPT_STATE);
    CHECK(script_run_set_phase(run, RUN_PHASE_TRANSMIT, 100) == SCRIPT_STATE);
    CHECK(script_run_start(run, 100) == SCRIPT_OK);
    CHECK(script_run_set_peers(run, peers, 0, 100) == SCRIPT_INVALID);
    CHECK(script_run_set_peers(run, peers, 2, 100) == SCRIPT_INVALID);
    peers[0].router_as = 65002;
    CHECK(script_run_set_peers(run, peers, 1, 100) == SCRIPT_INVALID);
    peers[0].router_as = 65001;
    CHECK(script_run_set_peers(run, peers, 1, 100) == SCRIPT_OK);
    CHECK(script_run_set_peers(run, peers, 1, 100) == SCRIPT_STATE);
    CHECK(script_run_set_phase(run, RUN_PHASE_TRANSMIT, 100) == SCRIPT_STATE);
    CHECK(script_run_set_phase(run, RUN_PHASE_QUEUE, 110) == SCRIPT_OK);
    CHECK(script_run_set_phase(run, RUN_PHASE_TRANSMIT, 109) == SCRIPT_STATE);
    CHECK(script_run_set_phase(run, RUN_PHASE_TRANSMIT, 112) == SCRIPT_OK);
    CHECK(script_run_tx_progress(run, 0, 1, 4, 113) == SCRIPT_STATE);
    CHECK(script_run_peer_start(run, 0, 113) == SCRIPT_OK);
    CHECK(script_run_peer_start(run, 0, 113) == SCRIPT_STATE);
    CHECK(script_run_tx_progress(run, 1, 1, 4, 114) == SCRIPT_INVALID);
    CHECK(script_run_tx_progress(run, 0, 601, 2400, 114) == SCRIPT_INVALID);
    CHECK(script_run_tx_progress(run, 0, 600, 2399, 114) == SCRIPT_INVALID);
    CHECK(script_run_tx_progress(run, 0, 100, 400, 114) == SCRIPT_OK);
    CHECK(script_run_tx_progress(run, 0, 99, 396, 115) == SCRIPT_INVALID);
    CHECK(script_run_fail(run, "write timeout", 115) == SCRIPT_OK);
    CHECK(run->state == RUN_FAILED && strcmp(run->error, "write timeout") == 0);
    CHECK(script_run_tx_progress(run, 0, 600, 2400, 116) == SCRIPT_STATE);
    CHECK(script_run_finish_step(run, 116) == SCRIPT_STATE);
    CHECK(run->stats[0].phases[RUN_PHASE_TRANSMIT].samples == 0);
    CHECK(script_run_phase_elapsed(run, 999) == 3);
    script_store_destroy(&store);
    test_result(1, "Invalid/stale TX observations cannot fake completion or successful timing samples");
}

static void test_forever_and_cancel(void) {
    script_store_t store = {0};
    append_sleep(make_script(&store, "churn"), "0ms");
    script_run_t *run = make_run(&store, 0);
    CHECK(script_run_remove(&store, run->id) == SCRIPT_STATE);
    CHECK(script_run_start(run, 100) == SCRIPT_OK);
    script_step_stats_t *stats = run->stats;
    for (unsigned i = 0; i < 10000; i++) CHECK(script_run_finish_step(run, 100 + i) == SCRIPT_OK);
    CHECK(run->state == RUN_RUNNING && run->iteration == 10001 && run->stats == stats);
    CHECK(run->peer_count == 0 && run->stats[0].phases[RUN_PHASE_SLEEP].samples == 10000);
    CHECK(script_run_cancel(run, 10100) == SCRIPT_OK);
    CHECK(script_run_cancel(run, 10101) == SCRIPT_OK);
    CHECK(script_run_finish_step(run, 10102) == SCRIPT_STATE);
    CHECK(script_run_elapsed(run, 999999) == 10000);
    CHECK(script_run_remove(&store, run->id) == SCRIPT_OK);
    run = make_run(&store, 1);
    CHECK(run->id == 2 && script_run_cancel(run, 100) == SCRIPT_OK);
    CHECK(script_run_start(run, 100) == SCRIPT_STATE);
    script_store_destroy(&store);
    test_result(1, "Forever runs use bounded storage; cancellation is terminal and IDs are not reused");
}

static void test_limits(void) {
    script_store_t   store = {0};
    bgpsim_script_t *script = make_script(&store, "churn"), *unused;
    script_step_t    step;
    CHECK(script_step_sleep(&step, "1ms") == SCRIPT_OK);
    for (unsigned i = 0; i < SCRIPT_MAX_STEPS; i++) CHECK(script_append(script, &step) == SCRIPT_OK);
    CHECK(script_append(script, &step) == SCRIPT_LIMIT && script->step_count == SCRIPT_MAX_STEPS);
    for (unsigned i = 1; i < SCRIPT_MAX_SCRIPTS; i++) {
        char name[64];
        snprintf(name, sizeof(name), "script-%u", i);
        make_script(&store, name);
    }
    CHECK(script_create(&store, "overflow", &unused) == SCRIPT_LIMIT);
    CHECK(script_create(&store, "churn", &unused) == SCRIPT_OK && unused == script);
    for (unsigned i = 0; i < SCRIPT_MAX_RUNS; i++) make_run(&store, 1);
    script_run_t *run = NULL;
    CHECK(script_run_create(&store, "churn", 1, 100, &run) == SCRIPT_LIMIT);
    CHECK(script_run_cancel(store.runs[0], 100) == SCRIPT_OK);
    CHECK(script_run_remove(&store, store.runs[0]->id) == SCRIPT_OK);
    run = make_run(&store, 1);
    CHECK(run->id == SCRIPT_MAX_RUNS + 1);
    CHECK(script_run_remove(&store, 0) == SCRIPT_NOT_FOUND);
    script_store_destroy(&store);
    CHECK(store.run_count == 0 && store.script_count == 0);
    test_result(1, "Script, step and run capacities are bounded and terminal records can be cleared");
}

static void test_tx_completion_boundary(void) {
    script_store_t store = {0};
    append_action(make_script(&store, "churn"), SCRIPT_REPLAY);
    script_run_t      *run = make_run(&store, 1);
    script_peer_plan_t peer = plan("192.0.2.2");
    CHECK(script_run_start(run, 100) == SCRIPT_OK);
    CHECK(script_run_set_peers(run, &peer, 1, 101) == SCRIPT_OK);
    CHECK(script_run_set_phase(run, RUN_PHASE_QUEUE, 101) == SCRIPT_OK);
    CHECK(script_run_set_phase(run, RUN_PHASE_TRANSMIT, 102) == SCRIPT_OK);
    CHECK(script_run_peer_start(run, 0, 102) == SCRIPT_OK);
    CHECK(script_run_tx_progress(run, 0, 300, 1200, 105) == SCRIPT_OK);
    CHECK(script_run_peer_elapsed(run, 0, 100) == 3);
    CHECK(script_run_tx_progress(run, 0, 600, 2400, 110) == SCRIPT_OK);
    CHECK(script_run_phase_elapsed(run, 500) == 8);
    CHECK(script_run_peer_elapsed(run, 0, 500) == 8);
    CHECK(script_run_finish_step(run, 500) == SCRIPT_OK);
    CHECK(run->state == RUN_COMPLETE && run->stats[0].phases[RUN_PHASE_TRANSMIT].total_ms == 8);
    CHECK(script_run_phase_elapsed(run, 900) == 8);
    CHECK(script_run_peer_elapsed(run, 0, 900) == 8);
    CHECK(script_run_cancel(run, 901) == SCRIPT_STATE);
    script_store_destroy(&store);
    test_result(1, "TX timing ends at last write completion, not delayed step bookkeeping");
}

static void test_peer_plan_boundaries(void) {
    script_store_t   store = {0};
    bgpsim_script_t *script = make_script(&store, "churn");
    script_step_t    step;
    CHECK(script_step_action(&step, SCRIPT_WITHDRAW, "blue", "2001:db8::1", 65001) == SCRIPT_OK);
    CHECK(script_append(script, &step) == SCRIPT_OK);
    script_run_t *run = make_run(&store, 1);
    CHECK(script_run_start(run, 100) == SCRIPT_OK);
    script_peer_plan_t peer = plan("192.0.2.2");
    CHECK(script_run_set_peers(run, &peer, 1, 100) == SCRIPT_INVALID);
    snprintf(peer.peer, sizeof(peer.peer), "2001:0db8:0:0::1");
    CHECK(script_run_set_peers(run, &peer, 1, 100) == SCRIPT_OK);
    CHECK(strcmp(run->peers[0].plan.peer, "2001:db8::1") == 0);
    script_store_destroy(&store);

    append_action(make_script(&store, "churn"), SCRIPT_ADVERTISE);
    run = make_run(&store, 1);
    CHECK(script_run_start(run, 100) == SCRIPT_OK);
    script_peer_plan_t peers[] = {plan("192.0.2.2"), plan("192.0.2.3")};
    memset(peers[0].peer, 'a', sizeof(peers[0].peer));
    CHECK(script_run_set_peers(run, peers, 1, 100) == SCRIPT_INVALID);
    CHECK(run->peers == NULL && run->peer_count == 0);
    peers[0] = plan("192.0.2.2");
    CHECK(script_run_set_peers(run, peers, (size_t)INT_MAX + 1, 100) == SCRIPT_INVALID);
    peers[0].bytes_total = UINT64_MAX;
    CHECK(script_run_set_peers(run, peers, 2, 100) == SCRIPT_INVALID);
    peers[0] = plan("all");
    CHECK(script_run_set_peers(run, peers, 1, 100) == SCRIPT_INVALID);
    peers[0] = plan("192.0.2.2");
    peers[0].messages_total = 0;
    peers[0].bytes_total = 0;
    CHECK(script_run_set_peers(run, peers, 1, 100) == SCRIPT_OK);
    CHECK(script_run_set_phase(run, RUN_PHASE_QUEUE, 100) == SCRIPT_OK);
    CHECK(script_run_set_phase(run, RUN_PHASE_TRANSMIT, 100) == SCRIPT_OK);
    CHECK(script_run_finish_step(run, 101) == SCRIPT_OK);
    CHECK(run->stats[0].phases[RUN_PHASE_TRANSMIT].total_ms == 0);
    script_store_destroy(&store);
    test_result(1, "Resolved peer plans enforce target scope, canonical identities, counter bounds and no-op TX");
}

static void test_withheld_and_skipped_peers(void) {
    script_store_t store = {0};
    append_action(make_script(&store, "churn"), SCRIPT_ADVERTISE);
    script_run_t *run = make_run(&store, 1);
    script_peer_plan_t peers[] = {plan("192.0.2.2"), plan("192.0.2.3"), plan("192.0.2.4")};

    CHECK(script_run_start(run, 100) == SCRIPT_OK);
    peers[1].status = SCRIPT_PEER_WITHHELD;
    peers[1].export_version = 0;
    peers[1].messages_total = peers[1].bytes_total = 0;
    CHECK(script_run_set_peers(run, peers, 2, 100) == SCRIPT_INVALID);  /* A withheld peer needs its reason */
    snprintf(peers[1].reason, sizeof(peers[1].reason), "4-octet AS not negotiated (AS_PATH is 4-octet)");
    peers[2].status = SCRIPT_PEER_SKIPPED;
    snprintf(peers[2].reason, sizeof(peers[2].reason), "session not established");
    CHECK(script_run_set_peers(run, peers, 3, 100) == SCRIPT_INVALID);  /* A skipped peer sends nothing     */
    peers[2].export_version = 0;
    peers[2].messages_total = peers[2].bytes_total = 0;
    CHECK(script_run_set_peers(run, peers, 3, 100) == SCRIPT_OK);
    CHECK(script_run_set_phase(run, RUN_PHASE_QUEUE, 101) == SCRIPT_OK);
    CHECK(script_run_set_phase(run, RUN_PHASE_TRANSMIT, 102) == SCRIPT_OK);
    CHECK(!run->peers[0].complete && run->peers[1].complete && run->peers[2].complete);
    CHECK(script_run_finish_step(run, 103) == SCRIPT_STATE);
    CHECK(script_run_peer_start(run, 0, 103) == SCRIPT_OK);
    CHECK(script_run_tx_progress(run, 0, 600, 2400, 110) == SCRIPT_OK);
    CHECK(script_run_finish_step(run, 111) == SCRIPT_OK && run->state == RUN_COMPLETE);
    script_store_destroy(&store);

    append_action(make_script(&store, "churn"), SCRIPT_ADVERTISE);
    run = make_run(&store, 2);
    peers[0].status = SCRIPT_PEER_WITHHELD;
    peers[0].export_version = 0;
    peers[0].messages_total = peers[0].bytes_total = 0;
    snprintf(peers[0].reason, sizeof(peers[0].reason), "IPv6 Unicast not negotiated");
    CHECK(script_run_start(run, 100) == SCRIPT_OK);
    CHECK(script_run_set_peers(run, peers, 1, 100) == SCRIPT_OK);
    CHECK(script_run_set_phase(run, RUN_PHASE_QUEUE, 100) == SCRIPT_OK);
    CHECK(script_run_set_phase(run, RUN_PHASE_TRANSMIT, 100) == SCRIPT_OK);
    CHECK(script_run_finish_step(run, 100) == SCRIPT_OK && run->iteration == 2 && run->phase == RUN_PHASE_PREPARE);
    script_store_destroy(&store);
    test_result(1, "Withheld and skipped peers carry a reason, send nothing, and complete with the step");
}

static void test_counter_boundaries(void) {
    script_store_t   store = {0};
    bgpsim_script_t *script = make_script(&store, "churn");
    append_sleep(script, "0ms");
    script_step_t step = {.action = SCRIPT_SLEEP};
    script->revision = UINT64_MAX;
    CHECK(script_append(script, &step) == SCRIPT_LIMIT && script->step_count == 1);
    CHECK(script_remove_step(script, 0) == SCRIPT_LIMIT && script->step_count == 1);
    script_run_t *run = make_run(&store, 0);
    CHECK(script_run_start(run, 100) == SCRIPT_OK);
    CHECK(script_run_finish_step(run, 110) == SCRIPT_OK);
    CHECK(script_run_finish_step(run, 115) == SCRIPT_OK);
    CHECK(run->stats[0].phases[RUN_PHASE_SLEEP].min_ms == 5);
    CHECK(run->stats[0].phases[RUN_PHASE_SLEEP].max_ms == 10);
    CHECK(run->stats[0].phases[RUN_PHASE_SLEEP].total_ms == 15);
    run->iteration = UINT64_MAX;
    CHECK(script_run_finish_step(run, 120) == SCRIPT_LIMIT);
    CHECK(run->iteration == UINT64_MAX && run->stats[0].phases[RUN_PHASE_SLEEP].samples == 2);
    CHECK(script_run_cancel(run, 120) == SCRIPT_OK);
    CHECK(script_run_remove(&store, run->id) == SCRIPT_OK);
    store.last_run_id = UINT32_MAX;
    CHECK(script_run_create(&store, "churn", 1, 100, &run) == SCRIPT_LIMIT && store.run_count == 0);
    script_store_destroy(&store);
    test_result(1, "Timing extrema are exact and revision, iteration and run-ID counters cannot wrap");
}

static uint32_t next_random(uint32_t *state) {
    *state ^= *state << 13;
    *state ^= *state >> 17;
    *state ^= *state << 5;
    return *state;
}

/*
 * A linear reference schedule owns its own step/iteration and timing totals.
 * Only public operations drive the model; peer completion order varies by seed.
 * Cancellation/failure and definition deletion must not resurrect a frozen run.
 */
static void test_seeded_schedules(void) {
    for (test_seed = 1; test_seed <= 96; test_seed++) {
        uint32_t         random = test_seed;
        script_store_t   store = {0};
        bgpsim_script_t *script = make_script(&store, "churn");
        uint64_t         sleeps[8] = {0}, totals[8][RUN_PHASE_COUNT] = {{0}};
        unsigned         samples[8] = {0};
        for (unsigned step = 0; step < 8; step++) {
            if (step % 2) {
                char duration[32];
                sleeps[step] = 1 + next_random(&random) % 20;
                snprintf(duration, sizeof(duration), "%" PRIu64 "ms", sleeps[step]);
                append_sleep(script, duration);
            } else append_action(script, (script_action_t)((step / 2) % 3));
        }
        unsigned      repeat = 1 + next_random(&random) % 4;
        script_run_t *run = make_run(&store, repeat);
        CHECK(script_remove(&store, "churn") == SCRIPT_OK);
        uint64_t now = 100;
        CHECK(script_run_start(run, now) == SCRIPT_OK);
        unsigned completed = 0;
        unsigned stop_after = test_seed % 3 ? 1 + next_random(&random) % (repeat * 8 - 1) : repeat * 8;
        for (unsigned iteration = 1; iteration <= repeat && completed < stop_after; iteration++) {
            for (unsigned step = 0; step < 8 && completed < stop_after; step++) {
                CHECK(run->state == RUN_RUNNING && run->iteration == iteration && run->step_index == step);
                if (sleeps[step]) {
                    CHECK(script_run_finish_step(run, now + sleeps[step] - 1) == SCRIPT_STATE);
                    now += sleeps[step];
                    totals[step][RUN_PHASE_SLEEP] += sleeps[step];
                } else {
                    script_peer_plan_t peers[] = {plan("192.0.2.2"), plan("192.0.2.3"), plan("192.0.2.4")};
                    uint64_t prepare = 1 + next_random(&random) % 7;
                    uint64_t queue = 1 + next_random(&random) % 7;
                    now += prepare;
                    CHECK(script_run_set_peers(run, peers, 3, now) == SCRIPT_OK);
                    CHECK(script_run_set_phase(run, RUN_PHASE_QUEUE, now) == SCRIPT_OK);
                    now += queue;
                    CHECK(script_run_set_phase(run, RUN_PHASE_TRANSMIT, now) == SCRIPT_OK);
                    uint64_t tx_start = now;
                    for (unsigned peer = 0; peer < 3; peer++) {
                        CHECK(script_run_peer_start(run, peer, now) == SCRIPT_OK);
                        CHECK(script_run_tx_progress(run, peer, 300, 1200, now) == SCRIPT_OK);
                    }
                    unsigned order[] = {0, 1, 2};
                    for (unsigned remaining = 3; remaining > 0; remaining--) {
                        unsigned chosen = next_random(&random) % remaining;
                        unsigned peer = order[chosen];
                        order[chosen] = order[remaining - 1];
                        now += 1 + next_random(&random) % 11;
                        CHECK(script_run_tx_progress(run, peer, 600, 2400, now) == SCRIPT_OK);
                        if (remaining > 1) CHECK(script_run_finish_step(run, now) == SCRIPT_STATE);
                    }
                    totals[step][RUN_PHASE_PREPARE] += prepare;
                    totals[step][RUN_PHASE_QUEUE] += queue;
                    totals[step][RUN_PHASE_TRANSMIT] += now - tx_start;
                    now += next_random(&random) % 5; /* Delayed bookkeeping cannot inflate TX time. */
                }
                CHECK(script_run_finish_step(run, now) == SCRIPT_OK);
                samples[step]++;
                completed++;
            }
        }
        if (completed < repeat * 8) {
            CHECK((test_seed % 3 == 1 ? script_run_cancel(run, now) :
                   script_run_fail(run, "injected write failure", now)) == SCRIPT_OK);
            CHECK(run->state == (test_seed % 3 == 1 ? RUN_CANCELLED : RUN_FAILED));
        } else CHECK(run->state == RUN_COMPLETE);
        for (unsigned step = 0; step < 8; step++) {
            for (unsigned phase = RUN_PHASE_PREPARE; phase < RUN_PHASE_COUNT; phase++) {
                unsigned expected = ((sleeps[step] != 0) == (phase == RUN_PHASE_SLEEP)) ? samples[step] : 0;
                CHECK(run->stats[step].phases[phase].samples == expected);
                CHECK(run->stats[step].phases[phase].total_ms == totals[step][phase]);
            }
        }
        script_run_t frozen = *run;
        CHECK(script_run_start(run, ++now) == SCRIPT_STATE);
        CHECK(script_run_finish_step(run, now) == SCRIPT_STATE);
        CHECK(script_run_tx_progress(run, 0, 600, 2400, now) == SCRIPT_STATE);
        CHECK(memcmp(run, &frozen, sizeof(frozen)) == 0);
        CHECK(script_run_elapsed(run, now + 10000) == frozen.finished_ms - 100);
        CHECK(script_run_remove(&store, run->id) == SCRIPT_OK && store.run_count == 0);
        script_store_destroy(&store);
    }
    test_seed = 0;
    test_result(1, "96 seeded schedules match independent timing/iteration totals and reject terminal callbacks");
}

static void test_peer_observation_scale(void) {
    script_store_t store = {0};
    append_action(make_script(&store, "churn"), SCRIPT_ADVERTISE);
    script_run_t       *run = make_run(&store, 1);
    const size_t        count = 10240;
    script_peer_plan_t *peers = calloc(count, sizeof(*peers));
    CHECK(peers && script_run_start(run, 100) == SCRIPT_OK);
    for (size_t i = 0; i < count; i++) {
        peers[i] = plan("192.0.2.1");
        snprintf(peers[i].peer, sizeof(peers[i].peer), "2001:db8::%x", (unsigned)i + 1);
    }
    CHECK(script_run_set_peers(run, peers, count, 101) == SCRIPT_OK && run->peer_count == count);
    free(peers);
    CHECK(script_run_set_phase(run, RUN_PHASE_QUEUE, 102) == SCRIPT_OK);
    CHECK(script_run_set_phase(run, RUN_PHASE_TRANSMIT, 103) == SCRIPT_OK);
    for (size_t i = 0; i < count; i++) CHECK(script_run_peer_start(run, i, 104) == SCRIPT_OK);
    for (size_t i = 0; i < count; i++) CHECK(script_run_tx_progress(run, i, 600, 2400, 105) == SCRIPT_OK);
    CHECK(script_run_finish_step(run, 106) == SCRIPT_OK && run->state == RUN_COMPLETE &&
          run->peers[count - 1].messages_done == 600 && !strcmp(run->peers[count - 1].plan.peer, "2001:db8::2800"));
    script_store_destroy(&store);
    test_result(1, "Ten times the former peer-observation cap records and completes every peer");
}

int main(void) {
    test_peer_observation_scale();
    test_step_validation();
    test_definition_and_snapshot();
    test_mock_cycle_timings();
    test_invalid_observations();
    test_forever_and_cancel();
    test_limits();
    test_tx_completion_boundary();
    test_peer_plan_boundaries();
    test_withheld_and_skipped_peers();
    test_counter_boundaries();
    test_seeded_schedules();
    return tests_failed ? 1 : 0;
}
