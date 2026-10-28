/*
 * Per-peer TX state machine with fake writes: admission against intended bindings, FIFO order, replacement versus
 * withdraw-then-advertise, overlap rejection, batches and progress, resets with a batch in flight, and references.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "test_case.h"
#include "bgp_ribout.h"
#include "bgp_peer_tx.h"

/*
 * A snapshot from "keyword value" lines with a block that the caller destroys.
 */
static bgp_ribout_snapshot_t *generate(bgp_ribout_config_t *block, const char *name, const char *const *lines) {
    if (bgp_ribout_init(block, name) != 0) {
        return NULL;
    }
    for (; *lines; lines++) {
        char        keyword[32];
        const char *value = strchr(*lines, ' ');

        snprintf(keyword, sizeof(keyword), "%.*s", (int)(value - *lines), *lines);
        if (bgp_ribout_edit(block, keyword, value + 1, 0) != 0) {
            return NULL;
        }
    }
    return bgp_ribout_generate(block) == BGP_RIBOUT_GENERATED ? block->snapshot : NULL;
}

static const char *const k_a[] = {"prefix 10.0.0.0/24 x 10", "next-hop 192.0.2.1", NULL};
static const char *const k_a_attr[] = {"prefix 10.0.0.0/24 x 10", "next-hop 192.0.2.9", "localpref 500", NULL};
static const char *const k_a_more[] = {"prefix 10.0.0.0/24 x 20", "next-hop 192.0.2.1", NULL};
static const char *const k_b[] = {"prefix 10.1.0.0/24 x 10", "next-hop 192.0.2.1", NULL};
static const char *const k_b_overlap[] = {"prefix 10.0.5.0/24 x 10", "next-hop 192.0.2.1", NULL};
static const char *const k_far[] = {"prefix 172.16.0.0/24 x 10", "next-hop 192.0.2.1", NULL};
/*
 * Many attribute groups: one UPDATE per prefix, several batches
 */
static const char *const k_big[] = {"prefix 10.0.0.0/24 x 3000", "next-hop 192.0.2.1", "localpref range(1,3000)",
                                    NULL};

static int request(bgp_peer_tx_t *tx, bgp_tx_op_t op, const char *name, bgp_ribout_snapshot_t *snapshot, char *reason) {
    bgp_tx_request_t req = {.op = op, .name = name, .snapshot = snapshot};
    bgp_tx_plan_t   *plan;

    if (bgp_peer_tx_plan(tx, &req, &plan, reason) != BGP_TX_PLAN_OK) {
        return -1;
    }
    bgp_peer_tx_commit(tx, plan);
    return 0;
}

/*
 * Write everything queued with fake successful writes; record the kind and ribout of each completed job.
 */
typedef struct {
    char   log[512];
    size_t msgs;
    size_t batches;
} drained_t;

static void drain(bgp_peer_tx_t *tx, uint64_t epoch, drained_t *out) {
    memset(out, 0, sizeof(*out));
    while (bgp_peer_tx_fill_batch(tx, epoch, BGP_TX_BATCH_BYTES) > 0) {
        const bgp_tx_job_t   *head = bgp_peer_tx_head(tx);
        char                  entry[64];
        bgp_tx_batch_result_t result;

        snprintf(entry, sizeof(entry), "%s%s%s ",
                 head->kind == BGP_TX_JOB_ADVERTISE ? (head->replay ? "replay:" : "adv:") :
                 head->kind == BGP_TX_JOB_WITHDRAW ? "wd:" : "eor:",
                 head->name,
                 head->kind != BGP_TX_JOB_EOR ? "" : (head->family.afi == 1 && head->family.safi == 1) ? "v4" : "mp");
        bgp_peer_tx_batch_done(tx, epoch, 1, &result);
        out->msgs += result.msgs;
        out->batches++;
        if (result.job_complete) {
            strncat(out->log, entry, sizeof(out->log) - strlen(out->log) - 1);
        }
    }
}

static void test_fifo_and_bindings(void) {
    bgp_ribout_config_t a, b;
    bgp_ribout_snapshot_t *sa = generate(&a, "A", k_a), *sb = generate(&b, "B", k_b);
    bgp_peer_tx_t         *tx = bgp_peer_tx_create();
    char                   reason[BGP_TX_REASON_SIZE];
    drained_t              d;

    TEST("Operations run in admission order; bindings are the state after the queue drains");
    ASSERT(sa && sb && tx, "setup");
    ASSERT(request(tx, BGP_TX_OP_ADVERTISE, "A", sa, reason) == 0, reason);
    ASSERT(request(tx, BGP_TX_OP_ADVERTISE, "B", sb, reason) == 0, reason);
    ASSERT(request(tx, BGP_TX_OP_WITHDRAW, "A", NULL, reason) == 0, reason);
    ASSERT(tx->binding_count == 1 && strcmp(tx->bindings[0].name, "B") == 0, "A unbound at admission");
    ASSERT(bgp_peer_tx_outq(tx) == sa->adv->count + sb->adv->count + 1, "OutQ counts queued messages");
    drain(tx, 1, &d);
    ASSERT(strcmp(d.log, "adv:A adv:B wd:A ") == 0, d.log);
    ASSERT(bgp_peer_tx_outq(tx) == 0 && tx->job_count == 0, "queue drained");
    ASSERT(request(tx, BGP_TX_OP_WITHDRAW, "A", NULL, reason) < 0 && strstr(reason, "not advertised"), reason);
    bgp_peer_tx_destroy(tx);
    ASSERT(sa->refs == 1 && sb->refs == 1 && sa->adv->refs == 1, "only the blocks hold the snapshots");
    bgp_ribout_destroy(&a);
    bgp_ribout_destroy(&b);
    PASS();
}

static void test_replace_or_withdraw(void) {
    bgp_ribout_config_t    block;
    bgp_ribout_snapshot_t *s1 = generate(&block, "X", k_a), *s2, *s3;
    bgp_peer_tx_t         *tx = bgp_peer_tx_create();
    char                   reason[BGP_TX_REASON_SIZE];
    drained_t              d;

    TEST("Same keys replace in place; changed keys withdraw the old snapshot first");
    ASSERT(s1 && tx, "setup");
    bgp_ribout_snapshot_ref(s1);
    ASSERT(request(tx, BGP_TX_OP_ADVERTISE, "X", s1, reason) == 0, reason);
    drain(tx, 1, &d);

    bgp_ribout_destroy(&block);
    s2 = generate(&block, "X", k_a_attr);
    ASSERT(s2 && request(tx, BGP_TX_OP_ADVERTISE, "X", s2, reason) == 0, reason);
    drain(tx, 1, &d);
    ASSERT(strcmp(d.log, "adv:X ") == 0, d.log);
    ASSERT(bgp_peer_tx_binding(tx, "X")->snapshot == s2 && s1->refs == 1, "binding moved to the new snapshot");

    bgp_ribout_snapshot_ref(s2);
    bgp_ribout_destroy(&block);
    s3 = generate(&block, "X", k_a_more);
    ASSERT(s3 && request(tx, BGP_TX_OP_ADVERTISE, "X", s3, reason) == 0, reason);
    drain(tx, 1, &d);
    ASSERT(strcmp(d.log, "wd:X adv:X ") == 0, d.log);
    ASSERT(s2->refs == 1 && s2->withdrawal == NULL, "the old snapshot and its withdrawal are released");

    ASSERT(request(tx, BGP_TX_OP_ADVERTISE, "X", s3, reason) == 0, reason);
    drain(tx, 1, &d);
    ASSERT(strcmp(d.log, "adv:X ") == 0, "advertising the bound snapshot again resends it");

    bgp_peer_tx_destroy(tx);
    bgp_ribout_snapshot_unref(s1);
    bgp_ribout_snapshot_unref(s2);
    bgp_ribout_destroy(&block);
    PASS();
}

static void test_overlap(void) {
    bgp_ribout_config_t a, b, c;
    bgp_ribout_snapshot_t *sa = generate(&a, "A", k_a), *sb = generate(&b, "B", k_b_overlap);
    bgp_ribout_snapshot_t *sc = generate(&c, "C", k_b);
    bgp_peer_tx_t         *tx = bgp_peer_tx_create();
    char                   reason[BGP_TX_REASON_SIZE];

    TEST("Overlapping route keys are rejected against queued and sent bindings");
    ASSERT(sa && sb && sc && tx, "setup");
    ASSERT(request(tx, BGP_TX_OP_ADVERTISE, "A", sa, reason) == 0, reason);
    ASSERT(request(tx, BGP_TX_OP_ADVERTISE, "B", sb, reason) < 0 && strstr(reason, "overlap ribout A"), reason);
    ASSERT(tx->job_count == 1 && tx->binding_count == 1, "nothing queued for the rejected ribout");
    ASSERT(request(tx, BGP_TX_OP_ADVERTISE, "C", sc, reason) == 0, "a disjoint ribout is accepted");
    ASSERT(request(tx, BGP_TX_OP_WITHDRAW, "A", NULL, reason) == 0, reason);
    ASSERT(request(tx, BGP_TX_OP_ADVERTISE, "B", sb, reason) == 0, "accepted once A is withdrawn");
    bgp_peer_tx_destroy(tx);
    bgp_ribout_destroy(&a);
    bgp_ribout_destroy(&b);
    bgp_ribout_destroy(&c);
    PASS();
}

static void test_withdraw_all_and_replay(void) {
    bgp_ribout_config_t a, b;
    bgp_ribout_snapshot_t *sa = generate(&a, "A", k_a), *sb = generate(&b, "B", k_b);
    bgp_peer_tx_t         *tx = bgp_peer_tx_create();
    char                   reason[BGP_TX_REASON_SIZE];
    drained_t              d;

    TEST("Replay needs only the bound snapshot; withdraw all expands to one withdrawal per binding");
    ASSERT(sa && sb && tx, "setup");
    ASSERT(request(tx, BGP_TX_OP_ADVERTISE, "A", sa, reason) == 0, reason);
    ASSERT(request(tx, BGP_TX_OP_ADVERTISE, "B", sb, reason) == 0, reason);
    drain(tx, 1, &d);
    bgp_ribout_destroy(&a);  /* no ribout A: the bound snapshot stays */
    ASSERT(request(tx, BGP_TX_OP_REPLAY, "A", NULL, reason) == 0, reason);
    ASSERT(request(tx, BGP_TX_OP_WITHDRAW_ALL, NULL, NULL, reason) == 0, reason);
    ASSERT(tx->binding_count == 0, "all bindings cleared at admission");
    drain(tx, 1, &d);
    ASSERT(strcmp(d.log, "replay:A wd:A wd:B ") == 0, d.log);
    ASSERT(request(tx, BGP_TX_OP_WITHDRAW_ALL, NULL, NULL, reason) == 0 && tx->job_count == 0,
           "withdraw all with nothing bound queues nothing");
    ASSERT(request(tx, BGP_TX_OP_REPLAY, "A", NULL, reason) < 0, "replay needs a binding");
    bgp_peer_tx_destroy(tx);
    bgp_ribout_destroy(&b);
    PASS();
}

static void test_batches_and_progress(void) {
    bgp_ribout_config_t    block;
    bgp_ribout_snapshot_t *s = generate(&block, "big", k_big);
    bgp_peer_tx_t         *tx = bgp_peer_tx_create();
    bgp_tx_request_t req = {.op = BGP_TX_OP_ADVERTISE, .name = "big", .snapshot = s,
                            .observer = {.run_id = 7, .peer_index = 2, .step_token = 99}};
    bgp_tx_plan_t *plan;
    char           reason[BGP_TX_REASON_SIZE];
    size_t total_msgs, msgs = 0, batches = 0;
    uint64_t total_bytes, bytes = 0;
    int started = 0, completed = 0;

    TEST("Batches send whole messages within the caps; progress is cumulative and observed");
    ASSERT(s && tx && s->adv->count == 3000, "3000 UPDATEs");
    ASSERT(bgp_peer_tx_plan(tx, &req, &plan, reason) == BGP_TX_PLAN_OK, reason);
    bgp_tx_plan_totals(plan, &total_msgs, &total_bytes);
    ASSERT(total_msgs == 3000 && total_bytes == s->adv->bytes, "plan totals");
    bgp_peer_tx_commit(tx, plan);
    while (bgp_peer_tx_fill_batch(tx, 5, 4096) > 0) {
        bgp_tx_batch_result_t result;

        ASSERT(tx->batch.nbufs <= BGP_TX_BATCH_BUFS && (tx->batch.bytes <= 4096 || tx->batch.nbufs == 1),
               "batch within caps");
        ASSERT(bgp_peer_tx_fill_batch(tx, 5, 4096) == 0, "one batch in flight");
        bgp_peer_tx_batch_done(tx, 5, 1, &result);
        msgs += result.msgs;
        bytes += result.bytes;
        batches++;
        started += result.job_started;
        completed += result.job_complete;
        ASSERT(result.observer.run_id == 7 && result.observer.peer_index == 2 &&
               result.observer.step_token == 99 && result.job_msgs == msgs && result.job_bytes == bytes,
               "cumulative observed progress");
    }
    ASSERT(msgs == 3000 && bytes == s->adv->bytes && batches > 1 && started == 1 && completed == 1, "all sent");
    bgp_peer_tx_destroy(tx);
    bgp_ribout_destroy(&block);
    PASS();
}

static int aborted;

static void count_abort(void *ctx, const bgp_tx_observer_t *observer) {
    (void)ctx;
    aborted += observer->run_id == 3;
}

static void test_reset_with_batch_in_flight(void) {
    bgp_ribout_config_t a, b;
    bgp_ribout_snapshot_t *sa = generate(&a, "A", k_big), *sb = generate(&b, "B", k_far);
    bgp_peer_tx_t         *tx = bgp_peer_tx_create();
    bgp_tx_request_t       req = {.op = BGP_TX_OP_ADVERTISE, .name = "A", .snapshot = sa, .observer = {.run_id = 3}};
    bgp_tx_plan_t         *plan;
    bgp_tx_batch_result_t  result;
    char                   reason[BGP_TX_REASON_SIZE];

    TEST("A reset drops jobs and bindings; the batch in flight stays pinned and its completion is stale");
    ASSERT(sa && sb && tx, "setup");
    ASSERT(bgp_peer_tx_plan(tx, &req, &plan, reason) == BGP_TX_PLAN_OK, reason);
    bgp_peer_tx_commit(tx, plan);
    ASSERT(request(tx, BGP_TX_OP_ADVERTISE, "B", sb, reason) == 0, reason);
    bgp_peer_tx_set_withheld(tx, "C", 0, "ribout not configured");
    ASSERT(bgp_peer_tx_fill_batch(tx, 1, BGP_TX_BATCH_BYTES) > 0, "batch in flight");
    ASSERT(sa->adv->refs == 3, "block, job and batch hold the stream");

    aborted = 0;
    bgp_peer_tx_reset(tx, count_abort, NULL);
    ASSERT(aborted == 1, "the observed job is reported");
    ASSERT(tx->job_count == 0 && tx->binding_count == 0 && tx->withheld_count == 0, "state cleared");
    ASSERT(sa->refs == 1 && sb->refs == 1 && sa->adv->refs == 2, "only the batch still pins the stream");

    bgp_peer_tx_batch_done(tx, 1, 0, &result);  /* The cancelled write completes */
    ASSERT(result.stale && sa->adv->refs == 1, "stale completion releases the batch");
    ASSERT(bgp_peer_tx_fill_batch(tx, 2, BGP_TX_BATCH_BYTES) == 0, "nothing left to send");

    // A completion from an older session never advances the new one.
    ASSERT(request(tx, BGP_TX_OP_ADVERTISE, "B", sb, reason) == 0, reason);
    ASSERT(bgp_peer_tx_fill_batch(tx, 2, BGP_TX_BATCH_BYTES) > 0, "new session batch");
    bgp_peer_tx_batch_done(tx, 1, 1, &result);
    ASSERT(result.stale && tx->job_count == 1 && bgp_peer_tx_head(tx)->sent_msgs == 0, "old epoch ignored");
    bgp_peer_tx_destroy(tx);
    bgp_ribout_destroy(&a);
    bgp_ribout_destroy(&b);
    PASS();
}

static void test_queue_cap_and_refresh(void) {
    bgp_ribout_config_t    a;
    bgp_ribout_snapshot_t *sa = generate(&a, "A", k_a);
    bgp_peer_tx_t         *tx = bgp_peer_tx_create();
    bgp_tx_request_t       refresh = {.op = BGP_TX_OP_REFRESH, .family = {1, 1}};
    bgp_tx_plan_t         *plan;
    char                   reason[BGP_TX_REASON_SIZE];
    drained_t              d;
    int                    accepted = 0;

    TEST("The queue is bounded; refresh replays merge until they start; EoR follows only when asked");
    ASSERT(sa && tx, "setup");
    ASSERT(request(tx, BGP_TX_OP_ADVERTISE, "A", sa, reason) == 0, reason);
    while (request(tx, BGP_TX_OP_REPLAY, "A", NULL, reason) == 0) {
        accepted++;
    }
    ASSERT((size_t)accepted == tx->limits.jobs - 1 && strstr(reason, "too many"), reason);
    drain(tx, 1, &d);

    ASSERT(bgp_peer_tx_plan(tx, &refresh, &plan, reason) == BGP_TX_PLAN_OK, reason);
    bgp_peer_tx_commit(tx, plan);
    ASSERT(bgp_peer_tx_plan(tx, &refresh, &plan, reason) == BGP_TX_PLAN_OK, reason);
    bgp_peer_tx_commit(tx, plan);
    ASSERT(tx->job_count == 1, "the second refresh merges with the unstarted replay");
    ASSERT(bgp_peer_tx_fill_batch(tx, 1, BGP_TX_BATCH_BYTES) > 0, "replay started");
    refresh.eor_after = 1;
    ASSERT(bgp_peer_tx_plan(tx, &refresh, &plan, reason) == BGP_TX_PLAN_OK, reason);
    bgp_peer_tx_commit(tx, plan);
    ASSERT(tx->job_count == 3, "a refresh after the replay started queues a new replay and the EoR");
    refresh.family.safi = 4;
    ASSERT(bgp_peer_tx_plan(tx, &refresh, &plan, reason) == BGP_TX_PLAN_OK, reason);
    bgp_peer_tx_commit(tx, plan);
    ASSERT(tx->job_count == 4, "another family: only its EoR");
    {
        bgp_tx_batch_result_t result;
        bgp_peer_tx_batch_done(tx, 1, 1, &result);
    }
    drain(tx, 1, &d);
    ASSERT(strcmp(d.log, "replay:A eor:v4 eor:mp ") == 0, d.log);
    ASSERT(tx->eor_sent_count == 2, "both End-of-RIB families recorded");
    bgp_peer_tx_destroy(tx);
    bgp_ribout_destroy(&a);
    PASS();
}

static void test_standing_then_eor(void) {
    static const bgp_afi_safi_t families[] = {{1, 1}, {2, 1}};
    bgp_ribout_config_t    a;
    bgp_ribout_snapshot_t *sa = generate(&a, "A", k_a);
    bgp_peer_tx_t         *tx = bgp_peer_tx_create();
    bgp_tx_request_t       eor = {.op = BGP_TX_OP_EOR, .eor_families = families, .eor_count = 2};
    bgp_tx_plan_t         *plan;
    char                   reason[BGP_TX_REASON_SIZE];
    drained_t              d;

    TEST("End-of-RIB queued after the standing advertisements follows them; a withheld record clears on advertise");
    ASSERT(sa && tx, "setup");
    bgp_peer_tx_set_withheld(tx, "A", sa->id, "4-octet AS not negotiated (AS_PATH is 4-octet)");
    bgp_peer_tx_set_withheld(tx, "Z", 0, "ribout Z is not configured");
    ASSERT(tx->withheld_count == 2, "two withheld records");
    ASSERT(request(tx, BGP_TX_OP_ADVERTISE, "A", sa, reason) == 0, reason);
    ASSERT(tx->withheld_count == 1 && strcmp(tx->withheld[0].name, "Z") == 0, "advertising A clears its record");
    ASSERT(bgp_peer_tx_plan(tx, &eor, &plan, reason) == BGP_TX_PLAN_OK, reason);
    bgp_peer_tx_commit(tx, plan);
    drain(tx, 1, &d);
    ASSERT(strcmp(d.log, "adv:A eor:v4 eor:mp ") == 0, d.log);
    ASSERT(tx->eor_sent_count == 2 && tx->eor_sent[1].afi == 2, "IPv4 then IPv6 unicast End-of-RIB");
    bgp_peer_tx_destroy(tx);
    bgp_ribout_destroy(&a);
    PASS();
}

static void test_growth_wrap_with_batch(void) {
    TEST("Ring growth preserves FIFO and an in-flight batch across a wrapped head");
    bgp_ribout_config_t    block;
    bgp_ribout_snapshot_t *snapshot = generate(&block, "A", k_a);
    bgp_peer_tx_t         *tx = bgp_peer_tx_create();
    char                   reason[BGP_TX_REASON_SIZE];
    ASSERT(tx && snapshot && request(tx, BGP_TX_OP_ADVERTISE, "A", snapshot, reason) == 0, "setup");
    for (int i = 0; i < 7; i++) ASSERT(request(tx, BGP_TX_OP_REPLAY, "A", NULL, reason) == 0, reason);
    for (int i = 0; i < 5; i++) {
        bgp_tx_batch_result_t result;
        ASSERT(bgp_peer_tx_fill_batch(tx, 1, BGP_TX_BATCH_BYTES) == 1, "one UPDATE per job");
        bgp_peer_tx_batch_done(tx, 1, 1, &result);
        ASSERT(result.job_complete && !result.stale, "completed job");
    }
    ASSERT(tx->job_head == 5 && tx->job_count == 3, "ring wraps on later appends");
    ASSERT(bgp_peer_tx_fill_batch(tx, 1, BGP_TX_BATCH_BYTES) == 1, "batch in flight");
    uint64_t                head_id = bgp_peer_tx_head(tx)->id;
    const bgp_msg_stream_t *pinned = tx->batch.stream;
    for (int i = 0; i < 6; i++) ASSERT(request(tx, BGP_TX_OP_REPLAY, "A", NULL, reason) == 0, reason);
    ASSERT(tx->job_count == 9 && tx->job_capacity >= 9 && bgp_peer_tx_head(tx)->id == head_id &&
           tx->batch.in_flight && tx->batch.stream == pinned, "growth preserves pending write ownership");
    for (size_t i = 0; i < tx->job_count; i++)
        ASSERT(bgp_peer_tx_job(tx, i)->id == head_id + i, "FIFO survives wrapped storage growth");
    bgp_tx_batch_result_t result;
    bgp_peer_tx_batch_done(tx, 1, 1, &result);
    ASSERT(result.job_complete && !result.stale && tx->job_count == 8, "original completion advances correct job");
    drained_t drained;
    drain(tx, 1, &drained);
    ASSERT(drained.msgs == 8 && !tx->job_count && snapshot->refs == 2, "all jobs release references");
    bgp_peer_tx_destroy(tx);
    ASSERT(snapshot->refs == 1, "only the configuration retains its snapshot");
    bgp_ribout_destroy(&block);
    PASS();
}

static void test_configurable_budgets(void) {
    TEST("Configured job, binding and retained-snapshot budgets reject atomically");
    bgp_ribout_config_t a, b;
    bgp_ribout_snapshot_t *sa = generate(&a, "A", k_a), *sb = generate(&b, "B", k_b);
    bgp_tx_limits_t        limits = {.jobs = 3, .bindings = 1, .retained_bytes = UINT64_MAX};
    bgp_peer_tx_t         *tx = bgp_peer_tx_create_with_limits(&limits);
    char                   reason[BGP_TX_REASON_SIZE];
    ASSERT(tx && sa && sb && request(tx, BGP_TX_OP_ADVERTISE, "A", sa, reason) == 0, "setup");
    ASSERT(request(tx, BGP_TX_OP_ADVERTISE, "B", sb, reason) < 0 && tx->binding_count == 1 &&
           tx->job_count == 1 && sb->refs == 1, "binding budget leaves jobs/bindings/references unchanged");
    for (int i = 0; i < 2; i++) ASSERT(request(tx, BGP_TX_OP_REPLAY, "A", NULL, reason) == 0, reason);
    ASSERT(request(tx, BGP_TX_OP_REPLAY, "A", NULL, reason) < 0 && tx->job_count == 3, "exact job budget");
    bgp_peer_tx_destroy(tx);
    limits.retained_bytes = 1;
    tx = bgp_peer_tx_create_with_limits(&limits);
    ASSERT(tx && request(tx, BGP_TX_OP_ADVERTISE, "A", sa, reason) < 0 && strstr(reason, "budget") &&
           !tx->job_count && !tx->binding_count && sa->refs == 1, "retained memory budget is not merely a job count");
    bgp_peer_tx_destroy(tx);

    // Account independently for the binding and queued job, including the job's separate stream reference.
    uint64_t stream_bytes = sa->adv->bytes + sa->adv->count * sizeof(bgp_msg_t);
    uint64_t snapshot_bytes = sizeof(*sa) + bgp_ribout_config_bytes(sa->config) + stream_bytes;
    limits.retained_bytes = 2 * snapshot_bytes + stream_bytes;
    tx = bgp_peer_tx_create_with_limits(&limits);
    ASSERT(tx && request(tx, BGP_TX_OP_ADVERTISE, "A", sa, reason) == 0, "exact retained-reference budget fits");
    ASSERT(request(tx, BGP_TX_OP_REPLAY, "A", NULL, reason) < 0 && tx->job_count == 1 && sa->refs == 3,
           "extra references are rejected below the job cap without leaking a reference");
    drained_t drained;
    drain(tx, 1, &drained);
    ASSERT(request(tx, BGP_TX_OP_REPLAY, "A", NULL, reason) == 0,
           "draining releases enough retained-reference budget to admit a replay");
    bgp_peer_tx_destroy(tx);
    bgp_ribout_destroy(&a);
    bgp_ribout_destroy(&b);
    PASS();
}

static void test_environment_budgets(void) {
    TEST("Environment budget overrides reject invalid, zero and overflowing values");
    const char *names[] = {"BGPSIM_TX_MAX_JOBS", "BGPSIM_TX_MAX_BINDINGS", "BGPSIM_TX_MAX_RETAINED_BYTES"};
    char *saved[3];
    for (int i = 0; i < 3; i++) saved[i] = getenv(names[i]) ? strdup(getenv(names[i])) : NULL;
    static const struct {
        const char *values[3];
        size_t      jobs, bindings;
        uint64_t    bytes;
    } cases[] = {
        {{"17", "9", "123456"}, 17, 9, 123456},
        {{"0", "-1", "not-a-number"}, BGP_TX_DEFAULT_JOBS, BGP_TX_DEFAULT_BINDINGS, BGP_TX_DEFAULT_RETAINED_BYTES},
        {{"2147483648", "12junk", "18446744073709551616"},
         BGP_TX_DEFAULT_JOBS, BGP_TX_DEFAULT_BINDINGS, BGP_TX_DEFAULT_RETAINED_BYTES},
    };
    int ok = 1;
    for (size_t c = 0; c < sizeof(cases) / sizeof(*cases); c++) {
        for (int i = 0; i < 3; i++) setenv(names[i], cases[c].values[i], 1);
        bgp_peer_tx_t *tx = bgp_peer_tx_create();
        ok = ok && tx && tx->limits.jobs == cases[c].jobs && tx->limits.bindings == cases[c].bindings &&
             tx->limits.retained_bytes == cases[c].bytes;
        bgp_peer_tx_destroy(tx);
    }
    for (int i = 0; i < 3; i++) {
        if (saved[i]) setenv(names[i], saved[i], 1);
        else unsetenv(names[i]);
        free(saved[i]);
    }
    ASSERT(ok, "valid values apply exactly; invalid values use documented defaults");
    PASS();
}

int main(void) {
    test_growth_wrap_with_batch();
    test_configurable_budgets();
    test_environment_budgets();
    test_fifo_and_bindings();
    test_replace_or_withdraw();
    test_overlap();
    test_withdraw_all_and_replay();
    test_batches_and_progress();
    test_reset_with_batch_in_flight();
    test_queue_cap_and_refresh();
    test_standing_then_eor();
    printf("\nTests run: %d, passed: %d, failed: %d\n", tests_run, tests_passed, tests_failed);
    return tests_failed == 0 ? 0 : 1;
}
