#include <errno.h>
#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"
#include "bgp_ribout.h"
#include "bgp_peer_tx.h"

typedef enum {
    PLAN_BINDING_NONE = 0,
    PLAN_BINDING_SET,
    PLAN_BINDING_CLEAR,
    PLAN_BINDING_CLEAR_ALL,
} plan_binding_t;

struct bgp_tx_plan {
    bgp_tx_job_t          *jobs;     /* Jobs to append; they hold their references    */
    int                    job_capacity;
    size_t                 job_limit;
    size_t                 job_count;
    size_t                 total_msgs;
    uint64_t               total_bytes;
    plan_binding_t         binding_change;
    char                   name[BGP_RIBOUT_NAME_SIZE];
    bgp_ribout_snapshot_t *binding;  /* PLAN_BINDING_SET: new binding (one reference) */
    // Reserved replacements copy existing ownership, without taking duplicate references.
    bgp_tx_job_t          *reserved_jobs;
    int                    reserved_job_capacity;
    bgp_tx_binding_t      *reserved_bindings;
    int                    reserved_binding_capacity;
};

static int find_binding(const bgp_peer_tx_t *tx, const char *name) {
    for (size_t i = 0; i < tx->binding_count; i++) {
        if (strcmp(tx->bindings[i].name, name) == 0) {
            return (int)i;
        }
    }
    return -1;
}

static bgp_tx_job_t *job_at(bgp_peer_tx_t *tx, size_t i) {
    return &tx->jobs[(tx->job_head + i) % (size_t)tx->job_capacity];
}

static const bgp_tx_job_t *job_at_const(const bgp_peer_tx_t *tx, size_t i) {
    return &tx->jobs[(tx->job_head + i) % (size_t)tx->job_capacity];
}

const bgp_tx_job_t *bgp_peer_tx_job(const bgp_peer_tx_t *tx, size_t index) {
    return index < tx->job_count ? job_at_const(tx, index) : NULL;
}

static void job_release(bgp_tx_job_t *job) {
    bgp_ribout_snapshot_unref(job->snapshot);
    bgp_msg_stream_unref(job->stream);
    memset(job, 0, sizeof(*job));
}

static uint64_t configured_limit(const char *name, uint64_t fallback, uint64_t maximum) {
    const char *value = getenv(name);
    if (!value || value[0] < '0' || value[0] > '9') return fallback;
    char *end;
    errno = 0;
    unsigned long long number = strtoull(value, &end, 10);
    return errno || *end || !number || number > maximum ? fallback : (uint64_t)number;
}

bgp_peer_tx_t *bgp_peer_tx_create_with_limits(const bgp_tx_limits_t *limits) {
    if (!limits || !limits->jobs || limits->jobs > INT_MAX || !limits->bindings ||
        limits->bindings > INT_MAX || !limits->retained_bytes) return NULL;
    bgp_peer_tx_t *tx = calloc(1, sizeof(*tx));
    if (tx) tx->limits = *limits;
    return tx;
}

bgp_peer_tx_t *bgp_peer_tx_create(void) {
    bgp_tx_limits_t limits = {
        .jobs = (size_t)configured_limit("BGPSIM_TX_MAX_JOBS", BGP_TX_DEFAULT_JOBS, INT_MAX),
        .bindings = (size_t)configured_limit("BGPSIM_TX_MAX_BINDINGS", BGP_TX_DEFAULT_BINDINGS, INT_MAX),
        .retained_bytes = configured_limit("BGPSIM_TX_MAX_RETAINED_BYTES", BGP_TX_DEFAULT_RETAINED_BYTES, UINT64_MAX),
    };
    return bgp_peer_tx_create_with_limits(&limits);
}

void bgp_peer_tx_destroy(bgp_peer_tx_t *tx) {
    if (!tx) {
        return;
    }
    bgp_peer_tx_reset(tx, NULL, NULL);
    bgp_msg_stream_unref(tx->batch.stream);
    free(tx->jobs);
    free(tx->bindings);
    free(tx->withheld);
    free(tx);
}

// Planning

/*
 * Append a job that sends stream (the plan takes the stream reference and a snapshot reference). A stream without
 * messages sends nothing, so it makes no job. Returns -1 when the plan is full.
 */
static int plan_add(bgp_tx_plan_t *plan, const bgp_tx_request_t *request, bgp_tx_job_kind_t kind, int replay,
                    const char *name, bgp_ribout_snapshot_t *snapshot, bgp_msg_stream_t *stream) {
    bgp_tx_job_t *job;

    if (stream->count == 0) {
        bgp_msg_stream_unref(stream);
        return 0;
    }
    if (plan->job_count == plan->job_limit) {
        bgp_msg_stream_unref(stream);
        return -1;
    }
    bgp_tx_job_t *jobs = array_reserve(plan->jobs, sizeof(*jobs), &plan->job_capacity, (int)plan->job_count + 1);
    if (!jobs) {
        bgp_msg_stream_unref(stream);
        return -1;
    }
    plan->jobs = jobs;
    job = &plan->jobs[plan->job_count++];
    memset(job, 0, sizeof(*job));
    job->kind = (uint8_t)kind;
    job->replay = (uint8_t)replay;
    snprintf(job->name, sizeof(job->name), "%s", name ? name : "");
    job->snapshot = bgp_ribout_snapshot_ref(snapshot);
    job->stream = stream;
    job->cursor = stream->msgs;
    job->observer = request->observer;
    job->observer.base_msgs += plan->total_msgs;
    job->observer.base_bytes += plan->total_bytes;
    plan->total_msgs += stream->count;
    plan->total_bytes += stream->bytes;
    return 0;
}

/*
 * Queue a withdrawal of snapshot.
 */
static int plan_withdraw(bgp_tx_plan_t *plan, const bgp_tx_request_t *request, const char *name,
                         bgp_ribout_snapshot_t *snapshot, char *reason) {
    bgp_msg_stream_t *stream = bgp_ribout_snapshot_withdrawal(snapshot);

    if (!stream) {
        snprintf(reason, BGP_TX_REASON_SIZE, "cannot build the withdrawal of ribout %s (no memory)", name);
        return -1;
    }
    if (plan_add(plan, request, BGP_TX_JOB_WITHDRAW, 0, name, snapshot, stream) < 0) {
        snprintf(reason, BGP_TX_REASON_SIZE, "too many operations queued for this peer");
        return -1;
    }
    return 0;
}

static int plan_advertise(bgp_tx_plan_t *plan, const bgp_tx_request_t *request, const char *name,
                          bgp_ribout_snapshot_t *snapshot, int replay, char *reason) {
    if (plan_add(plan, request, BGP_TX_JOB_ADVERTISE, replay, name, snapshot, bgp_msg_stream_ref(snapshot->adv)) < 0) {
        snprintf(reason, BGP_TX_REASON_SIZE, "too many operations queued for this peer");
        return -1;
    }
    return 0;
}

/*
 * A replay of snapshot that has not started yet: a new one would send the same bytes again right after it.
 */
static int replay_queued(const bgp_peer_tx_t *tx, const bgp_ribout_snapshot_t *snapshot) {
    for (size_t i = 0; i < tx->job_count; i++) {
        const bgp_tx_job_t *job = job_at_const(tx, i);
        int                 started = job->sent_msgs > 0 || (tx->batch.in_flight && tx->batch.job_id == job->id);

        if (job->kind == BGP_TX_JOB_ADVERTISE && job->replay && job->snapshot == snapshot && !started) {
            return 1;
        }
    }
    return 0;
}

static int plan_eor(bgp_tx_plan_t *plan, const bgp_tx_request_t *request, const bgp_afi_safi_t *family, char *reason) {
    bgp_msg_stream_t *stream = bgp_msg_stream_eor(family, 1);

    if (!stream) {
        snprintf(reason, BGP_TX_REASON_SIZE, "cannot build End-of-RIB (no memory)");
        return -1;
    }
    if (plan_add(plan, request, BGP_TX_JOB_EOR, 0, "", NULL, stream) < 0) {
        snprintf(reason, BGP_TX_REASON_SIZE, "too many operations queued for this peer");
        return -1;
    }
    plan->jobs[plan->job_count - 1].family = *family;
    return 0;
}

static int plan_request(const bgp_peer_tx_t *tx, const bgp_tx_request_t *request, bgp_tx_plan_t *plan, char *reason) {
    const char            *name = request->name ? request->name : "";
    int                    idx = request->name ? find_binding(tx, name) : -1;
    bgp_ribout_snapshot_t *bound = (idx >= 0) ? tx->bindings[idx].snapshot : NULL;

    switch (request->op) {
        case BGP_TX_OP_ADVERTISE: {
            bgp_ribout_snapshot_t *snapshot = request->snapshot;

            if (!snapshot) {
                snprintf(reason, BGP_TX_REASON_SIZE, "ribout %s has no UPDATE snapshot", name);
                return -1;
            }
            if (idx < 0 && tx->binding_count == tx->limits.bindings) {
                snprintf(reason, BGP_TX_REASON_SIZE, "too many ribouts bound to this peer");
                return -1;
            }
            for (size_t i = 0; i < tx->binding_count; i++) {
                if ((int)i != idx && bgp_ribout_snapshot_keys_overlap(snapshot, tx->bindings[i].snapshot)) {
                    snprintf(reason, BGP_TX_REASON_SIZE, "route keys overlap ribout %s on this peer",
                             tx->bindings[i].name);
                    return -1;
                }
            }
            // A regeneration that produced the same bytes changes nothing on the wire.
            if (request->skip_identical && bound && bound != snapshot &&
                bgp_msg_stream_equal(bound->adv, snapshot->adv)) {
                plan->binding_change = PLAN_BINDING_SET;
                plan->binding = bgp_ribout_snapshot_ref(snapshot);
                break;
            }
            // The receiver replaces routes with the same keys; keys that leave the set must be withdrawn first.
            if (bound && bound != snapshot && !bgp_ribout_snapshot_same_keys(bound, snapshot) &&
                plan_withdraw(plan, request, name, bound, reason) < 0) {
                return -1;
            }
            if (plan_advertise(plan, request, name, snapshot, 0, reason) < 0) {
                return -1;
            }
            plan->binding_change = PLAN_BINDING_SET;
            plan->binding = bgp_ribout_snapshot_ref(snapshot);
            break;
        }
        case BGP_TX_OP_WITHDRAW:
            if (!bound) {
                snprintf(reason, BGP_TX_REASON_SIZE, "ribout %s is not advertised to this peer", name);
                return -1;
            }
            if (plan_withdraw(plan, request, name, bound, reason) < 0) {
                return -1;
            }
            plan->binding_change = PLAN_BINDING_CLEAR;
            break;
        case BGP_TX_OP_REPLAY:
            if (!bound) {
                snprintf(reason, BGP_TX_REASON_SIZE, "ribout %s is not advertised to this peer", name);
                return -1;
            }
            if (plan_advertise(plan, request, name, bound, 1, reason) < 0) {
                return -1;
            }
            break;
        case BGP_TX_OP_WITHDRAW_ALL:
            for (size_t i = 0; i < tx->binding_count; i++) {
                if (plan_withdraw(plan, request, tx->bindings[i].name, tx->bindings[i].snapshot, reason) < 0) {
                    return -1;
                }
            }
            plan->binding_change = PLAN_BINDING_CLEAR_ALL;
            break;
        case BGP_TX_OP_REFRESH:
            for (size_t i = 0; i < tx->binding_count; i++) {
                bgp_ribout_snapshot_t *snapshot = tx->bindings[i].snapshot;

                if (snapshot->profile.afi == request->family.afi && snapshot->profile.safi == request->family.safi &&
                    !replay_queued(tx, snapshot) &&
                    plan_advertise(plan, request, tx->bindings[i].name, snapshot, 1, reason) < 0) {
                    return -1;
                }
            }
            if (request->eor_after && plan_eor(plan, request, &request->family, reason) < 0) {
                return -1;
            }
            break;
        case BGP_TX_OP_EOR:
            for (size_t i = 0; i < request->eor_count; i++) {
                if (plan_eor(plan, request, &request->eor_families[i], reason) < 0) {
                    return -1;
                }
            }
            break;
    }
    snprintf(plan->name, sizeof(plan->name), "%s", name);
    if (plan->job_count > tx->limits.jobs - tx->job_count) {
        snprintf(reason, BGP_TX_REASON_SIZE, "too many operations queued for this peer");
        return -1;
    }
    return 0;
}

static uint64_t add_charge(uint64_t a, uint64_t b) {
    return a > UINT64_MAX - b ? UINT64_MAX : a + b;
}

static uint64_t stream_charge(const bgp_msg_stream_t *stream) {
    if (!stream) return 0;
    if (stream->count > UINT64_MAX / sizeof(bgp_msg_t)) return UINT64_MAX;
    return add_charge(stream->bytes, (uint64_t)stream->count * sizeof(bgp_msg_t));
}

static uint64_t snapshot_charge(const bgp_ribout_snapshot_t *snapshot) {
    if (!snapshot) return 0;
    uint64_t config = bgp_ribout_config_bytes(snapshot->config);
    return add_charge(sizeof(*snapshot), add_charge(config, stream_charge(snapshot->adv)));
}

/*
 * Charge each retained reference conservatively, including snapshots behind queued replacements/withdrawals.
 * Shared snapshots may be charged more than once; a slow peer cannot retain unlimited generations.
 */
static int plan_within_memory_budget(const bgp_peer_tx_t *tx, const bgp_tx_plan_t *plan) {
    uint64_t charge = stream_charge(tx->batch.stream);
    for (size_t i = 0; i < tx->binding_count; i++) {
        if (plan->binding_change == PLAN_BINDING_CLEAR_ALL ||
            ((plan->binding_change == PLAN_BINDING_SET || plan->binding_change == PLAN_BINDING_CLEAR) &&
             !strcmp(tx->bindings[i].name, plan->name))) continue;
        charge = add_charge(charge, snapshot_charge(tx->bindings[i].snapshot));
    }
    charge = add_charge(charge, snapshot_charge(plan->binding));
    for (size_t i = 0; i < tx->job_count + plan->job_count; i++) {
        const bgp_tx_job_t *job = i < tx->job_count ? job_at_const(tx, i) : &plan->jobs[i - tx->job_count];
        charge = add_charge(charge, add_charge(snapshot_charge(job->snapshot), stream_charge(job->stream)));
    }
    return charge <= tx->limits.retained_bytes;
}

static int plan_reserve(const bgp_peer_tx_t *tx, bgp_tx_plan_t *plan) {
    /*
     * Do not realloc live tables: multi-peer admission can still fail after this peer's reservation.
     * These shallow copies borrow existing references until commit transfers their ownership.
     */
    size_t jobs = tx->job_count + plan->job_count;
    if (jobs > (size_t)tx->job_capacity) {
        plan->reserved_jobs = array_reserve(NULL, sizeof(*plan->reserved_jobs), &plan->reserved_job_capacity,
                                             (int)jobs);
        if (!plan->reserved_jobs) return -1;
        for (size_t i = 0; i < tx->job_count; i++) plan->reserved_jobs[i] = *job_at_const(tx, i);
    }
    size_t bindings = tx->binding_count +
                      (plan->binding_change == PLAN_BINDING_SET && find_binding(tx, plan->name) < 0);
    if (bindings > (size_t)tx->binding_capacity) {
        plan->reserved_bindings = array_reserve(NULL, sizeof(*plan->reserved_bindings),
                                                 &plan->reserved_binding_capacity, (int)bindings);
        if (!plan->reserved_bindings) return -1;
        if (tx->binding_count) memcpy(plan->reserved_bindings, tx->bindings, tx->binding_count * sizeof(*tx->bindings));
    }
    return 0;
}

bgp_tx_verdict_t bgp_peer_tx_plan(const bgp_peer_tx_t *tx, const bgp_tx_request_t *request, bgp_tx_plan_t **plan,
                                  char *reason) {
    bgp_tx_plan_t *candidate = calloc(1, sizeof(*candidate));

    *plan = NULL;
    reason[0] = '\0';
    if (!candidate) {
        snprintf(reason, BGP_TX_REASON_SIZE, "no memory");
        return BGP_TX_PLAN_REJECTED;
    }
    candidate->job_limit = tx->limits.jobs - tx->job_count;
    if (plan_request(tx, request, candidate, reason) < 0) {
        bgp_tx_plan_free(candidate);
        return BGP_TX_PLAN_REJECTED;
    }
    if (!plan_within_memory_budget(tx, candidate) || plan_reserve(tx, candidate) < 0) {
        snprintf(reason, BGP_TX_REASON_SIZE, "retained-snapshot budget exceeded or no memory for TX storage");
        bgp_tx_plan_free(candidate);
        return BGP_TX_PLAN_REJECTED;
    }
    *plan = candidate;
    return BGP_TX_PLAN_OK;
}

void bgp_tx_plan_totals(const bgp_tx_plan_t *plan, size_t *msgs, uint64_t *bytes) {
    *msgs = plan ? plan->total_msgs : 0;
    *bytes = plan ? plan->total_bytes : 0;
}

void bgp_tx_plan_free(bgp_tx_plan_t *plan) {
    if (!plan) {
        return;
    }
    for (size_t i = 0; i < plan->job_count; i++) {
        job_release(&plan->jobs[i]);
    }
    bgp_ribout_snapshot_unref(plan->binding);
    free(plan->jobs);
    free(plan->reserved_jobs);
    free(plan->reserved_bindings);
    free(plan);
}

static void binding_remove(bgp_peer_tx_t *tx, size_t i) {
    bgp_ribout_snapshot_unref(tx->bindings[i].snapshot);
    memmove(&tx->bindings[i], &tx->bindings[i + 1], (tx->binding_count - i - 1) * sizeof(tx->bindings[0]));
    tx->binding_count--;
}

void bgp_peer_tx_commit(bgp_peer_tx_t *tx, bgp_tx_plan_t *plan) {
    int idx;

    if (plan->reserved_jobs) {
        // The ring was copied in queue order. In-flight writes pin a separate stream, not a job address.
        free(tx->jobs);
        tx->jobs = plan->reserved_jobs;
        tx->job_capacity = plan->reserved_job_capacity;
        tx->job_head = 0;
        plan->reserved_jobs = NULL;
    }
    if (plan->reserved_bindings) {
        free(tx->bindings);
        tx->bindings = plan->reserved_bindings;
        tx->binding_capacity = plan->reserved_binding_capacity;
        plan->reserved_bindings = NULL;
    }
    for (size_t i = 0; i < plan->job_count; i++) {
        bgp_tx_job_t *job = job_at(tx, tx->job_count++);

        *job = plan->jobs[i];
        job->id = ++tx->next_job_id;
    }
    plan->job_count = 0;

    switch (plan->binding_change) {
        case PLAN_BINDING_SET:
            idx = find_binding(tx, plan->name);
            if (idx >= 0) {
                bgp_ribout_snapshot_unref(tx->bindings[idx].snapshot);
            } else {
                idx = (int)tx->binding_count++;
                snprintf(tx->bindings[idx].name, sizeof(tx->bindings[idx].name), "%s", plan->name);
            }
            tx->bindings[idx].snapshot = plan->binding;
            plan->binding = NULL;
            bgp_peer_tx_clear_withheld(tx, plan->name);
            break;
        case PLAN_BINDING_CLEAR:
            idx = find_binding(tx, plan->name);
            if (idx >= 0) {
                binding_remove(tx, (size_t)idx);
            }
            break;
        case PLAN_BINDING_CLEAR_ALL:
            while (tx->binding_count > 0) {
                binding_remove(tx, tx->binding_count - 1);
            }
            break;
        case PLAN_BINDING_NONE:
            break;
    }
    bgp_tx_plan_free(plan);
}

// Withheld records

void bgp_peer_tx_set_withheld(bgp_peer_tx_t *tx, const char *name, uint64_t snapshot_id, const char *reason) {
    size_t i;

    for (i = 0; i < tx->withheld_count && strcmp(tx->withheld[i].name, name) != 0; i++) {
    }
    if (i == tx->withheld_count) {
        if (tx->withheld_count == tx->limits.bindings) {
            return;
        }
        bgp_tx_withheld_t *records = array_reserve(tx->withheld, sizeof(*records), &tx->withheld_capacity,
                                                   (int)tx->withheld_count + 1);
        if (!records) return;
        tx->withheld = records;
        tx->withheld_count++;
    }
    snprintf(tx->withheld[i].name, sizeof(tx->withheld[i].name), "%s", name);
    snprintf(tx->withheld[i].reason, sizeof(tx->withheld[i].reason), "%s", reason);
    tx->withheld[i].snapshot_id = snapshot_id;
}

void bgp_peer_tx_clear_withheld(bgp_peer_tx_t *tx, const char *name) {
    for (size_t i = 0; i < tx->withheld_count; i++) {
        if (strcmp(tx->withheld[i].name, name) == 0) {
            memmove(&tx->withheld[i], &tx->withheld[i + 1], (tx->withheld_count - i - 1) * sizeof(tx->withheld[0]));
            tx->withheld_count--;
            return;
        }
    }
}

// Writing

const bgp_tx_job_t *bgp_peer_tx_head(const bgp_peer_tx_t *tx) {
    return tx->job_count ? job_at_const(tx, 0) : NULL;
}

const bgp_tx_job_t *bgp_peer_tx_pending(const bgp_peer_tx_t *tx, const char *name) {
    for (size_t i = tx->job_count; i > 0; i--) {
        const bgp_tx_job_t *job = job_at_const(tx, i - 1);

        if (strcmp(job->name, name) == 0) {
            return job;
        }
    }
    return NULL;
}

const bgp_tx_binding_t *bgp_peer_tx_binding(const bgp_peer_tx_t *tx, const char *name) {
    int idx = find_binding(tx, name);

    return (idx >= 0) ? &tx->bindings[idx] : NULL;
}

size_t bgp_peer_tx_fill_batch(bgp_peer_tx_t *tx, uint64_t epoch, size_t max_bytes) {
    bgp_tx_batch_t *batch = &tx->batch;
    bgp_tx_job_t   *job;

    if (batch->in_flight || tx->job_count == 0) {
        return 0;
    }
    job = job_at(tx, 0);
    batch->nbufs = 0;
    batch->msgs = 0;
    batch->bytes = 0;
    for (const bgp_msg_t *msg = job->cursor; msg && batch->nbufs < BGP_TX_BATCH_BUFS; msg = msg->next) {
        if (batch->nbufs > 0 && batch->bytes + msg->length > max_bytes) {
            break;
        }
        batch->bufs[batch->nbufs].base = (char *)msg->data;
        batch->bufs[batch->nbufs].len = msg->length;
        batch->nbufs++;
        batch->bytes += msg->length;
    }
    batch->msgs = batch->nbufs;
    batch->epoch = epoch;
    batch->job_id = job->id;
    batch->stream = bgp_msg_stream_ref(job->stream);
    batch->in_flight = 1;
    return batch->msgs;
}

static void record_eor(bgp_peer_tx_t *tx, const bgp_afi_safi_t *family) {
    for (size_t i = 0; i < tx->eor_sent_count; i++) {
        if (tx->eor_sent[i].afi == family->afi && tx->eor_sent[i].safi == family->safi) {
            return;
        }
    }
    if (tx->eor_sent_count < BGP_TX_MAX_EOR) {
        tx->eor_sent[tx->eor_sent_count++] = *family;
    }
}

void bgp_peer_tx_batch_done(bgp_peer_tx_t *tx, uint64_t epoch, int ok, bgp_tx_batch_result_t *result) {
    bgp_tx_batch_t   *batch = &tx->batch;
    bgp_msg_stream_t *stream = batch->stream;
    bgp_tx_job_t     *job = tx->job_count ? job_at(tx, 0) : NULL;

    memset(result, 0, sizeof(*result));
    result->msgs = batch->msgs;
    result->bytes = batch->bytes;
    batch->in_flight = 0;
    batch->stream = NULL;

    if (!ok || batch->epoch != epoch || !job || job->id != batch->job_id) {
        result->stale = 1;
        bgp_msg_stream_unref(stream);
        return;
    }

    result->job_started = job->sent_msgs == 0;
    for (size_t i = 0; i < batch->msgs && job->cursor; i++) {
        job->cursor = job->cursor->next;
    }
    job->sent_msgs += batch->msgs;
    job->sent_bytes += batch->bytes;
    result->job_kind = job->kind;
    result->observer = job->observer;
    result->job_msgs = job->sent_msgs;
    result->job_bytes = job->sent_bytes;
    if (!job->cursor) {
        result->job_complete = 1;
        if (job->kind == BGP_TX_JOB_EOR) {
            record_eor(tx, &job->family);
        }
        job_release(job);
        tx->job_head = (tx->job_head + 1) % (size_t)tx->job_capacity;
        tx->job_count--;
    }
    bgp_msg_stream_unref(stream);
}

void bgp_peer_tx_reset(bgp_peer_tx_t *tx, bgp_tx_abort_cb abort_cb, void *ctx) {
    while (tx->job_count > 0) {
        bgp_tx_job_t *job = job_at(tx, 0);

        if (abort_cb && job->observer.run_id != 0) {
            abort_cb(ctx, &job->observer);
        }
        job_release(job);
        tx->job_head = (tx->job_head + 1) % (size_t)tx->job_capacity;
        tx->job_count--;
    }
    tx->job_head = 0;
    while (tx->binding_count > 0) {
        binding_remove(tx, tx->binding_count - 1);
    }
    tx->withheld_count = 0;
    tx->eor_sent_count = 0;
}

uint64_t bgp_peer_tx_outq(const bgp_peer_tx_t *tx) {
    uint64_t queued = 0;

    for (size_t i = 0; i < tx->job_count; i++) {
        const bgp_tx_job_t *job = job_at_const(tx, i);

        queued += job->stream->count - job->sent_msgs;
    }
    return queued;
}
