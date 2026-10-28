#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "runtime.h"
#include "tx_exec.h"
#include "script_exec.h"

typedef struct script_exec {
    bgpsim_runtime_t   *runtime;
    bgp_sim_t          *sim;
    uint32_t            run_id;
    uint64_t            step_token;  /* Observers of the current step carry it */
    uv_timer_t          timer;       /* Sleeps and deferred step transitions   */
    struct script_exec *next;
} script_exec_t;

/*
 * Running executors, owned by the loop thread.
 */
static script_exec_t *g_execs;
static uint64_t      g_step_token;

static script_exec_t *exec_find(uint32_t run_id) {
    for (script_exec_t *exec = g_execs; exec; exec = exec->next) {
        if (exec->run_id == run_id) {
            return exec;
        }
    }
    return NULL;
}

static void exec_on_close(uv_handle_t *handle) {
    free(handle->data);
}

/*
 * Stop an executor: unlink it and free it once its timer has closed.
 */
static void exec_finish(script_exec_t *exec) {
    for (script_exec_t **link = &g_execs; *link; link = &(*link)->next) {
        if (*link == exec) {
            *link = exec->next;
            break;
        }
    }
    uv_timer_stop(&exec->timer);
    uv_close((uv_handle_t *)&exec->timer, exec_on_close);
}

static void exec_tick(uv_timer_t *timer);

/*
 * Run the next tick after delay_ms. A step transition always goes through the timer, never inline, so a step that
 * completes at once (every peer withheld, a zero sleep) cannot recurse through repeat forever.
 */
static void exec_schedule(script_exec_t *exec, uint64_t delay_ms) {
    uv_update_time(&exec->runtime->loop);
    uv_timer_start(&exec->timer, exec_tick, delay_ms, 0);
}

static void exec_fail(script_exec_t *exec, script_run_t *run, const char *reason) {
    char text[sizeof(run->error)];

    // A peer address and its reason can exceed the run's error field: keep the start.
    snprintf(text, sizeof(text), "%.*s", (int)sizeof(text) - 1, reason);
    script_run_fail(run, text, script_now_ms());
    exec_finish(exec);
}

static bgp_tx_op_t step_op(script_action_t action) {
    return action == SCRIPT_ADVERTISE ? BGP_TX_OP_ADVERTISE :
           action == SCRIPT_WITHDRAW  ? BGP_TX_OP_WITHDRAW : BGP_TX_OP_REPLAY;
}

/*
 * Admit the current step to its peers and record the plan of each.
 */
static void exec_prepare(script_exec_t *exec, script_run_t *run) {
    const script_step_t *step = &run->script.steps[run->step_index];
    tx_request_t request = {
        .op        = step_op(step->action),
        .ribout    = step->ribout,
        .peer      = step->peer,
        .router_as = step->router_as,
    };
    size_t              capacity = tx_result_capacity(exec->sim);
    tx_peer_result_t   *results = calloc(capacity, sizeof(*results));
    script_peer_plan_t *plans = calloc(capacity, sizeof(*plans));
    char                error[SCRIPT_REASON_SIZE + INET6_ADDRSTRLEN + 8];
    size_t              count = 0;
    int                 sends = 0;

    if (!results || !plans) {
        free(results);
        free(plans);
        exec_fail(exec, run, "no memory");
        return;
    }
    exec->step_token = ++g_step_token;
    request.observer.run_id = run->id;
    request.observer.step_token = exec->step_token;

    if (tx_admit(exec->sim, &request, results, capacity, &count, error, sizeof(error)) < 0) {
        goto fail;
    }
    if (run->state != RUN_RUNNING) {
        goto done;  /* A peer reset while admitting already failed the run */
    }
    if (count == 0) {
        snprintf(error, sizeof(error), "no neighbors");
        goto fail;
    }
    for (size_t i = 0; i < count; i++) {
        const tx_peer_result_t *result = &results[i];
        script_peer_plan_t     *plan = &plans[i];

        if (result->status == TX_PEER_REJECTED ||
            (result->status == TX_PEER_SKIPPED && strcmp(step->peer, "all") != 0)) {
            snprintf(error, sizeof(error), "%s: %s", result->peer, result->reason);
            goto fail;
        }
        snprintf(plan->peer, sizeof(plan->peer), "%s", result->peer);
        plan->router_as = result->router_as;
        if (result->status == TX_PEER_QUEUED) {
            plan->status = SCRIPT_PEER_PLANNED;
            plan->export_version = result->snapshot_id;
            plan->messages_total = result->msgs;
            plan->bytes_total = result->bytes;
            sends |= result->msgs > 0;
        } else {
            plan->status = result->status == TX_PEER_WITHHELD ? SCRIPT_PEER_WITHHELD : SCRIPT_PEER_SKIPPED;
            snprintf(plan->reason, sizeof(plan->reason), "%s", result->reason);
        }
    }
    if (script_run_set_peers(run, plans, count, script_now_ms()) != SCRIPT_OK ||
        script_run_set_phase(run, RUN_PHASE_QUEUE, script_now_ms()) != SCRIPT_OK) {
        snprintf(error, sizeof(error), "cannot record the peers of the step");
        goto fail;
    }
    /*
     * Nothing to write (every peer withheld or skipped): the step is done. Otherwise the first completed batch
     * starts the transmit phase.
     */
    if (!sends && script_run_set_phase(run, RUN_PHASE_TRANSMIT, script_now_ms()) == SCRIPT_OK) {
        exec_schedule(exec, 0);
    }
    goto done;

fail:
    exec_fail(exec, run, error);
done:
    free(results);
    free(plans);
}

static void exec_tick(uv_timer_t *timer) {
    script_exec_t *exec = timer->data;
    script_run_t  *run = script_run_find(&exec->sim->scripts, exec->run_id);
    uint64_t       now = script_now_ms();
    int            rc;

    if (!run || run->state != RUN_RUNNING) {
        exec_finish(exec);
        return;
    }
    switch (run->phase) {
        case RUN_PHASE_PREPARE:
            exec_prepare(exec, run);
            return;
        case RUN_PHASE_SLEEP:
        case RUN_PHASE_TRANSMIT:
            rc = script_run_finish_step(run, now);
            if (rc == SCRIPT_STATE && run->phase == RUN_PHASE_SLEEP) {
                // The timer fired before the requested time on the run clock: wait the rest.
                uint64_t elapsed = now - run->phase_started_ms;
                uint64_t wanted = run->script.steps[run->step_index].sleep_ms;

                exec_schedule(exec, wanted > elapsed ? wanted - elapsed : 1);
                return;
            }
            if (rc != SCRIPT_OK) {
                return;  /* Peers still sending: a write callback schedules the next tick */
            }
            if (run->state != RUN_RUNNING) {
                exec_finish(exec);
                return;
            }
            exec_schedule(exec, run->phase == RUN_PHASE_SLEEP ? run->script.steps[run->step_index].sleep_ms : 0);
            return;
        default:
            return;
    }
}

int script_exec_start(bgp_sim_t *sim, script_run_t *run) {
    script_exec_t *exec;

    if (!sim->runtime || !bgpsim_runtime_is_loop_thread(sim->runtime)) {
        return -1;
    }
    exec = calloc(1, sizeof(*exec));
    if (!exec || uv_timer_init(&sim->runtime->loop, &exec->timer) < 0) {
        free(exec);
        return -1;
    }
    if (script_run_start(run, script_now_ms()) != SCRIPT_OK) {
        uv_close((uv_handle_t *)&exec->timer, NULL);
        free(exec);
        return -1;
    }
    exec->runtime = sim->runtime;
    exec->sim = sim;
    exec->run_id = run->id;
    exec->timer.data = exec;
    exec->next = g_execs;
    g_execs = exec;
    exec_schedule(exec, run->phase == RUN_PHASE_SLEEP ? run->script.steps[run->step_index].sleep_ms : 0);
    return 0;
}

void script_exec_progress(bgp_sim_t *sim, const bgp_tx_batch_result_t *result) {
    const bgp_tx_observer_t *observer = &result->observer;
    script_exec_t           *exec = exec_find(observer->run_id);
    script_run_t            *run = script_run_find(&sim->scripts, observer->run_id);
    uint64_t                 now = script_now_ms();

    if (!exec || !run || run->state != RUN_RUNNING || observer->step_token != exec->step_token ||
        observer->peer_index >= run->peer_count) {
        return;  /* Cancelled, failed, or a job of an earlier step */
    }
    if (run->phase == RUN_PHASE_QUEUE) {
        script_run_set_phase(run, RUN_PHASE_TRANSMIT, now);
    }
    if (!run->peers[observer->peer_index].started) {
        script_run_peer_start(run, observer->peer_index, now);
    }
    script_run_tx_progress(run, observer->peer_index, observer->base_msgs + result->job_msgs,
                           observer->base_bytes + result->job_bytes, now);
    for (size_t i = 0; i < run->peer_count; i++) {
        if (!run->peers[i].complete) {
            return;
        }
    }
    exec_schedule(exec, 0);
}

void script_exec_abort(void *ctx, const bgp_tx_observer_t *observer) {
    bgp_sim_t     *sim = ctx;
    script_exec_t *exec = exec_find(observer->run_id);
    script_run_t  *run = sim ? script_run_find(&sim->scripts, observer->run_id) : NULL;
    char           reason[SCRIPT_REASON_SIZE];

    if (!exec || !run || run->state != RUN_RUNNING || observer->step_token != exec->step_token) {
        return;
    }
    snprintf(reason, sizeof(reason), "session to %s reset during the step",
             observer->peer_index < run->peer_count ? run->peers[observer->peer_index].plan.peer : "a peer");
    exec_fail(exec, run, reason);
}

void script_exec_stop(bgp_sim_t *sim, uint32_t run_id) {
    script_exec_t *exec = exec_find(run_id);

    (void)sim;
    if (exec) {
        exec_finish(exec);
    }
}

void script_exec_shutdown(bgp_sim_t *sim) {
    (void)sim;
    while (g_execs) {
        exec_finish(g_execs);
    }
}
