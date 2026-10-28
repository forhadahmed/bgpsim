#ifndef SCRIPT_EXEC_H
#define SCRIPT_EXEC_H

#include "bgpsim.h"
#include "bgp_peer_tx.h"

/*
 * Script run executor on the runtime loop. A run steps through its frozen script: an advertise, withdraw or replay
 * step is admitted to its peers through tx_admit() and completes when every planned peer has written its UPDATEs; a
 * sleep step waits on a timer. The run model (script.c) records the phases, the per-peer plan and progress, and the
 * timings; write callbacks report progress through the job observers.
 *
 * A session reset during a step fails the run. cancel run stops it; UPDATEs already queued for its current step are
 * still written, unobserved, and nothing is withdrawn.
 */

/*
 * Start run on the loop thread of sim's runtime. Returns -1 when there is no runtime or no memory.
 */
int script_exec_start(bgp_sim_t *sim, script_run_t *run);

/*
 * A batch of an observed job completed: report it to the run.
 */
void script_exec_progress(bgp_sim_t *sim, const bgp_tx_batch_result_t *result);

/*
 * bgp_tx_abort_cb for a peer reset (ctx is the sim): fail the run whose step the job belonged to.
 */
void script_exec_abort(void *ctx, const bgp_tx_observer_t *observer);

/*
 * Stop executing run run_id (cancel run).
 */
void script_exec_stop(bgp_sim_t *sim, uint32_t run_id);

/*
 * Runtime shutdown: stop every run's timer.
 */
void script_exec_shutdown(bgp_sim_t *sim);

#endif /* SCRIPT_EXEC_H */
