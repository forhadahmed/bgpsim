#ifndef RUNTIME_H
#define RUNTIME_H

#include <uv.h>
#include <pthread.h>
#include "bgpsim.h"

typedef struct bgpsim_control_session bgpsim_control_session_t;

typedef struct bgpsim_runtime {
    bgp_sim_t                *sim;
    uv_loop_t                 loop;
    uv_thread_t               thread;
    uv_async_t                shutdown_async;
    uv_async_t                reconcile_async;
    uv_timer_t                listener_retry_timer;  /* Retries passive listeners that failed to open */
    int                       listener_retry_initialized;
    uint64_t                  listener_retry_ms;     /* Next retry delay; doubles up to the maximum   */
    uv_pipe_t                 control_server;
    int                       control_server_initialized;
    int                       control_server_listening;
    int                       running;
    int                       ready;
    int                       ready_status;
    int                       stop_requested;
    int                       shutdown_started;
    int                       reconcile_requested;
    pthread_mutex_t           lifecycle_lock;
    pthread_cond_t            lifecycle_cond;
    char                      socket_path[256];
    bgpsim_control_session_t *sessions;
} bgpsim_runtime_t;

int bgpsim_runtime_start(bgpsim_runtime_t **out_runtime, bgp_sim_t *sim, const char *socket_path);
void bgpsim_runtime_request_shutdown(bgpsim_runtime_t *runtime);
void bgpsim_runtime_join(bgpsim_runtime_t *runtime);
void bgpsim_runtime_destroy(bgpsim_runtime_t *runtime);
int bgpsim_runtime_is_loop_thread(bgpsim_runtime_t *runtime);
void bgpsim_runtime_reconcile(bgpsim_runtime_t *runtime);
void bgpsim_runtime_request_reconcile(bgpsim_runtime_t *runtime);
void bgpsim_runtime_clear_neighbor(bgp_neighbor_t *neighbor, int record_reset);
/*
 * Start the next write of the peer if it is idle (loop thread only): after UPDATE jobs were queued.
 */
void bgpsim_runtime_peer_kick(bgp_neighbor_t *neighbor);
void bgpsim_runtime_emit_event_line(bgpsim_runtime_t *runtime, uint32_t router_as, const char *neighbor_ip,
                                    const char *text);

#endif /* RUNTIME_H */
