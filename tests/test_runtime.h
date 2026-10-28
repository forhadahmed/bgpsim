// Simulator lifetime and runtime ownership shared by in-process C fixtures.
#ifndef BGPSIM_TEST_RUNTIME_H
#define BGPSIM_TEST_RUNTIME_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "bgpsim.h"
#include "control.h"
#include "test_wait.h"
#include "bgp_router.h"
#include "bgp_neighbor.h"

static inline bgp_sim_t *create_sim(void) {
    bgp_sim_t *sim = calloc(1, sizeof(*sim));
    if (sim) bgp_init_simulator(sim);
    return sim;
}

static inline void destroy_sim(bgp_sim_t *sim) {
    if (!sim) return;
    if (sim->runtime) bgpsim_control_shutdown();
    bgp_shutdown_sim(sim);
    free(sim);
}

static inline int start_runtime(bgp_sim_t *sim, char *path, size_t size) {
    static unsigned counter;
    if (!sim || !path || !size) return -1;
    int length = snprintf(path, size, "/tmp/bgpsim-test-%ld-%u.sock", (long)getpid(), counter++);
    if (length < 0 || (size_t)length >= size) return -1;
    unlink(path);
    sim->config_loading = 0;
    return bgpsim_control_init(sim, path);
}

static inline int router_listening(void *opaque) {
    bgp_router_t *router = opaque;
    return router && router->listener_initialized && router->listener_open;
}

static inline int wait_for_router_listener(bgp_router_t *router) {
    return wait_until(router_listening, router, WAIT_TIMEOUT_MS);
}

static inline int only_neighbor_freed(void *opaque) {
    bgp_router_t   *router = opaque;
    bgp_neighbor_t *neighbor = router->neighbors[0];
    return router->neighbor_count == 0 && !neighbor->active && !neighbor->runtime_initialized &&
           !neighbor->stream_initialized && !neighbor->destroy_pending && neighbor->router == NULL;
}

static inline int wait_for_only_neighbor_freed(bgp_router_t *router) {
    return wait_until(only_neighbor_freed, router, WAIT_TIMEOUT_MS);
}

typedef struct {
    bgp_sim_t    *sim;
    bgp_router_t *router;
} router_wait_t;

static inline int router_finalized(void *opaque) {
    router_wait_t *wait = opaque;
    return wait->sim->router_count == 0 ||
           (!wait->router->active && !wait->router->listener_initialized && !wait->router->listener_open &&
            !wait->router->listener_closing && wait->router->sim == NULL);
}

static inline int wait_for_router_finalize(bgp_sim_t *sim, bgp_router_t *router) {
    return wait_until(router_finalized, &(router_wait_t){sim, router}, WAIT_TIMEOUT_MS);
}

#endif
