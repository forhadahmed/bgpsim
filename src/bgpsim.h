#ifndef BGPSIM_H
#define BGPSIM_H

#include <pthread.h>
#include "bgp.h"
#include "script.h"
#include "bgp_router.h"
#include "bgp_ribout_config.h"

struct bgpsim_runtime;
typedef struct bgpsim_runtime bgpsim_runtime_t;

/*
 * Top-level simulator container shared by config, CLI, and worker threads.
 */
typedef struct bgp_sim {
    bgp_router_t        **routers;
    int                   router_count;
    int                   router_capacity;
    // Stable configurations; growing or removing registry entries never moves other ribouts.
    bgp_ribout_config_t **ribouts;
    int                   ribout_count;
    int                   ribout_capacity;
    script_store_t        scripts;
    // Direct model-edit helpers still use this when called off-loop. Live runtime state is loop-owned.
    pthread_mutex_t       model_lock;
    int                   shutdown;        /* Global shutdown signal                            */
    int                   passive_mode;    /* Enable passive (listening) mode if set            */
    int                   config_loading;  /* Suppress live thread startup while parsing config */
    bgpsim_runtime_t     *runtime;         /* Libuv runtime root when control/runtime is active */
} bgp_sim_t;

/*
 * Simulator management functions
 */
void bgp_init_simulator(bgp_sim_t *sim);
void bgp_shutdown_sim(bgp_sim_t *sim);

/*
 * Find a ribout config block by name.  Returns NULL if not found.
 */
bgp_ribout_config_t* bgp_sim_find_ribout(bgp_sim_t *sim, const char *name);
bgp_ribout_config_t* bgp_sim_add_ribout(bgp_sim_t *sim, const char *name);
int bgp_sim_remove_ribout(bgp_sim_t *sim, const char *name);

#endif /* BGPSIM_H */
