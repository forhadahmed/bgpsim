#include <errno.h>
#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include "log.h"
#include "bgpsim.h"
#include "runtime.h"
#include "bgp_ribout.h"
#include "bgp_ribout_config.h"

static uint16_t bgp_get_listen_base_port(void) {
    const char *env_value;
    char       *endptr;
    long        parsed;

    env_value = getenv("BGPSIM_LISTEN_BASE_PORT");
    if (env_value == NULL || env_value[0] == '\0') {
        return BGP_LISTEN_BASE_PORT;
    }

    errno = 0;
    parsed = strtol(env_value, &endptr, 10);
    if (errno != 0 || endptr == env_value || *endptr != '\0') {
        return BGP_LISTEN_BASE_PORT;
    }

    if (parsed < 1024 || parsed > UINT16_MAX) {
        return BGP_LISTEN_BASE_PORT;
    }

    return (uint16_t)parsed;
}

static int bgp_router_error_not_found(uint32_t as_number) {
    fprintf(stderr, "Error: Router BGP %u not found\n", as_number);
    return -1;
}

void bgp_init_simulator(bgp_sim_t *sim) {
    memset(sim, 0, sizeof(*sim));
    pthread_mutex_init(&sim->model_lock, NULL);
#ifdef BGPSIM_TEST
    sim->config_loading = 1;
#else
    sim->config_loading = 0;
#endif
}

bgp_router_t *bgp_find_router(bgp_sim_t *sim, uint32_t as_number) {
    for (int i = 0; i < sim->router_count; i++) {
        if (sim->routers[i]->active && sim->routers[i]->local_as == as_number) {
            return sim->routers[i];
        }
    }

    return NULL;
}

bgp_ribout_config_t *bgp_sim_add_ribout(bgp_sim_t *sim, const char *name) {
    if (!bgp_ribout_name_valid(name)) return NULL;
    bgp_ribout_config_t *block = bgp_sim_find_ribout(sim, name);
    if (block) return block;
    if (sim->ribout_count == INT_MAX) return NULL;
    block = calloc(1, sizeof(*block));
    if (!block) return NULL;
    if (bgp_ribout_init(block, name) < 0) {
        free(block);
        return NULL;
    }
    bgp_ribout_config_t **table = array_reserve(sim->ribouts, sizeof(*table), &sim->ribout_capacity,
                                                sim->ribout_count + 1);
    if (!table) {
        bgp_ribout_destroy(block);
        free(block);
        return NULL;
    }
    sim->ribouts = table;
    sim->ribouts[sim->ribout_count++] = block;
    return block;
}

int bgp_sim_remove_ribout(bgp_sim_t *sim, const char *name) {
    for (int i = 0; i < sim->ribout_count; i++) {
        bgp_ribout_config_t *block = sim->ribouts[i];
        if (strcmp(block->name, name)) continue;
        bgp_ribout_destroy(block);
        free(block);
        memmove(sim->ribouts + i, sim->ribouts + i + 1, (size_t)(sim->ribout_count - i - 1) * sizeof(*sim->ribouts));
        sim->ribouts[--sim->ribout_count] = NULL;
        return 0;
    }
    return -1;
}

bgp_ribout_config_t *bgp_sim_find_ribout(bgp_sim_t *sim, const char *name) {
    for (int i = 0; i < sim->ribout_count; i++) {
        if (strcmp(sim->ribouts[i]->name, name) == 0) {
            return sim->ribouts[i];
        }
    }

    return NULL;
}

static int bgp_router_id_in_use(const bgp_sim_t *sim, uint32_t id) {
    for (int i = 0; i < sim->router_count; i++) {
        if (sim->routers[i]->active && sim->routers[i]->router_id == id) return 1;
    }
    return 0;
}

static uint32_t bgp_generate_unique_router_id(bgp_sim_t *sim, int router_index) {
    uint32_t candidate = UINT32_C(0x0a000101) + (uint32_t)router_index;
    if (bgp_router_id_in_use(sim, candidate)) {
        candidate = UINT32_C(0xc0a80101) + (uint32_t)router_index;
        while (bgp_router_id_in_use(sim, candidate)) candidate++;
    }
    return candidate;
}

void bgp_router_reset(bgp_router_t *router) {
    // Reuse storage, never live handles: callers must wait for the listener and every peer close callback.
    bgp_neighbor_t **saved_neighbors = router->neighbors;
    int              saved_capacity = router->neighbor_capacity;

    memset(router, 0, sizeof(*router));
    router->neighbors = saved_neighbors;
    router->neighbor_capacity = saved_capacity;

    for (int i = 0; i < saved_capacity; i++)
        if (saved_neighbors[i]) bgp_neighbor_reset(saved_neighbors[i]);
}

static int bgp_find_free_router_slot(bgp_sim_t *sim) {
    for (int i = 0; i < sim->router_count; i++) {
        // sim is cleared only after the listener AND every child finish closing.
        if (!sim->routers[i]->sim) return i;
    }

    return sim->router_count;
}

static void bgp_trim_router_tail(bgp_sim_t *sim) {
    while (sim->router_count > 0 && !sim->routers[sim->router_count - 1]->sim) {
        sim->router_count--;
    }
}

int bgp_add_router(bgp_sim_t *sim, uint32_t as_number) {
    struct in_addr addr;
    char           router_id_str[INET_ADDRSTRLEN];
    bgp_router_t  *router;
    int            slot;

    pthread_mutex_lock(&sim->model_lock);

    if (bgp_find_router(sim, as_number)) {
        log_write("Router BGP %u already exists\n", as_number);
        pthread_mutex_unlock(&sim->model_lock);
        return 0;
    }

    slot = bgp_find_free_router_slot(sim);
    uint32_t port = (uint32_t)bgp_get_listen_base_port() + (uint32_t)slot;
    if (port > UINT16_MAX) {
        pthread_mutex_unlock(&sim->model_lock);
        fprintf(stderr, "Error: No listener port available for router BGP %u\n", as_number);
        return -1;
    }
    // Environment changes must not assign a port already owned by another live/closing router.
    for (int i = 0; i < sim->router_count; i++) {
        if (i != slot && sim->routers[i]->sim && sim->routers[i]->listen_port == port) {
            pthread_mutex_unlock(&sim->model_lock);
            fprintf(stderr, "Error: Listener port %u is already assigned\n", port);
            return -1;
        }
    }
    router = slot < sim->router_capacity ? sim->routers[slot] : NULL;
    if (!router) {
        // libuv callbacks retain router/peer pointers, so only pointer tables may move during growth.
        router = calloc(1, sizeof(*router));
        bgp_router_t **table = router ? array_reserve(sim->routers, sizeof(*table),
                                                     &sim->router_capacity, slot + 1) : NULL;
        if (!table) {
            free(router);
            pthread_mutex_unlock(&sim->model_lock);
            fprintf(stderr, "Error: Failed to allocate router BGP %u\n", as_number);
            return -1;
        }
        sim->routers = table;
        sim->routers[slot] = router;
    }
    bgp_router_reset(router);

    router->local_as = as_number;
    router->router_index = slot;
    router->sim = sim;
    router->router_id = bgp_generate_unique_router_id(sim, router->router_index);
    router->router_id_configured = 0;
    router->source_ip[0] = '\0';
    router->active = 1;
    router->neighbor_count = 0;
    router->listen_port = (uint16_t)port;

    if (slot == sim->router_count) {
        sim->router_count++;
    }

    addr.s_addr = htonl(router->router_id);
    inet_ntop(AF_INET, &addr, router_id_str, sizeof(router_id_str));
    log_write("Added router BGP %u (router-id %s)\n", as_number, router_id_str);

    pthread_mutex_unlock(&sim->model_lock);

    if (sim->runtime) {
        bgpsim_runtime_reconcile(sim->runtime);
    }

    return 1;
}

int bgp_remove_router(bgp_sim_t *sim, uint32_t as_number) {
    bgp_router_t *router;

    pthread_mutex_lock(&sim->model_lock);

    router = bgp_find_router(sim, as_number);
    if (!router) {
        pthread_mutex_unlock(&sim->model_lock);
        return bgp_router_error_not_found(as_number);
    }

    router->active = 0;
    for (int i = 0; i < router->neighbor_count; i++) {
        router->neighbors[i]->active = 0;
    }

    log_write("Removed router BGP %u\n", as_number);
    pthread_mutex_unlock(&sim->model_lock);

    if (sim->runtime) {
        bgpsim_runtime_reconcile(sim->runtime);
    } else {
        pthread_mutex_lock(&sim->model_lock);
        bgp_router_reset(router);
        bgp_trim_router_tail(sim);
        pthread_mutex_unlock(&sim->model_lock);
    }

    return 1;
}

int bgp_set_router_id(bgp_sim_t *sim, uint32_t as_number, const char *router_id_str) {
    struct in_addr addr;
    bgp_router_t  *router;

    pthread_mutex_lock(&sim->model_lock);

    router = bgp_find_router(sim, as_number);
    if (!router) {
        pthread_mutex_unlock(&sim->model_lock);
        return bgp_router_error_not_found(as_number);
    }

    if (inet_pton(AF_INET, router_id_str, &addr) != 1) {
        pthread_mutex_unlock(&sim->model_lock);
        fprintf(stderr, "Error: Invalid router ID format: %s\n", router_id_str);
        return -1;
    }

    router->router_id = ntohl(addr.s_addr);
    router->router_id_configured = 1;

    pthread_mutex_unlock(&sim->model_lock);

    printf("Set router ID %s for BGP %u\n", router_id_str, as_number);
    fflush(stdout);
    return 1;
}

int bgp_set_source_ip(bgp_sim_t *sim, uint32_t as_number, const char *source_ip) {
    struct in_addr  addr4;
    struct in6_addr addr6;
    bgp_router_t   *router;

    pthread_mutex_lock(&sim->model_lock);

    router = bgp_find_router(sim, as_number);
    if (!router) {
        pthread_mutex_unlock(&sim->model_lock);
        return bgp_router_error_not_found(as_number);
    }

    if (inet_pton(AF_INET, source_ip, &addr4) != 1 && inet_pton(AF_INET6, source_ip, &addr6) != 1) {
        pthread_mutex_unlock(&sim->model_lock);
        fprintf(stderr, "Error: Invalid source IP format: %s\n", source_ip);
        return -1;
    }

    strncpy(router->source_ip, source_ip, sizeof(router->source_ip) - 1);
    router->source_ip[sizeof(router->source_ip) - 1] = '\0';

    pthread_mutex_unlock(&sim->model_lock);

    printf("Set update-source %s for BGP %u\n", source_ip, as_number);
    fflush(stdout);
    return 1;
}

int bgp_clear_source_ip(bgp_sim_t *sim, uint32_t as_number) {
    bgp_router_t *router;

    pthread_mutex_lock(&sim->model_lock);

    router = bgp_find_router(sim, as_number);
    if (!router) {
        pthread_mutex_unlock(&sim->model_lock);
        return bgp_router_error_not_found(as_number);
    }

    router->source_ip[0] = '\0';

    pthread_mutex_unlock(&sim->model_lock);

    printf("Cleared update-source for BGP %u\n", as_number);
    fflush(stdout);
    return 1;
}

void bgp_shutdown_sim(bgp_sim_t *sim) {
    sim->shutdown = 1;

    if (sim->runtime) {
        bgpsim_runtime_request_shutdown(sim->runtime);
        bgpsim_runtime_join(sim->runtime);
        bgpsim_runtime_destroy(sim->runtime);
        sim->runtime = NULL;
    }

    for (int i = 0; i < sim->ribout_count; i++) {
        bgp_ribout_destroy(sim->ribouts[i]);
        free(sim->ribouts[i]);
    }

    for (int i = 0; i < sim->router_capacity; i++) {
        bgp_router_t *router = sim->routers[i];
        if (!router) continue;
        bgp_router_reset(router);
        for (int j = 0; j < router->neighbor_capacity; j++) free(router->neighbors[j]);
        free(router->neighbors);
        free(router);
    }

    free(sim->routers);
    sim->routers = NULL;
    free(sim->ribouts);
    sim->ribouts = NULL;
    script_store_destroy(&sim->scripts);
    pthread_mutex_destroy(&sim->model_lock);

    log_write("BGP simulator shutdown complete\n");
}
